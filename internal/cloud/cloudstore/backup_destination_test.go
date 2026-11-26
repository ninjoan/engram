package cloudstore

import (
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
)

const (
	testDestinationAccessKeyID = "AKIAEXAMPLEACCESS7Q4Z"
	testDestinationSecret      = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
)

func testBackupSealer(t *testing.T, fill byte) *backupcrypto.Sealer {
	t.Helper()
	raw := strings.Repeat(string([]byte{fill}), backupcrypto.KeySize)
	key, err := backupcrypto.ParseKey(hex.EncodeToString([]byte(raw)))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	sealer, err := backupcrypto.NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

func seedDestinationAdmin(t *testing.T, cs *CloudStore) string {
	t.Helper()
	admin, err := cs.CreateHumanUser(context.Background(), CreateHumanUserParams{Username: "backup-admin", Email: "backup-admin@example.test", DisplayName: "Backup Admin", Role: PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	return admin.PrincipalID
}

func validDestinationParams(adminID string) PutBackupDestinationParams {
	return PutBackupDestinationParams{
		Endpoint:        "https://acct.r2.cloudflarestorage.com",
		Region:          "auto",
		Bucket:          "engram-backups",
		Prefix:          "prod/engram/",
		AccessKeyID:     testDestinationAccessKeyID,
		SecretAccessKey: testDestinationSecret,
		Actor:           BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"},
	}
}

func destinationRowText(t *testing.T, cs *CloudStore) string {
	t.Helper()
	var row string
	err := cs.db.QueryRowContext(context.Background(), `SELECT row_to_json(d)::text FROM cloud_backup_destinations d`).Scan(&row)
	if err != nil {
		t.Fatalf("read destination row: %v", err)
	}
	return row
}

func countRows(t *testing.T, cs *CloudStore, query string) int {
	t.Helper()
	var n int
	if err := cs.db.QueryRowContext(context.Background(), query).Scan(&n); err != nil {
		t.Fatalf("count %q: %v", query, err)
	}
	return n
}

func destinationAuditMetadata(t *testing.T, cs *CloudStore, action string) []string {
	t.Helper()
	rows, err := cs.db.QueryContext(context.Background(), `SELECT COALESCE(metadata::text, '') FROM cloud_auth_audit_log WHERE action = $1 ORDER BY id`, action)
	if err != nil {
		t.Fatalf("read audit: %v", err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var metadata string
		if err := rows.Scan(&metadata); err != nil {
			t.Fatal(err)
		}
		out = append(out, metadata)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestGetBackupDestinationReportsUnconfigured(t *testing.T) {
	cs := openIsolatedCloudStore(t)
	got, err := cs.GetBackupDestination(context.Background())
	if err != nil {
		t.Fatalf("GetBackupDestination: %v", err)
	}
	if got.Configured || got.Bucket != "" || got.AccessKeyIDHint != "" {
		t.Fatalf("empty store reports a destination: %+v", got)
	}
	if _, err := cs.OpenBackupDestinationCredentials(context.Background(), testBackupSealer(t, 1)); !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("Open on empty store error = %v, want %v", err, ErrBackupDestinationNotConfigured)
	}
}

func TestPutBackupDestinationStoresOnlySealedSecretsAndAudits(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)

	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}

	row := destinationRowText(t, cs)
	for _, secret := range []string{testDestinationSecret, testDestinationAccessKeyID} {
		if strings.Contains(row, secret) {
			t.Fatalf("destination row contains plaintext %q: %s", secret, row)
		}
	}
	var accessCipher, secretCipher, fingerprint string
	if err := cs.db.QueryRowContext(ctx, `SELECT access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint FROM cloud_backup_destinations`).Scan(&accessCipher, &secretCipher, &fingerprint); err != nil {
		t.Fatal(err)
	}
	if accessCipher == testDestinationAccessKeyID || secretCipher == testDestinationSecret || !strings.HasPrefix(secretCipher, "v1:") {
		t.Fatalf("raw columns are not sealed: access %q secret %q", accessCipher, secretCipher)
	}
	if fingerprint != sealer.Fingerprint() {
		t.Fatalf("key_fingerprint = %q, want %q", fingerprint, sealer.Fingerprint())
	}

	got, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatalf("GetBackupDestination: %v", err)
	}
	encoded, _ := json.Marshal(got)
	for _, secret := range []string{testDestinationSecret, testDestinationAccessKeyID, secretCipher, accessCipher} {
		if strings.Contains(string(encoded), secret) {
			t.Fatalf("Get exposes %q: %s", secret, encoded)
		}
	}
	want := BackupDestination{Configured: true, Kind: BackupDestinationKindS3, Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/engram/", KeyFingerprint: sealer.Fingerprint(), UpdatedByPrincipalID: adminID}
	want.AccessKeyIDHint = "****" + testDestinationAccessKeyID[len(testDestinationAccessKeyID)-4:]
	want.UpdatedAt = got.UpdatedAt
	if got != want || got.UpdatedAt.IsZero() {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}

	opened, err := cs.OpenBackupDestinationCredentials(ctx, sealer)
	if err != nil {
		t.Fatalf("OpenBackupDestinationCredentials: %v", err)
	}
	if opened.AccessKeyID != testDestinationAccessKeyID || opened.SecretAccessKey != testDestinationSecret || opened.Bucket != "engram-backups" || opened.Endpoint != want.Endpoint || opened.Region != "auto" || opened.Prefix != "prod/engram/" {
		t.Fatalf("Open = %+v", opened)
	}

	audits := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationUpdate)
	if len(audits) != 1 {
		t.Fatalf("update audits = %d, want 1", len(audits))
	}
	for _, secret := range []string{testDestinationSecret, testDestinationAccessKeyID, secretCipher, accessCipher} {
		if strings.Contains(audits[0], secret) {
			t.Fatalf("audit metadata contains %q: %s", secret, audits[0])
		}
	}
	if !strings.Contains(audits[0], `"bucket": "engram-backups"`) {
		t.Fatalf("audit metadata does not describe the destination: %s", audits[0])
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log WHERE action = 'backup.destination.update' AND actor_principal_id::text = '`+adminID+`' AND actor_source = 'dashboard' AND outcome = 'success'`); n != 1 {
		t.Fatalf("audit actor rows = %d, want 1", n)
	}
}

func TestPutBackupDestinationReplacesTheSingleRow(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	next := validDestinationParams(adminID)
	next.Bucket = "engram-backups-2"
	next.SecretAccessKey = "rotated-secret-value"
	if err := cs.PutBackupDestination(ctx, next, sealer); err != nil {
		t.Fatalf("second Put: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 1 {
		t.Fatalf("destination rows = %d, want 1", n)
	}
	opened, err := cs.OpenBackupDestinationCredentials(ctx, sealer)
	if err != nil {
		t.Fatal(err)
	}
	if opened.Bucket != "engram-backups-2" || opened.SecretAccessKey != "rotated-secret-value" {
		t.Fatalf("Open after replace = %+v", opened)
	}
}

func TestOpenBackupDestinationCredentialsWithRotatedKeyReportsMismatch(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	opened, err := cs.OpenBackupDestinationCredentials(ctx, testBackupSealer(t, 2))
	if !errors.Is(err, backupcrypto.ErrKeyMismatch) {
		t.Fatalf("Open error = %v, want %v", err, backupcrypto.ErrKeyMismatch)
	}
	if opened != (BackupDestinationCredentials{}) {
		t.Fatalf("mismatch returned credentials: %+v", opened)
	}
}

func TestOpenBackupDestinationCredentialsRejectsRedirectedDestination(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	// A direct database write that points sealed credentials at another
	// endpoint must not yield those credentials.
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_destinations SET endpoint = 'https://attacker.example.test'`); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.OpenBackupDestinationCredentials(ctx, sealer); !errors.Is(err, backupcrypto.ErrSealedValueInvalid) {
		t.Fatalf("Open error = %v, want %v", err, backupcrypto.ErrSealedValueInvalid)
	}
}

func TestPutBackupDestinationAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	before := destinationRowText(t, cs)

	next := validDestinationParams(adminID)
	next.Bucket = "other-bucket"
	next.Actor.Source = "" // the audit insert rejects a missing actor source
	err := cs.PutBackupDestination(ctx, next, sealer)
	if !errors.Is(err, ErrAuthAuditInsertFailed) {
		t.Fatalf("Put error = %v, want %v", err, ErrAuthAuditInsertFailed)
	}
	if after := destinationRowText(t, cs); after != before {
		t.Fatalf("failed audit changed the destination:\nbefore %s\nafter  %s", before, after)
	}
	if n := len(destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationUpdate)); n != 1 {
		t.Fatalf("update audits = %d, want 1", n)
	}
}

func TestPutBackupDestinationRejectsInvalidInputWithoutWriting(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)

	cases := map[string]func(*PutBackupDestinationParams){
		"http remote endpoint":      func(p *PutBackupDestinationParams) { p.Endpoint = "http://acct.r2.cloudflarestorage.com" },
		"endpoint without scheme":   func(p *PutBackupDestinationParams) { p.Endpoint = "acct.r2.cloudflarestorage.com" },
		"ftp endpoint":              func(p *PutBackupDestinationParams) { p.Endpoint = "ftp://acct.example.test" },
		"endpoint with credentials": func(p *PutBackupDestinationParams) { p.Endpoint = "https://user:pass@acct.example.test" },
		"endpoint with path":        func(p *PutBackupDestinationParams) { p.Endpoint = "https://acct.example.test/bucket" },
		"endpoint with query":       func(p *PutBackupDestinationParams) { p.Endpoint = "https://acct.example.test?x=1" },
		"empty endpoint":            func(p *PutBackupDestinationParams) { p.Endpoint = "" },
		"empty bucket":              func(p *PutBackupDestinationParams) { p.Bucket = "" },
		"short bucket":              func(p *PutBackupDestinationParams) { p.Bucket = "ab" },
		"uppercase bucket":          func(p *PutBackupDestinationParams) { p.Bucket = "Engram-Backups" },
		"bucket with underscore":    func(p *PutBackupDestinationParams) { p.Bucket = "engram_backups" },
		"bucket edge hyphen":        func(p *PutBackupDestinationParams) { p.Bucket = "-engram" },
		"bucket double dot":         func(p *PutBackupDestinationParams) { p.Bucket = "engram..backups" },
		"bucket ip address":         func(p *PutBackupDestinationParams) { p.Bucket = "192.168.1.10" },
		"bucket too long":           func(p *PutBackupDestinationParams) { p.Bucket = strings.Repeat("a", 64) },
		"empty region":              func(p *PutBackupDestinationParams) { p.Region = "" },
		"region with slash":         func(p *PutBackupDestinationParams) { p.Region = "us/east" },
		"prefix leading slash":      func(p *PutBackupDestinationParams) { p.Prefix = "/prod" },
		"prefix dot dot":            func(p *PutBackupDestinationParams) { p.Prefix = "prod/../other" },
		"prefix control char":       func(p *PutBackupDestinationParams) { p.Prefix = "pro\x07d" },
		"empty access key id":       func(p *PutBackupDestinationParams) { p.AccessKeyID = "" },
		"access key with space":     func(p *PutBackupDestinationParams) { p.AccessKeyID = "AKIA EXAMPLE" },
		"empty secret":              func(p *PutBackupDestinationParams) { p.SecretAccessKey = "" },
		"secret control char":       func(p *PutBackupDestinationParams) { p.SecretAccessKey = "abc\x00def" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			params := validDestinationParams(adminID)
			mutate(&params)
			err := cs.PutBackupDestination(ctx, params, sealer)
			if !errors.Is(err, ErrInvalidBackupDestination) {
				t.Fatalf("Put error = %v, want %v", err, ErrInvalidBackupDestination)
			}
			for _, secret := range []string{testDestinationSecret, "abc\x00def", "pass"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q echoes a secret", err)
				}
			}
			if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 0 {
				t.Fatalf("rejected Put wrote %d destination rows", n)
			}
			if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != 0 {
				t.Fatalf("rejected Put wrote %d audit rows", n)
			}
		})
	}
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), nil); !errors.Is(err, ErrBackupDestinationKeyRequired) {
		t.Fatalf("Put without sealer error = %v, want %v", err, ErrBackupDestinationKeyRequired)
	}
}

func TestPutBackupDestinationAllowsHTTPOnlyForLoopback(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	for _, endpoint := range []string{"http://127.0.0.1:9000", "http://localhost:9000", "http://[::1]:9000", "https://minio.internal:9000/"} {
		params := validDestinationParams(adminID)
		params.Endpoint = endpoint
		if err := cs.PutBackupDestination(ctx, params, sealer); err != nil {
			t.Fatalf("Put(%s): %v", endpoint, err)
		}
	}
	got, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if got.Endpoint != "https://minio.internal:9000" {
		t.Fatalf("endpoint = %q, want trailing slash trimmed", got.Endpoint)
	}
}

func TestClearBackupDestinationRemovesRowAndAudits(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatalf("ClearBackupDestination: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 0 {
		t.Fatalf("destination rows after clear = %d", n)
	}
	got, err := cs.GetBackupDestination(ctx)
	if err != nil || got.Configured {
		t.Fatalf("Get after clear = %+v, %v", got, err)
	}
	audits := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationClear)
	if len(audits) != 1 || !strings.Contains(audits[0], `"removed": true`) {
		t.Fatalf("clear audits = %v", audits)
	}

	// Clearing an absent destination is idempotent and still audited.
	if err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatalf("second clear: %v", err)
	}
	audits = destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationClear)
	if len(audits) != 2 || !strings.Contains(audits[1], `"removed": false`) {
		t.Fatalf("second clear audits = %v", audits)
	}
}

func TestClearBackupDestinationAuditFailureKeepsTheRow(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID})
	if !errors.Is(err, ErrAuthAuditInsertFailed) {
		t.Fatalf("Clear error = %v, want %v", err, ErrAuthAuditInsertFailed)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 1 {
		t.Fatalf("failed clear removed the destination")
	}
}

func TestDeletingTheUpdatingPrincipalKeepsTheDestination(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	// Audit rows reference the principal without ON DELETE; drop them first
	// so only the destination foreign key is exercised.
	if _, err := cs.db.ExecContext(ctx, `DELETE FROM cloud_auth_audit_log; DELETE FROM cloud_principals WHERE id = `+adminID); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	got, err := cs.GetBackupDestination(ctx)
	if err != nil || !got.Configured || got.UpdatedByPrincipalID != "" {
		t.Fatalf("Get after principal delete = %+v, %v", got, err)
	}
}
