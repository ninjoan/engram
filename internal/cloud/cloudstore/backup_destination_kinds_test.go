package cloudstore

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
)

const (
	testDropboxAppKey       = "dbxappkey7q4zexample"
	testDropboxAppSecret    = "dbx-app-secret-do-not-leak-0001"
	testDropboxRefreshToken = "dbx-refresh-token-do-not-leak-AAAAAAAAAAAAAAAAAAAAAAAA"
	testGDriveClientID      = "123456789012-abcdefexample.apps.googleusercontent.com"
	testGDriveClientSecret  = "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leak"
	testGDriveRefreshToken  = "1//gdrive-refresh-token-do-not-leak-BBBBBBBBBBBBBBBBBBBB"
)

var kindSecrets = []string{testDropboxAppSecret, testDropboxRefreshToken, testGDriveClientSecret, testGDriveRefreshToken}

func validDropboxParams(adminID string) PutDropboxDestinationParams {
	return PutDropboxDestinationParams{
		AppKey:       testDropboxAppKey,
		FolderPath:   "/Engram backups",
		AppSecret:    testDropboxAppSecret,
		RefreshToken: testDropboxRefreshToken,
		Actor:        BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"},
	}
}

func validGDriveParams(adminID string) PutGDriveDestinationParams {
	return PutGDriveDestinationParams{
		ClientID:     testGDriveClientID,
		FolderName:   "Engram backups",
		ClientSecret: testGDriveClientSecret,
		Actor:        BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"},
	}
}

func assertNoKindSecrets(t *testing.T, what, text string, extra ...string) {
	t.Helper()
	for _, secret := range append(append([]string(nil), kindSecrets...), extra...) {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s leaks %q: %s", what, secret, text)
		}
	}
}

// oldBackupDestinationsDDL is the table as T5-T14 created it: S3 only.
const oldBackupDestinationsDDL = `CREATE TABLE cloud_backup_destinations (
	id SMALLINT PRIMARY KEY DEFAULT 1 CHECK (id = 1),
	kind TEXT NOT NULL CHECK (kind IN ('s3')),
	endpoint TEXT NOT NULL,
	region TEXT NOT NULL,
	bucket TEXT NOT NULL,
	prefix TEXT NOT NULL DEFAULT '',
	access_key_id_hint TEXT NOT NULL DEFAULT '',
	access_key_id_ciphertext TEXT NOT NULL,
	secret_access_key_ciphertext TEXT NOT NULL,
	key_fingerprint TEXT NOT NULL,
	updated_by_principal_id BIGINT REFERENCES cloud_principals(id) ON DELETE SET NULL,
	updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

// An S3 row stored by the previous schema survives the migration unchanged,
// still opens, and the migrated table accepts the new kinds. Running the
// migration again changes nothing.
func TestBackupDestinationMigrationKeepsExistingS3Row(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}
	var kind, endpoint, region, bucket, prefix, hint, accessCipher, secretCipher, fingerprint string
	var updatedAt time.Time
	if err := cs.db.QueryRowContext(ctx, `SELECT kind, endpoint, region, bucket, prefix, access_key_id_hint, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, updated_at FROM cloud_backup_destinations`).
		Scan(&kind, &endpoint, &region, &bucket, &prefix, &hint, &accessCipher, &secretCipher, &fingerprint, &updatedAt); err != nil {
		t.Fatal(err)
	}
	before, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatal(err)
	}
	// Recreate the old table holding the very same row.
	if _, err := cs.db.ExecContext(ctx, `DROP TABLE cloud_backup_destinations`); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, oldBackupDestinationsDDL); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, prefix, access_key_id_hint, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, updated_by_principal_id, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)`, kind, endpoint, region, bucket, prefix, hint, accessCipher, secretCipher, fingerprint, adminID, updatedAt); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint) VALUES (1, 'dropbox', '', '', '', 'x', 'y', 'z') ON CONFLICT (id) DO UPDATE SET kind = EXCLUDED.kind`); err == nil {
		t.Fatal("the old table must refuse a dropbox row (fixture check)")
	}
	for i := range 2 {
		if err := cs.migrateSchema(ctx); err != nil {
			t.Fatalf("migrate #%d: %v", i+1, err)
		}
	}
	after, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatalf("Get after migration: %v", err)
	}
	if after != before || after.Kind != BackupDestinationKindS3 {
		t.Fatalf("Get after migration = %+v, want %+v", after, before)
	}
	opened, err := cs.OpenBackupDestinationCredentials(ctx, sealer)
	if err != nil {
		t.Fatalf("Open after migration: %v", err)
	}
	if opened.AccessKeyID != testDestinationAccessKeyID || opened.SecretAccessKey != testDestinationSecret || opened.Bucket != "engram-backups" {
		t.Fatalf("Open after migration = %v", opened)
	}
	generic, err := cs.OpenBackupDestination(ctx, sealer)
	if err != nil || generic.Kind != BackupDestinationKindS3 || generic.S3 != opened {
		t.Fatalf("OpenBackupDestination after migration = %v, %v", generic, err)
	}
	var checks int
	if err := cs.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM pg_constraint WHERE conrelid = 'cloud_backup_destinations'::regclass AND contype = 'c' AND pg_get_constraintdef(oid) LIKE '%gdrive%'`).Scan(&checks); err != nil {
		t.Fatal(err)
	}
	if checks != 2 {
		t.Fatalf("migrated table has %d check constraints naming gdrive, want 2 (kind and per-kind shape)", checks)
	}
	if err := cs.PutDropboxDestination(ctx, validDropboxParams(adminID), sealer); err != nil {
		t.Fatalf("PutDropboxDestination on the migrated table: %v", err)
	}
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatalf("PutBackupDestination back to s3: %v", err)
	}
}

// The per-kind shape constraint refuses rows whose columns do not match
// their kind, so a direct write cannot store a half-configured destination.
func TestBackupDestinationTableRefusesMismatchedKindShape(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	for name, query := range map[string]string{
		"s3 with dropbox columns":   `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, client_id) VALUES (1, 's3', 'https://h', 'auto', 'b', 'x', 'y', 'f', 'appkey')`,
		"s3 without secrets":        `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint) VALUES (1, 's3', 'https://h', 'auto', 'b', '', '', 'f')`,
		"dropbox without token":     `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, client_id, folder, client_secret_ciphertext) VALUES (1, 'dropbox', '', '', '', '', '', 'f', 'k', '/f', 'x')`,
		"dropbox with s3 columns":   `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, client_id, folder, client_secret_ciphertext, refresh_token_ciphertext) VALUES (1, 'dropbox', 'https://h', '', '', '', '', 'f', 'k', '/f', 'x', 'y')`,
		"gdrive without secret":     `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, client_id, folder) VALUES (1, 'gdrive', '', '', '', '', '', 'f', 'c', 'F')`,
		"unknown kind":              `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint) VALUES (1, 'ftp', 'https://h', 'auto', 'b', 'x', 'y', 'f')`,
		"gdrive with access cipher": `INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, client_id, folder, client_secret_ciphertext) VALUES (1, 'gdrive', '', '', '', 'x', '', 'f', 'c', 'F', 's')`,
	} {
		if _, err := cs.db.ExecContext(ctx, query); err == nil {
			t.Fatalf("%s: the table accepted a mismatched row", name)
		}
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 0 {
		t.Fatalf("rows = %d, want 0", n)
	}
}

func TestPutDropboxDestinationRoundTrip(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutDropboxDestination(ctx, validDropboxParams(adminID), sealer); err != nil {
		t.Fatalf("PutDropboxDestination: %v", err)
	}
	row := destinationRowText(t, cs)
	assertNoKindSecrets(t, "destination row", row)
	var secretCipher, tokenCipher, fingerprint string
	if err := cs.db.QueryRowContext(ctx, `SELECT client_secret_ciphertext, refresh_token_ciphertext, key_fingerprint FROM cloud_backup_destinations`).Scan(&secretCipher, &tokenCipher, &fingerprint); err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(secretCipher, "v1:") || !strings.HasPrefix(tokenCipher, "v1:") || fingerprint != sealer.Fingerprint() {
		t.Fatalf("columns not sealed: secret %q token %q fingerprint %q", secretCipher, tokenCipher, fingerprint)
	}

	got, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatalf("GetBackupDestination: %v", err)
	}
	want := BackupDestination{
		Configured: true, Kind: BackupDestinationKindDropbox, KeyFingerprint: sealer.Fingerprint(), UpdatedByPrincipalID: adminID, UpdatedAt: got.UpdatedAt,
		Dropbox: DropboxDestinationView{AppKey: testDropboxAppKey, FolderPath: "/Engram backups"},
	}
	if got != want || got.UpdatedAt.IsZero() {
		t.Fatalf("Get = %+v, want %+v", got, want)
	}
	encoded, _ := json.Marshal(got)
	assertNoKindSecrets(t, "Get JSON", string(encoded), secretCipher, tokenCipher)
	if !strings.Contains(string(encoded), `"folder_path":"/Engram backups"`) {
		t.Fatalf("Get JSON lacks the dropbox view: %s", encoded)
	}

	opened, err := cs.OpenBackupDestination(ctx, sealer)
	if err != nil {
		t.Fatalf("OpenBackupDestination: %v", err)
	}
	wantCreds := DropboxDestinationCredentials{AppKey: testDropboxAppKey, FolderPath: "/Engram backups", AppSecret: testDropboxAppSecret, RefreshToken: testDropboxRefreshToken}
	if opened.Kind != BackupDestinationKindDropbox || opened.Dropbox != wantCreds || opened.S3 != (BackupDestinationCredentials{}) || opened.GDrive != (GDriveDestinationCredentials{}) {
		t.Fatalf("Open = %v", opened)
	}
	if _, err := cs.OpenBackupDestinationCredentials(ctx, sealer); !errors.Is(err, ErrBackupDestinationKindMismatch) {
		t.Fatalf("S3 open of a dropbox destination error = %v, want %v", err, ErrBackupDestinationKindMismatch)
	}

	audits := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationUpdate)
	if len(audits) != 1 {
		t.Fatalf("update audits = %d, want 1", len(audits))
	}
	assertNoKindSecrets(t, "audit metadata", audits[0], secretCipher, tokenCipher, testDropboxAppKey)
	for _, want := range []string{`"kind": "dropbox"`, `"folder_path": "/Engram backups"`, `"app_key_hint": "****mple"`} {
		if !strings.Contains(audits[0], want) {
			t.Fatalf("audit metadata %s lacks %s", audits[0], want)
		}
	}

	if err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatalf("Clear: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 0 {
		t.Fatalf("rows after clear = %d", n)
	}
	clears := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationClear)
	if len(clears) != 1 || !strings.Contains(clears[0], `"removed": true`) || !strings.Contains(clears[0], `"kind": "dropbox"`) {
		t.Fatalf("clear audits = %v", clears)
	}
	if _, err := cs.OpenBackupDestination(ctx, sealer); !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("Open after clear error = %v", err)
	}
}

// Saving a destination of another kind replaces the single row and leaves
// no column of the previous kind behind.
func TestPutDestinationOfAnotherKindReplacesEveryColumn(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutDropboxDestination(ctx, validDropboxParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	var clientID, folder, secretCipher, tokenCipher string
	if err := cs.db.QueryRowContext(ctx, `SELECT client_id, folder, client_secret_ciphertext, refresh_token_ciphertext FROM cloud_backup_destinations`).Scan(&clientID, &folder, &secretCipher, &tokenCipher); err != nil {
		t.Fatal(err)
	}
	if clientID != "" || folder != "" || secretCipher != "" || tokenCipher != "" {
		t.Fatalf("s3 row keeps dropbox columns: %q %q %q %q", clientID, folder, secretCipher, tokenCipher)
	}
	got, err := cs.GetBackupDestination(ctx)
	if err != nil || got.Kind != BackupDestinationKindS3 || got.Dropbox != (DropboxDestinationView{}) || got.Bucket != "engram-backups" {
		t.Fatalf("Get = %+v, %v", got, err)
	}
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	var endpoint, bucket, accessCipher string
	if err := cs.db.QueryRowContext(ctx, `SELECT endpoint, bucket, access_key_id_ciphertext FROM cloud_backup_destinations`).Scan(&endpoint, &bucket, &accessCipher); err != nil {
		t.Fatal(err)
	}
	if endpoint != "" || bucket != "" || accessCipher != "" {
		t.Fatalf("gdrive row keeps s3 columns: %q %q %q", endpoint, bucket, accessCipher)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`); n != 1 {
		t.Fatalf("rows = %d, want 1", n)
	}
}

func TestPutGDriveDestinationIsPendingUntilAuthorized(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	actor := BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatalf("PutGDriveDestination: %v", err)
	}
	got, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatal(err)
	}
	want := BackupDestination{
		Configured: true, Kind: BackupDestinationKindGDrive, KeyFingerprint: sealer.Fingerprint(), UpdatedByPrincipalID: adminID, UpdatedAt: got.UpdatedAt,
		GDrive: GDriveDestinationView{ClientID: testGDriveClientID, FolderName: "Engram backups", Authorized: false},
	}
	if got != want {
		t.Fatalf("pending Get = %+v, want %+v", got, want)
	}
	opened, err := cs.OpenBackupDestination(ctx, sealer)
	if err != nil {
		t.Fatalf("Open pending: %v", err)
	}
	if opened.Kind != BackupDestinationKindGDrive || opened.GDrive != (GDriveDestinationCredentials{ClientID: testGDriveClientID, FolderName: "Engram backups", ClientSecret: testGDriveClientSecret}) || opened.GDrive.Authorized() {
		t.Fatalf("Open pending = %v", opened)
	}

	time.Sleep(5 * time.Millisecond) // updated_at must move
	if err := cs.SetGDriveRefreshToken(ctx, sealer, " "+testGDriveRefreshToken+" ", actor); err != nil {
		t.Fatalf("SetGDriveRefreshToken: %v", err)
	}
	assertNoKindSecrets(t, "destination row", destinationRowText(t, cs))
	authorized, err := cs.GetBackupDestination(ctx)
	if err != nil || !authorized.GDrive.Authorized || !authorized.UpdatedAt.After(got.UpdatedAt) {
		t.Fatalf("Get after authorize = %+v, %v (before %s)", authorized, err, got.UpdatedAt)
	}
	opened, err = cs.OpenBackupDestination(ctx, sealer)
	if err != nil || opened.GDrive.RefreshToken != testGDriveRefreshToken || opened.GDrive.ClientSecret != testGDriveClientSecret || !opened.GDrive.Authorized() {
		t.Fatalf("Open after authorize = %v, %v", opened, err)
	}
	audits := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationAuthorize)
	if len(audits) != 1 || !strings.Contains(audits[0], `"kind": "gdrive"`) || !strings.Contains(audits[0], `"folder_name": "Engram backups"`) {
		t.Fatalf("authorize audits = %v", audits)
	}
	assertNoKindSecrets(t, "authorize audit", audits[0], testGDriveClientID)
	updates := destinationAuditMetadata(t, cs, AuthAuditActionBackupDestinationUpdate)
	if len(updates) != 1 || !strings.Contains(updates[0], `"kind": "gdrive"`) {
		t.Fatalf("update audits = %v", updates)
	}
	assertNoKindSecrets(t, "update audit", updates[0], testGDriveClientID)

	// Saving the destination again requires a new authorization.
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	again, err := cs.GetBackupDestination(ctx)
	if err != nil || again.GDrive.Authorized {
		t.Fatalf("Get after re-save = %+v, %v", again, err)
	}
}

func TestGDriveDestinationRefreshTokenRefusals(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	actor := BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}
	var nilSealer *backupcrypto.Sealer

	if err := cs.SetGDriveRefreshToken(ctx, sealer, testGDriveRefreshToken, actor); !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("no destination: %v", err)
	}
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if err := cs.SetGDriveRefreshToken(ctx, sealer, testGDriveRefreshToken, actor); !errors.Is(err, ErrBackupDestinationKindMismatch) {
		t.Fatalf("s3 destination: %v", err)
	}
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	for name, token := range map[string]string{"empty": "  ", "space": "a b", "control": "tok\x00en", "too long": strings.Repeat("t", 4097), "non-ascii": "tökén"} {
		err := cs.SetGDriveRefreshToken(ctx, sealer, token, actor)
		if !errors.Is(err, ErrInvalidBackupDestination) || !strings.HasPrefix(backupReason(err), "refresh token ") {
			t.Fatalf("%s token: %v", name, err)
		}
		if strings.Contains(err.Error(), token) && strings.TrimSpace(token) != "" {
			t.Fatalf("%s: error echoes the token: %v", name, err)
		}
	}
	if err := cs.SetGDriveRefreshToken(ctx, nilSealer, testGDriveRefreshToken, actor); !errors.Is(err, ErrBackupDestinationKeyRequired) {
		t.Fatalf("typed-nil sealer: %v", err)
	}
	if err := cs.SetGDriveRefreshToken(ctx, testBackupSealer(t, 2), testGDriveRefreshToken, actor); !errors.Is(err, ErrBackupDestinationKeyChanged) {
		t.Fatalf("other key: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log WHERE action = 'backup.destination.authorize'`); n != 0 {
		t.Fatalf("refused authorizations wrote %d audit rows", n)
	}
	if got, err := cs.GetBackupDestination(ctx); err != nil || got.GDrive.Authorized {
		t.Fatalf("a refused authorization changed the destination: %+v, %v", got, err)
	}
}

func backupReason(err error) string {
	return strings.TrimPrefix(err.Error(), ErrInvalidBackupDestination.Error()+": ")
}

// Every sealed secret is bound to its kind and every non-secret field: a
// direct database write that changes one makes the secrets unopenable.
func TestKindSecretsAreBoundToTheirDestination(t *testing.T) {
	ctx := context.Background()
	sealer := testBackupSealer(t, 1)
	for name, tc := range map[string]struct {
		put    func(cs *CloudStore, adminID string) error
		mutate string
	}{
		"dropbox folder": {put: func(cs *CloudStore, id string) error {
			return cs.PutDropboxDestination(ctx, validDropboxParams(id), sealer)
		}, mutate: `UPDATE cloud_backup_destinations SET folder = '/elsewhere'`},
		"dropbox app key": {put: func(cs *CloudStore, id string) error {
			return cs.PutDropboxDestination(ctx, validDropboxParams(id), sealer)
		}, mutate: `UPDATE cloud_backup_destinations SET client_id = 'attackerappkey'`},
		"dropbox to gdrive": {put: func(cs *CloudStore, id string) error {
			return cs.PutDropboxDestination(ctx, validDropboxParams(id), sealer)
		}, mutate: `UPDATE cloud_backup_destinations SET kind = 'gdrive', folder = 'Engram backups'`},
		"gdrive client id": {put: func(cs *CloudStore, id string) error {
			return cs.PutGDriveDestination(ctx, validGDriveParams(id), sealer)
		}, mutate: `UPDATE cloud_backup_destinations SET client_id = 'attacker.apps.googleusercontent.com'`},
		"gdrive folder": {put: func(cs *CloudStore, id string) error {
			return cs.PutGDriveDestination(ctx, validGDriveParams(id), sealer)
		}, mutate: `UPDATE cloud_backup_destinations SET folder = 'Other'`},
		"gdrive swapped token": {put: func(cs *CloudStore, id string) error {
			if err := cs.PutGDriveDestination(ctx, validGDriveParams(id), sealer); err != nil {
				return err
			}
			return cs.SetGDriveRefreshToken(ctx, sealer, testGDriveRefreshToken, BackupDestinationActor{PrincipalID: id, Source: "dashboard"})
		}, mutate: `UPDATE cloud_backup_destinations SET refresh_token_ciphertext = client_secret_ciphertext`},
	} {
		t.Run(name, func(t *testing.T) {
			cs := openIsolatedCloudStore(t)
			adminID := seedDestinationAdmin(t, cs)
			if err := tc.put(cs, adminID); err != nil {
				t.Fatal(err)
			}
			if _, err := cs.db.ExecContext(ctx, tc.mutate); err != nil {
				t.Fatal(err)
			}
			opened, err := cs.OpenBackupDestination(ctx, sealer)
			if !errors.Is(err, backupcrypto.ErrSealedValueInvalid) {
				t.Fatalf("Open error = %v, want %v", err, backupcrypto.ErrSealedValueInvalid)
			}
			if opened != (OpenedBackupDestination{}) {
				t.Fatalf("a refused open returned %v", opened)
			}
		})
	}
}

func TestKindDestinationsRefuseRotatedKeyAndNilSealer(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	var nilSealer *backupcrypto.Sealer
	if err := cs.PutDropboxDestination(ctx, validDropboxParams(adminID), nilSealer); !errors.Is(err, ErrBackupDestinationKeyRequired) {
		t.Fatalf("dropbox typed-nil sealer: %v", err)
	}
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), nilSealer); !errors.Is(err, ErrBackupDestinationKeyRequired) {
		t.Fatalf("gdrive typed-nil sealer: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`) + countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != 0 {
		t.Fatalf("typed-nil sealer wrote %d rows", n)
	}
	if err := cs.PutDropboxDestination(ctx, validDropboxParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.OpenBackupDestination(ctx, nilSealer); !errors.Is(err, ErrBackupDestinationKeyRequired) {
		t.Fatalf("typed-nil opener: %v", err)
	}
	if _, err := cs.OpenBackupDestination(ctx, testBackupSealer(t, 2)); !errors.Is(err, backupcrypto.ErrKeyMismatch) {
		t.Fatalf("rotated key: %v", err)
	}
}

// Invalid input writes neither the destination nor an audit row, with the
// same error as the exported validator.
func TestPutKindDestinationRejectsInvalidInputWithoutWriting(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	for name, mutate := range invalidDropboxCases() {
		params := validDropboxParams(adminID)
		mutate(&params)
		_, validateErr := ValidateDropboxDestination(params)
		putErr := cs.PutDropboxDestination(ctx, params, sealer)
		if !errors.Is(putErr, ErrInvalidBackupDestination) || validateErr == nil || validateErr.Error() != putErr.Error() {
			t.Fatalf("dropbox %s: Validate %v, Put %v", name, validateErr, putErr)
		}
	}
	for name, mutate := range invalidGDriveCases() {
		params := validGDriveParams(adminID)
		mutate(&params)
		_, validateErr := ValidateGDriveDestination(params)
		putErr := cs.PutGDriveDestination(ctx, params, sealer)
		if !errors.Is(putErr, ErrInvalidBackupDestination) || validateErr == nil || validateErr.Error() != putErr.Error() {
			t.Fatalf("gdrive %s: Validate %v, Put %v", name, validateErr, putErr)
		}
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_destinations`) + countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != 0 {
		t.Fatalf("invalid input wrote %d rows", n)
	}
}

func invalidDropboxCases() map[string]func(*PutDropboxDestinationParams) {
	return map[string]func(*PutDropboxDestinationParams){
		"empty app key":          func(p *PutDropboxDestinationParams) { p.AppKey = " " },
		"app key with space":     func(p *PutDropboxDestinationParams) { p.AppKey = "app key" },
		"app key too long":       func(p *PutDropboxDestinationParams) { p.AppKey = strings.Repeat("k", 129) },
		"empty app secret":       func(p *PutDropboxDestinationParams) { p.AppSecret = "" },
		"app secret control":     func(p *PutDropboxDestinationParams) { p.AppSecret = "abc\x00def" },
		"empty refresh token":    func(p *PutDropboxDestinationParams) { p.RefreshToken = "" },
		"refresh token too long": func(p *PutDropboxDestinationParams) { p.RefreshToken = strings.Repeat("t", 4097) },
		"empty folder":           func(p *PutDropboxDestinationParams) { p.FolderPath = "" },
		"relative folder":        func(p *PutDropboxDestinationParams) { p.FolderPath = "Engram backups" },
		"dot dot segment":        func(p *PutDropboxDestinationParams) { p.FolderPath = "/Engram/../other" },
		"dot segment":            func(p *PutDropboxDestinationParams) { p.FolderPath = "/Engram/./x" },
		"double slash":           func(p *PutDropboxDestinationParams) { p.FolderPath = "/Engram//x" },
		"backslash":              func(p *PutDropboxDestinationParams) { p.FolderPath = `/Engram\x` },
		"control char":           func(p *PutDropboxDestinationParams) { p.FolderPath = "/Engram\nx" },
		"folder too long":        func(p *PutDropboxDestinationParams) { p.FolderPath = "/" + strings.Repeat("f", 512) },
		"invalid utf8":           func(p *PutDropboxDestinationParams) { p.FolderPath = "/\xff" },
	}
}

func invalidGDriveCases() map[string]func(*PutGDriveDestinationParams) {
	return map[string]func(*PutGDriveDestinationParams){
		"empty client id":      func(p *PutGDriveDestinationParams) { p.ClientID = "" },
		"client id with space": func(p *PutGDriveDestinationParams) { p.ClientID = "client id" },
		"client id too long":   func(p *PutGDriveDestinationParams) { p.ClientID = strings.Repeat("c", 257) },
		"empty client secret":  func(p *PutGDriveDestinationParams) { p.ClientSecret = " " },
		"secret with space":    func(p *PutGDriveDestinationParams) { p.ClientSecret = "pass word" },
		"empty folder name":    func(p *PutGDriveDestinationParams) { p.FolderName = "  " },
		"folder with slash":    func(p *PutGDriveDestinationParams) { p.FolderName = "Engram/backups" },
		"folder control char":  func(p *PutGDriveDestinationParams) { p.FolderName = "Engram\tbackups" },
		"folder too long":      func(p *PutGDriveDestinationParams) { p.FolderName = strings.Repeat("f", 256) },
		"folder invalid utf8":  func(p *PutGDriveDestinationParams) { p.FolderName = "\xff" },
	}
}

func TestValidateDropboxDestination(t *testing.T) {
	for name, mutate := range invalidDropboxCases() {
		t.Run(name, func(t *testing.T) {
			params := validDropboxParams("p")
			mutate(&params)
			creds, err := ValidateDropboxDestination(params)
			if !errors.Is(err, ErrInvalidBackupDestination) || creds != (DropboxDestinationCredentials{}) {
				t.Fatalf("Validate = %v, %v", creds, err)
			}
			reason := backupReason(err)
			if !strings.HasPrefix(reason, "app key ") && !strings.HasPrefix(reason, "app secret ") && !strings.HasPrefix(reason, "refresh token ") && !strings.HasPrefix(reason, "folder path ") {
				t.Fatalf("reason %q names no field", reason)
			}
			for _, secret := range []string{testDropboxAppSecret, testDropboxRefreshToken, "abc\x00def"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q echoes a secret", err)
				}
			}
		})
	}
	for name, tc := range map[string]struct{ in, want string }{
		"as given":       {"/Engram backups", "/Engram backups"},
		"spaces trimmed": {"  /Engram backups  ", "/Engram backups"},
		"trailing slash": {"/Engram backups/", "/Engram backups"},
		"nested":         {"/Apps/Engram/prod", "/Apps/Engram/prod"},
		"root":           {"/", "/"},
	} {
		params := validDropboxParams("p")
		params.FolderPath = tc.in
		params.AppKey, params.AppSecret, params.RefreshToken = " "+testDropboxAppKey, testDropboxAppSecret+" ", " "+testDropboxRefreshToken+" "
		creds, err := ValidateDropboxDestination(params)
		want := DropboxDestinationCredentials{AppKey: testDropboxAppKey, FolderPath: tc.want, AppSecret: testDropboxAppSecret, RefreshToken: testDropboxRefreshToken}
		if err != nil || creds != want {
			t.Fatalf("%s: Validate = %v, %v; want %v", name, creds, err, want)
		}
	}
}

func TestValidateGDriveDestination(t *testing.T) {
	for name, mutate := range invalidGDriveCases() {
		t.Run(name, func(t *testing.T) {
			params := validGDriveParams("p")
			mutate(&params)
			creds, err := ValidateGDriveDestination(params)
			if !errors.Is(err, ErrInvalidBackupDestination) || creds != (GDriveDestinationCredentials{}) {
				t.Fatalf("Validate = %v, %v", creds, err)
			}
			reason := backupReason(err)
			if !strings.HasPrefix(reason, "client id ") && !strings.HasPrefix(reason, "client secret ") && !strings.HasPrefix(reason, "folder name ") {
				t.Fatalf("reason %q names no field", reason)
			}
			for _, secret := range []string{testGDriveClientSecret, "pass word"} {
				if strings.Contains(err.Error(), secret) {
					t.Fatalf("error %q echoes a secret", err)
				}
			}
		})
	}
	params := validGDriveParams("p")
	params.ClientID, params.FolderName, params.ClientSecret = " "+testGDriveClientID+" ", "  Engram backups ", " "+testGDriveClientSecret
	creds, err := ValidateGDriveDestination(params)
	want := GDriveDestinationCredentials{ClientID: testGDriveClientID, FolderName: "Engram backups", ClientSecret: testGDriveClientSecret}
	if err != nil || creds != want {
		t.Fatalf("Validate = %v, %v; want %v", creds, err, want)
	}
	if DefaultGDriveFolderName != "Engram backups" || DefaultDropboxFolderPath != "/Engram backups" {
		t.Fatalf("defaults = %q %q", DefaultGDriveFolderName, DefaultDropboxFolderPath)
	}
}

func TestKindDestinationCredentialsAndParamsNeverLeakSecrets(t *testing.T) {
	dropbox := DropboxDestinationCredentials{AppKey: testDropboxAppKey, FolderPath: "/Engram backups", AppSecret: testDropboxAppSecret, RefreshToken: testDropboxRefreshToken}
	gdrive := GDriveDestinationCredentials{ClientID: testGDriveClientID, FolderName: "Engram backups", ClientSecret: testGDriveClientSecret, RefreshToken: testGDriveRefreshToken}
	opened := OpenedBackupDestination{Kind: BackupDestinationKindDropbox, Dropbox: dropbox, GDrive: gdrive, S3: BackupDestinationCredentials{AccessKeyID: testDestinationAccessKeyID, SecretAccessKey: testDestinationSecret}}
	dropboxParams := validDropboxParams("p")
	gdriveParams := validGDriveParams("p")
	type wrapper struct{ Opened OpenedBackupDestination }
	for name, value := range map[string]any{
		"dropbox creds": dropbox, "dropbox creds ptr": &dropbox, "gdrive creds": gdrive, "opened": opened, "opened nested": wrapper{Opened: opened},
		"dropbox params": dropboxParams, "gdrive params": gdriveParams,
	} {
		encoded, err := json.Marshal(value)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		assertNoKindSecrets(t, name+" JSON", string(encoded), testDestinationSecret, testDestinationAccessKeyID)
		if !strings.Contains(string(encoded), "Engram backups") {
			t.Fatalf("%s JSON dropped non-secret fields: %s", name, encoded)
		}
		if strings.HasSuffix(name, "params") {
			continue // params carry no Format; only JSON is guarded
		}
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q"} {
			assertNoKindSecrets(t, fmt.Sprintf("%s %s", name, verb), fmt.Sprintf(verb, value), testDestinationSecret, testDestinationAccessKeyID)
		}
	}
	if s := opened.Secrets(); len(s) != 2 || s[0] != testDropboxAppSecret || s[1] != testDropboxRefreshToken {
		t.Fatalf("dropbox Secrets() = %d values", len(s))
	}
	s3 := OpenedBackupDestination{Kind: BackupDestinationKindS3, S3: BackupDestinationCredentials{AccessKeyID: testDestinationAccessKeyID, SecretAccessKey: testDestinationSecret}}
	if s := s3.Secrets(); len(s) != 2 || s[0] != testDestinationAccessKeyID || s[1] != testDestinationSecret {
		t.Fatalf("s3 Secrets() = %d values", len(s))
	}
	g := OpenedBackupDestination{Kind: BackupDestinationKindGDrive, GDrive: gdrive}
	if s := g.Secrets(); len(s) != 2 || s[0] != testGDriveClientSecret || s[1] != testGDriveRefreshToken {
		t.Fatalf("gdrive Secrets() = %d values", len(s))
	}
}
