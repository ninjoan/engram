package cloudstore

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"reflect"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// External backup destination. At most one destination exists, of one kind:
// an S3-compatible bucket, a Dropbox folder or a Google Drive folder. Its
// secrets are sealed by a BackupSecretSealer (internal/cloud/backupcrypto
// keyed by ENGRAM_CLOUD_BACKUP_KEY) before they reach the database, are never
// returned by GetBackupDestination, and are only opened for the uploader.
// Each sealed secret is bound to its field, the kind and every non-secret
// setting of the destination (see backupDestinationTarget.associatedData).
// The Dropbox and Google Drive kinds live in backup_destination_kinds.go.

const (
	BackupDestinationKindS3      = "s3"
	BackupDestinationKindDropbox = "dropbox"
	BackupDestinationKindGDrive  = "gdrive"

	AuthAuditActionBackupDestinationUpdate = "backup.destination.update"
	AuthAuditActionBackupDestinationClear  = "backup.destination.clear"
	// AuthAuditActionBackupDestinationAuthorize is recorded when the OAuth
	// refresh token of a Google Drive destination is stored.
	AuthAuditActionBackupDestinationAuthorize = "backup.destination.authorize"
	// AuthAuditActionBackupDestinationTest is recorded by the dashboard
	// "Test connection" route: outcome success, or failure with a reason
	// code (auth_failed, bucket_not_found, network, unexpected_response,
	// key_mismatch, not_configured).
	AuthAuditActionBackupDestinationTest = "backup.destination.test"

	backupDestinationFieldAccessKeyID     = "access_key_id"
	backupDestinationFieldSecretAccessKey = "secret_access_key"
)

var (
	ErrInvalidBackupDestination       = errors.New("cloudstore: invalid backup destination")
	ErrBackupDestinationNotConfigured = errors.New("cloudstore: backup destination is not configured")
	ErrBackupDestinationKeyRequired   = errors.New("cloudstore: ENGRAM_CLOUD_BACKUP_KEY is required for backup destination credentials")
	// ErrBackupDestinationKindMismatch refuses a kind-specific operation on
	// a destination of another kind.
	ErrBackupDestinationKindMismatch = errors.New("cloudstore: the backup destination is of another kind")
	// ErrBackupDestinationKeyChanged refuses adding a secret to a destination
	// whose other secrets were sealed with another key.
	ErrBackupDestinationKeyChanged = errors.New("cloudstore: the backup destination was saved with another ENGRAM_CLOUD_BACKUP_KEY; save it again")
)

// backupDestinationKindShapeCheck is the per-kind CHECK of
// cloud_backup_destinations: each kind fills its own columns and leaves the
// others empty. A gdrive row may lack its refresh token (pending
// authorization).
const backupDestinationKindShapeCheck = `CASE kind
				WHEN 's3' THEN endpoint <> '' AND bucket <> '' AND access_key_id_ciphertext <> '' AND secret_access_key_ciphertext <> ''
					AND client_id = '' AND folder = '' AND client_secret_ciphertext = '' AND refresh_token_ciphertext = ''
				WHEN 'dropbox' THEN client_id <> '' AND folder <> '' AND client_secret_ciphertext <> '' AND refresh_token_ciphertext <> ''
					AND endpoint = '' AND region = '' AND bucket = '' AND prefix = '' AND access_key_id_hint = '' AND access_key_id_ciphertext = '' AND secret_access_key_ciphertext = ''
				WHEN 'gdrive' THEN client_id <> '' AND folder <> '' AND client_secret_ciphertext <> ''
					AND endpoint = '' AND region = '' AND bucket = '' AND prefix = '' AND access_key_id_hint = '' AND access_key_id_ciphertext = '' AND secret_access_key_ciphertext = ''
				ELSE FALSE END`

// BackupSecretSealer seals one credential bound to associatedData.
type BackupSecretSealer interface {
	Fingerprint() string
	Seal(associatedData string, plaintext []byte) (string, error)
}

// BackupSecretOpener opens a credential sealed by a BackupSecretSealer.
type BackupSecretOpener interface {
	Open(associatedData, sealed string) ([]byte, error)
}

// BackupDestinationActor identifies who changes the destination, for the
// audit row and updated_by_principal_id.
type BackupDestinationActor struct {
	PrincipalID string
	Source      string
}

// PutBackupDestinationParams is a complete destination. Both credentials are
// required on every update because they are sealed together with the
// destination they authorize.
type PutBackupDestinationParams struct {
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string `json:"-"`
	SecretAccessKey string `json:"-"`
	Actor           BackupDestinationActor
}

// BackupDestination is the non-secret view of the destination. It never holds
// a credential or ciphertext; AccessKeyIDHint shows only the last characters.
// Endpoint through AccessKeyIDHint describe an s3 destination; Dropbox and
// GDrive describe the other kinds and are zero for any other kind.
type BackupDestination struct {
	Configured           bool                   `json:"configured"`
	Kind                 string                 `json:"kind,omitempty"`
	Endpoint             string                 `json:"endpoint,omitempty"`
	Region               string                 `json:"region,omitempty"`
	Bucket               string                 `json:"bucket,omitempty"`
	Prefix               string                 `json:"prefix,omitempty"`
	AccessKeyIDHint      string                 `json:"access_key_id_hint,omitempty"`
	Dropbox              DropboxDestinationView `json:"dropbox,omitzero"`
	GDrive               GDriveDestinationView  `json:"gdrive,omitzero"`
	KeyFingerprint       string                 `json:"key_fingerprint,omitempty"`
	UpdatedByPrincipalID string                 `json:"updated_by_principal_id,omitempty"`
	UpdatedAt            time.Time              `json:"updated_at,omitzero"`
}

// BackupDestinationTest is the newest connection test of the current
// destination, read from its backup.destination.test audit row. The zero
// value means the destination was not tested since it was last saved.
type BackupDestinationTest struct {
	OccurredAt       time.Time
	ActorPrincipalID string
	// ActorName is the display name of the principal that ran the test.
	ActorName string
	Succeeded bool
	// ReasonCode is the failure reason code; empty on success.
	ReasonCode string
}

// Tested reports whether a test was recorded since the last save.
func (t BackupDestinationTest) Tested() bool {
	return !t.OccurredAt.IsZero()
}

// BackupDestinationCredentials is the opened destination, for the uploader
// only. It formats and JSON-encodes without its credentials.
type BackupDestinationCredentials struct {
	Endpoint        string
	Region          string
	Bucket          string
	Prefix          string
	AccessKeyID     string `json:"-"`
	SecretAccessKey string `json:"-"`
}

// Format prints the destination with both credentials redacted.
func (c BackupDestinationCredentials) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, fmt.Sprintf("{Endpoint:%s Region:%s Bucket:%s Prefix:%s AccessKeyID:redacted SecretAccessKey:redacted}", c.Endpoint, c.Region, c.Bucket, c.Prefix))
}

// backupDestinationTarget is the validated, normalized non-secret part of a
// destination: endpoint..prefix for s3, clientID and folder for the others.
type backupDestinationTarget struct {
	kind, endpoint, region, bucket, prefix string
	clientID, folder                       string
}

// associatedData binds a sealed credential to its field and to the exact
// destination it authorizes, so a database write that redirects the endpoint,
// bucket, folder or OAuth client makes the credentials unopenable instead of
// sending them there. The s3 form is the one stored rows were sealed with
// before other kinds existed and must not change.
func (d backupDestinationTarget) associatedData(field string) string {
	fields := []string{d.kind, d.endpoint, d.region, d.bucket, d.prefix}
	if d.kind != BackupDestinationKindS3 {
		fields = []string{d.kind, d.clientID, d.folder}
	}
	bound, _ := json.Marshal(fields)
	return "engram-backup-destination:v1:" + field + ":" + string(bound)
}

// sealedBackupDestination is a stored destination row: the target, its
// ciphertexts (empty for the columns its kind does not use) and the hint and
// fingerprint shown in the non-secret view.
type sealedBackupDestination struct {
	target                               backupDestinationTarget
	accessKeyIDHint                      string
	accessCipher, secretCipher           string
	clientSecretCipher, refreshTokCipher string
	fingerprint                          string
}

// GetBackupDestination returns the non-secret destination view without
// opening any credential. Configured is false when none is stored.
func (cs *CloudStore) GetBackupDestination(ctx context.Context) (BackupDestination, error) {
	if cs == nil || cs.db == nil {
		return BackupDestination{}, fmt.Errorf("cloudstore: not initialized")
	}
	var d BackupDestination
	var clientID, folder string
	var authorized bool
	err := cs.db.QueryRowContext(ctx, `
		SELECT kind, endpoint, region, bucket, prefix, access_key_id_hint, key_fingerprint, COALESCE(updated_by_principal_id::text, ''), updated_at,
			client_id, folder, refresh_token_ciphertext <> ''
		FROM cloud_backup_destinations WHERE id = 1`).Scan(&d.Kind, &d.Endpoint, &d.Region, &d.Bucket, &d.Prefix, &d.AccessKeyIDHint, &d.KeyFingerprint, &d.UpdatedByPrincipalID, &d.UpdatedAt,
		&clientID, &folder, &authorized)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupDestination{}, nil
	}
	if err != nil {
		return BackupDestination{}, fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	switch d.Kind {
	case BackupDestinationKindDropbox:
		d.Dropbox = DropboxDestinationView{AppKey: clientID, FolderPath: folder}
	case BackupDestinationKindGDrive:
		d.GDrive = GDriveDestinationView{ClientID: clientID, FolderName: folder, Authorized: authorized}
	}
	d.Configured = true
	return d, nil
}

// LatestBackupDestinationTest returns the newest backup.destination.test
// audit row recorded after the destination's updated_at, so saving the
// destination again resets it. It is zero when no destination is stored or
// none was tested since the last save. It reads only the audit columns and
// never a credential.
func (cs *CloudStore) LatestBackupDestinationTest(ctx context.Context) (BackupDestinationTest, error) {
	if cs == nil || cs.db == nil {
		return BackupDestinationTest{}, fmt.Errorf("cloudstore: not initialized")
	}
	var test BackupDestinationTest
	var outcome string
	err := cs.db.QueryRowContext(ctx, `
		SELECT a.occurred_at, COALESCE(a.actor_principal_id::text, ''), COALESCE(p.display_name, ''), a.outcome, COALESCE(a.reason_code, '')
		FROM cloud_auth_audit_log a
		JOIN cloud_backup_destinations d ON d.id = 1
		LEFT JOIN cloud_principals p ON p.id = a.actor_principal_id
		WHERE a.action = $1 AND a.occurred_at > d.updated_at
		ORDER BY a.occurred_at DESC, a.id DESC
		LIMIT 1`, AuthAuditActionBackupDestinationTest).Scan(&test.OccurredAt, &test.ActorPrincipalID, &test.ActorName, &outcome, &test.ReasonCode)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupDestinationTest{}, nil
	}
	if err != nil {
		return BackupDestinationTest{}, fmt.Errorf("cloudstore: read latest backup destination test: %w", err)
	}
	test.Succeeded = outcome == "success"
	if test.Succeeded {
		test.ReasonCode = ""
	}
	return test, nil
}

// PutBackupDestination validates params, seals both credentials and stores
// the destination with its audit row in one transaction. Invalid input writes
// nothing; an audit failure rolls the destination back.
func (cs *CloudStore) PutBackupDestination(ctx context.Context, params PutBackupDestinationParams, sealer BackupSecretSealer) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(sealer) {
		return ErrBackupDestinationKeyRequired
	}
	target, accessKeyID, secret, err := normalizeBackupDestination(params)
	if err != nil {
		return err
	}
	accessCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldAccessKeyID), []byte(accessKeyID))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination access key id: %w", err)
	}
	secretCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldSecretAccessKey), []byte(secret))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination secret access key: %w", err)
	}
	hint := backupAccessKeyIDHint(accessKeyID)
	fingerprint := sealer.Fingerprint()
	row := sealedBackupDestination{target: target, accessKeyIDHint: hint, accessCipher: accessCipher, secretCipher: secretCipher, fingerprint: fingerprint}
	// Metadata is built here, never from caller input, so it cannot carry a
	// credential or ciphertext.
	return cs.storeBackupDestination(ctx, row, params.Actor, map[string]any{
		"kind": target.kind, "endpoint": target.endpoint, "region": target.region, "bucket": target.bucket, "prefix": target.prefix,
		"access_key_id_hint": hint, "key_fingerprint": fingerprint,
	})
}

// storeBackupDestination replaces the single destination row with row, every
// column included so no setting of a previous kind survives, and records the
// backup.destination.update audit row with metadata in the same transaction.
// An audit failure rolls the destination back.
func (cs *CloudStore) storeBackupDestination(ctx context.Context, row sealedBackupDestination, actor BackupDestinationActor, metadata map[string]any) error {
	t := row.target
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup destination tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, prefix, access_key_id_hint, access_key_id_ciphertext, secret_access_key_ciphertext,
			client_id, folder, client_secret_ciphertext, refresh_token_ciphertext, key_fingerprint, updated_by_principal_id, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, NOW())
		ON CONFLICT (id) DO UPDATE SET
			kind = EXCLUDED.kind, endpoint = EXCLUDED.endpoint, region = EXCLUDED.region, bucket = EXCLUDED.bucket, prefix = EXCLUDED.prefix,
			access_key_id_hint = EXCLUDED.access_key_id_hint, access_key_id_ciphertext = EXCLUDED.access_key_id_ciphertext,
			secret_access_key_ciphertext = EXCLUDED.secret_access_key_ciphertext,
			client_id = EXCLUDED.client_id, folder = EXCLUDED.folder, client_secret_ciphertext = EXCLUDED.client_secret_ciphertext,
			refresh_token_ciphertext = EXCLUDED.refresh_token_ciphertext, key_fingerprint = EXCLUDED.key_fingerprint,
			updated_by_principal_id = EXCLUDED.updated_by_principal_id, updated_at = EXCLUDED.updated_at`,
		t.kind, t.endpoint, t.region, t.bucket, t.prefix, row.accessKeyIDHint, row.accessCipher, row.secretCipher,
		t.clientID, t.folder, row.clientSecretCipher, row.refreshTokCipher, row.fingerprint, nullableID(actor.PrincipalID),
	); err != nil {
		return fmt.Errorf("cloudstore: store backup destination: %w", err)
	}
	audit := AuthAuditEvent{
		ActorPrincipalID: actor.PrincipalID,
		ActorSource:      actor.Source,
		Action:           AuthAuditActionBackupDestinationUpdate,
		Outcome:          "success",
		Metadata:         metadata,
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup destination tx: %w", err)
	}
	return nil
}

// ClearBackupDestination removes the destination of any kind and audits it
// in one transaction, naming the removed kind. Clearing an absent
// destination is audited with removed=false.
func (cs *CloudStore) ClearBackupDestination(ctx context.Context, actor BackupDestinationActor) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup destination clear tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var kind string
	err = tx.QueryRowContext(ctx, `DELETE FROM cloud_backup_destinations WHERE id = 1 RETURNING kind`).Scan(&kind)
	if err != nil && !errors.Is(err, sql.ErrNoRows) {
		return fmt.Errorf("cloudstore: clear backup destination: %w", err)
	}
	metadata := map[string]any{"removed": kind != ""}
	if kind != "" {
		metadata["kind"] = kind
	}
	audit := AuthAuditEvent{
		ActorPrincipalID: actor.PrincipalID,
		ActorSource:      actor.Source,
		Action:           AuthAuditActionBackupDestinationClear,
		Outcome:          "success",
		Metadata:         metadata,
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup destination clear tx: %w", err)
	}
	return nil
}

// OpenBackupDestinationCredentials returns the s3 destination with its
// opened credentials. It is meant only for the uploader and the S3
// connection test; a wrong or rotated key surfaces the opener's key-mismatch
// error, and a destination of another kind wraps
// ErrBackupDestinationKindMismatch without opening anything.
func (cs *CloudStore) OpenBackupDestinationCredentials(ctx context.Context, opener BackupSecretOpener) (BackupDestinationCredentials, error) {
	row, err := cs.readSealedBackupDestination(ctx, opener)
	if err != nil {
		return BackupDestinationCredentials{}, err
	}
	if row.target.kind != BackupDestinationKindS3 {
		return BackupDestinationCredentials{}, fmt.Errorf("%w: it is a %s destination, not s3", ErrBackupDestinationKindMismatch, row.target.kind)
	}
	return openS3BackupDestination(row, opener)
}

// OpenBackupDestination returns the destination of any kind with its opened
// secrets, for the uploader only. A Google Drive destination pending
// authorization opens with an empty refresh token
// (GDriveDestinationCredentials.Authorized reports false).
func (cs *CloudStore) OpenBackupDestination(ctx context.Context, opener BackupSecretOpener) (OpenedBackupDestination, error) {
	row, err := cs.readSealedBackupDestination(ctx, opener)
	if err != nil {
		return OpenedBackupDestination{}, err
	}
	switch row.target.kind {
	case BackupDestinationKindS3:
		creds, err := openS3BackupDestination(row, opener)
		if err != nil {
			return OpenedBackupDestination{}, err
		}
		return OpenedBackupDestination{Kind: BackupDestinationKindS3, S3: creds}, nil
	case BackupDestinationKindDropbox:
		creds, err := openDropboxBackupDestination(row, opener)
		if err != nil {
			return OpenedBackupDestination{}, err
		}
		return OpenedBackupDestination{Kind: BackupDestinationKindDropbox, Dropbox: creds}, nil
	case BackupDestinationKindGDrive:
		creds, err := openGDriveBackupDestination(row, opener)
		if err != nil {
			return OpenedBackupDestination{}, err
		}
		return OpenedBackupDestination{Kind: BackupDestinationKindGDrive, GDrive: creds}, nil
	}
	return OpenedBackupDestination{}, fmt.Errorf("%w: unknown kind %q", ErrBackupDestinationKindMismatch, row.target.kind)
}

// readSealedBackupDestination reads the stored row without opening it.
func (cs *CloudStore) readSealedBackupDestination(ctx context.Context, opener BackupSecretOpener) (sealedBackupDestination, error) {
	if cs == nil || cs.db == nil {
		return sealedBackupDestination{}, fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(opener) {
		return sealedBackupDestination{}, ErrBackupDestinationKeyRequired
	}
	var row sealedBackupDestination
	t := &row.target
	err := cs.db.QueryRowContext(ctx, `
		SELECT kind, endpoint, region, bucket, prefix, access_key_id_ciphertext, secret_access_key_ciphertext,
			client_id, folder, client_secret_ciphertext, refresh_token_ciphertext, key_fingerprint
		FROM cloud_backup_destinations WHERE id = 1`).Scan(&t.kind, &t.endpoint, &t.region, &t.bucket, &t.prefix, &row.accessCipher, &row.secretCipher,
		&t.clientID, &t.folder, &row.clientSecretCipher, &row.refreshTokCipher, &row.fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return sealedBackupDestination{}, ErrBackupDestinationNotConfigured
	}
	if err != nil {
		return sealedBackupDestination{}, fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	return row, nil
}

func openS3BackupDestination(row sealedBackupDestination, opener BackupSecretOpener) (BackupDestinationCredentials, error) {
	target := row.target
	accessKeyID, err := opener.Open(target.associatedData(backupDestinationFieldAccessKeyID), row.accessCipher)
	if err != nil {
		return BackupDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination access key id: %w", err)
	}
	secret, err := opener.Open(target.associatedData(backupDestinationFieldSecretAccessKey), row.secretCipher)
	if err != nil {
		return BackupDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination secret access key: %w", err)
	}
	return BackupDestinationCredentials{
		Endpoint: target.endpoint, Region: target.region, Bucket: target.bucket, Prefix: target.prefix,
		AccessKeyID: string(accessKeyID), SecretAccessKey: string(secret),
	}, nil
}

// isNilBackupKeyHolder reports a nil sealer or opener, including a typed nil
// pointer such as a (*backupcrypto.Sealer)(nil) from an unset key, which
// would otherwise pass a plain nil check and panic on first use.
func isNilBackupKeyHolder(holder any) bool {
	if holder == nil {
		return true
	}
	v := reflect.ValueOf(holder)
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface, reflect.Map, reflect.Slice, reflect.Func, reflect.Chan:
		return v.IsNil()
	}
	return false
}

// ValidateBackupDestination applies exactly the validation and normalization
// of PutBackupDestination without sealing or storing anything, for checking a
// destination before it is saved. A rejection wraps
// ErrInvalidBackupDestination with a fixed reason that never echoes a
// credential or the endpoint; params.Actor is ignored.
func ValidateBackupDestination(params PutBackupDestinationParams) (BackupDestinationCredentials, error) {
	target, accessKeyID, secret, err := normalizeBackupDestination(params)
	if err != nil {
		return BackupDestinationCredentials{}, err
	}
	return BackupDestinationCredentials{
		Endpoint: target.endpoint, Region: target.region, Bucket: target.bucket, Prefix: target.prefix,
		AccessKeyID: accessKeyID, SecretAccessKey: secret,
	}, nil
}

// normalizeBackupDestination validates params. Error messages never echo a
// credential or the endpoint (which could carry userinfo).
func normalizeBackupDestination(params PutBackupDestinationParams) (backupDestinationTarget, string, string, error) {
	invalid := func(reason string) (backupDestinationTarget, string, string, error) {
		return backupDestinationTarget{}, "", "", fmt.Errorf("%w: %s", ErrInvalidBackupDestination, reason)
	}
	endpoint, reason := normalizeBackupEndpoint(params.Endpoint)
	if reason != "" {
		return invalid(reason)
	}
	region := strings.TrimSpace(params.Region)
	if region == "" || len(region) > 64 || strings.IndexFunc(region, func(r rune) bool {
		return !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || r == '-' || r == '_')
	}) >= 0 {
		return invalid("region must be 1-64 letters, digits, '-' or '_' (use \"auto\" for Cloudflare R2)")
	}
	bucket := strings.TrimSpace(params.Bucket)
	if reason := validateBackupBucket(bucket); reason != "" {
		return invalid(reason)
	}
	prefix := strings.TrimSpace(params.Prefix)
	if reason := validateBackupPrefix(prefix); reason != "" {
		return invalid(reason)
	}
	accessKeyID := strings.TrimSpace(params.AccessKeyID)
	if !validBackupCredential(accessKeyID, 128) {
		return invalid("access key id must be 1-128 printable characters without spaces")
	}
	secret := strings.TrimSpace(params.SecretAccessKey)
	if !validBackupCredential(secret, 256) {
		return invalid("secret access key must be 1-256 printable characters without spaces")
	}
	target := backupDestinationTarget{kind: BackupDestinationKindS3, endpoint: endpoint, region: region, bucket: bucket, prefix: prefix}
	return target, accessKeyID, secret, nil
}

// normalizeBackupEndpoint requires an https origin; plain http is allowed only
// for loopback hosts (local MinIO). It returns scheme://host[:port].
func normalizeBackupEndpoint(raw string) (string, string) {
	const reason = "endpoint must be an https origin such as https://<account>.r2.cloudflarestorage.com (http only for loopback hosts)"
	raw = strings.TrimSpace(raw)
	parsed, err := url.Parse(raw)
	if err != nil || raw == "" || parsed.Opaque != "" || parsed.User != nil || parsed.Hostname() == "" ||
		parsed.RawQuery != "" || parsed.ForceQuery || parsed.Fragment != "" || (parsed.Path != "" && parsed.Path != "/") {
		return "", reason
	}
	scheme := strings.ToLower(parsed.Scheme)
	switch scheme {
	case "https":
	case "http":
		host := parsed.Hostname()
		ip := net.ParseIP(host)
		if !strings.EqualFold(host, "localhost") && (ip == nil || !ip.IsLoopback()) {
			return "", reason
		}
	default:
		return "", reason
	}
	return scheme + "://" + parsed.Host, ""
}

// validateBackupBucket applies the S3 bucket naming rules.
func validateBackupBucket(bucket string) string {
	const reason = "bucket must be 3-63 lowercase letters, digits, '.' or '-', start and end with a letter or digit, and not look like an IP address"
	if len(bucket) < 3 || len(bucket) > 63 || strings.Contains(bucket, "..") || net.ParseIP(bucket) != nil {
		return reason
	}
	for i, r := range bucket {
		alnum := r >= 'a' && r <= 'z' || r >= '0' && r <= '9'
		if (i == 0 || i == len(bucket)-1) && !alnum {
			return reason
		}
		if !alnum && r != '.' && r != '-' {
			return reason
		}
	}
	return ""
}

// validateBackupPrefix allows an optional relative key prefix.
func validateBackupPrefix(prefix string) string {
	if prefix == "" {
		return ""
	}
	if len(prefix) > 512 || !utf8.ValidString(prefix) || strings.IndexFunc(prefix, unicode.IsControl) >= 0 || strings.Contains(prefix, `\`) {
		return "prefix must be at most 512 printable characters without backslashes"
	}
	if strings.HasPrefix(prefix, "/") {
		return "prefix must not start with '/'"
	}
	segments := strings.Split(prefix, "/")
	for i, segment := range segments {
		if segment == "." || segment == ".." || (segment == "" && i != len(segments)-1) {
			return "prefix must not contain '.', '..' or empty path segments"
		}
	}
	return ""
}

func validBackupCredential(value string, maxLen int) bool {
	if value == "" || len(value) > maxLen {
		return false
	}
	for i := 0; i < len(value); i++ {
		if value[i] < 0x21 || value[i] > 0x7e {
			return false
		}
	}
	return true
}

// backupAccessKeyIDHint keeps the last four characters of a long access key
// id and nothing of a short one.
func backupAccessKeyIDHint(accessKeyID string) string {
	if len(accessKeyID) < 12 {
		return "****"
	}
	return "****" + accessKeyID[len(accessKeyID)-4:]
}
