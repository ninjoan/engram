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

// External backup destination. At most one destination exists. Its
// credentials are sealed by a BackupSecretSealer (internal/cloud/backupcrypto
// keyed by ENGRAM_CLOUD_BACKUP_KEY) before they reach the database, are never
// returned by GetBackupDestination, and are only opened for the uploader.

const (
	BackupDestinationKindS3 = "s3"

	AuthAuditActionBackupDestinationUpdate = "backup.destination.update"
	AuthAuditActionBackupDestinationClear  = "backup.destination.clear"

	backupDestinationFieldAccessKeyID     = "access_key_id"
	backupDestinationFieldSecretAccessKey = "secret_access_key"
)

var (
	ErrInvalidBackupDestination       = errors.New("cloudstore: invalid backup destination")
	ErrBackupDestinationNotConfigured = errors.New("cloudstore: backup destination is not configured")
	ErrBackupDestinationKeyRequired   = errors.New("cloudstore: ENGRAM_CLOUD_BACKUP_KEY is required for backup destination credentials")
)

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
type BackupDestination struct {
	Configured           bool      `json:"configured"`
	Kind                 string    `json:"kind,omitempty"`
	Endpoint             string    `json:"endpoint,omitempty"`
	Region               string    `json:"region,omitempty"`
	Bucket               string    `json:"bucket,omitempty"`
	Prefix               string    `json:"prefix,omitempty"`
	AccessKeyIDHint      string    `json:"access_key_id_hint,omitempty"`
	KeyFingerprint       string    `json:"key_fingerprint,omitempty"`
	UpdatedByPrincipalID string    `json:"updated_by_principal_id,omitempty"`
	UpdatedAt            time.Time `json:"updated_at,omitzero"`
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

// backupDestinationTarget is the validated, normalized destination.
type backupDestinationTarget struct {
	kind, endpoint, region, bucket, prefix string
}

// associatedData binds a sealed credential to its field and to the exact
// destination it authorizes, so a database write that redirects the endpoint
// or bucket makes the credentials unopenable instead of sending them there.
func (d backupDestinationTarget) associatedData(field string) string {
	bound, _ := json.Marshal([]string{d.kind, d.endpoint, d.region, d.bucket, d.prefix})
	return "engram-backup-destination:v1:" + field + ":" + string(bound)
}

// GetBackupDestination returns the non-secret destination view without
// opening any credential. Configured is false when none is stored.
func (cs *CloudStore) GetBackupDestination(ctx context.Context) (BackupDestination, error) {
	if cs == nil || cs.db == nil {
		return BackupDestination{}, fmt.Errorf("cloudstore: not initialized")
	}
	var d BackupDestination
	err := cs.db.QueryRowContext(ctx, `
		SELECT kind, endpoint, region, bucket, prefix, access_key_id_hint, key_fingerprint, COALESCE(updated_by_principal_id::text, ''), updated_at
		FROM cloud_backup_destinations WHERE id = 1`).Scan(&d.Kind, &d.Endpoint, &d.Region, &d.Bucket, &d.Prefix, &d.AccessKeyIDHint, &d.KeyFingerprint, &d.UpdatedByPrincipalID, &d.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupDestination{}, nil
	}
	if err != nil {
		return BackupDestination{}, fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	d.Configured = true
	return d, nil
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

	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup destination tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_backup_destinations (id, kind, endpoint, region, bucket, prefix, access_key_id_hint, access_key_id_ciphertext, secret_access_key_ciphertext, key_fingerprint, updated_by_principal_id, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, NOW())
		ON CONFLICT (id) DO UPDATE SET
			kind = EXCLUDED.kind, endpoint = EXCLUDED.endpoint, region = EXCLUDED.region, bucket = EXCLUDED.bucket, prefix = EXCLUDED.prefix,
			access_key_id_hint = EXCLUDED.access_key_id_hint, access_key_id_ciphertext = EXCLUDED.access_key_id_ciphertext,
			secret_access_key_ciphertext = EXCLUDED.secret_access_key_ciphertext, key_fingerprint = EXCLUDED.key_fingerprint,
			updated_by_principal_id = EXCLUDED.updated_by_principal_id, updated_at = EXCLUDED.updated_at`,
		target.kind, target.endpoint, target.region, target.bucket, target.prefix, hint, accessCipher, secretCipher, fingerprint, nullableID(params.Actor.PrincipalID),
	); err != nil {
		return fmt.Errorf("cloudstore: store backup destination: %w", err)
	}
	// Metadata is built here, never from caller input, so it cannot carry a
	// credential or ciphertext.
	audit := AuthAuditEvent{
		ActorPrincipalID: params.Actor.PrincipalID,
		ActorSource:      params.Actor.Source,
		Action:           AuthAuditActionBackupDestinationUpdate,
		Outcome:          "success",
		Metadata: map[string]any{
			"kind": target.kind, "endpoint": target.endpoint, "region": target.region, "bucket": target.bucket, "prefix": target.prefix,
			"access_key_id_hint": hint, "key_fingerprint": fingerprint,
		},
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup destination tx: %w", err)
	}
	return nil
}

// ClearBackupDestination removes the destination and audits it in one
// transaction. Clearing an absent destination is audited with removed=false.
func (cs *CloudStore) ClearBackupDestination(ctx context.Context, actor BackupDestinationActor) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup destination clear tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	result, err := tx.ExecContext(ctx, `DELETE FROM cloud_backup_destinations WHERE id = 1`)
	if err != nil {
		return fmt.Errorf("cloudstore: clear backup destination: %w", err)
	}
	removed, err := result.RowsAffected()
	if err != nil {
		return fmt.Errorf("cloudstore: clear backup destination: %w", err)
	}
	audit := AuthAuditEvent{
		ActorPrincipalID: actor.PrincipalID,
		ActorSource:      actor.Source,
		Action:           AuthAuditActionBackupDestinationClear,
		Outcome:          "success",
		Metadata:         map[string]any{"removed": removed > 0},
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup destination clear tx: %w", err)
	}
	return nil
}

// OpenBackupDestinationCredentials returns the destination with its opened
// credentials. It is meant only for the uploader; a wrong or rotated key
// surfaces the opener's key-mismatch error.
func (cs *CloudStore) OpenBackupDestinationCredentials(ctx context.Context, opener BackupSecretOpener) (BackupDestinationCredentials, error) {
	if cs == nil || cs.db == nil {
		return BackupDestinationCredentials{}, fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(opener) {
		return BackupDestinationCredentials{}, ErrBackupDestinationKeyRequired
	}
	var target backupDestinationTarget
	var accessCipher, secretCipher string
	err := cs.db.QueryRowContext(ctx, `
		SELECT kind, endpoint, region, bucket, prefix, access_key_id_ciphertext, secret_access_key_ciphertext
		FROM cloud_backup_destinations WHERE id = 1`).Scan(&target.kind, &target.endpoint, &target.region, &target.bucket, &target.prefix, &accessCipher, &secretCipher)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupDestinationCredentials{}, ErrBackupDestinationNotConfigured
	}
	if err != nil {
		return BackupDestinationCredentials{}, fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	accessKeyID, err := opener.Open(target.associatedData(backupDestinationFieldAccessKeyID), accessCipher)
	if err != nil {
		return BackupDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination access key id: %w", err)
	}
	secret, err := opener.Open(target.associatedData(backupDestinationFieldSecretAccessKey), secretCipher)
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
