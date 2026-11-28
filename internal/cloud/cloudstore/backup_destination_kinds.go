package cloudstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Dropbox and Google Drive backup destinations (see backup_destination.go for
// the single-destination rules shared with S3).
//
// Both kinds store a non-secret OAuth client identifier (the Dropbox app key
// or the Google OAuth client id) and a folder in plain columns, and seal the
// client secret and the refresh token. The client identifier is not sealed
// because OAuth treats it as public (it appears in every authorization URL);
// it is still bound into the associated data of the sealed secrets, so
// changing it in the database makes them unopenable, and the audit metadata
// (which is part of a backup archive) carries only its last characters. A
// Google Drive destination is saved without a refresh token ("pending
// authorization"); SetGDriveRefreshToken adds it after the OAuth callback.
// Saving either kind again requires every secret again, so a re-saved Google
// Drive destination is pending until authorized again.

const (
	// DefaultDropboxFolderPath and DefaultGDriveFolderName are the folders
	// the dashboard proposes for a new destination.
	DefaultDropboxFolderPath = "/Engram backups"
	DefaultGDriveFolderName  = "Engram backups"

	backupDestinationFieldAppSecret    = "app_secret"
	backupDestinationFieldClientSecret = "client_secret"
	backupDestinationFieldRefreshToken = "refresh_token"

	maxBackupClientIDLen     = 256
	maxBackupAppKeyLen       = 128
	maxBackupClientSecretLen = 256
	maxBackupRefreshTokenLen = 4096
	maxBackupFolderPathLen   = 512
	maxBackupFolderNameLen   = 255
)

// DropboxDestinationView is the non-secret view of a Dropbox destination.
type DropboxDestinationView struct {
	AppKey     string `json:"app_key"`
	FolderPath string `json:"folder_path"`
}

// GDriveDestinationView is the non-secret view of a Google Drive destination.
// Authorized is false until SetGDriveRefreshToken stores a refresh token.
type GDriveDestinationView struct {
	ClientID   string `json:"client_id"`
	FolderName string `json:"folder_name"`
	Authorized bool   `json:"authorized"`
}

// PutDropboxDestinationParams is a complete Dropbox destination; the app
// secret and the refresh token are required on every save.
type PutDropboxDestinationParams struct {
	AppKey       string
	FolderPath   string
	AppSecret    string `json:"-"`
	RefreshToken string `json:"-"`
	Actor        BackupDestinationActor
}

// PutGDriveDestinationParams is a Google Drive destination before its OAuth
// authorization; the client secret is required on every save.
type PutGDriveDestinationParams struct {
	ClientID     string
	FolderName   string
	ClientSecret string `json:"-"`
	Actor        BackupDestinationActor
}

// DropboxDestinationCredentials is the opened Dropbox destination, for the
// uploader only. It formats and JSON-encodes without its secrets.
type DropboxDestinationCredentials struct {
	AppKey       string
	FolderPath   string
	AppSecret    string `json:"-"`
	RefreshToken string `json:"-"`
}

// Format prints the destination with both secrets redacted.
func (c DropboxDestinationCredentials) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, fmt.Sprintf("{AppKey:%s FolderPath:%s AppSecret:redacted RefreshToken:redacted}", c.AppKey, c.FolderPath))
}

// GDriveDestinationCredentials is the opened Google Drive destination, for
// the uploader only. RefreshToken is empty while authorization is pending.
// It formats and JSON-encodes without its secrets.
type GDriveDestinationCredentials struct {
	ClientID     string
	FolderName   string
	ClientSecret string `json:"-"`
	RefreshToken string `json:"-"`
}

// Authorized reports whether the OAuth refresh token is stored.
func (c GDriveDestinationCredentials) Authorized() bool { return c.RefreshToken != "" }

// Format prints the destination with both secrets redacted.
func (c GDriveDestinationCredentials) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, fmt.Sprintf("{ClientID:%s FolderName:%s ClientSecret:redacted RefreshToken:redacted Authorized:%t}", c.ClientID, c.FolderName, c.Authorized()))
}

// OpenedBackupDestination is the opened destination of any kind; only the
// field of Kind is set. It formats and JSON-encodes without secrets.
type OpenedBackupDestination struct {
	Kind    string
	S3      BackupDestinationCredentials
	Dropbox DropboxDestinationCredentials
	GDrive  GDriveDestinationCredentials
}

// Format prints the destination with every secret redacted.
func (d OpenedBackupDestination) Format(f fmt.State, _ rune) {
	_, _ = fmt.Fprintf(f, "{Kind:%s S3:%v Dropbox:%v GDrive:%v}", d.Kind, d.S3, d.Dropbox, d.GDrive)
}

// Secrets returns the secret values of the destination, for redacting them
// from error messages; empty values are omitted.
func (d OpenedBackupDestination) Secrets() []string {
	var all []string
	switch d.Kind {
	case BackupDestinationKindS3:
		all = []string{d.S3.AccessKeyID, d.S3.SecretAccessKey}
	case BackupDestinationKindDropbox:
		all = []string{d.Dropbox.AppSecret, d.Dropbox.RefreshToken}
	case BackupDestinationKindGDrive:
		all = []string{d.GDrive.ClientSecret, d.GDrive.RefreshToken}
	}
	out := all[:0]
	for _, s := range all {
		if s != "" {
			out = append(out, s)
		}
	}
	return out
}

// ValidateDropboxDestination applies exactly the validation and
// normalization of PutDropboxDestination without sealing or storing
// anything. A rejection wraps ErrInvalidBackupDestination with a fixed
// reason that names the field and never echoes a secret; params.Actor is
// ignored.
func ValidateDropboxDestination(params PutDropboxDestinationParams) (DropboxDestinationCredentials, error) {
	target, secret, token, err := normalizeDropboxDestination(params)
	if err != nil {
		return DropboxDestinationCredentials{}, err
	}
	return DropboxDestinationCredentials{AppKey: target.clientID, FolderPath: target.folder, AppSecret: secret, RefreshToken: token}, nil
}

// ValidateGDriveDestination applies exactly the validation and normalization
// of PutGDriveDestination without sealing or storing anything; the returned
// credentials have no refresh token. Rejections are as in
// ValidateDropboxDestination.
func ValidateGDriveDestination(params PutGDriveDestinationParams) (GDriveDestinationCredentials, error) {
	target, secret, err := normalizeGDriveDestination(params)
	if err != nil {
		return GDriveDestinationCredentials{}, err
	}
	return GDriveDestinationCredentials{ClientID: target.clientID, FolderName: target.folder, ClientSecret: secret}, nil
}

// PutDropboxDestination validates params, seals the app secret and the
// refresh token and replaces the destination with its audit row in one
// transaction. Invalid input writes nothing.
func (cs *CloudStore) PutDropboxDestination(ctx context.Context, params PutDropboxDestinationParams, sealer BackupSecretSealer) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(sealer) {
		return ErrBackupDestinationKeyRequired
	}
	target, secret, token, err := normalizeDropboxDestination(params)
	if err != nil {
		return err
	}
	secretCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldAppSecret), []byte(secret))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination app secret: %w", err)
	}
	tokenCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldRefreshToken), []byte(token))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination refresh token: %w", err)
	}
	fingerprint := sealer.Fingerprint()
	row := sealedBackupDestination{target: target, clientSecretCipher: secretCipher, refreshTokCipher: tokenCipher, fingerprint: fingerprint}
	return cs.storeBackupDestination(ctx, row, params.Actor, map[string]any{
		"kind": target.kind, "folder_path": target.folder, "app_key_hint": backupAccessKeyIDHint(target.clientID), "key_fingerprint": fingerprint,
	})
}

// PutGDriveDestination validates params, seals the client secret and
// replaces the destination with its audit row in one transaction. The
// destination is pending authorization until SetGDriveRefreshToken. Invalid
// input writes nothing.
func (cs *CloudStore) PutGDriveDestination(ctx context.Context, params PutGDriveDestinationParams, sealer BackupSecretSealer) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(sealer) {
		return ErrBackupDestinationKeyRequired
	}
	target, secret, err := normalizeGDriveDestination(params)
	if err != nil {
		return err
	}
	secretCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldClientSecret), []byte(secret))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination client secret: %w", err)
	}
	fingerprint := sealer.Fingerprint()
	row := sealedBackupDestination{target: target, clientSecretCipher: secretCipher, fingerprint: fingerprint}
	return cs.storeBackupDestination(ctx, row, params.Actor, map[string]any{
		"kind": target.kind, "folder_name": target.folder, "client_id_hint": backupAccessKeyIDHint(target.clientID), "key_fingerprint": fingerprint,
		"authorized": false,
	})
}

// SetGDriveRefreshToken seals the OAuth refresh token of the stored Google
// Drive destination, bound to that destination, and audits
// backup.destination.authorize in the same transaction. It refuses with
// ErrBackupDestinationNotConfigured when no destination is stored,
// ErrBackupDestinationKindMismatch for another kind,
// ErrBackupDestinationKeyChanged when the destination was saved with another
// key, and ErrInvalidBackupDestination for a malformed token; a refusal
// writes nothing.
func (cs *CloudStore) SetGDriveRefreshToken(ctx context.Context, sealer BackupSecretSealer, refreshToken string, actor BackupDestinationActor) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(sealer) {
		return ErrBackupDestinationKeyRequired
	}
	token := strings.TrimSpace(refreshToken)
	if !validBackupCredential(token, maxBackupRefreshTokenLen) {
		return fmt.Errorf("%w: %s", ErrInvalidBackupDestination, refreshTokenReason)
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup destination authorize tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	target := backupDestinationTarget{}
	var fingerprint string
	err = tx.QueryRowContext(ctx, `SELECT kind, client_id, folder, key_fingerprint FROM cloud_backup_destinations WHERE id = 1 FOR UPDATE`).
		Scan(&target.kind, &target.clientID, &target.folder, &fingerprint)
	if errors.Is(err, sql.ErrNoRows) {
		return ErrBackupDestinationNotConfigured
	}
	if err != nil {
		return fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	if target.kind != BackupDestinationKindGDrive {
		return fmt.Errorf("%w: it is a %s destination, not gdrive", ErrBackupDestinationKindMismatch, target.kind)
	}
	if fingerprint != sealer.Fingerprint() {
		return ErrBackupDestinationKeyChanged
	}
	tokenCipher, err := sealer.Seal(target.associatedData(backupDestinationFieldRefreshToken), []byte(token))
	if err != nil {
		return fmt.Errorf("cloudstore: seal backup destination refresh token: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		UPDATE cloud_backup_destinations SET refresh_token_ciphertext = $1, updated_by_principal_id = $2, updated_at = NOW()
		WHERE id = 1`, tokenCipher, nullableID(actor.PrincipalID)); err != nil {
		return fmt.Errorf("cloudstore: store backup destination refresh token: %w", err)
	}
	audit := AuthAuditEvent{
		ActorPrincipalID: actor.PrincipalID,
		ActorSource:      actor.Source,
		Action:           AuthAuditActionBackupDestinationAuthorize,
		Outcome:          "success",
		Metadata: map[string]any{
			"kind": target.kind, "folder_name": target.folder, "client_id_hint": backupAccessKeyIDHint(target.clientID), "key_fingerprint": fingerprint,
		},
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup destination authorize tx: %w", err)
	}
	return nil
}

func openDropboxBackupDestination(row sealedBackupDestination, opener BackupSecretOpener) (DropboxDestinationCredentials, error) {
	secret, err := opener.Open(row.target.associatedData(backupDestinationFieldAppSecret), row.clientSecretCipher)
	if err != nil {
		return DropboxDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination app secret: %w", err)
	}
	token, err := opener.Open(row.target.associatedData(backupDestinationFieldRefreshToken), row.refreshTokCipher)
	if err != nil {
		return DropboxDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination refresh token: %w", err)
	}
	return DropboxDestinationCredentials{AppKey: row.target.clientID, FolderPath: row.target.folder, AppSecret: string(secret), RefreshToken: string(token)}, nil
}

func openGDriveBackupDestination(row sealedBackupDestination, opener BackupSecretOpener) (GDriveDestinationCredentials, error) {
	secret, err := opener.Open(row.target.associatedData(backupDestinationFieldClientSecret), row.clientSecretCipher)
	if err != nil {
		return GDriveDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination client secret: %w", err)
	}
	creds := GDriveDestinationCredentials{ClientID: row.target.clientID, FolderName: row.target.folder, ClientSecret: string(secret)}
	if row.refreshTokCipher == "" {
		return creds, nil // pending authorization
	}
	token, err := opener.Open(row.target.associatedData(backupDestinationFieldRefreshToken), row.refreshTokCipher)
	if err != nil {
		return GDriveDestinationCredentials{}, fmt.Errorf("cloudstore: open backup destination refresh token: %w", err)
	}
	creds.RefreshToken = string(token)
	return creds, nil
}

const refreshTokenReason = "refresh token must be 1-4096 printable characters without spaces"

// normalizeDropboxDestination validates params. Error messages never echo a
// secret.
func normalizeDropboxDestination(params PutDropboxDestinationParams) (backupDestinationTarget, string, string, error) {
	invalid := func(reason string) (backupDestinationTarget, string, string, error) {
		return backupDestinationTarget{}, "", "", fmt.Errorf("%w: %s", ErrInvalidBackupDestination, reason)
	}
	appKey := strings.TrimSpace(params.AppKey)
	if !validBackupCredential(appKey, maxBackupAppKeyLen) {
		return invalid("app key must be 1-128 printable characters without spaces")
	}
	folder, reason := normalizeDropboxFolderPath(params.FolderPath)
	if reason != "" {
		return invalid(reason)
	}
	secret := strings.TrimSpace(params.AppSecret)
	if !validBackupCredential(secret, maxBackupClientSecretLen) {
		return invalid("app secret must be 1-256 printable characters without spaces")
	}
	token := strings.TrimSpace(params.RefreshToken)
	if !validBackupCredential(token, maxBackupRefreshTokenLen) {
		return invalid(refreshTokenReason)
	}
	return backupDestinationTarget{kind: BackupDestinationKindDropbox, clientID: appKey, folder: folder}, secret, token, nil
}

// normalizeGDriveDestination validates params. Error messages never echo a
// secret.
func normalizeGDriveDestination(params PutGDriveDestinationParams) (backupDestinationTarget, string, error) {
	invalid := func(reason string) (backupDestinationTarget, string, error) {
		return backupDestinationTarget{}, "", fmt.Errorf("%w: %s", ErrInvalidBackupDestination, reason)
	}
	clientID := strings.TrimSpace(params.ClientID)
	if !validBackupCredential(clientID, maxBackupClientIDLen) {
		return invalid("client id must be 1-256 printable characters without spaces")
	}
	folder := strings.TrimSpace(params.FolderName)
	if folder == "" || len(folder) > maxBackupFolderNameLen || !utf8.ValidString(folder) || strings.IndexFunc(folder, unicode.IsControl) >= 0 || strings.Contains(folder, "/") {
		return invalid("folder name must be 1-255 printable characters without '/'")
	}
	secret := strings.TrimSpace(params.ClientSecret)
	if !validBackupCredential(secret, maxBackupClientSecretLen) {
		return invalid("client secret must be 1-256 printable characters without spaces")
	}
	return backupDestinationTarget{kind: BackupDestinationKindGDrive, clientID: clientID, folder: folder}, secret, nil
}

// normalizeDropboxFolderPath requires an absolute Dropbox path ("/" is the
// root of the app's space) without '.', '..' or empty segments, and drops a
// trailing slash.
func normalizeDropboxFolderPath(raw string) (string, string) {
	path := strings.TrimSpace(raw)
	if len(path) > maxBackupFolderPathLen || !utf8.ValidString(path) || strings.IndexFunc(path, unicode.IsControl) >= 0 || strings.Contains(path, `\`) {
		return "", "folder path must be at most 512 printable characters without backslashes"
	}
	if !strings.HasPrefix(path, "/") {
		return "", "folder path must start with '/', for example " + DefaultDropboxFolderPath
	}
	if path == "/" {
		return path, ""
	}
	path = strings.TrimSuffix(path, "/")
	for _, segment := range strings.Split(path[1:], "/") {
		if segment == "" || segment == "." || segment == ".." {
			return "", "folder path must not contain '.', '..' or empty path segments"
		}
	}
	return path, ""
}
