package cloudstore

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"
)

// OAuth authorization states of the dashboard's "Connect with Google" flow
// (cloud_backup_oauth_states). A state is 32 random bytes sent to Google in
// the authorization URL and echoed back to the callback. Only its SHA-256 is
// stored, together with the admin who started the flow, a binding to the
// Google Drive destination as it was then, and the PKCE code verifier sealed
// with ENGRAM_CLOUD_BACKUP_KEY (associated data bound to the state hash). A
// state lives BackupOAuthStateTTL and is consumed at most once: the row is
// deleted when the callback consumes it. A refused consume writes nothing;
// expired rows are purged when the next state is created. These rows are
// ephemeral, never exported in a backup, and a restore target must not hold
// any.

// BackupOAuthStateTTL is how long a "Connect with Google" authorization may
// take before its state expires.
const BackupOAuthStateTTL = 10 * time.Minute

const (
	// backupOAuthStatesTable holds pending authorization states; it is never
	// exported.
	backupOAuthStatesTable = "cloud_backup_oauth_states"
	// maxBackupOAuthStatesPerPrincipal bounds the pending states of one
	// admin; creating another drops the oldest.
	maxBackupOAuthStatesPerPrincipal = 5
	backupOAuthStateBytes            = 32
	backupOAuthVerifierAD            = "engram-backup-oauth-state:v1:verifier:"
)

var (
	// ErrBackupOAuthStateNotFound refuses a state that is malformed, unknown
	// (tampered) or was already used.
	ErrBackupOAuthStateNotFound = errors.New("cloudstore: the authorization state is unknown or was already used")
	// ErrBackupOAuthStateExpired refuses a state older than
	// BackupOAuthStateTTL.
	ErrBackupOAuthStateExpired = errors.New("cloudstore: the authorization state expired")
	// ErrBackupOAuthStatePrincipal refuses a state started by another
	// principal.
	ErrBackupOAuthStatePrincipal = errors.New("cloudstore: the authorization was started by another principal")
	// ErrBackupOAuthDestinationChanged refuses a state whose Google Drive
	// destination was saved again, replaced or removed since it was created.
	ErrBackupOAuthDestinationChanged = errors.New("cloudstore: the Google Drive destination changed since the authorization started")
	// ErrInvalidBackupOAuthState refuses to create a state from invalid
	// input (no principal or a malformed PKCE verifier).
	ErrInvalidBackupOAuthState = errors.New("cloudstore: invalid backup OAuth state")
)

// BackupOAuthGrant is a consumed state: the PKCE verifier for the code
// exchange and the destination binding to check again before the refresh
// token is stored. It formats and JSON-encodes without the verifier.
type BackupOAuthGrant struct {
	Verifier string `json:"-"`
	Binding  string
}

// Format prints the grant with the verifier redacted.
func (g BackupOAuthGrant) Format(f fmt.State, _ rune) {
	_, _ = io.WriteString(f, "{Verifier:redacted Binding:"+g.Binding+"}")
}

// CreateBackupOAuthState starts a "Connect with Google" authorization for
// principalID: it stores a new state bound to the stored Google Drive
// destination with the PKCE verifier sealed by sealer, and returns the raw
// state for the authorization URL. The raw state is never stored. Expired
// states are purged and the principal keeps at most
// maxBackupOAuthStatesPerPrincipal pending states. It refuses with
// ErrBackupDestinationNotConfigured without a destination,
// ErrBackupDestinationKindMismatch for another kind, and a refusal writes
// nothing.
func (cs *CloudStore) CreateBackupOAuthState(ctx context.Context, sealer BackupSecretSealer, principalID, verifier string) (string, error) {
	if cs == nil || cs.db == nil {
		return "", fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(sealer) {
		return "", ErrBackupDestinationKeyRequired
	}
	principalID = strings.TrimSpace(principalID)
	if principalID == "" {
		return "", fmt.Errorf("%w: a principal is required", ErrInvalidBackupOAuthState)
	}
	if !validPKCEVerifier(verifier) {
		return "", fmt.Errorf("%w: the PKCE verifier must be 43-128 unreserved characters", ErrInvalidBackupOAuthState)
	}
	raw := make([]byte, backupOAuthStateBytes)
	if _, err := rand.Read(raw); err != nil {
		return "", fmt.Errorf("cloudstore: generate backup OAuth state: %w", err)
	}
	state := base64.RawURLEncoding.EncodeToString(raw)
	hash := backupOAuthStateHash(state)
	sealed, err := sealer.Seal(backupOAuthVerifierAD+hash, []byte(verifier))
	if err != nil {
		return "", fmt.Errorf("cloudstore: seal backup OAuth verifier: %w", err)
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return "", fmt.Errorf("cloudstore: begin backup OAuth state tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	binding, err := readBackupOAuthBinding(ctx, tx)
	if err != nil {
		return "", err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM cloud_backup_oauth_states WHERE expires_at <= NOW()`); err != nil {
		return "", fmt.Errorf("cloudstore: purge expired backup OAuth states: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		DELETE FROM cloud_backup_oauth_states WHERE principal_id = $1 AND state_hash NOT IN (
			SELECT state_hash FROM cloud_backup_oauth_states WHERE principal_id = $1 ORDER BY created_at DESC, state_hash LIMIT $2)`,
		principalID, maxBackupOAuthStatesPerPrincipal-1); err != nil {
		return "", fmt.Errorf("cloudstore: bound pending backup OAuth states: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_backup_oauth_states (state_hash, principal_id, destination_binding, verifier_ciphertext, created_at, expires_at)
		VALUES ($1, $2, $3, $4, NOW(), NOW() + make_interval(secs => $5))`,
		hash, principalID, binding, sealed, BackupOAuthStateTTL.Seconds()); err != nil {
		return "", fmt.Errorf("cloudstore: store backup OAuth state: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return "", fmt.Errorf("cloudstore: commit backup OAuth state tx: %w", err)
	}
	return state, nil
}

// ConsumeBackupOAuthState validates the state the OAuth callback received
// and consumes it: it must be well formed and stored
// (ErrBackupOAuthStateNotFound), unexpired (ErrBackupOAuthStateExpired),
// started by principalID (ErrBackupOAuthStatePrincipal) for the Google
// Drive destination as it is now (ErrBackupOAuthDestinationChanged), and
// its verifier must open with opener. Only then is the row deleted, in the
// same transaction, and the verifier returned; every refusal leaves the
// state as it was.
func (cs *CloudStore) ConsumeBackupOAuthState(ctx context.Context, opener BackupSecretOpener, state, principalID string) (BackupOAuthGrant, error) {
	if cs == nil || cs.db == nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: not initialized")
	}
	if isNilBackupKeyHolder(opener) {
		return BackupOAuthGrant{}, ErrBackupDestinationKeyRequired
	}
	if !validBackupOAuthState(state) {
		return BackupOAuthGrant{}, ErrBackupOAuthStateNotFound
	}
	hash := backupOAuthStateHash(state)
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: begin backup OAuth consume tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	var owner, binding, sealed string
	var expired bool
	err = tx.QueryRowContext(ctx, `
		SELECT principal_id::text, destination_binding, verifier_ciphertext, expires_at <= NOW()
		FROM cloud_backup_oauth_states WHERE state_hash = $1 FOR UPDATE`, hash).Scan(&owner, &binding, &sealed, &expired)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupOAuthGrant{}, ErrBackupOAuthStateNotFound
	}
	if err != nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: read backup OAuth state: %w", err)
	}
	if expired {
		return BackupOAuthGrant{}, ErrBackupOAuthStateExpired
	}
	if owner != strings.TrimSpace(principalID) {
		return BackupOAuthGrant{}, ErrBackupOAuthStatePrincipal
	}
	current, err := readBackupOAuthBinding(ctx, tx)
	if errors.Is(err, ErrBackupDestinationNotConfigured) || errors.Is(err, ErrBackupDestinationKindMismatch) || (err == nil && current != binding) {
		return BackupOAuthGrant{}, ErrBackupOAuthDestinationChanged
	}
	if err != nil {
		return BackupOAuthGrant{}, err
	}
	verifier, err := opener.Open(backupOAuthVerifierAD+hash, sealed)
	if err != nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: open backup OAuth verifier: %w", err)
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM cloud_backup_oauth_states WHERE state_hash = $1`, hash)
	if err != nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: consume backup OAuth state: %w", err)
	}
	if n, err := result.RowsAffected(); err != nil || n != 1 {
		return BackupOAuthGrant{}, ErrBackupOAuthStateNotFound
	}
	if err := tx.Commit(); err != nil {
		return BackupOAuthGrant{}, fmt.Errorf("cloudstore: commit backup OAuth consume tx: %w", err)
	}
	return BackupOAuthGrant{Verifier: string(verifier), Binding: binding}, nil
}

// CheckBackupOAuthBinding reports ErrBackupOAuthDestinationChanged unless
// the stored Google Drive destination still has binding, the value a
// consumed state returned. The callback calls it again right before storing
// the refresh token.
func (cs *CloudStore) CheckBackupOAuthBinding(ctx context.Context, binding string) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	current, err := readBackupOAuthBinding(ctx, cs.db)
	if errors.Is(err, ErrBackupDestinationNotConfigured) || errors.Is(err, ErrBackupDestinationKindMismatch) || (err == nil && current != binding) {
		return ErrBackupOAuthDestinationChanged
	}
	return err
}

type backupOAuthQueryer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// readBackupOAuthBinding is the binding of the stored Google Drive
// destination: a hash of its client id, folder, key fingerprint and
// updated_at, which every save and authorization moves forward.
func readBackupOAuthBinding(ctx context.Context, q backupOAuthQueryer) (string, error) {
	var kind, clientID, folder, fingerprint string
	var updatedAt time.Time
	err := q.QueryRowContext(ctx, `SELECT kind, client_id, folder, key_fingerprint, updated_at FROM cloud_backup_destinations WHERE id = 1`).
		Scan(&kind, &clientID, &folder, &fingerprint, &updatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return "", ErrBackupDestinationNotConfigured
	}
	if err != nil {
		return "", fmt.Errorf("cloudstore: read backup destination: %w", err)
	}
	if kind != BackupDestinationKindGDrive {
		return "", fmt.Errorf("%w: it is a %s destination, not gdrive", ErrBackupDestinationKindMismatch, kind)
	}
	bound, _ := json.Marshal([]string{kind, clientID, folder, fingerprint, updatedAt.UTC().Format(time.RFC3339Nano)})
	sum := sha256.Sum256(bound)
	return hex.EncodeToString(sum[:]), nil
}

func backupOAuthStateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// validBackupOAuthState accepts exactly the 43 base64url characters
// CreateBackupOAuthState returns.
func validBackupOAuthState(state string) bool {
	if len(state) != base64.RawURLEncoding.EncodedLen(backupOAuthStateBytes) {
		return false
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(state)
	return err == nil && len(decoded) == backupOAuthStateBytes
}

// validPKCEVerifier accepts an RFC 7636 code verifier: 43-128 characters
// from the unreserved set.
func validPKCEVerifier(v string) bool {
	if len(v) < 43 || len(v) > 128 {
		return false
	}
	for _, r := range v {
		switch {
		case r >= 'A' && r <= 'Z', r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.', r == '_', r == '~':
		default:
			return false
		}
	}
	return true
}
