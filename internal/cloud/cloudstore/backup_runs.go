package cloudstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"
)

// Backup run history. Each upload to the external destination, scheduled or
// manual, is one row: started as "running" and finished once as "success"
// or "failure". Like the schedule it is operational state of this server and
// is never exported in a backup.

const (
	BackupRunTriggerScheduled = "scheduled"
	BackupRunTriggerManual    = "manual"

	BackupRunStatusRunning = "running"
	BackupRunStatusSuccess = "success"
	BackupRunStatusFailure = "failure"

	// DefaultBackupRunListLimit is the page size of ListBackupRuns for a
	// non-positive limit; maxBackupRunListLimit caps any larger request.
	DefaultBackupRunListLimit = 20
	maxBackupRunListLimit     = 100

	// MaxBackupRunErrorMessageBytes bounds a stored error message.
	MaxBackupRunErrorMessageBytes = 512

	maxBackupRunObjectKeyBytes = 1024
	backupRunRedacted          = "[redacted]"
	backupRunTruncated         = "..."
	backupRunDefaultFailure    = "backup failed"
	minBackupRunRedactLength   = 4

	// BackupRunInterruptedMessage is the error of a run that stayed
	// "running" past the stale threshold, so its server stopped (or lost its
	// database connection) before it could record the result.
	BackupRunInterruptedMessage = "interrupted (server stopped before completion)"

	// backupRunStartLock serializes run starts across servers (a
	// transaction-scoped PostgreSQL advisory lock), so RefuseIfRunning sees
	// every start that committed before it.
	backupRunStartLock int64 = 0x656e6772616d4231 // "engramB1"
)

var (
	ErrInvalidBackupRun = errors.New("cloudstore: invalid backup run")
	// ErrBackupRunNotRunning reports a finish for an unknown or already
	// finished run; a run is finished exactly once.
	ErrBackupRunNotRunning = errors.New("cloudstore: backup run is not running")
	// ErrBackupRunAlreadyRecorded reports a second start for the same
	// scheduled slot, so two servers never both run it.
	ErrBackupRunAlreadyRecorded = errors.New("cloudstore: scheduled backup run is already recorded")
	// ErrBackupRunInProgress reports a start with RefuseIfRunning while
	// another run is running.
	ErrBackupRunInProgress = errors.New("cloudstore: another backup run is running")
)

// BackupRun is one history row. ScheduledFor is zero for a manual run and
// FinishedAt is zero while the run is running. ErrorMessage is already
// sanitized and bounded.
type BackupRun struct {
	ID               int64
	Trigger          string
	ScheduledFor     time.Time
	StartedAt        time.Time
	FinishedAt       time.Time
	Status           string
	ObjectKey        string
	SizeBytes        int64
	ErrorMessage     string
	ActorPrincipalID string
}

// StartBackupRunParams starts a run. A scheduled run names its slot; a
// manual run names no slot and usually the principal that requested it.
// RefuseIfRunning refuses the start with ErrBackupRunInProgress while any
// run is still running (on any server); expire stale runs first with
// ExpireStaleBackupRuns so an interrupted run does not block forever.
type StartBackupRunParams struct {
	Trigger          string
	ScheduledFor     time.Time
	ActorPrincipalID string
	RefuseIfRunning  bool
}

// FinishBackupRunParams finishes a running run. A success names the object
// key and size; a failure carries an error message, which is sanitized and
// bounded before it is stored. Redact lists exact values (such as the
// destination credentials) to scrub from the message; it is never stored.
type FinishBackupRunParams struct {
	ID           int64
	Status       string
	ObjectKey    string
	SizeBytes    int64
	ErrorMessage string
	Redact       []string `json:"-"`
}

const backupRunColumns = `id, trigger, scheduled_for, started_at, finished_at, status, object_key, size_bytes, error_message, COALESCE(actor_principal_id::text, '')`

// StartBackupRun records a running run and returns it. Starts are serialized
// by an advisory lock; a scheduled slot already recorded (by any server)
// fails with ErrBackupRunAlreadyRecorded.
func (cs *CloudStore) StartBackupRun(ctx context.Context, params StartBackupRunParams) (BackupRun, error) {
	if cs == nil || cs.db == nil {
		return BackupRun{}, fmt.Errorf("cloudstore: not initialized")
	}
	var scheduledFor any
	switch params.Trigger {
	case BackupRunTriggerScheduled:
		if params.ScheduledFor.IsZero() {
			return BackupRun{}, fmt.Errorf("%w: a scheduled run needs its scheduled time", ErrInvalidBackupRun)
		}
		scheduledFor = params.ScheduledFor.UTC()
	case BackupRunTriggerManual:
		if !params.ScheduledFor.IsZero() {
			return BackupRun{}, fmt.Errorf("%w: a manual run has no scheduled time", ErrInvalidBackupRun)
		}
	default:
		return BackupRun{}, fmt.Errorf("%w: trigger must be %q or %q", ErrInvalidBackupRun, BackupRunTriggerScheduled, BackupRunTriggerManual)
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return BackupRun{}, fmt.Errorf("cloudstore: begin backup run tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, backupRunStartLock); err != nil {
		return BackupRun{}, fmt.Errorf("cloudstore: lock backup run start: %w", err)
	}
	if params.RefuseIfRunning {
		var running bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM cloud_backup_runs WHERE status = 'running')`).Scan(&running); err != nil {
			return BackupRun{}, fmt.Errorf("cloudstore: check running backup runs: %w", err)
		}
		if running {
			return BackupRun{}, ErrBackupRunInProgress
		}
	}
	row := tx.QueryRowContext(ctx, `
		INSERT INTO cloud_backup_runs (trigger, scheduled_for, status, actor_principal_id)
		VALUES ($1, $2, 'running', $3)
		ON CONFLICT (scheduled_for) WHERE trigger = 'scheduled' DO NOTHING
		RETURNING `+backupRunColumns,
		params.Trigger, scheduledFor, nullableID(params.ActorPrincipalID))
	run, err := scanBackupRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupRun{}, ErrBackupRunAlreadyRecorded
	}
	if err != nil {
		return BackupRun{}, fmt.Errorf("cloudstore: start backup run: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return BackupRun{}, fmt.Errorf("cloudstore: commit backup run start: %w", err)
	}
	return run, nil
}

// ExpireStaleBackupRuns finishes every run that is still "running" although
// it started more than olderThan ago (by the database clock) as a failure
// with BackupRunInterruptedMessage, and returns how many it finished. A run
// is bounded well below the threshold the runner uses, so such a row belongs
// to a server that stopped mid-run.
func (cs *CloudStore) ExpireStaleBackupRuns(ctx context.Context, olderThan time.Duration) (int64, error) {
	if cs == nil || cs.db == nil {
		return 0, fmt.Errorf("cloudstore: not initialized")
	}
	if olderThan <= 0 {
		return 0, fmt.Errorf("%w: the stale threshold must be positive", ErrInvalidBackupRun)
	}
	result, err := cs.db.ExecContext(ctx, `
		UPDATE cloud_backup_runs
		SET status = 'failure', finished_at = NOW(), error_message = $2
		WHERE status = 'running' AND started_at < NOW() - make_interval(secs => $1)`,
		olderThan.Seconds(), BackupRunInterruptedMessage)
	if err != nil {
		return 0, fmt.Errorf("cloudstore: expire stale backup runs: %w", err)
	}
	expired, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("cloudstore: expire stale backup runs: %w", err)
	}
	return expired, nil
}

// FinishBackupRun moves a running run to success or failure and returns it.
func (cs *CloudStore) FinishBackupRun(ctx context.Context, params FinishBackupRunParams) (BackupRun, error) {
	if cs == nil || cs.db == nil {
		return BackupRun{}, fmt.Errorf("cloudstore: not initialized")
	}
	objectKey, message := "", ""
	switch params.Status {
	case BackupRunStatusSuccess:
		objectKey = strings.TrimSpace(params.ObjectKey)
		if objectKey == "" || len(objectKey) > maxBackupRunObjectKeyBytes || !utf8.ValidString(objectKey) {
			return BackupRun{}, fmt.Errorf("%w: a successful run needs an object key of 1-%d bytes", ErrInvalidBackupRun, maxBackupRunObjectKeyBytes)
		}
		if params.SizeBytes < 0 {
			return BackupRun{}, fmt.Errorf("%w: size must not be negative", ErrInvalidBackupRun)
		}
	case BackupRunStatusFailure:
		message = SanitizeBackupRunError(params.ErrorMessage, params.Redact...)
		if message == "" {
			message = backupRunDefaultFailure
		}
	default:
		return BackupRun{}, fmt.Errorf("%w: a run finishes as %q or %q", ErrInvalidBackupRun, BackupRunStatusSuccess, BackupRunStatusFailure)
	}
	size := params.SizeBytes
	if params.Status == BackupRunStatusFailure {
		size = max(size, 0)
	}
	row := cs.db.QueryRowContext(ctx, `
		UPDATE cloud_backup_runs
		SET status = $2, finished_at = NOW(), object_key = $3, size_bytes = $4, error_message = $5
		WHERE id = $1 AND status = 'running'
		RETURNING `+backupRunColumns,
		params.ID, params.Status, objectKey, size, message)
	run, err := scanBackupRun(row)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupRun{}, ErrBackupRunNotRunning
	}
	if err != nil {
		return BackupRun{}, fmt.Errorf("cloudstore: finish backup run: %w", err)
	}
	return run, nil
}

// ListBackupRuns returns the newest runs first. A non-positive limit uses
// DefaultBackupRunListLimit; limits above 100 are capped.
func (cs *CloudStore) ListBackupRuns(ctx context.Context, limit int) ([]BackupRun, error) {
	if cs == nil || cs.db == nil {
		return nil, fmt.Errorf("cloudstore: not initialized")
	}
	if limit <= 0 {
		limit = DefaultBackupRunListLimit
	}
	limit = min(limit, maxBackupRunListLimit)
	rows, err := cs.db.QueryContext(ctx, `SELECT `+backupRunColumns+` FROM cloud_backup_runs ORDER BY started_at DESC, id DESC LIMIT $1`, limit)
	if err != nil {
		return nil, fmt.Errorf("cloudstore: list backup runs: %w", err)
	}
	defer rows.Close()
	runs := []BackupRun{}
	for rows.Next() {
		run, err := scanBackupRun(rows)
		if err != nil {
			return nil, fmt.Errorf("cloudstore: scan backup run: %w", err)
		}
		runs = append(runs, run)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("cloudstore: list backup runs: %w", err)
	}
	return runs, nil
}

type backupRunScanner interface {
	Scan(dest ...any) error
}

func scanBackupRun(row backupRunScanner) (BackupRun, error) {
	var run BackupRun
	var scheduledFor, finishedAt sql.NullTime
	if err := row.Scan(&run.ID, &run.Trigger, &scheduledFor, &run.StartedAt, &finishedAt, &run.Status, &run.ObjectKey, &run.SizeBytes, &run.ErrorMessage, &run.ActorPrincipalID); err != nil {
		return BackupRun{}, err
	}
	if scheduledFor.Valid {
		run.ScheduledFor = scheduledFor.Time
	}
	if finishedAt.Valid {
		run.FinishedAt = finishedAt.Time
	}
	return run, nil
}

var (
	backupRunURLUserinfo = regexp.MustCompile(`([A-Za-z][A-Za-z0-9+.-]*://)[^/\s@]+@`)
	backupRunBearer      = regexp.MustCompile(`(?i)\b(bearer)\s+[^\s,;]+`)
	// backupRunXMLSecret matches S3 error-body elements that echo
	// credentials or signing material, such as <AWSAccessKeyId>,
	// <SignatureProvided> and <StringToSign>. The value runs to the next tag
	// or to the end of a truncated message.
	backupRunXMLSecret  = regexp.MustCompile(`(?i)(<(?:AWSAccessKeyId|SignatureProvided|StringToSign|StringToSignBytes|CanonicalRequest|CanonicalRequestBytes|Credential|X-Amz-Credential|X-Amz-Signature|SecretAccessKey|SessionToken|SecurityToken)(?:\s[^>]*)?>)[^<]*`)
	backupRunSecretPair = regexp.MustCompile(`(?i)\b(x-amz-signature|x-amz-credential|x-amz-security-token|signature|credential|authorization|password|passwd|secret[_-]?access[_-]?key|access[_-]?key[_-]?id|secret|token)(\s*[=:]\s*)("[^"]*"|'[^']*'|[^\s,;&]+)`)
)

// SanitizeBackupRunError makes an error message safe to store and display:
// it scrubs every value in secrets (of at least four bytes), URL userinfo,
// bearer tokens, credential-like key=value pairs and S3 XML elements that
// echo credentials or signing material (<AWSAccessKeyId>,
// <SignatureProvided>, <StringToSign>, <CanonicalRequest>...), replaces control
// characters and invalid UTF-8, collapses whitespace, and bounds the result
// to MaxBackupRunErrorMessageBytes, marking a truncation with "...".
func SanitizeBackupRunError(message string, secrets ...string) string {
	message = strings.ToValidUTF8(message, "?")
	for _, secret := range secrets {
		if len(secret) >= minBackupRunRedactLength {
			message = strings.ReplaceAll(message, secret, backupRunRedacted)
		}
	}
	message = backupRunURLUserinfo.ReplaceAllString(message, "${1}"+backupRunRedacted+"@")
	message = backupRunXMLSecret.ReplaceAllString(message, "${1}"+backupRunRedacted)
	message = backupRunBearer.ReplaceAllString(message, "${1} "+backupRunRedacted)
	message = backupRunSecretPair.ReplaceAllString(message, "${1}${2}"+backupRunRedacted)
	message = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) || unicode.IsSpace(r) {
			return ' '
		}
		return r
	}, message)
	message = strings.Join(strings.Fields(message), " ")
	if len(message) <= MaxBackupRunErrorMessageBytes {
		return message
	}
	cut := MaxBackupRunErrorMessageBytes - len(backupRunTruncated)
	for cut > 0 && !utf8.RuneStart(message[cut]) {
		cut--
	}
	return message[:cut] + backupRunTruncated
}
