// Package backuprunner runs Engram Cloud backups inside `engram cloud serve`:
// a scheduler loop that uploads a backup at every slot of the dashboard
// schedule, and the manual "Back up now" runs. Each run exports one archive
// (cloudbackup.Export) into a private temp file on the server's disk, uploads
// it with a single PUT to the configured S3-compatible destination and
// records the result in the backup run history. It never deletes objects;
// retention belongs to the bucket's lifecycle rules.
//
// Several servers may share one database: a scheduled slot is claimed with a
// unique history row (cloudstore.StartBackupRun), so exactly one server
// uploads it; a server busy with another run leaves the slot to the others.
// A run that stays "running" past the stale threshold belongs to a server
// that stopped mid-run and is marked interrupted. When it starts, the runner
// removes archive temp files that a killed server left in its temp
// directory.
package backuprunner

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudbackup"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

const (
	// DefaultPollInterval is how often the scheduler re-reads the schedule,
	// so a dashboard change applies without a restart.
	DefaultPollInterval = time.Minute
	// DefaultExportTimeout bounds writing the archive to the temp file.
	DefaultExportTimeout = 2 * time.Hour
	// DefaultStaleAfter is the age after which a "running" row is treated
	// as interrupted. It must exceed the longest possible run: the export
	// timeout plus the upload deadline of a maximum-size object.
	DefaultStaleAfter = 6 * time.Hour
	// MinUploadDeadline and UploadDeadlineSlack shape UploadDeadline.
	MinUploadDeadline   = 30 * time.Minute
	UploadDeadlineSlack = 10 * time.Minute
	// uploadDeadlineThroughput is the slowest sustained upload rate (bytes
	// per second) a run is given time for.
	uploadDeadlineThroughput = 1 << 20

	// ContentType is the content type of an uploaded archive.
	ContentType = "application/gzip"

	// finishTimeout bounds recording a result, even during shutdown.
	finishTimeout = 30 * time.Second

	// archiveTempPattern names the archive temp file of a run; the startup
	// sweep removes only regular files matching it.
	archiveTempPattern = "engram-cloud-backup-*.tar.gz"
)

// Messages recorded in the run history. A slot that could not run is
// recorded as a failure whose message starts with "skipped: ".
const (
	SkippedNoDestinationMessage = "skipped: no backup destination is configured"
	SkippedKeyMismatchMessage   = "skipped: the stored destination credentials cannot be opened with the current ENGRAM_CLOUD_BACKUP_KEY; save the destination again"
	CanceledMessage             = "canceled: the server stopped before the backup finished"
	InternalErrorMessage        = "internal error while running the backup; see the server log"
)

// ErrRunnerStopped refuses a manual backup when the runner is not running.
var ErrRunnerStopped = errors.New("backuprunner: the backup runner is not running")

// Store is the storage the runner needs; *cloudstore.CloudStore satisfies it.
type Store interface {
	cloudbackup.Source
	GetBackupSchedule(ctx context.Context) (cloudstore.BackupSchedule, error)
	OpenBackupDestinationCredentials(ctx context.Context, opener cloudstore.BackupSecretOpener) (cloudstore.BackupDestinationCredentials, error)
	StartBackupRun(ctx context.Context, params cloudstore.StartBackupRunParams) (cloudstore.BackupRun, error)
	FinishBackupRun(ctx context.Context, params cloudstore.FinishBackupRunParams) (cloudstore.BackupRun, error)
	ExpireStaleBackupRuns(ctx context.Context, olderThan time.Duration) (int64, error)
}

// Uploader stores one object; *s3client.Client satisfies it.
type Uploader interface {
	PutObject(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error
}

// Clock is the time source of the scheduler.
type Clock interface {
	Now() time.Time
	After(d time.Duration) <-chan time.Time
}

type systemClock struct{}

func (systemClock) Now() time.Time                         { return time.Now() }
func (systemClock) After(d time.Duration) <-chan time.Time { return time.After(d) }

// Config configures a Runner. Store and Key are required; zero values of the
// other fields select the defaults.
type Config struct {
	Store Store
	// Key opens the destination credentials (ENGRAM_CLOUD_BACKUP_KEY).
	Key           cloudstore.BackupSecretOpener
	EngramVersion string

	Clock         Clock
	PollInterval  time.Duration
	StaleAfter    time.Duration
	ExportTimeout time.Duration
	// UploadDeadline returns the overall deadline of one upload of size
	// bytes; it defaults to UploadDeadline.
	UploadDeadline func(size int64) time.Duration
	// TempDir holds the archive while it is uploaded; empty is the system
	// temp directory.
	TempDir string
	// NewUploader builds the uploader for the opened destination; it
	// defaults to an s3client.Client.
	NewUploader func(cloudstore.BackupDestinationCredentials) (Uploader, error)
	// Export writes one archive; it defaults to cloudbackup.Export of Store.
	Export func(ctx context.Context, w io.Writer) error
	// Logf defaults to log.Printf.
	Logf func(format string, args ...any)
}

// Runner runs scheduled and manual backups. It implements
// cloudserver.BackupRunner.
type Runner struct {
	store          Store
	key            cloudstore.BackupSecretOpener
	clock          Clock
	poll           time.Duration
	staleAfter     time.Duration
	exportTimeout  time.Duration
	uploadDeadline func(int64) time.Duration
	tempDir        string
	newUploader    func(cloudstore.BackupDestinationCredentials) (Uploader, error)
	export         func(context.Context, io.Writer) error
	logf           func(string, ...any)

	// busy is held by the one run this server executes at a time.
	busy atomic.Bool

	mu      sync.Mutex
	base    context.Context // set by Start; manual runs inherit it
	stopped bool
	wg      sync.WaitGroup
}

var _ cloudserver.BackupRunner = (*Runner)(nil)

// UploadDeadline is the default overall upload deadline for size bytes:
// enough time for 1 MiB/s plus ten minutes, and never less than 30 minutes.
func UploadDeadline(size int64) time.Duration {
	d := time.Duration(max(size, 0)/uploadDeadlineThroughput)*time.Second + UploadDeadlineSlack
	return max(d, MinUploadDeadline)
}

// New validates cfg and returns a Runner that is not started yet.
func New(cfg Config) (*Runner, error) {
	if isNil(cfg.Store) {
		return nil, errors.New("backuprunner: a store is required")
	}
	if isNil(cfg.Key) {
		return nil, errors.New("backuprunner: ENGRAM_CLOUD_BACKUP_KEY is required to run backups")
	}
	r := &Runner{
		store: cfg.Store, key: cfg.Key, clock: cfg.Clock,
		poll: cfg.PollInterval, staleAfter: cfg.StaleAfter, exportTimeout: cfg.ExportTimeout,
		uploadDeadline: cfg.UploadDeadline, tempDir: cfg.TempDir,
		newUploader: cfg.NewUploader, export: cfg.Export, logf: cfg.Logf,
	}
	if r.poll < 0 || r.staleAfter < 0 || r.exportTimeout < 0 {
		return nil, errors.New("backuprunner: intervals must not be negative")
	}
	if r.clock == nil {
		r.clock = systemClock{}
	}
	if r.poll == 0 {
		r.poll = DefaultPollInterval
	}
	if r.staleAfter == 0 {
		r.staleAfter = DefaultStaleAfter
	}
	if r.exportTimeout == 0 {
		r.exportTimeout = DefaultExportTimeout
	}
	if r.uploadDeadline == nil {
		r.uploadDeadline = UploadDeadline
	}
	if longest := r.exportTimeout + r.uploadDeadline(s3client.MaxObjectSize); r.staleAfter <= longest {
		return nil, fmt.Errorf("backuprunner: the stale threshold %s must exceed the longest run (%s)", r.staleAfter, longest)
	}
	if r.tempDir == "" {
		r.tempDir = os.TempDir()
	}
	if r.newUploader == nil {
		r.newUploader = newS3Uploader
	}
	if r.export == nil {
		store, version, tempDir := cfg.Store, cfg.EngramVersion, r.tempDir
		r.export = func(ctx context.Context, w io.Writer) error {
			_, err := cloudbackup.Export(ctx, store, w, cloudbackup.ExportOptions{EngramVersion: version, TempDir: tempDir})
			return err
		}
	}
	if r.logf == nil {
		r.logf = log.Printf
	}
	return r, nil
}

func newS3Uploader(creds cloudstore.BackupDestinationCredentials) (Uploader, error) {
	return s3client.New(s3client.Config{
		Endpoint: creds.Endpoint, Region: creds.Region, Bucket: creds.Bucket,
		AccessKeyID: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey,
	})
}

// Start removes stale archive temp files, then launches the scheduler loop.
// Cancel ctx to stop it, then call Wait; a run in progress is canceled and
// recorded as such. Start runs once.
func (r *Runner) Start(ctx context.Context) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.base != nil || r.stopped {
		return
	}
	// Before any run of this process can create its own temp file.
	r.sweepStaleArchives()
	r.base = ctx
	r.wg.Add(1)
	go r.loop(ctx)
}

// Wait blocks until the scheduler loop and every manual run have returned.
// It refuses new manual runs; call it after canceling Start's ctx.
func (r *Runner) Wait() {
	r.mu.Lock()
	r.stopped = true
	r.mu.Unlock()
	r.wg.Wait()
}

// StartManualBackup claims this server's run slot and records a manual run,
// then uploads in the background. It refuses with an error wrapping
// cloudserver.ErrBackupAlreadyRunning while a run is running here or, per
// the history, on any server.
func (r *Runner) StartManualBackup(ctx context.Context, actorPrincipalID string) (int64, error) {
	r.mu.Lock()
	base := r.base
	if base == nil || r.stopped || base.Err() != nil {
		r.mu.Unlock()
		return 0, ErrRunnerStopped
	}
	r.wg.Add(1) // reserved under mu so Wait never races a new run
	r.mu.Unlock()

	if !r.busy.CompareAndSwap(false, true) {
		r.wg.Done()
		return 0, fmt.Errorf("%w on this server", cloudserver.ErrBackupAlreadyRunning)
	}
	r.expireStale(ctx)
	run, err := r.store.StartBackupRun(ctx, cloudstore.StartBackupRunParams{
		Trigger: cloudstore.BackupRunTriggerManual, ActorPrincipalID: actorPrincipalID, RefuseIfRunning: true,
	})
	if err != nil {
		r.busy.Store(false)
		r.wg.Done()
		if errors.Is(err, cloudstore.ErrBackupRunInProgress) {
			return 0, fmt.Errorf("%w (another server's run is still running)", cloudserver.ErrBackupAlreadyRunning)
		}
		return 0, fmt.Errorf("backuprunner: record manual run: %w", err)
	}
	stamp := r.clock.Now()
	go func() {
		defer r.wg.Done()
		defer r.busy.Store(false)
		r.execute(base, run, stamp)
	}()
	return run.ID, nil
}

// loop runs every slot of the schedule. It re-reads the schedule at least
// every poll interval. A slot is due once it is at or before now and after
// the previous check, so slots that passed while the server was down, busy
// or before the schedule was changed are not caught up.
func (r *Runner) loop(ctx context.Context) {
	defer r.wg.Done()
	r.expireStale(ctx)
	checked := r.clock.Now()
	for ctx.Err() == nil {
		wait := r.poll
		schedule, err := r.store.GetBackupSchedule(ctx)
		now := r.clock.Now()
		switch {
		case err != nil:
			if ctx.Err() != nil {
				return
			}
			// checked stays put: a slot that passes meanwhile still runs
			// once the schedule can be read again.
			r.logf("[engram-cloud] backup scheduler: read schedule: %v", err)
		default:
			slot, ok := schedule.NextRun(checked)
			if ok && !slot.After(now) {
				r.runScheduled(ctx, slot)
				checked = laterOf(slot, r.clock.Now())
				continue
			}
			if ok && slot.Sub(now) < wait {
				wait = slot.Sub(now)
			}
			checked = now
		}
		select {
		case <-ctx.Done():
			return
		case <-r.clock.After(wait):
		}
	}
}

func laterOf(a, b time.Time) time.Time {
	if a.After(b) {
		return a
	}
	return b
}

// runScheduled claims slot for this server and runs it. A slot another
// server already claimed is skipped without a trace. A slot that arrives
// while this server is still running a backup is not claimed, so a free
// server sharing the database can run it; with no such server it is not
// run at all.
func (r *Runner) runScheduled(ctx context.Context, slot time.Time) {
	if !r.busy.CompareAndSwap(false, true) {
		r.logf("[engram-cloud] scheduled backup %s not claimed: this server is still running another backup; another server may run it", slot.UTC().Format(time.RFC3339))
		return
	}
	defer r.busy.Store(false)
	r.expireStale(ctx)
	run, err := r.store.StartBackupRun(ctx, cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: slot})
	switch {
	case errors.Is(err, cloudstore.ErrBackupRunAlreadyRecorded):
		r.logf("[engram-cloud] scheduled backup %s is already recorded by another server; skipping", slot.UTC().Format(time.RFC3339))
		return
	case err != nil:
		if ctx.Err() == nil {
			r.logf("[engram-cloud] scheduled backup %s not started: record run: %v", slot.UTC().Format(time.RFC3339), err)
		}
		return
	}
	r.execute(ctx, run, slot)
}

// sweepStaleArchives removes the archive temp files that a server of this
// user left in the temp directory when it was killed (SIGKILL, out of
// memory) before its own cleanup ran. It removes only regular files named
// like the archive and owned by this user; symlinks are never followed.
func (r *Runner) sweepStaleArchives() {
	entries, err := os.ReadDir(r.tempDir)
	if err != nil {
		r.logf("[engram-cloud] backup runner: sweep stale archive temp files: %v", err)
		return
	}
	removed := 0
	for _, entry := range entries {
		if match, _ := filepath.Match(archiveTempPattern, entry.Name()); !match || !entry.Type().IsRegular() {
			continue
		}
		info, err := entry.Info() // lstat: a symlink is never followed
		if err != nil || !info.Mode().IsRegular() || !ownedByCurrentUser(info) {
			continue
		}
		if err := os.Remove(filepath.Join(r.tempDir, entry.Name())); err != nil {
			r.logf("[engram-cloud] backup runner: remove stale archive temp file: %v", err)
			continue
		}
		removed++
	}
	if removed > 0 {
		r.logf("[engram-cloud] backup runner: removed %d stale backup archive temp file(s) from %s", removed, r.tempDir)
	}
}

// expireStale marks runs left "running" by a stopped server as interrupted.
func (r *Runner) expireStale(ctx context.Context) {
	n, err := r.store.ExpireStaleBackupRuns(ctx, r.staleAfter)
	switch {
	case err != nil && ctx.Err() == nil:
		r.logf("[engram-cloud] backup runner: expire stale runs: %v", err)
	case n > 0:
		r.logf("[engram-cloud] backup runner: marked %d stale run(s) interrupted", n)
	}
}

// execute uploads one recorded run and records its result exactly once,
// even if the export or upload panics.
func (r *Runner) execute(ctx context.Context, run cloudstore.BackupRun, stamp time.Time) {
	result := cloudstore.FinishBackupRunParams{ID: run.ID, Status: cloudstore.BackupRunStatusFailure}
	defer func() {
		if p := recover(); p != nil {
			r.logf("[engram-cloud] backup run %d panicked: %s", run.ID, cloudstore.SanitizeBackupRunError(fmt.Sprint(p), result.Redact...))
			result = cloudstore.FinishBackupRunParams{ID: run.ID, Status: cloudstore.BackupRunStatusFailure, ErrorMessage: InternalErrorMessage, Redact: result.Redact}
		}
		r.finish(ctx, result)
	}()

	creds, err := r.store.OpenBackupDestinationCredentials(ctx, r.key)
	switch {
	case errors.Is(err, cloudstore.ErrBackupDestinationNotConfigured):
		result.ErrorMessage = SkippedNoDestinationMessage
		return
	case errors.Is(err, backupcrypto.ErrKeyMismatch), errors.Is(err, backupcrypto.ErrSealedValueInvalid):
		result.ErrorMessage = SkippedKeyMismatchMessage
		return
	case err != nil:
		result.ErrorMessage = r.failure(ctx, "read the backup destination", err)
		return
	}
	result.Redact = []string{creds.AccessKeyID, creds.SecretAccessKey}
	uploader, err := r.newUploader(creds)
	if err != nil {
		result.ErrorMessage = "invalid backup destination: " + err.Error()
		return
	}
	key := s3client.BackupObjectKey(creds.Prefix, stamp)
	size, err := r.exportAndUpload(ctx, uploader, key)
	if err != nil {
		result.ErrorMessage = err.Error()
		return
	}
	result = cloudstore.FinishBackupRunParams{ID: run.ID, Status: cloudstore.BackupRunStatusSuccess, ObjectKey: key, SizeBytes: size}
}

// exportAndUpload writes the archive to a private temp file and uploads it
// under an overall deadline. The temp file is always removed.
func (r *Runner) exportAndUpload(ctx context.Context, uploader Uploader, key string) (int64, error) {
	file, err := os.CreateTemp(r.tempDir, archiveTempPattern) // mode 0600
	if err != nil {
		return 0, fmt.Errorf("create the archive temp file: %w", err)
	}
	defer func() {
		_ = file.Close()
		_ = os.Remove(file.Name())
	}()

	exportCtx, cancelExport := context.WithTimeout(ctx, r.exportTimeout)
	err = r.export(exportCtx, file)
	exportErr := exportCtx.Err()
	cancelExport()
	switch {
	case ctx.Err() != nil:
		return 0, errors.New(CanceledMessage)
	case err != nil && errors.Is(exportErr, context.DeadlineExceeded):
		return 0, fmt.Errorf("export did not finish within %s", r.exportTimeout)
	case err != nil:
		return 0, fmt.Errorf("export: %w", err)
	}
	info, err := file.Stat()
	if err != nil {
		return 0, fmt.Errorf("stat the archive temp file: %w", err)
	}
	size := info.Size()
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return 0, fmt.Errorf("rewind the archive temp file: %w", err)
	}

	deadline := r.uploadDeadline(size)
	uploadCtx, cancelUpload := context.WithTimeout(ctx, deadline)
	defer cancelUpload()
	err = uploader.PutObject(uploadCtx, key, file, size, ContentType)
	switch {
	case err == nil:
		return size, nil
	case ctx.Err() != nil:
		return 0, errors.New(CanceledMessage)
	case errors.Is(uploadCtx.Err(), context.DeadlineExceeded):
		return 0, fmt.Errorf("upload of %d bytes did not finish within the overall deadline of %s", size, deadline)
	default:
		return 0, fmt.Errorf("upload: %w", err)
	}
}

// failure describes err, or the cancellation when ctx ended.
func (r *Runner) failure(ctx context.Context, what string, err error) string {
	if ctx.Err() != nil {
		return CanceledMessage
	}
	return what + ": " + err.Error()
}

// finish records the result with a context that survives shutdown, so a
// canceled run is recorded instead of staying "running".
func (r *Runner) finish(ctx context.Context, params cloudstore.FinishBackupRunParams) {
	recordCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), finishTimeout)
	defer cancel()
	run, err := r.store.FinishBackupRun(recordCtx, params)
	if err != nil {
		r.logf("[engram-cloud] backup run %d: record result: %v", params.ID, err)
		return
	}
	if run.Status == cloudstore.BackupRunStatusSuccess {
		r.logf("[engram-cloud] backup run %d uploaded %s (%d bytes)", run.ID, run.ObjectKey, run.SizeBytes)
		return
	}
	// The stored message is already sanitized; log that, never the raw error.
	r.logf("[engram-cloud] backup run %d failed: %s", run.ID, run.ErrorMessage)
}

// isNil reports a nil interface or a typed nil pointer.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
