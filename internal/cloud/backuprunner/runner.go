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
// uploads it; a server busy with another run leaves the slot to the others
// and, once idle, records it as skipped if none of them ran it. A run that
// stays "running" past the stale threshold belongs to a server that stopped
// mid-run and is marked interrupted. When it starts and then every
// sweepInterval while it is idle, the runner removes the upload temp files
// and export spool directories that a killed server left in its temp
// directory, once they are older than the longest possible run.
// After a shutdown, recording a run's start and result shares a budget of a
// few seconds, so the process exits within a container's stop grace period.
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

	// claimTimeout bounds recording the start of a run. The claim ignores
	// the caller's cancellation, so a request or shutdown that ends while
	// the row commits cannot leave it "running".
	claimTimeout = 30 * time.Second
	// finishTimeout bounds recording a result, all attempts included.
	finishTimeout = 30 * time.Second
	// shutdownBudget bounds every store write still running or started
	// after a shutdown (the claim and the result of the run in progress,
	// all attempts included). It is shared, so a shutdown ends well within
	// the 10 seconds `docker stop` waits before SIGKILL.
	shutdownBudget = 5 * time.Second
	// finishAttempts is how often recording a result is tried.
	finishAttempts = 3
	// finishBackoff is the default wait before the second attempt to
	// record a result; the third waits twice as long.
	finishBackoff = time.Second
	// sweepInterval is how often the scheduler loop repeats the startup
	// sweep, so the leftovers of a server killed and restarted at once are
	// removed once they are old enough, not at some later restart.
	sweepInterval = time.Hour

	// uploadTempPattern names the archive temp file of a run. It differs
	// from the name of an archive downloaded from the dashboard
	// (engram-cloud-backup-<time>.tar.gz), so the sweep, which removes
	// regular files matching it, never touches a download.
	uploadTempPattern = "engram-cloud-backup-upload-*.tar.gz"
	// exportSpoolPattern names the spool directory of cloudbackup.Export;
	// the sweep removes directories matching it.
	exportSpoolPattern = cloudbackup.ExportSpoolPattern
)

// Messages recorded in the run history. A slot that could not run is
// recorded as a failure whose message starts with "skipped: ".
const (
	SkippedNoDestinationMessage = "skipped: no backup destination is configured"
	SkippedKeyMismatchMessage   = "skipped: the stored destination credentials cannot be opened with the current ENGRAM_CLOUD_BACKUP_KEY; save the destination again"
	SkippedBusyMessage          = "skipped: another backup was still running"
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
	// finishBackoff is the wait before the second attempt to record a
	// result; each later attempt waits twice as long.
	finishBackoff time.Duration
	// sweepAge is the age after which the sweep treats an upload temp file
	// or export spool directory as abandoned: the longest run.
	sweepAge time.Duration
	// drain survives the shutdown by shutdownBudget; store writes that must
	// outlive a shutdown (claim, result) derive from it. Set by Start.
	drain context.Context

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
		finishBackoff: finishBackoff,
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
	longest := r.exportTimeout + r.uploadDeadline(s3client.MaxObjectSize)
	if r.staleAfter <= longest {
		return nil, fmt.Errorf("backuprunner: the stale threshold %s must exceed the longest run (%s)", r.staleAfter, longest)
	}
	r.sweepAge = longest
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

// Start removes stale archive temp files, then launches the scheduler loop,
// which removes them again every sweepInterval while no run is in progress.
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
	drain, endDrain := context.WithCancel(context.WithoutCancel(ctx))
	context.AfterFunc(ctx, func() { time.AfterFunc(shutdownBudget, endDrain) })
	r.drain = drain
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
	run, err := r.claim(cloudstore.StartBackupRunParams{
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
// the previous check, so slots that passed while the server was down or
// before the schedule was changed are not caught up. A slot whose schedule
// could not be read or whose claim failed is tried again at the next poll.
// A slot that arrived while this server was busy is recorded as skipped at
// the first poll after it became idle, unless another server ran it. The
// stale archive sweep is repeated at the first poll at least sweepInterval
// after the previous one at which no run is in progress.
func (r *Runner) loop(ctx context.Context) {
	defer r.wg.Done()
	r.expireStale(ctx)
	checked := r.clock.Now()
	swept := checked // Start swept just before the loop began
	var busySlots []time.Time
	// failedSlot is the slot whose last claim failed: its retry may find
	// the row of that claim if the claim committed but its reply was lost.
	var failedSlot time.Time
	for ctx.Err() == nil {
		wait := r.poll
		swept = r.sweepIfDue(swept)
		busySlots = r.recordBusySlots(ctx, busySlots)
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
				switch r.runScheduled(ctx, slot, slot.Equal(failedSlot)) {
				case slotBusy:
					busySlots = append(busySlots, slot)
					fallthrough
				case slotDone:
					failedSlot = time.Time{}
					checked = laterOf(slot, r.clock.Now())
					continue
				}
				// The claim failed: checked stays put, so the slot is
				// claimed again after the poll interval.
				failedSlot = slot
				break
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

// slotOutcome is what runScheduled did with a slot.
type slotOutcome int

const (
	slotDone        slotOutcome = iota // run, skipped or shutting down
	slotClaimFailed                    // retry at the next poll
	slotBusy                           // this server is busy; record it later
)

// runScheduled claims slot for this server and runs it. A slot another
// server already claimed is skipped without a trace; retry tells that this
// server's own previous claim of slot failed, so the row found may be its
// own. A slot that arrives while this server is still running a backup is
// not claimed, so a free server sharing the database can run it.
func (r *Runner) runScheduled(ctx context.Context, slot time.Time, retry bool) slotOutcome {
	at := slot.UTC().Format(time.RFC3339)
	if !r.busy.CompareAndSwap(false, true) {
		r.logf("[engram-cloud] scheduled backup %s not claimed: this server is still running another backup; another server may run it, otherwise it is recorded as skipped once this server is idle", at)
		return slotBusy
	}
	defer r.busy.Store(false)
	r.expireStale(ctx)
	if ctx.Err() != nil {
		return slotDone // shutting down: claim nothing
	}
	run, err := r.claim(cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: slot})
	switch {
	case errors.Is(err, cloudstore.ErrBackupRunAlreadyRecorded) && retry:
		r.logf("[engram-cloud] scheduled backup %s is already recorded, by another server or by an earlier claim of this server whose reply was lost; skipping", at)
		return slotDone
	case errors.Is(err, cloudstore.ErrBackupRunAlreadyRecorded):
		r.logf("[engram-cloud] scheduled backup %s is already recorded by another server; skipping", at)
		return slotDone
	case err != nil:
		r.logf("[engram-cloud] scheduled backup %s not started: record run: %v; retrying at the next poll", at, err)
		return slotClaimFailed
	}
	r.execute(ctx, run, slot)
	return slotDone
}

// recordBusySlots records the slots that arrived while this server was busy
// as skipped, once it is idle, and returns those still to record. A slot
// another server ran meanwhile is left alone; one whose claim failed is
// tried again at the next poll.
func (r *Runner) recordBusySlots(ctx context.Context, slots []time.Time) []time.Time {
	if len(slots) == 0 || ctx.Err() != nil || r.busy.Load() {
		return slots
	}
	var left []time.Time
	for _, slot := range slots {
		at := slot.UTC().Format(time.RFC3339)
		run, err := r.claim(cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: slot})
		switch {
		case errors.Is(err, cloudstore.ErrBackupRunAlreadyRecorded):
			r.logf("[engram-cloud] scheduled backup %s, which passed while this server was busy, was run by another server", at)
		case err != nil:
			r.logf("[engram-cloud] scheduled backup %s, which passed while this server was busy, not recorded as skipped: record run: %v; retrying at the next poll", at, err)
			left = append(left, slot)
		default:
			r.finish(cloudstore.FinishBackupRunParams{ID: run.ID, Status: cloudstore.BackupRunStatusFailure, ErrorMessage: SkippedBusyMessage})
		}
	}
	return left
}

// claim records the start of a run. It ignores the cancellation of the
// request or shutdown that triggered it (one ending while the row commits
// would otherwise leave it "running" with nobody to finish it) and is
// bounded by claimTimeout and, after a shutdown, by the shutdown budget.
// After a shutdown the claimed run is recorded as canceled.
func (r *Runner) claim(params cloudstore.StartBackupRunParams) (cloudstore.BackupRun, error) {
	claimCtx, cancel := context.WithTimeout(r.drain, claimTimeout)
	defer cancel()
	return r.store.StartBackupRun(claimCtx, params)
}

// sweepIfDue repeats the stale archive sweep when sweepInterval has passed
// since the last one and returns when the last sweep ran. It
// never sweeps while this server runs a backup, so the upload temp file and
// export spool directory of that run are never removed; a run that starts
// during the sweep creates entries far younger than the age bound, which
// the sweep keeps.
func (r *Runner) sweepIfDue(last time.Time) time.Time {
	now := r.clock.Now()
	if now.Sub(last) < sweepInterval || r.busy.Load() {
		return last
	}
	r.sweepStaleArchives()
	return now
}

// sweepStaleArchives removes what a server of this user left in the temp
// directory when it was killed (SIGKILL, out of memory) before its own
// cleanup ran: regular files named like an upload temp file and
// directories named like an export spool directory, both owned by this
// user and last modified longer ago than the longest possible run, so the
// files of a run of another live server sharing the directory stay.
// Symlinks are never followed or removed; other names and file types are
// left alone.
func (r *Runner) sweepStaleArchives() {
	entries, err := os.ReadDir(r.tempDir)
	if err != nil {
		r.logf("[engram-cloud] backup runner: sweep stale archive temp files: %v", err)
		return
	}
	now := r.clock.Now()
	files, dirs := 0, 0
	for _, entry := range entries {
		name := entry.Name()
		isUpload, _ := filepath.Match(uploadTempPattern, name)
		isSpool, _ := filepath.Match(exportSpoolPattern, name)
		if !isUpload && !isSpool {
			continue
		}
		info, err := os.Lstat(filepath.Join(r.tempDir, name)) // a symlink is never followed
		if err != nil || !ownedByCurrentUser(info) || now.Sub(info.ModTime()) <= r.sweepAge {
			continue
		}
		path := filepath.Join(r.tempDir, name)
		switch {
		case isUpload && info.Mode().IsRegular():
			if err := os.Remove(path); err != nil {
				r.logf("[engram-cloud] backup runner: remove stale archive temp file: %v", err)
				continue
			}
			files++
		case isSpool && info.IsDir():
			// RemoveAll removes symlinks inside the directory without
			// following them.
			if err := os.RemoveAll(path); err != nil {
				r.logf("[engram-cloud] backup runner: remove stale export spool dir: %v", err)
				continue
			}
			dirs++
		}
	}
	if files > 0 || dirs > 0 {
		r.logf("[engram-cloud] backup runner: removed %d stale backup archive temp file(s) and %d export spool dir(s) from %s", files, dirs, r.tempDir)
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
		r.finish(result)
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
	key := s3client.BackupRunObjectKey(creds.Prefix, stamp, run.ID)
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
	file, err := os.CreateTemp(r.tempDir, uploadTempPattern) // mode 0600
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
// canceled run is recorded instead of staying "running". The run's temp
// file is already removed. A failed attempt is retried with a short
// backoff, up to finishAttempts attempts within finishTimeout and, after a
// shutdown, within the shutdown budget; a run that is no longer running is
// not retried. A retry that finds the run no longer running most likely
// follows an attempt that recorded the result but lost its reply. When
// every attempt fails, the log names the run's status and object key
// (never the raw error message or credentials) and the stale expiry later
// marks the run interrupted.
func (r *Runner) finish(params cloudstore.FinishBackupRunParams) {
	recordCtx, cancel := context.WithTimeout(r.drain, finishTimeout)
	defer cancel()
	var run cloudstore.BackupRun
	var err error
	attempts := 0
	for backoff := r.finishBackoff; ; backoff *= 2 {
		attempts++
		run, err = r.store.FinishBackupRun(recordCtx, params)
		if err == nil || attempts == finishAttempts || errors.Is(err, cloudstore.ErrBackupRunNotRunning) || !sleepCtx(recordCtx, backoff) {
			break
		}
	}
	if err != nil && attempts > 1 && errors.Is(err, cloudstore.ErrBackupRunNotRunning) {
		r.logf("[engram-cloud] backup run %d: the result (status %s, object key %q) was probably recorded by an earlier attempt whose reply was lost: attempt %d found the run no longer running", params.ID, params.Status, params.ObjectKey, attempts)
		return
	}
	if err != nil {
		plural := "s"
		if attempts == 1 {
			plural = ""
		}
		r.logf("[engram-cloud] backup run %d: could not record the result (status %s, object key %q) after %d attempt%s: %v", params.ID, params.Status, params.ObjectKey, attempts, plural, err)
		return
	}
	if run.Status == cloudstore.BackupRunStatusSuccess {
		r.logf("[engram-cloud] backup run %d uploaded %s (%d bytes)", run.ID, run.ObjectKey, run.SizeBytes)
		return
	}
	// The stored message is already sanitized; log that, never the raw error.
	r.logf("[engram-cloud] backup run %d failed: %s", run.ID, run.ErrorMessage)
}

// sleepCtx waits d and reports false when ctx ends first.
func sleepCtx(ctx context.Context, d time.Duration) bool {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-timer.C:
		return true
	}
}

// isNil reports a nil interface or a typed nil pointer.
func isNil(v any) bool {
	if v == nil {
		return true
	}
	rv := reflect.ValueOf(v)
	return rv.Kind() == reflect.Pointer && rv.IsNil()
}
