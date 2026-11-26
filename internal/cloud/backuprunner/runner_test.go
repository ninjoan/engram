package backuprunner

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

// Monday 2026-11-30 02:59 UTC, one minute before the 03:00 slot.
var beforeSlot = time.Date(2026, 11, 30, 2, 59, 0, 0, time.UTC)
var slot = time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)

func mondayAt3() cloudstore.BackupSchedule {
	return cloudstore.BackupSchedule{Configured: true, Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC"}
}

func TestSchedulerUploadsAtTheComputedSlot(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)

	if wake := h.clock.waitSleeping(t); !wake.Equal(slot) {
		t.Fatalf("scheduler sleeps until %s, want the slot %s", wake, slot)
	}
	if puts := h.uploader.snapshot(); len(puts) != 0 {
		t.Fatalf("uploaded before the slot: %+v", puts)
	}
	h.clock.Advance(time.Minute)
	waitFor(t, "the scheduled upload", func() bool {
		return len(h.store.snapshot()) == 1 && h.store.snapshot()[0].Status != cloudstore.BackupRunStatusRunning
	})

	puts := h.uploader.snapshot()
	if len(puts) != 1 {
		t.Fatalf("uploads = %d, want 1", len(puts))
	}
	wantKey := "prod/nightly/engram-cloud-backup-20261130T030000Z-run1.tar.gz"
	if puts[0].key != wantKey || puts[0].contentType != "application/gzip" || puts[0].size != int64(len(archiveBytes)) || !bytes.Equal(puts[0].body, archiveBytes) {
		t.Fatalf("upload = key %q type %q size %d body %q; want %q application/gzip %d", puts[0].key, puts[0].contentType, puts[0].size, puts[0].body, wantKey, len(archiveBytes))
	}
	if puts[0].tempFiles != 1 {
		t.Fatalf("temp files during upload = %d, want the one spooled archive", puts[0].tempFiles)
	}
	if puts[0].deadline <= 0 || puts[0].deadline > MinUploadDeadline {
		t.Fatalf("upload ctx deadline in %s, want at most %s", puts[0].deadline, MinUploadDeadline)
	}
	run := h.store.snapshot()[0]
	if run.Trigger != cloudstore.BackupRunTriggerScheduled || !run.ScheduledFor.Equal(slot) || run.Status != cloudstore.BackupRunStatusSuccess || run.ObjectKey != wantKey || run.SizeBytes != int64(len(archiveBytes)) {
		t.Fatalf("run = %+v", run)
	}
	h.clock.waitSleeping(t)
	h.assertTempDirEmpty(t)

	// The next run is a week later; nothing else happens meanwhile.
	h.clock.Advance(24 * time.Hour)
	h.clock.waitSleeping(t)
	if n := len(h.uploader.snapshot()); n != 1 {
		t.Fatalf("uploads after a day = %d, want 1", n)
	}
}

func TestSchedulerSkipsDisabledSchedule(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	disabled := mondayAt3()
	disabled.Enabled = false
	h.store.setSchedule(disabled)
	h.start(t)

	for range 3 {
		h.clock.waitSleeping(t)
		h.clock.Advance(time.Minute)
	}
	h.clock.waitSleeping(t)
	if puts, runs := h.uploader.snapshot(), h.store.snapshot(); len(puts) != 0 || len(runs) != 0 {
		t.Fatalf("disabled schedule uploaded %d times and recorded %+v", len(puts), runs)
	}
}

func TestSchedulerRecordsSkippedRunWhenDestinationIsUnusable(t *testing.T) {
	for name, tc := range map[string]struct {
		err  error
		want string
	}{
		"no destination": {err: cloudstore.ErrBackupDestinationNotConfigured, want: SkippedNoDestinationMessage},
		"key mismatch":   {err: fmt.Errorf("cloudstore: open backup destination access key id: %w", backupcrypto.ErrKeyMismatch), want: SkippedKeyMismatchMessage},
		"tampered value": {err: fmt.Errorf("cloudstore: open: %w", backupcrypto.ErrSealedValueInvalid), want: SkippedKeyMismatchMessage},
	} {
		t.Run(name, func(t *testing.T) {
			h := newHarness(t, beforeSlot, nil)
			h.store.setSchedule(mondayAt3())
			h.store.setCredsErr(tc.err)
			h.start(t)
			h.clock.waitSleeping(t)
			h.clock.Advance(time.Minute)
			waitFor(t, "the skipped run", func() bool {
				runs := h.store.snapshot()
				return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusFailure
			})
			if puts := h.uploader.snapshot(); len(puts) != 0 {
				t.Fatalf("unusable destination still uploaded: %+v", puts)
			}
			run := h.store.snapshot()[0]
			if run.ErrorMessage != tc.want || !strings.HasPrefix(run.ErrorMessage, "skipped: ") || !run.ScheduledFor.Equal(slot) {
				t.Fatalf("run = %+v, want failure %q", run, tc.want)
			}
			h.clock.waitSleeping(t)
			h.assertTempDirEmpty(t)
		})
	}
}

func TestSchedulerPicksUpScheduleChangesWithoutRestart(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.start(t)
	// No schedule yet: the loop re-reads it every poll interval.
	if wake := h.clock.waitSleeping(t); !wake.Equal(beforeSlot.Add(DefaultPollInterval)) {
		t.Fatalf("idle loop wakes at %s, want after the poll interval", wake)
	}
	changed := mondayAt3()
	changed.TimeOfDay = "03:02"
	h.store.setSchedule(changed)
	h.clock.Advance(DefaultPollInterval) // 03:00: re-read, next slot 03:02
	if wake := h.clock.waitSleeping(t); !wake.Equal(time.Date(2026, 11, 30, 3, 1, 0, 0, time.UTC)) {
		t.Fatalf("after the change the loop wakes at %s, want the next poll", wake)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploaded before the new slot: %d", n)
	}
	h.clock.Advance(time.Minute)
	if wake := h.clock.waitSleeping(t); !wake.Equal(time.Date(2026, 11, 30, 3, 2, 0, 0, time.UTC)) {
		t.Fatalf("loop wakes at %s, want the new slot 03:02", wake)
	}
	h.clock.Advance(time.Minute)
	waitFor(t, "the upload at the new slot", func() bool { return len(h.uploader.snapshot()) == 1 })
	if runs := h.store.snapshot(); len(runs) != 1 || !runs[0].ScheduledFor.Equal(time.Date(2026, 11, 30, 3, 2, 0, 0, time.UTC)) {
		t.Fatalf("runs = %+v", runs)
	}
}

func TestSchedulerDoesNotRunSlotsMissedBeforeTheChange(t *testing.T) {
	// The server has been up since 01:00; at 05:00 the admin enables a
	// 03:00 schedule. 03:00 already passed, so nothing runs today.
	start := time.Date(2026, 11, 30, 5, 0, 0, 0, time.UTC)
	h := newHarness(t, start, nil)
	h.start(t)
	h.clock.waitSleeping(t)
	h.store.setSchedule(mondayAt3())
	h.clock.Advance(DefaultPollInterval)
	if wake := h.clock.waitSleeping(t); !wake.Equal(start.Add(2 * DefaultPollInterval)) {
		t.Fatalf("loop wakes at %s, want the next poll", wake)
	}
	if runs := h.store.snapshot(); len(runs) != 0 {
		t.Fatalf("a slot before the change ran: %+v", runs)
	}
}

func TestSchedulerSkipsSlotClaimedByAnotherServer(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	other, err := h.store.StartBackupRun(context.Background(), cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: slot})
	if err != nil {
		t.Fatal(err)
	}
	h.start(t)
	h.clock.waitSleeping(t)
	h.clock.Advance(time.Minute)
	h.clock.waitSleeping(t)
	if puts := h.uploader.snapshot(); len(puts) != 0 {
		t.Fatalf("a slot owned by another server was uploaded again: %+v", puts)
	}
	if runs := h.store.snapshot(); len(runs) != 1 || runs[0].ID != other.ID || runs[0].Status != cloudstore.BackupRunStatusRunning {
		t.Fatalf("runs = %+v, want only the other server's run untouched", runs)
	}
}

func TestSchedulerStopsPromptlyOnCancel(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	h.cancel()
	waitDone(t, "Wait after cancel", h.runner.Wait)
	if _, err := h.runner.StartManualBackup(context.Background(), "7"); !errors.Is(err, ErrRunnerStopped) {
		t.Fatalf("manual backup after stop error = %v, want %v", err, ErrRunnerStopped)
	}
}

func TestSchedulerExpiresStaleRunsAtStartupAndBeforeEachRun(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	if n := h.store.expireCount(); n != 1 {
		t.Fatalf("expire calls at startup = %d, want 1", n)
	}
	h.clock.Advance(time.Minute)
	waitFor(t, "the scheduled run", func() bool { return len(h.uploader.snapshot()) == 1 })
	h.clock.waitSleeping(t)
	if n := h.store.expireCount(); n != 2 {
		t.Fatalf("expire calls after a run = %d, want 2", n)
	}
	h.store.mu.Lock()
	calls := append([]time.Duration(nil), h.store.expireCalls...)
	h.store.mu.Unlock()
	for _, c := range calls {
		if c != DefaultStaleAfter {
			t.Fatalf("stale threshold = %s, want %s", c, DefaultStaleAfter)
		}
	}
}

func TestManualBackupRunsInTheBackground(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.start(t)
	h.clock.waitSleeping(t) // the loop's startup expiry is done
	id, err := h.runner.StartManualBackup(context.Background(), "42")
	if err != nil || id == 0 {
		t.Fatalf("StartManualBackup = %d, %v", id, err)
	}
	waitFor(t, "the manual run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	run := h.store.snapshot()[0]
	if run.ID != id || run.Trigger != cloudstore.BackupRunTriggerManual || run.ActorPrincipalID != "42" || run.Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("run = %+v", run)
	}
	puts := h.uploader.snapshot()
	if len(puts) != 1 || puts[0].key != "prod/nightly/engram-cloud-backup-20261130T025900Z-run1.tar.gz" || run.ObjectKey != puts[0].key {
		t.Fatalf("puts = %+v, run key %q", puts, run.ObjectKey)
	}
	// Stale runs are expired before the manual run is recorded.
	if calls, want := h.store.callLog(), []string{"expire", "expire", "start", "finish"}; strings.Join(calls, ",") != strings.Join(want, ",") {
		t.Fatalf("store calls = %v, want %v", calls, want)
	}
	h.assertTempDirEmpty(t)
}

func TestManualBackupRefusedWhileARunIsRunning(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, beforeSlot, nil)
	h.uploader.block = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	h.start(t)
	first, err := h.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	// Same server: refused without touching the history.
	if _, err := h.runner.StartManualBackup(context.Background(), "2"); !errors.Is(err, cloudserver.ErrBackupAlreadyRunning) {
		t.Fatalf("second manual backup error = %v, want %v", err, cloudserver.ErrBackupAlreadyRunning)
	}
	if runs := h.store.snapshot(); len(runs) != 1 {
		t.Fatalf("refused start recorded a run: %+v", runs)
	}
	close(release)
	waitFor(t, "the first run", func() bool { return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusSuccess })
	waitFor(t, "the runner to become idle", func() bool { return !h.runner.busy.Load() })

	// Another server's run is still running in the database: refused too.
	if _, err := h.store.StartBackupRun(context.Background(), cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerManual}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.runner.StartManualBackup(context.Background(), "3"); !errors.Is(err, cloudserver.ErrBackupAlreadyRunning) {
		t.Fatalf("manual backup while another server runs one: %v, want %v", err, cloudserver.ErrBackupAlreadyRunning)
	}
	if runs := h.store.snapshot(); len(runs) != 2 || runs[0].ID != first {
		t.Fatalf("runs = %+v", runs)
	}
	// The refusal released the in-process slot.
	if h.runner.busy.Load() {
		t.Fatal("a refused start left the runner busy")
	}
}

// A server busy with another run leaves a scheduled slot unclaimed, so a
// free server sharing the database can still upload it.
func TestScheduledSlotWhileBusyIsLeftForAnotherServer(t *testing.T) {
	release := make(chan struct{})
	busy := newHarness(t, beforeSlot, nil)
	busy.store.setSchedule(mondayAt3())
	busy.uploader.block = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	busy.start(t)
	busy.clock.waitSleeping(t)
	manual, err := busy.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the manual upload to start", func() bool { return busy.runner.busy.Load() })

	freeClock, freeLogs, freeUploader := newFakeClock(beforeSlot), &logSink{}, &fakeUploader{}
	free, err := New(Config{
		Store: busy.store, Key: fakeOpener{}, Clock: freeClock, TempDir: t.TempDir(), Export: writeArchive,
		NewUploader: func(cloudstore.BackupDestinationCredentials) (Uploader, error) { return freeUploader, nil },
		Logf:        freeLogs.Logf,
	})
	if err != nil {
		t.Fatal(err)
	}
	freeCtx, cancelFree := context.WithCancel(context.Background())
	free.Start(freeCtx)
	t.Cleanup(func() {
		cancelFree()
		waitDone(t, "free runner shutdown", free.Wait)
	})
	freeClock.waitSleeping(t)

	// The busy server reaches the slot first and must not claim it.
	busy.clock.Advance(time.Minute)
	waitFor(t, "the busy server to pass the slot", func() bool {
		return strings.Contains(busy.logs.text(), "not claimed: this server is still running another backup")
	})
	busy.clock.waitSleeping(t)
	if runs := busy.store.snapshot(); len(runs) != 1 || runs[0].ID != manual {
		t.Fatalf("runs after the busy server passed the slot = %+v, want only the manual run", runs)
	}

	// The free server claims and uploads it.
	freeClock.Advance(time.Minute)
	waitFor(t, "the free server's scheduled run", func() bool {
		runs := busy.store.snapshot()
		return len(runs) == 2 && runs[1].Status == cloudstore.BackupRunStatusSuccess
	})
	scheduled := busy.store.snapshot()[1]
	if scheduled.Trigger != cloudstore.BackupRunTriggerScheduled || !scheduled.ScheduledFor.Equal(slot) {
		t.Fatalf("scheduled run = %+v, want the %s slot", scheduled, slot)
	}
	if puts := freeUploader.snapshot(); len(puts) != 1 {
		t.Fatalf("free server uploads = %d, want 1", len(puts))
	}
	close(release)
	waitFor(t, "the manual run", func() bool { return busy.store.snapshot()[0].Status == cloudstore.BackupRunStatusSuccess })
	if puts := busy.uploader.snapshot(); len(puts) != 1 || !strings.Contains(puts[0].key, "engram-cloud-backup-20261130T025900Z") {
		t.Fatalf("busy server uploads = %+v, want only the manual run", puts)
	}

	// Once idle, the busy server finds the slot run by the free server and
	// records nothing more.
	waitFor(t, "the busy server to become idle", func() bool { return !busy.runner.busy.Load() })
	busy.clock.Advance(DefaultPollInterval)
	waitFor(t, "the busy server to find the slot recorded", func() bool {
		return strings.Contains(busy.logs.text(), "scheduled backup 2026-11-30T03:00:00Z, which passed while this server was busy, was run by another server")
	})
	busy.clock.waitSleeping(t)
	if runs := busy.store.snapshot(); len(runs) != 2 || runs[1].ID != scheduled.ID || runs[1].Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("runs after the busy server became idle = %+v, want the manual run and the free server's upload", runs)
	}
}

func TestUploadFailureIsRecordedWithoutCredentials(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.uploader.err = fmt.Errorf("s3client: PutObject: authentication failed: key %s secret %s <AWSAccessKeyId>%s</AWSAccessKeyId>", testAccessKeyID, testSecretKey, testAccessKeyID)
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed run", func() bool { return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusFailure })
	run := h.store.snapshot()[0]
	for _, secret := range []string{testAccessKeyID, testSecretKey} {
		if strings.Contains(run.ErrorMessage, secret) {
			t.Fatalf("stored error leaks a credential: %q", run.ErrorMessage)
		}
	}
	if !strings.Contains(run.ErrorMessage, "authentication failed") || run.ObjectKey != "" {
		t.Fatalf("run = %+v, want the sanitized upload error", run)
	}
	h.store.mu.Lock()
	redact := h.store.redacts[run.ID]
	h.store.mu.Unlock()
	if len(redact) != 2 || redact[0] != testAccessKeyID || redact[1] != testSecretKey {
		t.Fatalf("Redact = %q, want both credentials", redact)
	}
	h.assertTempDirEmpty(t)
	h.assertNoSecretsLogged(t)
}

func TestCancellationMidUploadRecordsFailureAndRemovesTheTempFile(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	uploading := make(chan struct{})
	h.uploader.block = func(ctx context.Context) error {
		close(uploading)
		<-ctx.Done()
		return &s3client.Error{Op: "PutObject", Kind: ctx.Err()}
	}
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	<-uploading
	h.cancel()
	waitDone(t, "Wait during an upload", h.runner.Wait)
	run := h.store.snapshot()[0]
	if run.Status != cloudstore.BackupRunStatusFailure || run.ErrorMessage != CanceledMessage {
		t.Fatalf("canceled run = %+v, want failure %q", run, CanceledMessage)
	}
	h.assertTempDirEmpty(t)
}

func TestPanicDuringExportIsRecordedAndCleanedUp(t *testing.T) {
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.Export = func(_ context.Context, w io.Writer) error {
			_, _ = w.Write([]byte("partial"))
			panic("boom")
		}
	})
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	h.clock.Advance(time.Minute)
	waitFor(t, "the failed run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusFailure
	})
	if run := h.store.snapshot()[0]; run.ErrorMessage != InternalErrorMessage {
		t.Fatalf("panicked run = %+v, want %q", run, InternalErrorMessage)
	}
	// The scheduler survives and keeps going.
	h.clock.waitSleeping(t)
	h.assertTempDirEmpty(t)
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads after a failed export = %d", n)
	}
}

func TestExportFailureIsRecordedWithoutUpload(t *testing.T) {
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.Export = func(context.Context, io.Writer) error {
			return errors.New("read snapshot: connection reset")
		}
	})
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the failed run", func() bool { return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusFailure })
	if run := h.store.snapshot()[0]; !strings.Contains(run.ErrorMessage, "export") || !strings.Contains(run.ErrorMessage, "connection reset") {
		t.Fatalf("run = %+v", run)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploaded after a failed export: %d", n)
	}
	h.assertTempDirEmpty(t)
}

// The overall upload deadline is enforced end to end through the real S3
// client against a server that accepts the body but never answers.
func TestOverallUploadDeadlineIsEnforced(t *testing.T) {
	var puts atomic.Int32
	hang := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		puts.Add(1)
		select {
		case <-r.Context().Done():
		case <-hang:
		}
	}))
	t.Cleanup(func() { close(hang); srv.Close() })
	var gotSize int64
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.NewUploader = nil // the real s3client
		cfg.UploadDeadline = func(size int64) time.Duration {
			atomic.StoreInt64(&gotSize, size)
			return 200 * time.Millisecond
		}
	})
	h.store.creds.Endpoint = srv.URL
	h.start(t)
	started := time.Now()
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the timed-out run", func() bool { return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusFailure })
	if elapsed := time.Since(started); elapsed > 3*time.Second {
		t.Fatalf("deadline enforced after %s", elapsed)
	}
	run := h.store.snapshot()[0]
	if !strings.Contains(run.ErrorMessage, "overall deadline of 200ms") {
		t.Fatalf("run = %+v, want the overall deadline error", run)
	}
	if puts.Load() != 1 || atomic.LoadInt64(&gotSize) != int64(len(archiveBytes)) {
		t.Fatalf("PUT requests = %d, deadline size = %d", puts.Load(), atomic.LoadInt64(&gotSize))
	}
	h.assertTempDirEmpty(t)
	h.assertNoSecretsLogged(t)
}

func TestUploadDeadlineScalesWithSize(t *testing.T) {
	for _, tc := range []struct {
		size int64
		want time.Duration
	}{
		{0, 30 * time.Minute},
		{100 << 20, 30 * time.Minute},
		{1 << 30, 30 * time.Minute}, // 1024s + 10m is still below the minimum
		{2 << 30, 2048*time.Second + 10*time.Minute},
		{s3client.MaxObjectSize, 5120*time.Second + 10*time.Minute},
	} {
		if got := UploadDeadline(tc.size); got != tc.want {
			t.Errorf("UploadDeadline(%d) = %s, want %s", tc.size, got, tc.want)
		}
	}
}

func TestNewRejectsIncompleteConfig(t *testing.T) {
	store := newFakeStore()
	var nilSealer *backupcrypto.Sealer
	for name, cfg := range map[string]Config{
		"no store":           {Key: fakeOpener{}},
		"no key":             {Store: store},
		"typed nil key":      {Store: store, Key: nilSealer},
		"negative poll":      {Store: store, Key: fakeOpener{}, PollInterval: -time.Second},
		"stale below a run":  {Store: store, Key: fakeOpener{}, StaleAfter: time.Hour},
		"negative stale":     {Store: store, Key: fakeOpener{}, StaleAfter: -time.Hour},
		"negative export to": {Store: store, Key: fakeOpener{}, ExportTimeout: -time.Hour},
	} {
		if _, err := New(cfg); err == nil {
			t.Errorf("%s: New accepted an invalid config", name)
		}
	}
}

// The stale threshold must exceed the export timeout plus the deadline of a
// maximum-size upload, including a custom UploadDeadline.
func TestNewRejectsAnUploadDeadlineReachingTheStaleThreshold(t *testing.T) {
	store := newFakeStore()
	var sizes []int64
	deadline := func(d time.Duration) func(int64) time.Duration {
		return func(size int64) time.Duration {
			sizes = append(sizes, size)
			return d
		}
	}
	// 2h export + 4h upload = the 6h default threshold: refused.
	_, err := New(Config{Store: store, Key: fakeOpener{}, UploadDeadline: deadline(4 * time.Hour)})
	if err == nil || !strings.Contains(err.Error(), "the stale threshold 6h0m0s must exceed the longest run (6h0m0s)") {
		t.Fatalf("New with a 4h upload deadline: %v, want the stale threshold refusal", err)
	}
	if len(sizes) != 1 || sizes[0] != s3client.MaxObjectSize {
		t.Fatalf("upload deadline consulted for sizes %v, want the maximum object size", sizes)
	}
	// A longer threshold accepts the same deadline; a shorter deadline fits the default.
	if _, err := New(Config{Store: store, Key: fakeOpener{}, StaleAfter: 6*time.Hour + time.Second, UploadDeadline: deadline(4 * time.Hour)}); err != nil {
		t.Fatalf("New with a longer stale threshold: %v", err)
	}
	if _, err := New(Config{Store: store, Key: fakeOpener{}, UploadDeadline: deadline(4*time.Hour - time.Second)}); err != nil {
		t.Fatalf("New with an upload deadline below the threshold: %v", err)
	}
	// Previous behavior: the default deadline fits the default threshold.
	if _, err := New(Config{Store: store, Key: fakeOpener{}}); err != nil {
		t.Fatalf("New with the defaults: %v", err)
	}
}

func TestManualBackupBeforeStartIsRefused(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); !errors.Is(err, ErrRunnerStopped) {
		t.Fatalf("manual backup before Start error = %v, want %v", err, ErrRunnerStopped)
	}
	if runs := h.store.snapshot(); len(runs) != 0 {
		t.Fatalf("refused start recorded %+v", runs)
	}
}

func TestDefaultTempDirIsTheSystemTempDir(t *testing.T) {
	h := newHarness(t, beforeSlot, func(cfg *Config) { cfg.TempDir = "" })
	if h.runner.tempDir != os.TempDir() {
		t.Fatalf("temp dir = %q, want %q", h.runner.tempDir, os.TempDir())
	}
}

// ageAll makes every entry of dir older than r's longest run, so the
// startup sweep considers it abandoned.
func ageAll(t *testing.T, r *Runner, dir string) {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	old := r.clock.Now().Add(-r.exportTimeout - r.uploadDeadline(s3client.MaxObjectSize) - time.Minute)
	for _, e := range entries {
		if e.Type()&os.ModeSymlink != 0 {
			continue
		}
		if err := os.Chtimes(filepath.Join(dir, e.Name()), old, old); err != nil {
			t.Fatal(err)
		}
	}
}

func writeTestFile(t *testing.T, path string) {
	t.Helper()
	if err := os.WriteFile(path, []byte("plaintext archive"), 0o600); err != nil {
		t.Fatal(err)
	}
}

// Start removes what a killed server left behind: regular upload temp files
// (engram-cloud-backup-upload-*.tar.gz) and export spool directories
// (engram-cloud-backup-export-*). Symlinks are never followed or removed,
// and other names, including archives downloaded from the dashboard, stay.
func TestStartRemovesStaleUploadFilesAndExportSpoolDirsOnly(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	stale := []string{"engram-cloud-backup-upload-123456789.tar.gz", "engram-cloud-backup-upload-.tar.gz"}
	kept := []string{
		"engram-cloud-backup-20261126T000000Z.tar.gz", // a download from the dashboard
		"engram-cloud-backup-123456789.tar.gz",        // the previous upload prefix
		"engram-cloud-backup-upload-1.tar", "engram-cloud-backup-upload-1.tar.gz.part", "other-123.tar.gz",
		"xengram-cloud-backup-upload-1.tar.gz", "engram-cloud-backup-export-file",
		"engram-cloud-backup-import-1",
	}
	for _, name := range append(append([]string(nil), stale...), kept...) {
		writeTestFile(t, filepath.Join(h.tempDir, name))
	}
	spool := "engram-cloud-backup-export-4242"
	if err := os.MkdirAll(filepath.Join(h.tempDir, spool, "nested"), 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(h.tempDir, spool, "table-1.jsonl"))
	writeTestFile(t, filepath.Join(h.tempDir, spool, "nested", "member"))
	keptDirs := []string{"engram-cloud-backup-upload-dir.tar.gz", "xengram-cloud-backup-export-1"}
	for _, dir := range keptDirs {
		if err := os.Mkdir(filepath.Join(h.tempDir, dir), 0o700); err != nil {
			t.Fatal(err)
		}
		writeTestFile(t, filepath.Join(h.tempDir, dir, "inside"))
	}

	// Symlinks named like an upload file or a spool dir stay, and so do
	// their targets.
	outside := t.TempDir()
	targetFile := filepath.Join(outside, "engram-cloud-backup-upload-target.tar.gz")
	writeTestFile(t, targetFile)
	targetDir := filepath.Join(outside, "engram-cloud-backup-export-target")
	if err := os.Mkdir(targetDir, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(targetDir, "inside"))
	links := map[string]string{
		"engram-cloud-backup-upload-link.tar.gz":     targetFile,
		"engram-cloud-backup-export-link":            targetDir,
		"engram-cloud-backup-upload-dangling.tar.gz": filepath.Join(outside, "missing"),
		"engram-cloud-backup-export-dangling":        filepath.Join(outside, "missing-dir"),
	}
	// Everything but the symlinks is older than the longest run.
	ageAll(t, h.runner, h.tempDir)
	symlinked := true
	for name, target := range links {
		if err := os.Symlink(target, filepath.Join(h.tempDir, name)); err != nil {
			symlinked = false // e.g. Windows without the privilege
			break
		}
	}

	h.start(t)
	h.clock.waitSleeping(t)

	for _, name := range append(stale, spool) {
		if _, err := os.Lstat(filepath.Join(h.tempDir, name)); !os.IsNotExist(err) {
			t.Errorf("stale %s was not removed (%v)", name, err)
		}
	}
	for _, name := range kept {
		if data, err := os.ReadFile(filepath.Join(h.tempDir, name)); err != nil || string(data) != "plaintext archive" {
			t.Errorf("%s was removed or changed: %q %v", name, data, err)
		}
	}
	for _, dir := range keptDirs {
		if _, err := os.Lstat(filepath.Join(h.tempDir, dir, "inside")); err != nil {
			t.Errorf("directory %s was removed: %v", dir, err)
		}
	}
	if symlinked {
		for name := range links {
			if info, err := os.Lstat(filepath.Join(h.tempDir, name)); err != nil || info.Mode()&os.ModeSymlink == 0 {
				t.Errorf("symlink %s changed: %v %v", name, info, err)
			}
		}
	}
	for _, target := range []string{targetFile, filepath.Join(targetDir, "inside")} {
		if data, err := os.ReadFile(target); err != nil || string(data) != "plaintext archive" {
			t.Errorf("symlink target %s changed: %q %v", target, data, err)
		}
	}
	if logs := h.logs.text(); !strings.Contains(logs, "removed 2 stale backup archive temp file(s) and 1 export spool dir(s) from "+h.tempDir) {
		t.Errorf("logs = %q, want the removed counts", logs)
	}
}

// An empty temp directory is swept silently.
func TestStartWithoutStaleArchivesLogsNothing(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.start(t)
	h.clock.waitSleeping(t)
	if logs := h.logs.text(); strings.Contains(logs, "stale backup archive") {
		t.Fatalf("logs = %q, want no sweep line", logs)
	}
}

// The archive temp file is private to the server user and lives in the
// configured temp directory.
func TestArchiveTempFileIsPrivateAndInTheTempDir(t *testing.T) {
	var mode os.FileMode
	var dir, name string
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.Export = func(ctx context.Context, w io.Writer) error {
			f, ok := w.(*os.File)
			if !ok {
				return fmt.Errorf("export writer is %T, want the temp file", w)
			}
			info, err := f.Stat()
			if err != nil {
				return err
			}
			mode, dir, name = info.Mode().Perm(), filepath.Dir(f.Name()), filepath.Base(f.Name())
			return writeArchive(ctx, w)
		}
	})
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	if run := h.store.snapshot()[0]; run.Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("run = %+v", run)
	}
	if dir != h.tempDir {
		t.Fatalf("temp file dir = %s, want %s", dir, h.tempDir)
	}
	if match, _ := filepath.Match("engram-cloud-backup-upload-*.tar.gz", name); !match {
		t.Fatalf("temp file name = %s, want engram-cloud-backup-upload-*.tar.gz", name)
	}
	if runtime.GOOS != "windows" && mode != 0o600 {
		t.Fatalf("temp file mode = %o, want 600", mode)
	}
	h.assertTempDirEmpty(t)
}

type credentialEchoError struct{ msg string }

func (e *credentialEchoError) Error() string { return e.msg }

// An uploader that cannot be built from the destination records its error
// without the credentials it may echo, and uploads nothing.
func TestInvalidDestinationErrorIsRecordedWithoutCredentials(t *testing.T) {
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.NewUploader = func(creds cloudstore.BackupDestinationCredentials) (Uploader, error) {
			return nil, &credentialEchoError{msg: "bad endpoint for " + creds.SecretAccessKey + " id=" + creds.AccessKeyID}
		}
	})
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	run := h.store.snapshot()[0]
	if run.Status != cloudstore.BackupRunStatusFailure || !strings.HasPrefix(run.ErrorMessage, "invalid backup destination: bad endpoint for") {
		t.Fatalf("run = %+v, want the invalid destination failure", run)
	}
	for _, secret := range []string{testAccessKeyID, testSecretKey} {
		if strings.Contains(run.ErrorMessage, secret) {
			t.Fatalf("stored error leaks a credential: %q", run.ErrorMessage)
		}
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads = %d, want 0", n)
	}
	h.assertTempDirEmpty(t)
	h.assertNoSecretsLogged(t)
}
