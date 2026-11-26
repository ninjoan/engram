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
	wantKey := "prod/nightly/engram-cloud-backup-20261130T030000Z.tar.gz"
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
	if len(puts) != 1 || puts[0].key != "prod/nightly/engram-cloud-backup-20261130T025900Z.tar.gz" || run.ObjectKey != puts[0].key {
		t.Fatalf("puts = %+v, run key %q", puts, run.ObjectKey)
	}
	if h.store.expireCount() < 2 {
		t.Fatalf("stale runs were not expired before the manual run")
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

func TestScheduledSlotWhileAManualRunIsRunningIsRecordedAsSkipped(t *testing.T) {
	release := make(chan struct{})
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.uploader.block = func(ctx context.Context) error {
		select {
		case <-release:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	h.start(t)
	h.clock.waitSleeping(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the manual upload to start", func() bool { return h.runner.busy.Load() })
	h.clock.Advance(time.Minute)
	waitFor(t, "the skipped slot", func() bool { return len(h.store.snapshot()) == 2 })
	h.clock.waitSleeping(t)
	skipped := h.store.snapshot()[1]
	if skipped.Trigger != cloudstore.BackupRunTriggerScheduled || skipped.Status != cloudstore.BackupRunStatusFailure || skipped.ErrorMessage != SkippedBusyMessage {
		t.Fatalf("slot during a manual run = %+v, want failure %q", skipped, SkippedBusyMessage)
	}
	close(release)
	waitFor(t, "the manual run", func() bool { return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusSuccess })
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
