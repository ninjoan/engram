package backuprunner

import (
	"context"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// A scheduled slot whose claim fails (a database blip) is retried at the
// next poll instead of being lost.
func TestScheduledSlotIsRetriedAfterAFailedClaim(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.store.mu.Lock()
	h.store.startFailures = 1
	h.store.mu.Unlock()
	h.start(t)
	h.clock.waitSleeping(t)

	h.clock.Advance(time.Minute) // 03:00: the claim fails
	if wake := h.clock.waitSleeping(t); !wake.Equal(slot.Add(DefaultPollInterval)) {
		t.Fatalf("after a failed claim the loop wakes at %s, want the next poll %s", wake, slot.Add(DefaultPollInterval))
	}
	if runs := h.store.snapshot(); len(runs) != 0 {
		t.Fatalf("runs after the failed claim = %+v", runs)
	}
	if logs := h.logs.text(); !strings.Contains(logs, "scheduled backup 2026-11-30T03:00:00Z not started: record run: "+errStoreUnavailable.Error()) {
		t.Fatalf("logs = %q, want the failed claim", logs)
	}

	h.clock.Advance(DefaultPollInterval) // 03:01: the retry claims the 03:00 slot
	waitFor(t, "the retried slot", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusSuccess
	})
	if run := h.store.snapshot()[0]; run.Trigger != cloudstore.BackupRunTriggerScheduled || !run.ScheduledFor.Equal(slot) {
		t.Fatalf("run = %+v, want the %s slot", run, slot)
	}
	h.clock.waitSleeping(t)
	h.clock.Advance(DefaultPollInterval)
	h.clock.waitSleeping(t)
	if puts, starts := h.uploader.snapshot(), h.store.countCalls("start"); len(puts) != 1 || starts != 2 {
		t.Fatalf("uploads = %d, claims = %d; want the slot uploaded once after 2 claims", len(puts), starts)
	}
}

// A database that keeps failing gets one claim attempt per poll interval.
func TestPermanentlyFailingClaimIsRetriedOncePerPoll(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.store.mu.Lock()
	h.store.startFailures = -1
	h.store.mu.Unlock()
	h.start(t)
	h.clock.waitSleeping(t)
	h.clock.Advance(time.Minute)
	for i := 1; i <= 3; i++ {
		now := h.clock.Now()
		if wake := h.clock.waitSleeping(t); !wake.Equal(now.Add(DefaultPollInterval)) {
			t.Fatalf("poll %d: loop wakes at %s, want %s", i, wake, now.Add(DefaultPollInterval))
		}
		if n := h.store.countCalls("start"); n != i {
			t.Fatalf("claims after %d poll(s) = %d, want %d", i, n, i)
		}
		h.clock.Advance(DefaultPollInterval)
	}
	h.clock.waitSleeping(t)
	if runs, puts := h.store.snapshot(), h.uploader.snapshot(); len(runs) != 0 || len(puts) != 0 {
		t.Fatalf("runs = %+v, uploads = %d; want none", runs, len(puts))
	}
}

// A slot that passes while the schedule cannot be read still runs once it
// can be read again.
func TestSlotPassingWhileTheScheduleIsUnreadableRunsOnceReadable(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	h.store.setScheduleErr(errStoreUnavailable)
	h.clock.Advance(time.Minute) // 03:00: the schedule cannot be read
	if wake := h.clock.waitSleeping(t); !wake.Equal(slot.Add(DefaultPollInterval)) {
		t.Fatalf("loop wakes at %s, want the next poll", wake)
	}
	if runs := h.store.snapshot(); len(runs) != 0 {
		t.Fatalf("runs while the schedule is unreadable = %+v", runs)
	}
	if logs := h.logs.text(); !strings.Contains(logs, "backup scheduler: read schedule: "+errStoreUnavailable.Error()) {
		t.Fatalf("logs = %q, want the read error", logs)
	}
	h.store.setScheduleErr(nil)
	h.clock.Advance(DefaultPollInterval)
	waitFor(t, "the slot once the schedule is readable", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusSuccess
	})
	if run := h.store.snapshot()[0]; !run.ScheduledFor.Equal(slot) {
		t.Fatalf("run = %+v, want the %s slot", run, slot)
	}
	h.clock.waitSleeping(t)
	h.clock.Advance(DefaultPollInterval)
	h.clock.waitSleeping(t)
	if n := len(h.uploader.snapshot()); n != 1 {
		t.Fatalf("uploads = %d, want the slot once", n)
	}
}

// The manual claim does not inherit the request's cancellation: a request
// that ends while the run row commits cannot orphan a "running" row.
func TestManualClaimSurvivesTheRequestEndingMidCommit(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.start(t)
	reqCtx, cancelReq := context.WithCancel(context.Background())
	defer cancelReq()
	var claimDeadline time.Duration
	h.store.mu.Lock()
	h.store.startHook = func(ctx context.Context) error {
		cancelReq()
		if d, ok := ctx.Deadline(); ok {
			claimDeadline = time.Until(d)
		}
		return ctx.Err()
	}
	h.store.mu.Unlock()

	id, err := h.runner.StartManualBackup(reqCtx, "1")
	if err != nil || id == 0 {
		t.Fatalf("StartManualBackup = %d, %v; want the run started", id, err)
	}
	if claimDeadline <= 0 || claimDeadline > 30*time.Second {
		t.Fatalf("claim deadline in %s, want a bound of at most 30s", claimDeadline)
	}
	waitFor(t, "the manual run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	if run := h.store.snapshot()[0]; run.ID != id || run.Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("run = %+v, want run %d uploaded", run, id)
	}
}

// A shutdown while the scheduled claim commits records the run as canceled
// instead of leaving it "running".
func TestShutdownDuringTheScheduledClaimRecordsTheRunCanceled(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	h.store.mu.Lock()
	h.store.startHook = func(ctx context.Context) error {
		h.cancel()
		return ctx.Err()
	}
	h.store.mu.Unlock()
	h.clock.Advance(time.Minute)
	waitDone(t, "Wait after the shutdown", h.runner.Wait)
	runs := h.store.snapshot()
	if len(runs) != 1 || runs[0].Status != cloudstore.BackupRunStatusFailure || runs[0].ErrorMessage != CanceledMessage {
		t.Fatalf("runs = %+v, want the slot recorded as %q", runs, CanceledMessage)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads = %d, want none", n)
	}
	h.assertTempDirEmpty(t)
}

// Two runs in the same second upload to distinct objects.
func TestRunsInTheSameSecondUploadDistinctObjects(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.start(t)
	for i := 1; i <= 2; i++ {
		if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
			t.Fatalf("manual run %d: %v", i, err)
		}
		waitFor(t, "the manual run", func() bool {
			runs := h.store.snapshot()
			return len(runs) == i && runs[i-1].Status == cloudstore.BackupRunStatusSuccess && !h.runner.busy.Load()
		})
	}
	puts, runs := h.uploader.snapshot(), h.store.snapshot()
	want := []string{
		"prod/nightly/engram-cloud-backup-20261130T025900Z-run1.tar.gz",
		"prod/nightly/engram-cloud-backup-20261130T025900Z-run2.tar.gz",
	}
	if len(puts) != 2 || puts[0].key != want[0] || puts[1].key != want[1] {
		t.Fatalf("uploaded keys = %+v, want %v", puts, want)
	}
	if runs[0].ObjectKey != want[0] || runs[1].ObjectKey != want[1] {
		t.Fatalf("recorded keys = %q, %q; want %v", runs[0].ObjectKey, runs[1].ObjectKey, want)
	}
}

// Recording a result is retried with a short backoff.
func TestFinishIsRetriedUntilTheResultIsRecorded(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.runner.finishBackoff = time.Millisecond
	h.store.mu.Lock()
	h.store.finishFailures = 2
	h.store.mu.Unlock()
	h.start(t)
	id, err := h.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the recorded result", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusSuccess
	})
	waitFor(t, "the runner to become idle", func() bool { return !h.runner.busy.Load() })
	if n := h.store.countCalls("finish"); n != 3 {
		t.Fatalf("finish attempts = %d, want 3", n)
	}
	if logs := h.logs.text(); strings.Contains(logs, "record result") || !strings.Contains(logs, "uploaded prod/nightly/engram-cloud-backup-") {
		t.Fatalf("logs = %q, want only the success line for run %d", logs, id)
	}
}

// A result that cannot be recorded after three attempts is logged with the
// run's status and object key, never with credentials.
func TestFinishGivesUpAfterThreeAttemptsAndLogsTheResult(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.runner.finishBackoff = time.Millisecond
	h.store.mu.Lock()
	h.store.finishFailures = -1
	h.store.mu.Unlock()
	h.start(t)
	id, err := h.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	want := "backup run 1: could not record the result (status success, object key \"prod/nightly/engram-cloud-backup-20261130T025900Z-run1.tar.gz\") after 3 attempts: " + errStoreUnavailable.Error()
	waitFor(t, "the final failure log", func() bool { return strings.Contains(h.logs.text(), want) })
	waitFor(t, "the runner to become idle", func() bool { return !h.runner.busy.Load() })
	if n := h.store.countCalls("finish"); n != 3 {
		t.Fatalf("finish attempts = %d, want 3", n)
	}
	if run := h.store.snapshot()[0]; run.ID != id || run.Status != cloudstore.BackupRunStatusRunning {
		t.Fatalf("run = %+v, want it left running for the stale expiry", run)
	}
	h.assertNoSecretsLogged(t)
}

// A run that is no longer running (expired as stale meanwhile) is not
// retried.
func TestFinishDoesNotRetryARunThatIsNoLongerRunning(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.runner.finishBackoff = time.Millisecond
	h.start(t)
	h.uploader.block = func(context.Context) error {
		h.store.mu.Lock()
		defer h.store.mu.Unlock()
		h.store.runs[0].Status = cloudstore.BackupRunStatusFailure
		return nil
	}
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the final failure log", func() bool { return strings.Contains(h.logs.text(), "after 1 attempt") })
	if n := h.store.countCalls("finish"); n != 1 {
		t.Fatalf("finish attempts = %d, want 1", n)
	}
	if logs := h.logs.text(); !strings.Contains(logs, cloudstore.ErrBackupRunNotRunning.Error()) {
		t.Fatalf("logs = %q, want the not-running error", logs)
	}
}

// An export that outlives the export timeout is recorded as such.
func TestExportTimeoutIsClassified(t *testing.T) {
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.ExportTimeout = 50 * time.Millisecond
		cfg.Export = func(ctx context.Context, _ io.Writer) error {
			<-ctx.Done()
			return errors.Join(errors.New("read snapshot"), ctx.Err())
		}
	})
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "the timed-out run", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status == cloudstore.BackupRunStatusFailure
	})
	if run := h.store.snapshot()[0]; run.ErrorMessage != "export did not finish within 50ms" {
		t.Fatalf("run = %+v, want the export timeout", run)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads = %d, want none", n)
	}
	h.assertTempDirEmpty(t)
}
