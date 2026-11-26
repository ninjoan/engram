package backuprunner

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

// shutdownLimit is how long a shutdown may take when the database hangs:
// `docker stop` sends SIGKILL after 10 seconds, so the runner must be done
// well before that (5 seconds of database time plus scheduling slack).
const shutdownLimit = 6500 * time.Millisecond

// waitWithin runs Wait and returns how long it took, failing after limit.
func waitWithin(t *testing.T, r *Runner, limit time.Duration) time.Duration {
	t.Helper()
	started := time.Now()
	done := make(chan struct{})
	go func() { r.Wait(); close(done) }()
	select {
	case <-done:
		return time.Since(started)
	case <-time.After(limit):
		t.Fatalf("Wait did not return within %s of the shutdown", limit)
		return 0
	}
}

// hang blocks until ctx ends, like a database that never answers.
func hang(ctx context.Context) error {
	<-ctx.Done()
	return ctx.Err()
}

// A shutdown while the database hangs on the result of a run ends within
// the shutdown budget, and the plaintext temp file is already gone when the
// result is recorded.
func TestShutdownWithAHungFinishEndsWithinTheBudget(t *testing.T) {
	t.Parallel()
	h := newHarness(t, beforeSlot, nil)
	uploading := make(chan struct{})
	h.uploader.block = func(ctx context.Context) error {
		close(uploading)
		return hang(ctx)
	}
	var mu sync.Mutex
	var leftAtFinish []string
	h.store.finishGate = func(ctx context.Context) error {
		entries, _ := os.ReadDir(h.tempDir)
		mu.Lock()
		for _, e := range entries {
			leftAtFinish = append(leftAtFinish, e.Name())
		}
		mu.Unlock()
		return hang(ctx)
	}
	h.start(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatal(err)
	}
	<-uploading
	h.cancel()
	if took := waitWithin(t, h.runner, 15*time.Second); took > shutdownLimit {
		t.Fatalf("shutdown with a hung database took %s, want at most %s", took, shutdownLimit)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(leftAtFinish) != 0 {
		t.Fatalf("temp files present while the result was recorded: %v", leftAtFinish)
	}
	if n := h.store.countCalls("finish"); n < 1 {
		t.Fatalf("finish attempts = %d, want the result tried", n)
	}
	h.assertTempDirEmpty(t)
}

// A shutdown while the database hangs on the claim of a scheduled slot ends
// within the shutdown budget.
func TestShutdownWithAHungClaimEndsWithinTheBudget(t *testing.T) {
	t.Parallel()
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	claiming := make(chan struct{})
	h.store.mu.Lock()
	h.store.startHook = func(ctx context.Context) error {
		close(claiming)
		return hang(ctx)
	}
	h.store.mu.Unlock()
	h.clock.Advance(time.Minute)
	<-claiming
	h.cancel()
	if took := waitWithin(t, h.runner, 40*time.Second); took > shutdownLimit {
		t.Fatalf("shutdown with a hung claim took %s, want at most %s", took, shutdownLimit)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads = %d, want none", n)
	}
	h.assertTempDirEmpty(t)
}

// The claim and the result of a run share one shutdown budget: a slow
// claim leaves less time to record the result.
func TestShutdownBudgetIsSharedByTheClaimAndTheResult(t *testing.T) {
	t.Parallel()
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	h.start(t)
	h.clock.waitSleeping(t)
	var canceledAt time.Time
	h.store.mu.Lock()
	h.store.startHook = func(ctx context.Context) error {
		h.cancel()
		canceledAt = time.Now()
		time.Sleep(3 * time.Second) // slow, but answers within the budget
		return ctx.Err()
	}
	h.store.finishGate = hang
	h.store.mu.Unlock()
	h.clock.Advance(time.Minute)
	waitFor(t, "the claim", func() bool { return h.store.countCalls("start") == 1 })
	waitWithin(t, h.runner, 40*time.Second)
	if took := time.Since(canceledAt); took > shutdownLimit {
		t.Fatalf("shutdown took %s from the cancellation, want at most %s", took, shutdownLimit)
	}
	h.assertTempDirEmpty(t)
}

// longestRun is the runner's longest possible run: the export timeout plus
// the upload deadline of a maximum-size object.
func longestRun(r *Runner) time.Duration {
	return r.exportTimeout + r.uploadDeadline(s3client.MaxObjectSize)
}

// The startup sweep only removes entries older than the longest possible
// run, so a run of another live server sharing the temp directory keeps its
// upload file and export spool directory.
func TestStartSweepKeepsEntriesYoungerThanTheLongestRun(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	longest := longestRun(h.runner)
	if longest != 2*time.Hour+UploadDeadline(s3client.MaxObjectSize) {
		t.Fatalf("longest run = %s, want the export timeout plus the maximum upload deadline", longest)
	}
	now := h.clock.Now()
	ages := map[string]time.Duration{
		"engram-cloud-backup-upload-fresh.tar.gz":  0,
		"engram-cloud-backup-upload-recent.tar.gz": longest - time.Minute,
		"engram-cloud-backup-upload-old.tar.gz":    longest + time.Minute,
		"engram-cloud-backup-export-fresh":         0,
		"engram-cloud-backup-export-recent":        longest - time.Minute,
		"engram-cloud-backup-export-old":           longest + time.Minute,
	}
	for name, age := range ages {
		path := filepath.Join(h.tempDir, name)
		if strings.Contains(name, "-export-") {
			if err := os.Mkdir(path, 0o700); err != nil {
				t.Fatal(err)
			}
			writeTestFile(t, filepath.Join(path, "table.jsonl"))
		} else {
			writeTestFile(t, path)
		}
		if err := os.Chtimes(path, now.Add(-age), now.Add(-age)); err != nil {
			t.Fatal(err)
		}
	}
	h.start(t)
	h.clock.waitSleeping(t)
	for name, age := range ages {
		_, err := os.Lstat(filepath.Join(h.tempDir, name))
		switch {
		case age > longest && !os.IsNotExist(err):
			t.Errorf("old %s was not removed (%v)", name, err)
		case age < longest && err != nil:
			t.Errorf("%s, %s old, was removed: %v", name, age, err)
		}
	}
	if logs := h.logs.text(); !strings.Contains(logs, "removed 1 stale backup archive temp file(s) and 1 export spool dir(s) from "+h.tempDir) {
		t.Errorf("logs = %q, want the removed counts", logs)
	}
}

// A slot that arrives while this server runs another backup, with no other
// server to run it, is recorded as skipped once that backup ends.
func TestBusySlotIsRecordedAsSkippedOnASingleServer(t *testing.T) {
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
	manual, err := h.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	h.clock.Advance(time.Minute) // 03:00 while the manual run uploads
	waitFor(t, "the busy server to pass the slot", func() bool {
		return strings.Contains(h.logs.text(), "not claimed: this server is still running another backup")
	})
	h.clock.waitSleeping(t)
	if runs := h.store.snapshot(); len(runs) != 1 || runs[0].ID != manual {
		t.Fatalf("runs while busy = %+v, want only the manual run", runs)
	}
	close(release)
	waitFor(t, "the manual run", func() bool {
		return h.store.snapshot()[0].Status == cloudstore.BackupRunStatusSuccess && !h.runner.busy.Load()
	})
	h.clock.Advance(DefaultPollInterval) // the next poll records the slot
	waitFor(t, "the skipped slot", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 2 && runs[1].Status != cloudstore.BackupRunStatusRunning
	})
	run := h.store.snapshot()[1]
	if run.Trigger != cloudstore.BackupRunTriggerScheduled || !run.ScheduledFor.Equal(slot) || run.Status != cloudstore.BackupRunStatusFailure || run.ErrorMessage != "skipped: another backup was still running" {
		t.Fatalf("slot run = %+v, want the %s slot skipped because another backup was still running", run, slot)
	}
	if n := len(h.uploader.snapshot()); n != 1 {
		t.Fatalf("uploads = %d, want only the manual run", n)
	}
	// Recorded once: later polls add nothing.
	h.clock.waitSleeping(t)
	h.clock.Advance(DefaultPollInterval)
	h.clock.waitSleeping(t)
	if runs := h.store.snapshot(); len(runs) != 2 {
		t.Fatalf("runs after another poll = %+v, want 2", runs)
	}
}

// A retry that finds the run no longer running after a failed attempt
// reports that an earlier attempt probably recorded it, not a failure.
func TestFinishRetryAfterALostReplyReportsTheResultProbablyRecorded(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.runner.finishBackoff = time.Millisecond
	h.store.finishLostReplies = 1
	h.start(t)
	id, err := h.runner.StartManualBackup(context.Background(), "1")
	if err != nil {
		t.Fatal(err)
	}
	want := "backup run 1: the result (status success, object key \"prod/nightly/engram-cloud-backup-20261130T025900Z-run1.tar.gz\") was probably recorded by an earlier attempt whose reply was lost: attempt 2 found the run no longer running"
	waitFor(t, "the lost-reply log", func() bool { return strings.Contains(h.logs.text(), want) })
	waitFor(t, "the runner to become idle", func() bool { return !h.runner.busy.Load() })
	if logs := h.logs.text(); strings.Contains(logs, "could not record") {
		t.Fatalf("logs = %q, want no could-not-record line", logs)
	}
	if run := h.store.snapshot()[0]; run.ID != id || run.Status != cloudstore.BackupRunStatusSuccess {
		t.Fatalf("run = %+v, want it recorded as uploaded", run)
	}
	if n := h.store.countCalls("finish"); n != 2 {
		t.Fatalf("finish attempts = %d, want 2", n)
	}
}

// A retried claim that finds the slot already recorded after this server's
// own claim failed does not blame another server: the earlier claim may
// have committed.
func TestScheduledRetryFindingTheSlotRecordedLogsNeutrally(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	lost := true
	h.store.mu.Lock()
	h.store.startHook = func(context.Context) error {
		if lost {
			lost = false
			return errStoreUnavailable // committed, reply lost
		}
		return nil
	}
	h.store.mu.Unlock()
	h.start(t)
	h.clock.waitSleeping(t)
	h.clock.Advance(time.Minute)
	h.clock.waitSleeping(t)
	h.clock.Advance(DefaultPollInterval)
	want := "scheduled backup 2026-11-30T03:00:00Z is already recorded, by another server or by an earlier claim of this server whose reply was lost; skipping"
	waitFor(t, "the neutral log", func() bool { return strings.Contains(h.logs.text(), want) })
	if logs := h.logs.text(); strings.Contains(logs, "by another server; skipping") {
		t.Fatalf("logs = %q, want no claim that another server recorded it", logs)
	}
	if n := len(h.uploader.snapshot()); n != 0 {
		t.Fatalf("uploads = %d, want none", n)
	}
}

// Previous behavior: a slot already recorded at its first claim is logged
// as recorded by another server.
func TestScheduledSlotRecordedAtTheFirstClaimBlamesAnotherServer(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	h.store.setSchedule(mondayAt3())
	if _, err := h.store.StartBackupRun(context.Background(), cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: slot}); err != nil {
		t.Fatal(err)
	}
	h.start(t)
	h.clock.waitSleeping(t)
	h.clock.Advance(time.Minute)
	want := "scheduled backup 2026-11-30T03:00:00Z is already recorded by another server; skipping"
	waitFor(t, "the skip log", func() bool { return strings.Contains(h.logs.text(), want) })
}
