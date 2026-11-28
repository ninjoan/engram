package backuprunner

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudbackup"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// writeLeftovers creates an upload temp file and an export spool directory
// in dir, both last modified at mtime, as a killed server leaves them.
func writeLeftovers(t *testing.T, dir string, mtime time.Time) (upload, spool string) {
	t.Helper()
	upload = filepath.Join(dir, "engram-cloud-backup-upload-killed.tar.gz")
	writeTestFile(t, upload)
	spool = filepath.Join(dir, "engram-cloud-backup-export-killed")
	if err := os.Mkdir(spool, 0o700); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, filepath.Join(spool, "table.jsonl"))
	for _, path := range []string{upload, spool} {
		if err := os.Chtimes(path, mtime, mtime); err != nil {
			t.Fatal(err)
		}
	}
	return upload, spool
}

func assertExists(t *testing.T, when string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); err != nil {
			t.Errorf("%s: %s was removed: %v", when, filepath.Base(path), err)
		}
	}
}

func assertRemoved(t *testing.T, when string, paths ...string) {
	t.Helper()
	for _, path := range paths {
		if _, err := os.Lstat(path); !os.IsNotExist(err) {
			t.Errorf("%s: %s was not removed (%v)", when, filepath.Base(path), err)
		}
	}
}

// A server killed and restarted at once finds its leftovers too young for
// the startup sweep. The runner sweeps again every hour, so they are removed
// at most an hour after they become older than the longest possible run.
func TestPeriodicSweepRemovesLeftoversOnceOlderThanTheLongestRun(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	longest := longestRun(h.runner)
	upload, spool := writeLeftovers(t, h.tempDir, h.clock.Now())

	h.start(t)
	h.clock.waitSleeping(t)
	assertExists(t, "after the startup sweep", upload, spool)

	// Exactly as old as the longest run: still kept.
	h.clock.Advance(longest)
	h.clock.waitSleeping(t)
	assertExists(t, "at the age bound", upload, spool)

	// Older than the bound, but the last sweep was a minute ago.
	h.clock.Advance(time.Minute)
	h.clock.waitSleeping(t)
	assertExists(t, "a minute after the last sweep", upload, spool)
	if logs := h.logs.text(); strings.Contains(logs, "stale backup archive") {
		t.Fatalf("logs = %q, want no sweep line before anything is removed", logs)
	}

	// An hour after the last sweep: removed.
	h.clock.Advance(time.Hour)
	h.clock.waitSleeping(t)
	assertRemoved(t, "an hour after the last sweep", upload, spool)
	want := "removed 1 stale backup archive temp file(s) and 1 export spool dir(s) from " + h.tempDir
	if logs := h.logs.text(); strings.Count(logs, want) != 1 {
		t.Fatalf("logs = %q, want the removed counts once", logs)
	}

	// Later sweeps find nothing and log nothing.
	h.clock.Advance(time.Hour)
	h.clock.waitSleeping(t)
	if logs := h.logs.text(); strings.Count(logs, "stale backup archive") != 1 {
		t.Fatalf("logs = %q, want only the one sweep line", logs)
	}
}

// The periodic sweep never runs while this server runs a backup, so the
// upload temp file and export spool directory of that run stay even when
// they look abandoned; a due sweep runs at the first poll after the run.
func TestPeriodicSweepNeverRemovesTheEntriesOfTheRunInProgress(t *testing.T) {
	exporting := make(chan string, 1)
	release := make(chan struct{})
	h := newHarness(t, beforeSlot, func(cfg *Config) {
		cfg.Export = func(ctx context.Context, w io.Writer) error {
			spool, err := os.MkdirTemp(cfg.TempDir, cloudbackup.ExportSpoolPattern)
			if err != nil {
				return err
			}
			defer os.RemoveAll(spool)
			writeTestFile(t, filepath.Join(spool, "table.jsonl"))
			exporting <- spool
			select {
			case <-release:
			case <-ctx.Done():
				return ctx.Err()
			}
			return writeArchive(ctx, w)
		}
	})
	h.start(t)
	h.clock.waitSleeping(t)
	if _, err := h.runner.StartManualBackup(context.Background(), "1"); err != nil {
		t.Fatalf("StartManualBackup: %v", err)
	}
	var spool string
	select {
	case spool = <-exporting:
	case <-time.After(5 * time.Second):
		t.Fatal("the export never started")
	}
	uploads, err := filepath.Glob(filepath.Join(h.tempDir, "engram-cloud-backup-upload-*.tar.gz"))
	if err != nil || len(uploads) != 1 {
		t.Fatalf("upload temp files = %v %v, want the run's one", uploads, err)
	}
	inUse := []string{uploads[0], spool}
	old := h.clock.Now().Add(-longestRun(h.runner) - time.Hour)
	for _, path := range inUse {
		if err := os.Chtimes(path, old, old); err != nil {
			t.Fatal(err)
		}
	}
	leftovers := make([]string, 2)
	leftovers[0], leftovers[1] = writeLeftovers(t, h.tempDir, old)

	for range 3 {
		h.clock.Advance(time.Hour)
		h.clock.waitSleeping(t)
	}
	assertExists(t, "during the run", inUse...)
	assertExists(t, "during the run", leftovers...)

	close(release)
	waitFor(t, "the run to finish", func() bool {
		runs := h.store.snapshot()
		return len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	assertRemoved(t, "after the run", inUse...)

	h.clock.Advance(time.Minute)
	h.clock.waitSleeping(t)
	assertRemoved(t, "at the first poll after the run", leftovers...)
	if logs := h.logs.text(); !strings.Contains(logs, "removed 1 stale backup archive temp file(s) and 1 export spool dir(s) from "+h.tempDir) {
		t.Fatalf("logs = %q, want the removed counts", logs)
	}
}
