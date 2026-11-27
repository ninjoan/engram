package cloudstore

import (
	"context"
	"testing"
)

func TestLatestBackupRunOutcomes(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)

	got, err := cs.LatestBackupRunOutcomes(ctx)
	if err != nil {
		t.Fatalf("LatestBackupRunOutcomes: %v", err)
	}
	if got.LastSuccess.ID != 0 || got.LastFailure.ID != 0 {
		t.Fatalf("an empty history has no outcome, got %+v", got)
	}

	start := func() BackupRun {
		t.Helper()
		run, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
		if err != nil {
			t.Fatalf("StartBackupRun: %v", err)
		}
		return run
	}
	finish := func(run BackupRun, status, key, message string, size int64) {
		t.Helper()
		if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: run.ID, Status: status, ObjectKey: key, SizeBytes: size, ErrorMessage: message}); err != nil {
			t.Fatalf("FinishBackupRun: %v", err)
		}
	}
	older := start()
	finish(older, BackupRunStatusSuccess, "prod/engram-cloud-backup-old.tar.gz", "", 10)
	failed := start()
	finish(failed, BackupRunStatusFailure, "", "upload failed: network", 0)
	newest := start()
	finish(newest, BackupRunStatusSuccess, "prod/engram-cloud-backup-new.tar.gz", "", 4096)
	_ = start() // still running: never an outcome

	// Make finish order explicit: the failure finished after the older
	// success and before the newest one.
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_runs SET finished_at = started_at + make_interval(secs => id) WHERE finished_at IS NOT NULL`); err != nil {
		t.Fatal(err)
	}

	got, err = cs.LatestBackupRunOutcomes(ctx)
	if err != nil {
		t.Fatalf("LatestBackupRunOutcomes: %v", err)
	}
	if got.LastSuccess.ID != newest.ID || got.LastSuccess.ObjectKey != "prod/engram-cloud-backup-new.tar.gz" || got.LastSuccess.SizeBytes != 4096 || got.LastSuccess.FinishedAt.IsZero() {
		t.Fatalf("LastSuccess = %+v, want run %d", got.LastSuccess, newest.ID)
	}
	if got.LastFailure.ID != failed.ID || got.LastFailure.ErrorMessage != "upload failed: network" || got.LastFailure.Status != BackupRunStatusFailure {
		t.Fatalf("LastFailure = %+v, want run %d", got.LastFailure, failed.ID)
	}

	// The newest finish wins, not the newest start.
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_runs SET finished_at = NOW() + interval '1 hour' WHERE id = $1`, older.ID); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.LatestBackupRunOutcomes(ctx); err != nil || got.LastSuccess.ID != older.ID {
		t.Fatalf("LastSuccess after a later finish = %+v, %v, want run %d", got.LastSuccess, err, older.ID)
	}
}
