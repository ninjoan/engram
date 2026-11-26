package cloudstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

// Store behavior the backup runner relies on: stale running rows are
// reclaimed and a manual run can refuse to start while another run is
// running.

func backdateBackupRun(t *testing.T, cs *CloudStore, id int64, age time.Duration) {
	t.Helper()
	if _, err := cs.db.ExecContext(context.Background(), `UPDATE cloud_backup_runs SET started_at = NOW() - make_interval(secs => $2) WHERE id = $1`, id, age.Seconds()); err != nil {
		t.Fatalf("backdate run %d: %v", id, err)
	}
}

func backupRunByID(t *testing.T, cs *CloudStore, id int64) BackupRun {
	t.Helper()
	runs, err := cs.ListBackupRuns(context.Background(), 100)
	if err != nil {
		t.Fatalf("ListBackupRuns: %v", err)
	}
	for _, run := range runs {
		if run.ID == id {
			return run
		}
	}
	t.Fatalf("run %d not found in %+v", id, runs)
	return BackupRun{}
}

func TestExpireStaleBackupRunsMarksOnlyOldRunningRowsInterrupted(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)

	stale, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	backdateBackupRun(t, cs, stale.ID, 7*time.Hour)
	fresh, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	backdateBackupRun(t, cs, fresh.ID, 5*time.Hour)
	oldDone, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: oldDone.ID, Status: BackupRunStatusSuccess, ObjectKey: "k.tar.gz", SizeBytes: 3}); err != nil {
		t.Fatal(err)
	}
	backdateBackupRun(t, cs, oldDone.ID, 9*time.Hour)

	expired, err := cs.ExpireStaleBackupRuns(ctx, 6*time.Hour)
	if err != nil {
		t.Fatalf("ExpireStaleBackupRuns: %v", err)
	}
	if expired != 1 {
		t.Fatalf("expired = %d, want 1", expired)
	}
	got := backupRunByID(t, cs, stale.ID)
	if got.Status != BackupRunStatusFailure || got.FinishedAt.IsZero() || got.ErrorMessage != BackupRunInterruptedMessage {
		t.Fatalf("stale run = %+v, want failure %q", got, BackupRunInterruptedMessage)
	}
	if got.ErrorMessage != "interrupted (server stopped before completion)" {
		t.Fatalf("interrupted message = %q", got.ErrorMessage)
	}
	if got := backupRunByID(t, cs, fresh.ID); got.Status != BackupRunStatusRunning || !got.FinishedAt.IsZero() {
		t.Fatalf("fresh running run changed: %+v", got)
	}
	if got := backupRunByID(t, cs, oldDone.ID); got.Status != BackupRunStatusSuccess || got.ObjectKey != "k.tar.gz" || got.ErrorMessage != "" {
		t.Fatalf("finished run changed: %+v", got)
	}
	// Idempotent: nothing else is stale.
	if again, err := cs.ExpireStaleBackupRuns(ctx, 6*time.Hour); err != nil || again != 0 {
		t.Fatalf("second ExpireStaleBackupRuns = %d, %v; want 0, nil", again, err)
	}
	// The interrupted run can no longer be finished by a late writer.
	if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: stale.ID, Status: BackupRunStatusSuccess, ObjectKey: "late.tar.gz"}); !errors.Is(err, ErrBackupRunNotRunning) {
		t.Fatalf("finishing an interrupted run error = %v, want %v", err, ErrBackupRunNotRunning)
	}
}

func TestExpireStaleBackupRunsRejectsNonPositiveAge(t *testing.T) {
	cs := openIsolatedCloudStore(t)
	run, err := cs.StartBackupRun(context.Background(), StartBackupRunParams{Trigger: BackupRunTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	for _, age := range []time.Duration{0, -time.Hour} {
		if n, err := cs.ExpireStaleBackupRuns(context.Background(), age); !errors.Is(err, ErrInvalidBackupRun) || n != 0 {
			t.Fatalf("ExpireStaleBackupRuns(%s) = %d, %v; want 0, %v", age, n, err, ErrInvalidBackupRun)
		}
	}
	if got := backupRunByID(t, cs, run.ID); got.Status != BackupRunStatusRunning {
		t.Fatalf("rejected expiry changed the run: %+v", got)
	}
}

func TestStartBackupRunRefuseIfRunning(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	other, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, RefuseIfRunning: true}); !errors.Is(err, ErrBackupRunInProgress) {
		t.Fatalf("manual start while a run is running error = %v, want %v", err, ErrBackupRunInProgress)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_runs`); n != 1 {
		t.Fatalf("refused start wrote a row: %d rows", n)
	}
	// Without RefuseIfRunning the previous behavior holds: the start is recorded.
	parallel, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
	if err != nil {
		t.Fatalf("manual start without RefuseIfRunning: %v", err)
	}
	for _, id := range []int64{other.ID, parallel.ID} {
		if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: id, Status: BackupRunStatusFailure, ErrorMessage: "x"}); err != nil {
			t.Fatal(err)
		}
	}
	run, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, RefuseIfRunning: true})
	if err != nil || run.Status != BackupRunStatusRunning {
		t.Fatalf("manual start when idle = %+v, %v", run, err)
	}
	// A duplicate scheduled slot is still reported as already recorded.
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: other.ScheduledFor}); !errors.Is(err, ErrBackupRunAlreadyRecorded) {
		t.Fatalf("duplicate slot error = %v, want %v", err, ErrBackupRunAlreadyRecorded)
	}
}

func TestSanitizeBackupRunErrorRedactsXMLCredentialElements(t *testing.T) {
	in := `<Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>AKIAXMLLEAK1</AWSAccessKeyId>` +
		`<StringToSign>AWS4-HMAC-SHA256 20261130T030000Z scopeLEAK</StringToSign>` +
		`<SignatureProvided>feedfaceLEAK</SignatureProvided>` +
		`<StringToSignBytes>41 57 53 34 LEAKBYTES</StringToSignBytes>` +
		`<CanonicalRequest>PUT /bucket/key canonLEAK</CanonicalRequest>` +
		`<CanonicalRequestBytes>50 55 54 CANONBYTES</CanonicalRequestBytes>` +
		`<RequestId>req-1</RequestId></Error>`
	got := SanitizeBackupRunError(in)
	for _, leaked := range []string{"AKIAXMLLEAK1", "scopeLEAK", "feedfaceLEAK", "LEAKBYTES", "canonLEAK", "CANONBYTES"} {
		if strings.Contains(got, leaked) {
			t.Errorf("sanitized message %q still contains %q", got, leaked)
		}
	}
	for _, kept := range []string{"SignatureDoesNotMatch", "<AWSAccessKeyId>[redacted]</AWSAccessKeyId>", "req-1"} {
		if !strings.Contains(got, kept) {
			t.Errorf("sanitized message %q misses %q", got, kept)
		}
	}
	// A message cut inside an element still drops the credential.
	if got := SanitizeBackupRunError("s3 said <AWSAccessKeyId>AKIATRUNCATED"); strings.Contains(got, "AKIATRUNCATED") {
		t.Errorf("truncated element leaks: %q", got)
	}
	// Element names match case-insensitively and with attributes.
	if got := SanitizeBackupRunError(`<signatureprovided x="1">abcLEAK</signatureprovided>`); strings.Contains(got, "abcLEAK") {
		t.Errorf("lowercase element leaks: %q", got)
	}
}
