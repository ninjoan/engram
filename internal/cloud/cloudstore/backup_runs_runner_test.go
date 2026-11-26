package cloudstore

import (
	"context"
	"errors"
	"strings"
	"sync"
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

// Every XML element the sanitizer knows is scrubbed, whatever its case; an
// element that only shares a prefix with one (<CredentialScope>) is kept.
func TestSanitizeBackupRunErrorRedactsEveryXMLSecretElement(t *testing.T) {
	for _, element := range []string{
		"AWSAccessKeyId", "SignatureProvided", "StringToSign", "StringToSignBytes",
		"CanonicalRequest", "CanonicalRequestBytes", "Credential", "X-Amz-Credential",
		"X-Amz-Signature", "SecretAccessKey", "SessionToken", "SecurityToken",
	} {
		for _, name := range []string{element, strings.ToLower(element)} {
			t.Run(name, func(t *testing.T) {
				in := "upload: status 403: <Error><Code>AccessDenied</Code><" + name + ">LEAK value 0123</" + name + "><RequestId>req-7</RequestId></Error>"
				got := SanitizeBackupRunError(in)
				if strings.Contains(got, "LEAK") || strings.Contains(got, "0123") {
					t.Fatalf("SanitizeBackupRunError(%q) = %q leaks the element value", in, got)
				}
				for _, kept := range []string{"<" + name + ">[redacted]</" + name + ">", "AccessDenied", "req-7"} {
					if !strings.Contains(got, kept) {
						t.Fatalf("SanitizeBackupRunError(%q) = %q misses %q", in, got, kept)
					}
				}
			})
		}
	}
	t.Run("CredentialScope is kept", func(t *testing.T) {
		in := "<Error><CredentialScope>20261130/auto/s3/aws4_request</CredentialScope><HostId>host-1</HostId></Error>"
		if got := SanitizeBackupRunError(in); got != in {
			t.Fatalf("SanitizeBackupRunError(%q) = %q, want it unchanged", in, got)
		}
	})
	t.Run("signature mismatch body cut mid-element", func(t *testing.T) {
		in := `upload: status 403: <Error><Code>SignatureDoesNotMatch</Code><AWSAccessKeyId>AKIAVFYPROBE1234</AWSAccessKeyId><StringToSign>AWS4-HMAC-SHA256 x</StringToSign><SignatureProvided>abcdef0123</SignatureProvided><CanonicalRequest>PUT /b/k`
		got := SanitizeBackupRunError(in, "AKIAVFYPROBE1234", "vfysecretvfysecret")
		for _, leaked := range []string{"AKIAVFYPROBE1234", "abcdef0123", "AWS4-HMAC-SHA256 x", "PUT /b/k"} {
			if strings.Contains(got, leaked) {
				t.Fatalf("sanitized %q leaks %q", got, leaked)
			}
		}
		if !strings.Contains(got, "SignatureDoesNotMatch") {
			t.Fatalf("sanitized %q lost the error code", got)
		}
	})
}

// A running row is reclaimed only once it is older than the threshold; until
// then it keeps refusing RefuseIfRunning starts.
func TestExpireStaleBackupRunsAtTheThresholdBoundary(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	start := func() BackupRun {
		t.Helper()
		run, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
		if err != nil {
			t.Fatal(err)
		}
		return run
	}
	old, young := start(), start()
	backdateBackupRun(t, cs, old.ID, 6*time.Hour+time.Second)
	backdateBackupRun(t, cs, young.ID, 6*time.Hour-time.Minute)

	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, RefuseIfRunning: true}); !errors.Is(err, ErrBackupRunInProgress) {
		t.Fatalf("manual start beside running rows: %v, want %v", err, ErrBackupRunInProgress)
	}
	expired, err := cs.ExpireStaleBackupRuns(ctx, 6*time.Hour)
	if err != nil || expired != 1 {
		t.Fatalf("ExpireStaleBackupRuns = %d, %v; want 1, nil", expired, err)
	}
	if got := backupRunByID(t, cs, old.ID); got.Status != BackupRunStatusFailure || got.ErrorMessage != BackupRunInterruptedMessage {
		t.Fatalf("run past the threshold = %+v, want interrupted", got)
	}
	if got := backupRunByID(t, cs, young.ID); got.Status != BackupRunStatusRunning {
		t.Fatalf("run below the threshold = %+v, want still running", got)
	}
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, RefuseIfRunning: true}); !errors.Is(err, ErrBackupRunInProgress) {
		t.Fatalf("manual start beside the young running row: %v, want %v", err, ErrBackupRunInProgress)
	}
}

// Concurrent starts, as several servers would issue them, are serialized:
// one scheduled slot is recorded exactly once, at most one RefuseIfRunning
// manual start wins, nothing else fails and no advisory lock is left held.
func TestConcurrentBackupRunStartsAreSerialized(t *testing.T) {
	cs := openIsolatedCloudStore(t)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	slot := time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)
	const n = 16
	var (
		wg                                    sync.WaitGroup
		mu                                    sync.Mutex
		scheduled, duplicate, manual, refused int
		unexpected                            []error
	)
	record := func(err error, ok *int, expected error, refusals *int) {
		mu.Lock()
		defer mu.Unlock()
		switch {
		case err == nil:
			*ok++
		case errors.Is(err, expected):
			*refusals++
		default:
			unexpected = append(unexpected, err)
		}
	}
	for range n {
		wg.Add(2)
		go func() {
			defer wg.Done()
			_, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: slot})
			record(err, &scheduled, ErrBackupRunAlreadyRecorded, &duplicate)
		}()
		go func() {
			defer wg.Done()
			_, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, RefuseIfRunning: true})
			record(err, &manual, ErrBackupRunInProgress, &refused)
		}()
	}
	wg.Wait()
	if ctx.Err() != nil || len(unexpected) != 0 {
		t.Fatalf("concurrent starts: ctx %v, unexpected errors %v", ctx.Err(), unexpected)
	}
	if scheduled != 1 || duplicate != n-1 {
		t.Fatalf("scheduled starts = %d recorded, %d duplicates; want 1 and %d", scheduled, duplicate, n-1)
	}
	if manual > 1 || manual+refused != n {
		t.Fatalf("manual starts = %d recorded, %d refused; want at most 1 of %d", manual, refused, n)
	}
	if rows := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_runs`); rows != 1+manual {
		t.Fatalf("rows = %d, want %d", rows, 1+manual)
	}
	// The start lock is transaction-scoped: none may survive the starts.
	// Other suites may hold it briefly on the same database, so poll.
	heldStartLocks := func() int {
		t.Helper()
		var held int
		if err := cs.db.QueryRowContext(context.Background(), `
			SELECT COUNT(*) FROM pg_locks
			WHERE locktype = 'advisory' AND granted AND objsubid = 1 AND classid::bigint = $1 AND objid::bigint = $2`,
			backupRunStartLock>>32, backupRunStartLock&0xffffffff).Scan(&held); err != nil {
			t.Fatalf("read pg_locks: %v", err)
		}
		return held
	}
	// Control: the query sees the lock while a transaction holds it.
	tx, err := cs.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`SELECT pg_advisory_xact_lock($1)`, backupRunStartLock); err != nil {
		t.Fatal(err)
	}
	if held := heldStartLocks(); held < 1 {
		t.Fatalf("pg_locks query misses a held start lock (count %d)", held)
	}
	_ = tx.Rollback()
	deadline := time.Now().Add(5 * time.Second)
	for {
		held := heldStartLocks()
		if held == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("backup run start lock still held %d time(s)", held)
		}
		time.Sleep(10 * time.Millisecond)
	}
}
