package cloudstore

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
	"unicode/utf8"
)

func TestBackupRunLifecycle(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	slot := time.Date(2026, 11, 30, 8, 0, 0, 0, time.UTC)

	scheduled, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: slot})
	if err != nil {
		t.Fatalf("StartBackupRun scheduled: %v", err)
	}
	if scheduled.ID == 0 || scheduled.Status != BackupRunStatusRunning || !scheduled.ScheduledFor.Equal(slot) || scheduled.StartedAt.IsZero() || !scheduled.FinishedAt.IsZero() || scheduled.ActorPrincipalID != "" {
		t.Fatalf("started scheduled run = %+v", scheduled)
	}
	// The same slot cannot be recorded twice, so two servers never both run it.
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: slot}); !errors.Is(err, ErrBackupRunAlreadyRecorded) {
		t.Fatalf("duplicate scheduled slot error = %v, want %v", err, ErrBackupRunAlreadyRecorded)
	}

	manual, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, ActorPrincipalID: adminID})
	if err != nil {
		t.Fatalf("StartBackupRun manual: %v", err)
	}
	if manual.ActorPrincipalID != adminID || !manual.ScheduledFor.IsZero() {
		t.Fatalf("started manual run = %+v", manual)
	}

	done, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: scheduled.ID, Status: BackupRunStatusSuccess, ObjectKey: "prod/engram-cloud-backup-20261130T080000Z.tar.gz", SizeBytes: 4096})
	if err != nil {
		t.Fatalf("FinishBackupRun success: %v", err)
	}
	if done.Status != BackupRunStatusSuccess || done.FinishedAt.IsZero() || done.SizeBytes != 4096 || done.ObjectKey == "" || done.ErrorMessage != "" {
		t.Fatalf("finished run = %+v", done)
	}
	if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: scheduled.ID, Status: BackupRunStatusFailure, ErrorMessage: "late"}); !errors.Is(err, ErrBackupRunNotRunning) {
		t.Fatalf("finishing a finished run error = %v, want %v", err, ErrBackupRunNotRunning)
	}
	if _, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{ID: 999999, Status: BackupRunStatusFailure, ErrorMessage: "x"}); !errors.Is(err, ErrBackupRunNotRunning) {
		t.Fatalf("finishing an unknown run error = %v, want %v", err, ErrBackupRunNotRunning)
	}

	failed, err := cs.FinishBackupRun(ctx, FinishBackupRunParams{
		ID: manual.ID, Status: BackupRunStatusFailure,
		ErrorMessage: "PUT https://AKIAEXAMPLE:topsecret@acct.example.test/b failed: Signature=abc123 secret_access_key=wJalrXUtn\nline2",
		Redact:       []string{"wJalrXUtn"},
	})
	if err != nil {
		t.Fatalf("FinishBackupRun failure: %v", err)
	}
	for _, leaked := range []string{"topsecret", "AKIAEXAMPLE", "abc123", "wJalrXUtn", "\n"} {
		if strings.Contains(failed.ErrorMessage, leaked) {
			t.Fatalf("stored error message leaks %q: %q", leaked, failed.ErrorMessage)
		}
	}

	runs, err := cs.ListBackupRuns(ctx, 20)
	if err != nil {
		t.Fatalf("ListBackupRuns: %v", err)
	}
	if len(runs) != 2 || runs[0].ID != manual.ID || runs[1].ID != scheduled.ID {
		t.Fatalf("runs = %+v, want newest first", runs)
	}
	if runs, err := cs.ListBackupRuns(ctx, 1); err != nil || len(runs) != 1 || runs[0].ID != manual.ID {
		t.Fatalf("ListBackupRuns(1) = %+v, %v", runs, err)
	}
	// Non-positive limits fall back to the default page size.
	if runs, err := cs.ListBackupRuns(ctx, 0); err != nil || len(runs) != 2 {
		t.Fatalf("ListBackupRuns(0) = %+v, %v", runs, err)
	}
}

func TestBackupRunRejectsInvalidParamsWithoutWriting(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	for name, params := range map[string]StartBackupRunParams{
		"unknown trigger":              {Trigger: "cron"},
		"scheduled without slot":       {Trigger: BackupRunTriggerScheduled},
		"manual with a scheduled slot": {Trigger: BackupRunTriggerManual, ScheduledFor: time.Now()},
	} {
		if _, err := cs.StartBackupRun(ctx, params); !errors.Is(err, ErrInvalidBackupRun) {
			t.Errorf("%s: Start error = %v, want %v", name, err, ErrInvalidBackupRun)
		}
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_runs`); n != 0 {
		t.Fatalf("rejected starts wrote %d runs", n)
	}

	run, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	for name, params := range map[string]FinishBackupRunParams{
		"running status":       {ID: run.ID, Status: BackupRunStatusRunning},
		"unknown status":       {ID: run.ID, Status: "done"},
		"success without key":  {ID: run.ID, Status: BackupRunStatusSuccess, SizeBytes: 1},
		"negative size":        {ID: run.ID, Status: BackupRunStatusSuccess, ObjectKey: "k", SizeBytes: -1},
		"oversized object key": {ID: run.ID, Status: BackupRunStatusSuccess, ObjectKey: strings.Repeat("k", 1025)},
	} {
		if _, err := cs.FinishBackupRun(ctx, params); !errors.Is(err, ErrInvalidBackupRun) {
			t.Errorf("%s: Finish error = %v, want %v", name, err, ErrInvalidBackupRun)
		}
	}
	runs, err := cs.ListBackupRuns(ctx, 5)
	if err != nil || len(runs) != 1 || runs[0].Status != BackupRunStatusRunning {
		t.Fatalf("rejected finishes changed the run: %+v, %v", runs, err)
	}
}

func TestDeletingTheRunActorKeepsTheRun(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual, ActorPrincipalID: adminID}); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, `DELETE FROM cloud_principals WHERE id = `+adminID); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	runs, err := cs.ListBackupRuns(ctx, 5)
	if err != nil || len(runs) != 1 || runs[0].ActorPrincipalID != "" {
		t.Fatalf("runs after principal delete = %+v, %v", runs, err)
	}
}

func TestSanitizeBackupRunErrorRedactsAndBounds(t *testing.T) {
	cases := []struct {
		name, in string
		secrets  []string
		absent   []string
		present  []string
	}{
		{name: "url userinfo", in: "dial https://key:secretpw@host.example.test/x", absent: []string{"key:", "secretpw"}, present: []string{"https://[redacted]@host.example.test/x"}},
		{name: "sigv4 header", in: "Authorization: AWS4-HMAC-SHA256 Credential=AKIAXYZ/20261130/auto/s3/aws4_request, SignedHeaders=host, Signature=deadbeef", absent: []string{"AKIAXYZ", "deadbeef"}},
		{name: "presigned query", in: "GET /b?X-Amz-Credential=AKIAQ&X-Amz-Signature=cafe&X-Amz-Security-Token=tok", absent: []string{"AKIAQ", "cafe", "=tok"}},
		{name: "bearer", in: "upstream said Bearer egc_abcdef0123", absent: []string{"egc_abcdef0123"}},
		{name: "key value", in: `password="hunter2" token=abc; secret_access_key: s3cr3t`, absent: []string{"hunter2", "abc;", "s3cr3t"}},
		{name: "explicit secret", in: "bucket said nope to MYSECRETVALUE", secrets: []string{"MYSECRETVALUE", ""}, absent: []string{"MYSECRETVALUE"}, present: []string{"[redacted]"}},
		{name: "control characters", in: "line1\nline2\r\x00\tend", absent: []string{"\n", "\r", "\x00", "\t"}, present: []string{"line1 line2 end"}},
		{name: "invalid utf8", in: "bad \xff byte", present: []string{"bad"}},
	}
	for _, tc := range cases {
		got := SanitizeBackupRunError(tc.in, tc.secrets...)
		for _, a := range tc.absent {
			if strings.Contains(got, a) {
				t.Errorf("%s: %q still contains %q", tc.name, got, a)
			}
		}
		for _, p := range tc.present {
			if !strings.Contains(got, p) {
				t.Errorf("%s: %q misses %q", tc.name, got, p)
			}
		}
		if !utf8.ValidString(got) {
			t.Errorf("%s: %q is not valid UTF-8", tc.name, got)
		}
	}

	long := SanitizeBackupRunError(strings.Repeat("é", 400))
	if len(long) > 512 || !utf8.ValidString(long) || !strings.HasSuffix(long, "...") {
		t.Fatalf("long message = %d bytes (valid=%v), want <= 512 with a truncation marker", len(long), utf8.ValidString(long))
	}
	if got := SanitizeBackupRunError("   "); got != "" {
		t.Fatalf("blank message = %q, want empty", got)
	}
}
