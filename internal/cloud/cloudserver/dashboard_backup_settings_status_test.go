package cloudserver

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

func TestDashboardBackupsPageRendersTheStatusCardFromTheStore(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.latestTest = cloudstore.BackupDestinationTest{OccurredAt: time.Date(2026, 11, 26, 11, 55, 0, 0, time.UTC), ActorName: "ninjoan", ReasonCode: "bucket_not_found"}
	f.settings.outcomes = cloudstore.BackupRunOutcomes{LastSuccess: cloudstore.BackupRun{ID: 3, Status: cloudstore.BackupRunStatusSuccess, ObjectKey: "prod/engram-cloud-backup-20261126T030000Z-run3.tar.gz", SizeBytes: 2048, FinishedAt: time.Date(2026, 11, 26, 3, 1, 0, 0, time.UTC)}}
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, body)
	}
	// The fixture clock is 2026-11-26 12:00 UTC.
	for _, marker := range []string{
		`<span class="backup-pill is-failing">Failing</span>`,
		"<strong>Bucket not found.</strong>",
		`<time datetime="2026-11-26T11:55:00Z">5 min ago</time>`,
		"by ninjoan",
		"<code>prod/engram-cloud-backup-20261126T030000Z-run3.tar.gz</code>",
		"2.0 KiB",
		"engram-cloud-backup-&lt;yyyymmddThhmmssZ&gt;-run&lt;id&gt;.tar.gz",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected status card marker %q, body=%q", marker, body)
		}
	}
	for _, secret := range []string{testBackupSecret, testBackupAccessKeyID} {
		if strings.Contains(body, secret) {
			t.Fatalf("status card renders a credential %q", secret)
		}
	}
	if f.settings.opens != 0 {
		t.Fatalf("rendering the status card must never open the credentials, opened %d times", f.settings.opens)
	}
}

func TestDashboardBackupsPageStatusReadFailureIsUnavailable(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.statusErr = errors.New("dial tcp: password=hunter2")
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusBadGateway || !strings.Contains(body, "Backup settings are temporarily unavailable.") || strings.Contains(body, "hunter2") {
		t.Fatalf("expected 502 with the unavailable note and no error text, got %d body=%q", rec.Code, body)
	}
}

func TestDashboardBackupTestAuditRecordsAMachineReadableResult(t *testing.T) {
	for name, tc := range map[string]struct {
		err            error
		result, reason string
	}{
		"ok":      {nil, "ok", ""},
		"auth":    {s3client.ErrAuth, "auth", "auth_failed"},
		"bucket":  {s3client.ErrBucketNotFound, "bucket", "bucket_not_found"},
		"network": {s3client.ErrNetwork, "network", "network"},
	} {
		t.Run(name, func(t *testing.T) {
			f := managedBackupFixture(t)
			f.checker.err = tc.err
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("expected 303, got %d", rec.Code)
			}
			events := backupAuditEvents(f.audit, cloudstore.AuthAuditActionBackupDestinationTest)
			if len(events) != 1 || events[0].Metadata["result"] != tc.result || events[0].ReasonCode != tc.reason {
				t.Fatalf("test audit = %+v, want result %q reason %q", events, tc.result, tc.reason)
			}
			for _, value := range events[0].Metadata {
				if s, _ := value.(string); strings.Contains(s, testBackupSecret) || strings.Contains(s, testBackupAccessKeyID) {
					t.Fatalf("test audit metadata carries a credential: %+v", events[0].Metadata)
				}
			}
		})
	}
}

func TestDashboardBackupStatusCardPostgres(t *testing.T) {
	cs := openBackupDownloadTestStore(t)
	ctx := context.Background()
	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "ninjoan", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	principal := dashboardManagedPrincipal(admin.PrincipalID, cloudstore.PrincipalRoleAdmin, true)
	srv := New(cs, resolvingAuth{principals: map[string]cloudauth.Principal{"admin-token": principal}}, 0, WithAdminIdentityStore(cs), WithBackupSettings(cs, testBackupKey(t)))
	checker := &fakeBackupChecker{}
	srv.backupCheckAccess = checker.check
	cookie := managedDashboardLogin(t, srv, "admin-token", false)
	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}
	post := func(path, form string) {
		t.Helper()
		rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: path, form: form, headers: sameOrigin, cookie: cookie})
		if rec.Code != http.StatusSeeOther {
			t.Fatalf("%s = %d body=%q", path, rec.Code, rec.Body.String())
		}
	}
	page := func() string {
		t.Helper()
		body := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie).Body.String()
		if strings.Contains(body, testBackupSecret) || strings.Contains(body, testBackupAccessKeyID) {
			t.Fatal("page renders a stored credential")
		}
		return body
	}

	post(backupDestinationPath, validBackupDestinationForm)
	if body := page(); !strings.Contains(body, `<span class="backup-pill is-untested">Not tested</span>`) {
		t.Fatalf("a saved, never tested destination must be Not tested, body=%q", body)
	}
	post(backupDestinationTestPath, "")
	if body := page(); !strings.Contains(body, `<span class="backup-pill is-connected">Connected</span>`) || !strings.Contains(body, "by ninjoan") {
		t.Fatalf("after a passing test the destination must be Connected, body=%q", body)
	}
	checker.err = s3client.ErrAuth
	post(backupDestinationTestPath, "")
	if body := page(); !strings.Contains(body, `<span class="backup-pill is-failing">Failing</span>`) || !strings.Contains(body, "<strong>Keys rejected.</strong>") {
		t.Fatalf("after a rejected test the destination must be Failing with the reason, body=%q", body)
	}
	post(backupDestinationPath, validBackupDestinationForm)
	if body := page(); !strings.Contains(body, `<span class="backup-pill is-untested">Not tested</span>`) {
		t.Fatalf("saving again must reset the status to Not tested, body=%q", body)
	}
}
