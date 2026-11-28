package cloudserver

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// Until the dashboard has Dropbox and Google Drive forms, a stored
// destination of those kinds renders the status card with its kind and its
// non-secret settings, never a 500.
func TestDashboardBackupsPageRendersNonS3DestinationKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		destination cloudstore.BackupDestination
		want        []string
	}{
		"dropbox": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindDropbox, Dropbox: cloudstore.DropboxDestinationView{AppKey: "dbxappkey7q4zexample", FolderPath: "/Engram backups"}},
			want:        []string{"Dropbox destination", "/Engram backups", "****mple"},
		},
		"gdrive pending": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups"}},
			want:        []string{"Google Drive destination", "Engram backups", "****.com", "pending authorization"},
		},
		"gdrive authorized": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups", Authorized: true}},
			want:        []string{"Google Drive destination", "Engram backups", "authorized"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			settings := configuredBackupSettings()
			settings.destination = tc.destination
			settings.creds = cloudstore.BackupDestinationCredentials{}
			srv, audit, cookie := dashboardAdminUsersTestServer(t)
			f := wireBackupFixture(t, srv, audit, cookie, settings)
			rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
			body := rec.Body.String()
			if rec.Code != http.StatusOK {
				t.Fatalf("page = %d, body=%q", rec.Code, body)
			}
			for _, marker := range append(tc.want, `action="/dashboard/admin/backups/destination/remove"`) {
				if !strings.Contains(body, marker) {
					t.Fatalf("page lacks %q, body=%q", marker, body)
				}
			}
			if strings.Contains(body, "1234-abcd.apps.googleusercontent.com") || strings.Contains(body, "dbxappkey7q4zexample") {
				t.Fatalf("page shows the full client identifier: %q", body)
			}
			if strings.Contains(body, "pending authorization") != strings.HasSuffix(name, "pending") {
				t.Fatalf("pending marker mismatch for %s", name)
			}
			// A notice from the query string still wins over the kind notice.
			page := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice=schedule-saved", f.cookie).Body.String()
			if !strings.Contains(page, "Backup schedule saved.") {
				t.Fatalf("query notice lost, body=%q", page)
			}
		})
	}
}

func TestDashboardTestBackupConnectionRefusesNonS3Kind(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.destination = cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindDropbox, Dropbox: cloudstore.DropboxDestinationView{AppKey: "dbxappkey7q4zexample", FolderPath: "/Engram backups"}}
	f.settings.openErr = fmt.Errorf("%w: it is a dropbox destination, not s3", cloudstore.ErrBackupDestinationKindMismatch)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=test-unsupported" {
		t.Fatalf("expected 303 to test-unsupported, got %d %q", rec.Code, dashboardRedirect(rec))
	}
	if f.checker.calls != 0 {
		t.Fatalf("checks = %d, want 0", f.checker.calls)
	}
	events := backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)
	if len(events) != 1 || events[0].Outcome != authAuditOutcomeFailure || events[0].ReasonCode != "unsupported_kind" {
		t.Fatalf("unexpected test audit: %+v", events)
	}
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	if !strings.Contains(page, "Connection test is not available for this kind of destination yet.") {
		t.Fatalf("unsupported notice did not render, body=%q", page)
	}
}

func TestDashboardBackupNowReportsUnsupportedDestination(t *testing.T) {
	f := managedBackupFixture(t)
	f.runner.err = fmt.Errorf("%w: dropbox destination is not supported by this server yet", ErrBackupDestinationUnsupported)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupRunPath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=run-unsupported" {
		t.Fatalf("expected 303 to run-unsupported, got %d %q", rec.Code, dashboardRedirect(rec))
	}
	events := backupAuditEvents(f.audit, authAuditActionBackupRunManual)
	if len(events) != 2 || events[1].Outcome != authAuditOutcomeFailure || events[1].ReasonCode != "unsupported_destination" {
		t.Fatalf("unexpected run audits: %+v", events)
	}
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	if !strings.Contains(page, "This server cannot upload to this kind of destination yet; no backup was started.") {
		t.Fatalf("unsupported run notice did not render, body=%q", page)
	}
}
