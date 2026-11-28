package cloudserver

import (
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// A stored Dropbox or Google Drive destination renders its own status card
// with its kind and its non-secret settings, never a 500.
func TestDashboardBackupsPageRendersNonS3DestinationKinds(t *testing.T) {
	for name, tc := range map[string]struct {
		destination cloudstore.BackupDestination
		want        []string
	}{
		"dropbox": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindDropbox, Dropbox: cloudstore.DropboxDestinationView{AppKey: "dbxappkey7q4zexample", FolderPath: "/Engram backups"}},
			want:        []string{"Dropbox <span", "/Engram backups", "****mple"},
		},
		"gdrive pending": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups"}},
			want:        []string{"Google Drive <span", "Engram backups", "****.com", "<dd>Pending</dd>"},
		},
		"gdrive authorized": {
			destination: cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups", Authorized: true}},
			want:        []string{"Google Drive <span", "Engram backups", "<dd>Connected</dd>"},
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
			if strings.Contains(body, "<dd>Pending</dd>") != strings.HasSuffix(name, "pending") {
				t.Fatalf("pending marker mismatch for %s", name)
			}
			// A notice from the query string renders on the card.
			page := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice=schedule-saved", f.cookie).Body.String()
			if !strings.Contains(page, "Backup schedule saved.") {
				t.Fatalf("query notice lost, body=%q", page)
			}
		})
	}
}

// A repeated kind field is refused with 400 on save and check: nothing is
// stored, checked, opened or audited, whichever value comes first.
func TestDashboardBackupDestinationRefusesARepeatedKind(t *testing.T) {
	forms := map[string]string{
		"dropbox then gdrive": validDropboxForm + "&kind=gdrive",
		"dropbox then s3":     validDropboxForm + "&kind=s3",
		"s3 then dropbox":     validBackupDestinationForm + "&kind=s3&kind=dropbox",
		"same value twice":    validDropboxForm + "&kind=dropbox",
		"empty then dropbox":  validDropboxForm + "&kind=",
	}
	for name, form := range forms {
		for _, path := range []string{backupDestinationPath, backupDestinationCheckPath} {
			t.Run(name+" "+path, func(t *testing.T) {
				f := emptyBackupFixture(t)
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: form, cookie: f.cookie})
				if rec.Code != http.StatusBadRequest {
					t.Fatalf("status = %d, want 400", rec.Code)
				}
				if !strings.Contains(rec.Body.String(), "choose S3-compatible, Dropbox or Google Drive storage") {
					t.Fatalf("refusal does not name the kind, body=%q", rec.Body.String())
				}
				if f.settings.mutations() != 0 || f.dropbox.calls != 0 || f.checker.calls != 0 || backupAuditCount(f.audit) != 0 || f.settings.destination.Configured {
					t.Fatalf("a repeated kind had effects: store %d, dropbox %d, s3 %d, audit %d", f.settings.mutations(), f.dropbox.calls, f.checker.calls, backupAuditCount(f.audit))
				}
			})
		}
	}
	// A single kind still saves (previous behavior).
	f := emptyBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validDropboxForm, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || len(f.settings.putDropbox) != 1 {
		t.Fatalf("single kind save = %d, puts %d", rec.Code, len(f.settings.putDropbox))
	}
}

func TestDashboardTestBackupConnectionRefusesNonS3Kind(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.destination = cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups"}}
	f.settings.openErr = fmt.Errorf("%w: unknown kind %q", cloudstore.ErrBackupDestinationKindMismatch, "ftp")
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
