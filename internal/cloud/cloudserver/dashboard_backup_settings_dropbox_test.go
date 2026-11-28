package cloudserver

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dropbox"
)

const (
	testDropboxAppKey       = "dbxdashboardappkey7q4z"
	testDropboxAppSecret    = "dbx-dashboard-app-secret-never-render"
	testDropboxRefreshToken = "dbx-dashboard-refresh-token-never-render"
)

func dropboxForm(overrides map[string]string) string {
	v := url.Values{
		"kind":          {"dropbox"},
		"app_key":       {testDropboxAppKey},
		"app_secret":    {testDropboxAppSecret},
		"refresh_token": {testDropboxRefreshToken},
		"folder_path":   {"/Engram backups"},
	}
	for k, val := range overrides {
		v.Set(k, val)
	}
	return v.Encode()
}

var validDropboxForm = dropboxForm(nil)

func configuredDropboxSettings() *fakeBackupSettingsStore {
	settings := configuredBackupSettings()
	settings.destination = cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindDropbox, Dropbox: cloudstore.DropboxDestinationView{AppKey: testDropboxAppKey, FolderPath: "/Engram backups"}}
	settings.creds = cloudstore.BackupDestinationCredentials{}
	settings.dropboxCreds = cloudstore.DropboxDestinationCredentials{AppKey: testDropboxAppKey, FolderPath: "/Engram backups", AppSecret: testDropboxAppSecret, RefreshToken: testDropboxRefreshToken}
	return settings
}

func dropboxBackupFixture(t *testing.T) backupSettingsFixture {
	t.Helper()
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	return wireBackupFixture(t, srv, audit, cookie, configuredDropboxSettings())
}

// assertNoDropboxSecret fails when a Dropbox secret appears in text.
func assertNoDropboxSecret(t *testing.T, label, text string) {
	t.Helper()
	for _, secret := range []string{testDropboxAppSecret, testDropboxRefreshToken} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaked a Dropbox secret: %q", label, text)
		}
	}
}

func assertNoDropboxSecretInAudit(t *testing.T, f backupSettingsFixture) {
	t.Helper()
	f.audit.auditMu.Lock()
	defer f.audit.auditMu.Unlock()
	for _, ev := range f.audit.auditEvents {
		assertNoDropboxSecret(t, "audit", ev.Action+" "+ev.ReasonCode+" "+fmtAny(ev.Metadata))
		if strings.Contains(fmtAny(ev.Metadata), testDropboxAppKey) {
			t.Fatalf("audit holds the full app key: %v", ev.Metadata)
		}
	}
}

func dropboxInputTag(t *testing.T, body, name string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input[^>]*\bname="` + name + `"[^>]*>`).FindString(body)
	if tag == "" {
		t.Fatalf("no input %q in body=%q", name, body)
	}
	return tag
}

// The page offers the storage choice and renders the form of ?kind=; an
// unknown kind falls back to the stored kind or S3.
func TestDashboardBackupsPageStorageKindQuery(t *testing.T) {
	f := emptyBackupFixture(t)
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind=dropbox", f.cookie).Body.String()
	if !strings.Contains(body, `class="backup-provider-form backup-dropbox-form"`) || strings.Contains(body, `class="backup-wizard"`) {
		t.Fatalf("?kind=dropbox must render the Dropbox form, body=%q", body)
	}
	for _, query := range []string{"", "?kind=bogus", "?kind=s3"} {
		body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+query, f.cookie).Body.String()
		if !strings.Contains(body, `class="backup-wizard"`) || strings.Contains(body, "backup-dropbox-form") {
			t.Fatalf("%q must render the S3 wizard, body=%q", query, body)
		}
	}
	gdrive := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind=gdrive", f.cookie).Body.String()
	if !strings.Contains(gdrive, "Google Drive is coming next") || strings.Contains(gdrive, `action="/dashboard/admin/backups/destination"`) {
		t.Fatalf("?kind=gdrive must render only text, body=%q", gdrive)
	}
	if n := f.settings.mutations(); n != 0 || f.dropbox.calls != 0 || backupAuditCount(f.audit) != 0 {
		t.Fatalf("viewing the page had side effects: store %d checks %d audits %d", n, f.dropbox.calls, backupAuditCount(f.audit))
	}
}

// Saving kind=dropbox stores the Dropbox destination with the backup key;
// no S3 destination is written and the store audits the save.
func TestDashboardSaveDropboxDestination(t *testing.T) {
	f := emptyBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validDropboxForm, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=destination-saved" {
		t.Fatalf("save = %d %q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	if len(f.settings.putDestination) != 0 || len(f.settings.putDropbox) != 1 {
		t.Fatalf("writes: s3 %d dropbox %d", len(f.settings.putDestination), len(f.settings.putDropbox))
	}
	p := f.settings.putDropbox[0]
	if p.AppKey != testDropboxAppKey || p.FolderPath != "/Engram backups" || p.AppSecret != testDropboxAppSecret || p.RefreshToken != testDropboxRefreshToken || p.Actor.PrincipalID != "p-admin" {
		t.Fatalf("params = %+v", p)
	}
	if f.settings.putSealers[0] == nil || f.dropbox.calls != 0 || f.checker.calls != 0 {
		t.Fatalf("save sealed with %v and checked %d/%d times", f.settings.putSealers[0], f.dropbox.calls, f.checker.calls)
	}
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	for _, marker := range []string{"Backup destination saved.", "Dropbox <span", "****7q4z", "Not tested"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("saved page lacks %q, body=%q", marker, page)
		}
	}
	assertNoDropboxSecret(t, "saved page", page)
	if strings.Contains(page, testDropboxAppKey) {
		t.Fatalf("the page shows the full app key")
	}
}

// A refused Dropbox save is a 400 that keeps the app key and the folder,
// marks the failing field and never echoes a secret; an unknown kind is
// refused before the store.
func TestDashboardSaveDropboxDestinationRefusals(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	for name, tc := range map[string]struct {
		form, field, reason string
	}{
		"refresh token": {form: dropboxForm(map[string]string{"refresh_token": "has spaces " + testDropboxRefreshToken}), field: "refresh_token", reason: "refresh token must be"},
		"app secret":    {form: dropboxForm(map[string]string{"app_secret": ""}), field: "app_secret", reason: "app secret must be"},
		"folder":        {form: dropboxForm(map[string]string{"folder_path": "Engram backups"}), field: "folder_path", reason: "folder path must start with"},
	} {
		t.Run(name, func(t *testing.T) {
			f := emptyBackupFixture(t)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: tc.form, cookie: f.cookie})
			body := rec.Body.String()
			if rec.Code != http.StatusBadRequest || !strings.Contains(body, "Destination not saved.") || !strings.Contains(body, tc.reason) {
				t.Fatalf("refusal = %d, body=%q", rec.Code, body)
			}
			assertNoDropboxSecret(t, "refused page", body)
			if !strings.Contains(dropboxInputTag(t, body, "app_key"), `value="`+testDropboxAppKey+`"`) {
				t.Fatalf("app key not kept, body=%q", body)
			}
			if name != "folder" && !strings.Contains(dropboxInputTag(t, body, "folder_path"), `value="/Engram backups"`) {
				t.Fatalf("folder not kept, body=%q", body)
			}
			if !strings.Contains(dropboxInputTag(t, body, tc.field), `aria-invalid="true"`) {
				t.Fatalf("%s not marked, body=%q", tc.field, body)
			}
			for _, secret := range []string{"app_secret", "refresh_token"} {
				if !strings.Contains(dropboxInputTag(t, body, secret), `value=""`) {
					t.Fatalf("%s re-rendered with a value", secret)
				}
			}
			if f.dropbox.calls != 0 || backupAuditCount(f.audit) != 0 {
				t.Fatalf("refused save checked %d times, audited %d", f.dropbox.calls, backupAuditCount(f.audit))
			}
		})
	}
	f := emptyBackupFixture(t)
	for _, kind := range []string{"gdrive", "ftp"} {
		rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: dropboxForm(map[string]string{"kind": kind}), cookie: f.cookie})
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "choose S3-compatible or Dropbox storage") {
			t.Fatalf("kind %s = %d body=%q", kind, rec.Code, rec.Body.String())
		}
		assertNoDropboxSecret(t, "kind refusal", rec.Body.String())
	}
	if n := f.settings.mutations(); n != 0 {
		t.Fatalf("unknown kinds touched the store %d times", n)
	}
	assertNoDropboxSecret(t, "logs", logs.String())
}

// The check route checks submitted Dropbox values with a bounded check,
// stores and opens nothing, audits the typed result without secrets and
// re-renders the form with the app key and folder only.
func TestDashboardCheckDropboxDestination(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		result string
		reason string
		text   string
	}{
		"ok":      {result: "ok", text: "Connected."},
		"folder":  {err: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrFolderNotFound, StatusCode: 409}, result: "ok-folder", text: "Connected — folder will be created on first upload."},
		"auth":    {err: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrAuth, StatusCode: 400, Summary: "invalid_grant " + testDropboxRefreshToken}, result: "auth", reason: "auth_failed", text: "Credentials rejected."},
		"file":    {err: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrConflict}, result: "folder", reason: "folder_conflict", text: "Folder path is a file."},
		"network": {err: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrNetwork}, result: "network", reason: "network", text: "Dropbox unreachable."},
		"timeout": {err: context.DeadlineExceeded, result: "network", reason: "network", text: "Dropbox unreachable."},
		"other":   {err: &dropbox.Error{Op: "CheckAccess", Kind: dropbox.ErrRateLimited, StatusCode: 429}, result: "error", reason: "unexpected_response", text: "Unexpected response."},
	} {
		t.Run(name, func(t *testing.T) {
			f := emptyBackupFixture(t)
			f.dropbox.err = tc.err
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validDropboxForm, cookie: f.cookie})
			body := rec.Body.String()
			if rec.Code != http.StatusOK || !strings.Contains(body, `data-check-result="`+tc.result+`"`) || !strings.Contains(body, tc.text) {
				t.Fatalf("check = %d, body=%q", rec.Code, body)
			}
			if f.dropbox.calls != 1 || !f.dropbox.hadDeadline || f.dropbox.creds.AppSecret != testDropboxAppSecret || f.dropbox.creds.RefreshToken != testDropboxRefreshToken || f.dropbox.creds.FolderPath != "/Engram backups" || f.checker.calls != 0 {
				t.Fatalf("checker calls %d deadline %v creds %v s3 %d", f.dropbox.calls, f.dropbox.hadDeadline, f.dropbox.creds, f.checker.calls)
			}
			if n := f.settings.mutations(); n != 0 {
				t.Fatalf("check touched the store %d times", n)
			}
			assertNoDropboxSecret(t, "check page", body)
			if !strings.Contains(dropboxInputTag(t, body, "app_key"), `value="`+testDropboxAppKey+`"`) || strings.Contains(body, "Destination not saved.") {
				t.Fatalf("check must keep the app key without a refused-save alert, body=%q", body)
			}
			events := backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck)
			if len(events) != 1 || events[0].ReasonCode != tc.reason || events[0].Metadata["kind"] != "dropbox" || events[0].Metadata["result"] != tc.result || events[0].Metadata["folder_path"] != "/Engram backups" || events[0].Metadata["app_key_hint"] != "****7q4z" {
				t.Fatalf("check audit = %+v", events)
			}
			if (tc.reason == "") != (events[0].Outcome != authAuditOutcomeFailure) {
				t.Fatalf("audit outcome %q for reason %q", events[0].Outcome, tc.reason)
			}
			assertNoDropboxSecretInAudit(t, f)
		})
	}
}

func TestDashboardCheckDropboxDestinationInvalidAndHTMX(t *testing.T) {
	f := emptyBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: dropboxForm(map[string]string{"app_key": "has space"}), cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, `data-check-result="invalid"`) || !strings.Contains(dropboxInputTag(t, body, "app_key"), `aria-invalid="true"`) {
		t.Fatalf("invalid check = %d body=%q", rec.Code, body)
	}
	assertNoDropboxSecret(t, "invalid check", body)
	events := backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck)
	if f.dropbox.calls != 0 || len(events) != 1 || events[0].ReasonCode != "invalid_destination" || events[0].Metadata["field"] != "app_key" || events[0].Metadata["kind"] != "dropbox" {
		t.Fatalf("invalid check: calls %d audit %+v", f.dropbox.calls, events)
	}
	htmx := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validDropboxForm, cookie: f.cookie, htmx: true})
	if htmx.Code != http.StatusOK || !strings.Contains(htmx.Body.String(), `data-check-result="ok"`) || strings.Contains(htmx.Body.String(), "<html") {
		t.Fatalf("htmx check = %d body=%q", htmx.Code, htmx.Body.String())
	}
	unknown := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: dropboxForm(map[string]string{"kind": "gdrive"}), cookie: f.cookie})
	if unknown.Code != http.StatusBadRequest || f.dropbox.calls != 1 {
		t.Fatalf("unknown kind check = %d calls %d", unknown.Code, f.dropbox.calls)
	}
	assertNoDropboxSecretInAudit(t, f)
}

// The test route opens the stored Dropbox destination and checks it; the
// result is audited without secrets and shown after a redirect.
func TestDashboardTestDropboxDestination(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		notice string
		reason string
		text   string
	}{
		"ok":     {notice: "dropbox-test-ok", text: "Dropbox accepted the stored credentials and the folder exists."},
		"folder": {err: dropbox.ErrFolderNotFound, notice: "dropbox-test-ok-folder", text: "Connected — folder will be created on first upload."},
		"auth":   {err: dropbox.ErrAuth, notice: "dropbox-test-auth", reason: "auth_failed", text: "Credentials rejected."},
		"file":   {err: dropbox.ErrConflict, notice: "dropbox-test-folder", reason: "folder_conflict", text: "Folder path is a file."},
		"net":    {err: dropbox.ErrNetwork, notice: "dropbox-test-network", reason: "network", text: "Dropbox unreachable."},
		"other":  {err: fmt.Errorf("boom %s", testDropboxAppSecret), notice: "dropbox-test-error", reason: "unexpected_response", text: "Unexpected response."},
	} {
		t.Run(name, func(t *testing.T) {
			f := dropboxBackupFixture(t)
			f.dropbox.err = tc.err
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("test = %d %q", rec.Code, dashboardRedirect(rec))
			}
			if f.dropbox.calls != 1 || !f.dropbox.hadDeadline || f.dropbox.creds != f.settings.dropboxCreds || f.checker.calls != 0 {
				t.Fatalf("checks dropbox %d (deadline %v) s3 %d creds %v", f.dropbox.calls, f.dropbox.hadDeadline, f.checker.calls, f.dropbox.creds)
			}
			events := backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)
			if len(events) != 1 || events[0].ReasonCode != tc.reason || events[0].Metadata["kind"] != "dropbox" || events[0].Metadata["folder_path"] != "/Engram backups" || events[0].Metadata["app_key_hint"] != "****7q4z" {
				t.Fatalf("test audit = %+v", events)
			}
			assertNoDropboxSecretInAudit(t, f)
			page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
			if !strings.Contains(page, tc.text) {
				t.Fatalf("notice %q missing, body=%q", tc.text, page)
			}
			assertNoDropboxSecret(t, "test page", page)
		})
	}
	// A Google Drive destination still cannot be tested.
	f := dropboxBackupFixture(t)
	f.settings.destination = cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: "1234-abcd.apps.googleusercontent.com", FolderName: "Engram backups"}}
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if dashboardRedirect(rec) != backupsPagePath+"?notice=test-unsupported" || f.dropbox.calls != 0 {
		t.Fatalf("gdrive test = %q calls %d", dashboardRedirect(rec), f.dropbox.calls)
	}
}

// A refused S3 save or an S3 check on a configured Dropbox destination
// re-renders the S3 form, not the Dropbox form of the stored kind.
func TestDashboardS3RerenderOnAConfiguredDropboxDestination(t *testing.T) {
	f := dropboxBackupFixture(t)
	form := strings.Replace(validBackupDestinationForm, "bucket=engram-backups", "bucket=Bad_Bucket", 1)
	f.settings.putDestinationErr = fmt.Errorf("%w: bucket must be 3-63 lowercase letters, digits, dots or hyphens", cloudstore.ErrInvalidBackupDestination)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form, cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, `<details class="backup-change" open>`) || strings.Contains(body, "backup-dropbox-form") {
		t.Fatalf("refused S3 save = %d, body=%q", rec.Code, body)
	}
	if !strings.Contains(dropboxInputTag(t, body, "bucket"), `aria-invalid="true"`) {
		t.Fatalf("bucket not marked, body=%q", body)
	}
	f.settings.putDestinationErr = nil
	check := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validBackupDestinationForm, cookie: f.cookie})
	if check.Code != http.StatusOK || !strings.Contains(check.Body.String(), `name="endpoint"`) || strings.Contains(check.Body.String(), "backup-dropbox-form") {
		t.Fatalf("S3 check = %d, body=%q", check.Code, check.Body.String())
	}
}

// A configured Dropbox destination renders its status card and Change
// destination; removing it works like any destination.
func TestDashboardDropboxDestinationCardAndRemove(t *testing.T) {
	f := dropboxBackupFixture(t)
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie).Body.String()
	for _, marker := range []string{"Dropbox <span", "/Engram backups/", "<dt>App key</dt><dd><code>****7q4z</code></dd>", `action="/dashboard/admin/backups/destination/remove"`, "backup-dropbox-form"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("card lacks %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, testDropboxAppKey) || strings.Contains(body, "This dashboard cannot edit or test this kind of destination yet") {
		t.Fatalf("card shows the full app key or the unsupported notice, body=%q", body)
	}
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || len(f.settings.clears) != 1 || f.settings.destination.Configured {
		t.Fatalf("remove = %d clears %d", rec.Code, len(f.settings.clears))
	}
}
