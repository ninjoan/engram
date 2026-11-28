package dashboard

import (
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const (
	gdriveFormOpen        = `<form method="post" action="/dashboard/admin/backups/destination" class="backup-provider-form backup-gdrive-form" autocomplete="off">`
	gdriveConnectAction   = `action="/dashboard/admin/backups/gdrive/connect"`
	testGDriveRedirectURI = "https://engram.example.test/dashboard/admin/backups/gdrive/callback"
)

func gdriveDestination(authorized bool) cloudstore.BackupDestination {
	return cloudstore.BackupDestination{
		Configured: true, Kind: cloudstore.BackupDestinationKindGDrive,
		GDrive:          cloudstore.GDriveDestinationView{FolderName: "Engram backups", Authorized: authorized},
		AccessKeyIDHint: "****.com",
		UpdatedAt:       time.Date(2026, 11, 26, 18, 2, 0, 0, time.UTC),
	}
}

func gdriveFormHTML(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, gdriveFormOpen)
	if start < 0 {
		t.Fatalf("no Google Drive form, body=%q", body)
	}
	return body[start : start+strings.Index(body[start:], "</form>")]
}

// S15: choosing Google Drive renders a real form (client id, client secret,
// folder), the exact redirect URI to register and a collapsed guide that
// warns about the 7-day refresh token expiry of apps in "Testing".
func TestAdminBackupsGoogleDriveForm(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.StorageKind = cloudstore.BackupDestinationKindGDrive
	v.GDriveRedirectURI = testGDriveRedirectURI
	body := renderBackupsPageForTest(t, v)
	form := gdriveFormHTML(t, body)
	for _, marker := range []string{
		`<input type="hidden" name="kind" value="gdrive">`,
		`name="client_id" value=""`,
		`type="password" id="backup-gdrive-client-secret" name="client_secret" value=""`,
		`name="folder" value="Engram backups"`,
		"<code>" + testGDriveRedirectURI + "</code>",
		`<details class="backup-help"><summary>How to create a Google OAuth client</summary>`,
		"Google Drive API", "test user", "7 days", "In production", "Web application", "drive.file",
		"Save Google Drive settings",
	} {
		if !strings.Contains(form, marker) {
			t.Fatalf("Google Drive form lacks %q, form=%q", marker, form)
		}
	}
	for _, forbidden := range []string{`name="endpoint"`, `name="app_key"`, `name="refresh_token"`, "formaction=", gdriveConnectAction, backupWizardScript} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Google Drive choice renders %q, body=%q", forbidden, body)
		}
	}
}

// Without ENGRAM_CLOUD_PUBLIC_URL the form explains the missing setting and
// shows no redirect URI; the pending card shows no Connect control.
func TestAdminBackupsGoogleDriveWithoutPublicURL(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.StorageKind = cloudstore.BackupDestinationKindGDrive
	form := gdriveFormHTML(t, renderBackupsPageForTest(t, v))
	if !strings.Contains(form, "ENGRAM_CLOUD_PUBLIC_URL") || strings.Contains(form, "/gdrive/callback") {
		t.Fatalf("form without a public URL, form=%q", form)
	}
	pending := readyBackupsView(gdriveDestination(false))
	body := renderBackupsPageForTest(t, pending)
	if strings.Contains(body, gdriveConnectAction) || !strings.Contains(body, "ENGRAM_CLOUD_PUBLIC_URL") {
		t.Fatalf("pending card without a public URL must explain it and render no Connect control, body=%q", body)
	}
}

// A pending destination shows Not connected and Connect with Google; an
// authorized one shows the test pill, Test connection and Reconnect. The
// card names the folder and the client id hint only.
func TestAdminBackupsGoogleDriveStatusCard(t *testing.T) {
	pending := readyBackupsView(gdriveDestination(false))
	pending.GDriveRedirectURI = testGDriveRedirectURI
	body := renderBackupsPageForTest(t, pending)
	for _, marker := range []string{"Google Drive <span", `class="backup-pill is-untested">Not connected</span>`, gdriveConnectAction, ">Connect with Google</button>", "<dt>Client ID</dt><dd><code>****.com</code></dd>", "<dt>Authorization</dt><dd>Pending</dd>", "Engram backups/", `action="/dashboard/admin/backups/destination/remove"`} {
		if !strings.Contains(body, marker) {
			t.Fatalf("pending card lacks %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, `action="/dashboard/admin/backups/destination/test"`) {
		t.Fatalf("a pending destination offers Test connection, body=%q", body)
	}

	connected := readyBackupsView(gdriveDestination(true))
	connected.GDriveRedirectURI = testGDriveRedirectURI
	connected.DestinationTest = cloudstore.BackupDestinationTest{OccurredAt: time.Date(2026, 11, 26, 18, 5, 0, 0, time.UTC), Succeeded: true}
	connected.Now = time.Date(2026, 11, 26, 19, 0, 0, 0, time.UTC)
	body = renderBackupsPageForTest(t, connected)
	for _, marker := range []string{`class="backup-pill is-connected">Connected</span>`, `action="/dashboard/admin/backups/destination/test"`, "Reconnect with Google", "<dt>Authorization</dt><dd>Connected</dd>", "Google Drive accepted the saved authorization"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("connected card lacks %q, body=%q", marker, body)
		}
	}
	failing := connected
	failing.DestinationTest = cloudstore.BackupDestinationTest{OccurredAt: connected.DestinationTest.OccurredAt, ReasonCode: "auth_failed"}
	body = renderBackupsPageForTest(t, failing)
	if !strings.Contains(body, `class="backup-pill is-failing">Failing</span>`) || !strings.Contains(body, "Authorization rejected.") {
		t.Fatalf("failing card, body=%q", body)
	}
}

// A refused save re-renders the client id and folder, marks the failing
// field and never the client secret.
func TestAdminBackupsGoogleDriveRefusedSave(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.StorageKind = cloudstore.BackupDestinationKindGDrive
	v.GDriveForm = BackupGDriveForm{Submitted: true, ClientID: "1234-x.apps.googleusercontent.com", FolderName: "Backups", Field: "client_secret", Error: "client secret must be 1-256 printable characters without spaces"}
	form := gdriveFormHTML(t, renderBackupsPageForTest(t, v))
	for _, marker := range []string{"Destination not saved.", `value="1234-x.apps.googleusercontent.com"`, `name="folder" value="Backups"`, `aria-invalid="true"`, "client secret must be 1-256 printable characters without spaces", "Your client secret was not stored"} {
		if !strings.Contains(form, marker) {
			t.Fatalf("refused form lacks %q, form=%q", marker, form)
		}
	}
	if !strings.Contains(form, `name="client_secret" value=""`) {
		t.Fatalf("client secret re-rendered, form=%q", form)
	}
}

// A member sees the Google Drive card without any control.
func TestAdminBackupsGoogleDriveCardForMembers(t *testing.T) {
	v := readyBackupsView(gdriveDestination(false))
	v.CanManage = false
	v.GDriveRedirectURI = testGDriveRedirectURI
	body := renderBackupsPageForTest(t, v)
	if !strings.Contains(body, "Google Drive <span") || strings.Contains(body, gdriveConnectAction) || strings.Contains(body, gdriveFormOpen) {
		t.Fatalf("member view, body=%q", body)
	}
}
