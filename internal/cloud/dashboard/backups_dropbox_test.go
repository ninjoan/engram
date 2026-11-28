package dashboard

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const (
	backupStoragePickForm = `<div class="backup-storage-pick">`
	dropboxFormOpen       = `<form method="post" action="/dashboard/admin/backups/destination" class="backup-provider-form backup-dropbox-form" autocomplete="off">`
)

func configuredDropboxDestination() cloudstore.BackupDestination {
	return cloudstore.BackupDestination{
		Configured: true, Kind: cloudstore.BackupDestinationKindDropbox,
		Dropbox:         cloudstore.DropboxDestinationView{FolderPath: "/Engram backups"},
		AccessKeyIDHint: "****mple",
		UpdatedAt:       time.Date(2026, 11, 26, 18, 2, 0, 0, time.UTC),
	}
}

// renderedStorageOptions returns the kinds of the storage choice links and
// the current one; each link must lead to ?kind=<kind>.
func renderedStorageOptions(t *testing.T, body string) (values []string, selected string) {
	t.Helper()
	start := strings.Index(body, `<nav class="backup-storage-options" aria-labelledby="backup-storage-label">`)
	if start < 0 {
		t.Fatalf("no storage choice, body=%q", body)
	}
	nav := body[start : start+strings.Index(body[start:], "</nav>")]
	for _, m := range regexp.MustCompile(`<a href="([^"]*)" data-storage-kind="([^"]*)"( aria-current="true" class="active")?>`).FindAllStringSubmatch(nav, -1) {
		if m[1] != "/dashboard/admin/backups?kind="+m[2]+"#backup-destination-title" {
			t.Fatalf("storage link %q leads to %q", m[2], m[1])
		}
		values = append(values, m[2])
		if m[3] != "" {
			if selected != "" {
				t.Fatalf("two current storage kinds in %q", nav)
			}
			selected = m[2]
		}
	}
	return values, selected
}

// dropboxFormHTML returns the Dropbox destination form.
func dropboxFormHTML(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, dropboxFormOpen)
	if start < 0 {
		t.Fatalf("no Dropbox form, body=%q", body)
	}
	return body[start : start+strings.Index(body[start:], "</form>")]
}

// The storage choice is a row of plain links (no form, no JavaScript) at
// the top of the empty destination, defaulting to S3-compatible, which
// keeps the guided setup.
func TestAdminBackupsStorageChoiceDefaultsToS3AndKeepsTheWizard(t *testing.T) {
	body := renderBackupsPageForTest(t, readyBackupsView(cloudstore.BackupDestination{}))
	pick := strings.Index(body, backupStoragePickForm)
	wizard := strings.Index(body, `class="backup-wizard"`)
	if pick < 0 || wizard < 0 || pick > wizard {
		t.Fatalf("the storage choice must sit above the wizard (pick %d, wizard %d), body=%q", pick, wizard, body)
	}
	values, selected := renderedStorageOptions(t, body)
	if strings.Join(values, ",") != "s3,dropbox,gdrive" || selected != "s3" {
		t.Fatalf("storage options = %v selected %q", values, selected)
	}
	for _, marker := range []string{`<p class="backup-storage-label" id="backup-storage-label">Storage</p>`, ">S3-compatible<", ">Dropbox<", ">Google Drive<", backupWizardScript} {
		if !strings.Contains(body, marker) {
			t.Fatalf("page lacks %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, dropboxFormOpen) {
		t.Fatalf("the S3 choice must not render the Dropbox form")
	}
}

// Choosing Dropbox replaces the wizard with the Dropbox form: app key, app
// secret, refresh token and folder, the secrets always empty, a collapsed
// guide and a check-before-save button that works without JavaScript.
func TestAdminBackupsDropboxFormForANewDestination(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.StorageKind = cloudstore.BackupDestinationKindDropbox
	body := renderBackupsPageForTest(t, v)
	if _, selected := renderedStorageOptions(t, body); selected != "dropbox" {
		t.Fatalf("selected storage = %q", selected)
	}
	if strings.Contains(body, `class="backup-wizard"`) || strings.Contains(body, backupWizardScript) || strings.Contains(body, `id="backup-provider"`) {
		t.Fatalf("the Dropbox choice must not render the S3 wizard, body=%q", body)
	}
	form := dropboxFormHTML(t, body)
	for _, marker := range []string{
		`<input type="hidden" name="kind" value="dropbox">`,
		`<label for="backup-dropbox-app-key">App key</label>`,
		`<label for="backup-dropbox-app-secret">App secret</label>`,
		`<label for="backup-dropbox-refresh-token">Refresh token</label>`,
		`<label for="backup-dropbox-folder">Folder</label>`,
		`<summary>How to get these values</summary>`,
		"Scoped access", "App folder", "Full Dropbox",
		"<code>files.content.write</code>", "<code>files.metadata.read</code>",
		"https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&amp;response_type=code&amp;token_access_type=offline",
		"curl https://api.dropboxapi.com/oauth2/token",
		"-d grant_type=authorization_code", "-u APP_KEY:APP_SECRET", "<code>refresh_token</code>",
		`formaction="/dashboard/admin/backups/destination/check"`,
		">Test connection</button>", ">Save destination</button>",
		"/Engram backups/", "engram-cloud-backup-&lt;UTC timestamp&gt;-run&lt;id&gt;.tar.gz",
	} {
		if !strings.Contains(form, marker) {
			t.Fatalf("Dropbox form lacks %q, form=%q", marker, form)
		}
	}
	if !strings.Contains(backupInputTag(t, form, "app_key"), `value=""`) || !strings.Contains(backupInputTag(t, form, "folder_path"), `value="/Engram backups"`) {
		t.Fatalf("app key must start empty and the folder default to /Engram backups, form=%q", form)
	}
	for _, name := range []string{"app_secret", "refresh_token"} {
		tag := backupInputTag(t, form, name)
		if !strings.Contains(tag, `type="password"`) || !strings.Contains(tag, `value=""`) || !strings.Contains(tag, "required") {
			t.Fatalf("%s must be an empty required password field: %s", name, tag)
		}
	}
	if save, check := strings.Index(form, ">Save destination</button>"), strings.Index(form, ">Test connection</button>"); save > check {
		t.Fatalf("Save destination must be the form's default (first) submit button")
	}
	for _, forbidden := range []string{`name="endpoint"`, `name="access_key_id"`, `name="bucket"`} {
		if strings.Contains(form, forbidden) {
			t.Fatalf("Dropbox form renders S3 field %q", forbidden)
		}
	}
}

// A refused Dropbox save re-renders the app key and the folder, marks the
// failing field and never echoes a secret.
func TestAdminBackupsDropboxFormRerendersARefusedSave(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.StorageKind = cloudstore.BackupDestinationKindDropbox
	v.DropboxForm = BackupDropboxForm{Submitted: true, AppKey: "dbxsubmittedkey", FolderPath: "/Team/Backups", Field: "refresh_token", Error: "refresh token must be 1-4096 printable characters without spaces"}
	form := dropboxFormHTML(t, renderBackupsPageForTest(t, v))
	for _, marker := range []string{
		`<div class="alert alert-danger" role="alert">`, "Destination not saved.", "Fix the field marked below.",
		"Your app secret and refresh token were not stored: paste them again.",
		`<span class="field-error" id="backup-dropbox-refresh-token-error">refresh token must be 1-4096 printable characters without spaces</span>`,
	} {
		if !strings.Contains(form, marker) {
			t.Fatalf("refused form lacks %q, form=%q", marker, form)
		}
	}
	if tag := backupInputTag(t, form, "refresh_token"); !strings.Contains(tag, `aria-invalid="true"`) || !strings.Contains(tag, `value=""`) {
		t.Fatalf("refresh token tag = %s", tag)
	}
	if !strings.Contains(backupInputTag(t, form, "app_key"), `value="dbxsubmittedkey"`) || !strings.Contains(backupInputTag(t, form, "folder_path"), `value="/Team/Backups"`) {
		t.Fatalf("submitted app key and folder were not kept, form=%q", form)
	}
	if strings.Count(form, `aria-invalid="true"`) != 1 {
		t.Fatalf("exactly one field must be marked invalid, form=%q", form)
	}
	// A reason that names no field is shown in the alert.
	v.DropboxForm = BackupDropboxForm{Submitted: true, Error: "choose S3-compatible or Dropbox storage"}
	if form := dropboxFormHTML(t, renderBackupsPageForTest(t, v)); !strings.Contains(form, "choose S3-compatible or Dropbox storage.") {
		t.Fatalf("unplaced reason missing, form=%q", form)
	}
}

// A check of unsaved Dropbox values shows its result inside the Dropbox
// form; a missing folder reads as connected.
func TestAdminBackupsDropboxCheckResult(t *testing.T) {
	for result, want := range map[string]string{
		"ok":        "Connected.",
		"ok-folder": "Connected — folder will be created on first upload.",
		"auth":      "Credentials rejected.",
		"folder":    "Folder path is a file.",
		"network":   "Dropbox unreachable.",
		"error":     "Unexpected response.",
	} {
		v := readyBackupsView(cloudstore.BackupDestination{})
		v.StorageKind = cloudstore.BackupDestinationKindDropbox
		v.DropboxForm = BackupDropboxForm{Submitted: true, AppKey: "dbxsubmittedkey", FolderPath: "/Engram backups"}
		v.DestinationCheck = BackupDestinationCheck{Kind: cloudstore.BackupDestinationKindDropbox, Result: result}
		body := renderBackupsPageForTest(t, v)
		form := dropboxFormHTML(t, body)
		if !strings.Contains(form, `data-check-result="`+result+`"`) || !strings.Contains(form, want) {
			t.Fatalf("%s: form lacks %q, form=%q", result, want, form)
		}
		if strings.Count(body, "data-check-result=") != 1 || strings.Contains(form, "Destination not saved.") || strings.Contains(form, "wizard-goto") {
			t.Fatalf("%s: the result must render once, without a refused-save alert or wizard links, body=%q", result, body)
		}
	}
}

// A configured Dropbox destination renders the status card variant: kind,
// folder, masked app key, the pill of the latest test and the Dropbox path
// of the last upload; Change destination defaults to the Dropbox form with
// the stored folder.
func TestAdminBackupsDropboxStatusCard(t *testing.T) {
	v := readyBackupsView(configuredDropboxDestination())
	v.DestinationTest = cloudstore.BackupDestinationTest{OccurredAt: time.Date(2026, 11, 26, 11, 0, 0, 0, time.UTC), Succeeded: true, ActorName: "Ada"}
	v.LastRuns = cloudstore.BackupRunOutcomes{LastSuccess: cloudstore.BackupRun{ID: 9, Status: cloudstore.BackupRunStatusSuccess, ObjectKey: "/Engram backups/engram-cloud-backup-20261126T030000Z-run9.tar.gz", SizeBytes: 2048, FinishedAt: time.Date(2026, 11, 26, 3, 0, 5, 0, time.UTC)}}
	v.Now = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)
	body := renderBackupsPageForTest(t, v)
	for _, marker := range []string{
		`<h4 class="backup-summary-title">Dropbox <span class="backup-pill is-connected">Connected</span></h4>`,
		`<p class="backup-summary-path">/Engram backups/</p>`,
		"Dropbox accepted the saved credentials.",
		"<dt>App key</dt><dd><code>****mple</code></dd>",
		"<small>Folder</small>",
		"<code>/Engram backups/engram-cloud-backup-20261126T030000Z-run9.tar.gz</code>",
		`action="/dashboard/admin/backups/destination/test"`,
		`action="/dashboard/admin/backups/destination/remove"`,
		"Backups already uploaded stay in Dropbox.",
		"<summary>Change destination</summary>",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("Dropbox card lacks %q, body=%q", marker, body)
		}
	}
	for _, forbidden := range []string{"<dt>Endpoint</dt>", "<dt>Region</dt>", "S3-compatible <span", "the bucket was listed", "<details class=\"backup-change\" open"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("Dropbox card renders %q, body=%q", forbidden, body)
		}
	}
	change := body[strings.Index(body, "<summary>Change destination</summary>"):]
	if _, selected := renderedStorageOptions(t, change); selected != "dropbox" {
		t.Fatalf("Change destination storage = %q", selected)
	}
	form := dropboxFormHTML(t, change)
	if !strings.Contains(backupInputTag(t, form, "folder_path"), `value="/Engram backups"`) || !strings.Contains(backupInputTag(t, form, "app_key"), `value=""`) {
		t.Fatalf("Change destination must pre-fill only the folder, form=%q", form)
	}
}

// A failing Dropbox test names the reason in Dropbox terms.
func TestAdminBackupsDropboxStatusCardFailing(t *testing.T) {
	v := readyBackupsView(configuredDropboxDestination())
	v.DestinationTest = cloudstore.BackupDestinationTest{OccurredAt: time.Date(2026, 11, 26, 11, 0, 0, 0, time.UTC), ReasonCode: "auth_failed"}
	body := renderBackupsPageForTest(t, v)
	for _, marker := range []string{`<span class="backup-pill is-failing">Failing</span>`, "Credentials rejected.", "refresh token"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("failing card lacks %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, "Keys rejected.") {
		t.Fatalf("the Dropbox card uses the S3 failure text, body=%q", body)
	}
}

// Choosing another storage on a configured destination opens Change
// destination with that kind's form.
func TestAdminBackupsConfiguredS3ChoosingDropboxOpensChangeDestination(t *testing.T) {
	v := readyBackupsView(configuredR2Destination())
	v.StorageKind, v.StorageKindChosen = cloudstore.BackupDestinationKindDropbox, true
	body := renderBackupsPageForTest(t, v)
	if !strings.Contains(body, `<details class="backup-change" open>`) {
		t.Fatalf("Change destination must open, body=%q", body)
	}
	change := body[strings.Index(body, "<summary>Change destination</summary>"):]
	if !strings.Contains(change, dropboxFormOpen) || strings.Contains(change, `class="backup-provider-form" `) {
		t.Fatalf("Change destination must hold only the Dropbox form, body=%q", change)
	}
	// The S3 card itself is unchanged.
	if !strings.Contains(body, "Cloudflare R2 <span") {
		t.Fatalf("S3 card changed, body=%q", body)
	}
	// Without a choice, a configured S3 destination keeps the S3 form.
	plain := renderBackupsPageForTest(t, readyBackupsView(configuredR2Destination()))
	if strings.Contains(plain, dropboxFormOpen) || !strings.Contains(plain, `class="backup-provider-form" autocomplete="off"`) {
		t.Fatalf("configured S3 must default to the S3 form, body=%q", plain)
	}
	if _, selected := renderedStorageOptions(t, plain); selected != "s3" {
		t.Fatalf("configured S3 storage = %q", selected)
	}
}
