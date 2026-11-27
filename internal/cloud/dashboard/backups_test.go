package dashboard

import (
	"bytes"
	"context"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var (
	backupProviderRadio = regexp.MustCompile(`<input type="radio" name="provider" value="([a-z0-9]+)" id="backup-provider-[a-z0-9]+"( checked)?`)
	backupFormFieldName = regexp.MustCompile(`<(?:input|button)[^>]*\bname="([a-z_]+)"`)
)

func renderBackupsPageForTest(t *testing.T, v BackupsPageView) string {
	t.Helper()
	var buf bytes.Buffer
	if err := AdminBackupsPage(v).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func readyBackupsView(destination cloudstore.BackupDestination) BackupsPageView {
	return BackupsPageView{
		CanManage:   true,
		Settings:    BackupSettingsReady,
		Destination: destination,
		Schedule:    cloudstore.BackupSchedule{TimeOfDay: "03:00", Timezone: "UTC"},
	}
}

func configuredR2Destination() cloudstore.BackupDestination {
	return cloudstore.BackupDestination{
		Configured: true, Kind: "s3", Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto",
		Bucket: "engram-backups", Prefix: "prod/", AccessKeyIDHint: "****7f3a",
		UpdatedAt: time.Date(2026, 11, 26, 18, 2, 0, 0, time.UTC),
	}
}

// backupInputTag returns the rendered <input> tag of the named field.
func backupInputTag(t *testing.T, body, name string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input[^>]*\bname="` + name + `"[^>]*>`).FindString(body)
	if tag == "" {
		t.Fatalf("no input named %q in body=%q", name, body)
	}
	return tag
}

func backupProviderSelection(body string) (values []string, checked []string) {
	for _, m := range backupProviderRadio.FindAllStringSubmatch(body, -1) {
		values = append(values, m[1])
		if m[2] != "" {
			checked = append(checked, m[1])
		}
	}
	return values, checked
}

// The first-time (empty) state renders the guided setup instead
// (backups_wizard_test.go); the provider tiles and grouped form stay behind
// Change destination, pre-filled from the stored destination.
func TestAdminBackupsPageChangeDestinationRendersProviderTilesAndGroupedForm(t *testing.T) {
	d := configuredR2Destination()
	d.Endpoint, d.Bucket, d.Prefix = "https://s3.qa.local:9443", "", ""
	body := renderBackupsPageForTest(t, readyBackupsView(d))

	values, checked := backupProviderSelection(body)
	if got, want := strings.Join(values, ","), "r2,aws,b2,wasabi,do,minio,other"; got != want {
		t.Fatalf("provider tiles = %q, want %q", got, want)
	}
	if len(checked) != 1 || checked[0] != "other" {
		t.Fatalf("the tile must come from the stored endpoint host, got %v", checked)
	}
	for _, marker := range []string{
		`<form method="post" action="/dashboard/admin/backups/destination" class="backup-provider-form" autocomplete="off">`,
		"Cloudflare R2", "&lt;account-id&gt;.r2.cloudflarestorage.com",
		"Amazon S3", "s3.&lt;region&gt;.amazonaws.com",
		"Backblaze B2", "s3.&lt;region&gt;.backblazeb2.com",
		"Wasabi", "s3.&lt;region&gt;.wasabisys.com",
		"DigitalOcean Spaces", "&lt;region&gt;.digitaloceanspaces.com",
		"MinIO / self-hosted", "Other S3-compatible", "any SigV4 endpoint over https",
		`<svg class="backup-mark backup-mark-r2"`,
		"Storage provider", ">Connection</legend>", ">Location</legend>", ">Credentials</legend>",
		`data-provider-guide="none"`, `data-provider-guide="r2"`, `data-provider-guide="other"`,
		"Backups will be saved as",
		`<span class="backup-path-bucket">&lt;bucket&gt;</span>`,
		"engram-cloud-backup-&lt;UTC timestamp&gt;-run&lt;id&gt;.tar.gz",
		"Why paste both keys again?", "never shows them again",
		`<label for="backup-endpoint"`, `<label for="backup-secret-access-key"`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected marker %q, body=%q", marker, body)
		}
	}
	for _, field := range []string{"access_key_id", "secret_access_key"} {
		if tag := backupInputTag(t, body, field); !strings.Contains(tag, `value=""`) {
			t.Fatalf("credential input %s must render empty, got %q", field, tag)
		}
	}
	if tag := backupInputTag(t, body, "region"); !strings.Contains(tag, `value="auto"`) {
		t.Fatalf("region must still default to auto, got %q", tag)
	}
	for _, forbidden := range []string{"<script", "hx-post", "aria-invalid", "data-backup-wizard"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("the Change destination form must not render %q", forbidden)
		}
	}
}

func TestAdminBackupsPageDestinationFormPostsOnlyTheStoredFields(t *testing.T) {
	body := renderBackupsPageForTest(t, readyBackupsView(configuredR2Destination()))
	start := strings.Index(body, `action="/dashboard/admin/backups/destination"`)
	end := strings.Index(body[start:], "</form>")
	if start < 0 || end < 0 {
		t.Fatalf("destination form not found, body=%q", body)
	}
	seen := map[string]bool{}
	for _, m := range backupFormFieldName.FindAllStringSubmatch(body[start:start+end], -1) {
		seen[m[1]] = true
	}
	want := []string{"provider", "endpoint", "region", "bucket", "prefix", "access_key_id", "secret_access_key"}
	if len(seen) != len(want) {
		t.Fatalf("form fields = %v, want exactly %v", seen, want)
	}
	for _, name := range want {
		if !seen[name] {
			t.Fatalf("form misses field %q, got %v", name, seen)
		}
	}
	if !strings.Contains(body[start:start+end], `<button type="submit">Save destination</button>`) {
		t.Fatal("the form must post with a plain submit button")
	}
}

func TestAdminBackupsPageSelectsTileFromStoredEndpointHost(t *testing.T) {
	cases := []struct {
		endpoint, want, name string
	}{
		{"https://acct.r2.cloudflarestorage.com", "r2", "Cloudflare R2"},
		{"https://s3.us-east-1.amazonaws.com", "aws", "Amazon S3"},
		{"https://s3.us-west-004.backblazeb2.com", "b2", "Backblaze B2"},
		{"https://s3.eu-central-1.wasabisys.com", "wasabi", "Wasabi"},
		{"https://nyc3.digitaloceanspaces.com", "do", "DigitalOcean Spaces"},
		{"http://127.0.0.1:9000", "minio", "MinIO / self-hosted"},
		{"http://localhost:9000", "minio", "MinIO / self-hosted"},
		{"https://minio.internal.example.com:9000", "minio", "MinIO / self-hosted"},
		{"https://s3.qa.local:9443", "other", "S3-compatible"},
		{"https://notr2.cloudflarestorage.com.evil.test", "other", "S3-compatible"},
	}
	for _, tc := range cases {
		t.Run(tc.endpoint, func(t *testing.T) {
			d := configuredR2Destination()
			d.Endpoint = tc.endpoint
			body := renderBackupsPageForTest(t, readyBackupsView(d))
			if _, checked := backupProviderSelection(body); len(checked) != 1 || checked[0] != tc.want {
				t.Fatalf("checked tiles = %v, want [%s]", checked, tc.want)
			}
			if !strings.Contains(body, `<h4 class="backup-summary-title">`+tc.name) {
				t.Fatalf("summary must name provider %q, body=%q", tc.name, body)
			}
			if !strings.Contains(body, `<svg class="backup-mark backup-mark-`+tc.want+`"`) {
				t.Fatalf("summary must show the %s mark", tc.want)
			}
		})
	}
}

func TestAdminBackupsPageConfiguredCollapsesTilesBehindChangeDestination(t *testing.T) {
	body := renderBackupsPageForTest(t, readyBackupsView(configuredR2Destination()))
	for _, marker := range []string{
		`<span class="backup-pill is-untested">Not tested</span>`,
		`<p class="backup-summary-path">engram-backups/prod/</p>`,
		"<dd><code>https://acct.r2.cloudflarestorage.com</code></dd>",
		"<dd><code>****7f3a</code></dd>",
		"<dd>" + formatTimeValue(configuredR2Destination().UpdatedAt) + "</dd>",
		`action="/dashboard/admin/backups/destination/test"`,
		`action="/dashboard/admin/backups/destination/remove"`,
		`<details class="backup-change">`,
		"<summary>Change destination</summary>",
		"the saved key <code>****7f3a</code> keeps working until you save",
		`<span class="backup-path-bucket">engram-backups</span>/<span class="backup-path-prefix">prod/</span>`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected marker %q, body=%q", marker, body)
		}
	}
	details := strings.Index(body, `<details class="backup-change">`)
	if tiles := strings.Index(body, `name="provider"`); tiles < details {
		t.Fatalf("tiles must be collapsed inside Change destination (details at %d, tiles at %d)", details, tiles)
	}
	if form := strings.Index(body, `action="/dashboard/admin/backups/destination"`); form < details {
		t.Fatal("the destination form must be inside Change destination")
	}
	if strings.Contains(body, `<details class="backup-change" open`) || strings.Contains(body, "Not configured") {
		t.Fatal("a configured destination renders the summary with the form collapsed")
	}
	for field, want := range map[string]string{"endpoint": "https://acct.r2.cloudflarestorage.com", "region": "auto", "bucket": "engram-backups", "prefix": "prod/", "access_key_id": "", "secret_access_key": ""} {
		if tag := backupInputTag(t, body, field); !strings.Contains(tag, `value="`+want+`"`) {
			t.Fatalf("%s must be pre-filled with %q, got %q", field, want, tag)
		}
	}
}

func TestAdminBackupsPageShowsOnlyTheMaskedAccessKeyHint(t *testing.T) {
	d := configuredR2Destination()
	d.AccessKeyIDHint = "****"
	body := renderBackupsPageForTest(t, readyBackupsView(d))
	if !strings.Contains(body, "<dd><code>****</code></dd>") || strings.Contains(body, "7f3a") {
		t.Fatalf("a short access key id shows only ****, body=%q", body)
	}
}

func TestAdminBackupsPageReadOnlyStatesRenderNoForms(t *testing.T) {
	cases := map[string]BackupsPageView{
		"legacy admin": {CanManage: false, Settings: BackupSettingsReady, Destination: configuredR2Destination()},
		"key missing":  {CanManage: true, Settings: BackupSettingsKeyMissing, Destination: configuredR2Destination()},
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			body := renderBackupsPageForTest(t, v)
			if !strings.Contains(body, `<h4 class="backup-summary-title">Cloudflare R2`) || !strings.Contains(body, "engram-backups/prod/") || !strings.Contains(body, "****7f3a") {
				t.Fatalf("read-only summary missing, body=%q", body)
			}
			for _, forbidden := range []string{`action="/dashboard/admin/backups/destination`, `type="radio"`, "<details", "Change destination", `name="secret_access_key"`} {
				if strings.Contains(body, forbidden) {
					t.Fatalf("read-only state must not render %q", forbidden)
				}
			}
		})
	}
	body := renderBackupsPageForTest(t, BackupsPageView{CanManage: true, Settings: BackupSettingsKeyMissing})
	if !strings.Contains(body, "ENGRAM_CLOUD_BACKUP_KEY") || !strings.Contains(body, "No destination is configured.") || strings.Contains(body, `type="radio"`) {
		t.Fatalf("key missing without destination explains and renders no tiles, body=%q", body)
	}
}
