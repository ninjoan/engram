package cloudserver

import (
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// submittedBackupDestinationForm differs from the stored fixture destination
// in every non-secret field, so a re-render proves where each value came from.
func submittedBackupDestinationForm(endpoint string) url.Values {
	return url.Values{
		"provider":          {"aws"},
		"endpoint":          {endpoint},
		"region":            {"us-east-1"},
		"bucket":            {"submitted-bucket"},
		"prefix":            {"submitted/prefix/"},
		"access_key_id":     {testBackupAccessKeyID},
		"secret_access_key": {testBackupSecret},
	}
}

func backupFormInputTag(t *testing.T, body, name string) string {
	t.Helper()
	tag := regexp.MustCompile(`<input[^>]*\bname="` + name + `"[^>]*>`).FindString(body)
	if tag == "" {
		t.Fatalf("no input named %q, body=%q", name, body)
	}
	return tag
}

func TestDashboardSaveBackupDestinationRerendersSubmittedValuesAndMarksTheField(t *testing.T) {
	cases := []struct {
		field, id, reason string
	}{
		{"endpoint", "backup-endpoint", "endpoint must be an https origin such as https://<account>.r2.cloudflarestorage.com (http only for loopback hosts)"},
		{"region", "backup-region", `region must be 1-64 letters, digits, '-' or '_' (use "auto" for Cloudflare R2)`},
		{"bucket", "backup-bucket", "bucket must be 3-63 lowercase letters, digits, '.' or '-', start and end with a letter or digit, and not look like an IP address"},
		{"prefix", "backup-prefix", "prefix must not start with '/'"},
		{"access_key_id", "backup-access-key-id", "access key id must be 1-128 printable characters without spaces"},
		{"secret_access_key", "backup-secret-access-key", "secret access key must be 1-256 printable characters without spaces"},
	}
	for _, tc := range cases {
		t.Run(tc.field, func(t *testing.T) {
			f := managedBackupFixture(t)
			f.settings.putDestinationErr = fmt.Errorf("%w: %s", cloudstore.ErrInvalidBackupDestination, tc.reason)
			form := submittedBackupDestinationForm("https://s3.us-east-1.amazonaws.com").Encode()
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form, cookie: f.cookie})
			body := rec.Body.String()
			if rec.Code != http.StatusBadRequest {
				t.Fatalf("expected 400, got %d body=%q", rec.Code, body)
			}
			for field, want := range map[string]string{"endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "submitted-bucket", "prefix": "submitted/prefix/", "access_key_id": "", "secret_access_key": ""} {
				tag := backupFormInputTag(t, body, field)
				if !strings.Contains(tag, `value="`+want+`"`) {
					t.Fatalf("%s must re-render %q, got %q", field, want, tag)
				}
				invalid := strings.Contains(tag, `aria-invalid="true"`)
				if invalid != (field == tc.field) {
					t.Fatalf("%s aria-invalid=%v, only %s may be marked: %q", field, invalid, tc.field, tag)
				}
			}
			tag := backupFormInputTag(t, body, tc.field)
			if !strings.Contains(tag, `aria-describedby="`+tc.id+`-error`) {
				t.Fatalf("the failing field must reference its error, got %q", tag)
			}
			errorText := regexp.MustCompile(`<span class="field-error" id="` + tc.id + `-error">([^<]*)</span>`).FindStringSubmatch(body)
			if errorText == nil || !strings.Contains(errorText[1], html.EscapeString(tc.reason)) {
				t.Fatalf("expected the reason next to the field, got %v body=%q", errorText, body)
			}
			for _, marker := range []string{
				"alert alert-danger", "Destination not saved.", "Your keys were not stored",
				`<details class="backup-change" open>`,
				`<option value="aws" selected`,
				// The stored destination still shows in the summary.
				`<p class="backup-summary-path">engram-backups/prod/</p>`,
			} {
				if !strings.Contains(body, marker) {
					t.Fatalf("expected marker %q, body=%q", marker, body)
				}
			}
			if strings.Contains(body, testBackupSecret) || strings.Contains(body, testBackupAccessKeyID) || strings.Contains(body, "cloudstore:") {
				t.Fatalf("400 page must not echo credentials or internals, body=%q", body)
			}
		})
	}
}

func TestDashboardSaveBackupDestinationRerenderWithoutDestinationKeepsTheFormOpen(t *testing.T) {
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	f := wireBackupFixture(t, srv, audit, cookie, &fakeBackupSettingsStore{})
	f.settings.putDestinationErr = fmt.Errorf("%w: bucket must be 3-63 lowercase letters", cloudstore.ErrInvalidBackupDestination)
	form := submittedBackupDestinationForm("https://nyc3.digitaloceanspaces.com")
	form.Del("provider")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form.Encode(), cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || strings.Contains(body, `<details class="backup-`) || !strings.Contains(body, `<option value="do" selected`) || !strings.Contains(body, `<div class="backup-provider-hint" data-provider-hint="do">`) {
		t.Fatalf("expected the open form with the provider derived from the submitted endpoint, got %d body=%q", rec.Code, body)
	}
	if !strings.Contains(backupFormInputTag(t, body, "bucket"), `aria-invalid="true"`) || !strings.Contains(body, `<span class="backup-path-bucket">submitted-bucket</span>`) {
		t.Fatalf("expected the bucket marked and the path preview from the submitted values, body=%q", body)
	}
}

func TestDashboardSaveBackupDestinationNeverEchoesAnEndpointWithUserinfo(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.putDestinationErr = errInvalidEndpointForProbe
	form := submittedBackupDestinationForm("https://AKIAUSERINFO99:hunter2pass@s3.us-east-1.amazonaws.com").Encode()
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form, cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rec.Code)
	}
	if strings.Contains(body, "AKIAUSERINFO99") || strings.Contains(body, "hunter2pass") {
		t.Fatalf("an endpoint carrying userinfo must not be echoed, body=%q", body)
	}
	if tag := backupFormInputTag(t, body, "endpoint"); !strings.Contains(tag, `value=""`) || !strings.Contains(tag, `aria-invalid="true"`) {
		t.Fatalf("the endpoint must render empty and marked, got %q", tag)
	}
}

func TestDashboardSaveBackupDestinationIgnoresTheProviderHint(t *testing.T) {
	f := managedBackupFixture(t)
	form, err := url.ParseQuery(validBackupDestinationForm)
	if err != nil {
		t.Fatal(err)
	}
	form.Set("provider", "aws")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form.Encode(), cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=destination-saved" {
		t.Fatalf("expected 303, got %d %q", rec.Code, dashboardRedirect(rec))
	}
	want := cloudstore.PutBackupDestinationParams{
		Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/",
		AccessKeyID: testBackupAccessKeyID, SecretAccessKey: testBackupSecret,
		Actor: cloudstore.BackupDestinationActor{PrincipalID: "p-admin", Source: string(cloudauth.PrincipalSourceManagedToken)},
	}
	if len(f.settings.putDestination) != 1 || f.settings.putDestination[0] != want {
		t.Fatalf("the provider hint must not change the stored destination, got %+v", f.settings.putDestination)
	}
	// The re-rendered page derives the provider from the stored endpoint
	// (R2), not from the submitted hint.
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	if !strings.Contains(page, `<option value="r2" selected`) || strings.Contains(page, `<option value="aws" selected`) || !strings.Contains(page, `<div class="backup-provider-hint" data-provider-hint="r2">`) {
		t.Fatalf("the selected provider must come from the stored endpoint, body=%q", page)
	}
}

func TestDashboardBackupsPageRendersTestResultsInsideTheDestination(t *testing.T) {
	cases := map[string]string{
		"test-ok":      "Connected.",
		"test-auth":    "Keys rejected.",
		"test-bucket":  "Bucket not found.",
		"test-network": "Endpoint unreachable.",
	}
	for notice, title := range cases {
		t.Run(notice, func(t *testing.T) {
			f := managedBackupFixture(t)
			body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice="+notice, f.cookie).Body.String()
			destination := strings.Index(body, `aria-labelledby="backup-destination-title"`)
			schedule := strings.Index(body, ">SCHEDULE<")
			at := strings.Index(body, title)
			if destination < 0 || schedule < 0 || at < destination || at > schedule {
				t.Fatalf("%s result must render inside the destination frame (dest=%d at=%d schedule=%d), body=%q", notice, destination, at, schedule, body)
			}
			if strings.Count(body, backupNotices[notice].Message) != 1 || !strings.Contains(body, `role="status"`) {
				t.Fatalf("%s must render once as a status, body=%q", notice, body)
			}
		})
	}
}
