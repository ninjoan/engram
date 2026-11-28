package dashboard

import (
	"bytes"
	"context"
	"io/fs"
	"regexp"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var backupWizardScript = `<script src="` + StaticURL("backups-wizard.js") + `" defer></script>`

// backupFormBody returns the destination form that posts to the save route.
func backupFormBody(t *testing.T, body string) string {
	t.Helper()
	start := strings.Index(body, `action="/dashboard/admin/backups/destination"`)
	if start < 0 {
		t.Fatalf("destination form not found, body=%q", body)
	}
	end := strings.Index(body[start:], "</form>")
	if end < 0 {
		t.Fatalf("destination form not closed, body=%q", body)
	}
	return body[start : start+end]
}

func TestAdminBackupsPageEmptyStateRendersTheGuidedSetup(t *testing.T) {
	body := renderBackupsPageForTest(t, readyBackupsView(cloudstore.BackupDestination{}))
	form := backupFormBody(t, body)

	if got := strings.Count(form, `data-wizard-step="`); got != 4 {
		t.Fatalf("the wizard must have 4 step sections, got %d", got)
	}
	steps := []string{
		`id="backup-wizard-step-1" data-wizard-step="1"`, "Step 1 of 4 · Provider",
		`id="backup-wizard-step-2" data-wizard-step="2"`, "Step 2 of 4 · Connection",
		`id="backup-wizard-step-3" data-wizard-step="3"`, "Step 3 of 4 · Credentials",
		`id="backup-wizard-step-4" data-wizard-step="4"`, "Step 4 of 4 · Test &amp; save",
	}
	last := -1
	for _, marker := range steps {
		at := strings.Index(form, marker)
		if at < 0 || at < last {
			t.Fatalf("step marker %q missing or out of order, form=%q", marker, form)
		}
		last = at
	}
	for _, marker := range []string{
		`<form method="post" action="/dashboard/admin/backups/destination" class="backup-wizard" autocomplete="off" data-backup-wizard data-wizard-start="1">`,
		`<ol class="backup-stepper" aria-label="Setup progress">`,
		`tabindex="-1"`,
		`<aside class="backup-rail" aria-label="Setup summary">`, "Your destination",
		"Set up an off-site destination", "No destination is configured.",
		"badge badge-muted\">Not configured",
		// Step 1 is the provider select with one hint line, defaulting to
		// Cloudflare R2 like the placeholders.
		`<select id="backup-provider" name="provider" aria-describedby="backup-provider-hint"`,
		`<dd data-wizard-summary="provider" data-pending="not chosen">Cloudflare R2</dd>`,
		// Step 2: connection and location with the path preview.
		`name="endpoint"`, `name="region"`, `name="bucket"`, `name="prefix"`,
		"Backups will be saved as", `<span class="backup-path-bucket">&lt;bucket&gt;</span>`,
		// Step 3: the friendly re-entry note.
		"Your keys are sealed, then forgotten by the screen.", "every save asks for both keys",
		// Step 4: the check slot and its actions.
		`id="backup-wizard-result"`, `hx-post="/dashboard/admin/backups/destination/check"`, "Test connection",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected wizard marker %q, body=%q", marker, body)
		}
	}
	assertSingleProviderPicker(t, body, "r2")
	step1, step2 := strings.Index(form, `data-wizard-step="1"`), strings.Index(form, `data-wizard-step="2"`)
	if at := strings.Index(form, `id="backup-provider"`); at < step1 || at > step2 {
		t.Fatalf("the provider select must be in step 1, form=%q", form)
	}
	if strings.Count(body, backupWizardScript) != 1 {
		t.Fatalf("the wizard must load its script exactly once, body=%q", body)
	}
	for _, forbidden := range []string{`<details class="backup-`, "backup-provider-form", "backup-tiles", "onclick", "aria-invalid", "Destination not saved."} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("empty state must not render %q", forbidden)
		}
	}
}

// Without JavaScript the wizard is one form whose only submit is "Save
// destination", posting exactly the fields of the save route.
func TestAdminBackupsPageWizardWorksWithoutJavaScript(t *testing.T) {
	body := renderBackupsPageForTest(t, readyBackupsView(cloudstore.BackupDestination{}))
	form := backupFormBody(t, body)
	if strings.Count(body, "<form") != 2 || !strings.Contains(body, `action="/dashboard/admin/backups/download"`) {
		t.Fatalf("expected the download form and one destination form, body=%q", body)
	}
	submits := regexp.MustCompile(`<button[^>]*type="submit"[^>]*>([^<]*)</button>`).FindAllStringSubmatch(form, -1)
	if len(submits) != 1 || submits[0][1] != "Save destination" {
		t.Fatalf("the wizard must have one submit, Save destination, got %v", submits)
	}
	for _, tag := range regexp.MustCompile(`<button[^>]*>`).FindAllString(form, -1) {
		if strings.Contains(tag, `type="submit"`) {
			continue
		}
		if !strings.Contains(tag, `type="button"`) || !strings.Contains(tag, " hidden") {
			t.Fatalf("step buttons must be script-only (type=button, hidden), got %q", tag)
		}
	}
	if regexp.MustCompile(`<fieldset[^>]*data-wizard-step[^>]*hidden`).MatchString(form) {
		t.Fatal("every step section must be visible without JavaScript")
	}
	seen := map[string]bool{}
	for _, m := range backupFormFieldName.FindAllStringSubmatch(form, -1) {
		seen[m[1]] = true
	}
	want := []string{"provider", "endpoint", "region", "bucket", "prefix", "access_key_id", "secret_access_key"}
	if len(seen) != len(want) {
		t.Fatalf("wizard fields = %v, want exactly %v", seen, want)
	}
	for _, name := range want {
		if !seen[name] {
			t.Fatalf("wizard misses field %q", name)
		}
	}
	for _, field := range []string{"access_key_id", "secret_access_key"} {
		if tag := backupInputTag(t, body, field); !strings.Contains(tag, `value=""`) || !strings.Contains(tag, "required") {
			t.Fatalf("credential %s must render empty and required, got %q", field, tag)
		}
	}
	if tag := backupInputTag(t, body, "region"); !strings.Contains(tag, `value="auto"`) {
		t.Fatalf("region must default to auto, got %q", tag)
	}
}

func TestAdminBackupsPageWizardOnlyForTheEditableEmptyState(t *testing.T) {
	configured := renderBackupsPageForTest(t, readyBackupsView(configuredR2Destination()))
	for _, forbidden := range []string{"data-backup-wizard", backupWizardScript, "hx-post"} {
		if strings.Contains(configured, forbidden) {
			t.Fatalf("a configured destination must not render %q", forbidden)
		}
	}
	// Change destination keeps the 01 grouped form, with the provider select.
	details := strings.Index(configured, `<details class="backup-change">`)
	form := strings.Index(configured, `class="backup-provider-form"`)
	if details < 0 || form < details || strings.Index(configured, `<select id="backup-provider" name="provider"`) < form {
		t.Fatalf("Change destination must keep the grouped form with the provider select, body=%q", configured)
	}
	for name, v := range map[string]BackupsPageView{
		"key missing":  {CanManage: true, Settings: BackupSettingsKeyMissing},
		"legacy admin": {CanManage: false, Settings: BackupSettingsReady},
	} {
		body := renderBackupsPageForTest(t, v)
		if strings.Contains(body, "data-backup-wizard") || strings.Contains(body, backupWizardScript) || strings.Contains(body, `name="provider"`) {
			t.Fatalf("%s must not render the wizard, body=%q", name, body)
		}
		if !strings.Contains(body, "No destination is configured.") {
			t.Fatalf("%s must still explain the missing destination", name)
		}
	}
}

func TestAdminBackupsPageWizardRerendersARefusedSave(t *testing.T) {
	cases := map[string]string{"endpoint": "2", "bucket": "2", "prefix": "2", "access_key_id": "3", "secret_access_key": "3", "": "1"}
	for field, step := range cases {
		t.Run(field, func(t *testing.T) {
			v := readyBackupsView(cloudstore.BackupDestination{})
			v.DestinationForm = BackupDestinationForm{Submitted: true, Provider: "aws", Endpoint: "https://s3.us-east-1.amazonaws.com", Region: "us-east-1", Bucket: "submitted-bucket", Prefix: "submitted/", Field: field, Error: "a fixed reason"}
			body := renderBackupsPageForTest(t, v)
			assertSingleProviderPicker(t, body, "aws")
			for _, marker := range []string{
				`data-wizard-start="` + step + `"`, "Destination not saved.", "Your keys were not stored",
				`<option value="aws" selected`, `<span class="backup-path-bucket">submitted-bucket</span>`,
			} {
				if !strings.Contains(body, marker) {
					t.Fatalf("expected marker %q, body=%q", marker, body)
				}
			}
			for name, want := range map[string]string{"endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "submitted-bucket", "prefix": "submitted/", "access_key_id": "", "secret_access_key": ""} {
				tag := backupInputTag(t, body, name)
				if !strings.Contains(tag, `value="`+want+`"`) {
					t.Fatalf("%s must re-render %q, got %q", name, want, tag)
				}
				if strings.Contains(tag, `aria-invalid="true"`) != (name == field) {
					t.Fatalf("only %q may be marked invalid, got %q", field, tag)
				}
			}
		})
	}
}

func TestAdminBackupsPageWizardShowsACheckResultAtStepFour(t *testing.T) {
	v := readyBackupsView(cloudstore.BackupDestination{})
	v.DestinationForm = BackupDestinationForm{Submitted: true, Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups"}
	v.DestinationCheck = BackupDestinationCheck{Result: "auth"}
	body := renderBackupsPageForTest(t, v)
	result := strings.Index(body, `id="backup-wizard-result"`)
	at := strings.Index(body, "Keys rejected.")
	if result < 0 || at < result || !strings.Contains(body, `data-wizard-start="4"`) {
		t.Fatalf("the check result must render in the step 4 slot, body=%q", body)
	}
	if strings.Contains(body, "Destination not saved.") {
		t.Fatal("a check result is not a refused save")
	}
}

func renderCheckResultForTest(t *testing.T, c BackupDestinationCheck) string {
	t.Helper()
	var buf bytes.Buffer
	if err := BackupDestinationCheckResult(c).Render(context.Background(), &buf); err != nil {
		t.Fatalf("render: %v", err)
	}
	return buf.String()
}

func TestBackupDestinationCheckResultFragment(t *testing.T) {
	cases := []struct {
		check              BackupDestinationCheck
		class, role, title string
		gotoStep           string
	}{
		{BackupDestinationCheck{Result: "ok"}, "alert alert-success", "status", "Connected.", ""},
		{BackupDestinationCheck{Result: "auth"}, "alert alert-danger", "alert", "Keys rejected.", "3"},
		{BackupDestinationCheck{Result: "bucket"}, "alert alert-danger", "alert", "Bucket not found.", "2"},
		{BackupDestinationCheck{Result: "network"}, "alert alert-danger", "alert", "Endpoint unreachable.", "2"},
		{BackupDestinationCheck{Result: "error"}, "alert alert-danger", "alert", "Unexpected response.", "2"},
		{BackupDestinationCheck{Result: "invalid", Field: "bucket", Error: "bucket must be 3-63 lowercase letters"}, "alert alert-danger", "alert", "Check the destination.", "2"},
		{BackupDestinationCheck{Result: "invalid", Field: "secret_access_key", Error: "secret access key must be 1-256 printable characters without spaces"}, "alert alert-danger", "alert", "Check the destination.", "3"},
	}
	for _, tc := range cases {
		t.Run(tc.check.Result+tc.check.Field, func(t *testing.T) {
			body := renderCheckResultForTest(t, tc.check)
			for _, marker := range []string{`class="` + tc.class + `"`, `role="` + tc.role + `"`, `data-check-result="` + tc.check.Result + `"`, tc.title, "saved"} {
				if !strings.Contains(body, marker) {
					t.Fatalf("expected %q, body=%q", marker, body)
				}
			}
			if tc.check.Error != "" && !strings.Contains(body, tc.check.Error) {
				t.Fatalf("the validation reason must be shown, body=%q", body)
			}
			if tc.gotoStep != "" && !strings.Contains(body, `href="#backup-wizard-step-`+tc.gotoStep+`" data-wizard-goto="`+tc.gotoStep+`"`) {
				t.Fatalf("expected a link back to step %s, body=%q", tc.gotoStep, body)
			}
			if strings.Contains(body, "<html") || strings.Contains(body, "<form") {
				t.Fatalf("the result is a fragment, body=%q", body)
			}
		})
	}
	if body := renderCheckResultForTest(t, BackupDestinationCheck{Result: "<b>forged</b>"}); strings.TrimSpace(body) != "" {
		t.Fatalf("an unknown result renders nothing, got %q", body)
	}
}

func TestBackupWizardScriptIsSelfContained(t *testing.T) {
	raw, err := fs.ReadFile(StaticFS, "static/backups-wizard.js")
	if err != nil {
		t.Fatalf("the wizard script must be embedded: %v", err)
	}
	script := string(raw)
	for _, marker := range []string{"data-backup-wizard", "aria-current", "prefers-reduced-motion", ".focus(", "backup-wizard-check", "noValidate", "reportValidity", "data-provider-hint", "selectedIndex"} {
		if !strings.Contains(script, marker) {
			t.Fatalf("the wizard script misses %q", marker)
		}
	}
	for _, forbidden := range []string{"http://", "https://", "eval(", "innerHTML", "secret_access_key\"].value", "localStorage", "sessionStorage"} {
		if strings.Contains(script, forbidden) {
			t.Fatalf("the wizard script must not contain %q", forbidden)
		}
	}
}
