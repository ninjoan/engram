package cloudserver

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

// emptyBackupFixture is a managed admin with the backup key set and no
// destination: the state that renders the guided setup.
func emptyBackupFixture(t *testing.T) backupSettingsFixture {
	t.Helper()
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	return wireBackupFixture(t, srv, audit, cookie, &fakeBackupSettingsStore{})
}

// assertCheckStoredNothing proves a check neither stored, opened nor
// changed anything and recorded only its own audit event.
func assertCheckStoredNothing(t *testing.T, f backupSettingsFixture) {
	t.Helper()
	if n := f.settings.mutations(); n != 0 {
		t.Fatalf("a check must store nothing, settings store touched %d times", n)
	}
	if f.settings.destination.Configured {
		t.Fatal("a check must not configure a destination")
	}
	if len(f.runner.calls) != 0 || f.exporter.calls != 0 {
		t.Fatalf("a check must not run or export a backup: runs=%d exports=%d", len(f.runner.calls), f.exporter.calls)
	}
	if got, checks := backupAuditCount(f.audit), len(backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck)); got != checks || checks != 1 {
		t.Fatalf("expected exactly one backup.destination.check audit and no other backup audit, got %d backup audits (%d checks)", got, checks)
	}
}

func assertNoCredentialIn(t *testing.T, label, text string) {
	t.Helper()
	for _, secret := range []string{testBackupSecret, testBackupAccessKeyID} {
		if strings.Contains(text, secret) {
			t.Fatalf("%s leaks a credential: %q", label, text)
		}
	}
}

func TestDashboardCheckBackupDestinationMapsResults(t *testing.T) {
	cases := []struct {
		name     string
		checkErr error
		result   string
		outcome  string
		reason   string
		title    string
	}{
		{name: "ok", result: "ok", outcome: authAuditOutcomeSuccess, title: "Connected."},
		{name: "auth", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrAuth, StatusCode: 403}, result: "auth", outcome: authAuditOutcomeFailure, reason: "auth_failed", title: "Keys rejected."},
		{name: "bucket", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrBucketNotFound, StatusCode: 404}, result: "bucket", outcome: authAuditOutcomeFailure, reason: "bucket_not_found", title: "Bucket not found."},
		{name: "network", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrNetwork}, result: "network", outcome: authAuditOutcomeFailure, reason: "network", title: "Endpoint unreachable."},
		{name: "deadline", checkErr: context.DeadlineExceeded, result: "network", outcome: authAuditOutcomeFailure, reason: "network", title: "Endpoint unreachable."},
		{name: "unexpected", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrUnexpectedStatus, StatusCode: 500}, result: "error", outcome: authAuditOutcomeFailure, reason: "unexpected_response", title: "Unexpected response."},
	}
	for _, tc := range cases {
		for _, htmx := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/htmx=%v", tc.name, htmx), func(t *testing.T) {
				f := emptyBackupFixture(t)
				f.checker.err = tc.checkErr
				form := url.Values{
					"provider": {"r2"}, "endpoint": {" https://acct.r2.cloudflarestorage.com/ "}, "region": {"auto"}, "bucket": {"engram-backups"}, "prefix": {"prod/"},
					"access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret},
				}.Encode()
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: form, cookie: f.cookie, htmx: htmx, headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}})
				body := rec.Body.String()
				if rec.Code != http.StatusOK {
					t.Fatalf("expected 200, got %d body=%q", rec.Code, body)
				}
				if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("HX-Redirect") != "" || rec.Header().Get("Location") != "" {
					t.Fatalf("a check answers in place with no-store, headers=%v", rec.Header())
				}
				if !strings.Contains(body, tc.title) || !strings.Contains(body, `data-check-result="`+tc.result+`"`) {
					t.Fatalf("expected result %s (%s), body=%q", tc.result, tc.title, body)
				}
				if htmx == strings.Contains(strings.ToLower(body), "<!doctype html>") {
					t.Fatalf("HTMX gets a fragment, a plain post the full page (htmx=%v), body=%q", htmx, body)
				}
				if !htmx && (!strings.Contains(body, "data-backup-wizard") || !strings.Contains(body, `data-wizard-start="4"`)) {
					t.Fatalf("the full page re-renders the wizard at step 4, body=%q", body)
				}
				assertNoCredentialIn(t, "check response", body)
				if f.checker.calls != 1 || !f.checker.hadDeadline {
					t.Fatalf("expected one bounded check, calls=%d deadline=%v", f.checker.calls, f.checker.hadDeadline)
				}
				want := cloudstore.BackupDestinationCredentials{Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/", AccessKeyID: testBackupAccessKeyID, SecretAccessKey: testBackupSecret}
				if f.checker.creds != want {
					t.Fatalf("the check must use the validated, normalized form fields, got %v", f.checker.creds)
				}
				assertCheckStoredNothing(t, f)
				event := backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck)[0]
				if event.Outcome != tc.outcome || event.ReasonCode != tc.reason || event.ActorPrincipalID != "p-admin" || event.Metadata["result"] != tc.result {
					t.Fatalf("unexpected check audit: %+v", event)
				}
				if event.Metadata["endpoint"] != "https://acct.r2.cloudflarestorage.com" || event.Metadata["bucket"] != "engram-backups" {
					t.Fatalf("the check audit records the endpoint and bucket, got %+v", event.Metadata)
				}
				assertNoCredentialIn(t, "check audit", fmt.Sprintf("%+v", event))
				if n := len(backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)); n != 0 {
					t.Fatalf("a check before saving must not count as a test of the stored destination, got %d", n)
				}
			})
		}
	}
}

func TestDashboardCheckBackupDestinationValidationNamesTheField(t *testing.T) {
	cases := []struct {
		name, field, value, reasonPart, step string
	}{
		{"bucket", "bucket", "Engram_Bad", "bucket must be 3-63 lowercase letters", "2"},
		{"remote http endpoint", "endpoint", "http://acct.r2.cloudflarestorage.com", "endpoint must be an https origin", "2"},
		{"secret", "secret_access_key", "has space", "secret access key must be 1-256 printable characters", "3"},
	}
	for _, tc := range cases {
		for _, htmx := range []bool{true, false} {
			t.Run(fmt.Sprintf("%s/htmx=%v", tc.name, htmx), func(t *testing.T) {
				f := emptyBackupFixture(t)
				form := submittedBackupDestinationForm("https://s3.us-east-1.amazonaws.com")
				form.Set(tc.field, tc.value)
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: form.Encode(), cookie: f.cookie, htmx: htmx})
				body := rec.Body.String()
				wantStatus := http.StatusBadRequest
				if htmx {
					wantStatus = http.StatusOK
				}
				if rec.Code != wantStatus || !strings.Contains(body, tc.reasonPart) || !strings.Contains(body, `data-check-result="invalid"`) {
					t.Fatalf("expected %d with the reason, got %d body=%q", wantStatus, rec.Code, body)
				}
				if !strings.Contains(body, `data-wizard-goto="`+tc.step+`"`) {
					t.Fatalf("the result must link back to step %s, body=%q", tc.step, body)
				}
				if !htmx {
					tag := backupFormInputTag(t, body, tc.field)
					if !strings.Contains(tag, `aria-invalid="true"`) || !strings.Contains(body, `data-wizard-start="`+tc.step+`"`) {
						t.Fatalf("the full page marks %s and opens step %s, tag=%q", tc.field, tc.step, tag)
					}
					if !strings.Contains(backupFormInputTag(t, body, "bucket"), `value="`+form.Get("bucket")+`"`) || !strings.Contains(backupFormInputTag(t, body, "access_key_id"), `value=""`) {
						t.Fatalf("the full page keeps the non-secret values and empties the keys, body=%q", body)
					}
					if strings.Contains(body, "Destination not saved.") {
						t.Fatal("a check is not a refused save")
					}
				}
				assertNoCredentialIn(t, "validation response", body)
				if f.checker.calls != 0 {
					t.Fatalf("an invalid destination must not be contacted, calls=%d", f.checker.calls)
				}
				assertCheckStoredNothing(t, f)
				event := backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck)[0]
				if event.Outcome != authAuditOutcomeFailure || event.ReasonCode != "invalid_destination" || event.Metadata["result"] != "invalid" || event.Metadata["field"] != tc.field {
					t.Fatalf("unexpected validation audit: %+v", event)
				}
				if _, ok := event.Metadata["endpoint"]; ok {
					t.Fatalf("an unvalidated endpoint must not be audited: %+v", event.Metadata)
				}
				assertNoCredentialIn(t, "validation audit", fmt.Sprintf("%+v", event))
			})
		}
	}
}

func TestDashboardCheckBackupDestinationNeverEchoesUserinfo(t *testing.T) {
	f := emptyBackupFixture(t)
	form := submittedBackupDestinationForm("https://AKIAUSERINFO99:hunter2pass@s3.us-east-1.amazonaws.com")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: form.Encode(), cookie: f.cookie})
	body := rec.Body.String()
	event := fmt.Sprintf("%+v", backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck))
	for _, leaked := range []string{"AKIAUSERINFO99", "hunter2pass"} {
		if strings.Contains(body, leaked) || strings.Contains(event, leaked) {
			t.Fatalf("userinfo %q echoed, status=%d", leaked, rec.Code)
		}
	}
	if rec.Code != http.StatusBadRequest || f.checker.calls != 0 {
		t.Fatalf("expected 400 without contacting the endpoint, got %d calls=%d", rec.Code, f.checker.calls)
	}
}

func TestDashboardCheckBackupDestinationReadsOnlyURLEncodedBodyFields(t *testing.T) {
	f := emptyBackupFixture(t)
	path := backupDestinationCheckPath + "?access_key_id=" + testBackupAccessKeyID + "&secret_access_key=" + testBackupSecret
	form := url.Values{"endpoint": {"https://acct.r2.cloudflarestorage.com"}, "region": {"auto"}, "bucket": {"engram-backups"}}.Encode()
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: form, cookie: f.cookie, htmx: true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "access key id must be") || f.checker.calls != 0 {
		t.Fatalf("credentials in the URL must be ignored, got %d calls=%d body=%q", rec.Code, f.checker.calls, rec.Body.String())
	}
	json := `{"Endpoint":"https://acct.r2.cloudflarestorage.com","Region":"auto","Bucket":"engram-backups","AccessKeyID":"` + testBackupAccessKeyID + `","SecretAccessKey":"` + testBackupSecret + `"}`
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: json, ctype: "application/json", cookie: f.cookie, htmx: true})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "endpoint must be an https origin") || f.checker.calls != 0 {
		t.Fatalf("a JSON body must not be decoded, got %d calls=%d body=%q", rec.Code, f.checker.calls, rec.Body.String())
	}
	assertNoCredentialIn(t, "JSON check", rec.Body.String())
	if n := f.settings.mutations(); n != 0 {
		t.Fatalf("store touched %d times", n)
	}
}

func TestDashboardCheckBackupDestinationAuditFailureHidesResult(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	f := emptyBackupFixture(t)
	f.audit.auditErr = fmt.Errorf("audit down")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validBackupDestinationForm, cookie: f.cookie, htmx: true})
	body := rec.Body.String()
	if rec.Code != http.StatusInternalServerError || strings.Contains(body, "audit down") || strings.Contains(body, "Connected.") {
		t.Fatalf("expected a generic 500 without the result, got %d body=%q", rec.Code, body)
	}
	assertNoCredentialIn(t, "logs", logs.String())
}

func TestDashboardCheckBackupDestinationWithoutKeyRefuses(t *testing.T) {
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	settings := &fakeBackupSettingsStore{}
	WithBackupSettings(settings, nil)(srv)
	checker := &fakeBackupChecker{}
	srv.backupCheckAccess = checker.check
	rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validBackupDestinationForm, cookie: cookie})
	if rec.Code != http.StatusConflict || checker.calls != 0 || backupAuditCount(audit) != 0 || settings.mutations() != 0 {
		t.Fatalf("without the key the check must refuse with no side effect, got %d calls=%d audits=%d", rec.Code, checker.calls, backupAuditCount(audit))
	}
}

// The real access check: a refused request makes no outbound request; an
// allowed one reaches the endpoint and never follows a redirect.
func TestDashboardCheckBackupDestinationOutboundOnlyForAllowedRequests(t *testing.T) {
	var hits, stolen atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { stolen.Add(1); w.WriteHeader(http.StatusOK) }))
	defer target.Close()
	endpoint := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.Path, "redirected-bucket") {
			http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
			return
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer endpoint.Close()
	form := func(bucket string) string {
		return url.Values{"endpoint": {endpoint.URL}, "region": {"auto"}, "bucket": {bucket}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
	}
	realChecker := func(f backupSettingsFixture) backupSettingsFixture {
		f.srv.backupCheckAccess = nil
		return f
	}

	refusals := []struct {
		name    string
		fixture func(t *testing.T) backupSettingsFixture
		method  string
		headers map[string]string
	}{
		{"member", func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := memberDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, &fakeBackupSettingsStore{})
		}, http.MethodPost, nil},
		{"legacy admin", func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := legacyAdminDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, &fakeBackupSettingsStore{})
		}, http.MethodPost, nil},
		{"cross-origin", emptyBackupFixture, http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.test"}},
		{"GET", emptyBackupFixture, http.MethodGet, nil},
	}
	for _, tc := range refusals {
		f := realChecker(tc.fixture(t))
		rec := doBackupRequest(f.srv, backupRequest{method: tc.method, path: backupDestinationCheckPath, form: form("engram-backups"), headers: tc.headers, cookie: f.cookie})
		if rec.Code < 400 || hits.Load() != 0 || backupAuditCount(f.audit) != 0 {
			t.Fatalf("%s: expected a refusal with no outbound request, got %d hits=%d audits=%d", tc.name, rec.Code, hits.Load(), backupAuditCount(f.audit))
		}
		assertNoCredentialIn(t, tc.name, rec.Body.String())
	}

	f := realChecker(emptyBackupFixture(t))
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: form("engram-backups"), cookie: f.cookie, htmx: true})
	if rec.Code != http.StatusOK || hits.Load() != 1 || !strings.Contains(rec.Body.String(), `data-check-result="ok"`) {
		t.Fatalf("an allowed check reaches the endpoint once, got %d hits=%d body=%q", rec.Code, hits.Load(), rec.Body.String())
	}
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: form("redirected-bucket"), cookie: f.cookie, htmx: true})
	if stolen.Load() != 0 || strings.Contains(rec.Body.String(), `data-check-result="ok"`) {
		t.Fatalf("a redirect must not be followed or reported as ok, stolen=%d body=%q", stolen.Load(), rec.Body.String())
	}
}

func TestDashboardBackupsPageEmptyStateRendersTheGuidedSetup(t *testing.T) {
	f := emptyBackupFixture(t)
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie).Body.String()
	for _, marker := range []string{"data-backup-wizard", `<script src="/dashboard/static/backups-wizard.js" defer></script>`, `hx-post="/dashboard/admin/backups/destination/check"`, "Step 4 of 4 · Test &amp; save"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected %q on the empty page, body=%q", marker, body)
		}
	}
	cf := managedBackupFixture(t)
	configured := performDashboardRequest(cf.srv, http.MethodGet, backupsPagePath, cf.cookie).Body.String()
	if strings.Contains(configured, "data-backup-wizard") || strings.Contains(configured, "backups-wizard.js") {
		t.Fatal("a configured destination must not render the wizard")
	}
	static := performDashboardRequest(f.srv, http.MethodGet, "/dashboard/static/backups-wizard.js", nil)
	if static.Code != http.StatusOK || !strings.Contains(static.Body.String(), "data-backup-wizard") {
		t.Fatalf("the wizard script must be served, got %d", static.Code)
	}
}

func TestDashboardCheckBackupDestinationPostgres(t *testing.T) {
	cs := openBackupDownloadTestStore(t)
	ctx := context.Background()
	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	principal := dashboardManagedPrincipal(admin.PrincipalID, cloudstore.PrincipalRoleAdmin, true)
	srv := New(cs, resolvingAuth{principals: map[string]cloudauth.Principal{"admin-token": principal}}, 0, WithAdminIdentityStore(cs), WithBackupSettings(cs, testBackupKey(t)))
	checker := &fakeBackupChecker{err: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrAuth, StatusCode: 403}}
	srv.backupCheckAccess = checker.check
	cookie := managedDashboardLogin(t, srv, "admin-token", false)
	rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validBackupDestinationForm, cookie: cookie, htmx: true, headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}})
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "Keys rejected.") || checker.calls != 1 {
		t.Fatalf("check = %d calls=%d body=%q", rec.Code, checker.calls, rec.Body.String())
	}
	if destination, err := cs.GetBackupDestination(ctx); err != nil || destination.Configured {
		t.Fatalf("a check must store nothing, got %+v err=%v", destination, err)
	}
	events, err := cs.ListAuthAuditEvents(ctx, cloudstore.AuthAuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	checks := 0
	for _, event := range events {
		if strings.HasPrefix(event.Action, "backup.") && event.Action != authAuditActionBackupDestinationCheck {
			t.Fatalf("a check recorded %s", event.Action)
		}
		if event.Action == authAuditActionBackupDestinationCheck {
			checks++
			if event.Outcome != authAuditOutcomeFailure || event.ReasonCode != "auth_failed" || event.Metadata["result"] != "auth" {
				t.Fatalf("unexpected check audit %+v", event)
			}
		}
		assertNoCredentialIn(t, "audit "+event.Action, fmt.Sprintf("%+v", event.Metadata))
	}
	if checks != 1 {
		t.Fatalf("expected one backup.destination.check, got %d", checks)
	}
}
