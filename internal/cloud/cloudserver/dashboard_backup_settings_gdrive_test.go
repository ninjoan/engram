package cloudserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"io"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/gdrive"
)

const (
	testPublicURL           = "https://engram.example.test"
	testGDriveCallbackURI   = testPublicURL + "/dashboard/admin/backups/gdrive/callback"
	backupGDriveConnectPath = "/dashboard/admin/backups/gdrive/connect"
	backupGDriveCallback    = "/dashboard/admin/backups/gdrive/callback"

	testGDriveClientID     = "123456789012-dashboard.apps.googleusercontent.com"
	testGDriveClientSecret = "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r-render"
	testGDriveRefreshToken = "1//dashboard-refresh-token-never-render"
	testGDriveCode         = "4/dashboard-authorization-code-never-log"
)

func gdriveForm(overrides map[string]string) string {
	v := url.Values{
		"kind":          {"gdrive"},
		"client_id":     {testGDriveClientID},
		"client_secret": {testGDriveClientSecret},
		"folder":        {"Engram backups"},
	}
	for k, val := range overrides {
		if val == "" {
			v.Del(k)
			continue
		}
		v.Set(k, val)
	}
	return v.Encode()
}

var validGDriveForm = gdriveForm(nil)

// pendingGDriveSettings is a saved Google Drive destination awaiting its
// "Connect with Google" authorization.
func pendingGDriveSettings() *fakeBackupSettingsStore {
	settings := configuredBackupSettings()
	settings.destination = cloudstore.BackupDestination{Configured: true, Kind: cloudstore.BackupDestinationKindGDrive, GDrive: cloudstore.GDriveDestinationView{ClientID: testGDriveClientID, FolderName: "Engram backups"}}
	settings.creds = cloudstore.BackupDestinationCredentials{}
	settings.gdriveCreds = cloudstore.GDriveDestinationCredentials{ClientID: testGDriveClientID, FolderName: "Engram backups", ClientSecret: testGDriveClientSecret}
	settings.bindingVersion = 1
	return settings
}

func authorizedGDriveSettings() *fakeBackupSettingsStore {
	settings := pendingGDriveSettings()
	settings.destination.GDrive.Authorized = true
	settings.gdriveCreds.RefreshToken = testGDriveRefreshToken
	return settings
}

func gdriveBackupFixture(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture {
	t.Helper()
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	return wireBackupFixture(t, srv, audit, cookie, settings)
}

// fakeGDriveChecker is the Google Drive access check of the test route; it
// never reaches the network.
type fakeGDriveChecker struct {
	calls       int
	err         error
	creds       cloudstore.GDriveDestinationCredentials
	hadDeadline bool
}

func (f *fakeGDriveChecker) check(ctx context.Context, creds cloudstore.GDriveDestinationCredentials) error {
	f.calls++
	f.creds = creds
	_, f.hadDeadline = ctx.Deadline()
	return f.err
}

// fakeGoogle is the HTTP transport of every Google request the server makes
// in tests: it records each request and answers the token endpoint.
type fakeGoogle struct {
	mu       sync.Mutex
	requests []fakeGoogleRequest
	status   int
	body     string
	err      error
}

type fakeGoogleRequest struct {
	url  string
	form url.Values
}

func newFakeGoogle() *fakeGoogle {
	return &fakeGoogle{status: http.StatusOK, body: `{"access_token":"ya29.access-token-never-render","expires_in":3599,"refresh_token":"` + testGDriveRefreshToken + `","scope":"` + gdrive.Scope + `","token_type":"Bearer"}`}
}

func (g *fakeGoogle) RoundTrip(r *http.Request) (*http.Response, error) {
	body := []byte{}
	if r.Body != nil {
		body, _ = io.ReadAll(r.Body)
		_ = r.Body.Close()
	}
	form, _ := url.ParseQuery(string(body))
	g.mu.Lock()
	defer g.mu.Unlock()
	g.requests = append(g.requests, fakeGoogleRequest{url: r.URL.String(), form: form})
	if g.err != nil {
		return nil, g.err
	}
	return &http.Response{StatusCode: g.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(g.body)), Request: r}, nil
}

func (g *fakeGoogle) hits() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return len(g.requests)
}

// gdriveSecrets are the values that must never reach HTML, a URL the
// server redirects to (other than Google's consent URL), audit rows or logs.
func gdriveSecrets(extra ...string) []string {
	return append([]string{testGDriveClientSecret, testGDriveRefreshToken, testGDriveCode, "ya29.access-token-never-render"}, extra...)
}

func assertNoGDriveSecret(t *testing.T, label, text string, extra ...string) {
	t.Helper()
	for _, secret := range gdriveSecrets(extra...) {
		if secret != "" && strings.Contains(text, secret) {
			t.Fatalf("%s leaked %q: %q", label, secret, text)
		}
	}
}

func assertNoGDriveSecretInAudit(t *testing.T, f backupSettingsFixture, extra ...string) {
	t.Helper()
	f.audit.auditMu.Lock()
	defer f.audit.auditMu.Unlock()
	for _, ev := range f.audit.auditEvents {
		text := ev.Action + " " + ev.ReasonCode + " " + fmtAny(ev.Metadata)
		assertNoGDriveSecret(t, "audit", text, extra...)
		if strings.Contains(text, testGDriveClientID) {
			t.Fatalf("audit holds the full client id: %s", text)
		}
	}
}

func captureLogs(t *testing.T) *bytes.Buffer {
	t.Helper()
	var logs bytes.Buffer
	original := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(original) })
	return &logs
}

// connectGDrive starts the authorization and returns the consent URL the
// server redirected to.
func connectGDrive(t *testing.T, f backupSettingsFixture) *url.URL {
	t.Helper()
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("connect = %d body=%q", rec.Code, rec.Body.String())
	}
	consent, err := url.Parse(rec.Header().Get("Location"))
	if err != nil {
		t.Fatalf("consent URL: %v", err)
	}
	return consent
}

func gdriveCallbackRequest(f backupSettingsFixture, query url.Values, cookie *http.Cookie, headers map[string]string) *httptest.ResponseRecorder {
	return doBackupRequest(f.srv, backupRequest{method: http.MethodGet, path: backupGDriveCallback + "?" + query.Encode(), cookie: cookie, headers: headers})
}

func assertCallbackHeaders(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("callback headers = %v", rec.Header())
	}
}

// S15/S7: kind=gdrive saves the OAuth client (pending authorization) with
// the backup key; no other kind is written, nothing reaches Google, and the
// page shows the pending status card with Connect with Google.
func TestDashboardSaveGDriveDestination(t *testing.T) {
	f := emptyBackupFixture(t)
	logs := captureLogs(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validGDriveForm, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=destination-saved" {
		t.Fatalf("save = %d %q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	if len(f.settings.putGDrive) != 1 || len(f.settings.putDestination) != 0 || len(f.settings.putDropbox) != 0 {
		t.Fatalf("writes: gdrive %d s3 %d dropbox %d", len(f.settings.putGDrive), len(f.settings.putDestination), len(f.settings.putDropbox))
	}
	p := f.settings.putGDrive[0]
	if p.ClientID != testGDriveClientID || p.ClientSecret != testGDriveClientSecret || p.FolderName != "Engram backups" || p.Actor.PrincipalID != "p-admin" || f.settings.putSealers[0] == nil {
		t.Fatalf("params = %+v", p)
	}
	if f.google.hits() != 0 || f.gdrive.calls != 0 {
		t.Fatalf("save reached Google: %d requests, %d checks", f.google.hits(), f.gdrive.calls)
	}
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	for _, marker := range []string{"Backup destination saved.", "Google Drive <span", "Not connected", "<dd><code>****.com</code></dd>", `action="/dashboard/admin/backups/gdrive/connect"`, "Connect with Google"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("saved page lacks %q, body=%q", marker, page)
		}
	}
	if strings.Contains(page, testGDriveClientID) {
		t.Fatalf("page shows the full client id")
	}
	assertNoGDriveSecret(t, "saved page", page)
	assertNoGDriveSecret(t, "logs", logs.String())
}

// The client secret is required on every save and never re-rendered; a
// refusal re-renders the client id and folder and marks the failing field.
func TestDashboardSaveGDriveDestinationRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		form, field string
	}{
		"no secret":     {gdriveForm(map[string]string{"client_secret": ""}), "client_secret"},
		"bad client id": {gdriveForm(map[string]string{"client_id": "has space"}), "client_id"},
		"bad folder":    {gdriveForm(map[string]string{"folder": "a/b"}), "folder"},
	} {
		t.Run(name, func(t *testing.T) {
			f := emptyBackupFixture(t)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: tc.form, cookie: f.cookie})
			body := rec.Body.String()
			if rec.Code != http.StatusBadRequest || !strings.Contains(body, "Destination not saved") || !strings.Contains(body, "backup-gdrive-form") {
				t.Fatalf("refusal = %d body=%q", rec.Code, body)
			}
			if !strings.Contains(dropboxInputTag(t, body, tc.field), `aria-invalid="true"`) {
				t.Fatalf("%s not marked invalid, body=%q", tc.field, body)
			}
			if !strings.Contains(dropboxInputTag(t, body, "client_secret"), `value=""`) {
				t.Fatalf("client secret re-rendered with a value")
			}
			assertNoGDriveSecret(t, "refusal", body)
			if f.settings.destination.Configured || backupAuditCount(f.audit) != 0 || f.google.hits() != 0 {
				t.Fatalf("refused save stored, audited or reached Google")
			}
		})
	}
}

// There is no check-before-save for Google Drive: the check route explains
// that it needs Connect with Google and touches nothing.
func TestDashboardCheckGDriveDestinationExplainsConnect(t *testing.T) {
	f := emptyBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validGDriveForm, cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "Connect with Google, then Test connection") {
		t.Fatalf("gdrive check = %d body=%q", rec.Code, body)
	}
	if n := f.settings.mutations(); n != 0 || f.google.hits() != 0 || f.gdrive.calls != 0 || backupAuditCount(f.audit) != 0 {
		t.Fatalf("gdrive check had side effects: store %d google %d checks %d audit %d", n, f.google.hits(), f.gdrive.calls, backupAuditCount(f.audit))
	}
	assertNoGDriveSecret(t, "check", body)
	// A field the save would refuse is already marked.
	invalid := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: gdriveForm(map[string]string{"client_id": "has space"}), cookie: f.cookie})
	if invalid.Code != http.StatusBadRequest || !strings.Contains(dropboxInputTag(t, invalid.Body.String(), "client_id"), `aria-invalid="true"`) {
		t.Fatalf("invalid gdrive check = %d body=%q", invalid.Code, invalid.Body.String())
	}
	if n := f.settings.mutations(); n != 0 || f.google.hits() != 0 || backupAuditCount(f.audit) != 0 {
		t.Fatalf("invalid gdrive check had side effects")
	}
}

// S15: Connect with Google stores a state bound to this admin and the
// destination and redirects to Google's consent screen with the drive.file
// scope only, PKCE S256, offline access and the exact redirect URI built
// from ENGRAM_CLOUD_PUBLIC_URL, never from Host or X-Forwarded headers.
func TestDashboardConnectGDriveRedirectsToGoogle(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	logs := captureLogs(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: f.cookie, headers: map[string]string{"X-Forwarded-Host": "evil.example.test", "X-Forwarded-Proto": "http"}})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("connect = %d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
		t.Fatalf("connect headers = %v", rec.Header())
	}
	consent, err := url.Parse(rec.Header().Get("Location"))
	if err != nil || consent.Scheme != "https" || consent.Host != "accounts.google.com" || consent.Path != "/o/oauth2/v2/auth" {
		t.Fatalf("consent URL = %q (%v)", rec.Header().Get("Location"), err)
	}
	q := consent.Query()
	want := map[string]string{
		"client_id": testGDriveClientID, "redirect_uri": testGDriveCallbackURI, "response_type": "code",
		"scope": gdrive.Scope, "access_type": "offline", "code_challenge_method": "S256", "prompt": "consent",
	}
	for k, v := range want {
		if got := q[k]; len(got) != 1 || got[0] != v {
			t.Fatalf("consent %s = %q, want %q", k, got, v)
		}
	}
	if len(f.settings.oauthStates) != 1 || f.settings.oauthCreates != 1 {
		t.Fatalf("states = %d creates %d", len(f.settings.oauthStates), f.settings.oauthCreates)
	}
	var state string
	var pending fakeOAuthState
	for state, pending = range f.settings.oauthStates {
	}
	sum := sha256.Sum256([]byte(pending.verifier))
	if q.Get("state") != state || pending.principal != "p-admin" || q.Get("code_challenge") != base64.RawURLEncoding.EncodeToString(sum[:]) || len(pending.verifier) != 43 {
		t.Fatalf("state %q / challenge %q do not match the stored state for %q", q.Get("state"), q.Get("code_challenge"), pending.principal)
	}
	events := backupAuditEvents(f.audit, authAuditActionBackupDestinationAuthorizeStart)
	if len(events) != 1 || events[0].Outcome != authAuditOutcomeSuccess || events[0].Metadata["kind"] != "gdrive" || events[0].Metadata["folder_name"] != "Engram backups" || events[0].Metadata["client_id_hint"] != "****.com" {
		t.Fatalf("authorize_start audit = %+v", events)
	}
	assertNoGDriveSecretInAudit(t, f, state, pending.verifier, q.Get("code_challenge"))
	assertNoGDriveSecret(t, "logs", logs.String(), state, pending.verifier)
	if f.google.hits() != 0 || len(f.settings.gdriveTokens) != 0 {
		t.Fatalf("connect reached Google (%d) or stored a token", f.google.hits())
	}
}

// Connect needs ENGRAM_CLOUD_PUBLIC_URL and a stored Google Drive
// destination; otherwise it explains why and writes nothing.
func TestDashboardConnectGDriveRefusals(t *testing.T) {
	for name, tc := range map[string]struct {
		settings *fakeBackupSettingsStore
		public   string
		text     string
	}{
		"no public URL":  {pendingGDriveSettings(), "", "ENGRAM_CLOUD_PUBLIC_URL"},
		"s3 destination": {configuredBackupSettings(), testPublicURL, "Save the Google Drive settings first"},
		"no destination": {&fakeBackupSettingsStore{}, testPublicURL, "Save the Google Drive settings first"},
	} {
		t.Run(name, func(t *testing.T) {
			f := gdriveBackupFixture(t, tc.settings)
			WithPublicURL(tc.public)(f.srv)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: f.cookie})
			if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), tc.text) {
				t.Fatalf("connect = %d body=%q", rec.Code, rec.Body.String())
			}
			if f.settings.oauthCreates != 0 || backupAuditCount(f.audit) != 0 || f.google.hits() != 0 {
				t.Fatalf("refused connect wrote a state (%d), audited (%d) or reached Google (%d)", f.settings.oauthCreates, backupAuditCount(f.audit), f.google.hits())
			}
		})
	}
}

// Without ENGRAM_CLOUD_PUBLIC_URL the Google Drive form and the pending card
// explain the missing setting and render no Connect control; with it the
// form shows the exact redirect URI to register.
func TestDashboardGDrivePageAndPublicURL(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	page := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind=gdrive", f.cookie).Body.String()
	for _, marker := range []string{"backup-gdrive-form", "<code>" + testGDriveCallbackURI + "</code>", backupGDriveConnectPath} {
		if !strings.Contains(page, marker) {
			t.Fatalf("page lacks %q, body=%q", marker, page)
		}
	}
	WithPublicURL("")(f.srv)
	page = performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind=gdrive", f.cookie).Body.String()
	if !strings.Contains(page, "ENGRAM_CLOUD_PUBLIC_URL") || strings.Contains(page, backupGDriveConnectPath) || strings.Contains(page, "/gdrive/callback") {
		t.Fatalf("page without a public URL must explain it and render no Connect control, body=%q", page)
	}
	assertNoGDriveSecret(t, "page", page)
}

// S15/S7: the callback with a valid state exchanges the code at Google's
// token endpoint with the stored client secret, the state's verifier and
// the exact redirect URI, stores the refresh token through the store
// (sealed and audited there) and redirects to the page with a notice. No
// code, state, verifier or token reaches a URL, the page, audit or logs.
func TestDashboardGDriveCallbackStoresTheRefreshToken(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	logs := captureLogs(t)
	consent := connectGDrive(t, f)
	state := consent.Query().Get("state")
	var verifier string
	for _, pending := range f.settings.oauthStates {
		verifier = pending.verifier
	}
	rec := gdriveCallbackRequest(f, url.Values{"state": {state}, "code": {testGDriveCode}, "scope": {gdrive.Scope}}, f.cookie, nil)
	assertCallbackHeaders(t, rec)
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-connected" {
		t.Fatalf("callback = %d %q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	if f.google.hits() != 1 {
		t.Fatalf("google requests = %d, want 1", f.google.hits())
	}
	exchange := f.google.requests[0]
	if !strings.HasPrefix(exchange.url, "https://oauth2.googleapis.com/token") {
		t.Fatalf("exchange went to %q", exchange.url)
	}
	for k, v := range map[string]string{"grant_type": "authorization_code", "code": testGDriveCode, "code_verifier": verifier, "redirect_uri": testGDriveCallbackURI, "client_id": testGDriveClientID, "client_secret": testGDriveClientSecret} {
		if exchange.form.Get(k) != v {
			t.Fatalf("exchange %s = %q, want %q", k, exchange.form.Get(k), v)
		}
	}
	if len(f.settings.gdriveTokens) != 1 {
		t.Fatalf("tokens stored = %d", len(f.settings.gdriveTokens))
	}
	stored := f.settings.gdriveTokens[0]
	if stored.token != testGDriveRefreshToken || stored.sealer == nil || stored.actor.PrincipalID != "p-admin" || stored.actor.Source == "" {
		t.Fatalf("stored token = %+v", stored)
	}
	if len(f.settings.oauthStates) != 0 {
		t.Fatalf("state not consumed")
	}
	page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
	if !strings.Contains(page, "Google Drive connected.") || !strings.Contains(page, `action="/dashboard/admin/backups/destination/test"`) {
		t.Fatalf("connected page, body=%q", page)
	}
	for label, text := range map[string]string{"location": rec.Header().Get("Location"), "body": rec.Body.String(), "page": page, "logs": logs.String()} {
		assertNoGDriveSecret(t, label, text, state, verifier)
	}
	assertNoGDriveSecretInAudit(t, f, state, verifier)
}

// Google's error answers (the admin denied access, or another error) show a
// clear notice, consume nothing, store nothing and call no Google endpoint.
func TestDashboardGDriveCallbackGoogleErrors(t *testing.T) {
	for name, tc := range map[string]struct {
		query  url.Values
		notice string
		text   string
	}{
		"denied":       {url.Values{"error": {"access_denied"}}, "gdrive-denied", "Google access not granted."},
		"server error": {url.Values{"error": {"server_error"}, "error_description": {"<script>x</script>"}}, "gdrive-error", "Google did not complete the authorization."},
	} {
		t.Run(name, func(t *testing.T) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			consent := connectGDrive(t, f)
			tc.query.Set("state", consent.Query().Get("state"))
			creates, audits := f.settings.oauthCreates, backupAuditCount(f.audit)
			rec := gdriveCallbackRequest(f, tc.query, f.cookie, nil)
			assertCallbackHeaders(t, rec)
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("callback = %d %q", rec.Code, dashboardRedirect(rec))
			}
			if f.settings.oauthUsed != 0 || len(f.settings.gdriveTokens) != 0 || f.settings.oauthCreates != creates || backupAuditCount(f.audit) != audits || f.google.hits() != 0 {
				t.Fatalf("an error answer wrote or reached Google")
			}
			page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
			if !strings.Contains(page, tc.text) || strings.Contains(page, "<script>x</script>") {
				t.Fatalf("notice %q missing or Google's text echoed, body=%q", tc.text, page)
			}
		})
	}
}

// A failed code exchange stores no token, consumes the state (codes are
// single use), audits a failure without secrets and explains the cause.
func TestDashboardGDriveCallbackExchangeFailures(t *testing.T) {
	for name, tc := range map[string]struct {
		status int
		body   string
		err    error
		notice string
		reason string
		text   string
	}{
		"invalid grant": {status: http.StatusBadRequest, body: `{"error":"invalid_grant","error_description":"Bad Request"}`, notice: "gdrive-exchange", reason: "exchange_failed", text: "Google refused the authorization."},
		"wrong scope":   {status: http.StatusOK, body: `{"refresh_token":"` + testGDriveRefreshToken + `","scope":"https://www.googleapis.com/auth/drive"}`, notice: "gdrive-scope", reason: "scope", text: "Wrong access granted."},
		"no refresh":    {status: http.StatusOK, body: `{"access_token":"ya29.access-token-never-render","scope":"` + gdrive.Scope + `"}`, notice: "gdrive-no-refresh", reason: "no_refresh_token", text: "No refresh token."},
		"network":       {err: errors.New("dial tcp: connection refused"), notice: "gdrive-exchange", reason: "network", text: "Google refused the authorization."},
	} {
		t.Run(name, func(t *testing.T) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			logs := captureLogs(t)
			f.google.status, f.google.body, f.google.err = tc.status, tc.body, tc.err
			consent := connectGDrive(t, f)
			state := consent.Query().Get("state")
			rec := gdriveCallbackRequest(f, url.Values{"state": {state}, "code": {testGDriveCode}}, f.cookie, nil)
			assertCallbackHeaders(t, rec)
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("callback = %d %q", rec.Code, dashboardRedirect(rec))
			}
			if len(f.settings.gdriveTokens) != 0 || f.settings.oauthUsed != 1 || f.google.hits() != 1 {
				t.Fatalf("tokens %d consumed %d google %d", len(f.settings.gdriveTokens), f.settings.oauthUsed, f.google.hits())
			}
			events := backupAuditEvents(f.audit, cloudstore.AuthAuditActionBackupDestinationAuthorize)
			if len(events) != 1 || events[0].Outcome != authAuditOutcomeFailure || events[0].ReasonCode != tc.reason || events[0].Metadata["kind"] != "gdrive" {
				t.Fatalf("authorize failure audit = %+v", events)
			}
			page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
			if !strings.Contains(page, tc.text) {
				t.Fatalf("notice %q missing, body=%q", tc.text, page)
			}
			for label, text := range map[string]string{"location": rec.Header().Get("Location"), "page": page, "logs": logs.String()} {
				assertNoGDriveSecret(t, label, text, state)
			}
			assertNoGDriveSecretInAudit(t, f, state)
		})
	}
}

// A destination edited after the code was exchanged is not authorized with
// the old client's token.
func TestDashboardGDriveCallbackRefusesADestinationChangedDuringTheExchange(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	consent := connectGDrive(t, f)
	f.google.err = nil
	settings := f.settings
	f.srv.backupGDriveHTTPClient = &http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
		resp, err := f.google.RoundTrip(r)
		settings.mu.Lock()
		settings.bindingVersion++ // saved again while Google answered
		settings.mu.Unlock()
		return resp, err
	})}
	rec := gdriveCallbackRequest(f, url.Values{"state": {consent.Query().Get("state")}, "code": {testGDriveCode}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-mismatch" || len(f.settings.gdriveTokens) != 0 {
		t.Fatalf("callback = %q, tokens %d", dashboardRedirect(rec), len(f.settings.gdriveTokens))
	}
}

// A save that lands after the exchange, right before the token write, is
// caught by the write itself: the binding is compared under the
// destination lock, so no token is stored and the failure is audited.
func TestDashboardGDriveCallbackRefusesADestinationChangedRightBeforeTheTokenWrite(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	consent := connectGDrive(t, f)
	f.google.err = nil
	settings := f.settings
	settings.beforeSetToken = func() {
		settings.mu.Lock()
		settings.bindingVersion++ // saved again between the exchange and the write
		settings.mu.Unlock()
	}
	rec := gdriveCallbackRequest(f, url.Values{"state": {consent.Query().Get("state")}, "code": {testGDriveCode}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-mismatch" {
		t.Fatalf("callback = %q, want gdrive-mismatch", dashboardRedirect(rec))
	}
	if len(settings.gdriveTokens) != 0 || settings.destination.GDrive.Authorized || settings.gdriveCreds.RefreshToken != "" {
		t.Fatalf("a changed destination was authorized: tokens %d, authorized %v", len(settings.gdriveTokens), settings.destination.GDrive.Authorized)
	}
	events := backupAuditEvents(f.audit, cloudstore.AuthAuditActionBackupDestinationAuthorize)
	if len(events) != 1 || events[0].Outcome != authAuditOutcomeFailure || events[0].ReasonCode != backupReasonDestinationChanged {
		t.Fatalf("authorize audits = %+v, want one destination-changed failure", events)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (fn roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) { return fn(r) }

// The test route checks an authorized Google Drive destination with the
// stored credentials (bounded, read-only) and audits the typed result; a
// pending destination is reported without reaching Google.
func TestDashboardTestGDriveDestination(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		notice string
		reason string
		text   string
	}{
		"ok":      {nil, "gdrive-test-ok", "", "Google Drive accepted the stored authorization"},
		"auth":    {&gdrive.Error{Op: "CheckAccess", Kind: gdrive.ErrAuth}, "gdrive-test-auth", "auth_failed", "Authorization rejected."},
		"scope":   {&gdrive.Error{Op: "CheckAccess", Kind: gdrive.ErrScope}, "gdrive-test-auth", "auth_failed", "Authorization rejected."},
		"network": {&gdrive.Error{Op: "CheckAccess", Kind: gdrive.ErrNetwork}, "gdrive-test-network", "network", "Google Drive unreachable."},
		"timeout": {context.DeadlineExceeded, "gdrive-test-network", "network", "Google Drive unreachable."},
		"other":   {&gdrive.Error{Op: "CheckAccess", Kind: gdrive.ErrUnexpected}, "gdrive-test-error", "unexpected_response", "Unexpected response."},
	} {
		t.Run(name, func(t *testing.T) {
			f := gdriveBackupFixture(t, authorizedGDriveSettings())
			f.gdrive.err = tc.err
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("test = %d %q", rec.Code, dashboardRedirect(rec))
			}
			if f.gdrive.calls != 1 || !f.gdrive.hadDeadline || f.gdrive.creds.RefreshToken != testGDriveRefreshToken {
				t.Fatalf("check calls %d deadline %v creds %v", f.gdrive.calls, f.gdrive.hadDeadline, f.gdrive.creds)
			}
			events := backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)
			if len(events) != 1 || events[0].ReasonCode != tc.reason || events[0].Metadata["kind"] != "gdrive" || events[0].Metadata["folder_name"] != "Engram backups" {
				t.Fatalf("test audit = %+v", events)
			}
			assertNoGDriveSecretInAudit(t, f)
			page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
			if !strings.Contains(page, tc.text) {
				t.Fatalf("notice %q missing, body=%q", tc.text, page)
			}
			assertNoGDriveSecret(t, "test page", page)
		})
	}
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-test-pending" || f.gdrive.calls != 0 || f.google.hits() != 0 {
		t.Fatalf("pending test = %q calls %d google %d", dashboardRedirect(rec), f.gdrive.calls, f.google.hits())
	}
	events := backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)
	if len(events) != 1 || events[0].ReasonCode != "not_authorized" {
		t.Fatalf("pending test audit = %+v", events)
	}
}

// The real Drive check is the one the test route uses without a seam: it
// goes through backupGDriveHTTPClient, so the refusal matrices prove a real
// absence of requests.
func TestDashboardTestGDriveRealCheckUsesTheTransport(t *testing.T) {
	f := gdriveBackupFixture(t, authorizedGDriveSettings())
	f.srv.backupCheckGDrive = nil
	f.google.status, f.google.body = http.StatusBadRequest, `{"error":"invalid_grant","error_description":"Token has been expired or revoked."}`
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || f.google.hits() == 0 || dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-test-auth" {
		t.Fatalf("real check = %d %q with %d requests", rec.Code, dashboardRedirect(rec), f.google.hits())
	}
	if refresh := f.google.requests[0]; !strings.HasPrefix(refresh.url, "https://oauth2.googleapis.com/token") || refresh.form.Get("refresh_token") != testGDriveRefreshToken {
		t.Fatalf("real check did not refresh the stored token: %+v", refresh.url)
	}
}

// A stored Google Drive destination renders its status card; Change
// destination offers the Google Drive form, and Remove works like any
// destination.
func TestDashboardGDriveDestinationCard(t *testing.T) {
	f := gdriveBackupFixture(t, authorizedGDriveSettings())
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie).Body.String()
	for _, marker := range []string{"Google Drive <span", "Not tested", "Engram backups/", "<dt>Client ID</dt><dd><code>****.com</code></dd>", "Reconnect with Google", `action="/dashboard/admin/backups/destination/remove"`, "backup-gdrive-form"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("card lacks %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, testGDriveClientID) || strings.Contains(body, "cannot edit or test this kind") {
		t.Fatalf("card shows the full client id or the old unsupported notice, body=%q", body)
	}
	assertNoGDriveSecret(t, "card", body)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || len(f.settings.clears) != 1 {
		t.Fatalf("remove = %d clears %d", rec.Code, len(f.settings.clears))
	}
}

// Each callback notice is a fixed text; an unknown notice renders nothing.
func TestDashboardGDriveCallbackNotices(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	for notice, text := range map[string]string{
		"gdrive-expired":  "Authorization link expired or already used.",
		"gdrive-mismatch": "Authorization does not match.",
		"gdrive-key":      "Authorization cannot be completed.",
	} {
		page := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice="+notice, f.cookie).Body.String()
		if !strings.Contains(page, text) {
			t.Fatalf("notice %s lacks %q, body=%q", notice, text, page)
		}
	}
}
