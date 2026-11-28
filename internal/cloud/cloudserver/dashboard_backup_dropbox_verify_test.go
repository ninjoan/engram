package cloudserver

import (
	"bytes"
	"io"
	"log"
	"mime/multipart"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
)

const echoedDropboxAccessToken = "sl.ECHOEDACCESSTOKENLEAK0123456789"

// echoDropbox answers the Dropbox endpoints in-process, echoing every
// credential it receives (request body, Authorization header) in its error
// bodies; it never touches the network.
type echoDropbox struct {
	hits      atomic.Int32
	tokenCode int    // status of /oauth2/token
	metaCode  int    // status of get_metadata
	metaBody  string // body template; {ECHO} replaced
}

func (e *echoDropbox) RoundTrip(r *http.Request) (*http.Response, error) {
	e.hits.Add(1)
	body, _ := io.ReadAll(r.Body)
	echo := string(body) + " auth=" + r.Header.Get("Authorization") + " secret=" + testDropboxAppSecret + " refresh=" + testDropboxRefreshToken + " access=" + echoedDropboxAccessToken
	resp := func(code int, s string) *http.Response {
		return &http.Response{StatusCode: code, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(s)), Request: r}
	}
	if strings.HasSuffix(r.URL.Path, "/oauth2/token") {
		if e.tokenCode != 200 {
			return resp(e.tokenCode, `{"error":"invalid_grant","error_description":"`+jsonEsc(echo)+`"}`), nil
		}
		return resp(200, `{"access_token":"`+echoedDropboxAccessToken+`","token_type":"bearer","expires_in":14400}`), nil
	}
	return resp(e.metaCode, strings.ReplaceAll(e.metaBody, "{ECHO}", jsonEsc(echo))), nil
}

func jsonEsc(s string) string {
	return strings.NewReplacer(`\`, `\\`, `"`, `\"`).Replace(s)
}

func assertNoDropboxCredentialLeak(t *testing.T, label, text string) {
	t.Helper()
	for _, s := range []string{testDropboxAppSecret, testDropboxRefreshToken, echoedDropboxAccessToken, "ECHOEDACCESSTOKENLEAK"} {
		if strings.Contains(text, s) {
			t.Fatalf("%s leaked %q: %q", label, s, text)
		}
	}
}

func backupAuditText(f backupSettingsFixture) string {
	f.audit.auditMu.Lock()
	defer f.audit.auditMu.Unlock()
	var b strings.Builder
	for _, ev := range f.audit.auditEvents {
		b.WriteString(ev.Action + " " + ev.Outcome + " " + ev.ReasonCode + " " + fmtAny(ev.Metadata) + "\n")
	}
	return b.String()
}

// P1 extra guards: Origin null, Sec-Fetch-Site same-site/cross-site alone, HEAD.
func TestDashboardDropboxRoutesRefuseNullOriginSiteHeadersAndHEAD(t *testing.T) {
	routes := []struct{ name, path, form string }{
		{"save", backupDestinationPath, validDropboxForm},
		{"check", backupDestinationCheckPath, validDropboxForm},
		{"test", backupDestinationTestPath, "kind=dropbox"},
		{"remove", backupDestinationRemovePath, "kind=dropbox"},
	}
	cases := []struct {
		name    string
		method  string
		headers map[string]string
	}{
		{"origin null", http.MethodPost, map[string]string{"Origin": "null"}},
		{"sfs same-site alone", http.MethodPost, map[string]string{"Sec-Fetch-Site": "same-site"}},
		{"sfs cross-site alone", http.MethodPost, map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"sfs none", http.MethodPost, map[string]string{"Sec-Fetch-Site": "none"}},
		{"origin evil https", http.MethodPost, map[string]string{"Origin": "https://evil.example"}},
		{"origin same host other scheme", http.MethodPost, map[string]string{"Origin": "https://example.com"}},
		{"HEAD", http.MethodHead, nil},
		{"GET", http.MethodGet, nil},
	}
	for _, rt := range routes {
		for _, tc := range cases {
			t.Run(rt.name+"/"+tc.name, func(t *testing.T) {
				f := dropboxBackupFixture(t)
				tr := &echoDropbox{tokenCode: 200, metaCode: 200, metaBody: `{".tag":"folder"}`}
				f.srv.backupCheckDropbox = nil
				f.srv.backupDropboxHTTPClient = &http.Client{Transport: tr}
				rec := doBackupRequest(f.srv, backupRequest{method: tc.method, path: rt.path, form: rt.form, headers: tc.headers, cookie: f.cookie})
				if rec.Code < 400 {
					t.Fatalf("expected refusal, got %d", rec.Code)
				}
				if f.settings.mutations() != 0 || tr.hits.Load() != 0 || backupAuditCount(f.audit) != 0 {
					t.Fatalf("side effects: store %d hits %d audit %d", f.settings.mutations(), tr.hits.Load(), backupAuditCount(f.audit))
				}
				t.Logf("%d", rec.Code)
			})
		}
	}
}

// P2: echoing fake Dropbox; check (page + HTMX) and test route never leak.
func TestDashboardDropboxEchoingServerNeverLeaksCredentials(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })
	scen := map[string]*echoDropbox{
		"token 400 echo": {tokenCode: 400},
		"token 401 echo": {tokenCode: 401},
		"token 500 echo": {tokenCode: 500},
		"meta 409 echo":  {tokenCode: 200, metaCode: 409, metaBody: `{"error_summary":"path/conflict/{ECHO}","error":{".tag":"path"}}`},
		"meta 401 echo":  {tokenCode: 200, metaCode: 401, metaBody: `{"error_summary":"invalid_access_token/{ECHO}"}`},
		"meta 400 text":  {tokenCode: 200, metaCode: 400, metaBody: `Error in call: {ECHO}`},
		"meta 200 echo":  {tokenCode: 200, metaCode: 200, metaBody: `{".tag":"folder","name":"{ECHO}"}`},
		"meta notfound":  {tokenCode: 200, metaCode: 409, metaBody: `{"error_summary":"path/not_found/{ECHO}"}`},
	}
	for name, tr := range scen {
		t.Run(name, func(t *testing.T) {
			for _, htmx := range []bool{false, true} {
				f := emptyBackupFixture(t)
				f.srv.backupCheckDropbox = nil
				f.srv.backupDropboxHTTPClient = &http.Client{Transport: tr}
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validDropboxForm, cookie: f.cookie, htmx: htmx})
				assertNoDropboxCredentialLeak(t, "check body", rec.Body.String())
				assertNoDropboxCredentialLeak(t, "check audit", backupAuditText(f))
				if f.settings.mutations() != 0 {
					t.Fatalf("check wrote")
				}
				t.Logf("check htmx=%v code=%d audit=%s", htmx, rec.Code, backupAuditText(f))
			}
			f := dropboxBackupFixture(t)
			f.srv.backupCheckDropbox = nil
			f.srv.backupDropboxHTTPClient = &http.Client{Transport: tr}
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
			loc := rec.Header().Get("Location")
			page := performDashboardRequest(f.srv, http.MethodGet, loc, f.cookie).Body.String()
			assertNoDropboxCredentialLeak(t, "test redirect", loc+rec.Body.String())
			assertNoDropboxCredentialLeak(t, "test page", page)
			assertNoDropboxCredentialLeak(t, "test audit", backupAuditText(f))
			t.Logf("test %d %s audit=%s", rec.Code, loc, backupAuditText(f))
		})
	}
	assertNoDropboxCredentialLeak(t, "logs", logs.String())
}

// P3: credentials only from url-encoded body; required on every save.
func TestDashboardDropboxCredentialsComeOnlyFromTheFormBody(t *testing.T) {
	q := url.Values{"app_secret": {testDropboxAppSecret}, "refresh_token": {testDropboxRefreshToken}}.Encode()
	bodyNoSecrets := dropboxForm(map[string]string{"app_secret": "", "refresh_token": ""})
	for _, path := range []string{backupDestinationPath, backupDestinationCheckPath} {
		f := dropboxBackupFixture(t)
		rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path + "?" + q, form: bodyNoSecrets, cookie: f.cookie})
		if rec.Code != http.StatusBadRequest || len(f.settings.putDropbox) > 1 || f.dropbox.calls != 0 || f.settings.dropboxCreds.AppSecret != testDropboxAppSecret {
			t.Fatalf("%s query creds: %d puts %d calls %d", path, rec.Code, len(f.settings.putDropbox), f.dropbox.calls)
		}
		if len(f.settings.putDropbox) == 1 && (f.settings.putDropbox[0].AppSecret != "" || f.settings.putDropbox[0].RefreshToken != "") {
			t.Fatalf("query creds read")
		}
		assertNoDropboxCredentialLeak(t, "query refusal", rec.Body.String())
		// multipart
		var mb bytes.Buffer
		mw := multipart.NewWriter(&mb)
		for k, v := range map[string]string{"kind": "dropbox", "app_key": testDropboxAppKey, "app_secret": testDropboxAppSecret, "refresh_token": testDropboxRefreshToken, "folder_path": "/x"} {
			_ = mw.WriteField(k, v)
		}
		mw.Close()
		f = emptyBackupFixture(t)
		rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: mb.String(), ctype: mw.FormDataContentType(), cookie: f.cookie})
		for _, p := range f.settings.putDropbox {
			if p.AppSecret != "" || p.RefreshToken != "" {
				t.Fatalf("multipart creds read")
			}
		}
		if f.dropbox.calls != 0 || f.settings.destination.Configured {
			t.Fatalf("multipart used: %d", rec.Code)
		}
		t.Logf("%s multipart code=%d", path, rec.Code)
		// JSON
		f = emptyBackupFixture(t)
		rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: `{"kind":"dropbox","app_key":"k1234567890123","app_secret":"` + testDropboxAppSecret + `","refresh_token":"` + testDropboxRefreshToken + `","folder_path":"/x"}`, ctype: "application/json", cookie: f.cookie})
		if f.dropbox.calls != 0 || f.settings.destination.Configured {
			t.Fatalf("json used: %d", rec.Code)
		}
		t.Logf("%s json code=%d", path, rec.Code)
	}
	// Required on every save, also over a configured Dropbox destination.
	for _, miss := range []string{"app_secret", "refresh_token"} {
		f := dropboxBackupFixture(t)
		rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: dropboxForm(map[string]string{miss: ""}), cookie: f.cookie})
		if rec.Code != http.StatusBadRequest || f.settings.dropboxCreds.AppSecret != testDropboxAppSecret {
			t.Fatalf("missing %s = %d", miss, rec.Code)
		}
		if !strings.Contains(dropboxInputTag(t, rec.Body.String(), miss), `aria-invalid="true"`) {
			t.Fatalf("%s not marked", miss)
		}
	}
}

// P4: tampered kind values ("gdrive" is a valid kind since Connect with
// Google landed, so it is not in this list).
func TestDashboardDropboxRefusesTamperedKinds(t *testing.T) {
	for _, kind := range []string{"DROPBOX", "Dropbox", "dropbox ", " dropbox", "s3 ", "S3", "GDrive", "ftp", "dropbox\x00", "../dropbox", "dropbox,s3"} {
		for _, path := range []string{backupDestinationPath, backupDestinationCheckPath} {
			f := emptyBackupFixture(t)
			form := dropboxForm(map[string]string{"kind": kind})
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: form, cookie: f.cookie})
			if rec.Code != http.StatusBadRequest || f.settings.mutations() != 0 || f.dropbox.calls != 0 || f.checker.calls != 0 || backupAuditCount(f.audit) != 0 {
				t.Fatalf("kind %q %s: %d store %d dbx %d s3 %d audit %d", kind, path, rec.Code, f.settings.mutations(), f.dropbox.calls, f.checker.calls, backupAuditCount(f.audit))
			}
			assertNoDropboxCredentialLeak(t, "tampered", rec.Body.String())
		}
	}
	// repeated kind: refused, nothing stored
	f := emptyBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validDropboxForm + "&kind=gdrive", cookie: f.cookie})
	if rec.Code != http.StatusBadRequest || f.settings.mutations() != 0 {
		t.Fatalf("repeated kind code=%d store %d", rec.Code, f.settings.mutations())
	}
	// kind only in query string: ignored, body has no kind -> S3 path
	f = emptyBackupFixture(t)
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath + "?kind=dropbox", form: validBackupDestinationForm, cookie: f.cookie})
	if len(f.settings.putDropbox) != 0 || len(f.settings.putDestination) != 1 {
		t.Fatalf("query kind honored: %d", rec.Code)
	}
	// page with tampered ?kind= is harmless
	for _, q := range []string{"DROPBOX", "<script>", "dropbox%00"} {
		f = emptyBackupFixture(t)
		body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind="+url.QueryEscape(q), f.cookie).Body.String()
		if strings.Contains(body, "<script>x") || strings.Contains(body, "backup-dropbox-form") {
			t.Fatalf("?kind=%q rendered dropbox form or script", q)
		}
	}
}

// P5: no-JS markup of the Dropbox form.
func TestDashboardDropboxFormWorksWithoutJavaScript(t *testing.T) {
	f := emptyBackupFixture(t)
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?kind=dropbox", f.cookie).Body.String()
	for _, m := range []string{
		`<form method="post" action="/dashboard/admin/backups/destination" class="backup-provider-form backup-dropbox-form"`,
		`<input type="hidden" name="kind" value="dropbox">`,
		`name="app_key"`, `name="app_secret"`, `name="refresh_token"`, `name="folder_path"`,
		`formaction="/dashboard/admin/backups/destination/check"`,
		`href="/dashboard/admin/backups?kind=dropbox#backup-destination-title" data-storage-kind="dropbox" aria-current="true"`,
		`href="/dashboard/admin/backups?kind=s3#backup-destination-title"`,
	} {
		if !strings.Contains(body, m) {
			t.Fatalf("missing %q", m)
		}
	}
	// form fields must be inside the form; the check button submits the same fields
	start := strings.Index(body, `class="backup-provider-form backup-dropbox-form"`)
	end := strings.Index(body[start:], "</form>") + start
	inner := body[start:end]
	for _, m := range []string{`name="kind"`, `name="app_key"`, `name="app_secret"`, `name="refresh_token"`, `name="folder_path"`, `formaction="/dashboard/admin/backups/destination/check"`} {
		if !strings.Contains(inner, m) {
			t.Fatalf("%q outside the form", m)
		}
	}
	if strings.Contains(inner, "<form") {
		t.Fatalf("nested form")
	}
	// legacy admin: no Dropbox form
	srv, audit, cookie := legacyAdminDashboardServer(t)
	lf := wireBackupFixture(t, srv, audit, cookie, configuredDropboxSettings())
	lb := performDashboardRequest(lf.srv, http.MethodGet, backupsPagePath+"?kind=dropbox", lf.cookie).Body.String()
	if strings.Contains(lb, "backup-dropbox-form") || strings.Contains(lb, testDropboxAppKey) {
		t.Fatalf("legacy admin sees the form or full app key")
	}
	assertNoDropboxCredentialLeak(t, "legacy", lb)
}
