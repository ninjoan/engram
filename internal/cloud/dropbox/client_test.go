package dropbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"
	"unicode"
)

func TestNewValidatesConfig(t *testing.T) {
	for name, cfg := range map[string]Config{
		"missing app key":       {AppSecret: testAppSecret, RefreshToken: testRefreshToken},
		"missing app secret":    {AppKey: testAppKey, RefreshToken: testRefreshToken},
		"missing refresh token": {AppKey: testAppKey, AppSecret: testAppSecret},
		"blank refresh token":   {AppKey: testAppKey, AppSecret: testAppSecret, RefreshToken: "  \n"},
	} {
		c, err := New(cfg)
		if c != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: New = %v, %v; want ErrInvalidConfig", name, c, err)
		}
		assertNoSecrets(t, name, err.Error())
	}
	c, err := New(testConfig())
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	want := endpoints{auth: "https://api.dropbox.com", api: "https://api.dropboxapi.com", content: "https://content.dropboxapi.com"}
	if c.ep != want {
		t.Fatalf("production endpoints = %+v, want %+v", c.ep, want)
	}
}

func TestTestEndpointsMustBeLoopback(t *testing.T) {
	prod := endpoints{auth: "https://api.dropbox.com", api: "https://api.dropboxapi.com", content: "https://content.dropboxapi.com"}
	with := func(mod func(*endpoints)) endpoints { e := prod; mod(&e); return e }
	accepted := map[string]endpoints{
		"production":     prod,
		"loopback v4":    {auth: "http://127.0.0.1:1", api: "http://127.0.0.1:2", content: "https://127.0.0.1:3"},
		"localhost":      with(func(e *endpoints) { e.api = "http://localhost:8080" }),
		"loopback v6":    with(func(e *endpoints) { e.content = "http://[::1]:9" }),
		"trailing slash": with(func(e *endpoints) { e.api = "http://127.0.0.1:2/" }),
	}
	for name, ep := range accepted {
		if _, err := newClient(testConfig(), ep); err != nil {
			t.Fatalf("%s rejected: %v", name, err)
		}
	}
	rejected := map[string]endpoints{
		"foreign https host":     with(func(e *endpoints) { e.auth = "https://evil.example.com" }),
		"plain http dropbox":     with(func(e *endpoints) { e.api = "http://api.dropboxapi.com" }),
		"suffix host":            with(func(e *endpoints) { e.content = "https://content.dropboxapi.com.evil.example" }),
		"dropbox host with port": with(func(e *endpoints) { e.auth = "https://api.dropbox.com:444" }),
		"swapped hosts":          with(func(e *endpoints) { e.auth = "https://content.dropboxapi.com" }),
		"private address":        with(func(e *endpoints) { e.api = "http://10.0.0.1:80" }),
		"user info":              with(func(e *endpoints) { e.api = "http://user:pw@127.0.0.1:1" }),
		"path":                   with(func(e *endpoints) { e.api = "http://127.0.0.1:1/2" }),
		"query":                  with(func(e *endpoints) { e.api = "http://127.0.0.1:1?x=1" }),
		"empty":                  with(func(e *endpoints) { e.content = "" }),
		"ftp scheme":             with(func(e *endpoints) { e.content = "ftp://127.0.0.1:21" }),
	}
	for name, ep := range rejected {
		c, err := newClient(testConfig(), ep)
		if c != nil || !errors.Is(err, ErrInvalidConfig) {
			t.Fatalf("%s: newClient = %v, %v; want ErrInvalidConfig", name, c, err)
		}
	}
}

func TestDefaultHTTPClientAndCallerClientIsNotMutated(t *testing.T) {
	c, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if c.httpClient.Timeout != 0 || c.httpClient.Transport == nil || c.httpClient.CheckRedirect == nil {
		t.Fatalf("default client: timeout=%s transport=%v redirect policy set=%v", c.httpClient.Timeout, c.httpClient.Transport != nil, c.httpClient.CheckRedirect != nil)
	}
	caller := &http.Client{Timeout: time.Minute}
	cfg := testConfig()
	cfg.HTTPClient = caller
	c, err = New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if caller.CheckRedirect != nil || caller.Transport != nil {
		t.Fatalf("caller client was mutated")
	}
	if c.httpClient == caller || c.httpClient.Timeout != time.Minute {
		t.Fatalf("caller client must be copied with its timeout kept")
	}
}

func TestTokenRefreshFormAndCaching(t *testing.T) {
	f := newFakeDropbox(t)
	clk := &fakeClock{now: time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)}
	cfg := testConfig()
	cfg.Clock = clk.Now
	c, _ := newTestClient(t, f, cfg)
	ctx := context.Background()

	for range 2 {
		if err := c.CheckAccess(ctx, "/"); err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
	}
	tokenReqs := f.requests("/oauth2/token")
	if len(tokenReqs) != 1 {
		t.Fatalf("token requests = %d, want 1 (cached)", len(tokenReqs))
	}
	tr := tokenReqs[0]
	wantForm := map[string][]string{
		"grant_type":    {"refresh_token"},
		"refresh_token": {testRefreshToken},
		"client_id":     {testAppKey},
		"client_secret": {testAppSecret},
	}
	if !reflect.DeepEqual(map[string][]string(tr.Form), wantForm) {
		t.Fatalf("token form = %v", tr.Form)
	}
	if ct := tr.Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Fatalf("token Content-Type = %q", ct)
	}
	if tr.Header.Get("Authorization") != "" {
		t.Fatalf("token request must not carry an Authorization header")
	}
	for _, r := range f.requests("/2/users/get_current_account") {
		if got := r.Header.Get("Authorization"); got != "Bearer "+testAccessPrefix+"1" {
			t.Fatalf("Authorization = %q", got)
		}
	}

	// Still cached just before the refresh margin, refreshed after it.
	clk.Advance(14400*time.Second - refreshMargin - time.Second)
	if err := c.CheckAccess(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/oauth2/token"); n != 1 {
		t.Fatalf("token refreshed too early: %d requests", n)
	}
	clk.Advance(2 * time.Second)
	if err := c.CheckAccess(ctx, "/"); err != nil {
		t.Fatal(err)
	}
	if n := f.count("/oauth2/token"); n != 2 {
		t.Fatalf("token not refreshed near expiry: %d requests", n)
	}
	reqs := f.requests("/2/users/get_current_account")
	if got := reqs[len(reqs)-1].Header.Get("Authorization"); got != "Bearer "+testAccessPrefix+"2" {
		t.Fatalf("refreshed token not used: %q", got)
	}
}

func TestShortLivedTokenIsRefreshedAtHalfLife(t *testing.T) {
	f := newFakeDropbox(t)
	f.expiresIn = 60
	clk := &fakeClock{now: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)}
	cfg := testConfig()
	cfg.Clock = clk.Now
	c, _ := newTestClient(t, f, cfg)
	_ = c.CheckAccess(context.Background(), "/")
	clk.Advance(29 * time.Second)
	_ = c.CheckAccess(context.Background(), "/")
	if n := f.count("/oauth2/token"); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
	clk.Advance(2 * time.Second)
	_ = c.CheckAccess(context.Background(), "/")
	if n := f.count("/oauth2/token"); n != 2 {
		t.Fatalf("token requests = %d, want 2", n)
	}
}

func expiredToken(w http.ResponseWriter) {
	writeJSON(w, 401, dropboxError("expired_access_token/..", `{".tag": "expired_access_token"}`))
}

func TestExpiredAccessTokenRefreshesOnce(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			expiredToken(w)
			return true
		}
		return false
	})
	f.putFile("/Engram backups/old.tar.gz", []byte("x"))
	c, _ := newTestClient(t, f, testConfig())
	if err := c.CheckAccess(context.Background(), "/Engram backups"); err != nil {
		t.Fatalf("CheckAccess after expired token: %v", err)
	}
	if n := f.count("/oauth2/token"); n != 2 {
		t.Fatalf("token requests = %d, want 2", n)
	}
	reqs := f.requests("/2/files/get_metadata")
	if len(reqs) != 2 || reqs[1].Header.Get("Authorization") != "Bearer "+testAccessPrefix+"2" {
		t.Fatalf("retry did not use the refreshed token: %d requests", len(reqs))
	}

	// A token that stays "expired" is refreshed only once.
	f2 := newFakeDropbox(t)
	f2.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, _ int) bool { expiredToken(w); return true })
	c2, _ := newTestClient(t, f2, testConfig())
	err := c2.CheckAccess(context.Background(), "/Engram backups")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if a, b := f2.count("/oauth2/token"), f2.count("/2/files/get_metadata"); a != 2 || b != 2 {
		t.Fatalf("token requests = %d, api requests = %d; want 2 and 2", a, b)
	}
	assertNoSecrets(t, "expired error", err.Error())
}

func TestTokenEndpointErrorsAreAuthAndRedacted(t *testing.T) {
	cases := map[string]struct {
		status int
		body   string
	}{
		"invalid_grant":  {400, `{"error": "invalid_grant", "error_description": "refresh token refresh-TOKEN-SECRET-7d6c is revoked"}`},
		"invalid_client": {401, `{"error": "invalid_client", "error_description": "bad secret appsecret-SUPERSECRET-9f8e"}`},
		"bare 401":       {401, `unauthorized`},
	}
	for name, tc := range cases {
		f := newFakeDropbox(t)
		f.on("/oauth2/token", func(w http.ResponseWriter, _ *recorded, _ int) bool {
			writeJSON(w, tc.status, tc.body)
			return true
		})
		c, _ := newTestClient(t, f, testConfig())
		err := c.CheckAccess(context.Background(), "/Engram backups")
		if !errors.Is(err, ErrAuth) {
			t.Fatalf("%s: err = %v, want ErrAuth", name, err)
		}
		assertNoSecrets(t, name, err.Error())
		if f.count("/2/files/get_metadata") != 0 {
			t.Fatalf("%s: API called without a token", name)
		}
	}
	// Wrong stored credentials against the fake's own validation.
	f := newFakeDropbox(t)
	cfg := testConfig()
	cfg.RefreshToken = "refresh-TOKEN-SECRET-wrong"
	c, _ := newTestClient(t, f, cfg)
	err := c.CheckAccess(context.Background(), "/")
	if !errors.Is(err, ErrAuth) || !strings.Contains(err.Error(), "invalid_grant") {
		t.Fatalf("err = %v, want ErrAuth invalid_grant", err)
	}
	assertNoSecrets(t, "wrong refresh token", err.Error())
}

func TestCheckAccess(t *testing.T) {
	f := newFakeDropbox(t)
	f.putFile("/Engram backups/a.tar.gz", []byte("a"))
	f.putFile("/notafolder", []byte("x"))
	c, _ := newTestClient(t, f, testConfig())
	ctx := context.Background()

	if err := c.CheckAccess(ctx, "/Engram backups"); err != nil {
		t.Fatalf("existing folder: %v", err)
	}
	if err := c.CheckAccess(ctx, "/Engram backups/"); err != nil {
		t.Fatalf("existing folder with trailing slash: %v", err)
	}
	for _, r := range f.requests("/2/files/get_metadata") {
		if string(r.Body) != `{"path":"/Engram backups"}` || r.Header.Get("Content-Type") != "application/json" {
			t.Fatalf("get_metadata request = %s (%s)", r.Body, r.Header.Get("Content-Type"))
		}
	}
	err := c.CheckAccess(ctx, "/Missing folder")
	if !errors.Is(err, ErrFolderNotFound) {
		t.Fatalf("missing folder err = %v, want ErrFolderNotFound", err)
	}
	if err := c.CheckAccess(ctx, "/notafolder"); !errors.Is(err, ErrConflict) {
		t.Fatalf("file instead of folder err = %v, want ErrConflict", err)
	}
	for _, root := range []string{"", "/"} {
		if err := c.CheckAccess(ctx, root); err != nil {
			t.Fatalf("root %q: %v", root, err)
		}
	}
	acct := f.requests("/2/users/get_current_account")
	if len(acct) != 2 || string(acct[0].Body) != "null" || acct[0].Header.Get("Content-Type") != "application/json" {
		t.Fatalf("get_current_account requests = %d", len(acct))
	}
	if err := c.CheckAccess(ctx, "relative/folder"); !errors.Is(err, ErrInvalidPath) {
		t.Fatalf("relative folder err = %v, want ErrInvalidPath", err)
	}
	for _, r := range f.requests("") {
		switch r.Path {
		case "/oauth2/token", "/2/files/get_metadata", "/2/users/get_current_account":
		default:
			t.Fatalf("CheckAccess wrote: %s", r.Path)
		}
	}
}

func TestErrorClassification(t *testing.T) {
	long := strings.Repeat("x", 5000)
	cases := []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"folder not found", 409, dropboxError("path/not_found/..", `{".tag": "path", "path": {".tag": "not_found"}}`), ErrFolderNotFound},
		{"invalid access token", 401, dropboxError("invalid_access_token/..", `{".tag": "invalid_access_token"}`), ErrAuth},
		{"forbidden", 403, dropboxError("no_permission/..", `{".tag": "no_permission"}`), ErrAuth},
		{"bad input", 400, "Error in call to API function \"files/get_metadata\": bad \x1b[31m path " + long, ErrUnexpected},
		{"server error", 500, "internal", ErrUnexpected},
		{"unavailable", 503, "busy", ErrUnexpected},
		{"malformed path", 409, dropboxError("path/malformed_path/..", `{".tag": "path", "path": {".tag": "malformed_path"}}`), ErrUnexpected},
		{"rate limited", 429, dropboxError("too_many_requests/..", `{"reason": {".tag": "too_many_requests"}, "retry_after": 9999}`), ErrRateLimited},
	}
	for _, tc := range cases {
		f := newFakeDropbox(t)
		f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, _ int) bool {
			writeJSON(w, tc.status, tc.body)
			return true
		})
		c, _ := newTestClient(t, f, testConfig())
		err := c.CheckAccess(context.Background(), "/Engram backups")
		if !errors.Is(err, tc.want) {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		var de *Error
		if !errors.As(err, &de) || de.StatusCode != tc.status || de.Op != "CheckAccess" {
			t.Fatalf("%s: err = %#v, want *Error with status %d", tc.name, err, tc.status)
		}
		msg := err.Error()
		if len(msg) > 600 || strings.ContainsFunc(msg, unicode.IsControl) {
			t.Fatalf("%s: unbounded or unsanitized message (%d bytes): %q", tc.name, len(msg), msg)
		}
		if !strings.HasPrefix(msg, "dropbox: CheckAccess: ") {
			t.Fatalf("%s: message = %q", tc.name, msg)
		}
	}

	upload := []struct {
		name string
		body string
		want error
	}{
		{"insufficient space", dropboxError("path/insufficient_space/..", `{".tag": "path", "reason": {".tag": "insufficient_space"}}`), ErrInsufficientSpace},
		{"conflict", dropboxError("path/conflict/file/..", `{".tag": "path", "reason": {".tag": "conflict"}}`), ErrConflict},
	}
	for _, tc := range upload {
		f := newFakeDropbox(t)
		f.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool {
			writeJSON(w, 409, tc.body)
			return true
		})
		c, _ := newTestClient(t, f, testConfig())
		_, err := c.Upload(context.Background(), "/Engram backups/a.tar.gz", strings.NewReader("abc"), 3)
		if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), "HTTP 409") {
			t.Fatalf("%s: err = %v, want %v", tc.name, err, tc.want)
		}
		if f.count("/2/files/upload") != 1 {
			t.Fatalf("%s: definite 409 must not be retried", tc.name)
		}
	}

	// No server at all.
	f := newFakeDropbox(t)
	c, _ := newTestClient(t, f, testConfig())
	f.srv.Close()
	if err := c.CheckAccess(context.Background(), "/x"); !errors.Is(err, ErrNetwork) {
		t.Fatalf("closed server err = %v, want ErrNetwork", err)
	}
}

func TestSecretsAreRedactedEverywhere(t *testing.T) {
	f := newFakeDropbox(t)
	cfg := testConfig()
	cfg.HTTPClient = &http.Client{}
	cfg.Clock = time.Now
	c, _ := newTestClient(t, f, cfg)
	if err := c.CheckAccess(context.Background(), "/"); err != nil {
		t.Fatal(err)
	}
	if c.tok.access == "" {
		t.Fatalf("access token should be cached for this test")
	}
	type wrapper struct{ Cfg Config }
	values := map[string]any{
		"Config":        cfg,
		"*Config":       &cfg,
		"Client":        *c,
		"*Client":       c,
		"nested Config": wrapper{Cfg: cfg},
	}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X"} {
			out := fmt.Sprintf(verb, v)
			assertNoSecrets(t, name+" "+verb, out)
			for _, hexed := range []string{fmt.Sprintf("%x", testAppSecret), fmt.Sprintf("%X", testRefreshToken), fmt.Sprintf("%x", testAccessPrefix)} {
				if strings.Contains(out, hexed) {
					t.Fatalf("%s %s leaks hex secret: %s", name, verb, out)
				}
			}
			if verb == "%+v" && !strings.Contains(out, "REDACTED") {
				t.Fatalf("%s %s should show a redaction marker: %s", name, verb, out)
			}
		}
	}
	var nilCfg *Config
	var nilClient *Client
	if got := fmt.Sprintf("%v %v", nilCfg, nilClient); got != "<nil> <nil>" {
		t.Fatalf("nil pointers formatted as %q", got)
	}
	for name, v := range map[string]any{"Config": cfg, "Client": c} {
		raw, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json %s: %v", name, err)
		}
		assertNoSecrets(t, "json "+name, string(raw))
	}

	// Servers echoing secrets in error bodies never reach error strings.
	echo := newFakeDropbox(t)
	echo.on("/2/files/get_metadata", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		writeJSON(w, 400, "bad request with "+rec.Header.Get("Authorization")+" and "+testAppSecret+" "+testRefreshToken)
		return true
	})
	ec, _ := newTestClient(t, echo, testConfig())
	err := ec.CheckAccess(context.Background(), "/x")
	if err == nil {
		t.Fatal("expected error")
	}
	assertNoSecrets(t, "echoed error", err.Error())
	assertNoSecrets(t, "echoed error %+v", fmt.Sprintf("%+v %#v", err, err))
	if !strings.Contains(err.Error(), "REDACTED") {
		t.Fatalf("echoed secrets should be replaced by a marker: %s", err)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	target := newFakeDropbox(t)
	for _, p := range []string{"/oauth2/token", "/2/files/get_metadata", "/2/files/upload"} {
		f := newFakeDropbox(t)
		f.on(p, func(w http.ResponseWriter, rec *recorded, _ int) bool {
			w.Header().Set("Location", target.srv.URL+rec.Path)
			w.WriteHeader(http.StatusTemporaryRedirect)
			return true
		})
		permissive := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
		cfg := testConfig()
		cfg.HTTPClient = permissive
		c, _ := newTestClient(t, f, cfg)
		var err error
		if p == "/2/files/upload" {
			_, err = c.Upload(context.Background(), "/b/a.tar.gz", strings.NewReader("abc"), 3)
		} else {
			err = c.CheckAccess(context.Background(), "/b")
		}
		if !errors.Is(err, ErrRedirect) {
			t.Fatalf("%s: err = %v, want ErrRedirect", p, err)
		}
		assertNoSecrets(t, p, err.Error())
	}
	if n := len(target.requests("")); n != 0 {
		t.Fatalf("redirect target received %d requests", n)
	}
}

func TestClientExposesNoDeleteOperation(t *testing.T) {
	typ := reflect.TypeOf(&Client{})
	var names []string
	for i := range typ.NumMethod() {
		names = append(names, typ.Method(i).Name)
	}
	sort.Strings(names)
	if !reflect.DeepEqual(names, []string{"CheckAccess", "Format", "Upload"}) {
		t.Fatalf("exported methods = %v", names)
	}
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	literal := regexp.MustCompile(`"[^"\n]*(?i:delete|remove|move)[^"\n]*"`)
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") || strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		src, err := os.ReadFile(e.Name())
		if err != nil {
			t.Fatal(err)
		}
		if m := literal.Find(src); m != nil {
			t.Fatalf("%s contains a destructive endpoint literal: %s", e.Name(), m)
		}
	}
}
