package dropbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAppKey       = "appkey-abc123xyz"
	testAppSecret    = "appsecret-SUPERSECRET-9f8e"
	testRefreshToken = "refresh-TOKEN-SECRET-7d6c"
	testAccessPrefix = "sl.ACCESS-SECRET-"
)

// recorded is one request seen by the fake Dropbox server.
type recorded struct {
	Path   string
	Header http.Header
	Body   []byte
	Form   url.Values
	Arg    map[string]any // decoded Dropbox-API-Arg, if any
	RawArg string
}

// hook may answer a request itself (return true) before the fake's normal
// behavior. It can call f.serve to run the normal behavior first.
type hook func(w http.ResponseWriter, rec *recorded, n int) bool

// fakeDropbox implements the slice of Dropbox API v2 the client uses.
type fakeDropbox struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	expiresIn   int
	issued      []string
	valid       map[string]bool
	sessions    map[string][]byte
	nextSession int
	files       map[string][]byte
	reqs        []recorded
	counts      map[string]int
	hooks       map[string]hook
}

func newFakeDropbox(t *testing.T) *fakeDropbox {
	t.Helper()
	f := &fakeDropbox{
		t:         t,
		expiresIn: 14400,
		valid:     map[string]bool{},
		sessions:  map[string][]byte{},
		files:     map[string][]byte{},
		counts:    map[string]int{},
		hooks:     map[string]hook{},
	}
	f.srv = httptest.NewServer(http.HandlerFunc(f.handle))
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeDropbox) endpoints() endpoints {
	return endpoints{auth: f.srv.URL, api: f.srv.URL, content: f.srv.URL}
}

func (f *fakeDropbox) on(p string, h hook) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.hooks[p] = h
}

func (f *fakeDropbox) requests(p string) []recorded {
	f.mu.Lock()
	defer f.mu.Unlock()
	var out []recorded
	for _, r := range f.reqs {
		if p == "" || r.Path == p {
			out = append(out, r)
		}
	}
	return out
}

func (f *fakeDropbox) count(p string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.counts[p]
}

func (f *fakeDropbox) file(p string) ([]byte, bool) {
	f.mu.Lock()
	defer f.mu.Unlock()
	b, ok := f.files[p]
	return b, ok
}

func (f *fakeDropbox) fileCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.files)
}

func (f *fakeDropbox) putFile(p string, data []byte) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.files[p] = append([]byte(nil), data...)
}

func (f *fakeDropbox) handle(w http.ResponseWriter, r *http.Request) {
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return // the client aborted mid-body; Dropbox stores nothing
	}
	rec := recorded{Path: r.URL.Path, Header: r.Header.Clone(), Body: body}
	if r.URL.Path == "/oauth2/token" {
		rec.Form, _ = url.ParseQuery(string(body))
	}
	if raw := r.Header.Get("Dropbox-API-Arg"); raw != "" {
		rec.RawArg = raw
		_ = json.Unmarshal([]byte(raw), &rec.Arg)
	}
	f.mu.Lock()
	f.reqs = append(f.reqs, rec)
	f.counts[rec.Path]++
	n := f.counts[rec.Path]
	h := f.hooks[rec.Path]
	f.mu.Unlock()
	if h != nil && h(w, &rec, n) {
		return
	}
	status, out := f.serve(&rec)
	writeJSON(w, status, out)
}

func writeJSON(w http.ResponseWriter, status int, body string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_, _ = io.WriteString(w, body)
}

// dropResponse closes the connection without answering: the request may
// have been processed but the client never sees the result.
func dropResponse(t *testing.T, w http.ResponseWriter) {
	hj, ok := w.(http.Hijacker)
	if !ok {
		t.Errorf("response writer cannot hijack")
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil {
		t.Errorf("hijack: %v", err)
		return
	}
	_ = conn.Close()
}

func dropboxError(summary, errJSON string) string {
	return fmt.Sprintf(`{"error_summary": %q, "error": %s}`, summary, errJSON)
}

// serve runs the fake's normal behavior for rec.
func (f *fakeDropbox) serve(rec *recorded) (int, string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if rec.Path == "/oauth2/token" {
		fm := rec.Form
		if fm.Get("grant_type") != "refresh_token" || fm.Get("client_id") != testAppKey || fm.Get("client_secret") != testAppSecret {
			return 400, `{"error": "invalid_client", "error_description": "Invalid client_id or client_secret"}`
		}
		if fm.Get("refresh_token") != testRefreshToken {
			return 400, `{"error": "invalid_grant", "error_description": "refresh token is invalid or revoked"}`
		}
		tok := fmt.Sprintf("%s%d", testAccessPrefix, len(f.issued)+1)
		f.issued = append(f.issued, tok)
		f.valid[tok] = true
		return 200, fmt.Sprintf(`{"access_token": %q, "token_type": "bearer", "expires_in": %d}`, tok, f.expiresIn)
	}
	tok := strings.TrimPrefix(rec.Header.Get("Authorization"), "Bearer ")
	if !f.valid[tok] {
		return 401, dropboxError("invalid_access_token/..", `{".tag": "invalid_access_token"}`)
	}
	switch rec.Path {
	case "/2/users/get_current_account":
		return 200, `{"account_id": "dbid:fake", "email": "someone@example.com"}`
	case "/2/files/get_metadata":
		var in struct{ Path string }
		_ = json.Unmarshal(rec.Body, &in)
		if data, ok := f.files[in.Path]; ok {
			return 200, fileMetadata(in.Path, data)
		}
		for p := range f.files {
			if strings.HasPrefix(p, in.Path+"/") {
				return 200, fmt.Sprintf(`{".tag": "folder", "name": %q, "path_display": %q, "id": "id:folder"}`, path.Base(in.Path), in.Path)
			}
		}
		return 409, dropboxError("path/not_found/..", `{".tag": "path", "path": {".tag": "not_found"}}`)
	case "/2/files/upload":
		p, _ := rec.Arg["path"].(string)
		if _, ok := f.files[p]; ok {
			return 409, dropboxError("path/conflict/file/..", `{".tag": "path", "reason": {".tag": "conflict", "conflict": {".tag": "file"}}}`)
		}
		f.files[p] = rec.Body
		return 200, fileMetadata(p, rec.Body)
	case "/2/files/upload_session/start":
		f.nextSession++
		id := fmt.Sprintf("sess-%d", f.nextSession)
		f.sessions[id] = rec.Body
		return 200, fmt.Sprintf(`{"session_id": %q}`, id)
	case "/2/files/upload_session/append_v2":
		cursor, _ := rec.Arg["cursor"].(map[string]any)
		id, _ := cursor["session_id"].(string)
		off, _ := cursor["offset"].(float64)
		data, ok := f.sessions[id]
		if !ok {
			return 409, dropboxError("not_found/", `{".tag": "not_found"}`)
		}
		if int(off) != len(data) {
			return 409, dropboxError("incorrect_offset/..", fmt.Sprintf(`{".tag": "incorrect_offset", "correct_offset": %d}`, len(data)))
		}
		f.sessions[id] = append(data, rec.Body...)
		return 200, "null"
	case "/2/files/upload_session/finish":
		cursor, _ := rec.Arg["cursor"].(map[string]any)
		commit, _ := rec.Arg["commit"].(map[string]any)
		id, _ := cursor["session_id"].(string)
		off, _ := cursor["offset"].(float64)
		p, _ := commit["path"].(string)
		data, ok := f.sessions[id]
		if !ok {
			return 409, dropboxError("lookup_failed/not_found/..", `{".tag": "lookup_failed", "lookup_failed": {".tag": "not_found"}}`)
		}
		data = append(data, rec.Body...)
		if int(off) != len(data)-len(rec.Body) {
			return 409, dropboxError("lookup_failed/incorrect_offset/..", fmt.Sprintf(`{".tag": "lookup_failed", "lookup_failed": {".tag": "incorrect_offset", "correct_offset": %d}}`, len(data)-len(rec.Body)))
		}
		if _, exists := f.files[p]; exists {
			return 409, dropboxError("path/conflict/file/..", `{".tag": "path", "path": {".tag": "conflict", "conflict": {".tag": "file"}}}`)
		}
		delete(f.sessions, id)
		f.files[p] = data
		return 200, fileMetadata(p, data)
	}
	return 404, "unknown endpoint"
}

func fileMetadata(p string, data []byte) string {
	return fmt.Sprintf(`{".tag": "file", "name": %q, "path_display": %q, "path_lower": %q, "id": "id:file", "size": %d, "content_hash": %q}`,
		path.Base(p), p, strings.ToLower(p), len(data), testContentHash(data))
}

// testContentHash is an independent implementation of the Dropbox content
// hash: SHA-256 over the concatenated SHA-256 digests of 4 MiB blocks.
func testContentHash(data []byte) string {
	var digests []byte
	for len(data) > 0 {
		n := min(len(data), 4<<20)
		sum := sha256.Sum256(data[:n])
		digests = append(digests, sum[:]...)
		data = data[n:]
	}
	sum := sha256.Sum256(digests)
	return hex.EncodeToString(sum[:])
}

type fakeClock struct {
	mu  sync.Mutex
	now time.Time
}

func (c *fakeClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

func (c *fakeClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = c.now.Add(d)
}

// sleepRecorder replaces the client's ctx-aware sleep in tests.
type sleepRecorder struct {
	mu     sync.Mutex
	sleeps []time.Duration
}

func (s *sleepRecorder) sleep(ctx context.Context, d time.Duration) error {
	s.mu.Lock()
	s.sleeps = append(s.sleeps, d)
	s.mu.Unlock()
	return ctx.Err()
}

func (s *sleepRecorder) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.sleeps...)
}

func testConfig() Config {
	return Config{AppKey: testAppKey, AppSecret: testAppSecret, RefreshToken: testRefreshToken}
}

// newTestClient points a client at f with instant sleeps.
func newTestClient(t *testing.T, f *fakeDropbox, cfg Config) (*Client, *sleepRecorder) {
	t.Helper()
	c, err := newClient(cfg, f.endpoints())
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	rec := &sleepRecorder{}
	c.sleep = rec.sleep
	return c, rec
}

func assertNoSecrets(t *testing.T, what, s string) {
	t.Helper()
	for _, secret := range []string{testAppSecret, testRefreshToken, testAccessPrefix, "SUPERSECRET", "TOKEN-SECRET"} {
		if strings.Contains(s, secret) {
			t.Fatalf("%s leaks %q: %s", what, secret, s)
		}
	}
}

func waitErr(t *testing.T, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(10 * time.Second):
		t.Fatalf("%s did not return", what)
		return nil
	}
}
