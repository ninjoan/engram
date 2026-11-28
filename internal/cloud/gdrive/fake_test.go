package gdrive

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testClientID = "test-client-id.apps.googleusercontent.com"
	testSecret   = "GOCSPX-test-client-secret-value"
	testRefresh  = "1//test-refresh-token-value"
	testChunk    = int64(256) << 10
)

type recReq struct {
	Method        string
	Path          string
	Query         url.Values
	Header        http.Header
	Body          []byte
	ContentLength int64
}

type fakeFile struct {
	ID          string `json:"id"`
	Name        string `json:"name"`
	CreatedTime string `json:"createdTime,omitempty"`
}

type session struct {
	id     string
	total  int64
	data   []byte
	done   bool
	fileID string
}

// hook handles a request before the default behavior; it returns true when
// it wrote the response. n counts requests to the same route, from 1.
type hook func(w http.ResponseWriter, r *http.Request, body []byte, n int, s *session) bool

// fakeDrive is a minimal in-memory Google OAuth token endpoint plus the
// Drive v3 routes the client uses. Any other route (DELETE included) fails
// the test.
type fakeDrive struct {
	t   *testing.T
	srv *httptest.Server

	mu        sync.Mutex
	reqs      []recReq
	counts    map[string]int
	expiresIn int
	folders   []fakeFile
	sessions  map[string]*session
	sessionN  int
	fileN     int
	revoked   map[string]bool // access tokens answered with 401
	issued    map[string]bool

	token, list, create, init, put hook
}

func newFakeDrive(t *testing.T) *fakeDrive {
	t.Helper()
	fd := &fakeDrive{
		t:         t,
		counts:    map[string]int{},
		expiresIn: 3600,
		sessions:  map[string]*session{},
		revoked:   map[string]bool{},
		issued:    map[string]bool{},
	}
	fd.srv = httptest.NewServer(http.HandlerFunc(fd.serve))
	t.Cleanup(fd.srv.Close)
	return fd
}

func (fd *fakeDrive) route(r *http.Request) string {
	switch {
	case r.Method == http.MethodPost && r.URL.Path == "/token":
		return "token"
	case r.Method == http.MethodGet && r.URL.Path == "/drive/v3/files":
		return "list"
	case r.Method == http.MethodPost && r.URL.Path == "/drive/v3/files":
		return "create"
	case r.Method == http.MethodPost && r.URL.Path == "/upload/drive/v3/files":
		return "init"
	case r.Method == http.MethodPut && r.URL.Path == "/upload/drive/v3/files":
		return "put"
	}
	return ""
}

func (fd *fakeDrive) serve(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	route := fd.route(r)
	fd.mu.Lock()
	fd.reqs = append(fd.reqs, recReq{Method: r.Method, Path: r.URL.Path, Query: r.URL.Query(), Header: r.Header.Clone(), Body: body, ContentLength: r.ContentLength})
	fd.counts[route]++
	n := fd.counts[route]
	var h hook
	switch route {
	case "token":
		h = fd.token
	case "list":
		h = fd.list
	case "create":
		h = fd.create
	case "init":
		h = fd.init
	case "put":
		h = fd.put
	}
	var s *session
	if route == "put" {
		s = fd.sessions[r.URL.Query().Get("upload_id")]
	}
	fd.mu.Unlock()

	if route == "" {
		fd.t.Errorf("unexpected request %s %s", r.Method, r.URL.Path)
		http.Error(w, "not found", http.StatusMethodNotAllowed)
		return
	}
	if route != "token" && !fd.authorized(r) {
		writeGoogleError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return
	}
	if h != nil && h(w, r, body, n, s) {
		return
	}
	switch route {
	case "token":
		fd.serveToken(w, r, body)
	case "list":
		fd.mu.Lock()
		files := append([]fakeFile(nil), fd.folders...)
		fd.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"files": files})
	case "create":
		fd.mu.Lock()
		fd.fileN++
		id := fmt.Sprintf("folder-new-%d", fd.fileN)
		fd.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"id": id})
	case "init":
		total, _ := strconv.ParseInt(r.Header.Get("X-Upload-Content-Length"), 10, 64)
		fd.mu.Lock()
		fd.sessionN++
		id := fmt.Sprintf("sess-%d", fd.sessionN)
		fd.sessions[id] = &session{id: id, total: total}
		fd.mu.Unlock()
		w.Header().Set("Location", fd.srv.URL+"/upload/drive/v3/files?uploadType=resumable&upload_id="+id)
		w.WriteHeader(http.StatusOK)
	case "put":
		fd.servePut(w, r, body, s)
	}
}

func (fd *fakeDrive) authorized(r *http.Request) bool {
	tok, ok := strings.CutPrefix(r.Header.Get("Authorization"), "Bearer ")
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return ok && fd.issued[tok] && !fd.revoked[tok]
}

func (fd *fakeDrive) serveToken(w http.ResponseWriter, r *http.Request, body []byte) {
	form, _ := url.ParseQuery(string(body))
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != testRefresh ||
		form.Get("client_id") != testClientID || form.Get("client_secret") != testSecret {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "Bad Request"})
		return
	}
	fd.mu.Lock()
	tok := fmt.Sprintf("ya29.access-%d", fd.counts["token"])
	fd.issued[tok] = true
	exp := fd.expiresIn
	fd.mu.Unlock()
	writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "expires_in": exp, "token_type": "Bearer", "scope": Scope})
}

// servePut implements the resumable protocol for one session.
func (fd *fakeDrive) servePut(w http.ResponseWriter, r *http.Request, body []byte, s *session) {
	if s == nil {
		writeGoogleError(w, http.StatusNotFound, "notFound", "session not found")
		return
	}
	cr := r.Header.Get("Content-Range")
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if strings.HasPrefix(cr, "bytes */") {
		fd.answerProgressLocked(w, s)
		return
	}
	var start, end, total int64
	if _, err := fmt.Sscanf(cr, "bytes %d-%d/%d", &start, &end, &total); err != nil || total != s.total || end-start+1 != int64(len(body)) {
		fd.t.Errorf("bad Content-Range %q for %d bytes (session total %d)", cr, len(body), s.total)
		writeGoogleError(w, http.StatusBadRequest, "badContent", "bad range")
		return
	}
	if start == int64(len(s.data)) {
		s.data = append(s.data, body...)
	}
	fd.answerProgressLocked(w, s)
}

func (fd *fakeDrive) answerProgressLocked(w http.ResponseWriter, s *session) {
	if int64(len(s.data)) == s.total {
		if !s.done {
			s.done = true
			fd.fileN++
			s.fileID = fmt.Sprintf("file-%d", fd.fileN)
		}
		writeJSON(w, http.StatusOK, map[string]string{"id": s.fileID})
		return
	}
	if len(s.data) > 0 {
		w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", len(s.data)-1))
	}
	w.WriteHeader(http.StatusPermanentRedirect)
}

func (fd *fakeDrive) requests(route string) []recReq {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	var out []recReq
	for _, rq := range fd.reqs {
		r := &http.Request{Method: rq.Method, URL: &url.URL{Path: rq.Path}}
		if route == "" || fd.route(r) == route {
			out = append(out, rq)
		}
	}
	return out
}

func (fd *fakeDrive) count(route string) int {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	return fd.counts[route]
}

func (fd *fakeDrive) sessionData(id string) []byte {
	fd.mu.Lock()
	defer fd.mu.Unlock()
	if s := fd.sessions[id]; s != nil {
		return append([]byte(nil), s.data...)
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func writeGoogleError(w http.ResponseWriter, status int, reason, msg string) {
	writeJSON(w, status, map[string]any{"error": map[string]any{
		"code": status, "message": msg,
		"errors": []map[string]string{{"domain": "global", "reason": reason, "message": msg}},
	}})
}

type sleepLog struct {
	mu sync.Mutex
	d  []time.Duration
}

func (s *sleepLog) all() []time.Duration {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]time.Duration(nil), s.d...)
}

// newTestClient builds a client against fd with a 256 KiB chunk, recorded
// zero-length backoff sleeps and full (deterministic) jitter.
func newTestClient(t *testing.T, fd *fakeDrive, mods ...func(*Config)) (*Client, *sleepLog) {
	t.Helper()
	cfg := Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, baseURL: fd.srv.URL, chunkSize: testChunk}
	for _, m := range mods {
		m(&cfg)
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	log := &sleepLog{}
	c.backoffBase = 10 * time.Millisecond
	c.backoffMax = 40 * time.Millisecond
	c.jitter = func(d time.Duration) time.Duration { return d }
	c.sleep = func(ctx context.Context, d time.Duration) error {
		log.mu.Lock()
		log.d = append(log.d, d)
		log.mu.Unlock()
		return ctx.Err()
	}
	return c, log
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
