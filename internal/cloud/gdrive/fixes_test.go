package gdrive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// --- B1: the resumable session URI is a bearer capability -----------------

const (
	echoUploadIDRaw     = "ABPtcPpSECRETupload-id_0123456789%2Bplus%2Fslash"
	echoUploadIDDecoded = "ABPtcPpSECRETupload-id_0123456789+plus/slash"
)

func TestSessionURIEchoNeverInErrors(t *testing.T) {
	statuses := []int{
		http.StatusBadRequest, http.StatusForbidden, http.StatusNotFound, http.StatusGone,
		http.StatusInternalServerError, http.StatusServiceUnavailable, http.StatusTooManyRequests,
	}
	for _, status := range statuses {
		for _, reasonKind := range []string{"raw-id", "decoded-id", "uri"} {
			t.Run(fmt.Sprintf("%d/%s", status, reasonKind), func(t *testing.T) {
				fd := newFakeDrive(t)
				uri := fd.srv.URL + "/upload/drive/v3/files?uploadType=resumable&upload_id=" + echoUploadIDRaw
				decodedURI, _ := url.QueryUnescape(uri)
				fd.init = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
					w.Header().Set("Location", uri)
					w.WriteHeader(http.StatusOK)
					return true
				}
				reason := map[string]string{"raw-id": echoUploadIDRaw, "decoded-id": echoUploadIDDecoded, "uri": uri}[reasonKind]
				fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, _ int, _ *session) bool {
					msg := fmt.Sprintf("session %s (%s) upload_id=%s / %s seen as %s", uri, decodedURI, echoUploadIDRaw, echoUploadIDDecoded, r.URL.String())
					writeGoogleError(w, status, reason, msg)
					return true
				}
				c, _ := newTestClient(t, fd)
				data := payload(testChunk)
				_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
				if err == nil {
					t.Fatal("want error")
				}
				var ge *Error
				if !errors.As(err, &ge) {
					t.Fatalf("err = %v, want *Error", err)
				}
				for what, out := range map[string]string{
					"Error()": err.Error(), "%+v": fmt.Sprintf("%+v", err), "%#v": fmt.Sprintf("%#v", ge),
					"Message": ge.Message, "Reason": ge.Reason,
				} {
					for _, leak := range []string{"SECRETupload", echoUploadIDRaw, echoUploadIDDecoded, "upload_id=ABP"} {
						if strings.Contains(out, leak) {
							t.Fatalf("%s leaks %q: %s", what, leak, out)
						}
					}
				}
			})
		}
	}
}

// --- W1: ctx-aware single-flight token refresh ----------------------------

// blockFirstToken makes the first token request wait until release closes.
func blockFirstToken(t *testing.T, fd *fakeDrive) (started <-chan struct{}, release func()) {
	t.Helper()
	st := make(chan struct{}, 1)
	rel := make(chan struct{})
	var once sync.Once
	releaseFn := func() { once.Do(func() { close(rel) }) }
	t.Cleanup(releaseFn)
	fd.token = func(_ http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 1 {
			st <- struct{}{}
			<-rel
		}
		return false
	}
	return st, releaseFn
}

func TestTokenRefreshWaiterHonoursContext(t *testing.T) {
	fd := newFakeDrive(t)
	started, release := blockFirstToken(t, fd)
	c, _ := newTestClient(t, fd)
	first := make(chan error, 1)
	go func() { _, err := c.accessToken(context.Background()); first <- err }()
	<-started

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	waiter := make(chan error, 1)
	go func() { _, err := c.accessToken(ctx); waiter <- err }()
	select {
	case err := <-waiter:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("waiter err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		release()
		t.Fatal("a waiter with a canceled ctx blocked behind the in-flight refresh")
	}
	release()
	if err := <-first; err != nil {
		t.Fatalf("first refresh: %v", err)
	}
	if n := fd.count("token"); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
}

func TestTokenRefreshSurvivesFirstCallerCancel(t *testing.T) {
	fd := newFakeDrive(t)
	started, release := blockFirstToken(t, fd)
	c, _ := newTestClient(t, fd)
	ctxA, cancelA := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.accessToken(ctxA); first <- err }()
	<-started
	second := make(chan string, 1)
	go func() {
		tok, err := c.accessToken(context.Background())
		if err != nil {
			tok = "error: " + err.Error()
		}
		second <- tok
	}()
	time.Sleep(20 * time.Millisecond) // let the second caller join the flight
	cancelA()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first caller err = %v, want context.Canceled", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("canceled first caller did not return promptly")
	}
	release()
	if tok := <-second; tok != "ya29.access-1" {
		t.Fatalf("second caller token = %q, want the shared ya29.access-1", tok)
	}
	if n := fd.count("token"); n != 1 {
		t.Fatalf("token requests = %d, want 1 (first caller's cancel must not abort the refresh)", n)
	}
}

func TestConcurrentCallersShareOneRefresh(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(_ http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		time.Sleep(30 * time.Millisecond)
		return false
	}
	c, _ := newTestClient(t, fd)
	var wg sync.WaitGroup
	errs := make(chan error, 8)
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := c.accessToken(context.Background())
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := fd.count("token"); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
}

func TestMissingExpiresInCachesConservatively(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		tok := fmt.Sprintf("ya29.access-%d", n)
		fd.mu.Lock()
		fd.issued[tok] = true
		fd.mu.Unlock()
		writeJSON(w, http.StatusOK, map[string]any{"access_token": tok, "token_type": "Bearer"})
		return true
	}
	clk := &fakeClock{now: time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)}
	c, _ := newTestClient(t, fd, func(cfg *Config) { cfg.Clock = clk.Now })
	for range 2 {
		if _, err := c.EnsureFolder(context.Background(), "Engram Backups"); err != nil {
			t.Fatal(err)
		}
	}
	if n := fd.count("token"); n != 1 {
		t.Fatalf("token requests = %d, want 1 (missing expires_in must still cache)", n)
	}
	clk.Advance(time.Hour)
	if _, err := c.EnsureFolder(context.Background(), "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if n := fd.count("token"); n != 2 {
		t.Fatalf("token requests = %d, want 2 after the default lifetime", n)
	}
}

// --- Drive review advisories -----------------------------------------------

func TestEnsureFolderAmbiguousCreateReusesFolder(t *testing.T) {
	createAndFail := func(fd *fakeDrive, drop bool) hook {
		return func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
			if n != 1 {
				return false
			}
			fd.mu.Lock()
			fd.folders = append(fd.folders, fakeFile{ID: "folder-made-1", Name: "Engram Backups", CreatedTime: "2026-11-28T03:00:00Z"})
			fd.mu.Unlock()
			if drop {
				conn, _, err := w.(http.Hijacker).Hijack()
				if err == nil {
					_ = conn.Close()
				}
				return true
			}
			writeGoogleError(w, http.StatusServiceUnavailable, "backendError", "try again")
			return true
		}
	}
	for _, drop := range []bool{false, true} {
		t.Run(fmt.Sprintf("created-then-lost/drop=%v", drop), func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.create = createAndFail(fd, drop)
			c, _ := newTestClient(t, fd)
			id, err := c.EnsureFolder(context.Background(), "Engram Backups")
			if err != nil || id != "folder-made-1" {
				t.Fatalf("EnsureFolder = %q, %v; want folder-made-1", id, err)
			}
			if fd.count("create") != 1 || fd.count("list") != 2 {
				t.Fatalf("create %d list %d, want 1 and 2", fd.count("create"), fd.count("list"))
			}
		})
	}
	t.Run("not-created-retries-create", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.create = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
			if n == 1 {
				writeGoogleError(w, http.StatusInternalServerError, "backendError", "oops")
				return true
			}
			return false
		}
		c, sleeps := newTestClient(t, fd)
		id, err := c.EnsureFolder(context.Background(), "Engram Backups")
		if err != nil || id != "folder-new-1" {
			t.Fatalf("EnsureFolder = %q, %v", id, err)
		}
		if fd.count("create") != 2 || fd.count("list") != 2 || len(sleeps.all()) != 1 {
			t.Fatalf("create %d list %d sleeps %v", fd.count("create"), fd.count("list"), sleeps.all())
		}
	})
	t.Run("always-failing-is-bounded", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.create = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			writeGoogleError(w, http.StatusServiceUnavailable, "backendError", "down")
			return true
		}
		c, _ := newTestClient(t, fd)
		_, err := c.EnsureFolder(context.Background(), "Engram Backups")
		if !errors.Is(err, ErrUnexpected) {
			t.Fatalf("err = %v", err)
		}
		if n := fd.count("create"); n != defaultMaxRetries+1 {
			t.Fatalf("create = %d, want %d", n, defaultMaxRetries+1)
		}
	})
	t.Run("rate-limited-create-is-retried-without-listing", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.create = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
			if n == 1 {
				writeGoogleError(w, http.StatusTooManyRequests, "rateLimitExceeded", "slow")
				return true
			}
			return false
		}
		c, _ := newTestClient(t, fd)
		if _, err := c.EnsureFolder(context.Background(), "Engram Backups"); err != nil {
			t.Fatal(err)
		}
		if fd.count("create") != 2 || fd.count("list") != 1 {
			t.Fatalf("create %d list %d, want 2 and 1", fd.count("create"), fd.count("list"))
		}
	})
}

func TestUploadTokenRefreshFailureFailsFast(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n >= 2 {
			writeGoogleError(w, http.StatusServiceUnavailable, "backendError", "token service down")
			return true
		}
		return false
	}
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		writeGoogleError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return true
	}
	c, _ := newTestClient(t, fd)
	data := payload(2 * testChunk)
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrUnexpected) {
		t.Fatalf("err = %v, want the token refresh failure", err)
	}
	if n := fd.count("token"); n != 1+defaultMaxRetries+1 {
		t.Fatalf("token requests = %d, want %d (one bounded refresh, no chunk retries)", n, 1+defaultMaxRetries+1)
	}
	if n := fd.count("put"); n != 1 {
		t.Fatalf("puts = %d, want 1", n)
	}
}

func TestRefreshRejectsScopeOtherThanDriveFile(t *testing.T) {
	cases := []struct {
		name  string
		scope any
		want  error
	}{
		{"wider", Scope + " https://www.googleapis.com/auth/drive", ErrScope},
		{"other", "https://www.googleapis.com/auth/drive", ErrScope},
		{"exact", Scope, nil},
		{"absent", nil, nil},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				body := map[string]any{"access_token": "ya29.scoped-secret", "expires_in": 3600}
				if tc.scope != nil {
					body["scope"] = tc.scope
				}
				fd.mu.Lock()
				fd.issued["ya29.scoped-secret"] = true
				fd.mu.Unlock()
				writeJSON(w, http.StatusOK, body)
				return true
			}
			c, _ := newTestClient(t, fd)
			_, err := c.EnsureFolder(context.Background(), "Engram Backups")
			if tc.want == nil {
				if err != nil {
					t.Fatal(err)
				}
				return
			}
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if strings.Contains(err.Error(), "ya29.scoped-secret") {
				t.Fatalf("error leaks the access token: %v", err)
			}
			if fd.count("list") != 0 || fd.count("token") != 1 {
				t.Fatalf("list %d token %d, want 0 and 1", fd.count("list"), fd.count("token"))
			}
		})
	}
}

func TestForbiddenReasonsAreClassified(t *testing.T) {
	cases := []struct {
		reason string
		want   error
		calls  int
	}{
		{"dailyLimitExceeded", ErrQuota, 1},
		{"sharingRateLimitExceeded", ErrRateLimited, defaultMaxRetries + 1},
		{"domainPolicy", ErrUnexpected, 1},
		{"forbidden", ErrUnexpected, 1},
		{"", ErrUnexpected, 1},
		{"authError", ErrAuth, 1},
		{"insufficientPermissions", ErrAuth, 1},
	}
	for _, tc := range cases {
		t.Run("403/"+tc.reason, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				writeGoogleError(w, http.StatusForbidden, tc.reason, "The domain administrators have disabled Drive apps.")
				return true
			}
			c, _ := newTestClient(t, fd)
			err := c.CheckAccess(context.Background(), "Engram Backups")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			if tc.want != ErrAuth && errors.Is(err, ErrAuth) {
				t.Fatalf("err = %v must not ask to reconnect", err)
			}
			if tc.want == ErrUnexpected && !strings.Contains(err.Error(), "HTTP 403") {
				t.Fatalf("err = %v, want the HTTP status", err)
			}
			if fd.count("list") != tc.calls {
				t.Fatalf("list calls = %d, want %d", fd.count("list"), tc.calls)
			}
		})
	}
	t.Run("401 stays auth", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			writeGoogleError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
			return true
		}
		c, _ := newTestClient(t, fd)
		if err := c.CheckAccess(context.Background(), "Engram Backups"); !errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v, want ErrAuth", err)
		}
	})
	t.Run("403 domainPolicy on a chunk is fatal, no new session", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			writeGoogleError(w, http.StatusForbidden, "domainPolicy", "The domain administrators have disabled Drive apps.")
			return true
		}
		c, _ := newTestClient(t, fd)
		data := payload(testChunk)
		_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
		if !errors.Is(err, ErrUnexpected) || errors.Is(err, ErrSessionInvalid) || errors.Is(err, ErrAuth) {
			t.Fatalf("err = %v, want ErrUnexpected only", err)
		}
		if fd.count("init") != 1 || fd.count("put") != 1 {
			t.Fatalf("init %d put %d, want 1 and 1", fd.count("init"), fd.count("put"))
		}
	})
}

func TestExchangeCodeNeverResendsCode(t *testing.T) {
	t.Run("5xx", func(t *testing.T) {
		fd, forms := exchangeServer(t, http.StatusInternalServerError, map[string]any{"error": "server_error"})
		_, err := runExchange(t, fd)
		if !errors.Is(err, ErrUnexpected) {
			t.Fatalf("err = %v", err)
		}
		if len(*forms) != 1 {
			t.Fatalf("code sent %d times, want 1", len(*forms))
		}
	})
	t.Run("dropped connection", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			if conn, _, err := w.(http.Hijacker).Hijack(); err == nil {
				_ = conn.Close()
			}
			return true
		}
		_, err := runExchange(t, fd)
		if !errors.Is(err, ErrNetwork) {
			t.Fatalf("err = %v", err)
		}
		if n := fd.count("token"); n != 1 {
			t.Fatalf("code sent %d times, want 1", n)
		}
	})
}

// --- in-memory transport for chunk body lifetime tests -----------------------

const rtBase = "http://127.0.0.1:9"

// scriptRT answers token and session-start requests itself and hands every
// PUT to put. It never touches the network.
type scriptRT struct {
	put  func(req *http.Request, n int) (*http.Response, error)
	puts atomic.Int32
	wg   sync.WaitGroup
}

func rtResponse(req *http.Request, status int, header http.Header, body string) *http.Response {
	if header == nil {
		header = http.Header{}
	}
	return &http.Response{StatusCode: status, Header: header, Body: io.NopCloser(strings.NewReader(body)), Request: req, ContentLength: int64(len(body))}
}

func (s *scriptRT) RoundTrip(req *http.Request) (*http.Response, error) {
	switch {
	case req.Method == http.MethodPost && req.URL.Path == "/token":
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		return rtResponse(req, http.StatusOK, http.Header{"Content-Type": {"application/json"}}, `{"access_token":"ya29.rt","expires_in":3600}`), nil
	case req.Method == http.MethodPost && req.URL.Path == "/upload/drive/v3/files":
		_, _ = io.Copy(io.Discard, req.Body)
		_ = req.Body.Close()
		return rtResponse(req, http.StatusOK, http.Header{"Location": {rtBase + "/upload/drive/v3/files?uploadType=resumable&upload_id=rt-1"}}, ""), nil
	case req.Method == http.MethodPut && req.URL.Path == "/upload/drive/v3/files":
		return s.put(req, int(s.puts.Add(1)))
	}
	if req.Body != nil {
		_ = req.Body.Close()
	}
	return nil, fmt.Errorf("unexpected request %s %s", req.Method, req.URL.Path)
}

func rtClient(t *testing.T, rt *scriptRT) *Client {
	t.Helper()
	c, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, baseURL: rtBase, chunkSize: testChunk, HTTPClient: &http.Client{Transport: rt}})
	if err != nil {
		t.Fatal(err)
	}
	c.backoffBase, c.backoffMax = time.Millisecond, time.Millisecond
	c.sleep = func(ctx context.Context, _ time.Duration) error { return ctx.Err() }
	return c
}

func parseContentRange(t *testing.T, cr string) (start, end, total int64, probe bool) {
	t.Helper()
	if rest, ok := strings.CutPrefix(cr, "bytes */"); ok {
		total, _ = strconv.ParseInt(rest, 10, 64)
		return 0, 0, total, true
	}
	if _, err := fmt.Sscanf(cr, "bytes %d-%d/%d", &start, &end, &total); err != nil {
		t.Errorf("bad Content-Range %q", cr)
	}
	return start, end, total, false
}

// The transport may keep reading a request body after it returned the
// response (an early reply); the next chunk must not overwrite those bytes
// while they are read. Run with -race.
func TestChunkBufferIsNotReusedWhileTransportReadsBody(t *testing.T) {
	rt := &scriptRT{}
	var lateErrs atomic.Int32
	rt.put = func(req *http.Request, _ int) (*http.Response, error) {
		_, end, total, probe := parseContentRange(t, req.Header.Get("Content-Range"))
		if !probe {
			rt.wg.Add(1)
			go func(body io.ReadCloser) {
				defer rt.wg.Done()
				time.Sleep(2 * time.Millisecond)
				if _, err := io.Copy(io.Discard, body); err != nil {
					lateErrs.Add(1)
				}
				_ = body.Close()
			}(req.Body)
		}
		if end+1 == total {
			return rtResponse(req, http.StatusOK, nil, `{"id":"file-rt"}`), nil
		}
		return rtResponse(req, http.StatusPermanentRedirect, http.Header{"Range": {fmt.Sprintf("bytes=0-%d", end)}}, ""), nil
	}
	c := rtClient(t, rt)
	data := payload(6 * testChunk)
	id, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	rt.wg.Wait()
	if err != nil || id != "file-rt" {
		t.Fatalf("Upload = %q, %v", id, err)
	}
	if lateErrs.Load() == 0 {
		t.Fatal("a body read after the response must fail instead of reading the reused chunk buffer")
	}
}

func TestUploadStallWatchdogProbesAndResumes(t *testing.T) {
	stallingRT := func(stallAll bool, causes *[]error, mu *sync.Mutex) *scriptRT {
		rt := &scriptRT{}
		rt.put = func(req *http.Request, n int) (*http.Response, error) {
			_, _, _, probe := parseContentRange(t, req.Header.Get("Content-Range"))
			if probe {
				return rtResponse(req, http.StatusPermanentRedirect, nil, ""), nil
			}
			if n == 1 || stallAll {
				one := make([]byte, 1)
				_, _ = req.Body.Read(one) // arms the stall watchdog
				<-req.Context().Done()
				mu.Lock()
				*causes = append(*causes, context.Cause(req.Context()))
				mu.Unlock()
				_ = req.Body.Close()
				return nil, req.Context().Err()
			}
			_, _ = io.Copy(io.Discard, req.Body)
			_ = req.Body.Close()
			return rtResponse(req, http.StatusOK, nil, `{"id":"file-rt"}`), nil
		}
		return rt
	}
	t.Run("recovers", func(t *testing.T) {
		var mu sync.Mutex
		var causes []error
		rt := stallingRT(false, &causes, &mu)
		c := rtClient(t, rt)
		c.stallTimeout = 50 * time.Millisecond
		data := payload(testChunk)
		id, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
		if err != nil || id != "file-rt" {
			t.Fatalf("Upload = %q, %v", id, err)
		}
		mu.Lock()
		defer mu.Unlock()
		if len(causes) != 1 || !errors.Is(causes[0], ErrUploadStalled) {
			t.Fatalf("causes = %v, want one ErrUploadStalled", causes)
		}
		if n := rt.puts.Load(); n != 3 { // stalled chunk, probe, resent chunk
			t.Fatalf("puts = %d, want 3", n)
		}
	})
	t.Run("bounded", func(t *testing.T) {
		var mu sync.Mutex
		var causes []error
		rt := stallingRT(true, &causes, &mu)
		c := rtClient(t, rt)
		c.stallTimeout = 20 * time.Millisecond
		data := payload(testChunk)
		_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
		if !errors.Is(err, ErrUploadStalled) || !errors.Is(err, ErrNetwork) {
			t.Fatalf("err = %v, want ErrNetwork wrapping ErrUploadStalled", err)
		}
	})
}

// --- verifier probes kept as hardening tests --------------------------------

func TestUploadGoneSessionAfterProgressRestartsOnce(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, n int, _ *session) bool {
		if r.URL.Query().Get("upload_id") == "sess-1" && n == 2 {
			writeGoogleError(w, http.StatusGone, "gone", "session expired")
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(2 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if fd.count("init") != 2 || !bytes.Equal(fd.sessionData("sess-2"), data) {
		t.Fatalf("init = %d, data restarted from 0 in sess-2: %v", fd.count("init"), bytes.Equal(fd.sessionData("sess-2"), data))
	}
}

func TestTokenEndpointEchoIsRedacted(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(w http.ResponseWriter, _ *http.Request, body []byte, _ int, _ *session) bool {
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid_grant", "error_description": "bad form " + string(body)})
		return true
	}
	c, _ := newTestClient(t, fd)
	err := c.CheckAccess(context.Background(), "Engram Backups")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{testSecret, testRefresh, url.QueryEscape(testRefresh), url.QueryEscape(testSecret)} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks %q: %v", s, err)
		}
	}
}

// A token request that hangs past one attempt's timeout must be retried
// inside the shared refresh, not end the whole refresh.
func TestTokenRefreshRetriesAfterAHungAttempt(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(_ http.ResponseWriter, r *http.Request, _ []byte, n int, _ *session) bool {
		if n == 1 {
			<-r.Context().Done() // hang until this attempt's own timeout
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	c.requestTimeout = 150 * time.Millisecond
	if _, err := c.accessToken(context.Background()); err != nil {
		t.Fatalf("refresh after one hung attempt failed: %v", err)
	}
	if got := fd.count("token"); got != 2 {
		t.Fatalf("token requests = %d, want 2 (hung attempt + retry)", got)
	}
}
