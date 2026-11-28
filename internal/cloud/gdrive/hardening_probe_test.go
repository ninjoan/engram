package gdrive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

// Realistic Google upload_id ([A-Za-z0-9_-]) plus one needing encoding.
var vprobeIDs = []string{"AEnB2UqVPROBEsecretID_abc-123", "VPROBEsecret%2Bx%2Fy%3Dz"}

func vprobeLeaks(t *testing.T, err error, id, uri string) {
	t.Helper()
	dec, _ := url.QueryUnescape(id)
	decURI, _ := url.QueryUnescape(uri)
	var ge *Error
	errors.As(err, &ge)
	outs := map[string]string{"Error": err.Error(), "%+v": fmt.Sprintf("%+v", err), "%#v": fmt.Sprintf("%#v", err)}
	if ge != nil {
		outs["Msg"], outs["Reason"] = ge.Message, ge.Reason
		if ge.Err != nil {
			outs["Err"] = ge.Err.Error()
		}
	}
	for k, o := range outs {
		for _, leak := range []string{id, dec, uri, decURI, url.QueryEscape(uri), url.QueryEscape(dec), "VPROBEsecret"} {
			if strings.Contains(o, leak) {
				t.Fatalf("%s leaks %q: %s", k, leak, o)
			}
		}
	}
}

func TestHardeningSessionEcho(t *testing.T) {
	for _, id := range vprobeIDs {
		for _, st := range []int{400, 401, 403, 404, 410, 500, 503, 429} {
			for _, path := range []string{"put", "probe"} {
				t.Run(fmt.Sprintf("%s/%d/%s", id[:8], st, path), func(t *testing.T) {
					fd := newFakeDrive(t)
					uri := fd.srv.URL + "/upload/drive/v3/files?uploadType=resumable&upload_id=" + id
					fd.init = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
						w.Header().Set("Location", uri)
						w.WriteHeader(200)
						return true
					}
					dec, _ := url.QueryUnescape(id)
					decURI, _ := url.QueryUnescape(uri)
					echo := strings.Join([]string{uri, decURI, url.QueryEscape(uri), id, dec, url.QueryEscape(dec), "upload_id=" + id}, " | ")
					fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, n int, _ *session) bool {
						if path == "probe" && !strings.HasPrefix(r.Header.Get("Content-Range"), "bytes */") {
							writeGoogleError(w, 503, "backendError", "down")
							return true
						}
						writeGoogleError(w, st, "x"+id, echo)
						return true
					}
					c, _ := newTestClient(t, fd)
					data := payload(testChunk)
					_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
					if err == nil {
						t.Fatal("want error")
					}
					vprobeLeaks(t, err, id, uri)
				})
			}
		}
	}
}

func TestHardeningTokenEcho(t *testing.T) {
	secret, refresh := "GOCSPX-VP+sec/ret=1~x", "1//VP0g+refresh/tok=="
	fd := newFakeDrive(t)
	fd.token = func(w http.ResponseWriter, _ *http.Request, body []byte, _ int, _ *session) bool {
		form, _ := url.ParseQuery(string(body))
		desc := string(body) + " | " + form.Get("client_secret") + " | " + form.Get("refresh_token") + " | " + url.PathEscape(refresh) + " | " + url.PathEscape(secret)
		writeJSON(w, 400, map[string]string{"error": "invalid_grant", "error_description": desc})
		return true
	}
	c, _ := newTestClient(t, fd, func(cfg *Config) { cfg.ClientSecret, cfg.RefreshToken = secret, refresh })
	err := c.CheckAccess(context.Background(), "Engram Backups")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{secret, refresh, url.QueryEscape(secret), url.QueryEscape(refresh), url.PathEscape(secret), url.PathEscape(refresh), "VP+sec", "VP0g", "VP%2Bsec", "VP0g%2B"} {
		if strings.Contains(err.Error(), s) || strings.Contains(fmt.Sprintf("%+v", err), s) {
			t.Fatalf("leak %q: %v", s, err)
		}
	}
	t.Log(err)
}

func TestHardeningRefreshWaiters(t *testing.T) {
	fd := newFakeDrive(t)
	rel := make(chan struct{})
	started := make(chan struct{}, 1)
	fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 1 {
			started <- struct{}{}
			<-rel
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	firstCtx, firstCancel := context.WithCancel(context.Background())
	firstErr := make(chan error, 1)
	go func() { _, err := c.accessToken(firstCtx); firstErr <- err }()
	<-started
	var wg sync.WaitGroup
	okTok := make(chan string, 5)
	for i := 0; i < 5; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.accessToken(context.Background())
			if err == nil {
				okTok <- tok
			}
		}()
	}
	dctx, dcancel := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer dcancel()
	t0 := time.Now()
	if _, err := c.accessToken(dctx); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("deadline waiter err = %v", err)
	}
	if el := time.Since(t0); el > 500*time.Millisecond {
		t.Fatalf("deadline waiter took %v", el)
	}
	firstCancel()
	select {
	case err := <-firstErr:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first err %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first caller not released on cancel")
	}
	close(rel)
	wg.Wait()
	close(okTok)
	n := 0
	for tok := range okTok {
		n++
		if tok != "ya29.access-1" {
			t.Fatalf("tok %q", tok)
		}
	}
	if n != 5 || fd.count("token") != 1 {
		t.Fatalf("ok waiters %d token reqs %d", n, fd.count("token"))
	}
	if tok, err := c.accessToken(context.Background()); err != nil || tok != "ya29.access-1" || fd.count("token") != 1 {
		t.Fatalf("cache poisoned: %q %v %d", tok, err, fd.count("token"))
	}
}

func TestHardeningRefreshFailureNotSticky(t *testing.T) {
	fd := newFakeDrive(t)
	fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 1 {
			writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	if _, err := c.accessToken(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("err %v", err)
	}
	if _, err := c.accessToken(context.Background()); err != nil || fd.count("token") != 2 {
		t.Fatalf("second: %v count %d", err, fd.count("token"))
	}
}

func TestHardeningFolderAmbiguous(t *testing.T) {
	cases := []struct {
		name        string
		createdOn   map[int]bool // create attempt n actually stores the folder
		answer      func(w http.ResponseWriter, n int) bool
		wantCreates int
		wantErr     bool
	}{
		{"500-created", map[int]bool{1: true}, func(w http.ResponseWriter, n int) bool { writeGoogleError(w, 500, "backendError", "x"); return true }, 1, false},
		{"drop-created", map[int]bool{1: true}, nil, 1, false},
		{"500-not-created-then-ok", map[int]bool{}, func(w http.ResponseWriter, n int) bool {
			if n == 1 {
				writeGoogleError(w, 500, "backendError", "x")
				return true
			}
			return false
		}, 2, false},
		{"always-500", map[int]bool{}, func(w http.ResponseWriter, n int) bool { writeGoogleError(w, 503, "backendError", "x"); return true }, defaultMaxRetries + 1, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.create = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
				if tc.createdOn[n] {
					fd.mu.Lock()
					fd.folders = append(fd.folders, fakeFile{ID: "folder-made", Name: "Engram Backups"})
					fd.mu.Unlock()
					if tc.answer == nil {
						hj, _ := w.(http.Hijacker)
						conn, _, _ := hj.Hijack()
						conn.Close()
						return true
					}
				}
				if tc.answer != nil {
					return tc.answer(w, n)
				}
				return false
			}
			c, _ := newTestClient(t, fd)
			id, err := c.EnsureFolder(context.Background(), "Engram Backups")
			if (err != nil) != tc.wantErr {
				t.Fatalf("err %v", err)
			}
			if fd.count("create") != tc.wantCreates {
				t.Fatalf("creates %d want %d (id %q)", fd.count("create"), tc.wantCreates, id)
			}
			if tc.createdOn[1] && id != "folder-made" {
				t.Fatalf("id %q", id)
			}
		})
	}
}

func TestHardening403(t *testing.T) {
	cases := []struct {
		reason string
		want   error
		inits  int
	}{
		{"domainPolicy", ErrUnexpected, 1}, {"forbidden", ErrUnexpected, 1}, {"", ErrUnexpected, 1},
		{"insufficientPermissions", ErrAuth, 1}, {"storageQuotaExceeded", ErrQuota, 1}, {"dailyLimitExceeded", ErrQuota, 1},
	}
	for _, tc := range cases {
		t.Run("put/"+tc.reason, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				if tc.reason == "" {
					w.WriteHeader(403)
					return true
				}
				writeGoogleError(w, 403, tc.reason, "no")
				return true
			}
			c, _ := newTestClient(t, fd)
			data := payload(testChunk)
			_, err := c.Upload(context.Background(), "folder-a", "b", bytes.NewReader(data), int64(len(data)))
			if !errors.Is(err, tc.want) || errors.Is(err, ErrAuth) != (tc.want == ErrAuth) {
				t.Fatalf("err %v", err)
			}
			if fd.count("init") != tc.inits || fd.count("put") != 1 {
				t.Fatalf("init %d put %d", fd.count("init"), fd.count("put"))
			}
			t.Log(err)
		})
		t.Run("list/"+tc.reason, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				writeGoogleError(w, 403, tc.reason, "no")
				return true
			}
			c, _ := newTestClient(t, fd)
			err := c.CheckAccess(context.Background(), "Engram Backups")
			if tc.reason != "" && !errors.Is(err, tc.want) {
				t.Fatalf("err %v", err)
			}
		})
	}
	t.Run("put/rateLimitExceeded-retried", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, n int, _ *session) bool {
			if n == 1 {
				writeGoogleError(w, 403, "rateLimitExceeded", "slow")
				return true
			}
			return false
		}
		c, _ := newTestClient(t, fd)
		data := payload(testChunk)
		if _, err := c.Upload(context.Background(), "folder-a", "b", bytes.NewReader(data), int64(len(data))); err != nil {
			t.Fatal(err)
		}
	})
}

func TestHardeningTokenFailureMidUpload(t *testing.T) {
	for _, mode := range []string{"invalid_grant", "503", "drop"} {
		t.Run(mode, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.token = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
				if n == 1 {
					return false
				}
				switch mode {
				case "invalid_grant":
					writeJSON(w, 400, map[string]string{"error": "invalid_grant"})
				case "503":
					writeGoogleError(w, 503, "backendError", "x")
				default:
					hj, _ := w.(http.Hijacker)
					conn, _, _ := hj.Hijack()
					conn.Close()
				}
				return true
			}
			fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
				if n == 2 {
					writeGoogleError(w, 401, "authError", "expired")
					return true
				}
				return false
			}
			c, _ := newTestClient(t, fd)
			data := payload(4 * testChunk)
			_, err := c.Upload(context.Background(), "folder-a", "b", bytes.NewReader(data), int64(len(data)))
			if err == nil {
				t.Fatal("want error")
			}
			if n := fd.count("token"); n > 2+defaultMaxRetries {
				t.Fatalf("token reqs %d", n)
			}
			if fd.count("put") != 2 || fd.count("init") != 1 {
				t.Fatalf("put %d init %d", fd.count("put"), fd.count("init"))
			}
			t.Logf("tokens=%d err=%v", fd.count("token"), err)
		})
	}
}

// earlyRT answers a chunk PUT without waiting for the body, then keeps
// reading req.Body in the background (as a transport may); with -race any
// reuse of the chunk buffer while it is still read is reported.
type earlyRT struct {
	base http.RoundTripper
	wg   sync.WaitGroup
	mu   sync.Mutex
	seen int
	errs []error
}

func (e *earlyRT) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodPut || req.Body == nil || req.ContentLength == 0 {
		return e.base.RoundTrip(req)
	}
	// Forward a copy, but leave the original body to a late reader.
	body := req.Body
	e.wg.Add(1)
	go func() {
		defer e.wg.Done()
		time.Sleep(40 * time.Millisecond)
		_, err := io.Copy(io.Discard, body)
		e.mu.Lock()
		e.errs = append(e.errs, err)
		e.mu.Unlock()
	}()
	r2 := req.Clone(req.Context())
	gb, _ := req.GetBody()
	r2.Body = gb
	return e.base.RoundTrip(r2)
}

func TestHardeningBodyGuardEarlyResponse(t *testing.T) {
	fd := newFakeDrive(t)
	rt := &earlyRT{base: http.DefaultTransport}
	c, _ := newTestClient(t, fd, func(cfg *Config) { cfg.HTTPClient = &http.Client{Transport: rt} })
	data := payload(6 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	rt.wg.Wait()
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatal("data mismatch")
	}
	t.Logf("late reads: %v", rt.errs)
}
