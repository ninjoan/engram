package dropbox

import (
	"bytes"
	"context"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"testing"
	"time"
)

// --- W1: ctx-aware single-flight token refresh ----------------------------

// blockFirstToken makes the first token request wait until release is called.
func blockFirstToken(t *testing.T, f *fakeDropbox) (started <-chan struct{}, release func()) {
	t.Helper()
	st := make(chan struct{}, 1)
	rel := make(chan struct{})
	var once sync.Once
	releaseFn := func() { once.Do(func() { close(rel) }) }
	t.Cleanup(releaseFn)
	f.on("/oauth2/token", func(_ http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			st <- struct{}{}
			<-rel
		}
		return false
	})
	return st, releaseFn
}

func TestTokenRefreshWaiterHonoursContext(t *testing.T) {
	f := newFakeDropbox(t)
	started, release := blockFirstToken(t, f)
	c, _ := newTestClient(t, f, testConfig())
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
	if n := f.count("/oauth2/token"); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
}

func TestTokenRefreshSurvivesFirstCallerCancel(t *testing.T) {
	f := newFakeDropbox(t)
	started, release := blockFirstToken(t, f)
	c, _ := newTestClient(t, f, testConfig())
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
	if tok := <-second; tok != testAccessPrefix+"1" {
		t.Fatalf("second caller token = %q, want the shared first token", tok)
	}
	if n := f.count("/oauth2/token"); n != 1 {
		t.Fatalf("token requests = %d, want 1 (first caller's cancel must not abort the refresh)", n)
	}
}

func TestConcurrentCallersShareOneRefresh(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/oauth2/token", func(_ http.ResponseWriter, _ *recorded, _ int) bool {
		time.Sleep(30 * time.Millisecond)
		return false
	})
	c, _ := newTestClient(t, f, testConfig())
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
	if n := f.count("/oauth2/token"); n != 1 {
		t.Fatalf("token requests = %d, want 1", n)
	}
}

// --- Dropbox review advisories -----------------------------------------------

var expiresInField = regexp.MustCompile(`,\s*"expires_in":\s*-?\d+`)

func TestMissingOrZeroExpiresInIsCachedConservatively(t *testing.T) {
	for _, mode := range []string{"missing", "zero"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeDropbox(t)
			if mode == "zero" {
				f.expiresIn = 0
			} else {
				f.on("/oauth2/token", func(w http.ResponseWriter, rec *recorded, _ int) bool {
					status, out := f.serve(rec)
					writeJSON(w, status, expiresInField.ReplaceAllString(out, ""))
					return true
				})
			}
			clk := &fakeClock{now: time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)}
			cfg := testConfig()
			cfg.Clock = clk.Now
			c, _ := newTestClient(t, f, cfg)
			for range 2 {
				if err := c.CheckAccess(context.Background(), "/"); err != nil {
					t.Fatal(err)
				}
			}
			if n := f.count("/oauth2/token"); n != 1 {
				t.Fatalf("token requests = %d, want 1 (cached)", n)
			}
			clk.Advance(defaultTokenLifetime - refreshMargin - time.Second)
			_ = c.CheckAccess(context.Background(), "/")
			if n := f.count("/oauth2/token"); n != 1 {
				t.Fatalf("token requests = %d, want 1 before the default lifetime", n)
			}
			clk.Advance(2 * time.Second)
			_ = c.CheckAccess(context.Background(), "/")
			if n := f.count("/oauth2/token"); n != 2 {
				t.Fatalf("token requests = %d, want 2 after the default lifetime", n)
			}
		})
	}
}

func TestSessionTransientBudgetIsPerChunk(t *testing.T) {
	f := newFakeDropbox(t)
	var mu sync.Mutex
	failures := map[float64]int{}
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		cursor, _ := rec.Arg["cursor"].(map[string]any)
		off, _ := cursor["offset"].(float64)
		mu.Lock()
		defer mu.Unlock()
		if failures[off] < 3 { // not stored
			failures[off]++
			writeJSON(w, 503, "unavailable")
			return true
		}
		return false
	})
	c, sleeps := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123") // start 8, appends at 8, 16, 24
	if _, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload with 3 transient failures per chunk (9 in total): %v", err)
	}
	if stored, _ := f.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
	if n := f.count("/2/files/upload_session/append_v2"); n != 12 {
		t.Fatalf("appends = %d, want 12", n)
	}
	want := []time.Duration{backoff(0), backoff(1), backoff(2), backoff(0), backoff(1), backoff(2), backoff(0), backoff(1), backoff(2)}
	if got := sleeps.all(); len(got) != len(want) {
		t.Fatalf("sleeps = %v, want %v (backoff restarts per chunk)", got, want)
	} else {
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("sleeps = %v, want %v", got, want)
			}
		}
	}
}

func TestCommitProbeBacksOffAndRetriesTransientProbe(t *testing.T) {
	data := []byte("payload")
	t.Run("transient probe then found", func(t *testing.T) {
		f := newFakeDropbox(t)
		f.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, n int) bool {
			if n == 1 { // stored, but the answer is a 503
				f.serve(rec)
				writeJSON(w, 503, "unavailable")
				return true
			}
			return false
		})
		f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, n int) bool {
			if n == 1 {
				writeJSON(w, 500, "metadata hiccup")
				return true
			}
			return false
		})
		c, sleeps := newTestClient(t, f, testConfig())
		got, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
		if err != nil || got != testUploadPath {
			t.Fatalf("Upload = %q, %v", got, err)
		}
		if f.count("/2/files/upload") != 1 || f.count("/2/files/get_metadata") != 2 || f.fileCount() != 1 {
			t.Fatalf("upload %d metadata %d files %d", f.count("/2/files/upload"), f.count("/2/files/get_metadata"), f.fileCount())
		}
		if s := sleeps.all(); len(s) != 2 || s[0] != backoff(0) || s[1] != backoff(1) {
			t.Fatalf("sleeps = %v, want a backoff before each probe", s)
		}
	})
	t.Run("probe keeps failing is bounded", func(t *testing.T) {
		f := newFakeDropbox(t)
		f.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool { writeJSON(w, 503, "unavailable"); return true })
		f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, _ int) bool { writeJSON(w, 503, "down"); return true })
		c, _ := newTestClient(t, f, testConfig())
		_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
		if !errors.Is(err, ErrUnexpected) {
			t.Fatalf("err = %v", err)
		}
		if f.count("/2/files/upload") != 1 || f.count("/2/files/get_metadata") != maxCommitAttempts {
			t.Fatalf("upload %d metadata %d, want 1 and %d (never recommit blind)", f.count("/2/files/upload"), f.count("/2/files/get_metadata"), maxCommitAttempts)
		}
	})
}

// --- verifier probes kept as hardening tests --------------------------------

func TestTokenEchoInAPIErrorIsRedacted(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/get_metadata", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		writeJSON(w, 400, "bad request from "+rec.Header.Get("Authorization")+" "+string(rec.Body))
		return true
	})
	c, _ := newTestClient(t, f, testConfig())
	err := c.CheckAccess(context.Background(), "/Engram backups")
	if err == nil {
		t.Fatal("want error")
	}
	assertNoSecrets(t, "API error echo", err.Error())
}

func TestCommitConflictAfterLostAttemptIsResolvedByProbe(t *testing.T) {
	data := []byte("payload")
	f := newFakeDropbox(t)
	f.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, n int) bool {
		if n == 1 { // committed, answer lost
			f.serve(rec)
			dropResponse(t, w)
			return true
		}
		return false
	})
	// The first probe does not see the file yet (eventual consistency).
	f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			writeJSON(w, 409, dropboxError("path/not_found/..", `{".tag": "path", "path": {".tag": "not_found"}}`))
			return true
		}
		return false
	})
	c, _ := newTestClient(t, f, testConfig())
	got, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err != nil || got != testUploadPath {
		t.Fatalf("Upload = %q, %v; the 409 conflict on retry must be checked against our own content", got, err)
	}
	if f.fileCount() != 1 || f.count("/2/files/upload") != 2 {
		t.Fatalf("files %d uploads %d", f.fileCount(), f.count("/2/files/upload"))
	}
}

func TestTokenFormEchoIsRedactedInEveryEncoding(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/oauth2/token", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		writeJSON(w, 400, `{"error": "invalid_grant", "error_description": "bad form `+string(rec.Body)+`"}`)
		return true
	})
	cfg := testConfig()
	cfg.RefreshToken = "refresh/TOKEN+SECRET=7d6c"
	cfg.AppSecret = "app/SECRET+value"
	c, _ := newTestClient(t, f, cfg)
	err := c.CheckAccess(context.Background(), "/")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	for _, s := range []string{"TOKEN", "SECRET"} {
		if strings.Contains(err.Error(), s) {
			t.Fatalf("error leaks %q: %v", s, err)
		}
	}
}

// A refresh is bounded by every round trip its 429 retries may make plus
// their Retry-After waits, not by one RPC timeout: a slow 429 answer
// followed by a slow success still yields a token.
func TestTokenRefreshSurvivesARateLimitedSlowAttempt(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/oauth2/token", func(w http.ResponseWriter, _ *recorded, n int) bool {
		time.Sleep(200 * time.Millisecond)
		if n == 1 {
			w.Header().Set("Retry-After", "0")
			writeJSON(w, http.StatusTooManyRequests, `{"error_summary": "too_many_requests/..", "error": {"reason": {".tag": "too_many_requests"}}}`)
			return true
		}
		return false
	})
	c, sleeps := newTestClient(t, f, testConfig())
	c.rpcTimeout = 300 * time.Millisecond
	var tok string
	err := waitErr(t, "accessToken", func() error {
		var err error
		tok, err = c.accessToken(context.Background())
		return err
	})
	if err != nil || tok == "" {
		t.Fatalf("refresh = %q, %v; want a token after the 429 retry", tok, err)
	}
	if n := f.count("/oauth2/token"); n != 2 {
		t.Fatalf("token requests = %d, want 2", n)
	}
	if got := sleeps.all(); len(got) != 1 || got[0] != 0 {
		t.Fatalf("sleeps = %v, want one Retry-After wait of 0s", got)
	}
}

func TestTokenRefreshBudgetCoversEveryRateLimitRetry(t *testing.T) {
	c, err := newClient(testConfig(), productionEndpoints)
	if err != nil {
		t.Fatal(err)
	}
	c.rpcTimeout = time.Second
	want := time.Duration(maxRateLimitRetries+1)*time.Second + time.Duration(maxRateLimitRetries)*maxRetryWait
	if got := c.refreshBudget(); got != want {
		t.Fatalf("refreshBudget = %s, want %s", got, want)
	}
}
