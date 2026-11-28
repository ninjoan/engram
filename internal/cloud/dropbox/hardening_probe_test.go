package dropbox

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestHardeningTokenEcho(t *testing.T) {
	cfg := testConfig()
	cfg.AppSecret, cfg.RefreshToken = "VPsec+ret/x=1", "VPrt-ab+cd/ef=="
	for _, where := range []string{"desc", "error"} {
		t.Run(where, func(t *testing.T) {
			f := newFakeDropbox(t)
			f.on("/oauth2/token", func(w http.ResponseWriter, rec *recorded, _ int) bool {
				echo := string(rec.Body) + " " + rec.Form.Get("client_secret") + " " + rec.Form.Get("refresh_token") + " " + url.PathEscape(cfg.RefreshToken)
				if where == "desc" {
					writeJSON(w, 400, fmt.Sprintf(`{"error":"invalid_grant","error_description":%q}`, echo))
				} else {
					writeJSON(w, 500, fmt.Sprintf(`{"error":%q}`, echo))
				}
				return true
			})
			c, _ := newTestClient(t, f, cfg)
			err := c.CheckAccess(context.Background(), "/")
			if err == nil {
				t.Fatal("want err")
			}
			out := err.Error() + fmt.Sprintf("%+v %#v", err, err)
			for _, s := range []string{"VPsec", "VPrt"} {
				if strings.Contains(out, s) {
					t.Fatalf("leak %q: %s", s, out)
				}
			}
			t.Log(err)
		})
	}
}

func TestHardeningAccessTokenEchoOnUpload(t *testing.T) {
	for _, st := range []int{400, 403, 409, 500, 503, 429} {
		t.Run(fmt.Sprint(st), func(t *testing.T) {
			f := newFakeDropbox(t)
			f.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, _ int) bool {
				tok := strings.TrimPrefix(rec.Header.Get("Authorization"), "Bearer ")
				w.Header().Set("Retry-After", "0")
				writeJSON(w, st, dropboxError("x/"+tok+"/"+url.QueryEscape(tok), `{".tag":"other"}`))
				return true
			})
			f.on("/2/files/get_metadata", func(w http.ResponseWriter, rec *recorded, _ int) bool {
				writeJSON(w, 409, dropboxError("path/not_found/", `{".tag":"path","path":{".tag":"not_found"}}`))
				return true
			})
			c, _ := newTestClient(t, f, testConfig())
			_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader([]byte("abc")), 3)
			if err == nil {
				t.Fatal("want err")
			}
			assertNoSecrets(t, "upload", err.Error()+fmt.Sprintf("%+v", err))
		})
	}
}

func TestHardeningRefreshWaiters(t *testing.T) {
	f := newFakeDropbox(t)
	started, release := blockFirstToken(t, f)
	c, _ := newTestClient(t, f, testConfig())
	fctx, fcancel := context.WithCancel(context.Background())
	first := make(chan error, 1)
	go func() { _, err := c.accessToken(fctx); first <- err }()
	<-started
	var wg sync.WaitGroup
	var mu sync.Mutex
	toks := map[string]int{}
	for i := 0; i < 6; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tok, err := c.accessToken(context.Background())
			if err == nil {
				mu.Lock()
				toks[tok]++
				mu.Unlock()
			}
		}()
	}
	dctx, dc := context.WithTimeout(context.Background(), 30*time.Millisecond)
	defer dc()
	t0 := time.Now()
	if _, err := c.accessToken(dctx); !errors.Is(err, context.DeadlineExceeded) || time.Since(t0) > 500*time.Millisecond {
		t.Fatalf("deadline waiter %v after %v", err, time.Since(t0))
	}
	fcancel()
	select {
	case err := <-first:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("first %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("first not released")
	}
	release()
	wg.Wait()
	if len(toks) != 1 || f.count("/oauth2/token") != 1 {
		t.Fatalf("toks %v token reqs %d", toks, f.count("/oauth2/token"))
	}
	for tk, n := range toks {
		if n != 6 {
			t.Fatalf("waiters ok %d", n)
		}
		if got, err := c.accessToken(context.Background()); err != nil || got != tk || f.count("/oauth2/token") != 1 {
			t.Fatalf("cache: %v %v %d", got == tk, err, f.count("/oauth2/token"))
		}
	}
}

func TestHardeningRefreshFailureNotSticky(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/oauth2/token", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			writeJSON(w, 400, `{"error":"invalid_grant"}`)
			return true
		}
		return false
	})
	c, _ := newTestClient(t, f, testConfig())
	if _, err := c.accessToken(context.Background()); !errors.Is(err, ErrAuth) {
		t.Fatalf("err %v", err)
	}
	if _, err := c.accessToken(context.Background()); err != nil || f.count("/oauth2/token") != 2 {
		t.Fatalf("second %v %d", err, f.count("/oauth2/token"))
	}
}

func TestHardeningChunkBudgetBounded(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		cur, _ := rec.Arg["cursor"].(map[string]any)
		if off, _ := cur["offset"].(float64); off == 16 {
			writeJSON(w, 503, "down")
			return true
		}
		return false
	})
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("want err")
	}
	if n := f.count("/2/files/upload_session/append_v2"); n != 1+1+maxTransientRetries {
		t.Fatalf("appends %d", n)
	}
	if f.count("/2/files/upload_session/finish") != 0 || f.fileCount() != 0 {
		t.Fatal("finish/file after failure")
	}
}

func TestHardeningFinishNeverBlindRecommit(t *testing.T) {
	for _, mode := range []string{"drop-stored", "503-stored", "drop-probe-fails"} {
		t.Run(mode, func(t *testing.T) {
			f := newFakeDropbox(t)
			f.on("/2/files/upload_session/finish", func(w http.ResponseWriter, rec *recorded, n int) bool {
				if n == 1 {
					f.serve(rec)
					if strings.HasPrefix(mode, "503") {
						writeJSON(w, 503, "x")
					} else {
						dropResponse(t, w)
					}
					return true
				}
				return false
			})
			if mode == "drop-probe-fails" {
				f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, _ int) bool { writeJSON(w, 500, "x"); return true })
			}
			c, _ := sessionClient(t, f)
			data := []byte("abcdefghijklmnopqrstuvwxyz0123")
			_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
			if f.count("/2/files/upload_session/finish") != 1 || f.fileCount() != 1 {
				t.Fatalf("finish %d files %d err %v", f.count("/2/files/upload_session/finish"), f.fileCount(), err)
			}
			if mode == "drop-probe-fails" {
				if err == nil || f.count("/2/files/get_metadata") != maxCommitAttempts {
					t.Fatalf("err %v probes %d", err, f.count("/2/files/get_metadata"))
				}
			} else if err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestHardeningTokenFailureMidUploadBounded(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/oauth2/token", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n >= 2 {
			writeJSON(w, 503, "token down")
			return true
		}
		return false
	})
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			writeJSON(w, 401, dropboxError("expired_access_token/", `{".tag":"expired_access_token"}`))
			return true
		}
		return false
	})
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err == nil {
		t.Fatal("want err")
	}
	t.Logf("tokens=%d appends=%d err=%v", f.count("/oauth2/token"), f.count("/2/files/upload_session/append_v2"), err)
	if f.count("/oauth2/token") > 2+maxTransientRetries {
		t.Fatalf("token reqs %d", f.count("/oauth2/token"))
	}
}
