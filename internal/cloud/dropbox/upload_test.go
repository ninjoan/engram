package dropbox

import (
	"bytes"
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

const testUploadPath = "/Engram backups/engram-cloud-backup-20261128T030000Z-run7.tar.gz"

func TestUploadLimitsAreDropboxLimits(t *testing.T) {
	if SimpleUploadLimit != 150<<20 {
		t.Fatalf("SimpleUploadLimit = %d", SimpleUploadLimit)
	}
	if ChunkSize != 16<<20 || ChunkSize%(4<<20) != 0 {
		t.Fatalf("ChunkSize = %d, must be 16 MiB (a multiple of 4 MiB)", ChunkSize)
	}
	if MaxFileSize != 350_000_000_000 {
		t.Fatalf("MaxFileSize = %d", MaxFileSize)
	}
	c, err := New(testConfig())
	if err != nil {
		t.Fatal(err)
	}
	if c.chunkSize != ChunkSize || c.simpleLimit != SimpleUploadLimit {
		t.Fatalf("defaults: chunk %d simple %d", c.chunkSize, c.simpleLimit)
	}
}

func TestSimpleUploadSendsHeadersAndBody(t *testing.T) {
	f := newFakeDropbox(t)
	c, _ := newTestClient(t, f, testConfig())
	p := "/Engram backups/año-ü-😀.tar.gz"
	data := []byte("backup archive bytes")
	got, err := c.Upload(context.Background(), p, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got != p {
		t.Fatalf("path_display = %q, want %q", got, p)
	}
	reqs := f.requests("/2/files/upload")
	if len(reqs) != 1 {
		t.Fatalf("upload requests = %d", len(reqs))
	}
	r := reqs[0]
	if !bytes.Equal(r.Body, data) {
		t.Fatalf("body = %q", r.Body)
	}
	if ct := r.Header.Get("Content-Type"); ct != "application/octet-stream" {
		t.Fatalf("Content-Type = %q", ct)
	}
	if r.Header.Get("Authorization") != "Bearer "+testAccessPrefix+"1" {
		t.Fatalf("Authorization = %q", r.Header.Get("Authorization"))
	}
	for _, b := range []byte(r.RawArg) {
		if b < 0x20 || b >= 0x7f {
			t.Fatalf("Dropbox-API-Arg is not ASCII-safe: %q", r.RawArg)
		}
	}
	if !strings.Contains(r.RawArg, `a\u00f1o-\u00fc-\ud83d\ude00.tar.gz`) {
		t.Fatalf("non-ASCII not escaped as \\uXXXX: %s", r.RawArg)
	}
	want := map[string]any{"path": p, "mode": "add", "autorename": false, "mute": true, "strict_conflict": false}
	if !reflect.DeepEqual(r.Arg, want) {
		t.Fatalf("Dropbox-API-Arg = %v, want %v", r.Arg, want)
	}
	if stored, _ := f.file(p); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
	if f.count("/2/files/upload_session/start") != 0 {
		t.Fatalf("small file must use a single upload")
	}
}

func TestASCIIJSONEscapes(t *testing.T) {
	got, err := asciiJSON(map[string]string{"p": "a\x7fñ😀<"})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"p":"a\u007f\u00f1\ud83d\ude00\u003c"}`; got != want {
		t.Fatalf("asciiJSON = %s, want %s", got, want)
	}
}

func TestContentHash(t *testing.T) {
	if got, _ := contentHash(context.Background(), bytes.NewReader(nil), 0); got != "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855" {
		t.Fatalf("empty content hash = %s", got)
	}
	data := bytes.Repeat([]byte("0123456789abcdef"), (4<<20)/16+3) // 4 MiB + 48 bytes: two blocks
	got, err := contentHash(context.Background(), bytes.NewReader(data), int64(len(data)))
	if err != nil || got != testContentHash(data) {
		t.Fatalf("content hash = %s, %v; want %s", got, err, testContentHash(data))
	}
}

func sessionClient(t *testing.T, f *fakeDropbox) (*Client, *sleepRecorder) {
	c, rec := newTestClient(t, f, testConfig())
	c.simpleLimit = 10
	c.chunkSize = 8
	return c, rec
}

func appendOffsets(f *fakeDropbox) []int {
	var out []int
	for _, r := range f.requests("/2/files/upload_session/append_v2") {
		cursor, _ := r.Arg["cursor"].(map[string]any)
		off, _ := cursor["offset"].(float64)
		out = append(out, int(off))
	}
	return out
}

func TestSessionUploadUsesExactOffsets(t *testing.T) {
	f := newFakeDropbox(t)
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123") // 30 bytes: 8+8+8+6
	got, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got != testUploadPath {
		t.Fatalf("path_display = %q", got)
	}
	if stored, _ := f.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
	start := f.requests("/2/files/upload_session/start")
	if len(start) != 1 || string(start[0].Body) != "abcdefgh" || start[0].RawArg != `{"close":false}` {
		t.Fatalf("start = %+v", start)
	}
	appends := f.requests("/2/files/upload_session/append_v2")
	wantBodies := []string{"ijklmnop", "qrstuvwx", "yz0123"}
	if len(appends) != 3 {
		t.Fatalf("appends = %d", len(appends))
	}
	for i, r := range appends {
		if string(r.Body) != wantBodies[i] {
			t.Fatalf("append %d body = %q", i, r.Body)
		}
		if r.Header.Get("Content-Type") != "application/octet-stream" {
			t.Fatalf("append Content-Type = %q", r.Header.Get("Content-Type"))
		}
	}
	if want := `{"cursor":{"session_id":"sess-1","offset":8},"close":false}`; appends[0].RawArg != want {
		t.Fatalf("append arg = %s, want %s", appends[0].RawArg, want)
	}
	if got := appendOffsets(f); !reflect.DeepEqual(got, []int{8, 16, 24}) {
		t.Fatalf("offsets = %v", got)
	}
	finish := f.requests("/2/files/upload_session/finish")
	if len(finish) != 1 || len(finish[0].Body) != 0 {
		t.Fatalf("finish = %d requests", len(finish))
	}
	wantFinish := `{"cursor":{"session_id":"sess-1","offset":30},"commit":{"path":"` + testUploadPath + `","mode":"add","autorename":false,"mute":true,"strict_conflict":false}}`
	if finish[0].RawArg != wantFinish {
		t.Fatalf("finish arg = %s\nwant %s", finish[0].RawArg, wantFinish)
	}
	if f.count("/2/files/upload") != 0 {
		t.Fatalf("large file must not use the single upload endpoint")
	}

	// Exactly the simple limit still uses one request.
	f2 := newFakeDropbox(t)
	c2, _ := sessionClient(t, f2)
	if _, err := c2.Upload(context.Background(), testUploadPath, bytes.NewReader(data[:10]), 10); err != nil {
		t.Fatal(err)
	}
	if f2.count("/2/files/upload") != 1 || f2.count("/2/files/upload_session/start") != 0 {
		t.Fatalf("size == simple limit must use a single upload")
	}
}

func TestSessionUploadRecoversFromLostAppendViaIncorrectOffset(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, rec *recorded, n int) bool {
		if n == 1 { // the server stores the chunk, the response is lost
			f.serve(rec)
			dropResponse(t, w)
			return true
		}
		return false
	})
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	if _, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := appendOffsets(f); !reflect.DeepEqual(got, []int{8, 8, 16, 24}) {
		t.Fatalf("offsets = %v, want retry at 8 then resume from correct_offset 16", got)
	}
	if stored, _ := f.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
}

func TestSessionUploadSeeksToCorrectOffsetMidChunk(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, rec *recorded, n int) bool {
		if n == 1 { // pretend the server has 12 bytes (4 bytes of this chunk)
			f.mu.Lock()
			for id, d := range f.sessions {
				f.sessions[id] = append(d, rec.Body[:4]...)
			}
			f.mu.Unlock()
			writeJSON(w, 409, dropboxError("incorrect_offset/..", `{".tag": "incorrect_offset", "correct_offset": 12}`))
			return true
		}
		return false
	})
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	if _, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := appendOffsets(f); !reflect.DeepEqual(got, []int{8, 12, 20, 28}) {
		t.Fatalf("offsets = %v", got)
	}
	if stored, _ := f.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
}

func TestSessionUploadOffsetRecoveryIsBounded(t *testing.T) {
	for name, offset := range map[string]string{"looping": "8", "out of range": "999", "negative": "-1"} {
		f := newFakeDropbox(t)
		f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, _ *recorded, _ int) bool {
			writeJSON(w, 409, dropboxError("incorrect_offset/..", `{".tag": "incorrect_offset", "correct_offset": `+offset+`}`))
			return true
		})
		c, _ := sessionClient(t, f)
		data := []byte("abcdefghijklmnopqrstuvwxyz0123")
		_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
		if !errors.Is(err, ErrUnexpected) {
			t.Fatalf("%s: err = %v, want ErrUnexpected", name, err)
		}
		if n := f.count("/2/files/upload_session/append_v2"); n > maxOffsetResyncs+1 {
			t.Fatalf("%s: %d appends, recovery is unbounded", name, n)
		}
		if f.count("/2/files/upload_session/finish") != 0 {
			t.Fatalf("%s: finished an incomplete session", name)
		}
	}
}

func TestSessionUploadRefreshesExpiredTokenAndReplaysChunk(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			expiredToken(w)
			return true
		}
		return false
	})
	c, _ := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	if _, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	appends := f.requests("/2/files/upload_session/append_v2")
	if string(appends[0].Body) != "ijklmnop" || string(appends[1].Body) != "ijklmnop" {
		t.Fatalf("replayed chunk body = %q", appends[1].Body)
	}
	if f.count("/oauth2/token") != 2 {
		t.Fatalf("token requests = %d", f.count("/oauth2/token"))
	}
	if stored, _ := f.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}
}

func rateLimited(w http.ResponseWriter, retryAfter string) {
	if retryAfter != "" {
		w.Header().Set("Retry-After", retryAfter)
	}
	writeJSON(w, 429, dropboxError("too_many_requests/..", `{"reason": {".tag": "too_many_requests"}}`))
}

func TestRateLimitHonorsRetryAfter(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			rateLimited(w, "3")
			return true
		}
		return false
	})
	c, sleeps := newTestClient(t, f, testConfig())
	data := []byte("payload")
	if _, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if got := sleeps.all(); !reflect.DeepEqual(got, []time.Duration{3 * time.Second}) {
		t.Fatalf("sleeps = %v", got)
	}
	reqs := f.requests("/2/files/upload")
	if len(reqs) != 2 || !bytes.Equal(reqs[1].Body, data) {
		t.Fatalf("retried request body = %q", reqs[len(reqs)-1].Body)
	}

	// 429 on a session chunk retries the same offset.
	f2 := newFakeDropbox(t)
	f2.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 2 {
			rateLimited(w, "1")
			return true
		}
		return false
	})
	c2, _ := sessionClient(t, f2)
	big := []byte("abcdefghijklmnopqrstuvwxyz0123")
	if _, err := c2.Upload(context.Background(), testUploadPath, bytes.NewReader(big), int64(len(big))); err != nil {
		t.Fatal(err)
	}
	if got := appendOffsets(f2); !reflect.DeepEqual(got, []int{8, 16, 16, 24}) {
		t.Fatalf("offsets = %v", got)
	}

	// Persistent 429 ends with ErrRateLimited after bounded retries.
	f3 := newFakeDropbox(t)
	f3.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool { rateLimited(w, "1"); return true })
	c3, sleeps3 := newTestClient(t, f3, testConfig())
	_, err := c3.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if n := f3.count("/2/files/upload"); n != maxRateLimitRetries+1 || len(sleeps3.all()) != maxRateLimitRetries {
		t.Fatalf("requests = %d sleeps = %d", n, len(sleeps3.all()))
	}

	// A Retry-After beyond the bound fails at once.
	f4 := newFakeDropbox(t)
	f4.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool { rateLimited(w, "3600"); return true })
	c4, sleeps4 := newTestClient(t, f4, testConfig())
	_, err = c4.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrRateLimited) || len(sleeps4.all()) != 0 || f4.count("/2/files/upload") != 1 {
		t.Fatalf("err = %v sleeps = %v", err, sleeps4.all())
	}
}

func TestLostFinishResponseIsResolvedWithoutDoubleUpload(t *testing.T) {
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")

	// Committed but the response was lost: get_metadata proves it, no retry.
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/finish", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		f.serve(rec)
		dropResponse(t, w)
		return true
	})
	c, _ := sessionClient(t, f)
	got, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err != nil || got != testUploadPath {
		t.Fatalf("Upload = %q, %v", got, err)
	}
	if f.count("/2/files/upload_session/finish") != 1 || f.count("/2/files/get_metadata") != 1 || f.fileCount() != 1 {
		t.Fatalf("finish = %d metadata = %d files = %d", f.count("/2/files/upload_session/finish"), f.count("/2/files/get_metadata"), f.fileCount())
	}

	// Lost before commit: get_metadata finds nothing, finish is retried once.
	f2 := newFakeDropbox(t)
	f2.on("/2/files/upload_session/finish", func(w http.ResponseWriter, _ *recorded, n int) bool {
		if n == 1 {
			dropResponse(t, w)
			return true
		}
		return false
	})
	c2, _ := sessionClient(t, f2)
	if _, err := c2.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("Upload: %v", err)
	}
	if f2.count("/2/files/upload_session/finish") != 2 || f2.count("/2/files/get_metadata") != 1 {
		t.Fatalf("finish = %d metadata = %d", f2.count("/2/files/upload_session/finish"), f2.count("/2/files/get_metadata"))
	}
	if stored, _ := f2.file(testUploadPath); !bytes.Equal(stored, data) {
		t.Fatalf("stored = %q", stored)
	}

	// Simple upload: committed, response lost.
	f3 := newFakeDropbox(t)
	f3.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		f3.serve(rec)
		dropResponse(t, w)
		return true
	})
	c3, _ := newTestClient(t, f3, testConfig())
	if _, err := c3.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatalf("simple Upload: %v", err)
	}
	if f3.count("/2/files/upload") != 1 || f3.fileCount() != 1 {
		t.Fatalf("simple upload retried: %d", f3.count("/2/files/upload"))
	}

	// A different file at the path is a conflict, never success.
	f4 := newFakeDropbox(t)
	f4.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, _ int) bool {
		f4.putFile(testUploadPath, bytes.ToUpper(rec.Body))
		dropResponse(t, w)
		return true
	})
	c4, _ := newTestClient(t, f4, testConfig())
	_, err = c4.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrConflict) {
		t.Fatalf("err = %v, want ErrConflict", err)
	}
	if f4.count("/2/files/upload") != 1 {
		t.Fatalf("upload retried over a different file")
	}

	// Lost every time: bounded attempts, network error.
	f5 := newFakeDropbox(t)
	f5.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool { dropResponse(t, w); return true })
	c5, _ := newTestClient(t, f5, testConfig())
	_, err = c5.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrNetwork) || f5.count("/2/files/upload") != maxCommitAttempts {
		t.Fatalf("err = %v attempts = %d", err, f5.count("/2/files/upload"))
	}
}

func TestSessionChunkNetworkErrorsAreRetriedBounded(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload_session/append_v2", func(w http.ResponseWriter, _ *recorded, _ int) bool { dropResponse(t, w); return true })
	c, sleeps := sessionClient(t, f)
	data := []byte("abcdefghijklmnopqrstuvwxyz0123")
	_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("err = %v, want ErrNetwork", err)
	}
	if n := f.count("/2/files/upload_session/append_v2"); n != maxTransientRetries+1 {
		t.Fatalf("appends = %d, want %d", n, maxTransientRetries+1)
	}
	if len(sleeps.all()) != maxTransientRetries {
		t.Fatalf("backoff sleeps = %v", sleeps.all())
	}
}

func TestUploadValidatesInputWithoutNetwork(t *testing.T) {
	f := newFakeDropbox(t)
	c, _ := newTestClient(t, f, testConfig())
	ctx := context.Background()
	if _, err := c.Upload(ctx, testUploadPath, strings.NewReader(""), MaxFileSize+1); !errors.Is(err, ErrFileTooLarge) {
		t.Fatalf("too large err = %v", err)
	}
	if _, err := c.Upload(ctx, testUploadPath, strings.NewReader("abc"), 4); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("short body err = %v", err)
	}
	if _, err := c.Upload(ctx, testUploadPath, strings.NewReader("abcd"), 3); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("long body err = %v", err)
	}
	if _, err := c.Upload(ctx, testUploadPath, strings.NewReader(""), -1); !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("negative size err = %v", err)
	}
	if _, err := c.Upload(ctx, testUploadPath, nil, 0); err == nil {
		t.Fatalf("nil body accepted")
	}
	for _, p := range []string{"", "/", "relative.tar.gz", "/folder/", "/bad\nname.tar.gz", "/bad\x7f.tar.gz"} {
		if _, err := c.Upload(ctx, p, strings.NewReader("a"), 1); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("path %q err = %v, want ErrInvalidPath", p, err)
		}
	}
	if n := len(f.requests("")); n != 0 {
		t.Fatalf("invalid input made %d requests", n)
	}
	// An empty file is a valid single upload.
	if _, err := c.Upload(ctx, testUploadPath, strings.NewReader(""), 0); err != nil {
		t.Fatalf("empty upload: %v", err)
	}
}

func TestContextCancelStopsPromptly(t *testing.T) {
	// In-flight request.
	f := newFakeDropbox(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool {
		<-release
		return true
	})
	c, _ := newTestClient(t, f, testConfig())
	ctx, cancel := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel)
	start := time.Now()
	err := waitErr(t, "Upload", func() error {
		_, err := c.Upload(ctx, testUploadPath, strings.NewReader("abc"), 3)
		return err
	})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %s, want prompt context.Canceled", err, time.Since(start))
	}
	if f.count("/2/files/get_metadata") != 0 {
		t.Fatalf("canceled upload must not probe metadata")
	}

	// Waiting on Retry-After with the real sleep.
	f2 := newFakeDropbox(t)
	f2.on("/2/files/upload", func(w http.ResponseWriter, _ *recorded, _ int) bool { rateLimited(w, "60"); return true })
	c2, _ := newTestClient(t, f2, testConfig())
	c2.sleep = sleepCtx
	ctx2, cancel2 := context.WithCancel(context.Background())
	time.AfterFunc(100*time.Millisecond, cancel2)
	start = time.Now()
	err = waitErr(t, "Upload in Retry-After", func() error {
		_, err := c2.Upload(ctx2, testUploadPath, strings.NewReader("abc"), 3)
		return err
	})
	if !errors.Is(err, context.Canceled) || time.Since(start) > 3*time.Second {
		t.Fatalf("err = %v after %s, want prompt context.Canceled", err, time.Since(start))
	}

	// Already canceled: nothing is sent.
	f3 := newFakeDropbox(t)
	c3, _ := newTestClient(t, f3, testConfig())
	done, cancel3 := context.WithCancel(context.Background())
	cancel3()
	if _, err := c3.Upload(done, testUploadPath, strings.NewReader("abc"), 3); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if err := c3.CheckAccess(done, "/x"); !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v", err)
	}
	if n := len(f3.requests("")); n != 0 {
		t.Fatalf("canceled ctx sent %d requests", n)
	}
}

// stallConn simulates a full TCP window: once limit bytes were written,
// Write blocks until the connection is closed.
type stallConn struct {
	net.Conn
	limit     int
	written   int
	closed    chan struct{}
	closeOnce sync.Once
}

func (c *stallConn) Write(p []byte) (int, error) {
	if c.written+len(p) > c.limit {
		n, _ := c.Conn.Write(p[:c.limit-c.written])
		c.written += n
		<-c.closed
		return n, net.ErrClosed
	}
	n, err := c.Conn.Write(p)
	c.written += n
	return n, err
}

func (c *stallConn) Close() error {
	c.closeOnce.Do(func() { close(c.closed) })
	return c.Conn.Close()
}

func TestStalledUploadIsReportedAsStalled(t *testing.T) {
	f := newFakeDropbox(t)
	stalling := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &stallConn{Conn: conn, limit: 16 << 10, closed: make(chan struct{})}, nil
		},
	}}
	cfg := testConfig()
	cfg.HTTPClient = stalling
	c, _ := newTestClient(t, f, cfg)
	c.stallTimeout = 200 * time.Millisecond
	payload := bytes.Repeat([]byte("z"), 256<<10)
	err := waitErr(t, "stalled Upload", func() error {
		_, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(payload), int64(len(payload)))
		return err
	})
	if !errors.Is(err, ErrNetwork) || !errors.Is(err, ErrUploadStalled) || errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want ErrNetwork + ErrUploadStalled", err)
	}
	if f.fileCount() != 0 {
		t.Fatalf("stalled upload stored a file")
	}
}

func TestResponseTimeoutAfterBodySent(t *testing.T) {
	f := newFakeDropbox(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	f.on("/2/files/get_metadata", func(w http.ResponseWriter, _ *recorded, _ int) bool {
		<-release
		return true
	})
	c, _ := newTestClient(t, f, testConfig())
	c.rpcTimeout = 200 * time.Millisecond
	err := waitErr(t, "CheckAccess", func() error { return c.CheckAccess(context.Background(), "/x") })
	if !errors.Is(err, ErrNetwork) || errors.Is(err, context.DeadlineExceeded) || !strings.Contains(err.Error(), "timed out") {
		t.Fatalf("err = %v, want a network timeout", err)
	}
}

func TestRetryAfterForms(t *testing.T) {
	now := time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)
	header := func(v string) http.Header { h := http.Header{}; h.Set("Retry-After", v); return h }
	cases := []struct {
		name string
		h    http.Header
		body int64
		want time.Duration
	}{
		{"seconds", header("7"), 0, 7 * time.Second},
		{"http date", header(now.Add(4 * time.Second).Format(http.TimeFormat)), 0, 4 * time.Second},
		{"json retry_after", http.Header{}, 2, 2 * time.Second},
		{"default", http.Header{}, 0, time.Second},
		{"garbage header falls back to json", header("soon"), 3, 3 * time.Second},
		{"huge header is over the bound", header("99999999999"), 0, maxRetryWait + time.Second},
	}
	for _, tc := range cases {
		if got := retryAfter(tc.h, &Error{retryAfter: tc.body}, now); got != tc.want {
			t.Fatalf("%s: retryAfter = %s, want %s", tc.name, got, tc.want)
		}
	}
}

func TestServerErrorOnCommitIsCheckedBeforeRetry(t *testing.T) {
	f := newFakeDropbox(t)
	f.on("/2/files/upload", func(w http.ResponseWriter, rec *recorded, n int) bool {
		if n == 1 { // stored, but the server answers 503
			f.serve(rec)
			writeJSON(w, 503, "unavailable")
			return true
		}
		return false
	})
	c, _ := newTestClient(t, f, testConfig())
	data := []byte("payload")
	got, err := c.Upload(context.Background(), testUploadPath, bytes.NewReader(data), int64(len(data)))
	if err != nil || got != testUploadPath {
		t.Fatalf("Upload = %q, %v", got, err)
	}
	if f.count("/2/files/upload") != 1 || f.count("/2/files/get_metadata") != 1 {
		t.Fatalf("upload = %d metadata = %d", f.count("/2/files/upload"), f.count("/2/files/get_metadata"))
	}
}

// shrinkingSource reports size bytes when measured but holds fewer.
type shrinkingSource struct {
	*bytes.Reader
	size int64
}

func (s shrinkingSource) Seek(off int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		_, _ = s.Reader.Seek(0, io.SeekEnd)
		return s.size, nil
	}
	return s.Reader.Seek(off, whence)
}

func TestSourceShorterThanMeasuredIsSizeMismatch(t *testing.T) {
	f := newFakeDropbox(t)
	c, _ := newTestClient(t, f, testConfig())
	src := shrinkingSource{Reader: bytes.NewReader([]byte("abc")), size: 6}
	_, err := c.Upload(context.Background(), testUploadPath, src, 6)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("err = %v, want ErrSizeMismatch", err)
	}
	if f.fileCount() != 0 {
		t.Fatalf("a short body was stored")
	}
}
