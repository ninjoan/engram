package gdrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
)

func payload(n int64) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*7 + i/251)
	}
	return b
}

func contentRanges(fd *fakeDrive) []string {
	var out []string
	for _, r := range fd.requests("put") {
		out = append(out, r.Header.Get("Content-Range"))
	}
	return out
}

func assertRanges(t *testing.T, fd *fakeDrive, want ...string) {
	t.Helper()
	got := contentRanges(fd)
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("Content-Range sequence:\n got %q\nwant %q", got, want)
	}
}

func TestChunkSizeIsEightMiBAndAligned(t *testing.T) {
	if ChunkSize != 8<<20 || ChunkSize%(256<<10) != 0 {
		t.Fatalf("ChunkSize = %d", ChunkSize)
	}
	c, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh})
	if err != nil || c.chunkSize != ChunkSize {
		t.Fatalf("default chunk = %d, %v", c.chunkSize, err)
	}
	for _, bad := range []int64{-1, 100_000, 256<<10 + 1} {
		fd := newFakeDrive(t)
		if _, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, baseURL: fd.srv.URL, chunkSize: bad}); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("chunk %d: err = %v, want ErrInvalidConfig", bad, err)
		}
	}
}

func TestUploadResumableAcrossThreeChunks(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	data := payload(2*testChunk + testChunk/2)
	id, err := c.Upload(context.Background(), "folder-a", "engram-backup-run42.tar.gz", bytes.NewReader(data), int64(len(data)))
	if err != nil || id != "file-1" {
		t.Fatalf("Upload = %q, %v", id, err)
	}
	init := fd.requests("init")
	if len(init) != 1 {
		t.Fatalf("init calls = %d", len(init))
	}
	q := init[0].Query
	if q.Get("uploadType") != "resumable" || q.Get("supportsAllDrives") != "true" {
		t.Fatalf("init query = %v", q)
	}
	h := init[0].Header
	if h.Get("X-Upload-Content-Type") != "application/gzip" || h.Get("X-Upload-Content-Length") != fmt.Sprint(len(data)) ||
		h.Get("Content-Type") != "application/json; charset=UTF-8" || h.Get("Authorization") != "Bearer ya29.access-1" {
		t.Fatalf("init headers = %v", h)
	}
	var meta struct {
		Name    string   `json:"name"`
		Parents []string `json:"parents"`
	}
	if err := json.Unmarshal(init[0].Body, &meta); err != nil || meta.Name != "engram-backup-run42.tar.gz" || len(meta.Parents) != 1 || meta.Parents[0] != "folder-a" {
		t.Fatalf("metadata %s: %v", init[0].Body, err)
	}
	total := len(data)
	assertRanges(t, fd,
		fmt.Sprintf("bytes 0-262143/%d", total),
		fmt.Sprintf("bytes 262144-524287/%d", total),
		fmt.Sprintf("bytes 524288-%d/%d", total-1, total),
	)
	for i, r := range fd.requests("put") {
		if i < 2 && r.ContentLength%(256<<10) != 0 {
			t.Fatalf("chunk %d has %d bytes, not 256 KiB aligned", i, r.ContentLength)
		}
		if r.Query.Get("upload_id") != "sess-1" {
			t.Fatalf("chunk %d went to %v", i, r.Query)
		}
	}
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatalf("server data differs from the source")
	}
}

func TestUploadExactMultipleAndTinyFiles(t *testing.T) {
	for _, size := range []int64{1, testChunk, 2 * testChunk} {
		t.Run(fmt.Sprint(size), func(t *testing.T) {
			fd := newFakeDrive(t)
			c, _ := newTestClient(t, fd)
			data := payload(size)
			if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), size); err != nil {
				t.Fatal(err)
			}
			if want := int((size + testChunk - 1) / testChunk); fd.count("put") != want {
				t.Fatalf("PUTs = %d, want %d", fd.count("put"), want)
			}
			if !bytes.Equal(fd.sessionData("sess-1"), data) {
				t.Fatal("data differs")
			}
		})
	}
}

func TestUploadEmptyFileFinalizesWithZeroRange(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	id, err := c.Upload(context.Background(), "folder-a", "empty.tar.gz", bytes.NewReader(nil), 0)
	if err != nil || id == "" {
		t.Fatalf("Upload = %q, %v", id, err)
	}
	assertRanges(t, fd, "bytes */0")
}

func TestUploadResumesFromPartialRange(t *testing.T) {
	fd := newFakeDrive(t)
	half := testChunk / 2
	fd.put = func(w http.ResponseWriter, r *http.Request, body []byte, n int, s *session) bool {
		if n == 1 { // keep only the first half of the first chunk
			fd.mu.Lock()
			s.data = append(s.data, body[:half]...)
			fd.mu.Unlock()
			w.Header().Set("Range", fmt.Sprintf("bytes=0-%d", half-1))
			w.WriteHeader(http.StatusPermanentRedirect)
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(2 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertRanges(t, fd, "bytes 0-262143/524288", "bytes 131072-393215/524288", "bytes 393216-524287/524288")
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatal("data differs")
	}
}

func TestUploadServerErrorProbesStatusThenResumes(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 2 { // second chunk fails without storing anything
			writeGoogleError(w, http.StatusServiceUnavailable, "backendError", "try again")
			return true
		}
		return false
	}
	c, sleeps := newTestClient(t, fd)
	data := payload(3 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertRanges(t, fd, "bytes 0-262143/786432", "bytes 262144-524287/786432", "bytes */786432", "bytes 262144-524287/786432", "bytes 524288-786431/786432")
	probe := fd.requests("put")[2]
	if probe.ContentLength != 0 || len(probe.Body) != 0 {
		t.Fatalf("probe sent %d bytes (Content-Length %d)", len(probe.Body), probe.ContentLength)
	}
	if len(sleeps.all()) != 1 {
		t.Fatalf("sleeps = %v, want one backoff before the probe", sleeps.all())
	}
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatal("data differs")
	}
}

func TestUploadDroppedConnectionProbesAndResumesFromConfirmedOffset(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, body []byte, n int, s *session) bool {
		if n == 2 { // server stored the chunk but the connection died before the reply
			fd.mu.Lock()
			s.data = append(s.data, body...)
			fd.mu.Unlock()
			conn, _, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return true
			}
			_ = conn.Close()
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(3 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertRanges(t, fd, "bytes 0-262143/786432", "bytes 262144-524287/786432", "bytes */786432", "bytes 524288-786431/786432")
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatal("data differs")
	}
}

func TestUploadProbeReportsAlreadyComplete(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, body []byte, n int, s *session) bool {
		if n == 1 {
			fd.mu.Lock()
			s.data = append(s.data, body...)
			fd.mu.Unlock()
			writeGoogleError(w, http.StatusBadGateway, "", "bad gateway")
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(testChunk)
	id, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if err != nil || id != "file-1" {
		t.Fatalf("Upload = %q, %v", id, err)
	}
	assertRanges(t, fd, "bytes 0-262143/262144", "bytes */262144")
}

func TestUploadProbeWithoutRangeRestartsAtZero(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, s *session) bool {
		if n == 2 { // the server lost everything
			fd.mu.Lock()
			s.data = nil
			fd.mu.Unlock()
			writeGoogleError(w, http.StatusInternalServerError, "", "boom")
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(2 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertRanges(t, fd, "bytes 0-262143/524288", "bytes 262144-524287/524288", "bytes */524288", "bytes 0-262143/524288", "bytes 262144-524287/524288")
	if !bytes.Equal(fd.sessionData("sess-1"), data) {
		t.Fatal("data differs")
	}
}

func TestUploadInvalidSessionStartsNewSessionOnce(t *testing.T) {
	for _, status := range []int{http.StatusNotFound, http.StatusGone, http.StatusBadRequest} {
		t.Run(fmt.Sprint(status), func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, _ int, _ *session) bool {
				if r.URL.Query().Get("upload_id") == "sess-1" {
					writeGoogleError(w, status, "notFound", "session expired")
					return true
				}
				return false
			}
			c, _ := newTestClient(t, fd)
			data := payload(2 * testChunk)
			if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
				t.Fatal(err)
			}
			if fd.count("init") != 2 {
				t.Fatalf("sessions = %d, want 2", fd.count("init"))
			}
			assertRanges(t, fd, "bytes 0-262143/524288", "bytes 0-262143/524288", "bytes 262144-524287/524288")
			if !bytes.Equal(fd.sessionData("sess-2"), data) {
				t.Fatal("data differs")
			}
		})
	}
}

func TestUploadInvalidSessionTwiceFails(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusNotFound, "notFound", "session expired")
		return true
	}
	c, _ := newTestClient(t, fd)
	data := payload(testChunk)
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrSessionInvalid) {
		t.Fatalf("err = %v, want ErrSessionInvalid", err)
	}
	if fd.count("init") != 2 || fd.count("put") != 2 {
		t.Fatalf("init %d put %d, want 2 and 2", fd.count("init"), fd.count("put"))
	}
}

func TestUploadRateLimitBacksOffThenResumes(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		switch n {
		case 2:
			writeGoogleError(w, http.StatusTooManyRequests, "rateLimitExceeded", "slow down")
			return true
		case 3:
			writeGoogleError(w, http.StatusForbidden, "userRateLimitExceeded", "slow down")
			return true
		}
		return false
	}
	c, sleeps := newTestClient(t, fd)
	data := payload(2 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	assertRanges(t, fd, "bytes 0-262143/524288", "bytes 262144-524287/524288", "bytes */524288", "bytes */524288", "bytes 262144-524287/524288")
	if got := sleeps.all(); len(got) != 2 || got[0] != 10*time.Millisecond || got[1] != 20*time.Millisecond {
		t.Fatalf("sleeps = %v, want [10ms 20ms]", got)
	}
}

func TestUploadRateLimitIsBounded(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusTooManyRequests, "rateLimitExceeded", "slow down")
		return true
	}
	c, sleeps := newTestClient(t, fd)
	data := payload(testChunk)
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, ErrRateLimited) {
		t.Fatalf("err = %v, want ErrRateLimited", err)
	}
	if got := len(sleeps.all()); got != 5 || fd.count("put") != 6 {
		t.Fatalf("sleeps %d puts %d, want 5 and 6", got, fd.count("put"))
	}
}

func TestUploadQuotaErrorsAreFatal(t *testing.T) {
	t.Run("init", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.init = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			writeGoogleError(w, http.StatusForbidden, "storageQuotaExceeded", "The user's Drive storage quota has been exceeded.")
			return true
		}
		c, _ := newTestClient(t, fd)
		data := payload(10)
		_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), 10)
		if !errors.Is(err, ErrQuota) || fd.count("init") != 1 || fd.count("put") != 0 {
			t.Fatalf("err = %v, init %d put %d", err, fd.count("init"), fd.count("put"))
		}
	})
	t.Run("chunk", func(t *testing.T) {
		fd := newFakeDrive(t)
		fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
			writeGoogleError(w, http.StatusForbidden, "userUploadLimitExceeded", "daily upload limit")
			return true
		}
		c, _ := newTestClient(t, fd)
		data := payload(10)
		_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), 10)
		if !errors.Is(err, ErrQuota) || fd.count("init") != 1 || fd.count("put") != 1 {
			t.Fatalf("err = %v, init %d put %d", err, fd.count("init"), fd.count("put"))
		}
	})
}

func TestUploadFolderNotFound(t *testing.T) {
	fd := newFakeDrive(t)
	fd.init = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusNotFound, "notFound", "File not found: folder-a.")
		return true
	}
	c, _ := newTestClient(t, fd)
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, ErrNotFound) || errors.Is(err, ErrSessionInvalid) || fd.count("init") != 1 {
		t.Fatalf("err = %v init %d", err, fd.count("init"))
	}
}

func TestUploadChunkUnauthorizedRefreshesOnce(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, r *http.Request, _ []byte, n int, _ *session) bool {
		if n == 2 {
			fd.mu.Lock()
			fd.revoked["ya29.access-1"] = true
			fd.mu.Unlock()
			writeGoogleError(w, http.StatusUnauthorized, "authError", "expired")
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(2 * testChunk)
	if _, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data))); err != nil {
		t.Fatal(err)
	}
	if fd.count("token") != 2 {
		t.Fatalf("token calls = %d, want 2", fd.count("token"))
	}
	assertRanges(t, fd, "bytes 0-262143/524288", "bytes 262144-524287/524288", "bytes 262144-524287/524288")
}

func TestUploadRejectsBadInputWithoutRequests(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	ctx := context.Background()
	cases := []struct {
		name     string
		folder   string
		file     string
		body     io.ReadSeeker
		size     int64
		wantKind error
	}{
		{"too large", "folder-a", "b", bytes.NewReader(nil), MaxFileSize + 1, ErrFileTooLarge},
		{"negative", "folder-a", "b", bytes.NewReader(nil), -1, ErrSizeMismatch},
		{"short body", "folder-a", "b", bytes.NewReader([]byte("abc")), 4, ErrSizeMismatch},
		{"long body", "folder-a", "b", bytes.NewReader([]byte("abcde")), 4, ErrSizeMismatch},
		{"nil body", "folder-a", "b", nil, 4, ErrInvalidArgument},
		{"empty folder", "", "b", bytes.NewReader([]byte("abcd")), 4, ErrInvalidArgument},
		{"odd folder", "folder/../x", "b", bytes.NewReader([]byte("abcd")), 4, ErrInvalidArgument},
		{"empty name", "folder-a", "", bytes.NewReader([]byte("abcd")), 4, ErrInvalidArgument},
		{"control name", "folder-a", "a\nb", bytes.NewReader([]byte("abcd")), 4, ErrInvalidArgument},
	}
	for _, tc := range cases {
		if _, err := c.Upload(ctx, tc.folder, tc.file, tc.body, tc.size); !errors.Is(err, tc.wantKind) {
			t.Errorf("%s: err = %v, want %v", tc.name, err, tc.wantKind)
		}
	}
	if n := len(fd.requests("")); n != 0 {
		t.Fatalf("bad input made %d requests", n)
	}
	if MaxFileSize != 5<<40 {
		t.Fatalf("MaxFileSize = %d", MaxFileSize)
	}
}

// shrinkingReader reports size bytes on Seek(End) but returns fewer on read.
type shrinkingReader struct {
	*bytes.Reader
	size int64
}

func (s *shrinkingReader) Seek(off int64, whence int) (int64, error) {
	if whence == io.SeekEnd {
		return s.size, nil
	}
	return s.Reader.Seek(off, whence)
}

func TestUploadSourceShrinkingMidUploadIsSizeMismatch(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	data := payload(testChunk + 10)
	body := &shrinkingReader{Reader: bytes.NewReader(data), size: 2 * testChunk}
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", body, 2*testChunk)
	if !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("err = %v, want ErrSizeMismatch", err)
	}
	if fd.count("put") != 1 {
		t.Fatalf("puts = %d, want 1 (the second chunk is short)", fd.count("put"))
	}
}

func TestUploadResponseTimeoutProbesAndResumes(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, r *http.Request, body []byte, n int, s *session) bool {
		if n == 1 { // store the chunk, then hang until the client gives up
			fd.mu.Lock()
			s.data = append(s.data, body...)
			fd.mu.Unlock()
			<-r.Context().Done()
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	c.responseTimeout = 100 * time.Millisecond
	data := payload(2 * testChunk)
	done := make(chan error, 1)
	go func() {
		_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
		done <- err
	}()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Upload did not recover from a hung response")
	}
	assertRanges(t, fd, "bytes 0-262143/524288", "bytes */524288", "bytes 262144-524287/524288")
}

func TestUploadStopsOnContextCancel(t *testing.T) {
	fd := newFakeDrive(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 2 {
			cancel()
			writeGoogleError(w, http.StatusServiceUnavailable, "", "down")
			return true
		}
		return false
	}
	c, _ := newTestClient(t, fd)
	data := payload(3 * testChunk)
	_, err := c.Upload(ctx, "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	if fd.count("put") != 2 {
		t.Fatalf("puts = %d after cancel, want 2", fd.count("put"))
	}

	_, err = c.Upload(ctx, "folder-a", "b.tar.gz", bytes.NewReader(data), int64(len(data)))
	if !errors.Is(err, context.Canceled) || fd.count("init") != 1 {
		t.Fatalf("pre-canceled Upload err = %v, init %d", err, fd.count("init"))
	}
}

func TestUploadBackoffHonoursContext(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusTooManyRequests, "", "slow down")
		return true
	}
	c, _ := newTestClient(t, fd)
	c.sleep = sleepCtx
	c.backoffBase, c.backoffMax = time.Hour, time.Hour
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err := c.Upload(ctx, "folder-a", "b.tar.gz", bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > 10*time.Second {
		t.Fatalf("err = %v after %s", err, time.Since(start))
	}
}
