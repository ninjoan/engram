package s3client

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
	"unicode/utf8"
)

// W1: no fmt verb on Config, *Config, Client or *Client prints the secret.
func TestFormattingNeverPrintsSecret(t *testing.T) {
	cfg := Config{Endpoint: "https://r2.example.com", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret}
	c := newTestClient(t, cfg)
	type wrapper struct{ Cfg Config }
	values := map[string]any{
		"Config":         cfg,
		"*Config":        &cfg,
		"Client":         *c,
		"*Client":        c,
		"nested Config":  wrapper{Cfg: cfg},
		"nested *Config": &wrapper{Cfg: cfg},
	}
	forbidden := []string{testSecret, testAccessKey, "s3cr3t", hex.EncodeToString([]byte(testSecret)), strings.ToUpper(hex.EncodeToString([]byte(testSecret)))}
	for name, v := range values {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%d", "%x", "%X"} {
			out := fmt.Sprintf(verb, v)
			for _, f := range forbidden {
				if strings.Contains(out, f) {
					t.Fatalf("%s with %s leaks %q: %s", name, verb, f, out)
				}
			}
			switch verb {
			case "%v", "%+v", "%#v", "%s", "%q":
				if !strings.Contains(out, "****0001") || !strings.Contains(out, "REDACTED") || !strings.Contains(out, testBucket) {
					t.Fatalf("%s with %s should show bucket, masked key id and a redaction marker: %s", name, verb, out)
				}
			}
		}
	}
	var nilCfg *Config
	var nilClient *Client
	if got := fmt.Sprintf("%v %v", nilCfg, nilClient); got != "<nil> <nil>" {
		t.Fatalf("nil pointers formatted as %q", got)
	}
	short := Config{Endpoint: "https://r2.example.com", Bucket: testBucket, AccessKeyID: "AK12", SecretAccessKey: "x"}
	if out := fmt.Sprintf("%+v", short); strings.Contains(out, "AK12") {
		t.Fatalf("short access key id must be fully masked: %s", out)
	}
}

// R3-001: no overall client timeout; transport-level timeouts instead.
func TestDefaultHTTPClientHasNoOverallTimeout(t *testing.T) {
	c := newTestClient(t, Config{Endpoint: "https://r2.example.com"})
	if c.httpClient.Timeout != 0 {
		t.Fatalf("default client has an overall Timeout %s that would abort slow healthy uploads", c.httpClient.Timeout)
	}
	tr, ok := c.httpClient.Transport.(*http.Transport)
	if !ok {
		t.Fatalf("default transport = %T, want *http.Transport", c.httpClient.Transport)
	}
	if tr.DialContext == nil || tr.TLSHandshakeTimeout <= 0 || tr.ResponseHeaderTimeout <= 0 || tr.IdleConnTimeout <= 0 {
		t.Fatalf("default transport lacks dial/TLS/response-header/idle timeouts: tls=%s rh=%s idle=%s", tr.TLSHandshakeTimeout, tr.ResponseHeaderTimeout, tr.IdleConnTimeout)
	}
	if c.stallTimeout != DefaultStallTimeout || c.responseTimeout != DefaultResponseTimeout {
		t.Fatalf("stall = %s response = %s", c.stallTimeout, c.responseTimeout)
	}
	c = newTestClient(t, Config{Endpoint: "https://r2.example.com", StallTimeout: 7 * time.Second, HTTPClient: &http.Client{}})
	if c.stallTimeout != 7*time.Second || c.httpClient.Timeout != 0 {
		t.Fatalf("custom stall = %s, zero caller timeout became %s", c.stallTimeout, c.httpClient.Timeout)
	}
	if _, ok := c.httpClient.Transport.(*http.Transport); !ok {
		t.Fatalf("caller client without transport should get the tuned default, got %T", c.httpClient.Transport)
	}
	_, err := New(Config{Endpoint: "https://r2.example.com", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret, StallTimeout: -time.Second})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("negative stall timeout err = %v", err)
	}
}

// scriptedSeeker serves content; after the hash pass (second Seek) it switches
// to later and, when delay > 0, sleeps before each send-pass read.
type scriptedSeeker struct {
	mu    sync.Mutex
	r     *bytes.Reader
	later []byte
	seeks int
	chunk int
	delay time.Duration
}

func newScripted(first, later []byte) *scriptedSeeker {
	return &scriptedSeeker{r: bytes.NewReader(first), later: later}
}

func (s *scriptedSeeker) Seek(off int64, whence int) (int64, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.seeks++
	if s.seeks == 2 && s.later != nil {
		s.r = bytes.NewReader(s.later)
	}
	return s.r.Seek(off, whence)
}

func (s *scriptedSeeker) Read(p []byte) (int, error) {
	s.mu.Lock()
	sending := s.seeks >= 2
	s.mu.Unlock()
	if sending && s.delay > 0 {
		time.Sleep(s.delay)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.chunk > 0 && len(p) > s.chunk {
		p = p[:s.chunk]
	}
	return s.r.Read(p)
}

func TestPutObjectSlowButSteadyUploadIsNotAborted(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	c.stallTimeout = 300 * time.Millisecond
	payload := bytes.Repeat([]byte("s"), 16<<10)
	src := newScripted(payload, nil)
	src.chunk, src.delay = 1<<10, 60*time.Millisecond // ~1s total, > 3x the stall timeout
	if err := c.PutObject(context.Background(), "slow.tar.gz", src, int64(len(payload)), ""); err != nil {
		t.Fatalf("slow but steady upload aborted: %v", err)
	}
	if rec := onlyRequest(t, fake); !bytes.Equal(rec.Body, payload) {
		t.Fatalf("server got %d bytes, want %d", len(rec.Body), len(payload))
	}
}

func waitErr(t *testing.T, what string, fn func() error) error {
	t.Helper()
	done := make(chan error, 1)
	go func() { done <- fn() }()
	select {
	case err := <-done:
		return err
	case <-time.After(5 * time.Second):
		t.Fatalf("%s did not return", what)
		return nil
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

func TestPutObjectStallIsReportedAsStalled(t *testing.T) {
	srv, _ := newFakeS3(t, false, nil)
	stalling := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			conn, err := (&net.Dialer{}).DialContext(ctx, network, addr)
			if err != nil {
				return nil, err
			}
			return &stallConn{Conn: conn, limit: 8 << 10, closed: make(chan struct{})}, nil
		},
	}}
	c := newTestClient(t, Config{Endpoint: srv.URL, HTTPClient: stalling})
	c.stallTimeout = 200 * time.Millisecond
	payload := bytes.Repeat([]byte("z"), 64<<10)

	err := waitErr(t, "stalled PutObject", func() error {
		return c.PutObject(context.Background(), "stall.tar.gz", bytes.NewReader(payload), int64(len(payload)), "")
	})
	if !errors.Is(err, ErrNetwork) || !errors.Is(err, ErrUploadStalled) {
		t.Fatalf("err = %v, want ErrNetwork + ErrUploadStalled", err)
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("stall must not look like a caller cancellation: %v", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "stalled") || !strings.Contains(msg, "200ms") {
		t.Fatalf("stall error should say what happened: %s", msg)
	}
	assertNoCredentials(t, err)
}

func TestPutObjectResponseTimeoutAfterBodySent(t *testing.T) {
	release := make(chan struct{})
	srv, fake := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	c := newTestClient(t, Config{Endpoint: srv.URL})
	c.stallTimeout = 10 * time.Second
	c.responseTimeout = 200 * time.Millisecond
	for _, payload := range [][]byte{[]byte("whole body"), nil} {
		err := waitErr(t, "PutObject awaiting response", func() error {
			return c.PutObject(context.Background(), "k.tar.gz", bytes.NewReader(payload), int64(len(payload)), "")
		})
		if !errors.Is(err, ErrNetwork) || errors.Is(err, ErrUploadStalled) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
			t.Fatalf("size %d: err = %v, want a network response timeout", len(payload), err)
		}
		if msg := err.Error(); !strings.Contains(msg, "timed out") || !strings.Contains(msg, "response") {
			t.Fatalf("size %d: error should say it timed out waiting for the response: %s", len(payload), msg)
		}
	}
	if n := len(fake.requests()); n != 2 {
		t.Fatalf("requests = %d", n)
	}
}

func TestCallerDeadlineStaysAuthoritative(t *testing.T) {
	release := make(chan struct{})
	srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	c := newTestClient(t, Config{Endpoint: srv.URL})
	c.checkAccessTimeout = 10 * time.Second
	for op, call := range map[string]func(context.Context) error{
		"PutObject": func(ctx context.Context) error {
			return c.PutObject(ctx, "k.tar.gz", strings.NewReader("payload"), 7, "")
		},
		"CheckAccess": c.CheckAccess,
	} {
		ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
		err := waitErr(t, op, func() error { return call(ctx) })
		cancel()
		if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrNetwork) {
			t.Fatalf("%s err = %v, want the caller's context.DeadlineExceeded", op, err)
		}
	}
}

// R3-002: the client's own deadlines are network timeouts, not context errors.
func TestCheckAccessInternalDeadlineIsNetworkTimeout(t *testing.T) {
	release := make(chan struct{})
	srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	c := newTestClient(t, Config{Endpoint: srv.URL})
	c.checkAccessTimeout = 150 * time.Millisecond
	err := waitErr(t, "CheckAccess", func() error { return c.CheckAccess(context.Background()) })
	if !errors.Is(err, ErrNetwork) || errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) {
		t.Fatalf("internal deadline err = %v, want ErrNetwork only", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "timed out") || !strings.Contains(msg, "150ms") {
		t.Fatalf("internal deadline error should name the timeout: %s", msg)
	}

	hc := newTestClient(t, Config{Endpoint: srv.URL, HTTPClient: &http.Client{Timeout: 150 * time.Millisecond}})
	for op, call := range map[string]func() error{
		"CheckAccess": func() error { return hc.CheckAccess(context.Background()) },
		"PutObject": func() error {
			return hc.PutObject(context.Background(), "k.tar.gz", strings.NewReader("x"), 1, "")
		},
	} {
		err := waitErr(t, op, call)
		if !errors.Is(err, ErrNetwork) || errors.Is(err, context.DeadlineExceeded) {
			t.Fatalf("%s http.Client timeout err = %v, want ErrNetwork only", op, err)
		}
		if !strings.Contains(err.Error(), "timed out") {
			t.Fatalf("%s http.Client timeout error should say timed out: %v", op, err)
		}
	}
}

// R3-003: a PUT on a keep-alive connection the server dropped is retried.
func TestPutObjectRetriesOnStaleKeepAliveConnection(t *testing.T) {
	var first atomic.Bool
	first.Store(true)
	staleHit := make(chan bool, 1)
	srv, fake := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodGet && first.CompareAndSwap(true, false) {
			conn, brw, err := w.(http.Hijacker).Hijack()
			if err != nil {
				t.Errorf("hijack: %v", err)
				return
			}
			_, _ = brw.WriteString("HTTP/1.1 200 OK\r\nContent-Type: application/xml\r\nContent-Length: 0\r\n\r\n")
			_ = brw.Flush()
			go func() {
				_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
				_, err := brw.ReadByte() // the next request arrives on the kept-alive conn...
				_ = conn.Close()         // ...and the server drops it without answering
				staleHit <- err == nil
			}()
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	c := newTestClient(t, Config{Endpoint: srv.URL})
	if err := c.CheckAccess(context.Background()); err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	payload := []byte("retry me on a fresh connection")
	if err := c.PutObject(context.Background(), "k.tar.gz", bytes.NewReader(payload), int64(len(payload)), ""); err != nil {
		t.Fatalf("PutObject on stale keep-alive connection: %v", err)
	}
	select {
	case hit := <-staleHit:
		if !hit {
			t.Fatalf("the PUT never reached the stale connection; test is inconclusive")
		}
	case <-time.After(5 * time.Second):
		t.Fatalf("stale connection goroutine did not finish")
	}
	reqs := fake.requests()
	if len(reqs) != 2 || reqs[1].Method != http.MethodPut || !bytes.Equal(reqs[1].Body, payload) {
		t.Fatalf("requests = %+v, want CheckAccess then one full PUT", len(reqs))
	}
	assertValidSignature(t, reqs[1], "auto")
}

// R3-004: the source changing between the hash pass and the send pass.
func TestPutObjectDetectsSourceChangedAfterHashing(t *testing.T) {
	srv, fake := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	})
	c := newTestClient(t, Config{Endpoint: srv.URL})
	for name, later := range map[string]string{"shrank": "abc", "grew": "abcdefgh"} {
		err := waitErr(t, name, func() error {
			return c.PutObject(context.Background(), "k.tar.gz", newScripted([]byte("abcdef"), []byte(later)), 6, "")
		})
		if !errors.Is(err, ErrSizeMismatch) || errors.Is(err, ErrNetwork) {
			t.Fatalf("%s: err = %v, want ErrSizeMismatch only", name, err)
		}
		if !strings.Contains(err.Error(), "after it was hashed") {
			t.Fatalf("%s: error should explain the source changed: %v", name, err)
		}
	}
	// A shrunken source never delivers the declared length. (A grown source
	// may deliver exactly the hashed first 6 bytes: the transport caps reads
	// at Content-Length, so growth is only seen afterwards.)
	for _, rec := range fake.requests() {
		if bytes.HasPrefix(rec.Body, []byte("abc")) && len(rec.Body) == 6 && !bytes.Equal(rec.Body, []byte("abcdef")) {
			t.Fatalf("server received bytes that were never hashed: %q", rec.Body)
		}
	}

	hashSrv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusBadRequest)
		_, _ = io.WriteString(w, errorXML("XAmzContentSHA256Mismatch", "The provided 'x-amz-content-sha256' header does not match what was computed."))
	})
	c = newTestClient(t, Config{Endpoint: hashSrv.URL})
	err := c.PutObject(context.Background(), "k.tar.gz", newScripted([]byte("abcdef"), []byte("abcxyz")), 6, "")
	var s3err *Error
	if !errors.Is(err, ErrUnexpectedStatus) || !errors.As(err, &s3err) || s3err.Code != "XAmzContentSHA256Mismatch" {
		t.Fatalf("same-size change err = %v, want ErrUnexpectedStatus XAmzContentSHA256Mismatch", err)
	}
}

// R3-005: sanitize and RequestID parsing.
func TestSanitizeServerText(t *testing.T) {
	c := newTestClient(t, Config{Endpoint: "https://r2.example.com"})
	if got := c.sanitize("a\x00b\tc\nd\x7fe\u0085f\x1bg", 100); got != "a b c d e f g" {
		t.Fatalf("control characters: %q", got)
	}
	if got := c.sanitize("  a   b\r\n\t c  ", 100); got != "a b c" {
		t.Fatalf("whitespace: %q", got)
	}
	if got := c.sanitize(strings.Repeat("x", 500), 300); got != strings.Repeat("x", 300)+"…" {
		t.Fatalf("byte bound: len %d", len(got))
	}
	if got := c.sanitize(strings.Repeat("x", 300), 300); got != strings.Repeat("x", 300) {
		t.Fatalf("exact limit must not be truncated: len %d", len(got))
	}
	got := c.sanitize(strings.Repeat("é", 200), 301)
	if !utf8.ValidString(got) || got != strings.Repeat("é", 150)+"…" || len(got) > 301+len("…") {
		t.Fatalf("utf-8 truncation: %q", got)
	}
	got = c.sanitize("key "+testAccessKey+" secret "+testSecret, 300)
	if got != "key [REDACTED] secret [REDACTED]" {
		t.Fatalf("redaction: %q", got)
	}
}

func TestResponseErrorParsesRequestID(t *testing.T) {
	for name, tc := range map[string]struct{ xmlID, want string }{
		"plain":          {"REQ123", "REQ123"},
		"whitespace":     {"  REQ&#9;789\n ", "REQ 789"},
		"bounded":        {strings.Repeat("r", 200), strings.Repeat("r", 128) + "…"},
		"missing":        {"", ""},
		"redacts key id": {testAccessKey, "[REDACTED]"},
	} {
		srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusInternalServerError)
			_, _ = io.WriteString(w, `<Error><Code>InternalError</Code><Message>m</Message><RequestId>`+tc.xmlID+`</RequestId></Error>`)
		})
		err := newTestClient(t, Config{Endpoint: srv.URL}).CheckAccess(context.Background())
		var s3err *Error
		if !errors.As(err, &s3err) || s3err.RequestID != tc.want {
			t.Fatalf("%s: RequestID = %q, want %q (err %v)", name, s3err.RequestID, tc.want, err)
		}
	}
}

// Wire level: the fake server re-derives the canonical request from the raw
// request URI and headers it received.
func TestWireSignatureForAwkwardKeys(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	keys := map[string]string{
		"dir/a b c.tar.gz":      "/engram-backups/dir/a%20b%20c.tar.gz",
		"dir/ünïcødé-日本.tar.gz": "/engram-backups/dir/%C3%BCn%C3%AFc%C3%B8d%C3%A9-%E6%97%A5%E6%9C%AC.tar.gz",
		"dir/a+b+c.tar.gz":      "/engram-backups/dir/a%2Bb%2Bc.tar.gz",
		"dir/100%.tar.gz":       "/engram-backups/dir/100%25.tar.gz",
		"dir/~tilde~.tar.gz":    "/engram-backups/dir/~tilde~.tar.gz",
		"dir/a%2Fb.tar.gz":      "/engram-backups/dir/a%252Fb.tar.gz",
		"x/ a+%2F~ é=&?#;.tgz":  "/engram-backups/x/%20a%2B%252F~%20%C3%A9%3D%26%3F%23%3B.tgz",
	}
	for key, wantURI := range keys {
		before := len(fake.requests())
		if err := c.PutObject(context.Background(), key, strings.NewReader("k"), 1, ""); err != nil {
			t.Fatalf("key %q: %v", key, err)
		}
		reqs := fake.requests()
		if len(reqs) != before+1 {
			t.Fatalf("key %q: requests = %d", key, len(reqs)-before)
		}
		rec := reqs[len(reqs)-1]
		if rec.RequestURI != wantURI {
			t.Fatalf("key %q: wire URI = %q, want %q", key, rec.RequestURI, wantURI)
		}
		decoded, err := url.PathUnescape(rec.RequestURI)
		if err != nil || decoded != "/"+testBucket+"/"+key {
			t.Fatalf("key %q: server decodes %q (%v)", key, decoded, err)
		}
		assertValidSignature(t, rec, "auto")
	}
}

type countingTransport struct{ n atomic.Int64 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.n.Add(1)
	return nil, errors.New("network must not be used")
}

func TestEndpointRejectionTableMakesNoNetworkCalls(t *testing.T) {
	rt := &countingTransport{}
	cases := map[string]error{
		"http://127.0.0.1.evil.com":           ErrInsecureEndpoint,
		"http://127.0.0.1.evil.com:9000":      ErrInsecureEndpoint,
		"http://localhost@evil.com":           ErrInvalidConfig,
		"https://localhost@evil.com":          ErrInvalidConfig,
		"https://user:hunter2@r2.example.com": ErrInvalidConfig,
		"http://user:hunter2@localhost:9000":  ErrInvalidConfig,
		"http://evil.com#@localhost":          ErrInvalidConfig,
		"http://evil.com?@localhost":          ErrInvalidConfig,
		"http://localhost.evil.com":           ErrInsecureEndpoint,
		"http://0x7f000001":                   ErrInsecureEndpoint,
		"http://2130706433":                   ErrInsecureEndpoint,
		"http://127.1":                        ErrInsecureEndpoint,
		"http://[fe80::1%25lo]":               ErrInsecureEndpoint,
		"http://[::1%25lo]:9000":              ErrInsecureEndpoint,
		"https://r2.example.com/bucket":       ErrInvalidConfig,
		"https://r2.example.com/%2F":          ErrInvalidConfig,
		"http://localhost:9000/../":           ErrInvalidConfig,
		"https://r2.example.com/?x=1":         ErrInvalidConfig,
		"https://r2.example.com?x=1":          ErrInvalidConfig,
		"https://r2.example.com?":             ErrInvalidConfig,
		"https://r2.example.com#frag":         ErrInvalidConfig,
		"r2.example.com":                      ErrInvalidConfig,
		"//r2.example.com":                    ErrInvalidConfig,
	}
	for ep, want := range cases {
		c, err := New(Config{Endpoint: ep, Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret, HTTPClient: &http.Client{Transport: rt}})
		if c != nil || !errors.Is(err, want) {
			t.Errorf("endpoint %q: client=%v err = %v, want %v", ep, c != nil, err, want)
		}
		assertNoCredentials(t, err)
	}
	if n := rt.n.Load(); n != 0 {
		t.Fatalf("endpoint validation made %d network calls", n)
	}
}
