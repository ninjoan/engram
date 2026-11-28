package s3client

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

const (
	testAccessKey = "AKIDTESTACCESSKEY0001"
	testSecret    = "s3cr3t/TEST+SECRET=value0001"
	testBucket    = "engram-backups"
)

var testTime = time.Date(2026, 11, 25, 3, 4, 5, 0, time.UTC)

type recordedRequest struct {
	Method           string
	RequestURI       string
	Host             string
	Header           http.Header
	Body             []byte
	ContentLength    int64
	TransferEncoding []string
	Credential       string
	SignedHeaders    string
	Signature        string
	WantSignature    string
}

type fakeS3 struct {
	mu   sync.Mutex
	reqs []recordedRequest
}

func (f *fakeS3) requests() []recordedRequest {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]recordedRequest(nil), f.reqs...)
}

// newFakeS3 starts a loopback S3 stand-in that records every request and
// recomputes its SigV4 signature independently of the package code.
func newFakeS3(t *testing.T, tls bool, handler http.HandlerFunc) (*httptest.Server, *fakeS3) {
	t.Helper()
	f := &fakeS3{}
	h := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		rec := recordedRequest{
			Method:           r.Method,
			RequestURI:       r.RequestURI,
			Host:             r.Host,
			Header:           r.Header.Clone(),
			Body:             body,
			ContentLength:    r.ContentLength,
			TransferEncoding: r.TransferEncoding,
		}
		rec.Credential, rec.SignedHeaders, rec.Signature = parseAuthorization(r.Header.Get("Authorization"))
		if rec.SignedHeaders != "" {
			region := ""
			if parts := strings.Split(rec.Credential, "/"); len(parts) == 5 {
				region = parts[2]
			}
			rec.WantSignature = independentSignature(testSecret, region, r, strings.Split(rec.SignedHeaders, ";"))
		}
		f.mu.Lock()
		f.reqs = append(f.reqs, rec)
		f.mu.Unlock()
		if handler != nil {
			handler(w, r)
			return
		}
		w.WriteHeader(http.StatusOK)
	})
	var srv *httptest.Server
	if tls {
		srv = httptest.NewTLSServer(h)
	} else {
		srv = httptest.NewServer(h)
	}
	t.Cleanup(srv.Close)
	return srv, f
}

func parseAuthorization(h string) (credential, signedHeaders, sig string) {
	const prefix = "AWS4-HMAC-SHA256 "
	if !strings.HasPrefix(h, prefix) {
		return "", "", ""
	}
	for _, part := range strings.Split(h[len(prefix):], ",") {
		k, v, _ := strings.Cut(strings.TrimSpace(part), "=")
		switch k {
		case "Credential":
			credential = v
		case "SignedHeaders":
			signedHeaders = v
		case "Signature":
			sig = v
		}
	}
	return credential, signedHeaders, sig
}

func testEscape(s string) string {
	var b strings.Builder
	for _, c := range []byte(s) {
		if c >= 'A' && c <= 'Z' || c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || strings.IndexByte("-_.~", c) >= 0 {
			b.WriteByte(c)
			continue
		}
		b.WriteString("%" + strings.ToUpper(hex.EncodeToString([]byte{c})))
	}
	return b.String()
}

func testHMAC(key []byte, data string) []byte {
	m := hmac.New(sha256.New, key)
	m.Write([]byte(data))
	return m.Sum(nil)
}

// independentSignature recomputes SigV4 from what arrived on the wire.
func independentSignature(secret, region string, r *http.Request, signed []string) string {
	rawPath, _, _ := strings.Cut(r.RequestURI, "?")
	type pair struct{ k, v string }
	var pairs []pair
	for k, vs := range r.URL.Query() {
		for _, v := range vs {
			pairs = append(pairs, pair{testEscape(k), testEscape(v)})
		}
	}
	sort.Slice(pairs, func(i, j int) bool {
		if pairs[i].k != pairs[j].k {
			return pairs[i].k < pairs[j].k
		}
		return pairs[i].v < pairs[j].v
	})
	var q []string
	for _, p := range pairs {
		q = append(q, p.k+"="+p.v)
	}
	var hdrs strings.Builder
	for _, name := range signed {
		v := r.Header.Get(name)
		if name == "host" {
			v = r.Host
		}
		hdrs.WriteString(name + ":" + strings.TrimSpace(v) + "\n")
	}
	amzDate := r.Header.Get("X-Amz-Date")
	if len(amzDate) < 8 {
		return "missing x-amz-date"
	}
	canonical := strings.Join([]string{
		r.Method, rawPath, strings.Join(q, "&"), hdrs.String(), strings.Join(signed, ";"), r.Header.Get("X-Amz-Content-Sha256"),
	}, "\n")
	sum := sha256.Sum256([]byte(canonical))
	day := amzDate[:8]
	sts := "AWS4-HMAC-SHA256\n" + amzDate + "\n" + day + "/" + region + "/s3/aws4_request\n" + hex.EncodeToString(sum[:])
	k := testHMAC([]byte("AWS4"+secret), day)
	k = testHMAC(k, region)
	k = testHMAC(k, "s3")
	k = testHMAC(k, "aws4_request")
	return hex.EncodeToString(testHMAC(k, sts))
}

func newTestClient(t *testing.T, cfg Config) *Client {
	t.Helper()
	if cfg.Bucket == "" {
		cfg.Bucket = testBucket
	}
	if cfg.AccessKeyID == "" {
		cfg.AccessKeyID = testAccessKey
	}
	if cfg.SecretAccessKey == "" {
		cfg.SecretAccessKey = testSecret
	}
	c, err := New(cfg)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	c.now = func() time.Time { return testTime }
	return c
}

func assertNoCredentials(t *testing.T, err error) {
	t.Helper()
	if err == nil {
		return
	}
	msg := err.Error()
	for _, secret := range []string{testSecret, testAccessKey, exampleSecret, "hunter2"} {
		if strings.Contains(msg, secret) {
			t.Fatalf("error string leaks a credential %q: %s", secret, msg)
		}
	}
}

func assertValidSignature(t *testing.T, rec recordedRequest, wantRegion string) {
	t.Helper()
	wantCred := testAccessKey + "/20261125/" + wantRegion + "/s3/aws4_request"
	if rec.Credential != wantCred {
		t.Fatalf("credential = %q, want %q", rec.Credential, wantCred)
	}
	if rec.SignedHeaders != "host;x-amz-content-sha256;x-amz-date" {
		t.Fatalf("signed headers = %q", rec.SignedHeaders)
	}
	if rec.Signature == "" || rec.Signature != rec.WantSignature {
		t.Fatalf("signature = %q, independently recomputed %q", rec.Signature, rec.WantSignature)
	}
	if got := rec.Header.Get("X-Amz-Date"); got != "20261125T030405Z" {
		t.Fatalf("x-amz-date = %q", got)
	}
}

func onlyRequest(t *testing.T, f *fakeS3) recordedRequest {
	t.Helper()
	reqs := f.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want exactly one", len(reqs))
	}
	return reqs[0]
}

func sha256Hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

func TestPutObjectSendsSignedSinglePut(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	payload := []byte("engram cloud backup archive bytes")
	body := bytes.NewReader(payload)
	if _, err := body.Seek(7, io.SeekStart); err != nil { // the whole seeker content is uploaded
		t.Fatal(err)
	}
	key := "backups/engram-cloud-backup-20261125T030405Z.tar.gz"

	if err := c.PutObject(context.Background(), key, body, int64(len(payload)), "application/gzip"); err != nil {
		t.Fatalf("PutObject: %v", err)
	}

	reqs := fake.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d, want exactly one PUT", len(reqs))
	}
	rec := reqs[0]
	if rec.Method != http.MethodPut {
		t.Fatalf("method = %s", rec.Method)
	}
	if want := "/" + testBucket + "/" + key; rec.RequestURI != want {
		t.Fatalf("request URI = %q, want path-style %q", rec.RequestURI, want)
	}
	if rec.Host != strings.TrimPrefix(srv.URL, "http://") {
		t.Fatalf("host = %q", rec.Host)
	}
	if !bytes.Equal(rec.Body, payload) {
		t.Fatalf("body = %q, want %q", rec.Body, payload)
	}
	if rec.ContentLength != int64(len(payload)) || rec.Header.Get("Content-Length") != "33" || len(rec.TransferEncoding) != 0 {
		t.Fatalf("content-length = %d (%q) transfer-encoding = %v", rec.ContentLength, rec.Header.Get("Content-Length"), rec.TransferEncoding)
	}
	if got := rec.Header.Get("X-Amz-Content-Sha256"); got != sha256Hex(payload) {
		t.Fatalf("x-amz-content-sha256 = %q, want %q", got, sha256Hex(payload))
	}
	if got := rec.Header.Get("Content-Type"); got != "application/gzip" {
		t.Fatalf("content-type = %q", got)
	}
	assertValidSignature(t, rec, "auto")
}

func TestPutObjectEncodesKeySegments(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	payload := []byte("x")
	if err := c.PutObject(context.Background(), "backups/a b+c$~é.tar.gz", bytes.NewReader(payload), 1, ""); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	rec := onlyRequest(t, fake)
	if want := "/engram-backups/backups/a%20b%2Bc%24~%C3%A9.tar.gz"; rec.RequestURI != want {
		t.Fatalf("request URI = %q, want %q", rec.RequestURI, want)
	}
	if got := rec.Header.Get("Content-Type"); got != "application/octet-stream" {
		t.Fatalf("default content-type = %q", got)
	}
	assertValidSignature(t, rec, "auto")
}

func TestPutObjectEmptyBodySendsZeroLength(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	if err := c.PutObject(context.Background(), "empty.tar.gz", bytes.NewReader(nil), 0, "application/gzip"); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	rec := onlyRequest(t, fake)
	if rec.ContentLength != 0 || len(rec.TransferEncoding) != 0 || len(rec.Body) != 0 {
		t.Fatalf("content-length = %d transfer-encoding = %v body = %q", rec.ContentLength, rec.TransferEncoding, rec.Body)
	}
	if got := rec.Header.Get("X-Amz-Content-Sha256"); got != emptySHA256 {
		t.Fatalf("x-amz-content-sha256 = %q", got)
	}
	assertValidSignature(t, rec, "auto")
}

func TestPutObjectOverTLSWithCallerClient(t *testing.T) {
	srv, fake := newFakeS3(t, true, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL, Region: "us-east-1", HTTPClient: srv.Client()})
	if err := c.PutObject(context.Background(), "k.tar.gz", bytes.NewReader([]byte("tls")), 3, "application/gzip"); err != nil {
		t.Fatalf("PutObject: %v", err)
	}
	assertValidSignature(t, onlyRequest(t, fake), "us-east-1")
}

type countingSeeker struct {
	io.ReadSeeker
	reads int
}

func (c *countingSeeker) Read(p []byte) (int, error) {
	c.reads++
	return c.ReadSeeker.Read(p)
}

func TestPutObjectRejectsObjectsOverFiveGiB(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	body := &countingSeeker{ReadSeeker: bytes.NewReader([]byte("tiny"))}

	err := c.PutObject(context.Background(), "big.tar.gz", body, MaxObjectSize+1, "application/gzip")
	if !errors.Is(err, ErrObjectTooLarge) {
		t.Fatalf("err = %v, want ErrObjectTooLarge", err)
	}
	if !strings.Contains(err.Error(), "5 GiB") || !strings.Contains(err.Error(), "multipart") {
		t.Fatalf("error should explain the 5 GiB single PUT limit: %v", err)
	}
	if body.reads != 0 || len(fake.requests()) != 0 {
		t.Fatalf("oversize object must be rejected before reading (reads=%d) or sending (requests=%d)", body.reads, len(fake.requests()))
	}
	assertNoCredentials(t, err)

	// Exactly 5 GiB passes the limit check; the short body then fails the size check without sending.
	err = c.PutObject(context.Background(), "big.tar.gz", bytes.NewReader([]byte("tiny")), MaxObjectSize, "application/gzip")
	if errors.Is(err, ErrObjectTooLarge) || !errors.Is(err, ErrSizeMismatch) {
		t.Fatalf("5 GiB boundary err = %v, want ErrSizeMismatch only", err)
	}
	if len(fake.requests()) != 0 {
		t.Fatalf("requests = %d, want none", len(fake.requests()))
	}
}

func TestPutObjectRejectsSizeMismatch(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	for _, tc := range []struct {
		name string
		body string
		size int64
	}{
		{"body longer than size", "abcdef", 3},
		{"body shorter than size", "abc", 6},
		{"negative size", "abc", -1},
	} {
		err := c.PutObject(context.Background(), "k.tar.gz", strings.NewReader(tc.body), tc.size, "")
		if !errors.Is(err, ErrSizeMismatch) {
			t.Errorf("%s: err = %v, want ErrSizeMismatch", tc.name, err)
		}
	}
	if err := c.PutObject(context.Background(), "k.tar.gz", nil, 0, ""); err == nil {
		t.Errorf("nil body: want error")
	}
	if n := len(fake.requests()); n != 0 {
		t.Fatalf("requests = %d, want none", n)
	}
}

func TestPutObjectRejectsInvalidKeys(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	for _, key := range []string{"", "/abs.tar.gz", "a//b", "a/./b", "a/../b", "..", "a/", "ctl\x00.tar.gz", "bad\xff", strings.Repeat("k", 1025)} {
		err := c.PutObject(context.Background(), key, strings.NewReader("x"), 1, "")
		if !errors.Is(err, ErrInvalidKey) {
			t.Errorf("key %q: err = %v, want ErrInvalidKey", key, err)
		}
	}
	if n := len(fake.requests()); n != 0 {
		t.Fatalf("requests = %d, want none", n)
	}
}

func TestCheckAccessSendsSignedListObjectsV2(t *testing.T) {
	srv, fake := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/xml")
		_, _ = io.WriteString(w, `<?xml version="1.0" encoding="UTF-8"?><ListBucketResult><Name>engram-backups</Name><KeyCount>0</KeyCount><MaxKeys>1</MaxKeys></ListBucketResult>`)
	})
	c := newTestClient(t, Config{Endpoint: srv.URL + "/"})
	if err := c.CheckAccess(context.Background()); err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	reqs := fake.requests()
	if len(reqs) != 1 {
		t.Fatalf("requests = %d", len(reqs))
	}
	rec := reqs[0]
	if rec.Method != http.MethodGet || rec.RequestURI != "/engram-backups?list-type=2&max-keys=1" || len(rec.Body) != 0 {
		t.Fatalf("CheckAccess sent %s %s body=%q, want read-only GET ListObjectsV2", rec.Method, rec.RequestURI, rec.Body)
	}
	if got := rec.Header.Get("X-Amz-Content-Sha256"); got != emptySHA256 {
		t.Fatalf("x-amz-content-sha256 = %q", got)
	}
	assertValidSignature(t, rec, "auto")
}

func errorXML(code, message string) string {
	return `<?xml version="1.0" encoding="UTF-8"?><Error><Code>` + code + `</Code><Message>` + message + `</Message><RequestId>REQ123</RequestId></Error>`
}

func TestResponseErrorsAreTypedAndParsed(t *testing.T) {
	cases := []struct {
		name     string
		status   int
		body     string
		kind     error
		wantCode string
		wantMsg  string
	}{
		{"signature mismatch", 403, errorXML("SignatureDoesNotMatch", "The request signature we calculated does not match the signature you provided."), ErrAuth, "SignatureDoesNotMatch", "The request signature we calculated"},
		{"unknown access key", 403, errorXML("InvalidAccessKeyId", "The AWS Access Key Id you provided does not exist in our records."), ErrAuth, "InvalidAccessKeyId", "does not exist in our records"},
		{"access denied", 403, errorXML("AccessDenied", "Access Denied"), ErrAuth, "AccessDenied", "Access Denied"},
		{"unauthorized without body", 401, "", ErrAuth, "", ""},
		{"wrong region", 400, errorXML("AuthorizationHeaderMalformed", "The authorization header is malformed; the region is wrong"), ErrAuth, "AuthorizationHeaderMalformed", "region is wrong"},
		{"missing bucket", 404, errorXML("NoSuchBucket", "The specified bucket does not exist"), ErrBucketNotFound, "NoSuchBucket", "The specified bucket does not exist"},
		{"server error", 500, errorXML("InternalError", "We encountered an internal error."), ErrUnexpectedStatus, "InternalError", "internal error"},
		{"non-xml body", 503, "<html>bad gateway</html>", ErrUnexpectedStatus, "", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(tc.status)
				_, _ = io.WriteString(w, tc.body)
			})
			c := newTestClient(t, Config{Endpoint: srv.URL})
			for op, err := range map[string]error{
				"CheckAccess": c.CheckAccess(context.Background()),
				"PutObject":   c.PutObject(context.Background(), "k.tar.gz", strings.NewReader("x"), 1, ""),
			} {
				if !errors.Is(err, tc.kind) {
					t.Fatalf("%s err = %v, want kind %v", op, err, tc.kind)
				}
				for _, other := range []error{ErrAuth, ErrBucketNotFound, ErrUnexpectedStatus, ErrNetwork, ErrRedirect} {
					if other != tc.kind && errors.Is(err, other) {
						t.Fatalf("%s err = %v also matches %v", op, err, other)
					}
				}
				var s3err *Error
				if !errors.As(err, &s3err) {
					t.Fatalf("%s err %T is not *Error", op, err)
				}
				if s3err.Op != op || s3err.StatusCode != tc.status || s3err.Code != tc.wantCode || !strings.Contains(s3err.Message, tc.wantMsg) {
					t.Fatalf("%s parsed = %+v", op, s3err)
				}
				if tc.wantCode != "" && !strings.Contains(err.Error(), tc.wantCode) {
					t.Fatalf("%s error string %q lacks code", op, err)
				}
				assertNoCredentials(t, err)
			}
		})
	}
}

func TestErrorStringsNeverContainCredentials(t *testing.T) {
	srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		_, _ = io.WriteString(w, `<Error><Code>SignatureDoesNotMatch</Code><Message>key `+testAccessKey+` secret `+testSecret+` mismatch</Message><AWSAccessKeyId>`+testAccessKey+`</AWSAccessKeyId><StringToSign>AWS4-HMAC-SHA256 secret</StringToSign></Error>`)
	})
	c := newTestClient(t, Config{Endpoint: srv.URL})
	err := c.CheckAccess(context.Background())
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v", err)
	}
	assertNoCredentials(t, err)
	if strings.Contains(err.Error(), "AWS4-HMAC-SHA256") {
		t.Fatalf("error string echoes signing material: %v", err)
	}

	_, err = New(Config{Endpoint: "https://user:hunter2@r2.example.com", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("userinfo endpoint err = %v", err)
	}
	assertNoCredentials(t, err)
}

func TestRedirectsAreRefused(t *testing.T) {
	target, targetFake := newFakeS3(t, false, nil)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusTemporaryRedirect, http.StatusPermanentRedirect} {
		srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, target.URL+r.URL.Path, status)
		})
		permissive := &http.Client{CheckRedirect: func(*http.Request, []*http.Request) error { return nil }}
		for _, c := range []*Client{
			newTestClient(t, Config{Endpoint: srv.URL}),
			newTestClient(t, Config{Endpoint: srv.URL, HTTPClient: permissive}),
		} {
			for op, err := range map[string]error{
				"CheckAccess": c.CheckAccess(context.Background()),
				"PutObject":   c.PutObject(context.Background(), "k.tar.gz", strings.NewReader("x"), 1, ""),
			} {
				if !errors.Is(err, ErrRedirect) {
					t.Fatalf("status %d %s err = %v, want ErrRedirect", status, op, err)
				}
				assertNoCredentials(t, err)
			}
		}
		if permissive.CheckRedirect == nil {
			t.Fatalf("caller client was mutated")
		}
	}
	if n := len(targetFake.requests()); n != 0 {
		t.Fatalf("redirect target received %d requests; credentials followed a redirect", n)
	}
}

func TestNewValidatesEndpointAndConfig(t *testing.T) {
	ok := []string{
		"https://acct.r2.cloudflarestorage.com",
		"https://acct.r2.cloudflarestorage.com/",
		"HTTPS://minio.example.com:9000",
		"http://localhost:9000",
		"http://LOCALHOST:9000",
		"http://127.0.0.1:9000",
		"http://127.0.0.2",
		"http://[::1]:9000",
	}
	for _, ep := range ok {
		if _, err := New(Config{Endpoint: ep, Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret}); err != nil {
			t.Errorf("endpoint %q: unexpected err %v", ep, err)
		}
	}
	insecure := []string{"http://example.com", "http://127.0.0.1.nip.io:9000", "http://10.0.0.1:9000", "http://localhost.example.com", "http://foo.localhost"}
	for _, ep := range insecure {
		_, err := New(Config{Endpoint: ep, Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret})
		if !errors.Is(err, ErrInsecureEndpoint) {
			t.Errorf("endpoint %q: err = %v, want ErrInsecureEndpoint", ep, err)
		}
		assertNoCredentials(t, err)
	}
	invalid := []Config{
		{Endpoint: "", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "ftp://host", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host/base", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host?x=1", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host#frag", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host", Bucket: "", AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host", Bucket: "Bad_Bucket", AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host", Bucket: "a/b", AccessKeyID: testAccessKey, SecretAccessKey: testSecret},
		{Endpoint: "https://host", Bucket: testBucket, AccessKeyID: "", SecretAccessKey: testSecret},
		{Endpoint: "https://host", Bucket: testBucket, AccessKeyID: testAccessKey, SecretAccessKey: ""},
	}
	for _, cfg := range invalid {
		_, err := New(cfg)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("config %q/%q: err = %v, want ErrInvalidConfig", cfg.Endpoint, cfg.Bucket, err)
		}
		assertNoCredentials(t, err)
	}
}

func TestHTTPClientDefaultsAndCallerClientIsNotMutated(t *testing.T) {
	c := newTestClient(t, Config{Endpoint: "https://r2.example.com"})
	if c.httpClient.Timeout != 0 || c.httpClient.CheckRedirect == nil {
		t.Fatalf("default client timeout = %s, CheckRedirect set = %v", c.httpClient.Timeout, c.httpClient.CheckRedirect != nil)
	}
	callerTransport := &http.Transport{}
	caller := &http.Client{Timeout: 5 * time.Second, Transport: callerTransport}
	c = newTestClient(t, Config{Endpoint: "https://r2.example.com", HTTPClient: caller})
	if c.httpClient == caller || c.httpClient.Timeout != 5*time.Second || c.httpClient.CheckRedirect == nil || c.httpClient.Transport != callerTransport {
		t.Fatalf("caller client not copied with redirect refusal: %+v", c.httpClient)
	}
	if caller.CheckRedirect != nil {
		t.Fatalf("caller client was mutated")
	}
	c = newTestClient(t, Config{Endpoint: "https://r2.example.com", HTTPClient: &http.Client{}})
	if c.httpClient.Timeout != 0 {
		t.Fatalf("zero caller timeout must stay zero (no overall upload deadline), got %s", c.httpClient.Timeout)
	}
}

func TestContextCancellationStopsInFlightRequest(t *testing.T) {
	arrived := make(chan struct{}, 2)
	release := make(chan struct{})
	srv, _ := newFakeS3(t, false, func(w http.ResponseWriter, r *http.Request) {
		arrived <- struct{}{}
		select {
		case <-r.Context().Done():
		case <-release:
		}
	})
	t.Cleanup(func() { close(release) })
	c := newTestClient(t, Config{Endpoint: srv.URL})

	for op, call := range map[string]func(context.Context) error{
		"PutObject": func(ctx context.Context) error {
			return c.PutObject(ctx, "k.tar.gz", strings.NewReader("payload"), 7, "")
		},
		"CheckAccess": c.CheckAccess,
	} {
		ctx, cancel := context.WithCancel(context.Background())
		done := make(chan error, 1)
		go func() { done <- call(ctx) }()
		select {
		case <-arrived:
		case err := <-done:
			cancel()
			t.Fatalf("%s returned before reaching the server: %v", op, err)
		case <-time.After(5 * time.Second):
			cancel()
			t.Fatalf("%s never reached the server", op)
		}
		cancel()
		select {
		case err := <-done:
			if !errors.Is(err, context.Canceled) {
				t.Fatalf("%s err = %v, want context.Canceled", op, err)
			}
			assertNoCredentials(t, err)
		case <-time.After(5 * time.Second):
			t.Fatalf("%s did not stop after cancellation", op)
		}
	}
}

func TestCanceledContextSendsNothing(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	c := newTestClient(t, Config{Endpoint: srv.URL})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	body := &countingSeeker{ReadSeeker: strings.NewReader("payload")}
	if err := c.PutObject(ctx, "k.tar.gz", body, 7, ""); !errors.Is(err, context.Canceled) {
		t.Fatalf("PutObject err = %v", err)
	}
	if err := c.CheckAccess(ctx); !errors.Is(err, context.Canceled) {
		t.Fatalf("CheckAccess err = %v", err)
	}
	if body.reads != 0 || len(fake.requests()) != 0 {
		t.Fatalf("canceled context still read body (%d) or sent requests (%d)", body.reads, len(fake.requests()))
	}
}

func TestNetworkErrorsAreTyped(t *testing.T) {
	srv := httptest.NewServer(http.NotFoundHandler())
	endpoint := srv.URL
	srv.Close()
	c := newTestClient(t, Config{Endpoint: endpoint})
	for op, err := range map[string]error{
		"CheckAccess": c.CheckAccess(context.Background()),
		"PutObject":   c.PutObject(context.Background(), "k.tar.gz", strings.NewReader("x"), 1, ""),
	} {
		if !errors.Is(err, ErrNetwork) || errors.Is(err, ErrAuth) || errors.Is(err, ErrBucketNotFound) {
			t.Fatalf("%s err = %v, want ErrNetwork", op, err)
		}
		var s3err *Error
		if !errors.As(err, &s3err) || s3err.Op != op || s3err.StatusCode != 0 {
			t.Fatalf("%s err = %#v", op, err)
		}
		assertNoCredentials(t, err)
	}
}

// S9: retention is the operator's bucket lifecycle; the client exposes no way to delete.
func TestClientExposesNoDeleteOperation(t *testing.T) {
	typ := reflect.TypeOf(&Client{})
	var names []string
	for i := 0; i < typ.NumMethod(); i++ {
		names = append(names, typ.Method(i).Name)
	}
	// Format only renders a redacted view (W1); it performs no request.
	if !reflect.DeepEqual(names, []string{"CheckAccess", "Format", "PutObject"}) {
		t.Fatalf("exported Client methods = %v, want only CheckAccess, Format and PutObject", names)
	}
}
