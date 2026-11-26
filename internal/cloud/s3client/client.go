// Package s3client is a minimal S3-compatible client (Cloudflare R2, MinIO)
// built on the standard library. It signs requests with AWS Signature
// Version 4, uses path-style addressing and supports exactly two operations:
// a single-request PutObject and a read-only CheckAccess. It never deletes
// objects; backup retention belongs to the bucket's lifecycle rules.
package s3client

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

const (
	// MaxObjectSize is the S3 limit for a single PUT request (5 GiB).
	MaxObjectSize = int64(5) << 30
	// DefaultRegion is used when Config.Region is empty (Cloudflare R2).
	DefaultRegion = "auto"
	// DefaultCheckAccessTimeout bounds CheckAccess when ctx has no deadline.
	DefaultCheckAccessTimeout = 30 * time.Second
	// DefaultStallTimeout aborts a PutObject whose request body makes no
	// progress (no bytes accepted by the connection) for this long. There is
	// no overall upload deadline: a slow but steady upload of any allowed
	// size completes; only the caller's ctx bounds its total duration.
	DefaultStallTimeout = 2 * time.Minute
	// DefaultResponseTimeout bounds the wait for the server's response once
	// the whole request body has been handed to the connection.
	DefaultResponseTimeout = 5 * time.Minute

	defaultDialTimeout         = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultIdleConnTimeout     = 90 * time.Second

	defaultContentType = "application/octet-stream"
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Config describes an S3-compatible destination. Formatting a Config with
// any fmt verb never prints SecretAccessKey and masks AccessKeyID.
type Config struct {
	Endpoint string // scheme://host[:port], e.g. https://<account>.r2.cloudflarestorage.com
	Region   string // defaults to DefaultRegion
	Bucket   string
	// The credentials are never JSON-encoded; Format redacts them too.
	AccessKeyID     string `json:"-"`
	SecretAccessKey string `json:"-"`
	// HTTPClient is optional. It is copied, never mutated; redirects are
	// always refused. Its Timeout is kept as is (zero means no overall
	// deadline); a nil Transport becomes one with dial, TLS handshake,
	// response header and idle connection timeouts.
	HTTPClient *http.Client
	// StallTimeout defaults to DefaultStallTimeout; negative is invalid.
	StallTimeout time.Duration
}

// Client talks to one bucket of an S3-compatible endpoint. Formatting a
// Client with any fmt verb never prints its credentials.
type Client struct {
	scheme          string
	host            string
	bucket          string
	region          string
	accessKeyID     string
	secretAccessKey string
	httpClient      *http.Client
	now             func() time.Time

	checkAccessTimeout time.Duration
	stallTimeout       time.Duration
	responseTimeout    time.Duration
}

var bucketNamePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$`)

// New validates cfg and returns a Client. Errors never echo credentials.
func New(cfg Config) (*Client, error) {
	scheme, host, err := parseEndpoint(cfg.Endpoint)
	if err != nil {
		return nil, err
	}
	if !bucketNamePattern.MatchString(cfg.Bucket) {
		return nil, fmt.Errorf("s3client: %w: bucket name must be 3-63 lowercase letters, digits, dots or hyphens", ErrInvalidConfig)
	}
	if cfg.AccessKeyID == "" || cfg.SecretAccessKey == "" {
		return nil, fmt.Errorf("s3client: %w: access key ID and secret access key are required", ErrInvalidConfig)
	}
	if cfg.StallTimeout < 0 {
		return nil, fmt.Errorf("s3client: %w: stall timeout must not be negative", ErrInvalidConfig)
	}
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = DefaultRegion
	}
	stall := cfg.StallTimeout
	if stall == 0 {
		stall = DefaultStallTimeout
	}

	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	if hc.Transport == nil {
		hc.Transport = newDefaultTransport()
	}
	// Never follow a redirect: the signed request (and its credentials scope)
	// must only ever reach the configured endpoint.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{
		scheme:             scheme,
		host:               host,
		bucket:             cfg.Bucket,
		region:             region,
		accessKeyID:        cfg.AccessKeyID,
		secretAccessKey:    cfg.SecretAccessKey,
		httpClient:         hc,
		now:                time.Now,
		checkAccessTimeout: DefaultCheckAccessTimeout,
		stallTimeout:       stall,
		responseTimeout:    DefaultResponseTimeout,
	}, nil
}

// newDefaultTransport bounds every connection phase without bounding the
// time it takes to stream a large body.
func newDefaultTransport() *http.Transport {
	return &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           (&net.Dialer{Timeout: defaultDialTimeout, KeepAlive: 30 * time.Second}).DialContext,
		ForceAttemptHTTP2:     true,
		MaxIdleConns:          10,
		IdleConnTimeout:       defaultIdleConnTimeout,
		TLSHandshakeTimeout:   defaultTLSHandshakeTimeout,
		ResponseHeaderTimeout: DefaultResponseTimeout,
		ExpectContinueTimeout: time.Second,
	}
}

func parseEndpoint(raw string) (scheme, host string, err error) {
	invalid := func(reason string) (string, string, error) {
		return "", "", fmt.Errorf("s3client: %w: endpoint %s", ErrInvalidConfig, reason)
	}
	u, perr := url.Parse(strings.TrimSpace(raw))
	if perr != nil || raw == "" {
		return invalid("must be an absolute URL such as https://<account>.r2.cloudflarestorage.com")
	}
	if u.User != nil {
		return invalid("must not contain user info; set the access key fields instead")
	}
	if u.Host == "" || u.Hostname() == "" {
		return invalid("has no host")
	}
	if (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return invalid("must not contain a path, query or fragment (path-style bucket addressing is added by the client)")
	}
	switch scheme = strings.ToLower(u.Scheme); scheme {
	case "https":
	case "http":
		if !isLoopbackHost(u.Hostname()) {
			return "", "", fmt.Errorf("s3client: %w", ErrInsecureEndpoint)
		}
	default:
		return invalid("scheme must be https")
	}
	return scheme, u.Host, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// PutObject uploads body as key with a single signed PUT. The whole content of
// body from offset 0 is the object; it is read once to compute the payload
// SHA-256, rewound and then sent (and rewound again if the transport retries
// on a dropped keep-alive connection). size must equal that length and be at
// most MaxObjectSize; a body whose length changes after hashing fails with
// ErrSizeMismatch (if it grew, the server may still have stored exactly the
// hashed bytes; same-length changes are rejected by the server as an
// ErrUnexpectedStatus XAmzContentSHA256Mismatch). There is no overall deadline: the upload is aborted with
// ErrUploadStalled when no body bytes are sent for the stall timeout, with an
// ErrNetwork timeout when the response does not arrive in time, and with the
// ctx error when ctx ends first.
func (c *Client) PutObject(ctx context.Context, key string, body io.ReadSeeker, size int64, contentType string) error {
	const op = "PutObject"
	if err := validateKey(key); err != nil {
		return fmt.Errorf("s3client: %s: %w", op, err)
	}
	if body == nil {
		return fmt.Errorf("s3client: %s: body is required", op)
	}
	if size < 0 {
		return fmt.Errorf("s3client: %s: %w: negative size %d", op, ErrSizeMismatch, size)
	}
	if size > MaxObjectSize {
		return fmt.Errorf("s3client: %s: %w: size is %d bytes", op, ErrObjectTooLarge, size)
	}
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Kind: err}
	}
	payloadHash, err := hashSeeker(ctx, body, size)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &Error{Op: op, Kind: ctxErr}
		}
		return fmt.Errorf("s3client: %s: %w", op, err)
	}
	if contentType == "" {
		contentType = defaultContentType
	}
	return c.do(ctx, request{
		op:          op,
		method:      http.MethodPut,
		path:        "/" + c.bucket + "/" + key,
		payloadHash: payloadHash,
		contentType: contentType,
		upload:      &upload{src: body, size: size},
	})
}

// hashSeeker returns the hex SHA-256 of body's content and leaves body at offset 0.
func hashSeeker(ctx context.Context, body io.ReadSeeker, size int64) (string, error) {
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind body: %w", err)
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(ctxReader{ctx: ctx, r: body}, size+1))
	if err != nil {
		return "", fmt.Errorf("read body: %w", err)
	}
	if n != size {
		if n > size {
			return "", fmt.Errorf("%w: body is longer than %d bytes", ErrSizeMismatch, size)
		}
		return "", fmt.Errorf("%w: body has %d bytes, declared %d", ErrSizeMismatch, n, size)
	}
	if _, err := body.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind body: %w", err)
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

type ctxReader struct {
	ctx context.Context
	r   io.Reader
}

func (r ctxReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	return r.r.Read(p)
}

// CheckAccess proves the credentials can reach the bucket without writing:
// a signed ListObjectsV2 request for at most one key. When ctx has no
// deadline the request is bounded by DefaultCheckAccessTimeout, reported as
// an ErrNetwork timeout.
func (c *Client) CheckAccess(ctx context.Context) error {
	const op = "CheckAccess"
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Kind: err}
	}
	return c.do(ctx, request{
		op:          op,
		method:      http.MethodGet,
		path:        "/" + c.bucket,
		query:       url.Values{"list-type": {"2"}, "max-keys": {"1"}},
		payloadHash: emptyPayloadSHA256,
		timeout:     c.checkAccessTimeout,
	})
}

type request struct {
	op, method, path         string
	query                    url.Values
	payloadHash, contentType string
	upload                   *upload       // request body; nil for none
	timeout                  time.Duration // internal deadline applied when ctx has none
}

// do sends one signed request. callerCtx stays authoritative: when it ends,
// its error is the Kind. Deadlines owned by the client (CheckAccess timeout,
// stall and response watchdogs) are reported as ErrNetwork instead.
func (c *Client) do(callerCtx context.Context, r request) error {
	ctx, cancel := context.WithCancelCause(callerCtx)
	defer cancel(nil)
	if _, ok := callerCtx.Deadline(); !ok && r.timeout > 0 {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeoutCause(ctx, r.timeout,
			&timeoutError{msg: fmt.Sprintf("request timed out after %s without a response", r.timeout)})
		defer cancelTimeout()
	}

	u := &url.URL{
		Scheme:   c.scheme,
		Host:     c.host,
		Path:     r.path,
		RawPath:  canonicalURI(r.path),
		RawQuery: canonicalQueryString(r.query),
	}
	req, err := http.NewRequestWithContext(ctx, r.method, u.String(), http.NoBody)
	if err != nil {
		return fmt.Errorf("s3client: %s: build request: %w", r.op, err)
	}
	req.URL = u
	req.Host = c.host
	req.ContentLength = 0

	if r.upload != nil {
		wd := newWatchdog(cancel, c.stallTimeout, c.responseTimeout, r.upload.size == 0)
		defer wd.stop()
		if r.upload.size > 0 {
			r.upload.ctx, r.upload.wd = ctx, wd
			req.Body = io.NopCloser(r.upload.reader())
			req.GetBody = r.upload.getBody
			req.ContentLength = r.upload.size
			// Marks the PUT replayable so the transport may resend it on a
			// keep-alive connection the server already closed. A nil value
			// is never sent on the wire. Re-PUTting the same signed body
			// is idempotent.
			req.Header["Idempotency-Key"] = nil
		}
	}

	amzDate := c.now().UTC()
	in := signingInput{
		method: r.method,
		path:   r.path,
		query:  r.query,
		headers: map[string]string{
			"host":                 c.host,
			"x-amz-content-sha256": r.payloadHash,
			"x-amz-date":           amzDate.Format(amzDateFormat),
		},
		payloadHash: r.payloadHash,
		time:        amzDate,
		region:      c.region,
	}
	req.Header.Set("X-Amz-Content-Sha256", r.payloadHash)
	req.Header.Set("X-Amz-Date", in.headers["x-amz-date"])
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}
	req.Header.Set("Authorization", authorization(c.accessKeyID, c.secretAccessKey, in))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return c.transportError(callerCtx, ctx, r, err)
	}
	defer resp.Body.Close()
	if r.upload != nil {
		if mismatch := r.upload.mismatchErr(); mismatch != nil {
			return fmt.Errorf("s3client: %s: %w", r.op, mismatch)
		}
	}
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.responseError(r.op, resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	return nil
}

// transportError classifies a failed round trip.
func (c *Client) transportError(callerCtx, ctx context.Context, r request, err error) error {
	if ctxErr := callerCtx.Err(); ctxErr != nil {
		return &Error{Op: r.op, Kind: ctxErr, Err: err}
	}
	if r.upload != nil {
		if mismatch := r.upload.mismatchErr(); mismatch != nil {
			return fmt.Errorf("s3client: %s: %w", r.op, mismatch)
		}
	}
	if ctx.Err() != nil {
		// A deadline owned by this client fired; the transport error only
		// repeats "context canceled/deadline exceeded", so report the cause.
		return &Error{Op: r.op, Kind: ErrNetwork, Err: context.Cause(ctx)}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return &Error{Op: r.op, Kind: ErrNetwork, Err: &timeoutError{msg: "request timed out: " + urlErr.Err.Error()}}
	}
	return &Error{Op: r.op, Kind: ErrNetwork, Err: err}
}
