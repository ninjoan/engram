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
	// DefaultTimeout bounds a whole request, including the upload body, when
	// the caller's HTTP client sets no timeout.
	DefaultTimeout = time.Hour
	// DefaultCheckAccessTimeout bounds CheckAccess when ctx has no deadline.
	DefaultCheckAccessTimeout = 30 * time.Second

	defaultContentType = "application/octet-stream"
	emptyPayloadSHA256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"
)

// Config describes an S3-compatible destination.
type Config struct {
	Endpoint        string // scheme://host[:port], e.g. https://<account>.r2.cloudflarestorage.com
	Region          string // defaults to DefaultRegion
	Bucket          string
	AccessKeyID     string
	SecretAccessKey string
	// HTTPClient is optional. It is copied, never mutated; redirects are
	// always refused and a zero Timeout becomes DefaultTimeout.
	HTTPClient *http.Client
}

// Client talks to one bucket of an S3-compatible endpoint.
type Client struct {
	scheme          string
	host            string
	bucket          string
	region          string
	accessKeyID     string
	secretAccessKey string
	httpClient      *http.Client
	now             func() time.Time
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
	region := strings.TrimSpace(cfg.Region)
	if region == "" {
		region = DefaultRegion
	}

	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	if hc.Timeout == 0 {
		hc.Timeout = DefaultTimeout
	}
	// Never follow a redirect: the signed request (and its credentials scope)
	// must only ever reach the configured endpoint.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	return &Client{
		scheme:          scheme,
		host:            host,
		bucket:          cfg.Bucket,
		region:          region,
		accessKeyID:     cfg.AccessKeyID,
		secretAccessKey: cfg.SecretAccessKey,
		httpClient:      hc,
		now:             time.Now,
	}, nil
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
// SHA-256, rewound and then sent. size must equal that length and be at most
// MaxObjectSize.
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
	var reqBody io.Reader = http.NoBody
	if size > 0 {
		reqBody = io.LimitReader(body, size)
	}
	return c.do(ctx, op, http.MethodPut, "/"+c.bucket+"/"+key, nil, reqBody, size, payloadHash, contentType)
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
// a signed ListObjectsV2 request for at most one key.
func (c *Client) CheckAccess(ctx context.Context) error {
	const op = "CheckAccess"
	if err := ctx.Err(); err != nil {
		return &Error{Op: op, Kind: err}
	}
	if _, ok := ctx.Deadline(); !ok {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, DefaultCheckAccessTimeout)
		defer cancel()
	}
	query := url.Values{"list-type": {"2"}, "max-keys": {"1"}}
	return c.do(ctx, op, http.MethodGet, "/"+c.bucket, query, http.NoBody, 0, emptyPayloadSHA256, "")
}

func (c *Client) do(ctx context.Context, op, method, path string, query url.Values, body io.Reader, size int64, payloadHash, contentType string) error {
	u := &url.URL{
		Scheme:   c.scheme,
		Host:     c.host,
		Path:     path,
		RawPath:  canonicalURI(path),
		RawQuery: canonicalQueryString(query),
	}
	req, err := http.NewRequestWithContext(ctx, method, u.String(), body)
	if err != nil {
		return fmt.Errorf("s3client: %s: build request: %w", op, err)
	}
	req.URL = u
	req.Host = c.host
	req.ContentLength = size

	amzDate := c.now().UTC()
	in := signingInput{
		method: method,
		path:   path,
		query:  query,
		headers: map[string]string{
			"host":                 c.host,
			"x-amz-content-sha256": payloadHash,
			"x-amz-date":           amzDate.Format(amzDateFormat),
		},
		payloadHash: payloadHash,
		time:        amzDate,
		region:      c.region,
	}
	req.Header.Set("X-Amz-Content-Sha256", payloadHash)
	req.Header.Set("X-Amz-Date", in.headers["x-amz-date"])
	if contentType != "" {
		req.Header.Set("Content-Type", contentType)
	}
	req.Header.Set("Authorization", authorization(c.accessKeyID, c.secretAccessKey, in))

	resp, err := c.httpClient.Do(req)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &Error{Op: op, Kind: ctxErr, Err: err}
		}
		var urlErr *url.Error
		if errors.As(err, &urlErr) && urlErr.Timeout() {
			return &Error{Op: op, Kind: ErrNetwork, Err: fmt.Errorf("request timed out: %w", urlErr.Err)}
		}
		return &Error{Op: op, Kind: ErrNetwork, Err: err}
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return c.responseError(op, resp)
	}
	_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxErrorBody))
	return nil
}
