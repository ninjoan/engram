// Package gdrive is a minimal Google Drive API v3 client for OAuth user
// credentials, built on the standard library. It holds a refresh token for
// the least-privilege drive.file scope (the app only sees files and folders
// it created) and supports exactly three operations: EnsureFolder, a
// read-only CheckAccess and a resumable Upload. It never deletes or trashes
// anything; backup retention is the account owner's concern.
//
// Requests only ever reach https://accounts.google.com,
// https://oauth2.googleapis.com and https://www.googleapis.com, and
// redirects are always refused.
package gdrive

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
	"unicode"
)

const (
	// Scope is the only OAuth scope this client requests or accepts.
	Scope = "https://www.googleapis.com/auth/drive.file"
	// FolderMimeType identifies Drive folders.
	FolderMimeType = "application/vnd.google-apps.folder"
	// UploadContentType is the media type of every uploaded file.
	UploadContentType = "application/gzip"
	// ChunkAlignment is the Drive requirement for every non-final chunk of a
	// resumable upload: its size must be a multiple of 256 KiB.
	ChunkAlignment = int64(256) << 10
	// ChunkSize is the size of each resumable upload chunk (8 MiB).
	ChunkSize = int64(8) << 20
	// MaxFileSize is the largest file Drive accepts (5 TiB).
	MaxFileSize = int64(5) << 40

	// DefaultRequestTimeout bounds every request that carries no upload
	// chunk (token refresh, folder list/create, session start, status probe).
	DefaultRequestTimeout = 30 * time.Second
	// DefaultStallTimeout aborts a chunk PUT whose body makes no progress
	// for this long, measured from the transport's first body read so
	// connection setup is never counted. The chunk is then recovered with a
	// status probe.
	DefaultStallTimeout = 2 * time.Minute
	// DefaultResponseTimeout bounds the wait for the response to a chunk
	// once its whole body was handed to the connection.
	DefaultResponseTimeout = 5 * time.Minute

	tokenRefreshSkew   = time.Minute
	defaultMaxRetries  = 5
	maxUploadSessions  = 2
	defaultBackoffBase = time.Second
	defaultBackoffMax  = 32 * time.Second

	defaultDialTimeout         = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultIdleConnTimeout     = 90 * time.Second

	authURL         = "https://accounts.google.com/o/oauth2/v2/auth"
	googleTokenURL  = "https://oauth2.googleapis.com/token"
	googleAPIURL    = "https://www.googleapis.com/drive/v3"
	googleUploadURL = "https://www.googleapis.com/upload/drive/v3/files"
)

// ChunkSize must be a positive multiple of ChunkAlignment; these fail to
// compile otherwise (type mismatch, or a negative array length).
var (
	_ [0]struct{} = [ChunkSize % ChunkAlignment]struct{}{}
	_ [ChunkSize/ChunkAlignment - 1]struct{}
)

// Config holds OAuth user credentials for one Google account. Formatting a
// Config with any fmt verb never prints ClientSecret or RefreshToken, and
// they are never JSON-encoded.
type Config struct {
	ClientID     string
	ClientSecret string `json:"-"`
	RefreshToken string `json:"-"`
	// HTTPClient is optional. It is copied, never mutated; redirects are
	// always refused. A nil Transport becomes one with dial, TLS handshake,
	// response header and idle connection timeouts.
	HTTPClient *http.Client `json:"-"`
	// Clock is optional (defaults to time.Now); it decides access token expiry.
	Clock func() time.Time `json:"-"`

	// Test seams, settable only by in-package tests. baseURL routes every
	// call to one loopback origin; chunkSize overrides ChunkSize and must
	// still be a multiple of ChunkAlignment.
	baseURL   string
	chunkSize int64
}

// Client uploads to the Drive of the account behind one refresh token. It is
// safe for concurrent use. Formatting a Client never prints its credentials.
type Client struct {
	clientID     string
	clientSecret string
	refreshToken string
	hc           *http.Client
	now          func() time.Time
	ep           endpoints
	tok          *tokenCache

	chunkSize       int64
	requestTimeout  time.Duration
	stallTimeout    time.Duration
	responseTimeout time.Duration
	maxRetries      int
	backoffBase     time.Duration
	backoffMax      time.Duration
	sleep           func(context.Context, time.Duration) error
	jitter          func(time.Duration) time.Duration
}

// tokenCache holds the access token. mu guards the fields and is never held
// across a request; flight is the refresh in progress, shared by every
// caller that needs a token meanwhile.
type tokenCache struct {
	mu     sync.Mutex
	access string
	expiry time.Time
	flight *tokenFlight
}

// tokenFlight is one token refresh. done closes once token and err are set.
type tokenFlight struct {
	done  chan struct{}
	token string
	err   error
}

// New validates cfg and returns a Client. It makes no network call. Errors
// never echo credentials.
func New(cfg Config) (*Client, error) {
	if strings.TrimSpace(cfg.ClientID) == "" || cfg.ClientSecret == "" || cfg.RefreshToken == "" {
		return nil, fmt.Errorf("gdrive: %w: client ID, client secret and refresh token are required", ErrInvalidConfig)
	}
	for _, v := range []string{cfg.ClientID, cfg.ClientSecret, cfg.RefreshToken} {
		if strings.IndexFunc(v, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return nil, fmt.Errorf("gdrive: %w: credentials must not contain spaces or control characters", ErrInvalidConfig)
		}
	}
	ep := googleEndpoints()
	if cfg.baseURL != "" {
		var err error
		if ep, err = loopbackEndpoints(cfg.baseURL); err != nil {
			return nil, err
		}
	}
	chunk := ChunkSize
	if cfg.chunkSize != 0 {
		if cfg.chunkSize < 0 || cfg.chunkSize%ChunkAlignment != 0 {
			return nil, fmt.Errorf("gdrive: %w: chunk size must be a positive multiple of 256 KiB", ErrInvalidConfig)
		}
		chunk = cfg.chunkSize
	}
	c := newClient(cfg.HTTPClient, ep)
	c.clientID, c.clientSecret, c.refreshToken = cfg.ClientID, cfg.ClientSecret, cfg.RefreshToken
	c.chunkSize = chunk
	if cfg.Clock != nil {
		c.now = cfg.Clock
	}
	return c, nil
}

func newClient(hc *http.Client, ep endpoints) *Client {
	return &Client{
		hc:              safeHTTPClient(hc),
		now:             time.Now,
		ep:              ep,
		tok:             &tokenCache{},
		chunkSize:       ChunkSize,
		requestTimeout:  DefaultRequestTimeout,
		stallTimeout:    DefaultStallTimeout,
		responseTimeout: DefaultResponseTimeout,
		maxRetries:      defaultMaxRetries,
		backoffBase:     defaultBackoffBase,
		backoffMax:      defaultBackoffMax,
		sleep:           sleepCtx,
		jitter:          randomJitter,
	}
}

// safeHTTPClient copies hc (or a fresh client), refuses every redirect and
// fills in a bounded transport.
func safeHTTPClient(in *http.Client) *http.Client {
	hc := &http.Client{}
	if in != nil {
		copied := *in
		hc = &copied
	}
	if hc.Transport == nil {
		hc.Transport = &http.Transport{
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
	// Never follow a redirect: bearer tokens and upload bytes must only
	// reach the allowlisted Google hosts. A 308 is returned as is, which the
	// resumable protocol uses as "Resume Incomplete".
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return hc
}

func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}

func randomJitter(d time.Duration) time.Duration {
	if d <= 0 {
		return 0
	}
	return rand.N(d + 1)
}

// endpoints are the absolute URLs the client calls and the origins it may reach.
type endpoints struct {
	token, api, upload string
	allowed            map[string]bool // "scheme://host[:port]"
}

func googleEndpoints() endpoints {
	return endpoints{
		token:  googleTokenURL,
		api:    googleAPIURL,
		upload: googleUploadURL,
		allowed: map[string]bool{
			"https://accounts.google.com":   true,
			"https://oauth2.googleapis.com": true,
			"https://www.googleapis.com":    true,
		},
	}
}

// loopbackEndpoints routes every call to one loopback origin (tests only).
func loopbackEndpoints(base string) (endpoints, error) {
	u, err := url.Parse(base)
	if err != nil || u.Host == "" || u.Hostname() == "" || u.User != nil ||
		(u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" {
		return endpoints{}, fmt.Errorf("gdrive: %w: endpoint override must be a bare scheme://host:port", ErrInvalidConfig)
	}
	scheme := strings.ToLower(u.Scheme)
	if (scheme != "http" && scheme != "https") || !isLoopbackHost(u.Hostname()) {
		return endpoints{}, fmt.Errorf("gdrive: %w: endpoint override is only allowed for loopback hosts", ErrInvalidConfig)
	}
	origin := scheme + "://" + strings.ToLower(u.Host)
	return endpoints{
		token:   origin + "/token",
		api:     origin + "/drive/v3",
		upload:  origin + "/upload/drive/v3/files",
		allowed: map[string]bool{origin: true},
	}, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

// permits reports whether a request to u may be sent.
func (e endpoints) permits(u *url.URL) bool {
	return u != nil && u.User == nil && u.Opaque == "" &&
		e.allowed[strings.ToLower(u.Scheme)+"://"+strings.ToLower(u.Host)]
}

const opTokenRefresh = "TokenRefresh"

// accessToken returns a cached access token or waits for a refresh. Callers
// share one refresh at a time; each waiter stops waiting as soon as its own
// ctx ends. The refresh runs on a context detached from the caller that
// started it (so its cancellation never fails the other waiters), bounded
// by refreshBudget.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.tok.mu.Lock()
	if c.tok.access != "" && c.now().Before(c.tok.expiry) {
		tok := c.tok.access
		c.tok.mu.Unlock()
		return tok, nil
	}
	if err := ctx.Err(); err != nil {
		c.tok.mu.Unlock()
		return "", &Error{Op: opTokenRefresh, Kind: err}
	}
	f := c.tok.flight
	if f == nil {
		f = &tokenFlight{done: make(chan struct{})}
		c.tok.flight = f
		go c.runRefresh(context.WithoutCancel(ctx), f)
	}
	c.tok.mu.Unlock()
	select {
	case <-f.done:
		return f.token, f.err
	case <-ctx.Done():
		return "", &Error{Op: opTokenRefresh, Kind: ctx.Err()}
	}
}

// refreshBudget bounds one shared refresh: every attempt the retry loop in
// do may make (each already bounded by requestTimeout) plus the longest
// backoff between them, so a single hung attempt is retried rather than
// ending the refresh.
func (c *Client) refreshBudget() time.Duration {
	attempts := time.Duration(c.maxRetries + 1)
	return attempts*c.requestTimeout + time.Duration(c.maxRetries)*c.backoffMax
}

// runRefresh performs flight f and caches its token.
func (c *Client) runRefresh(base context.Context, f *tokenFlight) {
	budget := c.refreshBudget()
	ctx, cancel := context.WithTimeout(base, budget)
	defer cancel()
	tok, ttl, err := c.refresh(ctx)
	if err != nil && ctx.Err() != nil && errors.Is(err, context.DeadlineExceeded) {
		// The refresh's own bound, not a caller's deadline.
		err = &Error{Op: opTokenRefresh, Kind: ErrNetwork, Err: &timeoutError{msg: fmt.Sprintf("token refresh timed out after %s", budget)}}
	}
	c.tok.mu.Lock()
	if err == nil {
		skew := tokenRefreshSkew
		if ttl < 2*skew {
			skew = ttl / 2
		}
		c.tok.access, c.tok.expiry = tok, c.now().Add(ttl-skew)
	}
	f.token, f.err = tok, err
	c.tok.flight = nil
	c.tok.mu.Unlock()
	close(f.done)
}

// invalidate drops tok from the cache (all tokens when tok is empty).
func (t *tokenCache) invalidate(tok string) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if tok == "" || t.access == tok {
		t.access = ""
	}
}

// do sends an API request with bounded retries: a 401 refreshes the access
// token once; rate limits, 5xx responses and network errors back off
// exponentially with jitter up to maxRetries times.
func (c *Client) do(ctx context.Context, cl call, auth bool) (*response, error) {
	refreshed := false
	for retries := 0; ; {
		if auth {
			tok, err := c.accessToken(ctx)
			if err != nil {
				return nil, err
			}
			cl.token = tok
		}
		resp, err := c.roundTrip(ctx, cl)
		var retryAfter time.Duration
		if err == nil {
			if resp.status >= 200 && resp.status < 300 {
				return resp, nil
			}
			if auth && resp.status == http.StatusUnauthorized && !refreshed {
				refreshed = true
				c.tok.invalidate(cl.token)
				continue
			}
			retryAfter = parseRetryAfter(resp.header)
			err = c.responseError(cl, resp)
		}
		if !retryable(err) || retries >= c.maxRetries || (cl.noAmbiguousRetry && ambiguous(err)) {
			return nil, err
		}
		if err := c.backoff(ctx, cl.op, retries, retryAfter); err != nil {
			return nil, err
		}
		retries++
	}
}

// backoff waits base*2^attempt (capped at backoffMax) with jitter in its
// upper half, or the server's Retry-After when longer (also capped).
func (c *Client) backoff(ctx context.Context, op string, attempt int, retryAfter time.Duration) error {
	d := c.backoffMax
	if attempt < 30 && c.backoffBase<<attempt < c.backoffMax {
		d = c.backoffBase << attempt
	}
	d = d/2 + c.jitter(d-d/2)
	if retryAfter > d {
		d = min(retryAfter, c.backoffMax)
	}
	if err := c.sleep(ctx, d); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return &Error{Op: op, Kind: ctxErr}
		}
		return &Error{Op: op, Kind: err}
	}
	return nil
}

// ambiguous reports a failure after which the request may or may not have
// taken effect (no answer, or a server error).
func ambiguous(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return e.Kind == ErrNetwork || (e.Kind == ErrUnexpected && e.StatusCode >= 500)
}

func retryable(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	switch {
	case errors.Is(e.Kind, context.Canceled), errors.Is(e.Kind, context.DeadlineExceeded):
		return false
	case e.Kind == ErrRateLimited, e.Kind == ErrNetwork:
		return true
	case e.Kind == ErrUnexpected && e.StatusCode >= 500:
		return true
	}
	return false
}
