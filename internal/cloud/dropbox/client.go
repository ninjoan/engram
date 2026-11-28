// Package dropbox is a minimal Dropbox API v2 client built on the standard
// library. It refreshes short-lived access tokens from an app key, app
// secret and refresh token, checks access without writing and uploads one
// file (a single request up to SimpleUploadLimit, an upload session above
// it). It talks only to the three fixed Dropbox hosts over HTTPS, refuses
// redirects and never removes or overwrites anything: retention of uploaded
// backups belongs to the account owner.
package dropbox

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// SimpleUploadLimit is the largest file sent with a single
	// /2/files/upload request (Dropbox allows at most 150 MiB there).
	SimpleUploadLimit = int64(150) << 20
	// ChunkSize is the upload session chunk size. Dropbox requires every
	// chunk but the last to be a multiple of 4 MiB.
	ChunkSize = int64(16) << 20
	// MaxFileSize is the Dropbox limit for a file uploaded with a session.
	MaxFileSize = int64(350_000_000_000)

	// DefaultStallTimeout aborts a request whose body makes no progress for
	// this long. It is armed by the transport's first body read, after the
	// connection is set up. There is no overall upload deadline: only the
	// caller's ctx bounds the total duration.
	DefaultStallTimeout = 2 * time.Minute
	// DefaultResponseTimeout bounds the wait for the response once an
	// upload request's body was handed to the connection.
	DefaultResponseTimeout = 5 * time.Minute
	// DefaultRPCTimeout bounds token, metadata and account requests.
	DefaultRPCTimeout = 60 * time.Second

	// refreshMargin renews an access token this long before it expires
	// (half its lifetime for tokens that live less than twice the margin).
	refreshMargin = 5 * time.Minute
	// defaultTokenLifetime is assumed when a token response has no usable
	// expires_in, so the access token is still cached (renewed after 55m).
	defaultTokenLifetime = time.Hour

	maxOffsetResyncs    = 8               // incorrect_offset corrections per upload
	maxRateLimitRetries = 4               // 429 retries per request
	maxRetryWait        = 5 * time.Minute // longest Retry-After honored
	maxTransientRetries = 5               // network/5xx retries per session chunk
	maxCommitAttempts   = 3               // attempts of a commit (upload or finish)
	maxBackoff          = 30 * time.Second
	maxRememberedTokens = 8 // recent access tokens redacted from server text

	defaultDialTimeout         = 30 * time.Second
	defaultTLSHandshakeTimeout = 10 * time.Second
	defaultIdleConnTimeout     = 90 * time.Second
)

// Production base URLs. Each endpoint kind is pinned to its own host.
const (
	authHost    = "api.dropbox.com"
	apiHost     = "api.dropboxapi.com"
	contentHost = "content.dropboxapi.com"
)

// Config holds the credentials of a Dropbox app authorized with a refresh
// token. Formatting a Config with any fmt verb or encoding it as JSON never
// prints AppSecret or RefreshToken.
type Config struct {
	AppKey       string
	AppSecret    string `json:"-"`
	RefreshToken string `json:"-"`
	// HTTPClient is optional. It is copied, never mutated; redirects are
	// always refused. Its Timeout is kept as is (zero means no overall
	// deadline); a nil Transport becomes one with dial, TLS handshake,
	// response header and idle connection timeouts.
	HTTPClient *http.Client `json:"-"`
	// Clock is optional (time.Now); it decides when a cached access token
	// must be renewed.
	Clock func() time.Time `json:"-"`
}

// endpoints are the base URLs of the token, RPC and content hosts. Only
// New's production values or loopback URLs (tests) are accepted.
type endpoints struct{ auth, api, content string }

var productionEndpoints = endpoints{
	auth:    "https://" + authHost,
	api:     "https://" + apiHost,
	content: "https://" + contentHost,
}

// tokenState caches the short-lived access token. mu guards the fields and
// is never held across a request; flight is the refresh in progress, shared
// by every caller that needs a token meanwhile.
type tokenState struct {
	mu     sync.Mutex
	access string
	expiry time.Time
	seen   []string // every access token issued, for redaction
	flight *tokenFlight
}

// tokenFlight is one token refresh. done closes once token and err are set.
type tokenFlight struct {
	done  chan struct{}
	token string
	err   error
}

// Client uploads to one Dropbox account. It is safe for concurrent use.
// Formatting a Client with any fmt verb never prints its credentials.
type Client struct {
	ep           endpoints
	appKey       string
	appSecret    string
	refreshToken string
	httpClient   *http.Client
	now          func() time.Time
	tok          *tokenState

	chunkSize       int64
	simpleLimit     int64
	sleep           func(context.Context, time.Duration) error
	stallTimeout    time.Duration
	responseTimeout time.Duration
	rpcTimeout      time.Duration
}

// New validates cfg and returns a Client for the production Dropbox hosts.
// It makes no network calls. Errors never echo credentials.
func New(cfg Config) (*Client, error) {
	return newClient(cfg, productionEndpoints)
}

// newClient is New with injectable base URLs. Non-production base URLs must
// be loopback, so the seam can never send credentials elsewhere.
func newClient(cfg Config, ep endpoints) (*Client, error) {
	for _, f := range []struct{ name, value string }{
		{"app key", cfg.AppKey},
		{"app secret", cfg.AppSecret},
		{"refresh token", cfg.RefreshToken},
	} {
		if strings.TrimSpace(f.value) == "" {
			return nil, fmt.Errorf("dropbox: %w: %s is required", ErrInvalidConfig, f.name)
		}
	}
	var err error
	if ep.auth, err = checkBaseURL(ep.auth, authHost); err != nil {
		return nil, err
	}
	if ep.api, err = checkBaseURL(ep.api, apiHost); err != nil {
		return nil, err
	}
	if ep.content, err = checkBaseURL(ep.content, contentHost); err != nil {
		return nil, err
	}

	hc := &http.Client{}
	if cfg.HTTPClient != nil {
		copied := *cfg.HTTPClient
		hc = &copied
	}
	if hc.Transport == nil {
		hc.Transport = newDefaultTransport()
	}
	// Never follow a redirect: the token form and bearer token must only
	// ever reach the fixed Dropbox hosts.
	hc.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }

	now := cfg.Clock
	if now == nil {
		now = time.Now
	}
	return &Client{
		ep:              ep,
		appKey:          cfg.AppKey,
		appSecret:       cfg.AppSecret,
		refreshToken:    cfg.RefreshToken,
		httpClient:      hc,
		now:             now,
		tok:             &tokenState{},
		chunkSize:       ChunkSize,
		simpleLimit:     SimpleUploadLimit,
		sleep:           sleepCtx,
		stallTimeout:    DefaultStallTimeout,
		responseTimeout: DefaultResponseTimeout,
		rpcTimeout:      DefaultRPCTimeout,
	}, nil
}

// checkBaseURL accepts https://<fixedHost> or a loopback http(s) URL and
// returns it without a trailing slash.
func checkBaseURL(raw, fixedHost string) (string, error) {
	invalid := fmt.Errorf("dropbox: %w: base URL must be https://%s (loopback URLs are allowed for tests only)", ErrInvalidConfig, fixedHost)
	u, err := url.Parse(raw)
	if err != nil || raw == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || (u.Path != "" && u.Path != "/") {
		return "", invalid
	}
	scheme := strings.ToLower(u.Scheme)
	switch {
	case scheme == "https" && u.Host == fixedHost:
	case (scheme == "https" || scheme == "http") && isLoopbackHost(u.Hostname()):
	default:
		return "", invalid
	}
	return scheme + "://" + u.Host, nil
}

func isLoopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
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

const opRefreshToken = "RefreshToken"

// accessToken returns a cached access token or waits for a refresh. Callers
// share one refresh at a time; each waiter stops waiting as soon as its own
// ctx ends. The refresh runs on a context detached from the caller that
// started it (so its cancellation never fails the other waiters), bounded
// by the RPC timeout.
func (c *Client) accessToken(ctx context.Context) (string, error) {
	c.tok.mu.Lock()
	if c.tok.access != "" && c.now().Before(c.tok.expiry) {
		access := c.tok.access
		c.tok.mu.Unlock()
		return access, nil
	}
	if err := ctx.Err(); err != nil {
		c.tok.mu.Unlock()
		return "", &Error{Op: opRefreshToken, Kind: err}
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
		return "", &Error{Op: opRefreshToken, Kind: ctx.Err()}
	}
}

// runRefresh performs flight f and caches its token.
func (c *Client) runRefresh(base context.Context, f *tokenFlight) {
	ctx, cancel := context.WithTimeout(base, c.rpcTimeout)
	defer cancel()
	tok, lifetime, err := c.fetchToken(ctx)
	if err != nil && ctx.Err() != nil && errors.Is(err, context.DeadlineExceeded) {
		// The refresh's own bound, not a caller's deadline.
		err = &Error{Op: opRefreshToken, Kind: ErrNetwork, Err: &timeoutError{msg: fmt.Sprintf("token refresh timed out after %s", c.rpcTimeout)}}
	}
	c.tok.mu.Lock()
	if err == nil {
		margin := refreshMargin
		if lifetime < 2*margin {
			margin = lifetime / 2
		}
		c.tok.access = tok
		c.tok.expiry = c.now().Add(lifetime - margin)
	}
	f.token, f.err = tok, err
	c.tok.flight = nil
	c.tok.mu.Unlock()
	close(f.done)
}

// fetchToken trades the refresh token for an access token and its lifetime.
func (c *Client) fetchToken(ctx context.Context) (string, time.Duration, error) {
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
		"client_id":     {c.appKey},
		"client_secret": {c.appSecret},
	}
	resp, err := c.call(ctx, request{
		op:          opRefreshToken,
		url:         c.ep.auth + "/oauth2/token",
		contentType: "application/x-www-form-urlencoded",
		body:        []byte(form.Encode()),
		timeout:     c.rpcTimeout,
		tokenCall:   true,
	})
	if err != nil {
		return "", 0, err
	}
	var out struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.body, &out); err != nil || out.AccessToken == "" {
		return "", 0, &Error{Op: opRefreshToken, Kind: ErrUnexpected, StatusCode: resp.status, Summary: "token response has no access token"}
	}
	// Remember the token for redaction before anything can echo it.
	c.tok.mu.Lock()
	c.tok.seen = append(c.tok.seen, out.AccessToken)
	if len(c.tok.seen) > maxRememberedTokens {
		c.tok.seen = c.tok.seen[len(c.tok.seen)-maxRememberedTokens:]
	}
	c.tok.mu.Unlock()
	lifetime := time.Duration(out.ExpiresIn) * time.Second
	if out.ExpiresIn <= 0 || out.ExpiresIn > 24*3600 {
		lifetime = defaultTokenLifetime
	}
	return out.AccessToken, lifetime, nil
}

// dropAccessToken forgets token so the next request refreshes it.
func (c *Client) dropAccessToken(token string) {
	c.tok.mu.Lock()
	defer c.tok.mu.Unlock()
	if c.tok.access == token {
		c.tok.access = ""
	}
}

// secrets lists every value that must never reach an error string.
func (c *Client) secrets() []string {
	c.tok.mu.Lock()
	defer c.tok.mu.Unlock()
	out := []string{c.appSecret, c.refreshToken}
	return append(out, c.tok.seen...)
}

// sleepCtx waits for d or until ctx ends.
func sleepCtx(ctx context.Context, d time.Duration) error {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// backoff is the wait before transient retry n (0-based).
func backoff(n int) time.Duration {
	d := time.Second << min(n, 5)
	return min(d, maxBackoff)
}
