package gdrive

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"
)

const maxResponseBody = 1 << 20

// call is one HTTP request.
type call struct {
	op, method, url string
	header          http.Header
	body            []byte
	token           string   // bearer access token; empty for none
	chunk           bool     // upload chunk: stall/response watchdog instead of the request timeout
	secrets         []string // extra values to redact from server text
	// noAmbiguousRetry returns network errors and 5xx answers to the caller
	// instead of resending: the request may have taken effect (folder create).
	noAmbiguousRetry bool
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// roundTrip sends exactly one request. callerCtx stays authoritative: when it
// ends, its error is the Kind. Deadlines owned by the client (request
// timeout, stall and response watchdogs) are reported as ErrNetwork.
func (c *Client) roundTrip(callerCtx context.Context, cl call) (*response, error) {
	u, err := url.Parse(cl.url)
	if err != nil || !c.ep.permits(u) {
		return nil, &Error{Op: cl.op, Kind: ErrDisallowedHost}
	}
	if err := callerCtx.Err(); err != nil {
		return nil, &Error{Op: cl.op, Kind: err}
	}
	ctx, cancel := context.WithCancelCause(callerCtx)
	defer cancel(nil)
	var wd *watchdog
	if cl.chunk && len(cl.body) > 0 {
		wd = newWatchdog(cancel, c.stallTimeout, c.responseTimeout)
		defer wd.stop()
	} else {
		var cancelTimeout context.CancelFunc
		ctx, cancelTimeout = context.WithTimeoutCause(ctx, c.requestTimeout,
			&timeoutError{msg: fmt.Sprintf("request timed out after %s", c.requestTimeout)})
		defer cancelTimeout()
	}

	req, err := http.NewRequestWithContext(ctx, cl.method, u.String(), http.NoBody)
	if err != nil {
		return nil, fmt.Errorf("gdrive: %s: build request: %w", cl.op, err)
	}
	if len(cl.body) > 0 {
		// The transport may still read the body after Do returns (an early
		// response); the caller reuses the chunk buffer right after this
		// returns, so every reader is cut off from it first.
		body := cl.body
		guard := &bodyGuard{}
		defer guard.detach()
		req.Body = io.NopCloser(&progressReader{r: bytes.NewReader(body), wd: wd, guard: guard})
		req.ContentLength = int64(len(body))
		req.GetBody = func() (io.ReadCloser, error) {
			if wd != nil {
				wd.restart()
			}
			return io.NopCloser(&progressReader{r: bytes.NewReader(body), wd: wd, guard: guard}), nil
		}
	}
	for k, v := range cl.header {
		req.Header[k] = v
	}
	if cl.token != "" {
		req.Header.Set("Authorization", "Bearer "+cl.token)
	}

	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, transportError(callerCtx, ctx, cl.op, err)
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, transportError(callerCtx, ctx, cl.op, err)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: raw}, nil
}

// transportError classifies a failed round trip without leaking the request
// URL's query (a resumable session URI is a bearer capability).
func transportError(callerCtx, ctx context.Context, op string, err error) error {
	if ctxErr := callerCtx.Err(); ctxErr != nil {
		return &Error{Op: op, Kind: ctxErr, Err: redactURLError(err)}
	}
	if ctx.Err() != nil {
		return &Error{Op: op, Kind: ErrNetwork, Err: context.Cause(ctx)}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return &Error{Op: op, Kind: ErrNetwork, Err: &timeoutError{msg: "request timed out: " + urlErr.Err.Error()}}
	}
	return &Error{Op: op, Kind: ErrNetwork, Err: redactURLError(err)}
}

func redactURLError(err error) error {
	var urlErr *url.Error
	if !errors.As(err, &urlErr) {
		return err
	}
	safe := "request"
	if u, perr := url.Parse(urlErr.URL); perr == nil {
		safe = u.Scheme + "://" + u.Host + u.Path
	}
	return &url.Error{Op: urlErr.Op, URL: safe, Err: urlErr.Err}
}

// parseRetryAfter reads a Retry-After header in seconds.
func parseRetryAfter(h http.Header) time.Duration {
	v := strings.TrimSpace(h.Get("Retry-After"))
	if v == "" {
		return 0
	}
	secs, err := strconv.Atoi(v)
	if err != nil || secs < 0 {
		return 0
	}
	if secs > 3600 {
		secs = 3600
	}
	return time.Duration(secs) * time.Second
}

// timeoutError is a deadline owned by this client (not the caller's ctx).
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string { return e.msg }
func (e *timeoutError) Timeout() bool { return true }

// errBodyDetached is returned to a transport that reads a request body
// after its round trip ended.
var errBodyDetached = errors.New("request body read after the round trip ended")

// bodyGuard cuts every reader of one round trip's body off from the shared
// chunk buffer once the round trip has returned.
type bodyGuard struct {
	mu       sync.Mutex
	detached bool
}

func (g *bodyGuard) detach() {
	g.mu.Lock()
	g.detached = true
	g.mu.Unlock()
}

// progressReader feeds a chunk to the transport and reports progress.
type progressReader struct {
	r     *bytes.Reader
	wd    *watchdog
	guard *bodyGuard
}

func (p *progressReader) Read(b []byte) (int, error) {
	if p.wd != nil {
		p.wd.progress()
	}
	p.guard.mu.Lock()
	if p.guard.detached {
		p.guard.mu.Unlock()
		return 0, errBodyDetached
	}
	n, err := p.r.Read(b)
	sent := err == io.EOF || p.r.Len() == 0
	p.guard.mu.Unlock()
	if p.wd != nil && sent {
		p.wd.bodySent()
	}
	return n, err
}

// watchdog cancels a chunk PUT that stops making progress: while the body is
// being sent it fires after stall without a new read; once the whole body is
// handed to the connection it fires when no response arrives in time. Stall
// detection is armed by the transport's first body read, after connection
// setup, so a slow dial or TLS handshake is never reported as a stall.
type watchdog struct {
	cancel   context.CancelCauseFunc
	stall    time.Duration
	response time.Duration

	mu       sync.Mutex
	bodyDone bool
	timer    *time.Timer
}

func newWatchdog(cancel context.CancelCauseFunc, stall, response time.Duration) *watchdog {
	w := &watchdog{cancel: cancel, stall: stall, response: response}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer = time.AfterFunc(response, w.fire)
	w.timer.Stop() // armed by the first body read
	return w
}

func (w *watchdog) fire() {
	w.mu.Lock()
	done := w.bodyDone
	w.mu.Unlock()
	if done {
		w.cancel(&timeoutError{msg: fmt.Sprintf("timed out after %s waiting for the response to an uploaded chunk", w.response)})
		return
	}
	w.cancel(fmt.Errorf("%w: no chunk bytes were sent for %s", ErrUploadStalled, w.stall))
}

func (w *watchdog) progress() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.bodyDone {
		w.timer.Reset(w.stall)
	}
}

func (w *watchdog) bodySent() {
	w.mu.Lock()
	defer w.mu.Unlock()
	if !w.bodyDone {
		w.bodyDone = true
		w.timer.Reset(w.response)
	}
}

// restart disarms the watchdog for a transport retry of the same chunk.
func (w *watchdog) restart() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.bodyDone = false
	w.timer.Stop()
}

func (w *watchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer.Stop()
}
