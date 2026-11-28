package dropbox

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
	"sync/atomic"
	"time"
)

// request is one Dropbox HTTP call (always POST).
type request struct {
	op          string
	url         string
	auth        bool   // send the bearer access token
	tokenCall   bool   // the OAuth token endpoint (OAuth error format)
	apiArg      string // Dropbox-API-Arg header (content endpoints)
	contentType string
	body        []byte        // small in-memory body
	chunk       *chunk        // streamed upload body; replayed from src on retry
	timeout     time.Duration // response timeout once the body was sent
}

type response struct {
	status int
	header http.Header
	body   []byte
}

// call sends r, refreshing an expired access token once and honoring
// Retry-After on 429 a bounded number of times. Non-2xx answers become a
// classified *Error.
func (c *Client) call(ctx context.Context, r request) (*response, error) {
	refreshed := false
	rateRetries := 0
	for {
		if err := ctx.Err(); err != nil {
			return nil, &Error{Op: r.op, Kind: err}
		}
		token := ""
		if r.auth {
			var err error
			if token, err = c.accessToken(ctx); err != nil {
				return nil, err
			}
		}
		resp, err := c.roundTrip(ctx, r, token)
		if err != nil {
			return nil, err
		}
		if resp.status >= 200 && resp.status <= 299 {
			return resp, nil
		}
		apiErr := c.responseError(r, resp.status, resp.body)
		if r.auth && !refreshed && resp.status == http.StatusUnauthorized &&
			(apiErr.tag == "expired_access_token" || strings.HasPrefix(apiErr.Summary, "expired_access_token")) {
			refreshed = true
			c.dropAccessToken(token)
			continue
		}
		if resp.status == http.StatusTooManyRequests {
			wait := retryAfter(resp.header, apiErr, c.now())
			if rateRetries >= maxRateLimitRetries || wait > maxRetryWait {
				return nil, apiErr
			}
			rateRetries++
			if err := c.sleep(ctx, wait); err != nil {
				return nil, &Error{Op: r.op, Kind: err}
			}
			continue
		}
		return nil, apiErr
	}
}

// retryAfter reads Retry-After (seconds or HTTP date), then the JSON
// retry_after, defaulting to one second.
func retryAfter(h http.Header, e *Error, now time.Time) time.Duration {
	if v := strings.TrimSpace(h.Get("Retry-After")); v != "" {
		if secs, err := strconv.ParseInt(v, 10, 64); err == nil && secs >= 0 {
			if secs > int64(maxRetryWait/time.Second) {
				return maxRetryWait + time.Second
			}
			return time.Duration(secs) * time.Second
		}
		if at, err := http.ParseTime(v); err == nil {
			return max(at.Sub(now), 0)
		}
	}
	if e.retryAfter > 0 {
		if e.retryAfter > int64(maxRetryWait/time.Second) {
			return maxRetryWait + time.Second
		}
		return time.Duration(e.retryAfter) * time.Second
	}
	return time.Second
}

// roundTrip sends one attempt of r. The caller's ctx stays authoritative:
// when it ends, its error is the Kind. Deadlines owned by the client (stall
// and response watchdog) are reported as ErrNetwork.
func (c *Client) roundTrip(callerCtx context.Context, r request, token string) (*response, error) {
	ctx, cancel := context.WithCancelCause(callerCtx)
	defer cancel(nil)
	streaming := r.chunk != nil && r.chunk.n > 0
	wd := newWatchdog(cancel, c.stallTimeout, r.timeout, !streaming)
	defer wd.stop()

	var body io.Reader = http.NoBody
	var length int64
	var sr *sendReader
	switch {
	case streaming:
		var err error
		if sr, err = r.chunk.src.reader(ctx, r.chunk.offset, r.chunk.n, wd); err != nil {
			return nil, fmt.Errorf("dropbox: %s: %w", r.op, err)
		}
		body, length = sr, r.chunk.n
	case len(r.body) > 0:
		body, length = bytes.NewReader(r.body), int64(len(r.body))
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, r.url, body)
	if err != nil {
		return nil, fmt.Errorf("dropbox: %s: build request: %w", r.op, err)
	}
	req.ContentLength = length
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if r.apiArg != "" {
		req.Header.Set("Dropbox-API-Arg", r.apiArg)
	}
	if r.contentType != "" {
		req.Header.Set("Content-Type", r.contentType)
	}

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, c.transportError(callerCtx, ctx, r, sr, err)
	}
	defer resp.Body.Close()
	if sr != nil {
		if mismatch := sr.mismatchErr(); mismatch != nil {
			return nil, fmt.Errorf("dropbox: %s: %w", r.op, mismatch)
		}
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody))
	if err != nil {
		return nil, c.transportError(callerCtx, ctx, r, sr, err)
	}
	return &response{status: resp.StatusCode, header: resp.Header, body: raw}, nil
}

// transportError classifies a failed round trip.
func (c *Client) transportError(callerCtx, ctx context.Context, r request, sr *sendReader, err error) error {
	if ctxErr := callerCtx.Err(); ctxErr != nil {
		return &Error{Op: r.op, Kind: ctxErr, Err: err}
	}
	if sr != nil {
		if mismatch := sr.mismatchErr(); mismatch != nil {
			return fmt.Errorf("dropbox: %s: %w", r.op, mismatch)
		}
	}
	if ctx.Err() != nil {
		// A deadline owned by this client fired; the transport error only
		// repeats "context canceled", so report the cause.
		return &Error{Op: r.op, Kind: ErrNetwork, Err: context.Cause(ctx)}
	}
	var urlErr *url.Error
	if errors.As(err, &urlErr) && urlErr.Timeout() {
		return &Error{Op: r.op, Kind: ErrNetwork, Err: &timeoutError{msg: "request timed out: " + urlErr.Err.Error()}}
	}
	return &Error{Op: r.op, Kind: ErrNetwork, Err: err}
}

// chunk is the byte range [offset, offset+n) of an upload source.
type chunk struct {
	src       *bodySource
	offset, n int64
}

// bodySource serializes access to the caller's io.ReadSeeker across send
// attempts: a transport may still read an abandoned attempt's body after Do
// returns, so readers of superseded attempts stop working.
type bodySource struct {
	mu  sync.Mutex
	r   io.ReadSeeker
	gen int
}

var errStaleAttempt = errors.New("request body superseded by a retry")

// reader positions the source at offset for a new send attempt of n bytes.
func (s *bodySource) reader(ctx context.Context, offset, n int64, wd *watchdog) (*sendReader, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	if _, err := s.r.Seek(offset, io.SeekStart); err != nil {
		return nil, fmt.Errorf("seek body: %w", err)
	}
	return &sendReader{ctx: ctx, src: s, gen: s.gen, remaining: n, wd: wd}, nil
}

// contentHash computes the Dropbox content hash of the whole source.
func (s *bodySource) contentHash(ctx context.Context, size int64) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.gen++
	return contentHash(ctx, s.r, size)
}

type sendReader struct {
	ctx       context.Context
	src       *bodySource
	gen       int
	remaining int64
	wd        *watchdog
	mismatch  atomic.Pointer[error]
}

func (r *sendReader) fail(err error) error {
	r.mismatch.CompareAndSwap(nil, &err)
	return err
}

func (r *sendReader) mismatchErr() error {
	if p := r.mismatch.Load(); p != nil {
		return *p
	}
	return nil
}

func (r *sendReader) Read(p []byte) (int, error) {
	if err := r.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	if r.remaining == 0 {
		r.wd.bodySent()
		return 0, io.EOF
	}
	r.wd.bodyRead()
	if int64(len(p)) > r.remaining {
		p = p[:r.remaining]
	}
	r.src.mu.Lock()
	if r.gen != r.src.gen {
		r.src.mu.Unlock()
		return 0, errStaleAttempt
	}
	n, err := r.src.r.Read(p)
	r.src.mu.Unlock()

	r.remaining -= int64(n)
	if n > 0 {
		r.wd.progress()
	}
	switch {
	case r.remaining == 0:
		r.wd.bodySent()
		return n, io.EOF
	case err == io.EOF:
		return n, r.fail(fmt.Errorf("%w: body ended %d bytes early", ErrSizeMismatch, r.remaining))
	case err != nil:
		return n, fmt.Errorf("read body: %w", err)
	}
	return n, nil
}

// watchdog cancels a request that stops making progress: while a body is
// being sent it fires after stall without new bytes; once the body is handed
// to the connection (or for requests without a streamed body) it fires when
// no response arrives within response. Stall detection is armed by the
// transport's first read of the body, after the connection is set up.
type watchdog struct {
	cancel   context.CancelCauseFunc
	stall    time.Duration
	response time.Duration

	mu       sync.Mutex
	bodyDone bool
	timer    *time.Timer
}

func newWatchdog(cancel context.CancelCauseFunc, stall, response time.Duration, bodyDone bool) *watchdog {
	w := &watchdog{cancel: cancel, stall: stall, response: response, bodyDone: bodyDone}
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer = time.AfterFunc(response, w.fire)
	if !bodyDone {
		w.timer.Stop() // armed by the first body read
	}
	return w
}

func (w *watchdog) fire() {
	w.mu.Lock()
	done := w.bodyDone
	w.mu.Unlock()
	if done {
		w.cancel(&timeoutError{msg: fmt.Sprintf("timed out after %s waiting for the server response", w.response)})
		return
	}
	w.cancel(fmt.Errorf("%w: no request body bytes were sent for %s", ErrUploadStalled, w.stall))
}

func (w *watchdog) bodyRead() { w.progress() }

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

func (w *watchdog) stop() {
	w.mu.Lock()
	defer w.mu.Unlock()
	w.timer.Stop()
}
