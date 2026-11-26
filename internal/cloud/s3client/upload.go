package s3client

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"
)

// timeoutError is a deadline owned by this client (not the caller's ctx).
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string { return e.msg }
func (e *timeoutError) Timeout() bool { return true }

// upload streams a PutObject body that was already hashed. Every send
// attempt counts bytes so a source that changed length after hashing fails
// with ErrSizeMismatch instead of a transport error.
type upload struct {
	src  io.ReadSeeker
	size int64
	ctx  context.Context
	wd   *watchdog

	mu       sync.Mutex // serializes src access across send attempts
	attempt  int
	mismatch atomic.Pointer[error]
}

// reader returns the body for the first send attempt (src is at offset 0).
func (u *upload) reader() io.Reader {
	u.mu.Lock()
	defer u.mu.Unlock()
	u.attempt++
	return &sendReader{u: u, attempt: u.attempt, remaining: u.size}
}

// getBody rewinds src for a transport retry. Readers of earlier attempts
// stop working so two attempts never interleave reads of src. A request that
// was already canceled is not retried (an earlier attempt may still be
// blocked reading src while holding mu).
func (u *upload) getBody() (io.ReadCloser, error) {
	if err := u.ctx.Err(); err != nil {
		return nil, err
	}
	u.mu.Lock()
	defer u.mu.Unlock()
	if _, err := u.src.Seek(0, io.SeekStart); err != nil {
		return nil, fmt.Errorf("rewind body: %w", err)
	}
	u.attempt++
	u.wd.restart()
	return io.NopCloser(&sendReader{u: u, attempt: u.attempt, remaining: u.size}), nil
}

func (u *upload) fail(err error) error {
	u.mismatch.CompareAndSwap(nil, &err)
	return err
}

func (u *upload) mismatchErr() error {
	if p := u.mismatch.Load(); p != nil {
		return *p
	}
	return nil
}

var errStaleAttempt = errors.New("request body superseded by a retry")

type sendReader struct {
	u         *upload
	attempt   int
	remaining int64
}

func (r *sendReader) Read(p []byte) (int, error) {
	if err := r.u.ctx.Err(); err != nil {
		return 0, err
	}
	if len(p) == 0 {
		return 0, nil
	}
	r.u.wd.bodyRead()
	// Ask for one byte more than remains so a source that grew is detected
	// before its last declared bytes are handed to the connection.
	if int64(len(p)) > r.remaining+1 {
		p = p[:r.remaining+1]
	}
	r.u.mu.Lock()
	if r.attempt != r.u.attempt {
		r.u.mu.Unlock()
		return 0, errStaleAttempt
	}
	n, err := r.u.src.Read(p)
	r.u.mu.Unlock()

	if int64(n) > r.remaining {
		return 0, r.u.fail(fmt.Errorf("%w: body grew beyond the declared %d bytes after it was hashed", ErrSizeMismatch, r.u.size))
	}
	r.remaining -= int64(n)
	if n > 0 {
		r.u.wd.progress()
	}
	switch {
	case err == io.EOF && r.remaining > 0:
		return 0, r.u.fail(fmt.Errorf("%w: body shrank to %d bytes after it was hashed (declared %d)", ErrSizeMismatch, r.u.size-r.remaining, r.u.size))
	case err == io.EOF:
		r.u.wd.bodySent()
		return n, io.EOF
	case err != nil:
		return n, fmt.Errorf("read body: %w", err)
	}
	return n, nil
}

// watchdog cancels a PutObject that stops making progress: while the body is
// being sent it fires after stall without new bytes; once the whole body is
// handed to the connection it fires when no response arrives within response.
// Stall detection is armed by the transport's first read of the body, which
// happens only after the connection (dial, proxy, TLS) is set up, so a slow
// connection setup is never reported as a stalled upload; setup is bounded
// by the transport's timeouts and the caller's ctx.
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
		// Disarmed until the first body read (see bodyRead).
		w.timer.Stop()
	}
	return w
}

func (w *watchdog) fire() {
	w.mu.Lock()
	done := w.bodyDone
	w.mu.Unlock()
	if done {
		w.cancel(&timeoutError{msg: fmt.Sprintf("timed out after %s waiting for the server response to the uploaded body", w.response)})
		return
	}
	w.cancel(fmt.Errorf("%w: no request body bytes were sent for %s", ErrUploadStalled, w.stall))
}

// bodyRead marks a read of the body by the transport: the connection is set
// up and it accepted the previous bytes, so the stall timer (re)starts.
func (w *watchdog) bodyRead() {
	w.progress()
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

// restart disarms the watchdog for a retried send attempt; the retry's first
// body read arms stall detection again, after its connection is set up.
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
