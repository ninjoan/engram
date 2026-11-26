package s3client

import (
	"bytes"
	"context"
	"errors"
	"net"
	"net/http"
	"testing"
	"time"
)

// L19 R3-002: the stall timer measures body progress only. Connection setup
// (dial, TLS, proxy) happens before the transport reads the first body byte
// and is bounded by the transport's own timeouts and the caller's ctx, so a
// slow handshake is never reported as a stalled upload.
func TestPutObjectStallTimerStartsAtFirstBodyRead(t *testing.T) {
	srv, fake := newFakeS3(t, false, nil)
	slowSetup := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			select {
			case <-time.After(400 * time.Millisecond): // > 3x the stall timeout
			case <-ctx.Done():
				return nil, ctx.Err()
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		},
	}}
	c := newTestClient(t, Config{Endpoint: srv.URL, HTTPClient: slowSetup})
	c.stallTimeout = 100 * time.Millisecond
	payload := bytes.Repeat([]byte("d"), 4<<10)

	err := waitErr(t, "PutObject with slow connection setup", func() error {
		return c.PutObject(context.Background(), "slow-dial.tar.gz", bytes.NewReader(payload), int64(len(payload)), "")
	})
	if err != nil {
		t.Fatalf("slow connection setup was aborted: %v (stalled=%v)", err, errors.Is(err, ErrUploadStalled))
	}
	if rec := onlyRequest(t, fake); !bytes.Equal(rec.Body, payload) {
		t.Fatalf("server got %d bytes, want %d", len(rec.Body), len(payload))
	}
}

// A hung connection setup is still bounded by the caller's ctx.
func TestPutObjectHungConnectionSetupEndsWithCallerDeadline(t *testing.T) {
	hung := &http.Client{Transport: &http.Transport{
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			<-ctx.Done()
			return nil, ctx.Err()
		},
	}}
	c := newTestClient(t, Config{Endpoint: "https://r2.example.com", HTTPClient: hung})
	c.stallTimeout = 50 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	payload := []byte("body")
	err := waitErr(t, "PutObject with hung connection setup", func() error {
		return c.PutObject(ctx, "hung.tar.gz", bytes.NewReader(payload), int64(len(payload)), "")
	})
	if !errors.Is(err, context.DeadlineExceeded) || errors.Is(err, ErrUploadStalled) {
		t.Fatalf("err = %v, want the caller's deadline, not a stall", err)
	}
}
