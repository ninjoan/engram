package gdrive

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Upload stores the whole content of body (from offset 0, exactly size bytes)
// as a new file called name in folderID with Drive's resumable protocol and
// returns the new file ID. Drive allows duplicate names; Upload never looks
// for, overwrites or deletes an existing file.
//
// Chunks of ChunkSize bytes are PUT with Content-Range headers. A 308 with a
// Range header continues from the confirmed offset. After a network error,
// stall or 5xx, a status probe (Content-Range: bytes */size) finds the
// confirmed offset. Rate limits back off exponentially with jitter. All
// retries are bounded; an expired or rejected session is replaced by a new
// one, from offset 0, at most once. ctx bounds the total duration.
func (c *Client) Upload(ctx context.Context, folderID, name string, body io.ReadSeeker, size int64) (fileID string, err error) {
	const op = "Upload"
	if !fileIDPattern.MatchString(folderID) {
		return "", fmt.Errorf("gdrive: %s: %w: folder ID must be a Drive ID", op, ErrInvalidArgument)
	}
	if err := validateName(op, name); err != nil {
		return "", err
	}
	if body == nil {
		return "", fmt.Errorf("gdrive: %s: %w: body is required", op, ErrInvalidArgument)
	}
	if size < 0 {
		return "", fmt.Errorf("gdrive: %s: %w: negative size %d", op, ErrSizeMismatch, size)
	}
	if size > MaxFileSize {
		return "", fmt.Errorf("gdrive: %s: %w: size is %d bytes", op, ErrFileTooLarge, size)
	}
	end, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return "", fmt.Errorf("gdrive: %s: measure body: %w", op, err)
	}
	if end != size {
		return "", fmt.Errorf("gdrive: %s: %w: body has %d bytes, declared %d", op, ErrSizeMismatch, end, size)
	}
	if err := ctx.Err(); err != nil {
		return "", &Error{Op: op, Kind: err}
	}

	buf := make([]byte, min(c.chunkSize, size))
	for session := 1; ; session++ {
		uri, err := c.startSession(ctx, op, folderID, name, size)
		if err != nil {
			return "", err
		}
		id, err := c.sendSession(ctx, op, uri, body, size, buf)
		if errors.Is(err, ErrSessionInvalid) && session < maxUploadSessions {
			continue
		}
		return id, err
	}
}

// startSession opens a resumable session and returns its checked URI.
func (c *Client) startSession(ctx context.Context, op, folderID, name string, size int64) (string, error) {
	meta, _ := json.Marshal(struct {
		Name    string   `json:"name"`
		Parents []string `json:"parents"`
	}{name, []string{folderID}})
	q := url.Values{"uploadType": {"resumable"}, "supportsAllDrives": {"true"}, "fields": {"id"}}
	resp, err := c.do(ctx, call{
		op:     op,
		method: http.MethodPost,
		url:    c.ep.upload + "?" + q.Encode(),
		header: http.Header{
			"Content-Type":            {"application/json; charset=UTF-8"},
			"X-Upload-Content-Type":   {UploadContentType},
			"X-Upload-Content-Length": {strconv.FormatInt(size, 10)},
		},
		body: meta,
	}, true)
	if err != nil {
		return "", err
	}
	loc := resp.header.Get("Location")
	if err := c.checkSessionURI(loc); err != nil {
		return "", err
	}
	return loc, nil
}

// checkSessionURI accepts only a session URI on the upload endpoint itself
// (https://www.googleapis.com/upload/drive/v3/files in production).
func (c *Client) checkSessionURI(loc string) error {
	want, _ := url.Parse(c.ep.upload)
	u, err := url.Parse(loc)
	if err != nil || loc == "" || u.User != nil || u.Opaque != "" || u.Fragment != "" ||
		!strings.EqualFold(u.Scheme, want.Scheme) || !strings.EqualFold(u.Host, want.Host) ||
		u.Path != want.Path || !c.ep.permits(u) {
		return &Error{Op: "Upload", Kind: ErrInvalidLocation}
	}
	return nil
}

type outcome int

const (
	outcomeDone       outcome = iota
	outcomeIncomplete         // 308: continue from next
	outcomeTransient          // network, stall, 5xx, rate limit: back off and probe
	outcomeInvalid            // 404/410/other 4xx: the session is gone
	outcomeFatal
)

type result struct {
	kind       outcome
	id         string
	next       int64
	retryAfter time.Duration
	err        error
}

// sendSession streams body into one session.
func (c *Client) sendSession(ctx context.Context, op, uri string, body io.ReadSeeker, size int64, buf []byte) (string, error) {
	var offset int64
	probe := size == 0 // an empty file is finalized by "bytes */0"
	failures := 0      // consecutive attempts without progress
	for {
		var resp *response
		var tok string
		var err error
		chunkPUT := !probe
		if probe {
			resp, tok, err = c.putSession(ctx, op, uri, fmt.Sprintf("bytes */%d", size), nil)
		} else {
			n := min(int64(len(buf)), size-offset)
			if err := readChunk(body, offset, buf[:n]); err != nil {
				return "", fmt.Errorf("gdrive: %s: %w", op, err)
			}
			resp, tok, err = c.putSession(ctx, op, uri, fmt.Sprintf("bytes %d-%d/%d", offset, offset+n-1, size), buf[:n])
		}
		res := c.uploadResult(op, resp, tok, err, size)
		switch res.kind {
		case outcomeDone:
			return res.id, nil
		case outcomeIncomplete:
			progressed := res.next > offset
			offset = res.next
			if progressed {
				failures = 0
			} else if chunkPUT {
				failures++
			}
			probe = offset == size // every byte confirmed but not finalized
			if probe {
				failures++
			}
			if failures > c.maxRetries {
				return "", &Error{Op: op, Kind: ErrUnexpected, StatusCode: http.StatusPermanentRedirect, Message: "upload made no progress"}
			}
		case outcomeTransient:
			failures++
			if failures > c.maxRetries {
				return "", res.err
			}
			if err := c.backoff(ctx, op, failures-1, res.retryAfter); err != nil {
				return "", err
			}
			probe = true
		case outcomeInvalid:
			e := &Error{Op: op, Kind: ErrSessionInvalid, Err: res.err}
			var ge *Error
			if errors.As(res.err, &ge) {
				e.StatusCode, e.Reason, e.Message, e.Err = ge.StatusCode, ge.Reason, ge.Message, nil
			}
			return "", e
		default:
			return "", res.err
		}
	}
}

// putSession PUTs to the session URI, refreshing the access token once on
// 401. It returns the access token used, for redaction.
func (c *Client) putSession(ctx context.Context, op, uri, contentRange string, chunk []byte) (*response, string, error) {
	refreshed := false
	for {
		tok, err := c.accessToken(ctx)
		if err != nil {
			return nil, "", err
		}
		resp, err := c.roundTrip(ctx, call{
			op:     op,
			method: http.MethodPut,
			url:    uri,
			header: http.Header{"Content-Range": {contentRange}},
			body:   chunk,
			token:  tok,
			chunk:  true,
		})
		if err == nil && resp.status == http.StatusUnauthorized && !refreshed {
			refreshed = true
			c.tok.invalidate(tok)
			continue
		}
		return resp, tok, err
	}
}

func (c *Client) uploadResult(op string, resp *response, tok string, err error, size int64) result {
	if err != nil {
		if retryable(err) {
			return result{kind: outcomeTransient, err: err}
		}
		return result{kind: outcomeFatal, err: err}
	}
	switch resp.status {
	case http.StatusOK, http.StatusCreated:
		id, err := parseFileID(op, resp)
		if err != nil {
			return result{kind: outcomeFatal, err: err}
		}
		return result{kind: outcomeDone, id: id}
	case http.StatusPermanentRedirect:
		next, err := parseRange(resp.header.Get("Range"), size)
		if err != nil {
			return result{kind: outcomeFatal, err: &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Message: err.Error()}}
		}
		return result{kind: outcomeIncomplete, next: next}
	}
	e := c.responseError(call{op: op, token: tok}, resp)
	switch {
	case retryable(e):
		return result{kind: outcomeTransient, err: e, retryAfter: parseRetryAfter(resp.header)}
	case e.Kind == ErrQuota, e.Kind == ErrAuth, e.Kind == ErrRedirect:
		return result{kind: outcomeFatal, err: e}
	case resp.status >= 400 && resp.status < 500:
		return result{kind: outcomeInvalid, err: e}
	}
	return result{kind: outcomeFatal, err: e}
}

var rangePattern = regexp.MustCompile(`^bytes=0-(\d{1,19})$`)

// parseRange returns the next offset from a 308 Range header ("bytes=0-N"
// confirms N+1 bytes; no header confirms none).
func parseRange(h string, size int64) (int64, error) {
	if h == "" {
		return 0, nil
	}
	m := rangePattern.FindStringSubmatch(strings.TrimSpace(h))
	if m == nil {
		return 0, errors.New("malformed Range header in 308 response")
	}
	last, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil || last >= size {
		return 0, errors.New("308 Range header is outside the file")
	}
	return last + 1, nil
}

// readChunk fills buf with body's bytes at offset.
func readChunk(body io.ReadSeeker, offset int64, buf []byte) error {
	if _, err := body.Seek(offset, io.SeekStart); err != nil {
		return fmt.Errorf("seek body: %w", err)
	}
	if _, err := io.ReadFull(body, buf); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return fmt.Errorf("%w: body shrank during the upload", ErrSizeMismatch)
		}
		return fmt.Errorf("read body: %w", err)
	}
	return nil
}
