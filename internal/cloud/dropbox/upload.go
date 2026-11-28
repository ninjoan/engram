package dropbox

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"
)

const (
	opCheckAccess   = "CheckAccess"
	opUpload        = "Upload"
	opSessionStart  = "UploadSessionStart"
	opSessionAppend = "UploadSessionAppend"
	opSessionFinish = "UploadSessionFinish"

	contentHashBlock = 4 << 20
	octetStream      = "application/octet-stream"
)

// commitInfo is the Dropbox CommitInfo: always add, never overwrite or rename.
type commitInfo struct {
	Path           string `json:"path"`
	Mode           string `json:"mode"`
	Autorename     bool   `json:"autorename"`
	Mute           bool   `json:"mute"`
	StrictConflict bool   `json:"strict_conflict"`
}

func addCommit(path string) commitInfo {
	return commitInfo{Path: path, Mode: "add", Autorename: false, Mute: true, StrictConflict: false}
}

type sessionCursor struct {
	SessionID string `json:"session_id"`
	Offset    int64  `json:"offset"`
}

type metadata struct {
	Tag         string `json:".tag"`
	PathDisplay string `json:"path_display"`
	Size        int64  `json:"size"`
	ContentHash string `json:"content_hash"`
}

// CheckAccess proves the credentials work and folder is usable without
// writing anything: it reads the folder's metadata (or the current account
// for the root "" or "/"). A missing folder is ErrFolderNotFound (Upload
// creates it on first use); a file at that path is ErrConflict.
func (c *Client) CheckAccess(ctx context.Context, folder string) error {
	if err := ctx.Err(); err != nil {
		return &Error{Op: opCheckAccess, Kind: err}
	}
	folder = strings.TrimRight(folder, "/")
	if folder == "" {
		_, err := c.call(ctx, request{
			op:          opCheckAccess,
			url:         c.ep.api + "/2/users/get_current_account",
			auth:        true,
			contentType: "application/json",
			body:        []byte("null"),
			timeout:     c.rpcTimeout,
		})
		return err
	}
	if err := validatePath(folder); err != nil {
		return fmt.Errorf("dropbox: %s: %w", opCheckAccess, err)
	}
	md, err := c.getMetadata(ctx, opCheckAccess, folder)
	if err != nil {
		return err
	}
	if md.Tag != "folder" {
		return &Error{Op: opCheckAccess, Kind: ErrConflict, Summary: "the path is a file, not a folder"}
	}
	return nil
}

// Upload stores the whole content of body (from offset 0, exactly size
// bytes) as a new file at path, e.g. "/Engram backups/<name>.tar.gz", and
// returns the Dropbox path_display. It never overwrites or renames: an
// existing file at path is ErrConflict. Files up to SimpleUploadLimit use
// one request, larger ones an upload session in ChunkSize chunks with
// offset recovery. A commit whose response is lost is checked with
// get_metadata (size and content hash) before it is retried, so a file is
// never uploaded twice. There is no overall deadline: only ctx bounds the
// total duration; a request whose body makes no progress for the stall
// timeout is aborted with ErrUploadStalled.
func (c *Client) Upload(ctx context.Context, path string, body io.ReadSeeker, size int64) (string, error) {
	if err := validatePath(path); err != nil {
		return "", fmt.Errorf("dropbox: %s: %w", opUpload, err)
	}
	if body == nil {
		return "", fmt.Errorf("dropbox: %s: body is required", opUpload)
	}
	if size < 0 {
		return "", fmt.Errorf("dropbox: %s: %w: negative size %d", opUpload, ErrSizeMismatch, size)
	}
	if size > MaxFileSize {
		return "", fmt.Errorf("dropbox: %s: %w: size is %d bytes", opUpload, ErrFileTooLarge, size)
	}
	if err := ctx.Err(); err != nil {
		return "", &Error{Op: opUpload, Kind: err}
	}
	end, err := body.Seek(0, io.SeekEnd)
	if err != nil {
		return "", fmt.Errorf("dropbox: %s: seek body: %w", opUpload, err)
	}
	if end != size {
		return "", fmt.Errorf("dropbox: %s: %w: body has %d bytes, declared %d", opUpload, ErrSizeMismatch, end, size)
	}
	src := &bodySource{r: body}
	if size <= c.simpleLimit {
		arg, err := asciiJSON(addCommit(path))
		if err != nil {
			return "", fmt.Errorf("dropbox: %s: %w", opUpload, err)
		}
		return c.commit(ctx, path, src, size, request{
			op:          opUpload,
			url:         c.ep.content + "/2/files/upload",
			auth:        true,
			apiArg:      arg,
			contentType: octetStream,
			chunk:       &chunk{src: src, offset: 0, n: size},
			timeout:     c.responseTimeout,
		})
	}
	return c.uploadSession(ctx, path, src, size)
}

// uploadSession sends the first chunk with start, the rest with append_v2
// and commits with an empty finish.
func (c *Client) uploadSession(ctx context.Context, path string, src *bodySource, size int64) (string, error) {
	var sessionID string
	var offset int64
	resyncs, transients := 0, 0
	for sessionID == "" || offset < size {
		n := min(c.chunkSize, size-offset)
		ch := &chunk{src: src, offset: offset, n: n}
		var err error
		if sessionID == "" {
			sessionID, err = c.sessionStart(ctx, ch)
		} else {
			err = c.sessionAppend(ctx, sessionID, ch)
		}
		if err == nil {
			offset += n
			continue
		}
		if ctx.Err() != nil {
			return "", err
		}
		if correct, ok := incorrectOffset(err); ok && sessionID != "" {
			// The server holds a different number of bytes (e.g. a chunk
			// whose response was lost): resume from its offset.
			if resyncs >= maxOffsetResyncs || correct < 0 || correct > size {
				return "", err
			}
			resyncs++
			offset = correct
			continue
		}
		if isTransient(err) && transients < maxTransientRetries {
			if serr := c.sleep(ctx, backoff(transients)); serr != nil {
				return "", &Error{Op: opSessionAppend, Kind: serr}
			}
			transients++
			continue
		}
		return "", err
	}
	arg, err := asciiJSON(struct {
		Cursor sessionCursor `json:"cursor"`
		Commit commitInfo    `json:"commit"`
	}{sessionCursor{SessionID: sessionID, Offset: size}, addCommit(path)})
	if err != nil {
		return "", fmt.Errorf("dropbox: %s: %w", opSessionFinish, err)
	}
	return c.commit(ctx, path, src, size, request{
		op:          opSessionFinish,
		url:         c.ep.content + "/2/files/upload_session/finish",
		auth:        true,
		apiArg:      arg,
		contentType: octetStream,
		timeout:     c.responseTimeout,
	})
}

func (c *Client) sessionStart(ctx context.Context, ch *chunk) (string, error) {
	arg, err := asciiJSON(struct {
		Close bool `json:"close"`
	}{false})
	if err != nil {
		return "", err
	}
	resp, err := c.call(ctx, request{
		op:          opSessionStart,
		url:         c.ep.content + "/2/files/upload_session/start",
		auth:        true,
		apiArg:      arg,
		contentType: octetStream,
		chunk:       ch,
		timeout:     c.responseTimeout,
	})
	if err != nil {
		return "", err
	}
	var out struct {
		SessionID string `json:"session_id"`
	}
	if json.Unmarshal(resp.body, &out) != nil || out.SessionID == "" {
		return "", &Error{Op: opSessionStart, Kind: ErrUnexpected, StatusCode: resp.status, Summary: "response has no session_id"}
	}
	return out.SessionID, nil
}

func (c *Client) sessionAppend(ctx context.Context, sessionID string, ch *chunk) error {
	arg, err := asciiJSON(struct {
		Cursor sessionCursor `json:"cursor"`
		Close  bool          `json:"close"`
	}{sessionCursor{SessionID: sessionID, Offset: ch.offset}, false})
	if err != nil {
		return err
	}
	_, err = c.call(ctx, request{
		op:          opSessionAppend,
		url:         c.ep.content + "/2/files/upload_session/append_v2",
		auth:        true,
		apiArg:      arg,
		contentType: octetStream,
		chunk:       ch,
		timeout:     c.responseTimeout,
	})
	return err
}

// commit sends a request that creates the file (upload or finish). When its
// outcome is unknown (no response, timeout or server error) it asks
// get_metadata whether the file is already there with the expected size and
// content hash before retrying, so the file is never committed twice.
func (c *Client) commit(ctx context.Context, path string, src *bodySource, size int64, r request) (string, error) {
	ambiguous := false
	for attempt := 1; ; attempt++ {
		resp, err := c.call(ctx, r)
		if err == nil {
			var md metadata
			if json.Unmarshal(resp.body, &md) != nil || md.PathDisplay == "" {
				return "", &Error{Op: r.op, Kind: ErrUnexpected, StatusCode: resp.status, Summary: "response has no path_display"}
			}
			return md.PathDisplay, nil
		}
		if ctx.Err() != nil {
			return "", err
		}
		if !isTransient(err) {
			var e *Error
			if ambiguous && errors.As(err, &e) && e.StatusCode == http.StatusConflict {
				// An earlier attempt may have committed after all.
				if p, found, ferr := c.findUploaded(ctx, r.op, path, src, size); ferr == nil && found {
					return p, nil
				}
			}
			return "", err
		}
		ambiguous = true
		p, found, ferr := c.findUploaded(ctx, r.op, path, src, size)
		switch {
		case ferr != nil && (errors.Is(ferr, ErrConflict) || ctx.Err() != nil):
			return "", ferr
		case ferr != nil:
			return "", fmt.Errorf("%w (checking whether the file was stored also failed: %w)", err, ferr)
		case found:
			return p, nil
		case attempt >= maxCommitAttempts:
			return "", err
		}
		if serr := c.sleep(ctx, backoff(attempt-1)); serr != nil {
			return "", &Error{Op: r.op, Kind: serr}
		}
	}
}

// findUploaded reports whether path holds exactly the uploaded content.
// A different file or a folder there is ErrConflict.
func (c *Client) findUploaded(ctx context.Context, op, path string, src *bodySource, size int64) (string, bool, error) {
	md, err := c.getMetadata(ctx, op, path)
	if err != nil {
		var e *Error
		if errors.As(err, &e) && e.StatusCode == http.StatusConflict && strings.HasPrefix(e.Summary, "path/not_found") {
			return "", false, nil
		}
		return "", false, err
	}
	conflict := func(why string) (string, bool, error) {
		return "", false, &Error{Op: op, Kind: ErrConflict, Summary: why}
	}
	if md.Tag != "file" {
		return conflict("a folder exists at the upload path")
	}
	if md.Size != size {
		return conflict("a file of a different size exists at the upload path")
	}
	sum, err := src.contentHash(ctx, size)
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", false, &Error{Op: op, Kind: ctxErr}
		}
		return "", false, fmt.Errorf("dropbox: %s: %w", op, err)
	}
	if !strings.EqualFold(sum, md.ContentHash) {
		return conflict("a file with different content exists at the upload path")
	}
	return md.PathDisplay, true, nil
}

func (c *Client) getMetadata(ctx context.Context, op, path string) (*metadata, error) {
	body, err := json.Marshal(struct {
		Path string `json:"path"`
	}{path})
	if err != nil {
		return nil, fmt.Errorf("dropbox: %s: %w", op, err)
	}
	resp, err := c.call(ctx, request{
		op:          op,
		url:         c.ep.api + "/2/files/get_metadata",
		auth:        true,
		contentType: "application/json",
		body:        body,
		timeout:     c.rpcTimeout,
	})
	if err != nil {
		return nil, err
	}
	var md metadata
	if err := json.Unmarshal(resp.body, &md); err != nil || md.Tag == "" {
		return nil, &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Summary: "unreadable metadata response"}
	}
	return &md, nil
}

// validatePath accepts an absolute Dropbox path such as "/Engram backups/x".
func validatePath(p string) error {
	switch {
	case !strings.HasPrefix(p, "/") || p == "/":
		return fmt.Errorf("%w: must be an absolute path such as /Engram backups/file.tar.gz", ErrInvalidPath)
	case strings.HasSuffix(p, "/"):
		return fmt.Errorf("%w: must not end with a slash", ErrInvalidPath)
	case !utf8.ValidString(p) || strings.ContainsFunc(p, unicode.IsControl):
		return fmt.Errorf("%w: must be valid UTF-8 without control characters", ErrInvalidPath)
	}
	return nil
}

// asciiJSON encodes v as JSON safe for an HTTP header: every character at
// or above 0x7F is escaped as \uXXXX (UTF-16 surrogate pairs above U+FFFF),
// as Dropbox requires for Dropbox-API-Arg.
func asciiJSON(v any) (string, error) {
	raw, err := json.Marshal(v)
	if err != nil {
		return "", err
	}
	var b strings.Builder
	for _, r := range string(raw) {
		switch {
		case r < 0x7f:
			b.WriteRune(r)
		case r > 0xffff:
			r1, r2 := utf16.EncodeRune(r)
			fmt.Fprintf(&b, `\u%04x\u%04x`, r1, r2)
		default:
			fmt.Fprintf(&b, `\u%04x`, r)
		}
	}
	return b.String(), nil
}

// contentHash computes the Dropbox content hash of the first size bytes of
// r: SHA-256 over the concatenated SHA-256 digests of 4 MiB blocks.
func contentHash(ctx context.Context, r io.ReadSeeker, size int64) (string, error) {
	if _, err := r.Seek(0, io.SeekStart); err != nil {
		return "", fmt.Errorf("rewind body: %w", err)
	}
	outer := sha256.New()
	block := sha256.New()
	for remaining := size; remaining > 0; {
		n := min(int64(contentHashBlock), remaining)
		block.Reset()
		if _, err := io.CopyN(block, ctxReader{ctx: ctx, r: r}, n); err != nil {
			if errors.Is(err, io.EOF) {
				return "", fmt.Errorf("%w: body is shorter than %d bytes", ErrSizeMismatch, size)
			}
			return "", fmt.Errorf("read body: %w", err)
		}
		outer.Write(block.Sum(nil))
		remaining -= n
	}
	return hex.EncodeToString(outer.Sum(nil)), nil
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
