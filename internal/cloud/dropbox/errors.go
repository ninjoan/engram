package dropbox

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error kinds. Match them with errors.Is.
var (
	ErrInvalidConfig     = errors.New("invalid Dropbox destination configuration")
	ErrInvalidPath       = errors.New("invalid Dropbox path")
	ErrAuth              = errors.New("Dropbox authentication failed (check the app key, app secret and refresh token)")
	ErrFolderNotFound    = errors.New("folder not found")
	ErrInsufficientSpace = errors.New("not enough space in the Dropbox account")
	ErrConflict          = errors.New("a different file or folder already exists at the path")
	ErrRateLimited       = errors.New("rate limited by Dropbox")
	ErrNetwork           = errors.New("network error")
	ErrRedirect          = errors.New("redirect refused")
	ErrUnexpected        = errors.New("unexpected Dropbox response")
	ErrFileTooLarge      = errors.New("file exceeds the 350 GB Dropbox upload limit")
	ErrSizeMismatch      = errors.New("body length does not match the declared size")
	ErrUploadStalled     = errors.New("upload stalled")
)

// Error describes a failed Dropbox request. It never carries credentials or
// tokens: only a sanitized, bounded error summary is kept.
type Error struct {
	Op         string // e.g. "Upload", "UploadSessionAppend", "CheckAccess"
	Kind       error  // one of the Err* kinds, or a context error
	StatusCode int    // HTTP status; 0 when no response was received
	Summary    string // Dropbox error_summary (or OAuth error), sanitized
	Err        error  // underlying transport error, if any

	tag           string // top-level Dropbox error .tag
	correctOffset int64  // from incorrect_offset errors, -1 otherwise
	retryAfter    int64  // seconds, from the error body; 0 when absent
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("dropbox: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Kind.Error())
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.StatusCode)
		if e.Summary != "" {
			b.WriteString(" " + e.Summary)
		}
		b.WriteByte(')')
	} else if e.Summary != "" {
		b.WriteString(": " + e.Summary)
	}
	if e.Err != nil && !errors.Is(e.Kind, e.Err) {
		b.WriteString(": " + e.Err.Error())
	}
	return b.String()
}

func (e *Error) Unwrap() []error {
	errs := []error{e.Kind}
	if e.Err != nil {
		errs = append(errs, e.Err)
	}
	return errs
}

const (
	maxResponseBody = 64 << 10
	maxSummary      = 300
)

// oauthAuthErrors are OAuth token endpoint errors caused by the stored
// credentials (bad, expired or revoked refresh token, wrong app key/secret).
var oauthAuthErrors = map[string]bool{
	"invalid_grant":       true,
	"invalid_client":      true,
	"unauthorized_client": true,
	"invalid_request":     true,
}

// responseError classifies a non-2xx response and parses the Dropbox JSON
// error body (error_summary and .tag) or an OAuth error body.
func (c *Client) responseError(r request, status int, body []byte) *Error {
	e := &Error{Op: r.op, StatusCode: status, correctOffset: -1}
	var api struct {
		Summary string          `json:"error_summary"`
		Error   json.RawMessage `json:"error"`
		Desc    string          `json:"error_description"`
	}
	parsed := json.Unmarshal(body, &api) == nil
	var oauthCode string
	if parsed && len(api.Error) > 0 {
		var detail struct {
			Tag           string `json:".tag"`
			CorrectOffset *int64 `json:"correct_offset"`
			RetryAfter    int64  `json:"retry_after"`
			LookupFailed  *struct {
				Tag           string `json:".tag"`
				CorrectOffset *int64 `json:"correct_offset"`
			} `json:"lookup_failed"`
		}
		if json.Unmarshal(api.Error, &detail) == nil {
			e.tag = detail.Tag
			e.retryAfter = detail.RetryAfter
			if detail.CorrectOffset != nil {
				e.correctOffset = *detail.CorrectOffset
			} else if detail.LookupFailed != nil && detail.LookupFailed.CorrectOffset != nil {
				e.correctOffset = *detail.LookupFailed.CorrectOffset
			}
		} else {
			_ = json.Unmarshal(api.Error, &oauthCode) // OAuth: "error": "invalid_grant"
		}
	}
	switch {
	case api.Summary != "":
		e.Summary = c.sanitize(api.Summary)
	case oauthCode != "":
		e.Summary = c.sanitize(oauthCode + ": " + api.Desc)
	default:
		e.Summary = c.sanitize(string(body))
	}
	segments := strings.Split(api.Summary, "/")
	has := func(s string) bool {
		for _, seg := range segments {
			if strings.TrimSpace(seg) == s {
				return true
			}
		}
		return false
	}

	switch {
	case status >= 300 && status < 400:
		e.Kind = ErrRedirect
	case status == http.StatusTooManyRequests:
		e.Kind = ErrRateLimited
	case status == http.StatusUnauthorized, status == http.StatusForbidden:
		e.Kind = ErrAuth
	case r.tokenCall && status == http.StatusBadRequest && oauthAuthErrors[oauthCode]:
		e.Kind = ErrAuth
	case status == http.StatusConflict && has("insufficient_space"):
		e.Kind = ErrInsufficientSpace
	case status == http.StatusConflict && has("conflict"):
		e.Kind = ErrConflict
	case status == http.StatusConflict && r.op == opCheckAccess && strings.HasPrefix(api.Summary, "path/not_found"):
		e.Kind = ErrFolderNotFound
	default:
		e.Kind = ErrUnexpected
	}
	return e
}

// sanitize strips control characters, redacts credentials and tokens and
// bounds the length of server-provided text before it reaches an error.
func (c *Client) sanitize(s string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	for _, secret := range c.secrets() {
		for _, form := range secretForms(secret) {
			s = strings.ReplaceAll(s, form, redacted)
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > maxSummary {
		cut := maxSummary
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}

// timeoutError is a deadline owned by this client (not the caller's ctx).
type timeoutError struct{ msg string }

func (e *timeoutError) Error() string { return e.msg }
func (e *timeoutError) Timeout() bool { return true }

// isTransient reports a failure worth retrying: no answer (network error,
// stall, client timeout) or a Dropbox server error.
func isTransient(err error) bool {
	var e *Error
	if !errors.As(err, &e) {
		return false
	}
	return errors.Is(e.Kind, ErrNetwork) || (errors.Is(e.Kind, ErrUnexpected) && e.StatusCode >= 500)
}

// incorrectOffset returns the server's offset from an incorrect_offset error.
func incorrectOffset(err error) (int64, bool) {
	var e *Error
	if !errors.As(err, &e) || e.StatusCode != http.StatusConflict || !strings.Contains(e.Summary, "incorrect_offset") {
		return 0, false
	}
	return e.correctOffset, true
}

// secretForms returns secret as sent and its URL-encoded variants: the
// token endpoint may echo a form value encoded.
func secretForms(secret string) []string {
	if secret == "" {
		return nil
	}
	forms := []string{secret}
	for _, v := range []string{url.QueryEscape(secret), url.PathEscape(secret)} {
		if v != forms[len(forms)-1] && v != secret {
			forms = append(forms, v)
		}
	}
	return forms
}
