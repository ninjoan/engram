package s3client

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"unicode"
	"unicode/utf8"
)

// Error kinds. Match them with errors.Is.
var (
	ErrInvalidConfig    = errors.New("invalid S3 destination configuration")
	ErrInsecureEndpoint = errors.New("endpoint must use https (plain http is only allowed for loopback hosts)")
	ErrInvalidKey       = errors.New("invalid object key")
	ErrObjectTooLarge   = errors.New("object exceeds the 5 GiB single PUT limit (multipart upload is not supported)")
	ErrSizeMismatch     = errors.New("body length does not match the declared size")
	ErrAuth             = errors.New("authentication or authorization failed")
	ErrBucketNotFound   = errors.New("bucket not found")
	ErrNetwork          = errors.New("network error")
	ErrRedirect         = errors.New("redirect refused")
	ErrUnexpectedStatus = errors.New("unexpected response status")
)

// Error describes a failed S3 request. It never carries credentials or
// signing material: only the S3 error Code and a sanitized Message are kept.
type Error struct {
	Op         string // "PutObject" or "CheckAccess"
	Kind       error  // one of the Err* kinds, or a context error
	StatusCode int    // HTTP status; 0 when no response was received
	Code       string // S3 error code, e.g. "SignatureDoesNotMatch"
	Message    string // S3 error message
	RequestID  string
	Err        error // underlying transport error, if any
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("s3client: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Kind.Error())
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.StatusCode)
		if e.Code != "" {
			b.WriteString(" " + e.Code)
		}
		b.WriteByte(')')
	}
	if e.Message != "" {
		b.WriteString(": " + e.Message)
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
	maxErrorBody    = 64 << 10
	maxErrorMessage = 300
)

var authCodes = map[string]bool{
	"SignatureDoesNotMatch":        true,
	"InvalidAccessKeyId":           true,
	"AccessDenied":                 true,
	"AuthorizationHeaderMalformed": true,
	"InvalidToken":                 true,
	"ExpiredToken":                 true,
	"RequestTimeTooSkewed":         true,
}

// responseError classifies a non-2xx response and parses the S3 XML error body.
func (c *Client) responseError(op string, resp *http.Response) *Error {
	var body struct {
		Code      string `xml:"Code"`
		Message   string `xml:"Message"`
		RequestID string `xml:"RequestId"`
	}
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, maxErrorBody))
	_ = xml.Unmarshal(raw, &body)

	e := &Error{
		Op:         op,
		StatusCode: resp.StatusCode,
		Code:       c.sanitize(body.Code, 64),
		Message:    c.sanitize(body.Message, maxErrorMessage),
		RequestID:  c.sanitize(body.RequestID, 128),
	}
	switch {
	case resp.StatusCode >= 300 && resp.StatusCode < 400:
		e.Kind = ErrRedirect
	case authCodes[body.Code], resp.StatusCode == http.StatusUnauthorized, resp.StatusCode == http.StatusForbidden:
		e.Kind = ErrAuth
	case body.Code == "NoSuchBucket", resp.StatusCode == http.StatusNotFound:
		e.Kind = ErrBucketNotFound
	default:
		e.Kind = ErrUnexpectedStatus
	}
	return e
}

// sanitize strips control characters, redacts the configured credentials and
// bounds the length of server-provided text before it reaches an error string.
func (c *Client) sanitize(s string, limit int) string {
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	for _, secret := range []string{c.secretAccessKey, c.accessKeyID} {
		if secret != "" {
			s = strings.ReplaceAll(s, secret, "[REDACTED]")
		}
	}
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > limit {
		cut := limit
		for cut > 0 && !utf8.RuneStart(s[cut]) {
			cut--
		}
		s = s[:cut] + "…"
	}
	return s
}
