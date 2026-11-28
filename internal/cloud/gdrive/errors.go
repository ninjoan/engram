package gdrive

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
	ErrInvalidConfig   = errors.New("invalid Google Drive destination configuration")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrAuth            = errors.New("authorization revoked or expired; reconnect Google")
	ErrNoRefreshToken  = errors.New("no refresh token was returned; reconnect Google and grant offline access")
	ErrScope           = errors.New("granted access is not limited to the drive.file scope; reconnect Google and grant only the requested access")
	ErrQuota           = errors.New("storage or daily upload quota of the Google Drive account exceeded")
	ErrRateLimited     = errors.New("rate limit of the Google Drive API exceeded")
	ErrNotFound        = errors.New("folder or file not found in Google Drive")
	ErrNetwork         = errors.New("network error")
	ErrRedirect        = errors.New("redirect refused")
	ErrUnexpected      = errors.New("unexpected Google response")
	ErrDisallowedHost  = errors.New("request host is not an allowed Google endpoint")
	ErrInvalidLocation = errors.New("upload session URI is not on the Google upload endpoint")
	ErrSessionInvalid  = errors.New("upload session expired or was rejected")
	ErrUploadStalled   = errors.New("upload stalled")
	ErrSizeMismatch    = errors.New("body length does not match the declared size")
	ErrFileTooLarge    = errors.New("file exceeds the 5 TiB Google Drive limit")
)

// Error describes a failed Google request. It never carries credentials,
// access tokens or session URIs: only the Google error reason and a
// sanitized, bounded message are kept.
type Error struct {
	Op         string // "Upload", "EnsureFolder", "CheckAccess", "ExchangeCode" or "TokenRefresh"
	Kind       error  // one of the Err* kinds, or a context error
	StatusCode int    // HTTP status; 0 when no response was received
	Reason     string // Google error reason, e.g. "storageQuotaExceeded" or "invalid_grant"
	Message    string // sanitized Google error message
	Err        error  // underlying error, if any
}

func (e *Error) Error() string {
	var b strings.Builder
	b.WriteString("gdrive: ")
	b.WriteString(e.Op)
	b.WriteString(": ")
	b.WriteString(e.Kind.Error())
	if e.StatusCode != 0 {
		fmt.Fprintf(&b, " (HTTP %d", e.StatusCode)
		if e.Reason != "" {
			b.WriteString(" " + e.Reason)
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
	maxErrorMessage = 300
	maxErrorReason  = 64
)

var quotaReasons = map[string]bool{
	"storageQuotaExceeded":    true,
	"userUploadLimitExceeded": true,
	"dailyLimitExceeded":      true,
}

var rateLimitReasons = map[string]bool{
	"rateLimitExceeded":        true,
	"userRateLimitExceeded":    true,
	"sharingRateLimitExceeded": true,
}

// authReasons are the only Drive API reasons that mean the stored
// authorization no longer works. Every other 403 (domainPolicy, forbidden,
// ...) is a refusal reconnecting would not fix.
var authReasons = map[string]bool{
	"authError":               true,
	"insufficientPermissions": true,
}

var oauthAuthErrors = map[string]bool{
	"invalid_grant":       true,
	"invalid_client":      true,
	"unauthorized_client": true,
}

// parseGoogleError reads both the Drive API error shape
// {"error":{"message":..,"errors":[{"reason":..}],"status":..}} and the OAuth
// token endpoint shape {"error":"invalid_grant","error_description":..}.
func parseGoogleError(raw []byte) (reason, message string) {
	var env struct {
		Error       json.RawMessage `json:"error"`
		Description string          `json:"error_description"`
	}
	if json.Unmarshal(raw, &env) != nil || len(env.Error) == 0 {
		return "", ""
	}
	var code string
	if json.Unmarshal(env.Error, &code) == nil {
		return code, env.Description
	}
	var api struct {
		Message string `json:"message"`
		Status  string `json:"status"`
		Errors  []struct {
			Reason string `json:"reason"`
		} `json:"errors"`
	}
	if json.Unmarshal(env.Error, &api) != nil {
		return "", ""
	}
	reason = api.Status
	if len(api.Errors) > 0 && api.Errors[0].Reason != "" {
		reason = api.Errors[0].Reason
	}
	return reason, api.Message
}

// responseError classifies a non-2xx response.
func (c *Client) responseError(cl call, resp *response) *Error {
	rawReason, msg := parseGoogleError(resp.body)
	secrets := append([]string{cl.token}, cl.secrets...)
	e := &Error{
		Op:         cl.op,
		StatusCode: resp.status,
		Reason:     c.sanitize(rawReason, maxErrorReason, secrets),
		Message:    c.sanitize(msg, maxErrorMessage, secrets),
	}
	s := resp.status
	switch {
	case s >= 300 && s < 400:
		e.Kind = ErrRedirect
	case quotaReasons[rawReason]:
		e.Kind = ErrQuota
	case s == http.StatusTooManyRequests, rateLimitReasons[rawReason]:
		e.Kind = ErrRateLimited
	case s == http.StatusUnauthorized, oauthAuthErrors[rawReason], s == http.StatusForbidden && authReasons[rawReason]:
		e.Kind = ErrAuth
	case s == http.StatusNotFound:
		e.Kind = ErrNotFound
	default:
		e.Kind = ErrUnexpected
		if s == http.StatusForbidden && e.Message == "" {
			e.Message = "Google refused the request"
		}
	}
	return e
}

// sanitize strips control characters, redacts credentials and bounds the
// length of server-provided text before it reaches an error string.
func (c *Client) sanitize(s string, limit int, extra []string) string {
	s = strings.ToValidUTF8(s, "?")
	s = strings.Map(func(r rune) rune {
		if unicode.IsControl(r) {
			return ' '
		}
		return r
	}, s)
	for _, secret := range append([]string{c.clientSecret, c.refreshToken}, extra...) {
		for _, form := range secretForms(secret) {
			s = strings.ReplaceAll(s, form, redacted)
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

// secretForms returns secret as sent and its URL-encoded and URL-decoded
// variants (a server may echo a form or query value in any of them).
func secretForms(secret string) []string {
	if secret == "" {
		return nil
	}
	forms := []string{secret}
	add := func(v string) {
		if v == "" {
			return
		}
		for _, f := range forms {
			if f == v {
				return
			}
		}
		forms = append(forms, v)
	}
	add(url.QueryEscape(secret))
	add(url.PathEscape(secret))
	if v, err := url.QueryUnescape(secret); err == nil {
		add(v)
	}
	if v, err := url.PathUnescape(secret); err == nil {
		add(v)
	}
	return forms
}

// sessionSecrets lists the forms of a resumable session URI that must never
// reach an error: the URI is a bearer capability, so its upload_id value is
// redacted on its own too.
func sessionSecrets(uri string) []string {
	if uri == "" {
		return nil
	}
	out := []string{uri}
	if u, err := url.Parse(uri); err == nil {
		if u.RawQuery != "" {
			out = append(out, u.RawQuery)
		}
		if raw, ok := rawQueryValue(u.RawQuery, "upload_id"); ok {
			out = append(out, raw)
		}
	}
	return out
}

// rawQueryValue returns the still-encoded value of key in rawQuery.
func rawQueryValue(rawQuery, key string) (string, bool) {
	for _, kv := range strings.Split(rawQuery, "&") {
		k, v, _ := strings.Cut(kv, "=")
		if k == key && v != "" {
			return v, true
		}
	}
	return "", false
}
