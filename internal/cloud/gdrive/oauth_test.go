package gdrive

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func TestAuthCodeURLRequestsOnlyDriveFileOfflineWithPKCE(t *testing.T) {
	raw := AuthCodeURL(testClientID, "https://cloud.example.com/dashboard/admin/backups/google/callback", "state-123", "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM")
	u, err := url.Parse(raw)
	if err != nil {
		t.Fatalf("parse %q: %v", raw, err)
	}
	if u.Scheme != "https" || u.Host != "accounts.google.com" || u.Path != "/o/oauth2/v2/auth" {
		t.Fatalf("auth URL = %s://%s%s", u.Scheme, u.Host, u.Path)
	}
	want := url.Values{
		"client_id":              {testClientID},
		"redirect_uri":           {"https://cloud.example.com/dashboard/admin/backups/google/callback"},
		"response_type":          {"code"},
		"scope":                  {"https://www.googleapis.com/auth/drive.file"},
		"access_type":            {"offline"},
		"prompt":                 {"consent"},
		"include_granted_scopes": {"false"},
		"state":                  {"state-123"},
		"code_challenge":         {"E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM"},
		"code_challenge_method":  {"S256"},
	}
	got := u.Query()
	if len(got) != len(want) {
		t.Fatalf("query has %d params, want %d: %v", len(got), len(want), got)
	}
	for k, v := range want {
		if len(got[k]) != 1 || got[k][0] != v[0] {
			t.Errorf("%s = %q, want %q", k, got[k], v[0])
		}
	}
	if Scope != "https://www.googleapis.com/auth/drive.file" {
		t.Fatalf("Scope = %q", Scope)
	}
}

func TestPKCEChallengeMatchesRFC7636Example(t *testing.T) {
	// RFC 7636 Appendix B.
	if got := pkceChallenge("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"); got != "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM" {
		t.Fatalf("challenge = %q", got)
	}
}

func TestNewPKCEReturnsFreshRFC7636Verifier(t *testing.T) {
	unreserved := regexp.MustCompile(`^[A-Za-z0-9._~-]{43,128}$`)
	seen := map[string]bool{}
	for range 4 {
		v, c, err := NewPKCE()
		if err != nil {
			t.Fatalf("NewPKCE: %v", err)
		}
		if !unreserved.MatchString(v) {
			t.Fatalf("verifier %q is not 43-128 unreserved characters", v)
		}
		if c != pkceChallenge(v) || strings.ContainsAny(c, "+/=") {
			t.Fatalf("challenge %q does not match verifier", c)
		}
		if seen[v] {
			t.Fatalf("verifier repeated")
		}
		seen[v] = true
	}
}

// exchangeServer answers the authorization code exchange with body.
func exchangeServer(t *testing.T, status int, body map[string]any) (*fakeDrive, *[]url.Values) {
	fd := newFakeDrive(t)
	var forms []url.Values
	fd.token = func(w http.ResponseWriter, r *http.Request, b []byte, _ int, _ *session) bool {
		f, _ := url.ParseQuery(string(b))
		forms = append(forms, f)
		writeJSON(w, status, body)
		return true
	}
	return fd, &forms
}

func runExchange(t *testing.T, fd *fakeDrive) (string, error) {
	t.Helper()
	ep, err := loopbackEndpoints(fd.srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return exchangeCode(context.Background(), nil, ep, testClientID, testSecret, "4/auth-code-value", "https://cloud.example.com/cb", "verifier-value-0123456789012345678901234567890")
}

func TestExchangeCodeReturnsRefreshToken(t *testing.T) {
	fd, forms := exchangeServer(t, http.StatusOK, map[string]any{
		"access_token": "ya29.x", "expires_in": 3599, "refresh_token": "1//new-refresh", "scope": Scope, "token_type": "Bearer",
	})
	rt, err := runExchange(t, fd)
	if err != nil || rt != "1//new-refresh" {
		t.Fatalf("ExchangeCode = %q, %v", rt, err)
	}
	f := (*forms)[0]
	want := map[string]string{
		"grant_type": "authorization_code", "code": "4/auth-code-value", "redirect_uri": "https://cloud.example.com/cb",
		"client_id": testClientID, "client_secret": testSecret, "code_verifier": "verifier-value-0123456789012345678901234567890",
	}
	for k, v := range want {
		if f.Get(k) != v {
			t.Errorf("form %s = %q, want %q", k, f.Get(k), v)
		}
	}
	if ct := fd.requests("token")[0].Header.Get("Content-Type"); ct != "application/x-www-form-urlencoded" {
		t.Errorf("Content-Type = %q", ct)
	}
}

func TestExchangeCodeRefusesMissingRefreshTokenOrWiderScope(t *testing.T) {
	cases := []struct {
		name string
		body map[string]any
		want error
	}{
		{"no refresh token", map[string]any{"access_token": "ya29.x", "scope": Scope}, ErrNoRefreshToken},
		{"wider scope", map[string]any{"access_token": "ya29.x", "refresh_token": "1//r", "scope": Scope + " https://www.googleapis.com/auth/drive"}, ErrScope},
		{"other scope only", map[string]any{"access_token": "ya29.x", "refresh_token": "1//r", "scope": "https://www.googleapis.com/auth/drive"}, ErrScope},
		{"missing scope", map[string]any{"access_token": "ya29.x", "refresh_token": "1//r"}, ErrScope},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd, _ := exchangeServer(t, http.StatusOK, tc.body)
			rt, err := runExchange(t, fd)
			if rt != "" || !errors.Is(err, tc.want) {
				t.Fatalf("ExchangeCode = %q, %v; want %v", rt, err, tc.want)
			}
			if strings.Contains(err.Error(), "1//r") {
				t.Fatalf("error leaks the refresh token: %v", err)
			}
		})
	}
}

func TestExchangeCodeInvalidGrantIsAuthAndRedacted(t *testing.T) {
	fd, forms := exchangeServer(t, http.StatusBadRequest, map[string]any{
		"error": "invalid_grant", "error_description": "code 4/auth-code-value with secret " + testSecret + " and verifier verifier-value-0123456789012345678901234567890 is bad",
	})
	_, err := runExchange(t, fd)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	for _, secret := range []string{"4/auth-code-value", testSecret, "verifier-value-0123456789012345678901234567890"} {
		if strings.Contains(err.Error(), secret) {
			t.Fatalf("error leaks %q: %v", secret, err)
		}
	}
	if len(*forms) != 1 {
		t.Fatalf("authorization code sent %d times, want exactly once", len(*forms))
	}
}

func TestExchangeCodeRejectsEmptyArguments(t *testing.T) {
	_, err := ExchangeCode(context.Background(), nil, testClientID, testSecret, "", "https://cloud.example.com/cb", "v")
	if !errors.Is(err, ErrInvalidArgument) {
		t.Fatalf("err = %v, want ErrInvalidArgument", err)
	}
}

func TestAccessTokenIsCachedUntilShortlyBeforeExpiry(t *testing.T) {
	fd := newFakeDrive(t)
	clk := &fakeClock{now: time.Date(2026, 11, 28, 3, 0, 0, 0, time.UTC)}
	c, _ := newTestClient(t, fd, func(cfg *Config) { cfg.Clock = clk.Now })
	ctx := context.Background()
	for range 3 {
		if err := c.CheckAccess(ctx, "Engram Backups"); err != nil {
			t.Fatalf("CheckAccess: %v", err)
		}
	}
	// CheckAccess always proves the refresh token; folder calls reuse the cache.
	before := fd.count("token")
	if _, err := c.EnsureFolder(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.EnsureFolder(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if got := fd.count("token") - before; got != 0 {
		t.Fatalf("token refreshed %d times while the cached token was valid", got)
	}
	clk.Advance(time.Hour - 2*time.Minute) // inside the validity window
	if _, err := c.EnsureFolder(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if got := fd.count("token") - before; got != 0 {
		t.Fatalf("token refreshed %d times 58 minutes into a 60 minute token", got)
	}
	clk.Advance(90 * time.Second) // within the refresh skew of expiry
	if _, err := c.EnsureFolder(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if got := fd.count("token") - before; got != 1 {
		t.Fatalf("token refreshed %d times near expiry, want 1", got)
	}
	f := fd.requests("token")[0].Body
	form, _ := url.ParseQuery(string(f))
	if form.Get("grant_type") != "refresh_token" || form.Get("refresh_token") != testRefresh {
		t.Fatalf("refresh form = %v", form)
	}
}

func TestUnauthorizedRefreshesTokenOnce(t *testing.T) {
	fd := newFakeDrive(t)
	fd.revoked["ya29.access-1"] = true
	c, _ := newTestClient(t, fd)
	if _, err := c.EnsureFolder(context.Background(), "Engram Backups"); err != nil {
		t.Fatalf("EnsureFolder after one 401: %v", err)
	}
	if fd.count("token") != 2 || fd.count("list") != 2 {
		t.Fatalf("token calls %d, list calls %d; want 2 and 2", fd.count("token"), fd.count("list"))
	}
	if got := fd.requests("list")[1].Header.Get("Authorization"); got != "Bearer ya29.access-2" {
		t.Fatalf("retry Authorization = %q", got)
	}
}

func TestPersistentUnauthorizedIsAuthAfterOneRefresh(t *testing.T) {
	fd := newFakeDrive(t)
	fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusUnauthorized, "authError", "Invalid Credentials")
		return true
	}
	c, _ := newTestClient(t, fd)
	_, err := c.EnsureFolder(context.Background(), "Engram Backups")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if fd.count("token") != 2 || fd.count("list") != 2 {
		t.Fatalf("token calls %d, list calls %d; want 2 and 2", fd.count("token"), fd.count("list"))
	}
}

func TestInvalidGrantIsErrAuthReconnect(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd, func(cfg *Config) { cfg.RefreshToken = "1//revoked-refresh-token" })
	err := c.CheckAccess(context.Background(), "Engram Backups")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("err = %v, want ErrAuth", err)
	}
	if !strings.Contains(err.Error(), "authorization revoked or expired; reconnect Google") {
		t.Fatalf("err = %q, want the reconnect hint", err)
	}
	var ge *Error
	if !errors.As(err, &ge) || ge.Reason != "invalid_grant" {
		t.Fatalf("err = %#v, want Reason invalid_grant", err)
	}
	if fd.count("token") != 1 || fd.count("list") != 0 {
		t.Fatalf("token calls %d, list calls %d; want 1 and 0 (invalid_grant is not retried)", fd.count("token"), fd.count("list"))
	}
}
