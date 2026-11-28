package gdrive

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// AuthCodeURL returns the Google consent URL for the dashboard's "Connect
// with Google" flow: authorization code with PKCE (S256), offline access so a
// refresh token is issued, forced consent, and only the drive.file scope.
func AuthCodeURL(clientID, redirectURI, state, codeChallenge string) string {
	v := url.Values{
		"client_id":              {clientID},
		"redirect_uri":           {redirectURI},
		"response_type":          {"code"},
		"scope":                  {Scope},
		"access_type":            {"offline"},
		"prompt":                 {"consent"},
		"include_granted_scopes": {"false"},
		"state":                  {state},
		"code_challenge":         {codeChallenge},
		"code_challenge_method":  {"S256"},
	}
	return authURL + "?" + v.Encode()
}

// NewPKCE returns a fresh RFC 7636 code verifier (43 characters from 32
// random bytes) and its S256 challenge.
func NewPKCE() (verifier, challenge string, err error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", "", fmt.Errorf("gdrive: generate PKCE verifier: %w", err)
	}
	verifier = base64.RawURLEncoding.EncodeToString(b)
	return verifier, pkceChallenge(verifier), nil
}

func pkceChallenge(verifier string) string {
	sum := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(sum[:])
}

// ExchangeCode trades an authorization code (from the AuthCodeURL redirect)
// for a refresh token at https://oauth2.googleapis.com/token. The code is sent
// once, never retried. It fails with ErrNoRefreshToken when Google issues no
// refresh token and with ErrScope unless exactly the drive.file scope was
// granted. httpClient is optional and copied; redirects are refused. Errors
// never echo the client secret, code or verifier.
func ExchangeCode(ctx context.Context, httpClient *http.Client, clientID, clientSecret, code, redirectURI, verifier string) (refreshToken string, err error) {
	return exchangeCode(ctx, httpClient, googleEndpoints(), clientID, clientSecret, code, redirectURI, verifier)
}

func exchangeCode(ctx context.Context, httpClient *http.Client, ep endpoints, clientID, clientSecret, code, redirectURI, verifier string) (string, error) {
	const op = "ExchangeCode"
	for _, v := range []string{clientID, clientSecret, code, redirectURI, verifier} {
		if strings.TrimSpace(v) == "" {
			return "", fmt.Errorf("gdrive: %s: %w: client ID, client secret, code, redirect URI and verifier are required", op, ErrInvalidArgument)
		}
	}
	c := newClient(httpClient, ep)
	if httpClient == nil {
		defer c.hc.CloseIdleConnections() // the transport was built for this call only
	}
	c.clientSecret = clientSecret
	c.maxRetries = 0 // an authorization code is single-use
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {redirectURI},
		"client_id":     {clientID},
		"client_secret": {clientSecret},
		"code_verifier": {verifier},
	}
	resp, err := c.do(ctx, formCall(op, ep.token, form, code, verifier), false)
	if err != nil {
		return "", err
	}
	var body struct {
		RefreshToken string `json:"refresh_token"`
		Scope        string `json:"scope"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil {
		return "", &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Message: "token response is not JSON"}
	}
	if !driveFileOnly(body.Scope) {
		return "", &Error{Op: op, Kind: ErrScope, Message: "granted: " + c.sanitize(body.Scope, maxErrorMessage, []string{body.RefreshToken})}
	}
	if body.RefreshToken == "" {
		return "", &Error{Op: op, Kind: ErrNoRefreshToken}
	}
	return body.RefreshToken, nil
}

func driveFileOnly(scope string) bool {
	fields := strings.Fields(scope)
	return len(fields) == 1 && fields[0] == Scope
}

func formCall(op, tokenURL string, form url.Values, secrets ...string) call {
	return call{
		op:      op,
		method:  http.MethodPost,
		url:     tokenURL,
		header:  http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
		body:    []byte(form.Encode()),
		secrets: secrets,
	}
}

// refresh trades the refresh token for an access token and its lifetime.
func (c *Client) refresh(ctx context.Context) (string, time.Duration, error) {
	const op = "TokenRefresh"
	form := url.Values{
		"grant_type":    {"refresh_token"},
		"refresh_token": {c.refreshToken},
		"client_id":     {c.clientID},
		"client_secret": {c.clientSecret},
	}
	resp, err := c.do(ctx, formCall(op, c.ep.token, form), false)
	if err != nil {
		return "", 0, err
	}
	var body struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
	}
	if err := json.Unmarshal(resp.body, &body); err != nil || body.AccessToken == "" {
		return "", 0, &Error{Op: op, Kind: ErrUnexpected, StatusCode: resp.status, Message: "token response has no access token"}
	}
	if body.ExpiresIn < 0 || body.ExpiresIn > 24*3600 {
		body.ExpiresIn = 0
	}
	return body.AccessToken, time.Duration(body.ExpiresIn) * time.Second, nil
}
