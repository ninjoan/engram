package cloudserver

import (
	"errors"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// countingTransport counts outbound requests and answers none of them.
type countingTransport struct{ hits atomic.Int32 }

func (c *countingTransport) RoundTrip(*http.Request) (*http.Response, error) {
	c.hits.Add(1)
	return nil, errors.New("outbound request refused by the test")
}

// S3/S7: the Dropbox variants of the save, check and test routes refuse a
// member, a legacy admin, a stale session (disabled, demoted or deleted
// admin), a cross-origin request and a GET with zero writes, zero audit
// rows and zero outbound requests, even with the real Dropbox check.
func TestBackupSecurityDropboxRefusalsMakeNoWritesOrRequests(t *testing.T) {
	routes := []struct {
		name, path, form string
	}{
		{"save dropbox", backupDestinationPath, validDropboxForm},
		{"check dropbox", backupDestinationCheckPath, validDropboxForm},
		{"test dropbox", backupDestinationTestPath, ""},
		{"remove dropbox", backupDestinationRemovePath, ""},
	}
	stale := func(mutate func(f backupSettingsFixture)) func(t *testing.T) backupSettingsFixture {
		return func(t *testing.T) backupSettingsFixture {
			f := dropboxBackupFixture(t)
			mutate(f)
			return f
		}
	}
	cases := []struct {
		name    string
		fixture func(t *testing.T) backupSettingsFixture
		method  string
		headers map[string]string
		status  int
	}{
		{name: "member", fixture: func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := memberDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, configuredDropboxSettings())
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "legacy admin", fixture: func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := legacyAdminDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, configuredDropboxSettings())
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "stale session disabled admin", fixture: stale(func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, false)
		}), method: http.MethodPost},
		{name: "stale session demoted admin", fixture: stale(func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleMember, true)
		}), method: http.MethodPost},
		{name: "stale session deleted principal", fixture: stale(func(f backupSettingsFixture) { delete(f.audit.principals, "p-admin") }), method: http.MethodPost},
		{name: "cross-origin", fixture: dropboxBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.test"}, status: http.StatusForbidden},
		{name: "foreign Origin", fixture: dropboxBackupFixture, method: http.MethodPost, headers: map[string]string{"Origin": "http://evil.example.test"}, status: http.StatusForbidden},
		{name: "same-site other origin", fixture: dropboxBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://other.example.com"}, status: http.StatusForbidden},
		{name: "GET", fixture: dropboxBackupFixture, method: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "PUT", fixture: dropboxBackupFixture, method: http.MethodPut, status: http.StatusMethodNotAllowed},
	}
	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				f := tc.fixture(t)
				transport := &countingTransport{}
				f.srv.backupCheckDropbox = nil // the real check, over a counting transport
				f.srv.backupDropboxHTTPClient = &http.Client{Transport: transport}
				rec := doBackupRequest(f.srv, backupRequest{method: tc.method, path: route.path, form: route.form, headers: tc.headers, cookie: f.cookie})
				if tc.status != 0 && rec.Code != tc.status {
					t.Fatalf("expected %d, got %d body=%q", tc.status, rec.Code, rec.Body.String())
				}
				if rec.Code < 300 {
					t.Fatalf("expected a refusal, got %d", rec.Code)
				}
				if n := f.settings.mutations(); n != 0 {
					t.Fatalf("refused request touched the settings store %d times", n)
				}
				if transport.hits.Load() != 0 || f.dropbox.calls != 0 || f.checker.calls != 0 || len(f.runner.calls) != 0 {
					t.Fatalf("refused request reached out: requests %d dropbox %d s3 %d runs %d", transport.hits.Load(), f.dropbox.calls, f.checker.calls, len(f.runner.calls))
				}
				if n := backupAuditCount(f.audit); n != 0 {
					t.Fatalf("refused request recorded %d backup audit events", n)
				}
				assertNoDropboxSecret(t, "refusal", rec.Body.String())
			})
		}
	}
}

// The real Dropbox check is the one the routes use when no test seam is set:
// an allowed check reaches the transport, so the refusal test above proves
// a real absence of requests.
func TestBackupSecurityDropboxRealCheckUsesTheTransport(t *testing.T) {
	f := emptyBackupFixture(t)
	transport := &countingTransport{}
	f.srv.backupCheckDropbox = nil
	f.srv.backupDropboxHTTPClient = &http.Client{Transport: transport}
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationCheckPath, form: validDropboxForm, cookie: f.cookie})
	if rec.Code != http.StatusOK || transport.hits.Load() == 0 {
		t.Fatalf("allowed check = %d with %d requests", rec.Code, transport.hits.Load())
	}
	if body := rec.Body.String(); !strings.Contains(body, `data-check-result="`) {
		t.Fatalf("no check result, body=%q", body)
	}
	assertNoDropboxSecret(t, "real check page", rec.Body.String())
	assertNoDropboxSecretInAudit(t, f)
}
