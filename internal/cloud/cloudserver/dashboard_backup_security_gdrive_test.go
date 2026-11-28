package cloudserver

import (
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// gdriveSideEffects counts every write and outbound request a refused
// Google Drive request must not cause.
func assertNoGDriveSideEffects(t *testing.T, f backupSettingsFixture, transport *countingTransport, label string) {
	t.Helper()
	if n := f.settings.mutations(); n != 0 {
		t.Fatalf("%s: settings store touched %d times", label, n)
	}
	if transport.hits.Load() != 0 || f.google.hits() != 0 || f.gdrive.calls != 0 || f.dropbox.calls != 0 || f.checker.calls != 0 || len(f.runner.calls) != 0 {
		t.Fatalf("%s: reached out: transport %d google %d gdrive %d dropbox %d s3 %d runs %d", label, transport.hits.Load(), f.google.hits(), f.gdrive.calls, f.dropbox.calls, f.checker.calls, len(f.runner.calls))
	}
	if n := backupAuditCount(f.audit); n != 0 {
		t.Fatalf("%s: %d backup audit events", label, n)
	}
}

// S3/S7: the Google Drive save, connect and test requests refuse a member,
// a legacy admin, a stale session (disabled, demoted or deleted admin), a
// cross-origin request and a GET or PUT with zero writes, zero audit rows
// and zero outbound requests, even with the real Drive check.
func TestBackupSecurityGDriveMutationRefusals(t *testing.T) {
	routes := []struct {
		name, path, form string
		authorized       bool
	}{
		{"save gdrive", backupDestinationPath, validGDriveForm, false},
		{"connect gdrive", backupGDriveConnectPath, "", false},
		{"test gdrive", backupDestinationTestPath, "", true},
		{"check gdrive", backupDestinationCheckPath, validGDriveForm, false},
	}
	settingsFor := func(authorized bool) *fakeBackupSettingsStore {
		if authorized {
			return authorizedGDriveSettings()
		}
		return pendingGDriveSettings()
	}
	cases := []struct {
		name    string
		fixture func(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture
		method  string
		headers map[string]string
		status  int
	}{
		{name: "member", fixture: func(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture {
			srv, audit, cookie := memberDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, settings)
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "legacy admin", fixture: func(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture {
			srv, audit, cookie := legacyAdminDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, settings)
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "stale session disabled admin", fixture: staleGDriveFixture(func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, false)
		}), method: http.MethodPost},
		{name: "stale session demoted admin", fixture: staleGDriveFixture(func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleMember, true)
		}), method: http.MethodPost},
		{name: "stale session deleted principal", fixture: staleGDriveFixture(func(f backupSettingsFixture) { delete(f.audit.principals, "p-admin") }), method: http.MethodPost},
		{name: "cross-origin", fixture: gdriveBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.test"}, status: http.StatusForbidden},
		{name: "foreign Origin", fixture: gdriveBackupFixture, method: http.MethodPost, headers: map[string]string{"Origin": "http://evil.example.test"}, status: http.StatusForbidden},
		{name: "same-site other origin", fixture: gdriveBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://other.example.com"}, status: http.StatusForbidden},
		{name: "Google origin", fixture: gdriveBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://accounts.google.com"}, status: http.StatusForbidden},
		{name: "GET", fixture: gdriveBackupFixture, method: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "PUT", fixture: gdriveBackupFixture, method: http.MethodPut, status: http.StatusMethodNotAllowed},
	}
	for _, route := range routes {
		for _, tc := range cases {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				f := tc.fixture(t, settingsFor(route.authorized))
				transport := &countingTransport{}
				f.srv.backupCheckGDrive = nil // the real check, over a counting transport
				f.srv.backupGDriveHTTPClient = &http.Client{Transport: transport}
				rec := doBackupRequest(f.srv, backupRequest{method: tc.method, path: route.path, form: route.form, headers: tc.headers, cookie: f.cookie})
				if tc.status != 0 && rec.Code != tc.status {
					t.Fatalf("expected %d, got %d body=%q", tc.status, rec.Code, rec.Body.String())
				}
				if rec.Code < 300 || (route.path == backupGDriveConnectPath && strings.Contains(rec.Header().Get("Location"), "accounts.google.com")) {
					t.Fatalf("expected a refusal, got %d %q", rec.Code, rec.Header().Get("Location"))
				}
				assertNoGDriveSideEffects(t, f, transport, tc.name)
				assertNoGDriveSecret(t, "refusal", rec.Body.String())
			})
		}
	}
}

func staleGDriveFixture(mutate func(f backupSettingsFixture)) func(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture {
	return func(t *testing.T, settings *fakeBackupSettingsStore) backupSettingsFixture {
		f := gdriveBackupFixture(t, settings)
		mutate(f)
		return f
	}
}

// S3/S7: the OAuth callback is a top-level GET from Google, so it skips the
// same-origin check but still needs a managed admin session. Every refusal
// (no session, member, legacy admin, stale session, another admin's state,
// expired, reused, tampered or missing state, missing code, a destination
// changed since Connect, no public URL) makes zero writes and zero outbound
// requests, and no code or state reaches the redirect, the body or logs.
func TestBackupSecurityGDriveCallbackRefusals(t *testing.T) {
	type setup struct {
		f     backupSettingsFixture
		query url.Values
		state string
	}
	connected := func(t *testing.T, f backupSettingsFixture) setup {
		consent := connectGDrive(t, f)
		state := consent.Query().Get("state")
		f.audit.auditMu.Lock()
		f.audit.auditEvents = nil // only the callback's own audit rows count
		f.audit.auditMu.Unlock()
		f.settings.oauthCreates = 0
		return setup{f: f, state: state, query: url.Values{"state": {state}, "code": {testGDriveCode}}}
	}
	admin := func(t *testing.T) setup { return connected(t, gdriveBackupFixture(t, pendingGDriveSettings())) }
	asOther := func(login func(t *testing.T) (*CloudServer, *loginAuditTestStore, *http.Cookie)) func(t *testing.T) setup {
		return func(t *testing.T) setup {
			s := admin(t)
			srv, audit, cookie := login(t)
			f := wireBackupFixture(t, srv, audit, cookie, s.f.settings)
			return setup{f: f, state: s.state, query: s.query}
		}
	}
	cases := []struct {
		name    string
		setup   func(t *testing.T) setup
		noAuth  bool
		status  int
		notice  string
		headers map[string]string
	}{
		{name: "no session", setup: admin, noAuth: true, status: http.StatusSeeOther},
		{name: "member", setup: asOther(memberDashboardServer), status: http.StatusForbidden},
		{name: "legacy admin", setup: asOther(legacyAdminDashboardServer), status: http.StatusForbidden},
		{name: "stale session disabled admin", setup: func(t *testing.T) setup {
			s := admin(t)
			s.f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, false)
			return s
		}},
		{name: "stale session demoted admin", setup: func(t *testing.T) setup {
			s := admin(t)
			s.f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleMember, true)
			return s
		}},
		{name: "other admin's state", setup: func(t *testing.T) setup {
			s := admin(t)
			for state, pending := range s.f.settings.oauthStates {
				pending.principal = "p-other-admin"
				s.f.settings.oauthStates[state] = pending
			}
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-mismatch"},
		{name: "expired", setup: func(t *testing.T) setup {
			s := admin(t)
			for state, pending := range s.f.settings.oauthStates {
				pending.expired = true
				s.f.settings.oauthStates[state] = pending
			}
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "reused", setup: func(t *testing.T) setup {
			s := admin(t)
			first := gdriveCallbackRequest(s.f, s.query, s.f.cookie, nil)
			if dashboardRedirect(first) != backupsPagePath+"?notice=gdrive-connected" {
				t.Fatalf("first callback = %q", dashboardRedirect(first))
			}
			// Only the second callback's effects count.
			s.f.settings.oauthUsed, s.f.settings.gdriveTokens = 0, nil
			s.f.google.requests = nil
			s.f.audit.auditMu.Lock()
			s.f.audit.auditEvents = nil
			s.f.audit.auditMu.Unlock()
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "tampered state", setup: func(t *testing.T) setup {
			s := admin(t)
			tampered := []byte(s.state)
			tampered[5] ^= 0x01
			s.query.Set("state", string(tampered))
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "missing state", setup: func(t *testing.T) setup {
			s := admin(t)
			s.query.Del("state")
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "repeated state", setup: func(t *testing.T) setup {
			s := admin(t)
			s.query.Add("state", s.state)
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "missing code", setup: func(t *testing.T) setup {
			s := admin(t)
			s.query.Del("code")
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-expired"},
		{name: "destination changed", setup: func(t *testing.T) setup {
			s := admin(t)
			s.f.settings.bindingVersion++ // saved again after Connect
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-mismatch"},
		{name: "destination replaced by s3", setup: func(t *testing.T) setup {
			s := admin(t)
			s.f.settings.destination = configuredBackupSettings().destination
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-mismatch"},
		{name: "no public URL", setup: func(t *testing.T) setup {
			s := admin(t)
			WithPublicURL("")(s.f.srv)
			return s
		}, status: http.StatusSeeOther, notice: "gdrive-no-public-url"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			logs := captureLogs(t)
			s := tc.setup(t)
			transport := &countingTransport{}
			s.f.srv.backupGDriveHTTPClient = &http.Client{Transport: transport}
			cookie := s.f.cookie
			if tc.noAuth {
				cookie = nil
			}
			rec := gdriveCallbackRequest(s.f, s.query, cookie, tc.headers)
			if tc.status != 0 && rec.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%q", tc.status, rec.Code, rec.Body.String())
			}
			location := dashboardRedirect(rec)
			switch {
			case tc.notice != "":
				if location != backupsPagePath+"?notice="+tc.notice {
					t.Fatalf("redirect = %q, want notice %s", location, tc.notice)
				}
			case tc.noAuth:
				if location != "/dashboard/login?next=%2Fdashboard%2Fadmin%2Fbackups" {
					t.Fatalf("login redirect = %q", location)
				}
			case rec.Code < 300 || location == backupsPagePath+"?notice=gdrive-connected":
				t.Fatalf("expected a refusal, got %d %q", rec.Code, location)
			}
			assertCallbackHeaders(t, rec)
			if n := s.f.settings.oauthUsed + len(s.f.settings.gdriveTokens) + len(s.f.settings.putGDrive) + s.f.settings.oauthCreates; n != 0 {
				t.Fatalf("refused callback wrote %d times", n)
			}
			if transport.hits.Load() != 0 || s.f.google.hits() != 0 {
				t.Fatalf("refused callback reached Google: %d/%d", transport.hits.Load(), s.f.google.hits())
			}
			if n := backupAuditCount(s.f.audit); n != 0 {
				t.Fatalf("refused callback recorded %d backup audit events", n)
			}
			for label, text := range map[string]string{"location": location, "body": rec.Body.String(), "logs": logs.String()} {
				assertNoGDriveSecret(t, label, text, s.state)
			}
		})
	}
	t.Run("POST", func(t *testing.T) {
		s := admin(t)
		rec := doBackupRequest(s.f.srv, backupRequest{method: http.MethodPost, path: backupGDriveCallback, form: s.query.Encode(), cookie: s.f.cookie})
		if rec.Code != http.StatusMethodNotAllowed || s.f.settings.oauthUsed != 0 || len(s.f.settings.gdriveTokens) != 0 || s.f.google.hits() != 0 {
			t.Fatalf("POST callback = %d", rec.Code)
		}
	})
}
