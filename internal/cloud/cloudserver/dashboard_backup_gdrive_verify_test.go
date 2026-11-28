package cloudserver

import (
	"crypto/sha256"
	"encoding/base64"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"testing"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/gdrive"
)

// twoAdminGDriveFixture: two managed admins on one server sharing the
// pending Google Drive destination; returns the fixture (p-admin cookie)
// and the second admin's cookie.
func twoAdminGDriveFixture(t *testing.T) (backupSettingsFixture, *http.Cookie) {
	t.Helper()
	store := newLoginAuditTestStore()
	store.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, true)
	store.principals["p-admin2"] = dashboardStoredPrincipal("p-admin2", cloudstore.PrincipalRoleAdmin, true)
	authn := resolvingAuth{principals: map[string]cloudauth.Principal{
		"admin-token":  dashboardManagedPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, true),
		"admin2-token": dashboardManagedPrincipal("p-admin2", cloudstore.PrincipalRoleAdmin, true),
	}}
	srv := New(store, authn, 0, WithAdminIdentityStore(store))
	c1 := managedDashboardLogin(t, srv, "admin-token", false)
	c2 := managedDashboardLogin(t, srv, "admin2-token", false)
	return wireBackupFixture(t, srv, store, c1, pendingGDriveSettings()), c2
}

// S15/S3: spoofed Host / X-Forwarded-* never change the redirect URI; the
// consent URL carries exactly the expected parameters; challenge = S256(verifier).
func TestDashboardGDriveConnectRedirectURIIgnoresForwardedHeaders(t *testing.T) {
	for name, h := range map[string]map[string]string{
		"plain":     nil,
		"xfh":       {"X-Forwarded-Host": "evil.example", "X-Forwarded-Proto": "http"},
		"xfh-list":  {"X-Forwarded-Host": "evil.example, engram.example.test"},
		"forwarded": {"Forwarded": "host=evil.example;proto=http"},
	} {
		t.Run(name, func(t *testing.T) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: f.cookie, headers: h})
			if rec.Code != http.StatusSeeOther {
				t.Fatalf("connect = %d", rec.Code)
			}
			if rec.Header().Get("Cache-Control") != "no-store" || rec.Header().Get("Referrer-Policy") != "no-referrer" {
				t.Fatalf("headers %v", rec.Header())
			}
			u, _ := url.Parse(rec.Header().Get("Location"))
			if u.Scheme+"://"+u.Host+u.Path != "https://accounts.google.com/o/oauth2/v2/auth" {
				t.Fatalf("auth endpoint %q", u)
			}
			q := u.Query()
			keys := []string{}
			for k, v := range q {
				if len(v) != 1 {
					t.Fatalf("param %s repeated", k)
				}
				keys = append(keys, k)
			}
			sort.Strings(keys)
			if strings.Join(keys, ",") != "access_type,client_id,code_challenge,code_challenge_method,include_granted_scopes,prompt,redirect_uri,response_type,scope,state" {
				t.Fatalf("params %v", keys)
			}
			if q.Get("redirect_uri") != testGDriveCallbackURI || q.Get("scope") != gdrive.Scope || q.Get("scope") != "https://www.googleapis.com/auth/drive.file" ||
				q.Get("access_type") != "offline" || q.Get("prompt") != "consent" || q.Get("code_challenge_method") != "S256" || q.Get("response_type") != "code" || q.Get("client_id") != testGDriveClientID {
				t.Fatalf("consent query %v", q)
			}
			pending := f.settings.oauthStates[q.Get("state")]
			sum := sha256.Sum256([]byte(pending.verifier))
			if pending.principal != "p-admin" || base64.RawURLEncoding.EncodeToString(sum[:]) != q.Get("code_challenge") {
				t.Fatalf("challenge/verifier mismatch")
			}
			if strings.Contains(u.String(), pending.verifier) || strings.Contains(u.String(), testGDriveClientSecret) {
				t.Fatalf("consent URL leaks verifier/secret")
			}
			// callback with spoofed headers: exchange uses the same redirect URI and the verifier
			cb := gdriveCallbackRequest(f, url.Values{"state": {q.Get("state")}, "code": {testGDriveCode}}, f.cookie, h)
			if dashboardRedirect(cb) != backupsPagePath+"?notice=gdrive-connected" {
				t.Fatalf("callback %d %q", cb.Code, dashboardRedirect(cb))
			}
			if len(f.google.requests) != 1 {
				t.Fatalf("google hits %d", len(f.google.requests))
			}
			form := f.google.requests[0].form
			if form.Get("redirect_uri") != testGDriveCallbackURI || form.Get("code_verifier") != pending.verifier || form.Get("code") != testGDriveCode || form.Get("grant_type") != "authorization_code" {
				t.Fatalf("exchange form %v", form)
			}
		})
	}
}

// S3: connect guard order — no session, member, legacy, cross-origin, no public URL write nothing.
func TestDashboardGDriveConnectRefusalsWriteNothing(t *testing.T) {
	cases := map[string]func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int){
		"no session": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			return f, nil, nil, http.StatusSeeOther
		},
		"cross-site": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			return f, f.cookie, map[string]string{"Sec-Fetch-Site": "cross-site"}, http.StatusForbidden
		},
		"same-site sibling origin": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			return f, f.cookie, map[string]string{"Origin": "https://evil.example.com"}, http.StatusForbidden
		},
		"member": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			srv, audit, cookie := memberDashboardServer(t)
			f := wireBackupFixture(t, srv, audit, cookie, pendingGDriveSettings())
			return f, cookie, nil, http.StatusForbidden
		},
		"legacy": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			srv, audit, cookie := legacyAdminDashboardServer(t)
			f := wireBackupFixture(t, srv, audit, cookie, pendingGDriveSettings())
			return f, cookie, nil, http.StatusForbidden
		},
		"no public url": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			f := gdriveBackupFixture(t, pendingGDriveSettings())
			WithPublicURL("")(f.srv)
			return f, f.cookie, nil, http.StatusConflict
		},
		"s3 destination": func(t *testing.T) (backupSettingsFixture, *http.Cookie, map[string]string, int) {
			f := gdriveBackupFixture(t, configuredBackupSettings())
			return f, f.cookie, nil, http.StatusConflict
		},
	}
	for name, mk := range cases {
		t.Run(name, func(t *testing.T) {
			f, cookie, h, want := mk(t)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: cookie, headers: h})
			if rec.Code != want {
				t.Fatalf("got %d want %d body=%q", rec.Code, want, rec.Body.String())
			}
			if strings.Contains(rec.Header().Get("Location"), "accounts.google.com") || f.settings.oauthCreates != 0 || backupAuditCount(f.audit) != 0 {
				t.Fatalf("refusal wrote: creates=%d audit=%d loc=%q", f.settings.oauthCreates, backupAuditCount(f.audit), rec.Header().Get("Location"))
			}
		})
	}
	t.Run("GET connect 405", func(t *testing.T) {
		f := gdriveBackupFixture(t, pendingGDriveSettings())
		rec := doBackupRequest(f.srv, backupRequest{method: http.MethodGet, path: backupGDriveConnectPath, cookie: f.cookie})
		if rec.Code != http.StatusMethodNotAllowed || f.settings.oauthCreates != 0 {
			t.Fatalf("GET connect %d", rec.Code)
		}
	})
}

// S3 login-CSRF: the attacker admin's code+state delivered to the victim
// admin's browser does not bind the attacker's Google account; nothing reaches
// Google; the attacker's state stays usable only by the attacker.
func TestDashboardGDriveCallbackRefusesAStateFromAnotherAdmin(t *testing.T) {
	f, victim := twoAdminGDriveFixture(t)
	logs := captureLogs(t)
	attacker := connectGDrive(t, f) // p-admin
	state := attacker.Query().Get("state")
	f.audit.auditMu.Lock()
	f.audit.auditEvents = nil
	f.audit.auditMu.Unlock()
	rec := gdriveCallbackRequest(f, url.Values{"state": {state}, "code": {"4/attacker-code-xyz"}}, victim, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-mismatch" {
		t.Fatalf("victim callback %d %q", rec.Code, dashboardRedirect(rec))
	}
	if f.google.hits() != 0 || len(f.settings.gdriveTokens) != 0 || backupAuditCount(f.audit) != 0 {
		t.Fatalf("victim callback had effects")
	}
	if strings.Contains(logs.String(), "attacker-code") || strings.Contains(logs.String(), state) {
		t.Fatalf("logs leak: %s", logs.String())
	}
	// victim admin's own state cannot be used by attacker either
	v := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupGDriveConnectPath, cookie: victim})
	vu, _ := url.Parse(v.Header().Get("Location"))
	rec = gdriveCallbackRequest(f, url.Values{"state": {vu.Query().Get("state")}, "code": {"4/attacker-code-xyz"}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-mismatch" || f.google.hits() != 0 {
		t.Fatalf("cross use %q", dashboardRedirect(rec))
	}
}

// S15: error params never consume the state or reach Google; logs do not
// echo error_description; no-session redirect drops the query.
func TestDashboardGDriveCallbackErrorParamsAndMissingSessionWriteNothing(t *testing.T) {
	for _, tc := range []struct{ errv, notice string }{{"access_denied", "gdrive-denied"}, {"server_error", "gdrive-error"}, {"", "gdrive-error"}} {
		f := gdriveBackupFixture(t, pendingGDriveSettings())
		logs := captureLogs(t)
		st := connectGDrive(t, f).Query().Get("state")
		before := backupAuditCount(f.audit)
		q := url.Values{"state": {st}, "code": {testGDriveCode}, "error": {tc.errv}, "error_description": {"desc-SECRETISH-123"}}
		rec := gdriveCallbackRequest(f, q, f.cookie, nil)
		if dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice || f.google.hits() != 0 || f.settings.oauthUsed != 0 || backupAuditCount(f.audit) != before {
			t.Fatalf("%s: %q hits=%d used=%d", tc.errv, dashboardRedirect(rec), f.google.hits(), f.settings.oauthUsed)
		}
		if strings.Contains(logs.String(), "SECRETISH") || strings.Contains(logs.String(), testGDriveCode) {
			t.Fatalf("logs leak %s", logs.String())
		}
		assertCallbackHeaders(t, rec)
	}
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	logs := captureLogs(t)
	st := connectGDrive(t, f).Query().Get("state")
	rec := gdriveCallbackRequest(f, url.Values{"state": {st}, "code": {testGDriveCode}}, nil, nil)
	if loc := dashboardRedirect(rec); loc != "/dashboard/login?next=%2Fdashboard%2Fadmin%2Fbackups" || strings.Contains(rec.Body.String(), st) {
		t.Fatalf("no-session %q", loc)
	}
	if strings.Contains(logs.String(), testGDriveCode) || strings.Contains(logs.String(), st) || f.settings.oauthUsed != 0 {
		t.Fatalf("no-session leaked/consumed")
	}
	// state still valid for the admin afterwards
	rec = gdriveCallbackRequest(f, url.Values{"state": {st}, "code": {testGDriveCode}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-connected" {
		t.Fatalf("after login %q", dashboardRedirect(rec))
	}
}

// S15: exchange failure (Google echoing code/secret) writes only one failure
// audit row; nothing leaks; the state is consumed (not replayable).
func TestDashboardGDriveCallbackExchangeFailureOnlyAudits(t *testing.T) {
	f := gdriveBackupFixture(t, pendingGDriveSettings())
	logs := captureLogs(t)
	st := connectGDrive(t, f).Query().Get("state")
	verifier := f.settings.oauthStates[st].verifier
	f.audit.auditMu.Lock()
	f.audit.auditEvents = nil
	f.audit.auditMu.Unlock()
	f.google.status = http.StatusBadRequest
	f.google.body = `{"error":"invalid_grant","error_description":"bad ` + testGDriveCode + ` ` + testGDriveClientSecret + ` ` + verifier + `"}`
	rec := gdriveCallbackRequest(f, url.Values{"state": {st}, "code": {testGDriveCode}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-exchange" || len(f.settings.gdriveTokens) != 0 {
		t.Fatalf("exchange failure %q", dashboardRedirect(rec))
	}
	f.audit.auditMu.Lock()
	events := append([]cloudstore.AuthAuditEvent(nil), f.audit.auditEvents...)
	f.audit.auditMu.Unlock()
	if len(events) != 1 || events[0].Action != cloudstore.AuthAuditActionBackupDestinationAuthorize || events[0].Outcome != "failure" {
		t.Fatalf("audit %+v", events)
	}
	for _, text := range []string{logs.String(), fmtAny(events), rec.Body.String(), dashboardRedirect(rec)} {
		for _, sec := range []string{testGDriveCode, testGDriveClientSecret, verifier, st} {
			if strings.Contains(text, sec) {
				t.Fatalf("leak %q in %q", sec, text)
			}
		}
	}
	if f.google.hits() != 1 {
		t.Fatalf("hits %d", f.google.hits())
	}
	rec = gdriveCallbackRequest(f, url.Values{"state": {st}, "code": {testGDriveCode}}, f.cookie, nil)
	if dashboardRedirect(rec) != backupsPagePath+"?notice=gdrive-expired" || f.google.hits() != 1 {
		t.Fatalf("replay %q", dashboardRedirect(rec))
	}
}

// S15: a wide scope or missing refresh token is refused and stores nothing.
func TestDashboardGDriveCallbackRefusesAWiderScope(t *testing.T) {
	for _, body := range []string{
		`{"refresh_token":"1//r","scope":"https://www.googleapis.com/auth/drive"}`,
		`{"refresh_token":"1//r","scope":"https://www.googleapis.com/auth/drive.file https://www.googleapis.com/auth/drive"}`,
		`{"refresh_token":"1//r"}`,
		`{"scope":"https://www.googleapis.com/auth/drive.file"}`,
	} {
		f := gdriveBackupFixture(t, pendingGDriveSettings())
		st := connectGDrive(t, f).Query().Get("state")
		f.google.body = body
		rec := gdriveCallbackRequest(f, url.Values{"state": {st}, "code": {testGDriveCode}}, f.cookie, nil)
		loc := dashboardRedirect(rec)
		if (loc != backupsPagePath+"?notice=gdrive-scope" && loc != backupsPagePath+"?notice=gdrive-no-refresh") || len(f.settings.gdriveTokens) != 0 {
			t.Fatalf("%s -> %q tokens=%d", body, loc, len(f.settings.gdriveTokens))
		}
	}
}
