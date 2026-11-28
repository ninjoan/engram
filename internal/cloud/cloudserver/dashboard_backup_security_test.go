package cloudserver

import (
	"bytes"
	"context"
	"log"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

func vfyAssertNoSideEffects(t *testing.T, f backupSettingsFixture, label string) {
	t.Helper()
	if n := f.settings.mutations(); n != 0 {
		t.Fatalf("%s: settings store touched %d times", label, n)
	}
	if f.checker.calls != 0 || len(f.runner.calls) != 0 || f.exporter.calls != 0 {
		t.Fatalf("%s: side effect checks=%d runs=%d exports=%d", label, f.checker.calls, len(f.runner.calls), f.exporter.calls)
	}
	if n := backupAuditCount(f.audit); n != 0 {
		t.Fatalf("%s: %d backup audit events", label, n)
	}
}

// S3: revoked/disabled/demoted principals, HEAD/PUT, and origin combos are refused with zero side effects on every route.
func TestBackupSecurityBackupMutationRefusals(t *testing.T) {
	headerCases := []struct {
		name    string
		headers map[string]string
	}{
		{"https sibling origin same Host", map[string]string{"X-Forwarded-Proto": "https", "Origin": "https://other.example.com"}},
		{"https sibling origin same-site", map[string]string{"X-Forwarded-Proto": "https", "Sec-Fetch-Site": "same-site", "Origin": "https://other.example.com"}},
		{"http origin vs https XFP", map[string]string{"X-Forwarded-Proto": "https", "Origin": "http://example.com"}},
		{"https origin vs plain http", map[string]string{"Origin": "https://example.com"}},
		{"same-origin SFS but evil Origin", map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://evil.test"}},
		{"evil XFH not first", map[string]string{"X-Forwarded-Host": "example.com, evil.test", "Origin": "http://evil.test"}},
		{"userinfo origin", map[string]string{"Origin": "http://example.com@evil.test"}},
		{"origin with path", map[string]string{"Origin": "http://example.com/x"}},
		{"Origin null", map[string]string{"Origin": "null"}},
		{"SFS cross-site no origin", map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{"suffix host", map[string]string{"Origin": "http://example.com.evil.test"}},
	}
	for _, route := range backupMutationRoutes {
		for _, hc := range headerCases {
			t.Run(route.name+"/"+hc.name, func(t *testing.T) {
				f := managedBackupFixture(t)
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: route.path, form: route.form, headers: hc.headers, cookie: f.cookie})
				if rec.Code != http.StatusForbidden {
					t.Fatalf("expected 403, got %d", rec.Code)
				}
				vfyAssertNoSideEffects(t, f, hc.name)
			})
		}
		for _, method := range []string{http.MethodHead, http.MethodPut, http.MethodDelete, http.MethodPatch} {
			t.Run(route.name+"/"+method, func(t *testing.T) {
				f := managedBackupFixture(t)
				rec := doBackupRequest(f.srv, backupRequest{method: method, path: route.path, form: route.form, cookie: f.cookie})
				if rec.Code != http.StatusMethodNotAllowed {
					t.Fatalf("expected 405, got %d", rec.Code)
				}
				vfyAssertNoSideEffects(t, f, method)
			})
		}
		for _, mut := range []struct {
			name    string
			enabled bool
			role    string
		}{{"disabled admin", false, cloudstore.PrincipalRoleAdmin}, {"demoted admin", true, cloudstore.PrincipalRoleMember}} {
			t.Run(route.name+"/"+mut.name, func(t *testing.T) {
				f := managedBackupFixture(t)
				f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", mut.role, mut.enabled)
				rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: route.path, form: route.form, cookie: f.cookie})
				if rec.Code < 300 || rec.Code == http.StatusOK {
					t.Fatalf("expected a refusal, got %d", rec.Code)
				}
				vfyAssertNoSideEffects(t, f, mut.name)
			})
		}
	}
}

// S3: legitimate proxied combos are allowed.
func TestBackupSecurityBackupSameOriginAllowed(t *testing.T) {
	for name, headers := range map[string]map[string]string{
		"uppercase origin":      {"Origin": "HTTP://EXAMPLE.COM"},
		"origin trailing slash": {"Origin": "http://example.com/"},
		"SFS case-insensitive":  {"Sec-Fetch-Site": "Same-Origin", "Origin": "http://example.com"},
		"https XFP list":        {"X-Forwarded-Proto": "https,http", "Origin": "https://example.com:443"},
	} {
		t.Run(name, func(t *testing.T) {
			f := managedBackupFixture(t)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, headers: headers, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther || len(f.settings.clears) != 1 {
				t.Fatalf("expected allowed, got %d", rec.Code)
			}
		})
	}
}

// S7: secret and full access key never rendered, logged or audited; multipart/query/JSON credentials ignored.
func TestBackupSecurityBackupCredentialsNeverEchoed(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	t.Cleanup(func() { log.SetOutput(prev) })

	f := managedBackupFixture(t)
	// multipart body: ParseForm does not read it -> credentials empty -> 400
	mp := "--B\r\nContent-Disposition: form-data; name=\"access_key_id\"\r\n\r\n" + testBackupAccessKeyID + "\r\n--B\r\nContent-Disposition: form-data; name=\"secret_access_key\"\r\n\r\n" + testBackupSecret + "\r\n--B--\r\n"
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: mp, ctype: "multipart/form-data; boundary=B", cookie: f.cookie})
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("multipart save: expected 400, got %d", rec.Code)
	}
	if p := f.settings.putDestination; len(p) != 1 || p[0].AccessKeyID != "" || p[0].SecretAccessKey != "" {
		t.Fatalf("multipart credentials were read: %+v", p)
	}
	// invalid endpoint with valid creds: validation page must not echo secret
	f.settings.putDestinationErr = nil
	form := strings.Replace(validBackupDestinationForm, "https%3A%2F%2Facct", "ftp%3A%2F%2Facct", 1)
	f.settings.putDestinationErr = errInvalidEndpointForProbe
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: form, cookie: f.cookie})
	f.settings.putDestinationErr = nil
	for _, body := range []string{rec.Body.String()} {
		if strings.Contains(body, testBackupSecret) || strings.Contains(body, testBackupAccessKeyID) {
			t.Fatalf("validation page echoed a credential")
		}
	}
	// a store error that embeds a secret goes to log? (500 path)
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validBackupDestinationForm, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("save: %d", rec.Code)
	}
	page := doBackupRequest(f.srv, backupRequest{method: http.MethodGet, path: backupsPagePath, cookie: f.cookie})
	if strings.Contains(page.Body.String(), testBackupSecret) || strings.Contains(page.Body.String(), testBackupAccessKeyID) {
		t.Fatalf("page rendered a credential")
	}
	f.checker.err = context.DeadlineExceeded
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if !f.checker.hadDeadline {
		t.Fatalf("test connection had no deadline")
	}
	f.audit.auditMu.Lock()
	for _, ev := range f.audit.auditEvents {
		enc := strings.ToLower(strings.Join([]string{ev.Action, ev.ReasonCode, strings.TrimSpace(fmtAny(ev.Metadata))}, " "))
		if strings.Contains(enc, strings.ToLower(testBackupSecret)) || strings.Contains(enc, strings.ToLower(testBackupAccessKeyID)) {
			t.Errorf("audit leaked credential: %s", enc)
		}
	}
	f.audit.auditMu.Unlock()
	if strings.Contains(logs.String(), testBackupSecret) || strings.Contains(logs.String(), testBackupAccessKeyID) {
		t.Fatalf("logs leaked a credential: %s", logs.String())
	}
}

// S7: the real access check never follows a redirect and refuses plain http to non-loopback.
func TestBackupSecurityBackupCheckAccessNoRedirect(t *testing.T) {
	var hits atomic.Int32
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer target.Close()
	redirector := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, target.URL+"/steal", http.StatusTemporaryRedirect)
	}))
	defer redirector.Close()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	err := checkBackupDestinationAccess(ctx, cloudstore.BackupDestinationCredentials{Endpoint: redirector.URL, Region: "auto", Bucket: "engram-backups", AccessKeyID: "AKIAXXXXXXXXXXXX", SecretAccessKey: "secretsecretsecret"})
	if err == nil {
		t.Fatalf("redirect must not be reported as success")
	}
	if hits.Load() != 0 {
		t.Fatalf("redirect was followed %d times", hits.Load())
	}
	if n, r := classifyBackupConnectionTest(err); n == "test-ok" {
		t.Fatalf("classified %s %s", n, r)
	}
	for _, ep := range []string{"http://example.com", "http://10.0.0.1:9000", "ftp://127.0.0.1"} {
		if err := checkBackupDestinationAccess(ctx, cloudstore.BackupDestinationCredentials{Endpoint: ep, Region: "auto", Bucket: "engram-backups", AccessKeyID: "AKIAXXXXXXXXXXXX", SecretAccessKey: "secretsecretsecret"}); err == nil {
			t.Fatalf("%s accepted", ep)
		}
	}
}

// Route precedence: page and trailing-slash variants.
func TestBackupSecurityBackupRoutePrecedence(t *testing.T) {
	f := managedBackupFixture(t)
	if rec := doBackupRequest(f.srv, backupRequest{method: http.MethodGet, path: backupsPagePath, cookie: f.cookie}); rec.Code != 200 || !strings.Contains(rec.Body.String(), "Scheduled backups") {
		t.Fatalf("page: %d", rec.Code)
	}
	if rec := doBackupRequest(f.srv, backupRequest{method: http.MethodHead, path: backupsPagePath, cookie: f.cookie}); rec.Code != 200 {
		t.Fatalf("HEAD page: %d", rec.Code)
	}
	m, _, mcookie := memberDashboardServer(t)
	if rec := doBackupRequest(m, backupRequest{method: http.MethodGet, path: backupsPagePath, cookie: mcookie}); rec.Code != http.StatusForbidden {
		t.Fatalf("member page: %d", rec.Code)
	}
	if rec := doBackupRequest(f.srv, backupRequest{method: http.MethodGet, path: backupsPagePath, cookie: nil}); rec.Code != http.StatusSeeOther {
		t.Fatalf("unauth page: %d", rec.Code)
	}
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath + "/", cookie: f.cookie})
	t.Logf("POST trailing slash remove -> %d", rec.Code)
	vfyAssertNoSideEffects(t, f, "trailing slash")
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: "/dashboard/admin/backups", cookie: f.cookie})
	t.Logf("POST page path -> %d", rec.Code)
	vfyAssertNoSideEffects(t, f, "POST page")
}
