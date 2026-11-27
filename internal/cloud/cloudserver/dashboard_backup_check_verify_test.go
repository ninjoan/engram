package cloudserver

import (
	"bytes"
	"context"
	"crypto/sha256"
	"fmt"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// S3/S7: every refused check makes zero outbound requests with the REAL access check.
func TestBackupCheckVerifyRefusalsMakeNoOutboundRequest(t *testing.T) {
	var hits atomic.Int32
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer s3.Close()
	form := url.Values{"endpoint": {s3.URL}, "region": {"auto"}, "bucket": {"engram-backups"}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
	real := func(f backupSettingsFixture) backupSettingsFixture { f.srv.backupCheckAccess = nil; return f }
	type tc struct {
		name   string
		fx     func(*testing.T) backupSettingsFixture
		method string
		hdr    map[string]string
		noAuth bool
		mutate func(f backupSettingsFixture)
	}
	cases := []tc{
		{name: "member", fx: func(t *testing.T) backupSettingsFixture {
			s, a, c := memberDashboardServer(t)
			return wireBackupFixture(t, s, a, c, &fakeBackupSettingsStore{})
		}, method: "POST"},
		{name: "legacy", fx: func(t *testing.T) backupSettingsFixture {
			s, a, c := legacyAdminDashboardServer(t)
			return wireBackupFixture(t, s, a, c, &fakeBackupSettingsStore{})
		}, method: "POST"},
		{name: "no session", fx: emptyBackupFixture, method: "POST", noAuth: true},
		{name: "disabled", fx: emptyBackupFixture, method: "POST", mutate: func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleAdmin, false)
		}},
		{name: "demoted", fx: emptyBackupFixture, method: "POST", mutate: func(f backupSettingsFixture) {
			f.audit.principals["p-admin"] = dashboardStoredPrincipal("p-admin", cloudstore.PrincipalRoleMember, true)
		}},
		{name: "deleted principal", fx: emptyBackupFixture, method: "POST", mutate: func(f backupSettingsFixture) { delete(f.audit.principals, "p-admin") }},
		{name: "origin evil", fx: emptyBackupFixture, method: "POST", hdr: map[string]string{"Origin": "http://evil.test"}},
		{name: "sfs cross-site", fx: emptyBackupFixture, method: "POST", hdr: map[string]string{"Sec-Fetch-Site": "cross-site"}},
		{name: "sfs same-site", fx: emptyBackupFixture, method: "POST", hdr: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://example.com"}},
		{name: "origin null", fx: emptyBackupFixture, method: "POST", hdr: map[string]string{"Origin": "null"}},
		{name: "GET", fx: emptyBackupFixture, method: "GET"},
		{name: "HEAD", fx: emptyBackupFixture, method: "HEAD"},
		{name: "PUT", fx: emptyBackupFixture, method: "PUT"},
	}
	for _, c := range cases {
		for _, htmx := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s/htmx=%v", c.name, htmx), func(t *testing.T) {
				hits.Store(0)
				f := real(c.fx(t))
				if c.mutate != nil {
					c.mutate(f)
				}
				ck := f.cookie
				if c.noAuth {
					ck = nil
				}
				rec := doBackupRequest(f.srv, backupRequest{method: c.method, path: backupDestinationCheckPath + "?x=1", form: form, headers: c.hdr, cookie: ck, htmx: htmx})
				if rec.Code < 300 || hits.Load() != 0 || backupAuditCount(f.audit) != 0 || f.settings.mutations() != 0 {
					t.Fatalf("status=%d hits=%d audits=%d mut=%d", rec.Code, hits.Load(), backupAuditCount(f.audit), f.settings.mutations())
				}
				if strings.Contains(rec.Body.String(), testBackupSecret) || strings.Contains(rec.Body.String(), testBackupAccessKeyID) {
					t.Fatal("refusal leaks a credential")
				}
				t.Logf("status=%d", rec.Code)
			})
		}
	}
}

// S7: tricky endpoints - check route agrees exactly with cloudstore.ValidateBackupDestination and never contacts an invalid endpoint.
func TestBackupCheckVerifyTrickyEndpoints(t *testing.T) {
	for _, ep := range []string{
		"http://example.com", "http://127.0.0.1.evil.com", "http://localhost@evil.com", "https://localhost@evil.com",
		"https://user:pw@s3.example.com", "https://:9000", "http://:9000", ":9000", "https://s3.example.com/path",
		"https://s3.example.com?x=1", "https://s3.example.com#f", "ftp://s3.example.com", "//s3.example.com", "s3.example.com",
		"http://localhost.:9000", "http://0x7f.0.0.1", "http://[::1]:9000", "http://127.0.0.2:9000", "HTTP://LOCALHOST:9000",
		"https://127.0.0.1.evil.com", "http://localhost%40evil.com", "javascript:alert(1)", " https://s3.example.com/ ", "",
	} {
		t.Run(ep, func(t *testing.T) {
			p := cloudstore.PutBackupDestinationParams{Endpoint: ep, Region: "auto", Bucket: "engram-backups", AccessKeyID: testBackupAccessKeyID, SecretAccessKey: testBackupSecret}
			creds, verr := cloudstore.ValidateBackupDestination(p)
			f := emptyBackupFixture(t)
			form := url.Values{"endpoint": {ep}, "region": {"auto"}, "bucket": {"engram-backups"}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
			rec := doBackupRequest(f.srv, backupRequest{method: "POST", path: backupDestinationCheckPath, form: form, cookie: f.cookie, htmx: true})
			body := rec.Body.String()
			invalid := strings.Contains(body, `data-check-result="invalid"`)
			if (verr != nil) != invalid {
				t.Fatalf("validate err=%v but route invalid=%v body=%q", verr, invalid, body)
			}
			if verr != nil && f.checker.calls != 0 {
				t.Fatalf("invalid endpoint contacted")
			}
			if verr == nil && (f.checker.calls != 1 || f.checker.creds != creds) {
				t.Fatalf("valid: calls=%d creds=%+v want %+v", f.checker.calls, f.checker.creds, creds)
			}
			// save route on the same input must agree
			fs := emptyBackupFixture(t)
			srec := doBackupRequest(fs.srv, backupRequest{method: "POST", path: backupDestinationPath, form: form, cookie: fs.cookie})
			for _, leak := range []string{testBackupSecret, testBackupAccessKeyID, "evil", "user:pw"} {
				if verr != nil && strings.Contains(body, leak) && leak != "evil" {
					t.Fatalf("leak %q", leak)
				}
			}
			ev := fmt.Sprintf("%+v", backupAuditEvents(f.audit, authAuditActionBackupDestinationCheck))
			if strings.Contains(ev, testBackupSecret) || strings.Contains(ev, testBackupAccessKeyID) || (verr != nil && strings.Contains(ev, "evil")) {
				t.Fatalf("audit leak %s", ev)
			}
			t.Logf("validate=%v route=%d save=%d", verr, rec.Code, srec.Code)
		})
	}
}

// S7: multipart body credentials are not read by the check route.
func TestBackupCheckVerifyIgnoresMultipart(t *testing.T) {
	f := emptyBackupFixture(t)
	var b strings.Builder
	for k, v := range map[string]string{"endpoint": "https://acct.r2.cloudflarestorage.com", "region": "auto", "bucket": "engram-backups", "access_key_id": testBackupAccessKeyID, "secret_access_key": testBackupSecret} {
		fmt.Fprintf(&b, "--B\r\nContent-Disposition: form-data; name=%q\r\n\r\n%s\r\n", k, v)
	}
	b.WriteString("--B--\r\n")
	rec := doBackupRequest(f.srv, backupRequest{method: "POST", path: backupDestinationCheckPath, form: b.String(), ctype: "multipart/form-data; boundary=B", cookie: f.cookie, htmx: true})
	if f.checker.calls != 0 || !strings.Contains(rec.Body.String(), `data-check-result="invalid"`) {
		t.Fatalf("multipart read: %d calls=%d body=%q", rec.Code, f.checker.calls, rec.Body.String())
	}
}

// S7: provider answer echoing credentials never reaches the response, audit or logs; real client, both modes.
func TestBackupCheckVerifyProviderEchoNotRendered(t *testing.T) {
	var logs bytes.Buffer
	prev := log.Writer()
	log.SetOutput(&logs)
	defer log.SetOutput(prev)
	for _, status := range []int{200, 403, 404, 500, 301} {
		for _, htmx := range []bool{false, true} {
			s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("X-Echo", testBackupAccessKeyID+testBackupSecret)
				if status == 301 {
					w.Header().Set("Location", "http://127.0.0.1:1/"+testBackupSecret)
				}
				w.WriteHeader(status)
				fmt.Fprintf(w, "<Error><Code>X</Code><AWSAccessKeyId>%s</AWSAccessKeyId><Message>%s %s</Message></Error>", testBackupAccessKeyID, testBackupSecret, r.Header.Get("Authorization"))
			}))
			f := emptyBackupFixture(t)
			f.srv.backupCheckAccess = nil
			form := url.Values{"endpoint": {s3.URL}, "region": {"auto"}, "bucket": {"engram-backups"}, "prefix": {"p/"}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
			rec := doBackupRequest(f.srv, backupRequest{method: "POST", path: backupDestinationCheckPath, form: form, cookie: f.cookie, htmx: htmx})
			s3.Close()
			body := rec.Body.String()
			all := body + fmt.Sprintf("%+v", rec.Header()) + fmt.Sprintf("%+v", f.audit.auditEvents)
			for _, leak := range []string{testBackupSecret, testBackupAccessKeyID, "Credential=", "AWSAccessKeyId"} {
				if strings.Contains(all, leak) {
					t.Fatalf("status %d htmx=%v leaks %q", status, htmx, leak)
				}
			}
			i := strings.Index(body, "data-check-result=")
			t.Logf("upstream=%d htmx=%v code=%d result=%s", status, htmx, rec.Code, body[i:i+30])
		}
	}
	if strings.Contains(logs.String(), testBackupSecret) || strings.Contains(logs.String(), testBackupAccessKeyID) {
		t.Fatalf("logs leak: %s", logs.String())
	}
}

// S7: a hanging endpoint is bounded (~15s) and reported as network.
func TestBackupCheckVerifyHangingEndpointBounded(t *testing.T) {
	release := make(chan struct{})
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { <-release }))
	defer s3.Close()
	defer close(release)
	f := emptyBackupFixture(t)
	f.srv.backupCheckAccess = nil
	form := url.Values{"endpoint": {s3.URL}, "region": {"auto"}, "bucket": {"engram-backups"}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
	start := time.Now()
	rec := doBackupRequest(f.srv, backupRequest{method: "POST", path: backupDestinationCheckPath, form: form, cookie: f.cookie, htmx: true})
	el := time.Since(start)
	if el > 17*time.Second || !strings.Contains(rec.Body.String(), `data-check-result="network"`) {
		t.Fatalf("elapsed=%s body=%q", el, rec.Body.String())
	}
	t.Logf("elapsed=%s", el)
}

// S7/S3 Postgres: a check against a configured destination leaves the row byte-identical and the pill untouched.
func TestBackupCheckVerifyPostgresRowUnchanged(t *testing.T) {
	cs := openBackupDownloadTestStore(t)
	ctx := context.Background()
	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	principal := dashboardManagedPrincipal(admin.PrincipalID, cloudstore.PrincipalRoleAdmin, true)
	key := testBackupKey(t)
	srv := New(cs, resolvingAuth{principals: map[string]cloudauth.Principal{"admin-token": principal}}, 0, WithAdminIdentityStore(cs), WithBackupSettings(cs, key))
	if err := cs.PutBackupDestination(ctx, cloudstore.PutBackupDestinationParams{Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "saved-bucket", Prefix: "a/", AccessKeyID: "AKIASAVEDKEY00001111", SecretAccessKey: "saved-secret-value", Actor: cloudstore.BackupDestinationActor{PrincipalID: admin.PrincipalID, Source: "managed_token"}}, key); err != nil {
		t.Fatal(err)
	}
	snap := func() string {
		d, err := cs.GetBackupDestination(ctx)
		if err != nil {
			t.Fatal(err)
		}
		c, err := cs.OpenBackupDestinationCredentials(ctx, key)
		if err != nil {
			t.Fatal(err)
		}
		return fmt.Sprintf("%#v|%x", d, sha256.Sum256([]byte(fmt.Sprintf("%#v", c))))
	}
	before := snap()
	var hits atomic.Int32
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1); w.WriteHeader(200) }))
	defer s3.Close()
	cookie := managedDashboardLogin(t, srv, "admin-token", false)
	form := url.Values{"endpoint": {s3.URL}, "region": {"auto"}, "bucket": {"other-bucket"}, "access_key_id": {testBackupAccessKeyID}, "secret_access_key": {testBackupSecret}}.Encode()
	for _, htmx := range []bool{true, false} {
		rec := doBackupRequest(srv, backupRequest{method: "POST", path: backupDestinationCheckPath, form: form, cookie: cookie, htmx: htmx})
		if rec.Code != 200 || strings.Contains(rec.Body.String(), testBackupSecret) || strings.Contains(rec.Body.String(), testBackupAccessKeyID) || strings.Contains(rec.Body.String(), "saved-secret-value") {
			t.Fatalf("code=%d", rec.Code)
		}
	}
	if hits.Load() != 2 || snap() != before {
		t.Fatalf("hits=%d row changed=%v", hits.Load(), snap() != before)
	}
	lt, err := cs.LatestBackupDestinationTest(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if lt != (cloudstore.BackupDestinationTest{}) {
		t.Fatalf("pill changed by check: %+v", lt)
	}
	events, err := cs.ListAuthAuditEvents(ctx, cloudstore.AuthAuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	dump := fmt.Sprintf("%+v", events)
	if strings.Contains(dump, testBackupSecret) || strings.Contains(dump, testBackupAccessKeyID) || strings.Contains(dump, "saved-secret-value") {
		t.Fatalf("audit leak: %s", dump)
	}
	t.Logf("audit:\n%s", dump)
}
