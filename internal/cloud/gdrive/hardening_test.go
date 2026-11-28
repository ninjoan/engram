package gdrive

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestNewValidatesConfig(t *testing.T) {
	ok := Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh}
	cases := map[string]func(*Config){
		"no client id":     func(c *Config) { c.ClientID = "" },
		"no client secret": func(c *Config) { c.ClientSecret = "" },
		"no refresh token": func(c *Config) { c.RefreshToken = "" },
		"spaces in token":  func(c *Config) { c.RefreshToken = "1//abc def" },
	}
	for name, mod := range cases {
		cfg := ok
		mod(&cfg)
		_, err := New(cfg)
		if !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%s: err = %v, want ErrInvalidConfig", name, err)
		}
		if err != nil && (strings.Contains(err.Error(), testSecret) || strings.Contains(err.Error(), testRefresh)) {
			t.Errorf("%s: error leaks a credential: %v", name, err)
		}
	}
	c, err := New(ok)
	if err != nil {
		t.Fatal(err)
	}
	if c.ep.token != "https://oauth2.googleapis.com/token" || c.ep.api != "https://www.googleapis.com/drive/v3" ||
		c.ep.upload != "https://www.googleapis.com/upload/drive/v3/files" {
		t.Fatalf("production endpoints = %+v", c.ep)
	}
}

func TestEndpointSeamIsLoopbackOnly(t *testing.T) {
	for _, base := range []string{"https://example.com", "http://example.com", "http://10.0.0.1:8080", "ftp://127.0.0.1", "http://user:pw@127.0.0.1:1", "http://127.0.0.1:1/path", "http://127.0.0.1:1?x=1"} {
		_, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, baseURL: base})
		if err == nil {
			t.Errorf("baseURL %q accepted", base)
		}
	}
	for _, base := range []string{"http://127.0.0.1:1234", "http://localhost:1234", "http://[::1]:1234", "https://127.0.0.1:9"} {
		if _, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, baseURL: base}); err != nil {
			t.Errorf("baseURL %q refused: %v", base, err)
		}
	}
}

func TestProductionAllowlistIsGoogleHTTPSOnly(t *testing.T) {
	ep := googleEndpoints()
	for _, raw := range []string{"https://accounts.google.com/x", "https://oauth2.googleapis.com/token", "https://www.googleapis.com/drive/v3/files"} {
		u, _ := url.Parse(raw)
		if !ep.permits(u) {
			t.Errorf("%s refused", raw)
		}
	}
	for _, raw := range []string{"http://www.googleapis.com/drive/v3/files", "https://evil.googleapis.com/x", "https://www.googleapis.com.evil.com/x", "https://user@www.googleapis.com/x", "https://www.googleapis.com:8443/x", "https://127.0.0.1/x"} {
		u, _ := url.Parse(raw)
		if ep.permits(u) {
			t.Errorf("%s permitted", raw)
		}
	}
}

func TestFormattingAndJSONNeverPrintCredentials(t *testing.T) {
	fd := newFakeDrive(t)
	cfg := Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh, HTTPClient: &http.Client{}}
	c, _ := newTestClient(t, fd)
	if err := c.CheckAccess(context.Background(), "Engram Backups"); err != nil { // caches an access token
		t.Fatal(err)
	}
	secrets := []string{testSecret, testRefresh, "ya29.access-1"}
	var outs []string
	for _, v := range []any{cfg, &cfg, *c, c} {
		for _, verb := range []string{"%v", "%+v", "%#v", "%s", "%q", "%x", "%X", "%d", "%T %v"} {
			outs = append(outs, fmt.Sprintf(verb, v))
		}
		b, err := json.Marshal(v)
		if err != nil {
			t.Fatalf("json.Marshal(%T): %v", v, err)
		}
		outs = append(outs, string(b))
	}
	for _, out := range outs {
		for _, s := range secrets {
			if strings.Contains(out, s) {
				t.Fatalf("output leaks %q: %s", s, out)
			}
		}
	}
	if s := fmt.Sprintf("%+v", cfg); !strings.Contains(s, testClientID) || !strings.Contains(s, "[REDACTED]") {
		t.Fatalf("Config format = %s", s)
	}
}

func TestErrorsRedactEchoedCredentials(t *testing.T) {
	fd := newFakeDrive(t)
	fd.list = func(w http.ResponseWriter, r *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusBadRequest, "invalid", "echo "+r.Header.Get("Authorization")+" "+testSecret+" "+testRefresh)
		return true
	}
	c, _ := newTestClient(t, fd)
	err := c.CheckAccess(context.Background(), "Engram Backups")
	if err == nil {
		t.Fatal("want error")
	}
	for _, out := range []string{err.Error(), fmt.Sprintf("%+v", err), fmt.Sprintf("%#v", err)} {
		for _, s := range []string{testSecret, testRefresh, "ya29.access-1"} {
			if strings.Contains(out, s) {
				t.Fatalf("error leaks %q: %s", s, out)
			}
		}
	}
	var ge *Error
	if !errors.As(err, &ge) || !strings.Contains(ge.Message, "[REDACTED]") {
		t.Fatalf("message = %q", ge.Message)
	}
	b, _ := json.Marshal(ge)
	for _, s := range []string{testSecret, testRefresh, "ya29.access-1"} {
		if bytes.Contains(b, []byte(s)) {
			t.Fatalf("error JSON leaks %q: %s", s, b)
		}
	}
}

func TestErrorMessageIsSanitizedAndBounded(t *testing.T) {
	fd := newFakeDrive(t)
	fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		writeGoogleError(w, http.StatusBadRequest, "bad\r\nreason", "line1\nline2\x1b[31m"+strings.Repeat("é", 400))
		return true
	}
	c, _ := newTestClient(t, fd)
	err := c.CheckAccess(context.Background(), "Engram Backups")
	var ge *Error
	if !errors.As(err, &ge) {
		t.Fatalf("err = %v", err)
	}
	if strings.ContainsAny(ge.Message+ge.Reason, "\r\n\x1b") || len(ge.Message) > 310 || len(ge.Reason) > 70 {
		t.Fatalf("unsanitized: reason %q message %q (%d bytes)", ge.Reason, ge.Message, len(ge.Message))
	}
}

func TestTransportErrorsDoNotLeakSessionURI(t *testing.T) {
	fd := newFakeDrive(t)
	fd.put = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
		conn, _, _ := w.(http.Hijacker).Hijack()
		_ = conn.Close()
		return true
	}
	c, _ := newTestClient(t, fd)
	_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader([]byte("x")), 1)
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("err = %v, want ErrNetwork", err)
	}
	if strings.Contains(err.Error(), "upload_id") || strings.Contains(err.Error(), "sess-1") {
		t.Fatalf("error leaks the session URI: %v", err)
	}
}

func TestRedirectsAreRefused(t *testing.T) {
	for _, route := range []string{"token", "list", "init", "put"} {
		t.Run(route, func(t *testing.T) {
			fd := newFakeDrive(t)
			redirect := func(w http.ResponseWriter, r *http.Request, _ []byte, _ int, _ *session) bool {
				http.Redirect(w, r, fd.srv.URL+"/elsewhere", http.StatusFound)
				return true
			}
			switch route {
			case "token":
				fd.token = redirect
			case "list":
				fd.list = redirect
			case "init":
				fd.init = redirect
			case "put":
				fd.put = redirect
			}
			c, _ := newTestClient(t, fd)
			var err error
			if route == "init" || route == "put" {
				_, err = c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader([]byte("x")), 1)
			} else {
				_, err = c.EnsureFolder(context.Background(), "Engram Backups")
			}
			if !errors.Is(err, ErrRedirect) {
				t.Fatalf("err = %v, want ErrRedirect", err)
			}
			for _, r := range fd.requests("") {
				if r.Path == "/elsewhere" {
					t.Fatal("redirect was followed")
				}
			}
		})
	}
}

func TestUploadRejectsUnexpectedSessionLocation(t *testing.T) {
	cases := map[string]func(base string) string{
		"other host": func(string) string { return "https://evil.example.com/upload/drive/v3/files?upload_id=x" },
		"https peer": func(base string) string {
			return strings.Replace(base, "http://", "https://", 1) + "/upload/drive/v3/files?upload_id=x"
		},
		"userinfo": func(base string) string {
			return strings.Replace(base, "http://", "http://u:p@", 1) + "/upload/drive/v3/files?upload_id=x"
		},
		"other path":  func(base string) string { return base + "/drive/v3/files?upload_id=x" },
		"missing":     func(string) string { return "" },
		"relative":    func(string) string { return "/upload/drive/v3/files?upload_id=x" },
		"google prod": func(string) string { return "https://www.googleapis.com/upload/drive/v3/files?upload_id=x" },
	}
	for name, loc := range cases {
		t.Run(name, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.init = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				if l := loc(fd.srv.URL); l != "" {
					w.Header().Set("Location", l)
				}
				w.WriteHeader(http.StatusOK)
				return true
			}
			c, _ := newTestClient(t, fd)
			_, err := c.Upload(context.Background(), "folder-a", "b.tar.gz", bytes.NewReader([]byte("x")), 1)
			if !errors.Is(err, ErrInvalidLocation) {
				t.Fatalf("err = %v, want ErrInvalidLocation", err)
			}
			if fd.count("put") != 0 {
				t.Fatal("chunk sent to an unchecked session URI")
			}
		})
	}
}

func TestProductionSessionLocationCheck(t *testing.T) {
	c, err := New(Config{ClientID: testClientID, ClientSecret: testSecret, RefreshToken: testRefresh})
	if err != nil {
		t.Fatal(err)
	}
	if err := c.checkSessionURI("https://www.googleapis.com/upload/drive/v3/files?uploadType=resumable&upload_id=ABC"); err != nil {
		t.Fatalf("google session URI refused: %v", err)
	}
	for _, bad := range []string{
		"http://www.googleapis.com/upload/drive/v3/files?upload_id=ABC",
		"https://oauth2.googleapis.com/upload/drive/v3/files?upload_id=ABC",
		"https://www.googleapis.com.evil.com/upload/drive/v3/files?upload_id=ABC",
		"https://www.googleapis.com/drive/v3/files?upload_id=ABC",
	} {
		if err := c.checkSessionURI(bad); !errors.Is(err, ErrInvalidLocation) {
			t.Errorf("%s: err = %v", bad, err)
		}
	}
}

// S9: the client never deletes or trashes anything. Its exported surface is
// pinned so a delete/trash call cannot be added without changing this test.
func TestClientExposesNoDeleteOperation(t *testing.T) {
	var got []string
	ty := reflect.TypeOf(&Client{})
	for i := range ty.NumMethod() {
		got = append(got, ty.Method(i).Name)
	}
	sort.Strings(got)
	want := []string{"CheckAccess", "EnsureFolder", "Format", "Upload"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("exported methods = %v, want %v", got, want)
	}
	for _, name := range got {
		l := strings.ToLower(name)
		if strings.Contains(l, "delete") || strings.Contains(l, "trash") || strings.Contains(l, "remove") {
			t.Fatalf("method %s looks destructive", name)
		}
	}
}

func TestNoRequestUsesDeleteOrTrash(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	ctx := context.Background()
	if _, err := c.EnsureFolder(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Upload(ctx, "folder-new-1", "b.tar.gz", bytes.NewReader(payload(testChunk+1)), testChunk+1); err != nil {
		t.Fatal(err)
	}
	if err := c.CheckAccess(ctx, "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	for _, r := range fd.requests("") {
		if r.Method == http.MethodDelete || strings.Contains(string(r.Body), "trashed\":true") || strings.Contains(r.Path, "trash") {
			t.Fatalf("destructive request %s %s %s", r.Method, r.Path, r.Body)
		}
	}
}
