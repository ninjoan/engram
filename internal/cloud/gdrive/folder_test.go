package gdrive

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"testing"
)

func TestEnsureFolderReusesOldestExistingFolder(t *testing.T) {
	fd := newFakeDrive(t)
	fd.folders = []fakeFile{
		{ID: "folder-b", Name: "Engram Backups", CreatedTime: "2026-03-02T10:00:00.000Z"},
		{ID: "folder-a", Name: "Engram Backups", CreatedTime: "2026-01-05T10:00:00.000Z"},
	}
	c, _ := newTestClient(t, fd)
	id, err := c.EnsureFolder(context.Background(), "Engram Backups")
	if err != nil || id != "folder-a" {
		t.Fatalf("EnsureFolder = %q, %v; want folder-a", id, err)
	}
	if fd.count("create") != 0 {
		t.Fatalf("created a folder although one exists")
	}
	q := fd.requests("list")[0].Query
	if got, want := q.Get("q"), "mimeType='application/vnd.google-apps.folder' and name='Engram Backups' and trashed=false"; got != want {
		t.Fatalf("q = %q, want %q", got, want)
	}
	if q.Get("supportsAllDrives") != "true" || q.Get("orderBy") != "createdTime" {
		t.Fatalf("list query = %v", q)
	}
	if f := q.Get("fields"); f != "files(id,name,createdTime)" {
		t.Fatalf("fields = %q", f)
	}
}

func TestEnsureFolderCreatesMissingFolder(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	id, err := c.EnsureFolder(context.Background(), "Engram Backups")
	if err != nil || id != "folder-new-1" {
		t.Fatalf("EnsureFolder = %q, %v", id, err)
	}
	cr := fd.requests("create")[0]
	var meta map[string]any
	if err := json.Unmarshal(cr.Body, &meta); err != nil {
		t.Fatalf("create body %q: %v", cr.Body, err)
	}
	if len(meta) != 2 || meta["name"] != "Engram Backups" || meta["mimeType"] != "application/vnd.google-apps.folder" {
		t.Fatalf("create metadata = %v", meta)
	}
	if cr.Query.Get("supportsAllDrives") != "true" || cr.Query.Get("fields") != "id" {
		t.Fatalf("create query = %v", cr.Query)
	}
	if ct := cr.Header.Get("Content-Type"); ct != "application/json; charset=UTF-8" {
		t.Fatalf("Content-Type = %q", ct)
	}
}

func TestEnsureFolderEscapesQuery(t *testing.T) {
	fd := newFakeDrive(t)
	fd.folders = []fakeFile{{ID: "folder-x", Name: `Bob's \ backups`}}
	c, _ := newTestClient(t, fd)
	id, err := c.EnsureFolder(context.Background(), `Bob's \ backups`)
	if err != nil || id != "folder-x" {
		t.Fatalf("EnsureFolder = %q, %v", id, err)
	}
	want := `mimeType='application/vnd.google-apps.folder' and name='Bob\'s \\ backups' and trashed=false`
	if got := fd.requests("list")[0].Query.Get("q"); got != want {
		t.Fatalf("q = %q, want %q", got, want)
	}
}

func TestEnsureFolderIgnoresNonMatchingNames(t *testing.T) {
	fd := newFakeDrive(t)
	fd.folders = []fakeFile{{ID: "folder-other", Name: "engram backups"}}
	c, _ := newTestClient(t, fd)
	id, err := c.EnsureFolder(context.Background(), "Engram Backups")
	if err != nil || id != "folder-new-1" {
		t.Fatalf("EnsureFolder = %q, %v; want a created folder", id, err)
	}
}

func TestFolderNameValidation(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	for _, name := range []string{"", "bad\nname", "bad\x00", string([]byte{0xff, 0xfe})} {
		if _, err := c.EnsureFolder(context.Background(), name); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("EnsureFolder(%q) err = %v, want ErrInvalidArgument", name, err)
		}
		if err := c.CheckAccess(context.Background(), name); !errors.Is(err, ErrInvalidArgument) {
			t.Errorf("CheckAccess(%q) err = %v, want ErrInvalidArgument", name, err)
		}
	}
	if n := len(fd.requests("")); n != 0 {
		t.Fatalf("invalid names made %d requests", n)
	}
}

func TestCheckAccessIsReadOnly(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	if err := c.CheckAccess(context.Background(), "Engram Backups"); err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	for _, r := range fd.requests("") {
		if r.Method != http.MethodGet && r.Path != "/token" {
			t.Fatalf("CheckAccess wrote: %s %s", r.Method, r.Path)
		}
	}
	if fd.count("token") != 1 || fd.count("list") != 1 {
		t.Fatalf("token %d list %d, want 1 and 1", fd.count("token"), fd.count("list"))
	}
	if ps := fd.requests("list")[0].Query.Get("pageSize"); ps != "1" {
		t.Fatalf("pageSize = %q", ps)
	}
}

func TestCheckAccessClassifiesErrors(t *testing.T) {
	cases := []struct {
		name   string
		status int
		reason string
		want   error
		calls  int
	}{
		{"storage quota", http.StatusForbidden, "storageQuotaExceeded", ErrQuota, 1},
		{"upload limit", http.StatusForbidden, "userUploadLimitExceeded", ErrQuota, 1},
		{"rate limit 403", http.StatusForbidden, "rateLimitExceeded", ErrRateLimited, 6},
		{"user rate limit 403", http.StatusForbidden, "userRateLimitExceeded", ErrRateLimited, 6},
		{"429", http.StatusTooManyRequests, "", ErrRateLimited, 6},
		{"insufficient permissions", http.StatusForbidden, "insufficientPermissions", ErrAuth, 1},
		{"server error", http.StatusInternalServerError, "backendError", ErrUnexpected, 6},
		{"bad request", http.StatusBadRequest, "invalid", ErrUnexpected, 1},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fd := newFakeDrive(t)
			fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, _ int, _ *session) bool {
				writeGoogleError(w, tc.status, tc.reason, "Google said <b>no</b>\n"+tc.reason)
				return true
			}
			c, sleeps := newTestClient(t, fd)
			err := c.CheckAccess(context.Background(), "Engram Backups")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
			var ge *Error
			if !errors.As(err, &ge) || ge.StatusCode != tc.status || ge.Reason != tc.reason {
				t.Fatalf("err = %#v", err)
			}
			if got := fd.count("list"); got != tc.calls {
				t.Fatalf("list calls = %d, want %d", got, tc.calls)
			}
			if got := len(sleeps.all()); got != tc.calls-1 {
				t.Fatalf("backoff sleeps = %d, want %d", got, tc.calls-1)
			}
		})
	}
}

func TestCheckAccessNetworkError(t *testing.T) {
	fd := newFakeDrive(t)
	c, _ := newTestClient(t, fd)
	if err := c.CheckAccess(context.Background(), "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	fd.srv.Close()
	err := c.CheckAccess(context.Background(), "Engram Backups")
	if !errors.Is(err, ErrNetwork) {
		t.Fatalf("err = %v, want ErrNetwork", err)
	}
}

func TestRateLimitedCallsBackOffExponentiallyThenSucceed(t *testing.T) {
	fd := newFakeDrive(t)
	fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n <= 3 {
			writeGoogleError(w, http.StatusTooManyRequests, "rateLimitExceeded", "slow down")
			return true
		}
		return false
	}
	c, sleeps := newTestClient(t, fd)
	if err := c.CheckAccess(context.Background(), "Engram Backups"); err != nil {
		t.Fatalf("CheckAccess: %v", err)
	}
	got := sleeps.all()
	want := []int64{10, 20, 40} // base 10ms doubling, full jitter, capped at 40ms
	if len(got) != len(want) {
		t.Fatalf("sleeps = %v", got)
	}
	for i := range want {
		if got[i].Milliseconds() != want[i] {
			t.Fatalf("sleeps = %v, want %v ms", got, want)
		}
	}
}

func TestRetryAfterIsHonouredWithinTheCap(t *testing.T) {
	fd := newFakeDrive(t)
	fd.list = func(w http.ResponseWriter, _ *http.Request, _ []byte, n int, _ *session) bool {
		if n == 1 {
			w.Header().Set("Retry-After", "120")
			writeGoogleError(w, http.StatusTooManyRequests, "", "slow down")
			return true
		}
		return false
	}
	c, sleeps := newTestClient(t, fd)
	if err := c.CheckAccess(context.Background(), "Engram Backups"); err != nil {
		t.Fatal(err)
	}
	if got := sleeps.all(); len(got) != 1 || got[0] != c.backoffMax {
		t.Fatalf("sleeps = %v, want [%v]", got, c.backoffMax)
	}
}
