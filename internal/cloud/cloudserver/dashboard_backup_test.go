package cloudserver

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"regexp"
	"strings"
	"testing"
	"time"

	_ "github.com/jackc/pgx/v5/stdlib"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/chunkcodec"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudbackup"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const (
	backupsPagePath     = "/dashboard/admin/backups"
	backupsDownloadPath = "/dashboard/admin/backups/download"
)

var backupFilenamePattern = regexp.MustCompile(`^attachment; filename="engram-cloud-backup-\d{8}T\d{6}Z\.tar\.gz"$`)

// fakeBackupExporter records every export attempt and replays a scripted
// outcome, so the download handler is exercised without Postgres.
type fakeBackupExporter struct {
	calls       int
	auditsAtRun int
	ctxErr      error
	write       []byte
	err         error
	store       *loginAuditTestStore
}

func (f *fakeBackupExporter) export(ctx context.Context, w io.Writer) error {
	f.calls++
	f.ctxErr = ctx.Err()
	if f.store != nil {
		f.auditsAtRun = countAuditAction(f.store, authAuditActionBackupDownload)
	}
	if len(f.write) > 0 {
		if _, err := w.Write(f.write); err != nil {
			return err
		}
	}
	return f.err
}

func countAuditAction(store *loginAuditTestStore, action string) int {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	n := 0
	for _, event := range store.auditEvents {
		if event.Action == action {
			n++
		}
	}
	return n
}

func memberDashboardServer(t *testing.T) (*CloudServer, *loginAuditTestStore, *http.Cookie) {
	t.Helper()
	store := newLoginAuditTestStore()
	store.principals["p-member"] = dashboardStoredPrincipal("p-member", cloudstore.PrincipalRoleMember, true)
	member := dashboardManagedPrincipal("p-member", cloudstore.PrincipalRoleMember, true)
	authn := resolvingAuth{principals: map[string]cloudauth.Principal{"member-token": member}}
	srv := New(store, authn, 0, WithAdminIdentityStore(store))
	return srv, store, managedDashboardLogin(t, srv, "member-token", false)
}

func legacyAdminDashboardServer(t *testing.T) (*CloudServer, *loginAuditTestStore, *http.Cookie) {
	t.Helper()
	store := newLoginAuditTestStore()
	srv := New(store, legacyAdminOnlyAuthService(t), 0, WithAdminIdentityStore(store), WithDashboardAdminToken("legacy-admin-token"))
	return srv, store, managedDashboardLogin(t, srv, "legacy-admin-token", false)
}

func assertNoArchiveResponse(t *testing.T, rec *httptest.ResponseRecorder) {
	t.Helper()
	if got := rec.Header().Get("Content-Disposition"); got != "" {
		t.Fatalf("refused download must not offer an attachment, got Content-Disposition %q", got)
	}
	if got := rec.Header().Get("Content-Type"); got == "application/gzip" {
		t.Fatalf("refused download must not declare an archive body, body=%q", rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "archive-bytes") {
		t.Fatalf("refused download must not stream archive bytes, body=%q", rec.Body.String())
	}
}

func TestDashboardBackupsPageManagedAdminSeesDownloadForm(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)

	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected managed admin to view the backups page, got %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, marker := range []string{
		`<form method="post" action="/dashboard/admin/backups/download"`,
		"Download backup",
		`href="/dashboard/admin/backups" class="active"`,
		"plaintext",
		"backup.json",
		"cloud_chunks",
		"cloud_principal_tokens",
		"password_hash",
		"Scheduled backups",
		"engram cloud backup import",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected backups page marker %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, "Backup download requires a managed admin token.") {
		t.Fatalf("managed admin must not see the legacy policy note, body=%q", body)
	}
	for _, forbidden := range []string{`type="checkbox"`, "hx-post", `action="/dashboard/admin/backups/import"`, `action="/dashboard/admin/backups/restore"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("backups page must not render %q (no fake toggles, no restore route), body=%q", forbidden, body)
		}
	}
}

func TestDashboardBackupsPageLegacyAdminSeesPolicyNoteWithoutDownloadForm(t *testing.T) {
	srv, _, cookie := legacyAdminDashboardServer(t)

	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected legacy admin to view the backups page, got %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, marker := range []string{"Backup download requires a managed admin token.", "engram cloud bootstrap admin --issue-token", "cloud_principal_tokens"} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected legacy admin backups marker %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, `action="/dashboard/admin/backups/download"`) || strings.Contains(body, ">Download backup</button>") {
		t.Fatalf("legacy admin must not see an enabled download form, body=%q", body)
	}
}

func TestDashboardBackupsPageMemberForbidden(t *testing.T) {
	srv, _, cookie := memberDashboardServer(t)

	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected member to be forbidden from the backups page, got %d body=%q", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "Download backup") {
		t.Fatalf("forbidden backups page must not render download controls, body=%q", rec.Body.String())
	}
}

func TestDashboardBackupRoutesRequireSession(t *testing.T) {
	srv, store, _ := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{write: []byte("archive-bytes")}
	srv.backupExport = exporter.export

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodGet, backupsPagePath},
		{http.MethodPost, backupsDownloadPath},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			rec := performDashboardForm(srv, tc.method, tc.path, "", nil, false)
			if rec.Code != http.StatusSeeOther || !strings.HasPrefix(dashboardRedirect(rec), "/dashboard/login") {
				t.Fatalf("expected 303 to login without a session, got %d location=%q", rec.Code, dashboardRedirect(rec))
			}
			assertNoArchiveResponse(t, rec)
			htmxRec := performDashboardForm(srv, tc.method, tc.path, "", nil, true)
			if htmxRec.Code != http.StatusUnauthorized || !strings.HasPrefix(htmxRec.Header().Get("HX-Redirect"), "/dashboard/login") {
				t.Fatalf("expected 401 with HX-Redirect to login, got %d hx=%q", htmxRec.Code, htmxRec.Header().Get("HX-Redirect"))
			}
			assertNoArchiveResponse(t, htmxRec)
		})
	}
	if exporter.calls != 0 || countAuditAction(store, authAuditActionBackupDownload) != 0 {
		t.Fatalf("unauthenticated requests must not export or audit, calls=%d", exporter.calls)
	}
}

func TestDashboardBackupDownloadStreamsArchiveAfterAudit(t *testing.T) {
	srv, store, cookie := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{write: []byte("archive-bytes"), store: store}
	srv.backupExport = exporter.export

	rec := performDashboardForm(srv, http.MethodPost, backupsDownloadPath, "", cookie, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected managed admin download to succeed, got %d body=%q", rec.Code, rec.Body.String())
	}
	if got := rec.Header().Get("Content-Type"); got != "application/gzip" {
		t.Fatalf("expected Content-Type application/gzip, got %q", got)
	}
	if got := rec.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("expected Cache-Control no-store, got %q", got)
	}
	if got := rec.Header().Get("Content-Disposition"); !backupFilenamePattern.MatchString(got) {
		t.Fatalf("expected UTC-stamped attachment filename, got %q", got)
	}
	if rec.Body.String() != "archive-bytes" {
		t.Fatalf("expected the exporter output as the body, got %q", rec.Body.String())
	}
	if exporter.calls != 1 {
		t.Fatalf("expected exactly one export, got %d", exporter.calls)
	}
	if exporter.auditsAtRun != 1 {
		t.Fatalf("backup.download audit must be recorded before the export starts, saw %d at export time", exporter.auditsAtRun)
	}
	event := lastAuditEvent(t, store)
	if event.Action != authAuditActionBackupDownload || event.Outcome != authAuditOutcomeSuccess || event.ActorPrincipalID != "p-admin" || event.ActorSource != string(cloudauth.PrincipalSourceManagedToken) {
		t.Fatalf("unexpected backup.download audit event: %+v", event)
	}
}

func TestDashboardBackupDownloadRefusesNonManagedAdminsAndGet(t *testing.T) {
	cases := []struct {
		name   string
		server func(t *testing.T) (*CloudServer, *loginAuditTestStore, *http.Cookie)
		method string
		status int
	}{
		{name: "member POST", server: memberDashboardServer, method: http.MethodPost, status: http.StatusForbidden},
		{name: "legacy admin POST", server: legacyAdminDashboardServer, method: http.MethodPost, status: http.StatusForbidden},
		{name: "managed admin GET", server: dashboardAdminUsersTestServer, method: http.MethodGet, status: http.StatusMethodNotAllowed},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			srv, store, cookie := tc.server(t)
			exporter := &fakeBackupExporter{write: []byte("archive-bytes")}
			srv.backupExport = exporter.export

			rec := performDashboardForm(srv, tc.method, backupsDownloadPath, "", cookie, false)
			if rec.Code != tc.status {
				t.Fatalf("expected %d, got %d body=%q", tc.status, rec.Code, rec.Body.String())
			}
			if tc.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
				t.Fatalf("expected Allow: POST on 405, got %q", rec.Header().Get("Allow"))
			}
			assertNoArchiveResponse(t, rec)
			if exporter.calls != 0 {
				t.Fatalf("refused download must not export, got %d calls", exporter.calls)
			}
			if n := countAuditAction(store, authAuditActionBackupDownload); n != 0 {
				t.Fatalf("refused download must not record a backup.download audit, got %d", n)
			}
		})
	}
}

func TestDashboardBackupDownloadAuditFailureReturns500WithoutArchive(t *testing.T) {
	srv, store, cookie := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{write: []byte("archive-bytes")}
	srv.backupExport = exporter.export
	store.auditErr = errors.New("audit unavailable")

	rec := performDashboardForm(srv, http.MethodPost, backupsDownloadPath, "", cookie, false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected audit failure to fail the download, got %d body=%q", rec.Code, rec.Body.String())
	}
	assertNoArchiveResponse(t, rec)
	if exporter.calls != 0 {
		t.Fatalf("audit failure must stop before exporting, got %d calls", exporter.calls)
	}
}

func TestDashboardBackupDownloadExportFailureBeforeBytesReturns500(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{err: errors.New("snapshot failed")}
	srv.backupExport = exporter.export

	rec := performDashboardForm(srv, http.MethodPost, backupsDownloadPath, "", cookie, false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected export failure before any byte to return 500, got %d body=%q", rec.Code, rec.Body.String())
	}
	assertNoArchiveResponse(t, rec)
}

func TestDashboardBackupDownloadMidStreamFailureAbortsConnection(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{write: bytes.Repeat([]byte("x"), 64<<10), err: errors.New("disk vanished")}
	srv.backupExport = exporter.export
	ts := httptest.NewServer(srv.Handler())
	defer ts.Close()

	req, err := http.NewRequest(http.MethodPost, ts.URL+backupsDownloadPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.AddCookie(cookie)
	resp, err := ts.Client().Do(req)
	if err != nil {
		return // aborted before the response head reached the client
	}
	defer resp.Body.Close()
	if _, err := io.ReadAll(resp.Body); err == nil {
		t.Fatalf("mid-stream export failure must abort the response, got a clean %d body", resp.StatusCode)
	}
}

func TestDashboardBackupDownloadUsesRequestContext(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	exporter := &fakeBackupExporter{}
	srv.backupExport = exporter.export

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, backupsDownloadPath, nil).WithContext(ctx)
	req.AddCookie(cookie)
	srv.Handler().ServeHTTP(rec, req)
	if exporter.calls != 1 || !errors.Is(exporter.ctxErr, context.Canceled) {
		t.Fatalf("export must run on the request context, calls=%d ctxErr=%v", exporter.calls, exporter.ctxErr)
	}
}

func TestDashboardBackupDownloadWithoutBackupSourceFailsWithoutAudit(t *testing.T) {
	srv, store, cookie := dashboardAdminUsersTestServer(t)

	rec := performDashboardForm(srv, http.MethodPost, backupsDownloadPath, "", cookie, false)
	if rec.Code != http.StatusInternalServerError {
		t.Fatalf("expected 500 without a backup source, got %d body=%q", rec.Code, rec.Body.String())
	}
	assertNoArchiveResponse(t, rec)
	if n := countAuditAction(store, authAuditActionBackupDownload); n != 0 {
		t.Fatalf("unconfigured backup source must not record a backup.download audit, got %d", n)
	}
}

func openBackupDownloadTestStore(t *testing.T) *cloudstore.CloudStore {
	t.Helper()
	dsn := os.Getenv("CLOUDSTORE_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDSTORE_TEST_DSN not set — skipping integration test (requires Postgres)")
	}
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test requires URL-style CLOUDSTORE_TEST_DSN so a per-test search_path can be attached")
	}
	schema := fmt.Sprintf("cloudserver_backup_%d", time.Now().UnixNano())
	adminDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	if _, err := adminDB.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminDB.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`) })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	cs, err := cloudstore.New(cloud.Config{DSN: dsn + sep + "search_path=" + schema})
	if err != nil {
		t.Fatalf("open cloudstore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs
}

func TestDashboardBackupDownloadStreamsRealArchivePostgres(t *testing.T) {
	cs := openBackupDownloadTestStore(t)
	ctx := context.Background()
	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	payload, err := chunkcodec.CanonicalizeForProject([]byte(`{"sessions":[{"id":"sess-1","project":"alpha","directory":"/work/alpha"}],"observations":[],"prompts":[]}`), "alpha")
	if err != nil {
		t.Fatalf("canonicalize chunk: %v", err)
	}
	if err := cs.WriteChunk(ctx, "alpha", chunkcodec.ChunkID(payload), "alice", "", payload); err != nil {
		t.Fatalf("seed chunk: %v", err)
	}
	principal := dashboardManagedPrincipal(admin.PrincipalID, cloudstore.PrincipalRoleAdmin, true)
	srv := New(cs, resolvingAuth{principals: map[string]cloudauth.Principal{"admin-token": principal}}, 0, WithAdminIdentityStore(cs))
	cookie := managedDashboardLogin(t, srv, "admin-token", false)

	rec := performDashboardForm(srv, http.MethodPost, backupsDownloadPath, "", cookie, false)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected real backup download to succeed, got %d body=%q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Type") != "application/gzip" || !backupFilenamePattern.MatchString(rec.Header().Get("Content-Disposition")) {
		t.Fatalf("unexpected download headers: %v", rec.Header())
	}
	gz, err := gzip.NewReader(bytes.NewReader(rec.Body.Bytes()))
	if err != nil {
		t.Fatalf("archive is not gzip: %v", err)
	}
	tr := tar.NewReader(gz)
	members := map[string][]byte{}
	var names []string
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("read archive: %v", err)
		}
		data, err := io.ReadAll(tr)
		if err != nil {
			t.Fatalf("read member %s: %v", header.Name, err)
		}
		names = append(names, header.Name)
		members[header.Name] = data
	}
	if len(names) == 0 || names[len(names)-1] != cloudbackup.ManifestName {
		t.Fatalf("expected %s as the last member, got %v", cloudbackup.ManifestName, names)
	}
	if !strings.Contains(string(members["tables/cloud_chunks.jsonl"]), `"alpha"`) {
		t.Fatalf("expected the seeded chunk in the archive, got %q", members["tables/cloud_chunks.jsonl"])
	}
	if _, ok := members["tables/cloud_principal_tokens.jsonl"]; ok {
		t.Fatal("archive must not contain the principal token table")
	}
	// The audit row is written before the snapshot, so the archive's own
	// audit table proves the audit-first order.
	auditRows := string(members["tables/cloud_auth_audit_log.jsonl"])
	if !strings.Contains(auditRows, `"backup.download"`) || !strings.Contains(auditRows, admin.PrincipalID) {
		t.Fatalf("expected the backup.download audit row inside the archive, got %q", auditRows)
	}
}
