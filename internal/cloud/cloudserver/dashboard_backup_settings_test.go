package cloudserver

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

const (
	backupDestinationPath       = "/dashboard/admin/backups/destination"
	backupDestinationTestPath   = "/dashboard/admin/backups/destination/test"
	backupDestinationRemovePath = "/dashboard/admin/backups/destination/remove"
	backupSchedulePath          = "/dashboard/admin/backups/schedule"
	backupRunPath               = "/dashboard/admin/backups/run"

	testBackupAccessKeyID = "AKIADASHBOARDKEY77Q4"
	testBackupSecret      = "dashboard-secret-access-key-never-render"
)

var validBackupDestinationForm = url.Values{
	"endpoint":          {"https://acct.r2.cloudflarestorage.com"},
	"region":            {"auto"},
	"bucket":            {"engram-backups"},
	"prefix":            {"prod/"},
	"access_key_id":     {testBackupAccessKeyID},
	"secret_access_key": {testBackupSecret},
}.Encode()

// fakeBackupSettingsStore is an in-memory BackupSettingsStore that records
// every mutation so refusal tests can prove there were no side effects.
type fakeBackupSettingsStore struct {
	mu          sync.Mutex
	destination cloudstore.BackupDestination
	creds       cloudstore.BackupDestinationCredentials
	openErr     error
	schedule    cloudstore.BackupSchedule
	runs        []cloudstore.BackupRun
	readErr     error
	latestTest  cloudstore.BackupDestinationTest
	outcomes    cloudstore.BackupRunOutcomes
	statusErr   error

	putDestination    []cloudstore.PutBackupDestinationParams
	putSealers        []cloudstore.BackupSecretSealer
	putDestinationErr error
	clears            []cloudstore.BackupDestinationActor
	opens             int
	putSchedule       []cloudstore.PutBackupScheduleParams
	putScheduleErr    error
}

func (f *fakeBackupSettingsStore) GetBackupDestination(context.Context) (cloudstore.BackupDestination, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.destination, f.readErr
}

func (f *fakeBackupSettingsStore) PutBackupDestination(_ context.Context, params cloudstore.PutBackupDestinationParams, sealer cloudstore.BackupSecretSealer) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putDestination = append(f.putDestination, params)
	f.putSealers = append(f.putSealers, sealer)
	if f.putDestinationErr != nil {
		return f.putDestinationErr
	}
	if params.AccessKeyID == "" || params.SecretAccessKey == "" {
		return fmt.Errorf("%w: access key id must be 1-128 printable characters without spaces", cloudstore.ErrInvalidBackupDestination)
	}
	f.destination = cloudstore.BackupDestination{Configured: true, Kind: "s3", Endpoint: params.Endpoint, Region: params.Region, Bucket: params.Bucket, Prefix: params.Prefix, AccessKeyIDHint: "****" + params.AccessKeyID[len(params.AccessKeyID)-4:]}
	return nil
}

func (f *fakeBackupSettingsStore) ClearBackupDestination(_ context.Context, actor cloudstore.BackupDestinationActor) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.clears = append(f.clears, actor)
	f.destination = cloudstore.BackupDestination{}
	return nil
}

func (f *fakeBackupSettingsStore) OpenBackupDestinationCredentials(_ context.Context, opener cloudstore.BackupSecretOpener) (cloudstore.BackupDestinationCredentials, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.opens++
	if opener == nil {
		return cloudstore.BackupDestinationCredentials{}, cloudstore.ErrBackupDestinationKeyRequired
	}
	if f.openErr != nil {
		return cloudstore.BackupDestinationCredentials{}, f.openErr
	}
	if !f.destination.Configured {
		return cloudstore.BackupDestinationCredentials{}, cloudstore.ErrBackupDestinationNotConfigured
	}
	return f.creds, nil
}

func (f *fakeBackupSettingsStore) GetBackupSchedule(context.Context) (cloudstore.BackupSchedule, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.schedule.TimeOfDay == "" {
		return cloudstore.BackupSchedule{TimeOfDay: "03:00", Timezone: "UTC"}, f.readErr
	}
	return f.schedule, f.readErr
}

func (f *fakeBackupSettingsStore) PutBackupSchedule(_ context.Context, params cloudstore.PutBackupScheduleParams) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.putSchedule = append(f.putSchedule, params)
	if f.putScheduleErr != nil {
		return f.putScheduleErr
	}
	for _, day := range params.Weekdays {
		if day < time.Sunday || day > time.Saturday {
			return fmt.Errorf("%w: weekdays must be Monday through Sunday", cloudstore.ErrInvalidBackupSchedule)
		}
	}
	f.schedule = cloudstore.BackupSchedule{Configured: true, Enabled: params.Enabled, Weekdays: params.Weekdays, TimeOfDay: params.TimeOfDay, Timezone: params.Timezone}
	return nil
}

func (f *fakeBackupSettingsStore) ListBackupRuns(_ context.Context, limit int) ([]cloudstore.BackupRun, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if limit != cloudstore.DefaultBackupRunListLimit {
		return nil, fmt.Errorf("unexpected history limit %d", limit)
	}
	return f.runs, f.readErr
}

func (f *fakeBackupSettingsStore) LatestBackupDestinationTest(context.Context) (cloudstore.BackupDestinationTest, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.latestTest, f.statusErr
}

func (f *fakeBackupSettingsStore) LatestBackupRunOutcomes(context.Context) (cloudstore.BackupRunOutcomes, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.outcomes, f.statusErr
}

func (f *fakeBackupSettingsStore) mutations() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return len(f.putDestination) + len(f.clears) + f.opens + len(f.putSchedule)
}

type fakeBackupRunner struct {
	mu     sync.Mutex
	calls  []string
	err    error
	audits func() int
	seen   []int
}

func (f *fakeBackupRunner) StartManualBackup(_ context.Context, actorPrincipalID string) (int64, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, actorPrincipalID)
	if f.audits != nil {
		f.seen = append(f.seen, f.audits())
	}
	if f.err != nil {
		return 0, f.err
	}
	return 42, nil
}

type fakeBackupChecker struct {
	calls       int
	err         error
	creds       cloudstore.BackupDestinationCredentials
	hadDeadline bool
}

func (f *fakeBackupChecker) check(ctx context.Context, creds cloudstore.BackupDestinationCredentials) error {
	f.calls++
	f.creds = creds
	_, f.hadDeadline = ctx.Deadline()
	return f.err
}

func testBackupKey(t *testing.T) *backupcrypto.Sealer {
	t.Helper()
	key, err := backupcrypto.ParseKey(hex.EncodeToString([]byte(strings.Repeat("k", backupcrypto.KeySize))))
	if err != nil {
		t.Fatalf("ParseKey: %v", err)
	}
	sealer, err := backupcrypto.NewSealer(key)
	if err != nil {
		t.Fatalf("NewSealer: %v", err)
	}
	return sealer
}

func configuredBackupSettings() *fakeBackupSettingsStore {
	return &fakeBackupSettingsStore{
		destination: cloudstore.BackupDestination{Configured: true, Kind: "s3", Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/", AccessKeyIDHint: "****" + testBackupAccessKeyID[len(testBackupAccessKeyID)-4:]},
		creds:       cloudstore.BackupDestinationCredentials{Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/", AccessKeyID: testBackupAccessKeyID, SecretAccessKey: testBackupSecret},
		schedule:    cloudstore.BackupSchedule{Configured: true, Enabled: true, Weekdays: []time.Weekday{time.Monday, time.Friday}, TimeOfDay: "03:00", Timezone: "America/Lima"},
	}
}

type backupSettingsFixture struct {
	srv      *CloudServer
	audit    *loginAuditTestStore
	settings *fakeBackupSettingsStore
	runner   *fakeBackupRunner
	checker  *fakeBackupChecker
	exporter *fakeBackupExporter
	cookie   *http.Cookie
}

// wireBackupFixture applies the backup options to a server built by one of
// the dashboard session helpers.
func wireBackupFixture(t *testing.T, srv *CloudServer, audit *loginAuditTestStore, cookie *http.Cookie, settings *fakeBackupSettingsStore) backupSettingsFixture {
	t.Helper()
	f := backupSettingsFixture{srv: srv, audit: audit, settings: settings, runner: &fakeBackupRunner{}, checker: &fakeBackupChecker{}, exporter: &fakeBackupExporter{write: []byte("archive-bytes")}, cookie: cookie}
	WithBackupSettings(settings, testBackupKey(t))(srv)
	WithBackupRunner(f.runner)(srv)
	srv.backupCheckAccess = f.checker.check
	srv.backupExport = f.exporter.export
	srv.backupNow = func() time.Time { return time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC) }
	return f
}

func managedBackupFixture(t *testing.T) backupSettingsFixture {
	t.Helper()
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	return wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
}

func backupAuditCount(store *loginAuditTestStore) int {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	n := 0
	for _, event := range store.auditEvents {
		if strings.HasPrefix(event.Action, "backup.") {
			n++
		}
	}
	return n
}

func backupAuditEvents(store *loginAuditTestStore, action string) []cloudstore.AuthAuditEvent {
	store.auditMu.Lock()
	defer store.auditMu.Unlock()
	var out []cloudstore.AuthAuditEvent
	for _, event := range store.auditEvents {
		if event.Action == action {
			out = append(out, event)
		}
	}
	return out
}

type backupRequest struct {
	method  string
	path    string
	form    string
	headers map[string]string
	cookie  *http.Cookie
	htmx    bool
	ctype   string
}

func doBackupRequest(srv *CloudServer, req backupRequest) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	r := httptest.NewRequest(req.method, req.path, strings.NewReader(req.form))
	switch {
	case req.ctype != "":
		r.Header.Set("Content-Type", req.ctype)
	case req.form != "":
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	for k, v := range req.headers {
		r.Header.Set(k, v)
	}
	if req.cookie != nil {
		r.AddCookie(req.cookie)
	}
	if req.htmx {
		r.Header.Set("HX-Request", "true")
	}
	srv.Handler().ServeHTTP(rec, r)
	return rec
}

var backupMutationRoutes = []struct {
	name string
	path string
	form string
}{
	{"save destination", backupDestinationPath, validBackupDestinationForm},
	{"test destination", backupDestinationTestPath, ""},
	{"remove destination", backupDestinationRemovePath, ""},
	{"save schedule", backupSchedulePath, "weekday=mon&time=03:00&timezone=UTC&enabled=on"},
	{"back up now", backupRunPath, ""},
	{"download", backupsDownloadPath, ""},
}

func TestDashboardBackupMutationRoutesRefuseWithoutSideEffects(t *testing.T) {
	cases := []struct {
		name    string
		fixture func(t *testing.T) backupSettingsFixture
		method  string
		headers map[string]string
		noAuth  bool
		status  int
	}{
		{name: "member", fixture: func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := memberDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "legacy admin", fixture: func(t *testing.T) backupSettingsFixture {
			srv, audit, cookie := legacyAdminDashboardServer(t)
			return wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
		}, method: http.MethodPost, status: http.StatusForbidden},
		{name: "unauthenticated", fixture: managedBackupFixture, method: http.MethodPost, noAuth: true, status: http.StatusSeeOther},
		{name: "managed admin GET", fixture: managedBackupFixture, method: http.MethodGet, status: http.StatusMethodNotAllowed},
		{name: "cross-site", fixture: managedBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "cross-site", "Origin": "https://evil.example.test"}, status: http.StatusForbidden},
		{name: "same-site other origin", fixture: managedBackupFixture, method: http.MethodPost, headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://other.example.com"}, status: http.StatusForbidden},
		{name: "foreign Origin without Sec-Fetch-Site", fixture: managedBackupFixture, method: http.MethodPost, headers: map[string]string{"Origin": "http://evil.example.test"}, status: http.StatusForbidden},
		{name: "opaque null Origin", fixture: managedBackupFixture, method: http.MethodPost, headers: map[string]string{"Origin": "null"}, status: http.StatusForbidden},
	}
	for _, route := range backupMutationRoutes {
		for _, tc := range cases {
			t.Run(route.name+"/"+tc.name, func(t *testing.T) {
				f := tc.fixture(t)
				cookie := f.cookie
				if tc.noAuth {
					cookie = nil
				}
				rec := doBackupRequest(f.srv, backupRequest{method: tc.method, path: route.path, form: route.form, headers: tc.headers, cookie: cookie})
				if rec.Code != tc.status {
					t.Fatalf("expected %d, got %d body=%q", tc.status, rec.Code, rec.Body.String())
				}
				if tc.noAuth && !strings.HasPrefix(dashboardRedirect(rec), "/dashboard/login") {
					t.Fatalf("expected a login redirect, got %q", dashboardRedirect(rec))
				}
				if tc.status == http.StatusMethodNotAllowed && rec.Header().Get("Allow") != http.MethodPost {
					t.Fatalf("expected Allow: POST, got %q", rec.Header().Get("Allow"))
				}
				if n := f.settings.mutations(); n != 0 {
					t.Fatalf("refused request touched the settings store %d times", n)
				}
				if f.checker.calls != 0 || len(f.runner.calls) != 0 || f.exporter.calls != 0 {
					t.Fatalf("refused request ran a side effect: checks=%d runs=%d exports=%d", f.checker.calls, len(f.runner.calls), f.exporter.calls)
				}
				if n := backupAuditCount(f.audit); n != 0 {
					t.Fatalf("refused request recorded %d backup audit events", n)
				}
				assertNoArchiveResponse(t, rec)
				if strings.Contains(rec.Body.String(), testBackupSecret) {
					t.Fatalf("refusal echoed the secret: %q", rec.Body.String())
				}
			})
		}
	}
}

func TestDashboardBackupMutationSameOriginCheck(t *testing.T) {
	cases := []struct {
		name    string
		headers map[string]string
		allowed bool
	}{
		{name: "no fetch metadata or Origin (older clients)", allowed: true},
		{name: "same-origin fetch metadata and matching Origin", headers: map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}, allowed: true},
		{name: "matching Origin with explicit default port", headers: map[string]string{"Origin": "http://example.com:80"}, allowed: true},
		{name: "matching Origin behind TLS proxy", headers: map[string]string{"X-Forwarded-Proto": "https", "Origin": "https://example.com"}, allowed: true},
		{name: "Origin matching the forwarded host", headers: map[string]string{"X-Forwarded-Proto": "https", "X-Forwarded-Host": "engram.example.org", "Origin": "https://engram.example.org"}, allowed: true},
		{name: "same-origin fetch metadata only", headers: map[string]string{"Sec-Fetch-Site": "same-origin"}, allowed: true},
		{name: "http Origin behind TLS proxy", headers: map[string]string{"X-Forwarded-Proto": "https", "Origin": "http://example.com"}},
		{name: "other port", headers: map[string]string{"Origin": "http://example.com:8443"}},
		{name: "same-site fetch metadata with matching Origin", headers: map[string]string{"Sec-Fetch-Site": "same-site", "Origin": "http://example.com"}},
		{name: "user-initiated fetch metadata", headers: map[string]string{"Sec-Fetch-Site": "none"}},
		{name: "malformed Origin", headers: map[string]string{"Origin": "::not a url"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := managedBackupFixture(t)
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, headers: tc.headers, cookie: f.cookie})
			if tc.allowed {
				if rec.Code != http.StatusSeeOther || len(f.settings.clears) != 1 {
					t.Fatalf("expected the same-origin request to remove the destination, got %d clears=%d body=%q", rec.Code, len(f.settings.clears), rec.Body.String())
				}
				return
			}
			if rec.Code != http.StatusForbidden || len(f.settings.clears) != 0 {
				t.Fatalf("expected 403 without side effects, got %d clears=%d", rec.Code, len(f.settings.clears))
			}
		})
	}
}

func TestDashboardBackupsPageRendersDestinationScheduleAndControls(t *testing.T) {
	f := managedBackupFixture(t)
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, rec.Body.String())
	}
	body := rec.Body.String()
	for _, marker := range []string{
		`action="/dashboard/admin/backups/download"`,
		`action="/dashboard/admin/backups/destination"`,
		`action="/dashboard/admin/backups/destination/test"`,
		`action="/dashboard/admin/backups/destination/remove"`,
		`action="/dashboard/admin/backups/schedule"`,
		`action="/dashboard/admin/backups/run"`,
		"https://acct.r2.cloudflarestorage.com",
		"engram-backups",
		"****" + testBackupAccessKeyID[len(testBackupAccessKeyID)-4:],
		`name="weekday" value="mon" checked`,
		`name="weekday" value="fri" checked`,
		`name="weekday" value="tue"`,
		`name="time" value="03:00"`,
		`name="timezone" value="America/Lima"`,
		`name="enabled" value="on" checked`,
		`name="secret_access_key" value=""`,
		"Back up now",
		// 2026-11-26 is a Thursday; the next Mon/Fri 03:00 in Lima (UTC-5).
		"Fri 27 Nov 2026 03:00 America/Lima (08:00 UTC)",
		"cloud_backup_schedule",
		"cloud_backup_runs",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected backups page marker %q, body=%q", marker, body)
		}
	}
	for _, secret := range []string{testBackupSecret, testBackupAccessKeyID, "Not Configured", "hx-post"} {
		if strings.Contains(body, secret) {
			t.Fatalf("backups page must not render %q, body=%q", secret, body)
		}
	}
	if f.settings.opens != 0 {
		t.Fatalf("rendering the page must never open the credentials, opened %d times", f.settings.opens)
	}
}

func TestDashboardBackupsPageHidesRunNowWithoutRunner(t *testing.T) {
	srv, audit, cookie := dashboardAdminUsersTestServer(t)
	settings := configuredBackupSettings()
	WithBackupSettings(settings, testBackupKey(t))(srv)
	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "Back up now") || strings.Contains(rec.Body.String(), `action="/dashboard/admin/backups/run"`) {
		t.Fatalf("without a runner the page must not render Back up now, got %d", rec.Code)
	}
	run := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: backupRunPath, cookie: cookie})
	if run.Code != http.StatusNotFound || backupAuditCount(audit) != 0 {
		t.Fatalf("back up now without a runner = %d with %d audits, want 404 and none", run.Code, backupAuditCount(audit))
	}
}

func TestDashboardBackupsPageWithoutKeyExplainsAndRendersNoForms(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	settings := configuredBackupSettings()
	WithBackupSettings(settings, nil)(srv)
	WithBackupRunner(&fakeBackupRunner{})(srv)
	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "ENGRAM_CLOUD_BACKUP_KEY") || !strings.Contains(body, "engram-backups") || !strings.Contains(body, "Paused: ENGRAM_CLOUD_BACKUP_KEY not set") {
		t.Fatalf("expected the key notice and the read-only destination, body=%q", body)
	}
	for _, forbidden := range []string{`action="/dashboard/admin/backups/destination"`, `action="/dashboard/admin/backups/schedule"`, `action="/dashboard/admin/backups/run"`, `type="checkbox"`, "Next run: <strong>Fri"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("without the key the page must not render %q, body=%q", forbidden, body)
		}
	}
	// The mutation routes refuse too, without touching the store.
	for _, path := range []string{backupDestinationPath, backupDestinationTestPath, backupSchedulePath} {
		rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: path, form: validBackupDestinationForm, cookie: cookie})
		if rec.Code != http.StatusConflict || settings.mutations() != 0 {
			t.Fatalf("%s without the key = %d (store calls %d), want 409 and none", path, rec.Code, settings.mutations())
		}
	}
}

func TestDashboardBackupsPageWithoutDestinationHasNoScheduleForm(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	f := wireBackupFixture(t, srv, nil, cookie, &fakeBackupSettingsStore{})
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, `action="/dashboard/admin/backups/destination"`) || !strings.Contains(body, "No destination is configured.") {
		t.Fatalf("expected the destination form, got %d body=%q", rec.Code, body)
	}
	for _, forbidden := range []string{`action="/dashboard/admin/backups/schedule"`, `action="/dashboard/admin/backups/destination/test"`, `action="/dashboard/admin/backups/run"`, `type="checkbox"`} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("without a destination the page must not render %q", forbidden)
		}
	}
}

func TestDashboardBackupsPageLegacyAdminIsReadOnly(t *testing.T) {
	srv, audit, cookie := legacyAdminDashboardServer(t)
	f := wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "Changing scheduled backups requires a managed admin token.") || !strings.Contains(body, "engram-backups") {
		t.Fatalf("expected a read-only settings view, got %d body=%q", rec.Code, body)
	}
	for _, forbidden := range []string{"<form method=\"post\" action=\"/dashboard/admin/backups/", `type="checkbox"`, "Back up now", testBackupSecret} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("legacy admin page must not render %q", forbidden)
		}
	}
}

func TestDashboardBackupsPageReportsUnavailableSettings(t *testing.T) {
	srv, _, cookie := dashboardAdminUsersTestServer(t)
	settings := configuredBackupSettings()
	settings.readErr = errors.New("dial tcp 10.0.0.5:5432: password=hunter2")
	WithBackupSettings(settings, testBackupKey(t))(srv)
	rec := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusBadGateway || !strings.Contains(body, "Backup settings are temporarily unavailable.") || !strings.Contains(body, `action="/dashboard/admin/backups/download"`) {
		t.Fatalf("expected 502 with the unavailable note and the download form, got %d body=%q", rec.Code, body)
	}
	if strings.Contains(body, "hunter2") || strings.Contains(body, "10.0.0.5") || strings.Contains(body, `action="/dashboard/admin/backups/destination"`) {
		t.Fatalf("unavailable settings must not echo the error or render forms, body=%q", body)
	}
}

func TestDashboardBackupsPageRendersRunHistory(t *testing.T) {
	f := managedBackupFixture(t)
	started := time.Date(2026, 11, 23, 8, 0, 5, 0, time.UTC)
	f.settings.runs = []cloudstore.BackupRun{
		{ID: 3, Trigger: cloudstore.BackupRunTriggerManual, StartedAt: started.Add(48 * time.Hour), Status: cloudstore.BackupRunStatusRunning},
		{ID: 2, Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: started.Add(-5 * time.Second), StartedAt: started, FinishedAt: started.Add(time.Minute), Status: cloudstore.BackupRunStatusFailure, ErrorMessage: `PUT failed: <script>alert(1)</script>`},
		{ID: 1, Trigger: cloudstore.BackupRunTriggerScheduled, ScheduledFor: started.Add(-72 * time.Hour), StartedAt: started.Add(-72 * time.Hour), FinishedAt: started.Add(-71 * time.Hour), Status: cloudstore.BackupRunStatusSuccess, ObjectKey: "prod/engram-cloud-backup-20261120T080000Z.tar.gz", SizeBytes: 4096},
	}
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie).Body.String()
	for _, marker := range []string{
		"RECENT RUNS", ">manual<", ">scheduled<", "badge-warning\">running", "badge-danger\">failure", "badge-success\">success",
		"23 Nov 2026 08:00 UTC", "prod/engram-cloud-backup-20261120T080000Z.tar.gz", "4.0 KiB",
		"PUT failed: &lt;script&gt;alert(1)&lt;/script&gt;",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected history marker %q, body=%q", marker, body)
		}
	}
	if strings.Contains(body, "<script>alert(1)") {
		t.Fatal("history must escape error messages")
	}
}

func TestDashboardBackupsPageNoticeIsFromAFixedSet(t *testing.T) {
	f := managedBackupFixture(t)
	body := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice=test-auth", f.cookie).Body.String()
	if !strings.Contains(body, "the destination rejected the credentials") {
		t.Fatalf("expected the auth failure notice, body=%q", body)
	}
	body = performDashboardRequest(f.srv, http.MethodGet, backupsPagePath+"?notice=%3Cb%3Eforged%3C%2Fb%3E", f.cookie).Body.String()
	if strings.Contains(body, "forged") || strings.Contains(body, `role="status"`) {
		t.Fatalf("an unknown notice must render nothing, body=%q", body)
	}
}

func TestDashboardSaveBackupDestinationReadsFormFieldsExplicitly(t *testing.T) {
	f := managedBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validBackupDestinationForm, cookie: f.cookie, headers: map[string]string{"Origin": "http://example.com", "Sec-Fetch-Site": "same-origin"}})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=destination-saved" {
		t.Fatalf("expected 303 to the page, got %d location=%q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	if len(f.settings.putDestination) != 1 {
		t.Fatalf("expected one store call, got %d", len(f.settings.putDestination))
	}
	got := f.settings.putDestination[0]
	want := cloudstore.PutBackupDestinationParams{
		Endpoint: "https://acct.r2.cloudflarestorage.com", Region: "auto", Bucket: "engram-backups", Prefix: "prod/",
		AccessKeyID: testBackupAccessKeyID, SecretAccessKey: testBackupSecret,
		Actor: cloudstore.BackupDestinationActor{PrincipalID: "p-admin", Source: string(cloudauth.PrincipalSourceManagedToken)},
	}
	if got != want {
		t.Fatalf("store params = %+v, want %+v", got, want)
	}
	if f.settings.putSealers[0] != cloudstore.BackupSecretSealer(f.srv.backupKey) {
		t.Fatal("the destination must be sealed with the server's backup key")
	}

	// HTMX posts redirect with HX-Redirect.
	htmx := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validBackupDestinationForm, cookie: f.cookie, htmx: true})
	if htmx.Code != http.StatusOK || htmx.Header().Get("HX-Redirect") != backupsPagePath+"?notice=destination-saved" {
		t.Fatalf("expected an HX-Redirect, got %d %q", htmx.Code, htmx.Header().Get("HX-Redirect"))
	}
}

func TestDashboardSaveBackupDestinationIgnoresQueryAndJSONCredentials(t *testing.T) {
	f := managedBackupFixture(t)
	path := backupDestinationPath + "?access_key_id=" + testBackupAccessKeyID + "&secret_access_key=" + testBackupSecret
	form := url.Values{"endpoint": {"https://acct.r2.cloudflarestorage.com"}, "region": {"auto"}, "bucket": {"engram-backups"}}.Encode()
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: path, form: form, cookie: f.cookie})
	if rec.Code != http.StatusBadRequest || f.settings.putDestination[0].AccessKeyID != "" || f.settings.putDestination[0].SecretAccessKey != "" {
		t.Fatalf("credentials in the URL must be ignored, got %d params=%+v", rec.Code, f.settings.putDestination)
	}
	json := `{"Endpoint":"https://acct.r2.cloudflarestorage.com","Region":"auto","Bucket":"engram-backups","AccessKeyID":"` + testBackupAccessKeyID + `","SecretAccessKey":"` + testBackupSecret + `"}`
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: json, ctype: "application/json", cookie: f.cookie})
	if rec.Code != http.StatusBadRequest || f.settings.putDestination[1] != (cloudstore.PutBackupDestinationParams{Actor: f.settings.putDestination[1].Actor}) {
		t.Fatalf("a JSON body must not be decoded into the params, got %d params=%+v", rec.Code, f.settings.putDestination[1])
	}
	for _, body := range []string{rec.Body.String()} {
		if strings.Contains(body, testBackupSecret) || strings.Contains(body, testBackupAccessKeyID) {
			t.Fatalf("error page echoes a credential: %q", body)
		}
	}
}

func TestDashboardSaveBackupDestinationRendersValidationErrors(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.putDestinationErr = fmt.Errorf("%w: bucket must be 3-63 lowercase letters", cloudstore.ErrInvalidBackupDestination)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validBackupDestinationForm, cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "bucket must be 3-63 lowercase letters") || !strings.Contains(body, "alert alert-danger") {
		t.Fatalf("expected 400 with the validation reason, got %d body=%q", rec.Code, body)
	}
	if strings.Contains(body, testBackupSecret) || strings.Contains(body, testBackupAccessKeyID) || strings.Contains(body, "cloudstore:") {
		t.Fatalf("validation page must not echo credentials or internals, body=%q", body)
	}

	f.settings.putDestinationErr = errors.New("dial tcp 10.0.0.5:5432: connection refused")
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationPath, form: validBackupDestinationForm, cookie: f.cookie})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "10.0.0.5") {
		t.Fatalf("store failure must be a generic 500, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestDashboardTestBackupConnectionMapsResults(t *testing.T) {
	cases := []struct {
		name       string
		checkErr   error
		openErr    error
		noDest     bool
		notice     string
		outcome    string
		reason     string
		wantChecks int
	}{
		{name: "ok", notice: "test-ok", outcome: authAuditOutcomeSuccess, wantChecks: 1},
		{name: "auth failed", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrAuth, StatusCode: 403}, notice: "test-auth", outcome: authAuditOutcomeFailure, reason: "auth_failed", wantChecks: 1},
		{name: "bucket not found", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrBucketNotFound, StatusCode: 404}, notice: "test-bucket", outcome: authAuditOutcomeFailure, reason: "bucket_not_found", wantChecks: 1},
		{name: "network", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrNetwork}, notice: "test-network", outcome: authAuditOutcomeFailure, reason: "network", wantChecks: 1},
		{name: "deadline", checkErr: context.DeadlineExceeded, notice: "test-network", outcome: authAuditOutcomeFailure, reason: "network", wantChecks: 1},
		{name: "unexpected", checkErr: &s3client.Error{Op: "CheckAccess", Kind: s3client.ErrUnexpectedStatus, StatusCode: 500}, notice: "test-error", outcome: authAuditOutcomeFailure, reason: "unexpected_response", wantChecks: 1},
		{name: "rotated key", openErr: fmt.Errorf("open: %w", backupcrypto.ErrKeyMismatch), notice: "test-key", outcome: authAuditOutcomeFailure, reason: "key_mismatch"},
		{name: "tampered row", openErr: fmt.Errorf("open: %w", backupcrypto.ErrSealedValueInvalid), notice: "test-key", outcome: authAuditOutcomeFailure, reason: "key_mismatch"},
		{name: "no destination", noDest: true, notice: "test-none", outcome: authAuditOutcomeFailure, reason: "not_configured"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := managedBackupFixture(t)
			f.checker.err = tc.checkErr
			f.settings.openErr = tc.openErr
			if tc.noDest {
				f.settings.destination = cloudstore.BackupDestination{}
			}
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("expected 303 to notice %s, got %d %q", tc.notice, rec.Code, dashboardRedirect(rec))
			}
			if f.checker.calls != tc.wantChecks {
				t.Fatalf("checks = %d, want %d", f.checker.calls, tc.wantChecks)
			}
			if tc.wantChecks == 1 && (!f.checker.hadDeadline || f.checker.creds.SecretAccessKey != testBackupSecret || f.checker.creds.Bucket != "engram-backups") {
				t.Fatalf("checker must get the opened credentials and a bounded context, deadline=%v creds bucket=%q", f.checker.hadDeadline, f.checker.creds.Bucket)
			}
			events := backupAuditEvents(f.audit, authAuditActionBackupDestinationTest)
			if len(events) != 1 || events[0].Outcome != tc.outcome || events[0].ReasonCode != tc.reason || events[0].ActorPrincipalID != "p-admin" {
				t.Fatalf("unexpected test audit: %+v", events)
			}
			encoded := fmt.Sprintf("%+v", events[0])
			if strings.Contains(encoded, testBackupSecret) || strings.Contains(encoded, testBackupAccessKeyID) {
				t.Fatalf("test audit leaks a credential: %s", encoded)
			}
			page := performDashboardRequest(f.srv, http.MethodGet, dashboardRedirect(rec), f.cookie).Body.String()
			if !strings.Contains(page, `role="status"`) {
				t.Fatalf("result notice %s did not render", tc.notice)
			}
		})
	}
}

func TestDashboardTestBackupConnectionAuditFailureHidesResult(t *testing.T) {
	f := managedBackupFixture(t)
	f.audit.auditErr = errors.New("audit down")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationTestPath, cookie: f.cookie})
	if rec.Code != http.StatusInternalServerError || strings.Contains(rec.Body.String(), "audit down") {
		t.Fatalf("expected a generic 500 when the audit fails, got %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestDashboardRemoveBackupDestination(t *testing.T) {
	f := managedBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=destination-removed" {
		t.Fatalf("expected 303, got %d %q", rec.Code, dashboardRedirect(rec))
	}
	if len(f.settings.clears) != 1 || f.settings.clears[0] != (cloudstore.BackupDestinationActor{PrincipalID: "p-admin", Source: string(cloudauth.PrincipalSourceManagedToken)}) {
		t.Fatalf("clear calls = %+v", f.settings.clears)
	}
}

func TestDashboardSaveBackupSchedule(t *testing.T) {
	f := managedBackupFixture(t)
	form := "weekday=mon&weekday=fri&weekday=wed&time=03:00&timezone=America%2FLima&enabled=on"
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: form, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=schedule-saved" {
		t.Fatalf("expected 303, got %d %q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	got := f.settings.putSchedule[0]
	if !got.Enabled || fmt.Sprint(got.Weekdays) != fmt.Sprint([]time.Weekday{time.Monday, time.Friday, time.Wednesday}) || got.TimeOfDay != "03:00" || got.Timezone != "America/Lima" ||
		got.Actor != (cloudstore.BackupDestinationActor{PrincipalID: "p-admin", Source: string(cloudauth.PrincipalSourceManagedToken)}) {
		t.Fatalf("schedule params = %+v", got)
	}

	// Disabling sends no enabled field.
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "time=04:15&timezone=UTC", cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || f.settings.putSchedule[1].Enabled || len(f.settings.putSchedule[1].Weekdays) != 0 {
		t.Fatalf("disable = %d %+v", rec.Code, f.settings.putSchedule[1])
	}

	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "weekday=funday&time=03:00&timezone=UTC&enabled=on", cookie: f.cookie})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "weekdays must be Monday through Sunday") {
		t.Fatalf("unknown weekday = %d body=%q", rec.Code, rec.Body.String())
	}

	f.settings.putScheduleErr = fmt.Errorf("%w: configure a backup destination before enabling the schedule", cloudstore.ErrBackupDestinationNotConfigured)
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: form, cookie: f.cookie})
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "Configure a backup destination before enabling the schedule.") {
		t.Fatalf("enable without destination = %d body=%q", rec.Code, rec.Body.String())
	}

	f.settings.putScheduleErr = fmt.Errorf("%w: time zone must be an IANA name such as UTC or America/Lima", cloudstore.ErrInvalidBackupSchedule)
	rec = doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: form, cookie: f.cookie})
	if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "time zone must be an IANA name") {
		t.Fatalf("invalid schedule = %d body=%q", rec.Code, rec.Body.String())
	}
}

func TestDashboardBackupNowAuditsBeforeStartingTheRunner(t *testing.T) {
	f := managedBackupFixture(t)
	f.runner.audits = func() int { return len(backupAuditEvents(f.audit, authAuditActionBackupRunManual)) }
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupRunPath, cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=run-started" {
		t.Fatalf("expected 303, got %d %q", rec.Code, dashboardRedirect(rec))
	}
	if len(f.runner.calls) != 1 || f.runner.calls[0] != "p-admin" || f.runner.seen[0] != 1 {
		t.Fatalf("runner calls = %v, audits seen at start = %v", f.runner.calls, f.runner.seen)
	}
	events := backupAuditEvents(f.audit, authAuditActionBackupRunManual)
	if len(events) != 1 || events[0].Outcome != authAuditOutcomeStarted || events[0].ActorPrincipalID != "p-admin" {
		t.Fatalf("unexpected run audit: %+v", events)
	}
}

func TestDashboardBackupNowReportsRunnerRefusal(t *testing.T) {
	for name, tc := range map[string]struct {
		err    error
		notice string
		reason string
	}{
		"busy":   {err: fmt.Errorf("start: %w", ErrBackupAlreadyRunning), notice: "run-busy", reason: "already_running"},
		"failed": {err: errors.New("destination unreachable: secret=xyz"), notice: "run-failed", reason: "runner_error"},
	} {
		t.Run(name, func(t *testing.T) {
			f := managedBackupFixture(t)
			f.runner.err = tc.err
			rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupRunPath, cookie: f.cookie})
			if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+tc.notice {
				t.Fatalf("expected 303 to %s, got %d %q", tc.notice, rec.Code, dashboardRedirect(rec))
			}
			events := backupAuditEvents(f.audit, authAuditActionBackupRunManual)
			if len(events) != 2 || events[0].Outcome != authAuditOutcomeStarted || events[1].Outcome != authAuditOutcomeFailure || events[1].ReasonCode != tc.reason {
				t.Fatalf("unexpected run audits: %+v", events)
			}
			if strings.Contains(fmt.Sprintf("%+v", events), "xyz") {
				t.Fatalf("run audit carries the runner error text: %+v", events)
			}
		})
	}
}

func TestDashboardBackupNowAuditFailureDoesNotStartTheRunner(t *testing.T) {
	f := managedBackupFixture(t)
	f.audit.auditErr = errors.New("audit down")
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupRunPath, cookie: f.cookie})
	if rec.Code != http.StatusInternalServerError || len(f.runner.calls) != 0 {
		t.Fatalf("expected 500 without starting the runner, got %d calls=%d", rec.Code, len(f.runner.calls))
	}
}

func TestDashboardBackupSettingsEndToEndPostgres(t *testing.T) {
	cs := openBackupDownloadTestStore(t)
	ctx := context.Background()
	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed admin: %v", err)
	}
	principal := dashboardManagedPrincipal(admin.PrincipalID, cloudstore.PrincipalRoleAdmin, true)
	key := testBackupKey(t)
	srv := New(cs, resolvingAuth{principals: map[string]cloudauth.Principal{"admin-token": principal}}, 0, WithAdminIdentityStore(cs), WithBackupSettings(cs, key))
	checker := &fakeBackupChecker{}
	srv.backupCheckAccess = checker.check
	cookie := managedDashboardLogin(t, srv, "admin-token", false)
	sameOrigin := map[string]string{"Sec-Fetch-Site": "same-origin", "Origin": "http://example.com"}

	steps := []struct {
		path, form, notice string
	}{
		{backupDestinationPath, validBackupDestinationForm, "destination-saved"},
		{backupDestinationTestPath, "", "test-ok"},
		{backupSchedulePath, "weekday=mon&weekday=thu&time=03:00&timezone=America%2FLima&enabled=on", "schedule-saved"},
	}
	for _, step := range steps {
		rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: step.path, form: step.form, headers: sameOrigin, cookie: cookie})
		if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice="+step.notice {
			t.Fatalf("%s = %d %q body=%q", step.path, rec.Code, dashboardRedirect(rec), rec.Body.String())
		}
	}
	if checker.creds.SecretAccessKey != testBackupSecret || checker.creds.AccessKeyID != testBackupAccessKeyID {
		t.Fatal("test connection must use the credentials opened with the server key")
	}

	page := performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie).Body.String()
	for _, marker := range []string{"engram-backups", "****" + testBackupAccessKeyID[len(testBackupAccessKeyID)-4:], "Mon, Thu at 03:00 America/Lima", "Next run: <strong>"} {
		if !strings.Contains(page, marker) {
			t.Fatalf("page misses %q, body=%q", marker, page)
		}
	}
	if strings.Contains(page, testBackupSecret) || strings.Contains(page, testBackupAccessKeyID) {
		t.Fatal("page renders a stored credential")
	}

	events, err := cs.ListAuthAuditEvents(ctx, cloudstore.AuthAuditQuery{Limit: 50})
	if err != nil {
		t.Fatal(err)
	}
	actions := map[string]int{}
	for _, event := range events {
		actions[event.Action]++
		if event.ActorPrincipalID != admin.PrincipalID {
			t.Fatalf("audit %s has actor %q", event.Action, event.ActorPrincipalID)
		}
		if encoded := fmt.Sprintf("%+v", event.Metadata); strings.Contains(encoded, testBackupSecret) || strings.Contains(encoded, testBackupAccessKeyID) {
			t.Fatalf("audit %s leaks a credential: %s", event.Action, encoded)
		}
	}
	for _, action := range []string{cloudstore.AuthAuditActionBackupDestinationUpdate, authAuditActionBackupDestinationTest, cloudstore.AuthAuditActionBackupScheduleUpdate} {
		if actions[action] != 1 {
			t.Fatalf("audit actions = %v, want one %s", actions, action)
		}
	}

	rec := doBackupRequest(srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, headers: sameOrigin, cookie: cookie})
	if rec.Code != http.StatusSeeOther {
		t.Fatalf("remove = %d", rec.Code)
	}
	page = performDashboardRequest(srv, http.MethodGet, backupsPagePath, cookie).Body.String()
	if !strings.Contains(page, "Paused: no destination") || strings.Contains(page, `action="/dashboard/admin/backups/schedule"`) {
		t.Fatalf("after removing the destination the schedule must show as paused without a form, body=%q", page)
	}
}
