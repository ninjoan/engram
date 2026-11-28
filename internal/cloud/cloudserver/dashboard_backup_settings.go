package cloudserver

import (
	"context"
	"errors"
	"log"
	"net/http"
	"reflect"
	"strings"
	"time"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dashboard"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/dropbox"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/s3client"
)

// This file implements the dashboard Backups page and its settings routes
// (cloud backups stage 3): the external destination (an S3-compatible
// bucket or a Dropbox folder, chosen by the kind form field), the
// weekday/time schedule, "Back up now" and the run history. Every mutation
// route is POST only, requires a managed admin (requireManagedAdmin), passes
// the same-origin check (dashboard_backup_origin.go) and is audited. Form
// fields are read one by one from the POST body; a request body is never
// decoded into cloudstore.PutBackupDestinationParams or
// cloudstore.PutDropboxDestinationParams.

// BackupSettingsStore is the storage boundary of the backup settings.
// *cloudstore.CloudStore satisfies it; the destination and schedule writes
// record their own audit rows in the same transaction.
type BackupSettingsStore interface {
	GetBackupDestination(ctx context.Context) (cloudstore.BackupDestination, error)
	PutBackupDestination(ctx context.Context, params cloudstore.PutBackupDestinationParams, sealer cloudstore.BackupSecretSealer) error
	PutDropboxDestination(ctx context.Context, params cloudstore.PutDropboxDestinationParams, sealer cloudstore.BackupSecretSealer) error
	ClearBackupDestination(ctx context.Context, actor cloudstore.BackupDestinationActor) error
	// OpenBackupDestination opens the stored destination of any kind for
	// "Test connection".
	OpenBackupDestination(ctx context.Context, opener cloudstore.BackupSecretOpener) (cloudstore.OpenedBackupDestination, error)
	GetBackupSchedule(ctx context.Context) (cloudstore.BackupSchedule, error)
	PutBackupSchedule(ctx context.Context, params cloudstore.PutBackupScheduleParams) error
	ListBackupRuns(ctx context.Context, limit int) ([]cloudstore.BackupRun, error)
	// LatestBackupDestinationTest and LatestBackupRunOutcomes feed the
	// destination status card; neither reads a credential.
	LatestBackupDestinationTest(ctx context.Context) (cloudstore.BackupDestinationTest, error)
	LatestBackupRunOutcomes(ctx context.Context) (cloudstore.BackupRunOutcomes, error)
}

// BackupKey seals and opens destination credentials; *backupcrypto.Sealer
// built from ENGRAM_CLOUD_BACKUP_KEY satisfies it.
type BackupKey interface {
	cloudstore.BackupSecretSealer
	cloudstore.BackupSecretOpener
}

// BackupRunner starts a manual backup upload to the configured destination.
// StartManualBackup must return promptly (the upload runs in the background)
// and records the run in the backup run history; it returns the run id.
type BackupRunner interface {
	StartManualBackup(ctx context.Context, actorPrincipalID string) (int64, error)
}

// ErrBackupAlreadyRunning is returned by a BackupRunner that refuses to start
// a run while another one is running.
var ErrBackupAlreadyRunning = errors.New("a backup is already running")

// ErrBackupDestinationUnsupported is returned by a BackupRunner that refuses
// to start a run because this server cannot upload to the configured kind of
// destination yet.
var ErrBackupDestinationUnsupported = errors.New("the backup destination is not supported")

// WithBackupSettings wires the backup settings store and the backup key. A
// nil key means ENGRAM_CLOUD_BACKUP_KEY is not set: the page explains it and
// renders no settings form, and the routes that need the key refuse.
func WithBackupSettings(store BackupSettingsStore, key BackupKey) Option {
	return func(s *CloudServer) {
		s.backupSettings = store
		s.backupKey = nil
		if key != nil && !isNilInterfaceValue(key) {
			s.backupKey = key
		}
	}
}

// WithBackupRunner wires the runner behind "Back up now". Without it the
// button is not rendered and the route answers 404.
func WithBackupRunner(runner BackupRunner) Option {
	return func(s *CloudServer) {
		s.backupRunner = runner
	}
}

func isNilInterfaceValue(value any) bool {
	v := reflect.ValueOf(value)
	return v.Kind() == reflect.Pointer && v.IsNil()
}

const (
	backupsPageURL = "/dashboard/admin/backups"
	// backupConnectionTestTimeout bounds "Test connection" below the
	// client's own CheckAccess default.
	backupConnectionTestTimeout = 15 * time.Second

	// Reason codes of a failed backup.destination.test or backup.run.manual.
	backupReasonAuthFailed         = "auth_failed"
	backupReasonBucketNotFound     = "bucket_not_found"
	backupReasonNetwork            = "network"
	backupReasonUnexpectedResponse = "unexpected_response"
	backupReasonKeyMismatch        = "key_mismatch"
	backupReasonNotConfigured      = "not_configured"
	backupReasonAlreadyRunning     = "already_running"
	backupReasonRunnerError        = "runner_error"
	// backupReasonUnsupportedKind fails a connection test of a destination
	// kind the test route cannot check yet (Dropbox, Google Drive).
	backupReasonUnsupportedKind = "unsupported_kind"
	// backupReasonUnsupportedDestination refuses a manual run of a
	// destination kind the runner cannot upload to yet.
	backupReasonUnsupportedDestination = "unsupported_destination"
	// backupReasonInvalidDestination is the reason code of a
	// backup.destination.check refused by validation.
	backupReasonInvalidDestination = "invalid_destination"
	// backupReasonFolderConflict fails a Dropbox check whose folder path is
	// a file.
	backupReasonFolderConflict = "folder_conflict"
)

// backupStorageKindReason refuses a destination save or check of a kind
// the dashboard has no form for.
const backupStorageKindReason = "choose S3-compatible or Dropbox storage"

// backupNotices maps the notice query parameter to a fixed message, so a
// crafted URL can only select one of these.
var backupNotices = map[string]dashboard.BackupsNotice{
	"destination-saved":   {Kind: "success", Message: "Backup destination saved.", Destination: true},
	"destination-removed": {Kind: "success", Message: "Backup destination removed.", Destination: true},
	"schedule-saved":      {Kind: "success", Message: "Backup schedule saved."},
	"test-ok":             {Kind: "success", Title: "Connected.", Message: "Connection test passed: the bucket is reachable with the stored credentials.", Destination: true},
	"test-auth":           {Kind: "danger", Title: "Keys rejected.", Message: "Connection test failed: the destination rejected the credentials (authentication or authorization failed).", Destination: true},
	"test-bucket":         {Kind: "danger", Title: "Bucket not found.", Message: "Connection test failed: the bucket was not found at this endpoint.", Destination: true},
	"test-network":        {Kind: "danger", Title: "Endpoint unreachable.", Message: "Connection test failed: the endpoint could not be reached (network error or timeout).", Destination: true},
	"test-error":          {Kind: "danger", Title: "Unexpected response.", Message: "Connection test failed: the destination returned an unexpected response.", Destination: true},
	"test-key":            {Kind: "danger", Title: "Credentials cannot be opened.", Message: "Connection test failed: the stored credentials cannot be opened with the current ENGRAM_CLOUD_BACKUP_KEY. Save the destination again.", Destination: true},
	"test-none":           {Kind: "danger", Title: "No destination.", Message: "Connection test failed: no backup destination is configured.", Destination: true},
	"test-unsupported":    {Kind: "danger", Title: "Not available.", Message: "Connection test is not available for this kind of destination yet.", Destination: true},
	// Dropbox connection tests: dropbox-test-<result>.
	"dropbox-test-ok":        {Kind: "success", Title: "Connected.", Message: "Connection test passed: Dropbox accepted the stored credentials and the folder exists.", Destination: true},
	"dropbox-test-ok-folder": {Kind: "success", Title: "Connected — folder will be created on first upload.", Message: "Connection test passed: Dropbox accepted the stored credentials; the folder does not exist yet.", Destination: true},
	"dropbox-test-auth":      {Kind: "danger", Title: "Credentials rejected.", Message: "Connection test failed: Dropbox refused the stored app key, app secret or refresh token.", Destination: true},
	"dropbox-test-folder":    {Kind: "danger", Title: "Folder path is a file.", Message: "Connection test failed: a file already exists at the folder path in Dropbox.", Destination: true},
	"dropbox-test-network":   {Kind: "danger", Title: "Dropbox unreachable.", Message: "Connection test failed: Dropbox could not be reached (network error or timeout).", Destination: true},
	"dropbox-test-error":     {Kind: "danger", Title: "Unexpected response.", Message: "Connection test failed: Dropbox returned an unexpected response.", Destination: true},
	"run-started":            {Kind: "success", Message: "Backup started. Its result appears in the run history."},
	"run-busy":               {Kind: "danger", Message: "A backup is already running; wait for it to finish."},
	"run-failed":             {Kind: "danger", Message: "The backup could not be started. Check the server log."},
	"run-unsupported":        {Kind: "danger", Message: "This server cannot upload to this kind of destination yet; no backup was started."},
}

// backupKindNotice describes a stored destination of a kind the dashboard
// has no form for yet (Google Drive) with its non-secret settings; the OAuth
// client identifier shows only its last characters. It is empty for an s3
// or Dropbox destination.
func backupKindNotice(d cloudstore.BackupDestination) dashboard.BackupsNotice {
	var title, detail string
	switch d.Kind {
	case cloudstore.BackupDestinationKindGDrive:
		state := "pending authorization"
		if d.GDrive.Authorized {
			state = "authorized"
		}
		title = "Google Drive destination."
		detail = "folder " + d.GDrive.FolderName + ", client id " + backupClientIDHint(d.GDrive.ClientID) + ", " + state
	default:
		return dashboard.BackupsNotice{}
	}
	return dashboard.BackupsNotice{
		Kind:        "danger",
		Title:       title,
		Message:     "Stored destination: " + detail + ". This dashboard cannot edit or test this kind of destination yet; remove it to configure an S3-compatible bucket or a Dropbox folder.",
		Destination: true,
	}
}

// backupKindSummary maps a stored destination onto the fields the status
// card renders. A Dropbox destination keeps its folder and carries only the
// app key hint (the full app key is cleared, so the page cannot render it);
// a Google Drive destination shows its folder in place of the bucket and
// the client identifier hint in place of the access key id hint.
func backupKindSummary(d cloudstore.BackupDestination) cloudstore.BackupDestination {
	switch d.Kind {
	case cloudstore.BackupDestinationKindDropbox:
		d.AccessKeyIDHint, d.Dropbox.AppKey = backupClientIDHint(d.Dropbox.AppKey), ""
	case cloudstore.BackupDestinationKindGDrive:
		d.Bucket, d.AccessKeyIDHint = d.GDrive.FolderName, backupClientIDHint(d.GDrive.ClientID)
	}
	return d
}

// backupClientIDHint keeps the last four characters of a long OAuth client
// identifier and nothing of a short one.
func backupClientIDHint(id string) string {
	if len(id) < 12 {
		return "****"
	}
	return "****" + id[len(id)-4:]
}

// checkBackupDestinationAccess is the default "Test connection" check: a
// read-only ListObjectsV2 of at most one key.
func checkBackupDestinationAccess(ctx context.Context, creds cloudstore.BackupDestinationCredentials) error {
	client, err := s3client.New(s3client.Config{
		Endpoint: creds.Endpoint, Region: creds.Region, Bucket: creds.Bucket,
		AccessKeyID: creds.AccessKeyID, SecretAccessKey: creds.SecretAccessKey,
	})
	if err != nil {
		return err
	}
	return client.CheckAccess(ctx)
}

// checkDropboxDestinationAccess is the default Dropbox access check: it
// refreshes an access token and reads the folder's metadata, writing
// nothing. httpClient is nil outside tests.
func checkDropboxDestinationAccess(ctx context.Context, creds cloudstore.DropboxDestinationCredentials, httpClient *http.Client) error {
	client, err := dropbox.New(dropbox.Config{AppKey: creds.AppKey, AppSecret: creds.AppSecret, RefreshToken: creds.RefreshToken, HTTPClient: httpClient})
	if err != nil {
		return err
	}
	return client.CheckAccess(ctx, creds.FolderPath)
}

// runDropboxCheck runs the Dropbox access check bounded like the S3 one.
func (s *CloudServer) runDropboxCheck(ctx context.Context, creds cloudstore.DropboxDestinationCredentials) error {
	ctx, cancel := context.WithTimeout(ctx, backupConnectionTestTimeout)
	defer cancel()
	if s.backupCheckDropbox != nil {
		return s.backupCheckDropbox(ctx, creds)
	}
	return checkDropboxDestinationAccess(ctx, creds, s.backupDropboxHTTPClient)
}

// classifyDropboxConnectionTest maps a Dropbox access check to a result and
// a failure reason code ("" for success). A missing folder is a success:
// the first upload creates it.
func classifyDropboxConnectionTest(err error) (string, string) {
	switch {
	case err == nil:
		return "ok", ""
	case errors.Is(err, dropbox.ErrFolderNotFound):
		return "ok-folder", ""
	case errors.Is(err, dropbox.ErrAuth):
		return "auth", backupReasonAuthFailed
	case errors.Is(err, dropbox.ErrConflict):
		return "folder", backupReasonFolderConflict
	case errors.Is(err, dropbox.ErrNetwork), errors.Is(err, dropbox.ErrUploadStalled), errors.Is(err, context.DeadlineExceeded):
		return "network", backupReasonNetwork
	default:
		return "error", backupReasonUnexpectedResponse
	}
}

// dropboxAuditMetadata is the non-secret description of a Dropbox
// destination in an audit row: kind, folder and app key hint.
func dropboxAuditMetadata(creds cloudstore.DropboxDestinationCredentials, result string) map[string]any {
	return map[string]any{"kind": cloudstore.BackupDestinationKindDropbox, "folder_path": creds.FolderPath, "app_key_hint": backupClientIDHint(creds.AppKey), "result": result}
}

// handleDashboardBackupsPage handles GET /dashboard/admin/backups. Any
// dashboard admin may view it; forms render only for managed admins.
// ?kind=s3|dropbox|gdrive selects the destination form.
func (s *CloudServer) handleDashboardBackupsPage(w http.ResponseWriter, r *http.Request) {
	if !s.isDashboardAdmin(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	notice := backupNotices[r.URL.Query().Get("notice")]
	s.renderBackupsPage(w, r, http.StatusOK, notice)
}

// renderBackupsPage renders the page with status and notice. Unreadable
// settings turn a 200 into 502; the download section still renders.
func (s *CloudServer) renderBackupsPage(w http.ResponseWriter, r *http.Request, status int, notice dashboard.BackupsNotice) {
	s.renderBackupsPageWithForm(w, r, status, notice, dashboard.BackupDestinationForm{})
}

// renderBackupsPageWithForm renders the page and re-renders a refused
// destination save from form, which never carries a credential.
func (s *CloudServer) renderBackupsPageWithForm(w http.ResponseWriter, r *http.Request, status int, notice dashboard.BackupsNotice, form dashboard.BackupDestinationForm) {
	s.renderBackupsPageWithCheck(w, r, status, notice, form, dashboard.BackupDestinationCheck{})
}

// renderBackupsPageWithCheck renders the page with a re-rendered form and
// the result of a destination check; neither carries a credential.
func (s *CloudServer) renderBackupsPageWithCheck(w http.ResponseWriter, r *http.Request, status int, notice dashboard.BackupsNotice, form dashboard.BackupDestinationForm, check dashboard.BackupDestinationCheck) {
	view := s.backupsPageView(r)
	view.DestinationForm = form
	view.DestinationCheck = check
	if form.Submitted {
		// Re-render the S3 form even when another kind is stored.
		view.StorageKind = cloudstore.BackupDestinationKindS3
	}
	s.renderBackupsPageView(w, r, status, view, notice)
}

// renderBackupsPageWithDropbox renders the page with the Dropbox form
// re-rendered from form (never a secret) and the result of a Dropbox check.
func (s *CloudServer) renderBackupsPageWithDropbox(w http.ResponseWriter, r *http.Request, status int, notice dashboard.BackupsNotice, form dashboard.BackupDropboxForm, check dashboard.BackupDestinationCheck) {
	view := s.backupsPageView(r)
	view.StorageKind = cloudstore.BackupDestinationKindDropbox
	view.DropboxForm = form
	view.DestinationCheck = check
	s.renderBackupsPageView(w, r, status, view, notice)
}

// renderBackupsPageView renders view with status and notice.
func (s *CloudServer) renderBackupsPageView(w http.ResponseWriter, r *http.Request, status int, view dashboard.BackupsPageView, notice dashboard.BackupsNotice) {
	// A request's own notice wins over the notice describing the stored
	// destination's kind (backupKindNotice).
	if notice.Kind != "" || view.Notice.Kind == "" {
		view.Notice = notice
	}
	if view.Settings == dashboard.BackupSettingsUnavailable && status == http.StatusOK {
		status = http.StatusBadGateway
	}
	w.Header().Set("Cache-Control", "no-store")
	component := dashboard.AdminBackupsPage(view)
	if isDashboardHTMXRequest(r) {
		renderDashboardAdminComponentStatus(w, r, status, component)
		return
	}
	renderDashboardAdminComponentStatus(w, r, status, s.dashboardAdminLayout(r, "Backups", component))
}

func (s *CloudServer) backupsPageView(r *http.Request) dashboard.BackupsPageView {
	view := dashboard.BackupsPageView{
		CanManage:  s.canManageManagedUsers(r),
		Tables:     cloudstore.BackupTables(),
		Exclusions: cloudstore.BackupExclusions(),
	}
	if kind := r.URL.Query().Get("kind"); dashboard.IsBackupStorageKind(kind) {
		view.StorageKind, view.StorageKindChosen = kind, true
	}
	if s.backupSettings == nil {
		return view
	}
	ctx := r.Context()
	destination, err := s.backupSettings.GetBackupDestination(ctx)
	if err == nil {
		view.Schedule, err = s.backupSettings.GetBackupSchedule(ctx)
	}
	if err == nil {
		view.Runs, err = s.backupSettings.ListBackupRuns(ctx, cloudstore.DefaultBackupRunListLimit)
	}
	if err == nil && destination.Configured {
		view.DestinationTest, err = s.backupSettings.LatestBackupDestinationTest(ctx)
	}
	if err == nil && destination.Configured {
		view.LastRuns, err = s.backupSettings.LatestBackupRunOutcomes(ctx)
	}
	if err != nil {
		log.Printf("[engram-cloud] backups page: read backup settings: %v", err)
		return dashboard.BackupsPageView{CanManage: view.CanManage, Tables: view.Tables, Exclusions: view.Exclusions, Settings: dashboard.BackupSettingsUnavailable}
	}
	view.Destination = destination
	if destination.Configured && destination.Kind != cloudstore.BackupDestinationKindS3 {
		view.Destination = backupKindSummary(destination)
		view.Notice = backupKindNotice(destination)
	}
	view.Now = s.backupClock()
	view.Settings = dashboard.BackupSettingsKeyMissing
	if s.backupKey != nil {
		view.Settings = dashboard.BackupSettingsReady
		if destination.Configured {
			view.NextRun, _ = view.Schedule.NextRun(s.backupClock())
		}
	}
	view.CanRunNow = view.CanManage && view.Settings == dashboard.BackupSettingsReady && destination.Configured && s.backupRunner != nil
	return view
}

func (s *CloudServer) backupClock() time.Time {
	if s.backupNow != nil {
		return s.backupNow()
	}
	return time.Now()
}

// backupSettingsActor gates a settings mutation: managed admin, a wired
// settings store and, when needKey, the backup key. It writes the refusal.
func (s *CloudServer) backupSettingsActor(w http.ResponseWriter, r *http.Request, needKey bool) (cloudauth.Principal, bool) {
	actor, ok := s.requireManagedAdmin(w, r)
	if !ok {
		return cloudauth.Principal{}, false
	}
	if s.backupSettings == nil {
		http.Error(w, "backup settings are not available on this server", http.StatusNotFound)
		return cloudauth.Principal{}, false
	}
	if needKey && s.backupKey == nil {
		s.renderBackupsPage(w, r, http.StatusConflict, dashboard.BackupsNotice{Kind: "danger", Message: "ENGRAM_CLOUD_BACKUP_KEY is not set, so backup destination credentials cannot be stored or used."})
		return cloudauth.Principal{}, false
	}
	return actor, true
}

func backupStoreActor(actor cloudauth.Principal) cloudstore.BackupDestinationActor {
	return cloudstore.BackupDestinationActor{PrincipalID: strings.TrimSpace(actor.ID), Source: string(actor.Source)}
}

// handleDashboardSaveBackupDestination handles POST
// /dashboard/admin/backups/destination. Both credentials are required on
// every save; the store seals them bound to the destination and audits
// backup.destination.update in the same transaction.
func (s *CloudServer) handleDashboardSaveBackupDestination(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, true)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	switch r.PostForm.Get("kind") {
	case "", cloudstore.BackupDestinationKindS3:
	case cloudstore.BackupDestinationKindDropbox:
		s.saveDropboxDestination(w, r, actor)
		return
	default:
		s.renderBackupsPage(w, r, http.StatusBadRequest, dashboard.BackupsNotice{Kind: "danger", Message: "Destination not saved: " + backupStorageKindReason + ".", Destination: true})
		return
	}
	params := backupDestinationFormParams(r, actor)
	err := s.backupSettings.PutBackupDestination(r.Context(), params, s.backupKey)
	switch {
	case err == nil:
		redirectDashboardAdmin(w, r, backupsPageURL+"?notice=destination-saved")
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		// The reasons are fixed strings that never echo the submitted values.
		// The form re-renders the submitted non-secret fields, marks the
		// field the reason is about and leaves both credentials empty.
		reason := backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		form := refusedBackupDestinationForm(r, params, backupDestinationInvalidField(reason), reason)
		s.renderBackupsPageWithForm(w, r, http.StatusBadRequest, dashboard.BackupsNotice{Kind: "danger", Message: "Destination not saved: " + reason + ".", Destination: true}, form)
	default:
		log.Printf("[engram-cloud] save backup destination failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "save backup destination failed", http.StatusInternalServerError)
	}
}

// saveDropboxDestination saves a kind=dropbox form. The app secret and the
// refresh token are required on every save; the store seals them bound to
// the app key and folder and audits backup.destination.update (kind, folder,
// app key hint) in the same transaction. A refusal re-renders the app key
// and the folder only.
func (s *CloudServer) saveDropboxDestination(w http.ResponseWriter, r *http.Request, actor cloudauth.Principal) {
	params := dropboxDestinationFormParams(r, actor)
	err := s.backupSettings.PutDropboxDestination(r.Context(), params, s.backupKey)
	switch {
	case err == nil:
		redirectDashboardAdmin(w, r, backupsPageURL+"?notice=destination-saved")
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		reason := backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		form := refusedDropboxForm(params, backupDropboxInvalidField(reason), reason)
		s.renderBackupsPageWithDropbox(w, r, http.StatusBadRequest, dashboard.BackupsNotice{Kind: "danger", Message: "Destination not saved: " + reason + ".", Destination: true}, form, dashboard.BackupDestinationCheck{})
	default:
		log.Printf("[engram-cloud] save Dropbox backup destination failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "save backup destination failed", http.StatusInternalServerError)
	}
}

// dropboxDestinationFormParams reads a Dropbox destination from the POST
// form (url-encoded body fields only, like backupDestinationFormParams).
func dropboxDestinationFormParams(r *http.Request, actor cloudauth.Principal) cloudstore.PutDropboxDestinationParams {
	return cloudstore.PutDropboxDestinationParams{
		AppKey:       r.PostForm.Get("app_key"),
		FolderPath:   r.PostForm.Get("folder_path"),
		AppSecret:    r.PostForm.Get("app_secret"),
		RefreshToken: r.PostForm.Get("refresh_token"),
		Actor:        backupStoreActor(actor),
	}
}

// refusedDropboxForm is the submitted Dropbox form as the page may
// re-render it: the app key and the folder, the failing field and its
// fixed reason, never the app secret or the refresh token.
func refusedDropboxForm(params cloudstore.PutDropboxDestinationParams, field, reason string) dashboard.BackupDropboxForm {
	return dashboard.BackupDropboxForm{Submitted: true, AppKey: params.AppKey, FolderPath: params.FolderPath, Field: field, Error: reason}
}

// backupDropboxInvalidField maps a Dropbox validation reason to the form
// field it is about; "" when it names none.
func backupDropboxInvalidField(reason string) string {
	for _, field := range []struct{ prefix, name string }{
		{"app key ", "app_key"},
		{"app secret ", "app_secret"},
		{"refresh token ", "refresh_token"},
		{"folder path ", "folder_path"},
	} {
		if strings.HasPrefix(reason, field.prefix) {
			return field.name
		}
	}
	return ""
}

// backupDestinationFormParams reads the destination from the POST form.
// PostForm holds only url-encoded body fields: credentials in the URL query
// string, a multipart body or a JSON body are never read.
func backupDestinationFormParams(r *http.Request, actor cloudauth.Principal) cloudstore.PutBackupDestinationParams {
	return cloudstore.PutBackupDestinationParams{
		Endpoint:        r.PostForm.Get("endpoint"),
		Region:          r.PostForm.Get("region"),
		Bucket:          r.PostForm.Get("bucket"),
		Prefix:          r.PostForm.Get("prefix"),
		AccessKeyID:     r.PostForm.Get("access_key_id"),
		SecretAccessKey: r.PostForm.Get("secret_access_key"),
		Actor:           backupStoreActor(actor),
	}
}

// refusedBackupDestinationForm is the submitted form as the page may
// re-render it: the non-secret fields (the endpoint omitted when it may
// carry userinfo), the failing field and its fixed reason, never a
// credential.
func refusedBackupDestinationForm(r *http.Request, params cloudstore.PutBackupDestinationParams, field, reason string) dashboard.BackupDestinationForm {
	return dashboard.BackupDestinationForm{
		Submitted: true,
		Provider:  r.PostForm.Get("provider"),
		Endpoint:  backupEchoableEndpoint(params.Endpoint),
		Region:    params.Region,
		Bucket:    params.Bucket,
		Prefix:    params.Prefix,
		Field:     field,
		Error:     reason,
	}
}

// backupDestinationInvalidField maps a destination validation reason to the
// form field it is about; "" when it names none.
func backupDestinationInvalidField(reason string) string {
	for _, field := range []struct{ prefix, name string }{
		{"endpoint ", "endpoint"},
		{"region ", "region"},
		{"bucket ", "bucket"},
		{"prefix ", "prefix"},
		{"access key id ", "access_key_id"},
		{"secret access key ", "secret_access_key"},
	} {
		if strings.HasPrefix(reason, field.prefix) {
			return field.name
		}
	}
	return ""
}

// backupEchoableEndpoint is the submitted endpoint as the refused form may
// show it: an endpoint carrying userinfo ("https://key:secret@host") may
// hold a credential, so it is never echoed.
func backupEchoableEndpoint(endpoint string) string {
	if strings.Contains(endpoint, "@") {
		return ""
	}
	return endpoint
}

// handleDashboardTestBackupDestination handles POST
// /dashboard/admin/backups/destination/test: it opens the stored credentials
// and runs a bounded, read-only access check (S3: list at most one key;
// Dropbox: refresh a token and read the folder's metadata). The typed result
// is audited as backup.destination.test and shown after a redirect. A Google
// Drive destination cannot be tested yet.
func (s *CloudServer) handleDashboardTestBackupDestination(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, true)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	dest, err := s.backupSettings.OpenBackupDestination(r.Context(), s.backupKey)
	creds := dest.S3
	var notice, reason string
	var metadata map[string]any
	switch {
	case errors.Is(err, cloudstore.ErrBackupDestinationNotConfigured):
		notice, reason = "test-none", backupReasonNotConfigured
	case errors.Is(err, backupcrypto.ErrKeyMismatch), errors.Is(err, backupcrypto.ErrSealedValueInvalid):
		notice, reason = "test-key", backupReasonKeyMismatch
	case errors.Is(err, cloudstore.ErrBackupDestinationKindMismatch):
		notice, reason = "test-unsupported", backupReasonUnsupportedKind
	case err != nil:
		log.Printf("[engram-cloud] backup destination test failed to read the destination: actor=%q: %v", actor.ID, err)
		http.Error(w, "test backup destination failed", http.StatusInternalServerError)
		return
	case dest.Kind == cloudstore.BackupDestinationKindDropbox:
		var result string
		result, reason = classifyDropboxConnectionTest(s.runDropboxCheck(r.Context(), dest.Dropbox))
		notice = "dropbox-test-" + result
		metadata = dropboxAuditMetadata(dest.Dropbox, result)
	case dest.Kind != cloudstore.BackupDestinationKindS3:
		notice, reason = "test-unsupported", backupReasonUnsupportedKind
	default:
		check := s.backupCheckAccess
		if check == nil {
			check = checkBackupDestinationAccess
		}
		ctx, cancel := context.WithTimeout(r.Context(), backupConnectionTestTimeout)
		notice, reason = classifyBackupConnectionTest(check(ctx, creds))
		cancel()
	}
	if metadata == nil {
		metadata = map[string]any{"endpoint": creds.Endpoint, "bucket": creds.Bucket, "result": strings.TrimPrefix(notice, "test-")}
	}
	event := adminAuditEvent(actor, authAuditActionBackupDestinationTest, "", "", metadata)
	if reason != "" {
		event.Outcome = authAuditOutcomeFailure
		event.ReasonCode = reason
	}
	if err := store.InsertAuthAuditEvent(r.Context(), event); err != nil {
		log.Printf("[engram-cloud] backup destination test audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	redirectDashboardAdmin(w, r, backupsPageURL+"?notice="+notice)
}

// handleDashboardCheckBackupDestination handles POST
// /dashboard/admin/backups/destination/check: the guided setup's "Test
// connection" before saving. It reads the destination from the POST form
// exactly like the save route, validates it with the same rules
// (cloudstore.ValidateBackupDestination) and runs the same bounded,
// read-only access check as the test route, without storing or opening
// anything. The typed result (ok, auth, bucket, network, error or invalid)
// is audited as backup.destination.check and answered in place: an HTML
// fragment with 200 for HTMX, else the page with the form re-rendered (400
// for a validation error). Credentials are never echoed or audited.
func (s *CloudServer) handleDashboardCheckBackupDestination(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, true)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	switch r.PostForm.Get("kind") {
	case "", cloudstore.BackupDestinationKindS3:
	case cloudstore.BackupDestinationKindDropbox:
		s.checkDropboxDestination(w, r, actor, store)
		return
	default:
		s.renderBackupsPage(w, r, http.StatusBadRequest, dashboard.BackupsNotice{Kind: "danger", Message: "Destination not checked: " + backupStorageKindReason + ".", Destination: true})
		return
	}
	params := backupDestinationFormParams(r, actor)
	var result dashboard.BackupDestinationCheck
	var reason string
	var metadata map[string]any
	creds, err := cloudstore.ValidateBackupDestination(params)
	switch {
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		// The submitted endpoint is not audited: it was not validated and may
		// carry userinfo.
		message := backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		result = dashboard.BackupDestinationCheck{Result: "invalid", Field: backupDestinationInvalidField(message), Error: message}
		reason = backupReasonInvalidDestination
		metadata = map[string]any{"result": result.Result}
		if result.Field != "" {
			metadata["field"] = result.Field
		}
	case err != nil:
		log.Printf("[engram-cloud] backup destination check failed to validate: actor=%q: %v", actor.ID, err)
		http.Error(w, "check backup destination failed", http.StatusInternalServerError)
		return
	default:
		check := s.backupCheckAccess
		if check == nil {
			check = checkBackupDestinationAccess
		}
		ctx, cancel := context.WithTimeout(r.Context(), backupConnectionTestTimeout)
		var notice string
		notice, reason = classifyBackupConnectionTest(check(ctx, creds))
		cancel()
		result = dashboard.BackupDestinationCheck{Result: strings.TrimPrefix(notice, "test-")}
		metadata = map[string]any{"endpoint": creds.Endpoint, "bucket": creds.Bucket, "result": result.Result}
	}
	event := adminAuditEvent(actor, authAuditActionBackupDestinationCheck, "", "", metadata)
	if reason != "" {
		event.Outcome = authAuditOutcomeFailure
		event.ReasonCode = reason
	}
	if err := store.InsertAuthAuditEvent(r.Context(), event); err != nil {
		log.Printf("[engram-cloud] backup destination check audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	if isDashboardHTMXRequest(r) {
		// htmx swaps only 2xx answers, so every typed result is a 200.
		w.Header().Set("Cache-Control", "no-store")
		renderDashboardAdminComponentStatus(w, r, http.StatusOK, dashboard.BackupDestinationCheckResult(result))
		return
	}
	status := http.StatusOK
	if result.Result == "invalid" {
		status = http.StatusBadRequest
	}
	form := refusedBackupDestinationForm(r, params, result.Field, result.Error)
	s.renderBackupsPageWithCheck(w, r, status, dashboard.BackupsNotice{}, form, result)
}

// checkDropboxDestination is the check route for a kind=dropbox form: the
// same validation as the save (cloudstore.ValidateDropboxDestination), then
// the bounded Dropbox access check, storing and opening nothing. The typed
// result is audited as backup.destination.check with the kind, folder and
// app key hint, and answered like the S3 check: an HTML fragment for HTMX,
// else the page with the Dropbox form re-rendered (app key and folder only;
// 400 for a validation error).
func (s *CloudServer) checkDropboxDestination(w http.ResponseWriter, r *http.Request, actor cloudauth.Principal, store AdminIdentityStore) {
	params := dropboxDestinationFormParams(r, actor)
	result := dashboard.BackupDestinationCheck{Kind: cloudstore.BackupDestinationKindDropbox}
	var reason string
	var metadata map[string]any
	creds, err := cloudstore.ValidateDropboxDestination(params)
	switch {
	case errors.Is(err, cloudstore.ErrInvalidBackupDestination):
		result.Error = backupValidationReason(err, cloudstore.ErrInvalidBackupDestination)
		result.Result, result.Field = "invalid", backupDropboxInvalidField(result.Error)
		reason = backupReasonInvalidDestination
		metadata = map[string]any{"kind": cloudstore.BackupDestinationKindDropbox, "result": result.Result}
		if result.Field != "" {
			metadata["field"] = result.Field
		}
	case err != nil:
		log.Printf("[engram-cloud] Dropbox backup destination check failed to validate: actor=%q: %v", actor.ID, err)
		http.Error(w, "check backup destination failed", http.StatusInternalServerError)
		return
	default:
		result.Result, reason = classifyDropboxConnectionTest(s.runDropboxCheck(r.Context(), creds))
		metadata = dropboxAuditMetadata(creds, result.Result)
	}
	event := adminAuditEvent(actor, authAuditActionBackupDestinationCheck, "", "", metadata)
	if reason != "" {
		event.Outcome = authAuditOutcomeFailure
		event.ReasonCode = reason
	}
	if err := store.InsertAuthAuditEvent(r.Context(), event); err != nil {
		log.Printf("[engram-cloud] backup destination check audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	if isDashboardHTMXRequest(r) {
		w.Header().Set("Cache-Control", "no-store")
		renderDashboardAdminComponentStatus(w, r, http.StatusOK, dashboard.BackupDestinationCheckResult(result))
		return
	}
	status := http.StatusOK
	if result.Result == "invalid" {
		status = http.StatusBadRequest
	}
	form := refusedDropboxForm(params, result.Field, result.Error)
	s.renderBackupsPageWithDropbox(w, r, status, dashboard.BackupsNotice{}, form, result)
}

// classifyBackupConnectionTest maps a CheckAccess result to a notice and a
// failure reason code ("" for success).
func classifyBackupConnectionTest(err error) (string, string) {
	switch {
	case err == nil:
		return "test-ok", ""
	case errors.Is(err, s3client.ErrAuth):
		return "test-auth", backupReasonAuthFailed
	case errors.Is(err, s3client.ErrBucketNotFound):
		return "test-bucket", backupReasonBucketNotFound
	case errors.Is(err, s3client.ErrNetwork), errors.Is(err, context.DeadlineExceeded):
		return "test-network", backupReasonNetwork
	default:
		return "test-error", backupReasonUnexpectedResponse
	}
}

// handleDashboardRemoveBackupDestination handles POST
// /dashboard/admin/backups/destination/remove. The store audits
// backup.destination.clear in the same transaction. Removing needs no key.
func (s *CloudServer) handleDashboardRemoveBackupDestination(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, false)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	if err := s.backupSettings.ClearBackupDestination(r.Context(), backupStoreActor(actor)); err != nil {
		log.Printf("[engram-cloud] remove backup destination failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "remove backup destination failed", http.StatusInternalServerError)
		return
	}
	redirectDashboardAdmin(w, r, backupsPageURL+"?notice=destination-removed")
}

// handleDashboardSaveBackupSchedule handles POST
// /dashboard/admin/backups/schedule. The store validates the schedule,
// requires a destination to enable it and audits backup.schedule.update in
// the same transaction.
func (s *CloudServer) handleDashboardSaveBackupSchedule(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.backupSettingsActor(w, r, true)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	params := cloudstore.PutBackupScheduleParams{
		Enabled:   r.PostForm.Get("enabled") == "on",
		Weekdays:  parseBackupWeekdays(r.PostForm["weekday"]),
		TimeOfDay: r.PostForm.Get("time"),
		Timezone:  r.PostForm.Get("timezone"),
		Actor:     backupStoreActor(actor),
	}
	err := s.backupSettings.PutBackupSchedule(r.Context(), params)
	switch {
	case err == nil:
		redirectDashboardAdmin(w, r, backupsPageURL+"?notice=schedule-saved")
	case errors.Is(err, cloudstore.ErrInvalidBackupSchedule):
		reason := backupValidationReason(err, cloudstore.ErrInvalidBackupSchedule)
		view := s.backupsPageView(r)
		view.ScheduleForm = dashboard.BackupScheduleForm{Field: backupScheduleInvalidField(reason), Error: reason}
		s.renderBackupsPageView(w, r, http.StatusBadRequest, view, dashboard.BackupsNotice{Kind: "danger", Message: "Schedule not saved: " + reason + "."})
	case errors.Is(err, cloudstore.ErrBackupDestinationNotConfigured):
		s.renderBackupsPage(w, r, http.StatusConflict, dashboard.BackupsNotice{Kind: "danger", Message: "Schedule not saved: Configure a backup destination before enabling the schedule."})
	default:
		log.Printf("[engram-cloud] save backup schedule failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "save backup schedule failed", http.StatusInternalServerError)
	}
}

// backupScheduleInvalidField maps a schedule validation reason to the form
// field it is about; "" when it names none (the weekdays).
func backupScheduleInvalidField(reason string) string {
	switch {
	case strings.HasPrefix(reason, "time zone "):
		return "timezone"
	case strings.HasPrefix(reason, "time "):
		return "time"
	}
	return ""
}

// parseBackupWeekdays maps "mon".."sun" to weekdays. An unknown value maps to
// an out-of-range weekday so the store rejects the whole schedule.
func parseBackupWeekdays(values []string) []time.Weekday {
	days := make([]time.Weekday, 0, len(values))
	for _, value := range values {
		day := time.Weekday(-1)
		for _, candidate := range cloudstore.BackupScheduleWeekdays {
			if strings.EqualFold(strings.TrimSpace(value), cloudstore.BackupWeekdayName(candidate)) {
				day = candidate
			}
		}
		days = append(days, day)
	}
	return days
}

// backupValidationReason strips the sentinel prefix from a validation error,
// leaving the fixed human-readable reason.
func backupValidationReason(err, sentinel error) string {
	return strings.TrimPrefix(err.Error(), sentinel.Error()+": ")
}

// handleDashboardBackupNow handles POST /dashboard/admin/backups/run. A
// backup.run.manual audit row with outcome "started" is committed before the
// runner is asked to start; a refused start is recorded as a failure row.
// The run itself is tracked in the backup run history.
func (s *CloudServer) handleDashboardBackupNow(w http.ResponseWriter, r *http.Request) {
	actor, ok := s.requireManagedAdmin(w, r)
	if !ok {
		return
	}
	if s.backupRunner == nil {
		http.Error(w, "backup runner is not configured", http.StatusNotFound)
		return
	}
	store, ok := s.adminStore(w)
	if !ok {
		return
	}
	if !parseDashboardMutationForm(w, r) {
		return
	}
	started := adminAuditEvent(actor, authAuditActionBackupRunManual, "", "", map[string]any{"trigger": cloudstore.BackupRunTriggerManual})
	started.Outcome = authAuditOutcomeStarted
	if err := store.InsertAuthAuditEvent(r.Context(), started); err != nil {
		log.Printf("[engram-cloud] backup run audit failed: actor=%q: %v", actor.ID, err)
		http.Error(w, "record audit failed", http.StatusInternalServerError)
		return
	}
	runID, err := s.backupRunner.StartManualBackup(r.Context(), strings.TrimSpace(actor.ID))
	if err == nil {
		log.Printf("[engram-cloud] manual backup started: actor=%q run=%d", actor.ID, runID)
		redirectDashboardAdmin(w, r, backupsPageURL+"?notice=run-started")
		return
	}
	notice, reason := "run-failed", backupReasonRunnerError
	switch {
	case errors.Is(err, ErrBackupAlreadyRunning):
		notice, reason = "run-busy", backupReasonAlreadyRunning
	case errors.Is(err, ErrBackupDestinationUnsupported):
		notice, reason = "run-unsupported", backupReasonUnsupportedDestination
	}
	log.Printf("[engram-cloud] manual backup not started: actor=%q: %v", actor.ID, err)
	failed := adminAuditEvent(actor, authAuditActionBackupRunManual, "", "", map[string]any{"trigger": cloudstore.BackupRunTriggerManual})
	failed.Outcome = authAuditOutcomeFailure
	failed.ReasonCode = reason
	if err := store.InsertAuthAuditEvent(context.WithoutCancel(r.Context()), failed); err != nil {
		log.Printf("[engram-cloud] backup run failure audit failed: actor=%q: %v", actor.ID, err)
	}
	redirectDashboardAdmin(w, r, backupsPageURL+"?notice="+notice)
}
