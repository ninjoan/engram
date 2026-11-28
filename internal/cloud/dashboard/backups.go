package dashboard

import (
	"net"
	"net/url"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/a-h/templ"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// BackupSettingsState says whether the external backup settings (destination,
// schedule, run history) can be shown and changed.
type BackupSettingsState int

const (
	// BackupSettingsNotWired means this server has no backup settings store.
	BackupSettingsNotWired BackupSettingsState = iota
	// BackupSettingsKeyMissing means ENGRAM_CLOUD_BACKUP_KEY is not set, so
	// credentials cannot be sealed or opened and no form is rendered.
	BackupSettingsKeyMissing
	// BackupSettingsUnavailable means reading the settings failed.
	BackupSettingsUnavailable
	// BackupSettingsReady means the settings were read and the key is set.
	BackupSettingsReady
)

// BackupsNotice is a one-line outcome shown above the backups page.
type BackupsNotice struct {
	// Kind is "success" or "danger"; an empty Kind shows nothing.
	Kind    string
	Message string
	// Title is an optional short lead shown before Message.
	Title string
	// Destination renders the notice inside the destination frame (for
	// example a connection test result) when that frame is shown.
	Destination bool
}

// BackupDestinationForm is the destination form as the admin submitted it,
// re-rendered after a refused save. It never holds a credential: both key
// fields always render empty.
type BackupDestinationForm struct {
	// Submitted is true when the form re-renders a refused save; otherwise
	// the form is pre-filled from the stored destination.
	Submitted bool
	// Provider is the submitted provider select value; it is only a hint
	// and an unknown value falls back to the provider derived from Endpoint.
	Provider string
	Endpoint string
	Region   string
	Bucket   string
	Prefix   string
	// Field names the form field the error is about (endpoint, region,
	// bucket, prefix, access_key_id or secret_access_key); empty when the
	// error is not about a single field.
	Field string
	// Error is the fixed validation reason; it never echoes a value.
	Error string
}

// BackupScheduleForm marks the schedule field a refused save is about. The
// form re-renders from the stored schedule, so a refused value is never
// echoed.
type BackupScheduleForm struct {
	// Field is "time" or "timezone"; empty when the error is not about one
	// of them.
	Field string
	// Error is the fixed validation reason.
	Error string
}

// BackupDropboxForm is the Dropbox destination form as the admin submitted
// it, re-rendered after a refused save or a check. It never holds a secret:
// the app secret and refresh token fields always render empty.
type BackupDropboxForm struct {
	// Submitted is true when the form re-renders submitted values;
	// otherwise the folder is pre-filled from the stored Dropbox destination
	// or the default folder, and the app key starts empty.
	Submitted  bool
	AppKey     string
	FolderPath string
	// Field names the form field the error is about (app_key, app_secret,
	// refresh_token or folder_path); empty when the error names none.
	Field string
	// Error is the fixed validation reason; it never echoes a value.
	Error string
}

// BackupGDriveForm is the Google Drive destination form as the admin
// submitted it, re-rendered after a refused save or check. It never holds the
// client secret, which always renders empty.
type BackupGDriveForm struct {
	// Submitted is true when the form re-renders submitted values;
	// otherwise the folder is pre-filled from the stored Google Drive
	// destination or the default folder, and the client id starts empty.
	Submitted  bool
	ClientID   string
	FolderName string
	// Field names the form field the error is about (client_id,
	// client_secret or folder); empty when the error names none.
	Field string
	// Error is the fixed validation reason; it never echoes a value.
	Error string
}

// BackupDestinationCheck is the typed result of checking a destination
// before saving it (POST /dashboard/admin/backups/destination/check). It
// never holds a credential or a provider's answer.
type BackupDestinationCheck struct {
	// Kind is the checked destination kind; empty means s3.
	Kind string
	// Result is ok, auth, bucket, network, error or invalid (S3) or ok,
	// ok-folder, auth, folder, network, error or invalid (Dropbox); empty
	// when no check ran.
	Result string
	// Field names the form field a validation error is about; empty when
	// the error is not about a single field.
	Field string
	// Error is the fixed validation reason of an invalid result.
	Error string
}

// BackupsPageView is everything the admin Backups page renders. It is built
// by internal/cloud/cloudserver, which owns the routes, the managed-admin
// policy and the stores; it never holds a credential.
type BackupsPageView struct {
	// CanManage is true for a managed admin session, the only kind that may
	// download a backup or change the backup settings.
	CanManage   bool
	Tables      []string
	Exclusions  []cloudstore.BackupExclusion
	Settings    BackupSettingsState
	Destination cloudstore.BackupDestination
	Schedule    cloudstore.BackupSchedule
	// NextRun is the next scheduled run, zero when none will happen.
	NextRun time.Time
	// CanRunNow renders "Back up now"; it requires a backup runner.
	CanRunNow bool
	Runs      []cloudstore.BackupRun
	Notice    BackupsNotice
	// DestinationForm re-renders a refused destination save.
	DestinationForm BackupDestinationForm
	// ScheduleForm marks the field of a refused schedule save.
	ScheduleForm BackupScheduleForm
	// DestinationTest is the newest connection test since the destination
	// was last saved; zero when it was not tested since.
	DestinationTest cloudstore.BackupDestinationTest
	// LastRuns is the newest successful and the newest failed run.
	LastRuns cloudstore.BackupRunOutcomes
	// DestinationCheck is the result of a connection check of submitted,
	// unsaved fields, shown in the guided setup's last step or in the
	// Dropbox form.
	DestinationCheck BackupDestinationCheck
	// StorageKind is the destination kind whose form renders (s3, dropbox
	// or gdrive); empty or unknown selects the stored destination's kind,
	// else s3.
	StorageKind string
	// StorageKindChosen is true when the admin picked StorageKind
	// explicitly; it opens Change destination on a configured destination.
	StorageKindChosen bool
	// DropboxForm re-renders a refused or checked Dropbox save.
	DropboxForm BackupDropboxForm
	// GDriveForm re-renders a refused Google Drive save or check.
	GDriveForm BackupGDriveForm
	// GDriveRedirectURI is the Google OAuth redirect URI built from
	// ENGRAM_CLOUD_PUBLIC_URL; empty when it is not set, and then no
	// Connect with Google control renders.
	GDriveRedirectURI string
	// Now is the time relative times are measured from; zero uses the
	// wall clock.
	Now time.Time
}

func (v BackupsPageView) settingsFormsVisible() bool {
	return v.CanManage && v.Settings == BackupSettingsReady
}

// destinationFrameVisible is true when the settings state renders the
// destination frame.
func (v BackupsPageView) destinationFrameVisible() bool {
	return v.Settings == BackupSettingsReady || v.Settings == BackupSettingsKeyMissing
}

// pageNotice is the notice shown at the top of the page; a destination
// notice moves into the destination frame when that frame is shown.
func (v BackupsPageView) pageNotice() BackupsNotice {
	if v.Notice.Destination && v.destinationFrameVisible() {
		return BackupsNotice{}
	}
	return v.Notice
}

// destinationNotice is the notice shown inside the destination frame. A
// refused save is explained by the re-rendered form instead.
func (v BackupsPageView) destinationNotice() BackupsNotice {
	if !v.Notice.Destination || !v.destinationFrameVisible() {
		return BackupsNotice{}
	}
	if v.DestinationForm.Submitted && v.settingsFormsVisible() {
		return BackupsNotice{}
	}
	return v.Notice
}

func (v BackupsPageView) scheduleFormVisible() bool {
	return v.settingsFormsVisible() && v.Destination.Configured
}

// scheduleFieldError is the validation reason shown next to a schedule
// field.
func (v BackupsPageView) scheduleFieldError(field string) string {
	if field != "" && v.ScheduleForm.Field == field {
		return v.ScheduleForm.Error
	}
	return ""
}

// scheduleFieldAttrs marks the refused schedule field and links its error
// and hint text with aria-describedby.
func (v BackupsPageView) scheduleFieldAttrs(field, id string, hint bool) templ.Attributes {
	return backupFieldAttrs(v.scheduleFieldError(field) != "", id, hint)
}

func (v BackupsPageView) scheduleStatusLabel() string {
	label, _ := v.scheduleStatus()
	return label
}

func (v BackupsPageView) scheduleStatusVariant() string {
	_, variant := v.scheduleStatus()
	return variant
}

// scheduleStatus describes the effective schedule state in a few words and
// its badge variant.
func (v BackupsPageView) scheduleStatus() (string, string) {
	switch {
	case !v.Schedule.Enabled:
		return "Disabled", "muted"
	case !v.Destination.Configured:
		return "Paused: no destination", "warning"
	case v.Settings == BackupSettingsKeyMissing:
		return "Paused: ENGRAM_CLOUD_BACKUP_KEY not set", "warning"
	default:
		return "Enabled", "success"
	}
}

type backupWeekdayOption struct {
	Value   string
	Label   string
	Checked bool
}

func backupWeekdayOptions(selected []time.Weekday) []backupWeekdayOption {
	options := make([]backupWeekdayOption, 0, len(cloudstore.BackupScheduleWeekdays))
	for _, day := range cloudstore.BackupScheduleWeekdays {
		options = append(options, backupWeekdayOption{
			Value:   cloudstore.BackupWeekdayName(day),
			Label:   day.String()[:3],
			Checked: slices.Contains(selected, day),
		})
	}
	return options
}

func backupWeekdaysLabel(days []time.Weekday) string {
	if len(days) == 0 {
		return "No weekdays"
	}
	label := ""
	for i, day := range days {
		if i > 0 {
			label += ", "
		}
		label += day.String()[:3]
	}
	return label
}

// formatBackupNextRun shows a run in the schedule's zone and in UTC.
func formatBackupNextRun(t time.Time, timezone string) string {
	if t.IsZero() {
		return "-"
	}
	local := t
	if loc, err := time.LoadLocation(timezone); err == nil {
		local = t.In(loc)
	}
	return local.Format("Mon 02 Jan 2006 15:04") + " " + timezone + " (" + t.UTC().Format("15:04") + " UTC)"
}

func formatBackupScheduledFor(t time.Time) string {
	if t.IsZero() {
		return "-"
	}
	return t.UTC().Format(dashboardTimestampLayout) + " UTC"
}

// formatBackupSize renders a byte count with a binary unit.
func formatBackupSize(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	value, suffix := float64(n), "B"
	for _, next := range []string{"KiB", "MiB", "GiB", "TiB"} {
		if value < unit {
			break
		}
		value, suffix = value/unit, next
	}
	return strconv.FormatFloat(value, 'f', 1, 64) + " " + suffix
}

// backupDestinationRegionValue pre-fills the region, "auto" for R2.
func backupDestinationRegionValue(d cloudstore.BackupDestination) string {
	if d.Region == "" {
		return "auto"
	}
	return d.Region
}

func backupRunSizeLabel(run cloudstore.BackupRun) string {
	if run.Status != cloudstore.BackupRunStatusSuccess {
		return "-"
	}
	return formatBackupSize(run.SizeBytes)
}

func backupRunStatusVariant(status string) string {
	switch status {
	case cloudstore.BackupRunStatusSuccess:
		return "success"
	case cloudstore.BackupRunStatusFailure:
		return "danger"
	default:
		return "warning"
	}
}

// backupAlertClass styles a notice shown inside the destination frame.
func backupAlertClass(kind string) string {
	if kind == "danger" {
		return "alert alert-danger"
	}
	return "alert alert-success"
}

func backupNoticeClass(kind string) string {
	if kind == "danger" {
		return "data-frame policy-note danger-note"
	}
	return "data-frame policy-note success-note"
}

// backupProvider is one option of the destination form's provider select.
// The provider is only a hint for the endpoint format: it is never stored,
// and the configured destination's provider is derived from its endpoint
// host.
type backupProvider struct {
	ID string
	// Name labels the option; Summary names a configured destination.
	Name    string
	Summary string
	// Pattern is the endpoint host pattern shown in the provider's hint.
	Pattern             string
	EndpointPlaceholder string
	RegionPlaceholder   string
}

var backupProviders = []backupProvider{
	{ID: "r2", Name: "Cloudflare R2", Summary: "Cloudflare R2", Pattern: "<account-id>.r2.cloudflarestorage.com", EndpointPlaceholder: "https://<account-id>.r2.cloudflarestorage.com", RegionPlaceholder: "auto"},
	{ID: "aws", Name: "Amazon S3", Summary: "Amazon S3", Pattern: "s3.<region>.amazonaws.com", EndpointPlaceholder: "https://s3.<region>.amazonaws.com", RegionPlaceholder: "us-east-1"},
	{ID: "b2", Name: "Backblaze B2", Summary: "Backblaze B2", Pattern: "s3.<region>.backblazeb2.com", EndpointPlaceholder: "https://s3.<region>.backblazeb2.com", RegionPlaceholder: "us-west-004"},
	{ID: "wasabi", Name: "Wasabi", Summary: "Wasabi", Pattern: "s3.<region>.wasabisys.com", EndpointPlaceholder: "https://s3.<region>.wasabisys.com", RegionPlaceholder: "eu-central-1"},
	{ID: "do", Name: "DigitalOcean Spaces", Summary: "DigitalOcean Spaces", Pattern: "<region>.digitaloceanspaces.com", EndpointPlaceholder: "https://<region>.digitaloceanspaces.com", RegionPlaceholder: "nyc3"},
	{ID: "minio", Name: "MinIO / self-hosted", Summary: "MinIO / self-hosted", Pattern: "your server's https URL", EndpointPlaceholder: "https://minio.example.com:9000", RegionPlaceholder: "us-east-1"},
	{ID: "other", Name: "Other S3-compatible", Summary: "S3-compatible", Pattern: "any SigV4 endpoint over https", EndpointPlaceholder: "https://s3.example.com", RegionPlaceholder: "auto"},
}

// backupRegionSuggestions are the example regions the provider guides name;
// the region field offers them without restricting the value.
var backupRegionSuggestions = []string{"auto", "us-east-1", "us-west-004", "eu-central-1", "nyc3"}

func lookupBackupProvider(id string) (backupProvider, bool) {
	for _, p := range backupProviders {
		if p.ID == id {
			return p, true
		}
	}
	return backupProvider{}, false
}

// backupProviderForEndpoint derives the provider from an endpoint host:
// known provider domains map to their provider, loopback hosts and hosts named
// like MinIO to "minio", anything else to "other". An endpoint without a
// host has no provider.
func backupProviderForEndpoint(endpoint string) string {
	parsed, err := url.Parse(strings.TrimSpace(endpoint))
	if err != nil || parsed.Hostname() == "" {
		return ""
	}
	host := strings.ToLower(strings.TrimSuffix(parsed.Hostname(), "."))
	within := func(domain string) bool { return host == domain || strings.HasSuffix(host, "."+domain) }
	switch {
	case within("r2.cloudflarestorage.com"):
		return "r2"
	case within("amazonaws.com"):
		return "aws"
	case within("backblazeb2.com"):
		return "b2"
	case within("wasabisys.com"):
		return "wasabi"
	case within("digitaloceanspaces.com"):
		return "do"
	}
	if host == "localhost" || strings.Contains(host, "minio") {
		return "minio"
	}
	if ip := net.ParseIP(host); ip != nil && ip.IsLoopback() {
		return "minio"
	}
	return "other"
}

// selectedBackupProvider is the provider the form names: the submitted hint
// when it is a known provider, else the provider of the endpoint in the form.
func (v BackupsPageView) selectedBackupProvider() string {
	if v.DestinationForm.Submitted {
		if _, ok := lookupBackupProvider(v.DestinationForm.Provider); ok {
			return v.DestinationForm.Provider
		}
	}
	return backupProviderForEndpoint(v.destinationFormValue("endpoint"))
}

// configuredBackupProvider describes the stored destination by its host.
func (v BackupsPageView) configuredBackupProvider() backupProvider {
	p, ok := lookupBackupProvider(backupProviderForEndpoint(v.Destination.Endpoint))
	if !ok {
		p, _ = lookupBackupProvider("other")
	}
	return p
}

// pickedBackupProvider is the option the provider select shows, and the one
// whose hint and placeholders render: the selected provider, or Cloudflare
// R2 (the first option) when the form names none.
func (v BackupsPageView) pickedBackupProvider() backupProvider {
	p, ok := lookupBackupProvider(v.selectedBackupProvider())
	if !ok {
		p, _ = lookupBackupProvider("r2")
	}
	return p
}

// destinationFormValue is the value a non-secret form field renders: the
// submitted value after a refused save, else the stored destination. The
// credential fields have no value here and always render empty.
func (v BackupsPageView) destinationFormValue(field string) string {
	form := v.DestinationForm
	if form.Submitted {
		switch field {
		case "endpoint":
			return form.Endpoint
		case "region":
			return form.Region
		case "bucket":
			return form.Bucket
		case "prefix":
			return form.Prefix
		}
		return ""
	}
	switch field {
	case "endpoint":
		return v.Destination.Endpoint
	case "region":
		return backupDestinationRegionValue(v.Destination)
	case "bucket":
		return v.Destination.Bucket
	case "prefix":
		return v.Destination.Prefix
	}
	return ""
}

// destinationFieldError is the validation reason shown next to field.
func (v BackupsPageView) destinationFieldError(field string) string {
	if v.DestinationForm.Submitted && v.DestinationForm.Field == field {
		return v.DestinationForm.Error
	}
	return ""
}

// destinationFieldAttrs marks the failing field and links its hint and
// error text with aria-describedby.
func (v BackupsPageView) destinationFieldAttrs(field, id string, hint bool) templ.Attributes {
	return backupFieldAttrs(v.destinationFieldError(field) != "", id, hint)
}

// backupFieldAttrs marks an invalid field and links its error (id-error) and
// hint (id-hint) text with aria-describedby.
func backupFieldAttrs(invalid bool, id string, hint bool) templ.Attributes {
	var describedBy []string
	attrs := templ.Attributes{}
	if invalid {
		attrs["aria-invalid"] = "true"
		describedBy = append(describedBy, id+"-error")
	}
	if hint {
		describedBy = append(describedBy, id+"-hint")
	}
	if len(describedBy) > 0 {
		attrs["aria-describedby"] = strings.Join(describedBy, " ")
	}
	return attrs
}

// destinationFormOpen opens the collapsed form of a configured destination
// when it re-renders a refused save or check, or when the admin chose a
// storage kind.
func (v BackupsPageView) destinationFormOpen() bool {
	return v.DestinationForm.Submitted || v.DropboxForm.Submitted || v.GDriveForm.Submitted || v.StorageKindChosen
}

// backupStorageOption is one option of the storage select.
type backupStorageOption struct {
	Kind, Name string
}

var backupStorageOptions = []backupStorageOption{
	{Kind: cloudstore.BackupDestinationKindS3, Name: "S3-compatible"},
	{Kind: cloudstore.BackupDestinationKindDropbox, Name: "Dropbox"},
	{Kind: cloudstore.BackupDestinationKindGDrive, Name: "Google Drive"},
}

// backupStorageURL is the page with kind's form, scrolled to the
// destination frame.
func backupStorageURL(kind string) string {
	return "/dashboard/admin/backups?kind=" + url.QueryEscape(kind) + "#backup-destination-title"
}

// IsBackupStorageKind reports whether kind is an option of the storage
// choice.
func IsBackupStorageKind(kind string) bool {
	for _, o := range backupStorageOptions {
		if o.Kind == kind {
			return true
		}
	}
	return false
}

// storageKind is the kind whose form renders: the chosen kind, else the
// stored destination's kind, else s3.
func (v BackupsPageView) storageKind() string {
	if IsBackupStorageKind(v.StorageKind) {
		return v.StorageKind
	}
	if v.Destination.Configured && IsBackupStorageKind(v.Destination.Kind) {
		return v.Destination.Kind
	}
	return cloudstore.BackupDestinationKindS3
}

// isDropboxDestination is true for a stored Dropbox destination, which the
// status card describes by its folder and masked app key.
func (v BackupsPageView) isDropboxDestination() bool {
	return v.Destination.Configured && v.Destination.Kind == cloudstore.BackupDestinationKindDropbox
}

// dropboxFormValue is the value a non-secret Dropbox field renders: the
// submitted value, else the stored folder (the app key starts empty), else
// the default folder. The secret fields always render empty.
func (v BackupsPageView) dropboxFormValue(field string) string {
	form := v.DropboxForm
	switch {
	case form.Submitted && field == "app_key":
		return form.AppKey
	case form.Submitted && field == "folder_path":
		return form.FolderPath
	case field == "folder_path" && v.isDropboxDestination():
		return v.Destination.Dropbox.FolderPath
	case field == "folder_path":
		return cloudstore.DefaultDropboxFolderPath
	}
	return ""
}

func (v BackupsPageView) dropboxFieldError(field string) string {
	if v.DropboxForm.Submitted && v.DropboxForm.Field == field {
		return v.DropboxForm.Error
	}
	return ""
}

func (v BackupsPageView) dropboxFieldAttrs(field, id string, hint bool) templ.Attributes {
	return backupFieldAttrs(v.dropboxFieldError(field) != "", id, hint)
}

// dropboxSaveRefused is true when the Dropbox form re-renders a refused
// save; a re-render after a check shows the check result instead.
func (v BackupsPageView) dropboxSaveRefused() bool {
	return v.DropboxForm.Submitted && v.DestinationCheck.Result == ""
}

// dropboxErrorUnplaced is the reason no Dropbox field shows.
func (v BackupsPageView) dropboxErrorUnplaced() string {
	switch v.DropboxForm.Field {
	case "app_key", "app_secret", "refresh_token", "folder_path":
		return ""
	}
	return v.DropboxForm.Error
}

// dropboxCheckVisible is true when the Dropbox form shows a check result.
func (v BackupsPageView) dropboxCheckVisible() bool {
	return v.DestinationCheck.Kind == cloudstore.BackupDestinationKindDropbox && v.DestinationCheck.Result != ""
}

// backupDropboxFolderPrefix renders a Dropbox folder as the start of a file
// path: "/Engram backups/", or "/" for the root.
func backupDropboxFolderPrefix(folder string) string {
	return strings.TrimRight(strings.TrimSpace(folder), "/") + "/"
}

// isGDriveDestination is true for a stored Google Drive destination, which
// the status card describes by its folder, masked client id and
// authorization.
func (v BackupsPageView) isGDriveDestination() bool {
	return v.Destination.Configured && v.Destination.Kind == cloudstore.BackupDestinationKindGDrive
}

// gdrivePending is true for a stored Google Drive destination whose
// Connect with Google authorization has not completed.
func (v BackupsPageView) gdrivePending() bool {
	return v.isGDriveDestination() && !v.Destination.GDrive.Authorized
}

// gdriveConnectVisible renders Connect with Google: a managed admin with the
// backup key, a stored Google Drive destination and ENGRAM_CLOUD_PUBLIC_URL.
func (v BackupsPageView) gdriveConnectVisible() bool {
	return v.settingsFormsVisible() && v.isGDriveDestination() && v.GDriveRedirectURI != ""
}

// gdriveFormValue is the value a non-secret Google Drive field renders: the
// submitted value, else the stored folder (the client id starts empty),
// else the default folder. The client secret always renders empty.
func (v BackupsPageView) gdriveFormValue(field string) string {
	form := v.GDriveForm
	switch {
	case form.Submitted && field == "client_id":
		return form.ClientID
	case form.Submitted && field == "folder":
		return form.FolderName
	case field == "folder" && v.isGDriveDestination():
		return v.Destination.GDrive.FolderName
	case field == "folder":
		return cloudstore.DefaultGDriveFolderName
	}
	return ""
}

func (v BackupsPageView) gdriveFieldError(field string) string {
	if v.GDriveForm.Submitted && v.GDriveForm.Field == field {
		return v.GDriveForm.Error
	}
	return ""
}

func (v BackupsPageView) gdriveFieldAttrs(field, id string, hint bool) templ.Attributes {
	return backupFieldAttrs(v.gdriveFieldError(field) != "", id, hint)
}

// gdriveSaveRefused is true when the Google Drive form re-renders a refused
// save.
func (v BackupsPageView) gdriveSaveRefused() bool {
	return v.GDriveForm.Submitted && v.GDriveForm.Error != ""
}

// gdriveErrorUnplaced is the reason no Google Drive field shows.
func (v BackupsPageView) gdriveErrorUnplaced() string {
	switch v.GDriveForm.Field {
	case "client_id", "client_secret", "folder":
		return ""
	}
	return v.GDriveForm.Error
}

// backupGDriveFolderPrefix renders a Google Drive folder name as the start
// of a file path.
func backupGDriveFolderPrefix(folder string) string {
	return strings.TrimSpace(folder) + "/"
}

// backupDropboxAuthorizeURL is the authorization URL pattern of the
// offline (refresh token) code flow; APP_KEY is replaced by the admin.
const backupDropboxAuthorizeURL = "https://www.dropbox.com/oauth2/authorize?client_id=APP_KEY&response_type=code&token_access_type=offline"

// backupDropboxTokenExchange trades the authorization code for a refresh
// token at the Dropbox token endpoint.
const backupDropboxTokenExchange = `curl https://api.dropboxapi.com/oauth2/token \
  -d code=AUTHORIZATION_CODE \
  -d grant_type=authorization_code \
  -u APP_KEY:APP_SECRET`

// setupReadyNote says what to have at hand for the chosen storage kind.
func (v BackupsPageView) setupReadyNote() string {
	switch v.storageKind() {
	case cloudstore.BackupDestinationKindDropbox:
		return "have your Dropbox app key, app secret and refresh token ready."
	case cloudstore.BackupDestinationKindGDrive:
		return "have your Google OAuth client id and client secret ready; Connect with Google follows the save."
	}
	return "have your bucket name and an access key pair ready."
}

// untestedNote is the status line of a destination not tested since it was
// saved.
func (v BackupsPageView) untestedNote() string {
	if v.isGDriveDestination() {
		return "Not tested since it was connected; the next backup is the first check that the authorization reaches the Google Drive folder."
	}
	if v.isDropboxDestination() {
		return "Not tested since it was saved; the next backup is the first check that the saved credentials reach the Dropbox folder."
	}
	return "Not tested since it was saved; the next backup is the first check that the saved keys reach the bucket."
}

// testedNote ends the status line of a passed test.
func (v BackupsPageView) testedNote() string {
	if v.isGDriveDestination() {
		return " · Google Drive accepted the saved authorization."
	}
	if v.isDropboxDestination() {
		return " · Dropbox accepted the saved credentials."
	}
	return " · the bucket was listed with the saved keys."
}

// destinationErrorUnplaced is the validation reason that no single field
// shows, so the alert carries it.
func (v BackupsPageView) destinationErrorUnplaced() string {
	switch v.DestinationForm.Field {
	case "endpoint", "region", "bucket", "prefix", "access_key_id", "secret_access_key":
		return ""
	}
	return v.DestinationForm.Error
}

// backupObjectNamePattern is the object name of each run, as built by
// s3client.BackupRunObjectKey.
const backupObjectNamePattern = "engram-cloud-backup-<yyyymmddThhmmssZ>-run<id>.tar.gz"

// backupDestinationStatus is the status pill of a configured destination.
// Class selects the pill's color and shape, so it never relies on color
// alone; Title and Detail explain a failing test.
type backupDestinationStatus struct {
	Class  string
	Label  string
	Title  string
	Detail string
}

// backupTestFailures maps a backup.destination.test reason code to a short
// title and the next step. The texts are fixed; nothing from the provider's
// answer is shown.
var backupTestFailures = map[string]backupDestinationStatus{
	"auth_failed":         {Title: "Keys rejected.", Detail: "The provider refused the access key or its permissions. Save the destination with a key pair that can list and write objects in this bucket."},
	"bucket_not_found":    {Title: "Bucket not found.", Detail: "The bucket does not exist at this endpoint. Check the bucket name and the endpoint (for Cloudflare R2, the account id)."},
	"network":             {Title: "Endpoint unreachable.", Detail: "Network error or no answer within 15 s. Check DNS and the firewall from this server, then test again."},
	"key_mismatch":        {Title: "Saved keys cannot be opened.", Detail: "ENGRAM_CLOUD_BACKUP_KEY changed since they were saved. Save the destination again with both keys."},
	"unexpected_response": {Title: "Unexpected response.", Detail: "The destination answered in a way Engram does not recognize. Check the endpoint and the region."},
}

// backupDropboxTestFailures are the Dropbox texts of backupTestFailures.
var backupDropboxTestFailures = map[string]backupDestinationStatus{
	"auth_failed":         {Title: "Credentials rejected.", Detail: "Dropbox refused the app key, app secret or refresh token. Save the destination again with a refresh token issued for this app (token_access_type=offline)."},
	"folder_conflict":     {Title: "Folder path is a file.", Detail: "A file already exists at the folder path in Dropbox. Save the destination with another folder."},
	"network":             {Title: "Dropbox unreachable.", Detail: "Network error or no answer within 15 s. Check DNS and the firewall from this server, then test again."},
	"key_mismatch":        {Title: "Saved credentials cannot be opened.", Detail: "ENGRAM_CLOUD_BACKUP_KEY changed since they were saved. Save the destination again with the app secret and refresh token."},
	"unexpected_response": {Title: "Unexpected response.", Detail: "Dropbox answered in a way Engram does not recognize. Test again later."},
}

// backupGDriveTestFailures are the Google Drive texts of backupTestFailures.
var backupGDriveTestFailures = map[string]backupDestinationStatus{
	"auth_failed":         {Title: "Authorization rejected.", Detail: "Google refused the saved authorization: it was revoked, it expired (apps left in Testing lose it after 7 days) or it is not limited to drive.file. Press Reconnect with Google."},
	"network":             {Title: "Google Drive unreachable.", Detail: "Network error or no answer within 15 s. Check DNS and the firewall from this server, then test again."},
	"key_mismatch":        {Title: "Saved settings cannot be opened.", Detail: "ENGRAM_CLOUD_BACKUP_KEY changed since they were saved. Save the Google Drive settings again and connect."},
	"unexpected_response": {Title: "Unexpected response.", Detail: "Google Drive answered in a way Engram does not recognize. Test again later."},
}

// destinationStatus is Locked without ENGRAM_CLOUD_BACKUP_KEY, Not
// connected for a Google Drive destination awaiting its authorization, Not
// tested when no test was recorded since the last save, else Connected or
// Failing from the newest test.
func (v BackupsPageView) destinationStatus() backupDestinationStatus {
	switch {
	case v.Settings == BackupSettingsKeyMissing:
		return backupDestinationStatus{Class: "is-locked", Label: "Locked"}
	case v.gdrivePending():
		return backupDestinationStatus{Class: "is-untested", Label: "Not connected"}
	case !v.DestinationTest.Tested():
		return backupDestinationStatus{Class: "is-untested", Label: "Not tested"}
	case v.DestinationTest.Succeeded:
		return backupDestinationStatus{Class: "is-connected", Label: "Connected"}
	}
	failures := backupTestFailures
	switch {
	case v.isDropboxDestination():
		failures = backupDropboxTestFailures
	case v.isGDriveDestination():
		failures = backupGDriveTestFailures
	}
	status, ok := failures[v.DestinationTest.ReasonCode]
	if !ok {
		status = backupDestinationStatus{Title: "Connection test failed.", Detail: "Check the destination and test again."}
	}
	status.Class, status.Label = "is-failing", "Failing"
	return status
}

func (v BackupsPageView) now() time.Time {
	if v.Now.IsZero() {
		return time.Now()
	}
	return v.Now
}

// lastFailureVisible shows the newest failed run when no run succeeded
// after it.
func (v BackupsPageView) lastFailureVisible() bool {
	failure, success := v.LastRuns.LastFailure, v.LastRuns.LastSuccess
	return failure.ID != 0 && (success.ID == 0 || failure.FinishedAt.After(success.FinishedAt))
}

// backupRelativeTime says how long ago t was, in whole minutes, hours or
// days; a time in the future (clock skew) reads as "just now".
func backupRelativeTime(t, now time.Time) string {
	d := now.Sub(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return strconv.Itoa(int(d/time.Minute)) + " min ago"
	case d < 24*time.Hour:
		return strconv.Itoa(int(d/time.Hour)) + " h ago"
	}
	if days := int(d / (24 * time.Hour)); days > 1 {
		return strconv.Itoa(days) + " days ago"
	}
	return "1 day ago"
}

// backupUTCLabel is the absolute time shown next to a relative one.
func backupUTCLabel(t time.Time) string {
	return "(" + t.UTC().Format("2006-01-02 15:04") + " UTC)"
}

func backupTimeAttr(t time.Time) string {
	return t.UTC().Format(time.RFC3339)
}

// backupPathPrefix renders a key prefix the way object keys are built:
// non-empty segments joined by "/", with a trailing "/".
func backupPathPrefix(prefix string) string {
	var segments []string
	for _, s := range strings.Split(strings.TrimSpace(prefix), "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	if len(segments) == 0 {
		return ""
	}
	return strings.Join(segments, "/") + "/"
}

// backupPathBucket is the bucket shown in the object path preview.
func backupPathBucket(bucket string) string {
	if strings.TrimSpace(bucket) == "" {
		return "<bucket>"
	}
	return strings.TrimSpace(bucket)
}

// wizardVisible renders the guided setup: only for the first-time state, a
// managed admin with the backup key set and no destination. A configured
// destination keeps the status card and the grouped form behind "Change
// destination".
func (v BackupsPageView) wizardVisible() bool {
	return v.settingsFormsVisible() && !v.Destination.Configured
}

// destinationSaveRefused is true when the form re-renders a refused save; a
// re-render after a check shows the check result instead.
func (v BackupsPageView) destinationSaveRefused() bool {
	return v.DestinationForm.Submitted && v.DestinationCheck.Result == ""
}

// backupWizardStepForField is the guided setup step that holds field.
func backupWizardStepForField(field string) string {
	switch field {
	case "endpoint", "region", "bucket", "prefix":
		return "2"
	case "access_key_id", "secret_access_key":
		return "3"
	}
	return ""
}

// wizardStartStep is the step the script opens first: the step of the field
// a refused save or check is about, the last step after a finished check,
// else the first.
func (v BackupsPageView) wizardStartStep() string {
	if step := backupWizardStepForField(v.DestinationForm.Field); step != "" && v.DestinationForm.Submitted {
		return step
	}
	if v.DestinationCheck.Result != "" {
		if step := backupWizardStepForField(v.DestinationCheck.Field); step != "" {
			return step
		}
		return "4"
	}
	return "1"
}

// backupWizardStep is one step of the guided setup.
type backupWizardStep struct {
	Number string
	Name   string
	// Sub is the line under the step name until the script fills in what
	// was chosen.
	Sub string
}

var backupWizardSteps = []backupWizardStep{
	{Number: "1", Name: "Provider", Sub: "where archives go"},
	{Number: "2", Name: "Connection", Sub: "endpoint, bucket"},
	{Number: "3", Name: "Credentials", Sub: "both keys"},
	{Number: "4", Name: "Test & save", Sub: "check, then save"},
}

// wizardSummaryValue is a non-secret value for the setup summary, or "" when
// the field is empty.
func (v BackupsPageView) wizardSummaryValue(field string) string {
	return strings.TrimSpace(v.destinationFormValue(field))
}

// backupCheckMessage is the fixed text of a check result. Step is the
// guided setup step to go back to, with its link label.
type backupCheckMessage struct {
	Kind, Title, Detail, Step, StepLabel string
}

var backupCheckMessages = map[string]backupCheckMessage{
	"ok":      {Kind: "success", Title: "Connected.", Detail: "Engram listed the bucket with these keys."},
	"auth":    {Kind: "danger", Title: "Keys rejected.", Detail: "The provider refused this key pair or its permissions. Paste a key that can list and write objects in this bucket.", Step: "3", StepLabel: "Back to credentials"},
	"bucket":  {Kind: "danger", Title: "Bucket not found.", Detail: "The bucket does not exist at this endpoint. Check the bucket name and the endpoint (for Cloudflare R2, the account id).", Step: "2", StepLabel: "Back to connection"},
	"network": {Kind: "danger", Title: "Endpoint unreachable.", Detail: "Network error or no answer within 15 s. Check the endpoint, DNS and the firewall from this server, then test again.", Step: "2", StepLabel: "Back to connection"},
	"error":   {Kind: "danger", Title: "Unexpected response.", Detail: "The destination answered in a way Engram does not recognize. Check the endpoint and the region.", Step: "2", StepLabel: "Back to connection"},
	"invalid": {Kind: "danger", Title: "Check the destination."},
}

// backupDropboxCheckMessages are the texts of a Dropbox check; they link to
// no wizard step.
var backupDropboxCheckMessages = map[string]backupCheckMessage{
	"ok":        {Kind: "success", Title: "Connected.", Detail: "Dropbox accepted these credentials and the folder exists."},
	"ok-folder": {Kind: "success", Title: "Connected — folder will be created on first upload.", Detail: "Dropbox accepted these credentials; the folder does not exist yet."},
	"auth":      {Kind: "danger", Title: "Credentials rejected.", Detail: "Dropbox refused the app key, app secret or refresh token. The refresh token must come from this app's offline authorization (token_access_type=offline)."},
	"folder":    {Kind: "danger", Title: "Folder path is a file.", Detail: "A file already exists at this path in Dropbox. Choose another folder."},
	"network":   {Kind: "danger", Title: "Dropbox unreachable.", Detail: "Network error or no answer within 15 s. Check DNS and the firewall from this server, then test again."},
	"error":     {Kind: "danger", Title: "Unexpected response.", Detail: "Dropbox answered in a way Engram does not recognize. Test again later."},
	"invalid":   {Kind: "danger", Title: "Check the destination."},
}

// message is the fixed text of the check result; an unknown result has no
// title and renders nothing.
func (c BackupDestinationCheck) message() backupCheckMessage {
	if c.Kind == cloudstore.BackupDestinationKindDropbox {
		m, ok := backupDropboxCheckMessages[c.Result]
		if ok && c.Result == "invalid" {
			m.Detail = c.Error + "."
		}
		return m
	}
	m, ok := backupCheckMessages[c.Result]
	if !ok {
		return backupCheckMessage{}
	}
	if c.Result == "invalid" {
		m.Detail = c.Error + "."
		m.Step = backupWizardStepForField(c.Field)
		switch m.Step {
		case "2":
			m.StepLabel = "Back to connection"
		case "3":
			m.StepLabel = "Back to credentials"
		}
	}
	return m
}

// backupContentGroup is one plain-language line of what a backup contains
// or never contains. Hidden groups are mapped (so every table and exclusion
// has exactly one group) but only listed under the technical details.
type backupContentGroup struct {
	ID     string
	Label  string
	Detail string
	// EnvVars names server secrets that live in the environment, never in a
	// table; a group with EnvVars is shown even without a mapped member.
	EnvVars []string
	Hidden  bool
}

var backupIncludedGroups = []backupContentGroup{
	{ID: "memories", Label: "Memories and sessions of every project"},
	{ID: "access", Label: "Users, permissions and project pauses"},
	{ID: "audit", Label: "Audit logs"},
}

var backupExcludedGroups = []backupContentGroup{
	{ID: "credentials", Label: "Tokens and passwords", Detail: "managed tokens are re-issued after a restore"},
	{ID: "backup-settings", Label: "Backup destination, schedule and run history", Detail: "configure them again after a restore"},
	{ID: "secrets", Label: "Server secrets", EnvVars: []string{"ENGRAM_CLOUD_TOKEN_PEPPER", "ENGRAM_JWT_SECRET", "ENGRAM_CLOUD_BACKUP_KEY"}},
	// Legacy columns and the instance-bound receipt audit mean nothing to an
	// admin; they stay in the technical details only.
	{ID: "internal", Label: "Internal bookkeeping", Hidden: true},
}

// backupTableGroups maps every table of cloudstore.BackupTables() to its
// included group; backups_contents_test.go fails when a table is missing.
var backupTableGroups = map[string]string{
	"cloud_chunks":                     "memories",
	"cloud_project_sessions":           "memories",
	"cloud_mutations":                  "memories",
	"cloud_session_authority":          "memories",
	"cloud_prompt_pair_claims":         "memories",
	"cloud_prompt_source_attestations": "memories",
	"cloud_users":                      "access",
	"cloud_principals":                 "access",
	"cloud_human_users":                "access",
	"cloud_project_grants":             "access",
	"cloud_project_controls":           "access",
	"cloud_auth_audit_log":             "audit",
	"cloud_sync_audit_log":             "audit",
}

// backupExclusionGroups maps every cloudstore.BackupExclusions() entry, by
// backupExclusionKey, to its never-included group.
var backupExclusionGroups = map[string]string{
	"cloud_principal_tokens":                                     "credentials",
	"cloud_users.password_hash":                                  "credentials",
	"cloud_backup_destinations":                                  "backup-settings",
	"cloud_backup_schedule":                                      "backup-settings",
	"cloud_backup_runs":                                          "backup-settings",
	"cloud_backup_oauth_states":                                  "backup-settings",
	"cloud_chunks.user_id,imported_at,sessions,memories,prompts": "internal",
	"cloud_mutations.user_id":                                    "internal",
	"receipt_audit.*":                                            "internal",
}

// backupExclusionKey identifies an exclusion as table or table.column.
func backupExclusionKey(e cloudstore.BackupExclusion) string {
	if e.Column == "" {
		return e.Table
	}
	return e.Table + "." + e.Column
}

// backupContentsIncluded lists the included groups that hold at least one
// table of the page's list, in a fixed order.
func (v BackupsPageView) backupContentsIncluded() []backupContentGroup {
	present := map[string]bool{}
	for _, table := range v.Tables {
		present[backupTableGroups[table]] = true
	}
	return backupVisibleGroups(backupIncludedGroups, present)
}

// backupContentsExcluded lists the never-included groups that hold at
// least one exclusion of the page's list, plus the server secrets.
func (v BackupsPageView) backupContentsExcluded() []backupContentGroup {
	present := map[string]bool{}
	for _, e := range v.Exclusions {
		present[backupExclusionGroups[backupExclusionKey(e)]] = true
	}
	return backupVisibleGroups(backupExcludedGroups, present)
}

func backupVisibleGroups(groups []backupContentGroup, present map[string]bool) []backupContentGroup {
	var out []backupContentGroup
	for _, g := range groups {
		if !g.Hidden && (present[g.ID] || len(g.EnvVars) > 0) {
			out = append(out, g)
		}
	}
	return out
}

// backupTechnicalDetailsLabel is the summary of the collapsed table lists,
// with counts computed from them.
func (v BackupsPageView) backupTechnicalDetailsLabel() string {
	return "Technical details (" + backupCount(len(v.Tables), "table", "tables") + " included, " + backupCount(len(v.Exclusions), "exclusion", "exclusions") + ")"
}

func backupCount(n int, singular, plural string) string {
	if n == 1 {
		return "1 " + singular
	}
	return strconv.Itoa(n) + " " + plural
}

// role announces a passed check politely and a failed one as an alert.
func (m backupCheckMessage) role() string {
	if m.Kind == "success" {
		return "status"
	}
	return "alert"
}

// backupContentsDetail is why a never-included line is left out, after a
// dash; empty without a reason.
func backupContentsDetail(detail string) string {
	if detail == "" {
		return ""
	}
	return " — " + detail
}

// backupEnvVarLead is the text before the i-th environment variable of a
// never-included line.
func backupEnvVarLead(i int) string {
	if i == 0 {
		return " (environment variables such as "
	}
	return ", "
}

// backupEnvVarTail closes the list after its last environment variable.
func backupEnvVarTail(i, n int) string {
	if i == n-1 {
		return ")"
	}
	return ""
}
