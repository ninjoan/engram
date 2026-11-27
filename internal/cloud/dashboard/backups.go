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
	// Provider is the submitted provider tile; it is only a hint and an
	// unknown value falls back to the provider derived from Endpoint.
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

// backupProvider is one provider tile of the destination form. The provider
// is only a hint for the endpoint format: it is never stored, and the
// configured destination's provider is derived from its endpoint host.
type backupProvider struct {
	ID string
	// Name labels the tile; Summary names a configured destination.
	Name    string
	Summary string
	// Mark is the two-letter monogram drawn in the tile.
	Mark string
	// Pattern is the endpoint host pattern shown in the tile.
	Pattern             string
	EndpointPlaceholder string
	RegionPlaceholder   string
}

var backupProviders = []backupProvider{
	{ID: "r2", Name: "Cloudflare R2", Summary: "Cloudflare R2", Mark: "R2", Pattern: "<account-id>.r2.cloudflarestorage.com", EndpointPlaceholder: "https://<account-id>.r2.cloudflarestorage.com", RegionPlaceholder: "auto"},
	{ID: "aws", Name: "Amazon S3", Summary: "Amazon S3", Mark: "S3", Pattern: "s3.<region>.amazonaws.com", EndpointPlaceholder: "https://s3.<region>.amazonaws.com", RegionPlaceholder: "us-east-1"},
	{ID: "b2", Name: "Backblaze B2", Summary: "Backblaze B2", Mark: "B2", Pattern: "s3.<region>.backblazeb2.com", EndpointPlaceholder: "https://s3.<region>.backblazeb2.com", RegionPlaceholder: "us-west-004"},
	{ID: "wasabi", Name: "Wasabi", Summary: "Wasabi", Mark: "Wa", Pattern: "s3.<region>.wasabisys.com", EndpointPlaceholder: "https://s3.<region>.wasabisys.com", RegionPlaceholder: "eu-central-1"},
	{ID: "do", Name: "DigitalOcean Spaces", Summary: "DigitalOcean Spaces", Mark: "DO", Pattern: "<region>.digitaloceanspaces.com", EndpointPlaceholder: "https://<region>.digitaloceanspaces.com", RegionPlaceholder: "nyc3"},
	{ID: "minio", Name: "MinIO / self-hosted", Summary: "MinIO / self-hosted", Mark: "Mi", Pattern: "your server's https URL", EndpointPlaceholder: "https://minio.example.com:9000", RegionPlaceholder: "us-east-1"},
	{ID: "other", Name: "Other S3-compatible", Summary: "S3-compatible", Mark: "S3", Pattern: "any SigV4 endpoint over https", EndpointPlaceholder: "https://s3.example.com", RegionPlaceholder: "auto"},
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

// backupProviderForEndpoint derives the provider tile from an endpoint host:
// known provider domains map to their tile, loopback hosts and hosts named
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

// selectedBackupProvider is the tile checked in the form: the submitted hint
// when it is a known tile, else the provider of the endpoint in the form.
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

// placeholderBackupProvider picks the placeholders: the selected tile, or
// Cloudflare R2 when none is selected.
func (v BackupsPageView) placeholderBackupProvider() backupProvider {
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
	var describedBy []string
	attrs := templ.Attributes{}
	if v.destinationFieldError(field) != "" {
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
// when it re-renders a refused save.
func (v BackupsPageView) destinationFormOpen() bool {
	return v.DestinationForm.Submitted
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
