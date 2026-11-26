package dashboard

import (
	"slices"
	"strconv"
	"time"

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
}

func (v BackupsPageView) settingsFormsVisible() bool {
	return v.CanManage && v.Settings == BackupSettingsReady
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

func backupNoticeClass(kind string) string {
	if kind == "danger" {
		return "data-frame policy-note danger-note"
	}
	return "data-frame policy-note success-note"
}
