package cloudstore

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// Backup schedule. At most one schedule exists: the weekdays and the local
// time of day, in an IANA time zone, at which the scheduler uploads a backup
// to the configured destination. Like the destination it is operational
// state of this server and is never exported in a backup.

const (
	AuthAuditActionBackupScheduleUpdate = "backup.schedule.update"

	// DefaultBackupScheduleTimeOfDay and DefaultBackupScheduleTimezone describe
	// an unconfigured schedule.
	DefaultBackupScheduleTimeOfDay = "03:00"
	DefaultBackupScheduleTimezone  = "UTC"

	maxBackupScheduleTimezoneLength = 64
)

var ErrInvalidBackupSchedule = errors.New("cloudstore: invalid backup schedule")

// BackupScheduleWeekdays lists the weekdays Monday first, the order the
// dashboard and audit metadata use.
var BackupScheduleWeekdays = []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday, time.Saturday, time.Sunday}

var backupScheduleTimePattern = regexp.MustCompile(`^([01][0-9]|2[0-3]):[0-5][0-9]$`)

// BackupSchedule is the stored schedule. Configured is false when none is
// stored; the other fields then hold the defaults. Weekdays are Monday first.
type BackupSchedule struct {
	Configured           bool
	Enabled              bool
	Weekdays             []time.Weekday
	TimeOfDay            string
	Timezone             string
	UpdatedByPrincipalID string
	UpdatedAt            time.Time
}

// PutBackupScheduleParams is a complete schedule. Enabling it requires at
// least one weekday and a configured backup destination.
type PutBackupScheduleParams struct {
	Enabled   bool
	Weekdays  []time.Weekday
	TimeOfDay string
	Timezone  string
	Actor     BackupDestinationActor
}

// GetBackupSchedule returns the stored schedule, or the disabled defaults
// with Configured false when none is stored.
func (cs *CloudStore) GetBackupSchedule(ctx context.Context) (BackupSchedule, error) {
	if cs == nil || cs.db == nil {
		return BackupSchedule{}, fmt.Errorf("cloudstore: not initialized")
	}
	var s BackupSchedule
	var mask int16
	err := cs.db.QueryRowContext(ctx, `
		SELECT enabled, weekdays, time_of_day, timezone, COALESCE(updated_by_principal_id::text, ''), updated_at
		FROM cloud_backup_schedule WHERE id = 1`).Scan(&s.Enabled, &mask, &s.TimeOfDay, &s.Timezone, &s.UpdatedByPrincipalID, &s.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return BackupSchedule{TimeOfDay: DefaultBackupScheduleTimeOfDay, Timezone: DefaultBackupScheduleTimezone}, nil
	}
	if err != nil {
		return BackupSchedule{}, fmt.Errorf("cloudstore: read backup schedule: %w", err)
	}
	s.Configured = true
	s.Weekdays = backupWeekdaysFromMask(mask)
	return s, nil
}

// PutBackupSchedule validates params and stores the schedule with its
// backup.schedule.update audit row in one transaction. Invalid input, or
// enabling without a destination, writes nothing; an audit failure rolls the
// schedule back.
func (cs *CloudStore) PutBackupSchedule(ctx context.Context, params PutBackupScheduleParams) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	mask, timeOfDay, timezone, err := normalizeBackupSchedule(params)
	if err != nil {
		return err
	}
	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup schedule tx: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if params.Enabled {
		// FOR SHARE keeps a concurrent destination removal from committing
		// between this check and the schedule write.
		var configured bool
		err := tx.QueryRowContext(ctx, `SELECT TRUE FROM cloud_backup_destinations WHERE id = 1 FOR SHARE`).Scan(&configured)
		if errors.Is(err, sql.ErrNoRows) {
			return fmt.Errorf("%w: configure a backup destination before enabling the schedule", ErrBackupDestinationNotConfigured)
		}
		if err != nil {
			return fmt.Errorf("cloudstore: read backup destination: %w", err)
		}
	}
	if _, err := tx.ExecContext(ctx, `
		INSERT INTO cloud_backup_schedule (id, enabled, weekdays, time_of_day, timezone, updated_by_principal_id, updated_at)
		VALUES (1, $1, $2, $3, $4, $5, NOW())
		ON CONFLICT (id) DO UPDATE SET
			enabled = EXCLUDED.enabled, weekdays = EXCLUDED.weekdays, time_of_day = EXCLUDED.time_of_day,
			timezone = EXCLUDED.timezone, updated_by_principal_id = EXCLUDED.updated_by_principal_id, updated_at = EXCLUDED.updated_at`,
		params.Enabled, mask, timeOfDay, timezone, nullableID(params.Actor.PrincipalID),
	); err != nil {
		return fmt.Errorf("cloudstore: store backup schedule: %w", err)
	}
	audit := AuthAuditEvent{
		ActorPrincipalID: params.Actor.PrincipalID,
		ActorSource:      params.Actor.Source,
		Action:           AuthAuditActionBackupScheduleUpdate,
		Outcome:          "success",
		Metadata: map[string]any{
			"enabled": params.Enabled, "weekdays": backupWeekdayNames(backupWeekdaysFromMask(mask)), "time": timeOfDay, "timezone": timezone,
		},
	}
	if err := insertAuthAuditEvent(ctx, tx, audit); err != nil {
		return fmt.Errorf("%w: %w", ErrAuthAuditInsertFailed, err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup schedule tx: %w", err)
	}
	return nil
}

// NextRun returns the first scheduled run strictly after after, or false when
// the schedule is disabled, has no weekday, or holds an invalid time or zone.
// A local time skipped by a daylight-saving jump runs once, at the instant
// the clocks jump; a local time that repeats runs once.
func (s BackupSchedule) NextRun(after time.Time) (time.Time, bool) {
	if !s.Enabled || len(s.Weekdays) == 0 {
		return time.Time{}, false
	}
	hour, minute, ok := parseBackupScheduleTime(s.TimeOfDay)
	if !ok {
		return time.Time{}, false
	}
	loc, ok := loadBackupScheduleLocation(s.Timezone)
	if !ok {
		return time.Time{}, false
	}
	var days [7]bool
	for _, day := range s.Weekdays {
		if day >= time.Sunday && day <= time.Saturday {
			days[day] = true
		}
	}
	local := after.In(loc)
	// Eight days cover a weekly schedule whose only slot today already passed.
	for offset := 0; offset <= 7; offset++ {
		date := time.Date(local.Year(), local.Month(), local.Day()+offset, 12, 0, 0, 0, loc)
		if !days[date.Weekday()] {
			continue
		}
		candidate := backupScheduleSlot(date.Year(), date.Month(), date.Day(), hour, minute, loc)
		if candidate.After(after) {
			return candidate, true
		}
	}
	return time.Time{}, false
}

// backupScheduleSlot returns the instant of the local wall-clock time. For a
// time that a daylight-saving jump skips, time.Date may pick an instant on
// either side of the gap; the slot is then the transition itself, so the run
// is neither moved an hour earlier nor lost.
func backupScheduleSlot(year int, month time.Month, day, hour, minute int, loc *time.Location) time.Time {
	candidate := time.Date(year, month, day, hour, minute, 0, 0, loc)
	if candidate.Hour() == hour && candidate.Minute() == minute {
		return candidate
	}
	start, end := candidate.ZoneBounds()
	wall := time.Date(candidate.Year(), candidate.Month(), candidate.Day(), candidate.Hour(), candidate.Minute(), 0, 0, time.UTC)
	requested := time.Date(year, month, day, hour, minute, 0, 0, time.UTC)
	if wall.Before(requested) && !end.IsZero() {
		return end
	}
	if !wall.Before(requested) && !start.IsZero() {
		return start
	}
	return candidate
}

// BackupWeekdayName is the short lowercase name ("mon".."sun") of day used in
// forms and audit metadata.
func BackupWeekdayName(day time.Weekday) string {
	return strings.ToLower(day.String()[:3])
}

// normalizeBackupSchedule validates params and returns the weekday bitmask
// (bit n is time.Weekday n), the time of day and the time zone.
func normalizeBackupSchedule(params PutBackupScheduleParams) (int16, string, string, error) {
	invalid := func(reason string) (int16, string, string, error) {
		return 0, "", "", fmt.Errorf("%w: %s", ErrInvalidBackupSchedule, reason)
	}
	var mask int16
	for _, day := range params.Weekdays {
		if day < time.Sunday || day > time.Saturday {
			return invalid("weekdays must be Monday through Sunday")
		}
		mask |= 1 << day
	}
	if params.Enabled && mask == 0 {
		return invalid("select at least one weekday to enable the schedule")
	}
	timeOfDay := strings.TrimSpace(params.TimeOfDay)
	if _, _, ok := parseBackupScheduleTime(timeOfDay); !ok {
		return invalid("time must be HH:MM on a 24-hour clock, such as 03:00")
	}
	timezone := strings.TrimSpace(params.Timezone)
	if _, ok := loadBackupScheduleLocation(timezone); !ok {
		return invalid("time zone must be an IANA name such as UTC or America/Lima")
	}
	return mask, timeOfDay, timezone, nil
}

func parseBackupScheduleTime(value string) (int, int, bool) {
	if !backupScheduleTimePattern.MatchString(value) {
		return 0, 0, false
	}
	hour, _ := strconv.Atoi(value[:2])
	minute, _ := strconv.Atoi(value[3:])
	return hour, minute, true
}

// loadBackupScheduleLocation accepts IANA zone names only. "Local" is refused
// because it would make the schedule depend on the server host's zone.
func loadBackupScheduleLocation(name string) (*time.Location, bool) {
	if name == "" || len(name) > maxBackupScheduleTimezoneLength || strings.EqualFold(name, "local") || strings.ContainsAny(name, " \t\r\n\\") {
		return nil, false
	}
	loc, err := time.LoadLocation(name)
	if err != nil {
		return nil, false
	}
	return loc, true
}

func backupWeekdaysFromMask(mask int16) []time.Weekday {
	days := []time.Weekday{}
	for _, day := range BackupScheduleWeekdays {
		if mask&(1<<day) != 0 {
			days = append(days, day)
		}
	}
	return days
}

func backupWeekdayNames(days []time.Weekday) []string {
	names := make([]string, 0, len(days))
	for _, day := range days {
		names = append(names, BackupWeekdayName(day))
	}
	return names
}
