package cloudstore

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"
)

func validScheduleParams(adminID string) PutBackupScheduleParams {
	return PutBackupScheduleParams{
		Enabled:   true,
		Weekdays:  []time.Weekday{time.Friday, time.Monday, time.Wednesday},
		TimeOfDay: "03:00",
		Timezone:  "America/Lima",
		Actor:     BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"},
	}
}

func scheduleRowText(t *testing.T, cs *CloudStore) string {
	t.Helper()
	var row string
	err := cs.db.QueryRowContext(context.Background(), `SELECT COALESCE((SELECT row_to_json(s)::text FROM cloud_backup_schedule s), '')`).Scan(&row)
	if err != nil {
		t.Fatalf("read schedule row: %v", err)
	}
	return row
}

func TestGetBackupScheduleReportsUnconfiguredDefaults(t *testing.T) {
	cs := openIsolatedCloudStore(t)
	got, err := cs.GetBackupSchedule(context.Background())
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	if got.Configured || got.Enabled || len(got.Weekdays) != 0 || got.TimeOfDay != "03:00" || got.Timezone != "UTC" {
		t.Fatalf("unconfigured schedule = %+v, want disabled 03:00 UTC defaults", got)
	}
}

func TestPutBackupScheduleStoresScheduleAndAuditsInOneTransaction(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}

	if err := cs.PutBackupSchedule(ctx, validScheduleParams(adminID)); err != nil {
		t.Fatalf("PutBackupSchedule: %v", err)
	}
	got, err := cs.GetBackupSchedule(ctx)
	if err != nil {
		t.Fatalf("GetBackupSchedule: %v", err)
	}
	want := []time.Weekday{time.Monday, time.Wednesday, time.Friday}
	if !got.Configured || !got.Enabled || !slices.Equal(got.Weekdays, want) || got.TimeOfDay != "03:00" || got.Timezone != "America/Lima" || got.UpdatedByPrincipalID != adminID || got.UpdatedAt.IsZero() {
		t.Fatalf("Get = %+v", got)
	}
	audits := destinationAuditMetadata(t, cs, AuthAuditActionBackupScheduleUpdate)
	if len(audits) != 1 {
		t.Fatalf("schedule audits = %d, want 1", len(audits))
	}
	for _, want := range []string{`"enabled": true`, `"time": "03:00"`, `"timezone": "America/Lima"`, `"weekdays": ["mon", "wed", "fri"]`} {
		if !strings.Contains(audits[0], want) {
			t.Fatalf("schedule audit %s misses %s", audits[0], want)
		}
	}
	if strings.Contains(audits[0], testDestinationSecret) || strings.Contains(audits[0], testDestinationAccessKeyID) {
		t.Fatalf("schedule audit carries a credential: %s", audits[0])
	}

	// A second Put replaces the single row; a disabled schedule may keep no weekdays.
	next := validScheduleParams(adminID)
	next.Enabled, next.Weekdays, next.TimeOfDay, next.Timezone = false, nil, "23:59", "UTC"
	if err := cs.PutBackupSchedule(ctx, next); err != nil {
		t.Fatalf("disable schedule: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_schedule`); n != 1 {
		t.Fatalf("schedule rows = %d, want 1", n)
	}
	got, err = cs.GetBackupSchedule(ctx)
	if err != nil || got.Enabled || len(got.Weekdays) != 0 || got.TimeOfDay != "23:59" || got.Timezone != "UTC" {
		t.Fatalf("Get after disable = %+v, %v", got, err)
	}
}

func TestPutBackupScheduleRejectsInvalidInputWithoutWriting(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	baseAudits := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`)

	cases := map[string]func(*PutBackupScheduleParams){
		"hour out of range":        func(p *PutBackupScheduleParams) { p.TimeOfDay = "24:00" },
		"minute out of range":      func(p *PutBackupScheduleParams) { p.TimeOfDay = "03:60" },
		"single digit hour":        func(p *PutBackupScheduleParams) { p.TimeOfDay = "3:00" },
		"seconds":                  func(p *PutBackupScheduleParams) { p.TimeOfDay = "03:00:00" },
		"empty time":               func(p *PutBackupScheduleParams) { p.TimeOfDay = "" },
		"twelve hour clock":        func(p *PutBackupScheduleParams) { p.TimeOfDay = "03:00 PM" },
		"empty timezone":           func(p *PutBackupScheduleParams) { p.Timezone = "" },
		"Local timezone":           func(p *PutBackupScheduleParams) { p.Timezone = "Local" },
		"unknown timezone":         func(p *PutBackupScheduleParams) { p.Timezone = "Mars/Olympus_Mons" },
		"path timezone":            func(p *PutBackupScheduleParams) { p.Timezone = "../../etc/passwd" },
		"zero weekdays enabled":    func(p *PutBackupScheduleParams) { p.Weekdays = nil },
		"weekday out of range":     func(p *PutBackupScheduleParams) { p.Weekdays = []time.Weekday{7} },
		"negative weekday":         func(p *PutBackupScheduleParams) { p.Weekdays = []time.Weekday{-1} },
		"timezone with whitespace": func(p *PutBackupScheduleParams) { p.Timezone = "America/ Lima" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			params := validScheduleParams(adminID)
			mutate(&params)
			if err := cs.PutBackupSchedule(ctx, params); !errors.Is(err, ErrInvalidBackupSchedule) {
				t.Fatalf("Put error = %v, want %v", err, ErrInvalidBackupSchedule)
			}
			if row := scheduleRowText(t, cs); row != "" {
				t.Fatalf("rejected Put wrote a schedule: %s", row)
			}
			if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != baseAudits {
				t.Fatalf("rejected Put wrote %d audit rows", n-baseAudits)
			}
		})
	}
}

func TestPutBackupScheduleEnableRequiresDestination(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)

	if err := cs.PutBackupSchedule(ctx, validScheduleParams(adminID)); !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("enable without destination error = %v, want %v", err, ErrBackupDestinationNotConfigured)
	}
	if row := scheduleRowText(t, cs); row != "" {
		t.Fatalf("refused enable wrote a schedule: %s", row)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != 0 {
		t.Fatalf("refused enable wrote %d audit rows", n)
	}
	// Saving a disabled schedule does not need a destination.
	disabled := validScheduleParams(adminID)
	disabled.Enabled = false
	if err := cs.PutBackupSchedule(ctx, disabled); err != nil {
		t.Fatalf("disabled schedule without destination: %v", err)
	}
}

func TestPutBackupScheduleAuditFailureRollsBack(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatal(err)
	}
	if err := cs.PutBackupSchedule(ctx, validScheduleParams(adminID)); err != nil {
		t.Fatal(err)
	}
	before := scheduleRowText(t, cs)

	next := validScheduleParams(adminID)
	next.TimeOfDay = "05:30"
	next.Actor.Source = "" // the audit insert rejects a missing actor source
	if err := cs.PutBackupSchedule(ctx, next); !errors.Is(err, ErrAuthAuditInsertFailed) {
		t.Fatalf("Put error = %v, want %v", err, ErrAuthAuditInsertFailed)
	}
	if after := scheduleRowText(t, cs); after != before {
		t.Fatalf("failed audit changed the schedule:\nbefore %s\nafter  %s", before, after)
	}
}

func TestDeletingTheUpdatingPrincipalKeepsTheSchedule(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	disabled := validScheduleParams(adminID)
	disabled.Enabled = false
	if err := cs.PutBackupSchedule(ctx, disabled); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, `DELETE FROM cloud_auth_audit_log; DELETE FROM cloud_principals WHERE id = `+adminID); err != nil {
		t.Fatalf("delete principal: %v", err)
	}
	got, err := cs.GetBackupSchedule(ctx)
	if err != nil || !got.Configured || got.UpdatedByPrincipalID != "" {
		t.Fatalf("Get after principal delete = %+v, %v", got, err)
	}
}

func mustLocation(t *testing.T, name string) *time.Location {
	t.Helper()
	loc, err := time.LoadLocation(name)
	if err != nil {
		t.Fatalf("LoadLocation(%s): %v", name, err)
	}
	return loc
}

func TestBackupScheduleNextRun(t *testing.T) {
	lima := mustLocation(t, "America/Lima")
	weekdays := BackupSchedule{Enabled: true, Weekdays: []time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}, TimeOfDay: "03:00", Timezone: "America/Lima"}

	cases := []struct {
		name  string
		after time.Time
		want  time.Time
	}{
		{"later the same day", time.Date(2026, 11, 26, 1, 0, 0, 0, lima), time.Date(2026, 11, 26, 3, 0, 0, 0, lima)},
		{"exactly at the run is the next day", time.Date(2026, 11, 26, 3, 0, 0, 0, lima), time.Date(2026, 11, 27, 3, 0, 0, 0, lima)},
		{"friday evening skips the weekend", time.Date(2026, 11, 27, 20, 0, 0, 0, lima), time.Date(2026, 11, 30, 3, 0, 0, 0, lima)},
		{"input in UTC is converted to the schedule zone", time.Date(2026, 11, 26, 7, 59, 0, 0, time.UTC), time.Date(2026, 11, 26, 3, 0, 0, 0, lima)},
	}
	for _, tc := range cases {
		got, ok := weekdays.NextRun(tc.after)
		if !ok || !got.Equal(tc.want) {
			t.Errorf("%s: NextRun(%s) = %s, %v; want %s", tc.name, tc.after, got, ok, tc.want)
		}
	}

	single := BackupSchedule{Enabled: true, Weekdays: []time.Weekday{time.Sunday}, TimeOfDay: "00:00", Timezone: "UTC"}
	if got, ok := single.NextRun(time.Date(2026, 11, 29, 0, 0, 0, 0, time.UTC)); !ok || !got.Equal(time.Date(2026, 12, 6, 0, 0, 0, 0, time.UTC)) {
		t.Errorf("weekly schedule NextRun at its own run = %s, %v; want one week later", got, ok)
	}

	for name, s := range map[string]BackupSchedule{
		"disabled":    {Enabled: false, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC"},
		"no weekdays": {Enabled: true, TimeOfDay: "03:00", Timezone: "UTC"},
		"bad zone":    {Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "Local"},
		"bad time":    {Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "25:00", Timezone: "UTC"},
	} {
		if got, ok := s.NextRun(time.Now()); ok {
			t.Errorf("%s schedule has a next run %s", name, got)
		}
	}
}

func TestBackupScheduleNextRunAcrossDaylightSavingTransitions(t *testing.T) {
	ny := mustLocation(t, "America/New_York")
	daily := BackupSchedule{Enabled: true, Weekdays: []time.Weekday{time.Sunday, time.Monday}, TimeOfDay: "02:30", Timezone: "America/New_York"}

	// 2026-03-08 02:30 does not exist in New York (clocks jump 02:00 -> 03:00).
	// The run still happens once that day, at the jump (03:00 EDT), and the
	// following run is back at 02:30 local time.
	gap, ok := daily.NextRun(time.Date(2026, 3, 8, 0, 0, 0, 0, ny))
	if !ok || !gap.Equal(time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC)) {
		t.Fatalf("spring-forward run = %s, %v; want 2026-03-08 03:00 EDT, the instant the clocks jump", gap.In(ny), ok)
	}
	next, ok := daily.NextRun(gap)
	if !ok || !next.Equal(time.Date(2026, 3, 9, 2, 30, 0, 0, ny)) || next.Sub(gap) >= 24*time.Hour {
		t.Fatalf("run after spring-forward = %s, %v; want 2026-03-09 02:30 EDT", next.In(ny), ok)
	}

	// Europe/Berlin is ahead of UTC: 2026-03-29 02:30 does not exist there
	// (clocks jump 02:00 CET -> 03:00 CEST). The run happens at the jump
	// (01:00 UTC), neither an hour early nor lost, and the next run is back
	// at 02:30 local time.
	berlin := mustLocation(t, "Europe/Berlin")
	berlinDaily := BackupSchedule{Enabled: true, Weekdays: []time.Weekday{time.Sunday, time.Monday}, TimeOfDay: "02:30", Timezone: "Europe/Berlin"}
	berlinGap, ok := berlinDaily.NextRun(time.Date(2026, 3, 29, 0, 0, 0, 0, berlin))
	if !ok || !berlinGap.Equal(time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC)) {
		t.Fatalf("Berlin spring-forward run = %s (%s UTC), %v; want 2026-03-29 03:00 CEST, the instant the clocks jump", berlinGap.In(berlin), berlinGap.UTC(), ok)
	}
	berlinNext, ok := berlinDaily.NextRun(berlinGap)
	if !ok || !berlinNext.Equal(time.Date(2026, 3, 30, 2, 30, 0, 0, berlin)) {
		t.Fatalf("Berlin run after spring-forward = %s, %v; want 2026-03-30 02:30 CEST", berlinNext.In(berlin), ok)
	}
	// Asked just before the jump, the run is still the jump itself.
	if got, ok := berlinDaily.NextRun(time.Date(2026, 3, 29, 0, 59, 0, 0, time.UTC)); !ok || !got.Equal(berlinGap) {
		t.Fatalf("Berlin NextRun one minute before the jump = %s, %v; want %s", got.UTC(), ok, berlinGap.UTC())
	}

	// 2026-11-01 01:30 happens twice in New York; the run must happen once.
	fallBack := BackupSchedule{Enabled: true, Weekdays: []time.Weekday{time.Sunday, time.Monday}, TimeOfDay: "01:30", Timezone: "America/New_York"}
	first, ok := fallBack.NextRun(time.Date(2026, 11, 1, 0, 0, 0, 0, ny))
	if !ok || first.In(ny).Day() != 1 || first.In(ny).Hour() != 1 || first.In(ny).Minute() != 30 {
		t.Fatalf("fall-back run = %s, %v; want 01:30 on November 1", first.In(ny), ok)
	}
	second, ok := fallBack.NextRun(first)
	if !ok || !second.Equal(time.Date(2026, 11, 2, 1, 30, 0, 0, ny)) {
		t.Fatalf("run after fall-back = %s, %v; want 2026-11-02 01:30 EST (no second run on November 1)", second.In(ny), ok)
	}
}
