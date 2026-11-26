package cloudstore

import (
	"context"
	"errors"
	"testing"
	"time"
)

func vfySchedule(days []time.Weekday, tod, tz string) BackupSchedule {
	return BackupSchedule{Configured: true, Enabled: true, Weekdays: days, TimeOfDay: tod, Timezone: tz}
}

func TestBackupScheduleProbeNextRunDST(t *testing.T) {
	ny, _ := time.LoadLocation("America/New_York")
	cases := []struct {
		name  string
		s     BackupSchedule
		after time.Time
		want  time.Time
	}{
		// 2026-03-08 02:30 local does not exist in New York; clocks jump 02:00 EST -> 03:00 EDT (07:00Z).
		{"NY spring-forward gap", vfySchedule([]time.Weekday{time.Sunday}, "02:30", "America/New_York"), time.Date(2026, 3, 8, 0, 0, 0, 0, ny), time.Date(2026, 3, 8, 7, 0, 0, 0, time.UTC)},
		// 2026-11-01 01:30 repeats; first occurrence is 01:30 EDT = 05:30Z.
		{"NY fall-back first occurrence", vfySchedule([]time.Weekday{time.Sunday}, "01:30", "America/New_York"), time.Date(2026, 11, 1, 0, 0, 0, 0, ny), time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC)},
		// after the first occurrence, the next run is the following Sunday 01:30 EST = 06:30Z on Nov 8, not 06:30Z Nov 1.
		{"NY fall-back runs once", vfySchedule([]time.Weekday{time.Sunday}, "01:30", "America/New_York"), time.Date(2026, 11, 1, 5, 30, 0, 0, time.UTC), time.Date(2026, 11, 8, 6, 30, 0, 0, time.UTC)},
		// Lord Howe: 30-minute DST shift 2026-10-04 02:00 -> 02:30 (+10:30 -> +11). 02:15 is skipped; slot is the transition 15:30Z Oct 3.
		{"Lord Howe 30-min gap", vfySchedule([]time.Weekday{time.Sunday}, "02:15", "Australia/Lord_Howe"), time.Date(2026, 10, 3, 12, 0, 0, 0, time.UTC), time.Date(2026, 10, 3, 15, 30, 0, 0, time.UTC)},
		// Kolkata +05:30 fixed offset.
		{"Kolkata half-hour offset", vfySchedule([]time.Weekday{time.Friday}, "03:00", "Asia/Kolkata"), time.Date(2026, 11, 26, 0, 0, 0, 0, time.UTC), time.Date(2026, 11, 26, 21, 30, 0, 0, time.UTC)},
		// Week wrap: Monday only, after exactly Monday 03:00 -> next Monday.
		{"week wrap exact", vfySchedule([]time.Weekday{time.Monday}, "03:00", "UTC"), time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC), time.Date(2026, 12, 7, 3, 0, 0, 0, time.UTC)},
		{"week wrap before", vfySchedule([]time.Weekday{time.Monday}, "03:00", "UTC"), time.Date(2026, 11, 30, 2, 59, 59, 0, time.UTC), time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)},
		{"Sunday to Monday wrap", vfySchedule([]time.Weekday{time.Monday}, "03:00", "UTC"), time.Date(2026, 11, 29, 23, 59, 0, 0, time.UTC), time.Date(2026, 11, 30, 3, 0, 0, 0, time.UTC)},
		{"Lima Mon-Fri", vfySchedule([]time.Weekday{time.Monday, time.Tuesday, time.Wednesday, time.Thursday, time.Friday}, "03:00", "America/Lima"), time.Date(2026, 11, 28, 12, 0, 0, 0, time.UTC), time.Date(2026, 11, 30, 8, 0, 0, 0, time.UTC)},
	}
	for _, tc := range cases {
		got, ok := tc.s.NextRun(tc.after)
		if !ok || !got.Equal(tc.want) {
			t.Errorf("%s: NextRun(%s) = %s,%v want %s", tc.name, tc.after.UTC(), got.UTC(), ok, tc.want)
		}
	}
	// Disabled / no weekday / bad tz -> false.
	for name, s := range map[string]BackupSchedule{
		"disabled":   {Enabled: false, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC"},
		"no weekday": {Enabled: true, TimeOfDay: "03:00", Timezone: "UTC"},
		"bad tz":     {Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "Mars/Base"},
	} {
		if _, ok := s.NextRun(time.Now()); ok {
			t.Errorf("%s: NextRun must report no run", name)
		}
	}
}

func TestBackupScheduleProbeScheduleValidation(t *testing.T) {
	bad := map[string]PutBackupScheduleParams{
		"weekday 7":       {Weekdays: []time.Weekday{7}, TimeOfDay: "03:00", Timezone: "UTC"},
		"weekday -1":      {Weekdays: []time.Weekday{-1}, TimeOfDay: "03:00", Timezone: "UTC"},
		"enabled no days": {Enabled: true, TimeOfDay: "03:00", Timezone: "UTC"},
		"24:00":           {TimeOfDay: "24:00", Timezone: "UTC"},
		"3:00":            {TimeOfDay: "3:00", Timezone: "UTC"},
		"03:60":           {TimeOfDay: "03:60", Timezone: "UTC"},
		"03:00:00":        {TimeOfDay: "03:00:00", Timezone: "UTC"},
		"empty time":      {TimeOfDay: "", Timezone: "UTC"},
		"Local":           {TimeOfDay: "03:00", Timezone: "Local"},
		"empty tz":        {TimeOfDay: "03:00", Timezone: ""},
		"unknown tz":      {TimeOfDay: "03:00", Timezone: "America/Nowhere"},
		"path tz":         {TimeOfDay: "03:00", Timezone: "../../etc/passwd"},
		"offset tz":       {TimeOfDay: "03:00", Timezone: "+05:00"},
	}
	for name, p := range bad {
		if _, _, _, err := normalizeBackupSchedule(p); !errors.Is(err, ErrInvalidBackupSchedule) {
			t.Errorf("%s: err = %v, want ErrInvalidBackupSchedule", name, err)
		}
	}
	mask, tod, tz, err := normalizeBackupSchedule(PutBackupScheduleParams{Enabled: true, Weekdays: []time.Weekday{time.Monday, time.Monday, time.Sunday}, TimeOfDay: " 23:59 ", Timezone: " America/Lima "})
	if err != nil || mask != 0b0000011 || tod != "23:59" || tz != "America/Lima" {
		t.Errorf("valid schedule = %d %q %q %v", mask, tod, tz, err)
	}
}

func TestBackupScheduleProbeScheduledSlotUniqueAcrossZones(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	lima, _ := time.LoadLocation("America/Lima")
	slot := time.Date(2026, 11, 30, 3, 0, 0, 0, lima)
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: slot}); err != nil {
		t.Fatalf("first: %v", err)
	}
	if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerScheduled, ScheduledFor: slot.UTC()}); !errors.Is(err, ErrBackupRunAlreadyRecorded) {
		t.Fatalf("same instant in UTC: err = %v", err)
	}
	// Two manual runs are not constrained.
	for i := 0; i < 2; i++ {
		if _, err := cs.StartBackupRun(ctx, StartBackupRunParams{Trigger: BackupRunTriggerManual}); err != nil {
			t.Fatalf("manual %d: %v", i, err)
		}
	}
	// PutBackupSchedule enabled without destination -> not configured, nothing written.
	err := cs.PutBackupSchedule(ctx, PutBackupScheduleParams{Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC"})
	if !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("enable without destination: %v", err)
	}
	if s, _ := cs.GetBackupSchedule(ctx); s.Configured {
		t.Fatalf("refused schedule was stored: %+v", s)
	}
}
