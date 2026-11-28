package cloudserver

import (
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var scheduleTimezoneSelectTag = regexp.MustCompile(`<select[^>]*\bname="timezone"[^>]*>`)

func TestDashboardBackupsPageRendersTheSavedZoneSelected(t *testing.T) {
	f := managedBackupFixture(t)
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || scheduleTimezoneSelectTag.FindString(body) == "" {
		t.Fatalf("expected the time zone select, got %d body=%q", rec.Code, body)
	}
	for _, marker := range []string{
		`<option value="UTC">UTC (UTC+00:00)</option>`,
		`<option value="America/Lima" selected>America/Lima (UTC−05:00)</option>`,
		`<optgroup label="Europe">`,
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected %q, body=%q", marker, body)
		}
	}
	if strings.Count(body, " selected>") != 1 {
		t.Fatalf("exactly one zone is selected, body=%q", body)
	}
}

func TestDashboardSaveBackupScheduleWithAListedZone(t *testing.T) {
	f := managedBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "weekday=tue&time=22:30&timezone=Europe%2FMadrid&enabled=on", cookie: f.cookie})
	if rec.Code != http.StatusSeeOther || dashboardRedirect(rec) != backupsPagePath+"?notice=schedule-saved" {
		t.Fatalf("expected 303, got %d %q body=%q", rec.Code, dashboardRedirect(rec), rec.Body.String())
	}
	if got := f.settings.putSchedule; len(got) != 1 || got[0].Timezone != "Europe/Madrid" || got[0].TimeOfDay != "22:30" {
		t.Fatalf("schedule params = %+v", got)
	}
	page := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie).Body.String()
	if !strings.Contains(page, `<option value="Europe/Madrid" selected>Europe/Madrid (UTC+01:00)</option>`) {
		t.Fatalf("the saved zone must render selected, body=%q", page)
	}
}

// A zone that is not in the list (a tampered form) is still refused by the
// store with a 400 that marks the field and never echoes the value.
func TestDashboardSaveBackupScheduleTamperedZoneMarksTheField(t *testing.T) {
	const reason = "time zone must be an IANA name such as UTC or America/Lima"
	for _, zone := range []string{"Mars%2FOlympus_Mons", "Local", ""} {
		f := managedBackupFixture(t)
		f.settings.putScheduleErr = fmt.Errorf("%w: %s", cloudstore.ErrInvalidBackupSchedule, reason)
		rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "weekday=mon&time=03:00&enabled=on&timezone=" + zone, cookie: f.cookie})
		body := rec.Body.String()
		if rec.Code != http.StatusBadRequest || !strings.Contains(body, "Schedule not saved: "+reason+".") {
			t.Fatalf("zone %q: expected 400 with the reason, got %d body=%q", zone, rec.Code, body)
		}
		tag := scheduleTimezoneSelectTag.FindString(body)
		if !strings.Contains(tag, `aria-invalid="true"`) || !strings.Contains(body, `id="backup-schedule-timezone-error">`+reason+`</span>`) {
			t.Fatalf("zone %q: the select must be marked, tag=%q body=%q", zone, tag, body)
		}
		if strings.Contains(body, "Olympus") {
			t.Fatalf("the refused zone must not be echoed, body=%q", body)
		}
		if !strings.Contains(body, `<option value="America/Lima" selected>`) {
			t.Fatalf("the stored zone stays selected, body=%q", body)
		}
	}
}

func TestDashboardSaveBackupScheduleInvalidTimeMarksOnlyTheTime(t *testing.T) {
	f := managedBackupFixture(t)
	f.settings.putScheduleErr = fmt.Errorf("%w: time must be HH:MM on a 24-hour clock, such as 03:00", cloudstore.ErrInvalidBackupSchedule)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "weekday=mon&time=25:00&timezone=UTC&enabled=on", cookie: f.cookie})
	body := rec.Body.String()
	timeTag := regexp.MustCompile(`<input[^>]*\bname="time"[^>]*>`).FindString(body)
	if rec.Code != http.StatusBadRequest || !strings.Contains(timeTag, `aria-invalid="true"`) || strings.Contains(scheduleTimezoneSelectTag.FindString(body), "aria-invalid") {
		t.Fatalf("expected 400 marking only the time, got %d time=%q body=%q", rec.Code, timeTag, body)
	}
}

// A weekday error names no single control, so nothing is marked; the notice
// still explains it (previous behavior).
func TestDashboardSaveBackupScheduleWeekdayErrorMarksNoField(t *testing.T) {
	f := managedBackupFixture(t)
	rec := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupSchedulePath, form: "weekday=funday&time=03:00&timezone=UTC&enabled=on", cookie: f.cookie})
	body := rec.Body.String()
	if rec.Code != http.StatusBadRequest || !strings.Contains(body, "weekdays must be Monday through Sunday") || strings.Contains(body, `aria-invalid="true"`) {
		t.Fatalf("expected 400 without a marked field, got %d body=%q", rec.Code, body)
	}
}
