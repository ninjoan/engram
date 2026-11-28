package dashboard

import (
	"regexp"
	"strings"
	"testing"
	"time"
)

var (
	backupTimezoneSelect    = regexp.MustCompile(`(?s)<select[^>]*\bname="timezone"[^>]*>.*?</select>`)
	backupTimezoneSelectTag = regexp.MustCompile(`<select[^>]*\bname="timezone"[^>]*>`)
	backupSelectOption      = regexp.MustCompile(`<option value="([^"]*)"( selected)?>([^<]*)</option>`)
	backupSelectOptgroup    = regexp.MustCompile(`<optgroup label="([^"]*)">`)
	backupScheduleFormHTML  = regexp.MustCompile(`(?s)<form method="post" action="/dashboard/admin/backups/schedule"[^>]*>.*?</form>`)
)

// scheduleBackupsView is a configured destination whose schedule runs in
// zone, rendered at now.
func scheduleBackupsView(zone string, now time.Time) BackupsPageView {
	v := readyBackupsView(configuredR2Destination())
	v.Schedule.Configured = true
	v.Schedule.Timezone = zone
	v.Now = now
	v.CanRunNow = true
	return v
}

func backupTimezoneSelectHTML(t *testing.T, body string) string {
	t.Helper()
	sel := backupTimezoneSelect.FindString(body)
	if sel == "" {
		t.Fatalf("no time zone select in body=%q", body)
	}
	return sel
}

type renderedTimezoneOption struct {
	value, label string
	selected     bool
}

func backupTimezoneOptions(sel string) []renderedTimezoneOption {
	var options []renderedTimezoneOption
	for _, m := range backupSelectOption.FindAllStringSubmatch(sel, -1) {
		options = append(options, renderedTimezoneOption{value: m[1], selected: m[2] != "", label: m[3]})
	}
	return options
}

func backupSelectedTimezones(sel string) []string {
	var selected []string
	for _, o := range backupTimezoneOptions(sel) {
		if o.selected {
			selected = append(selected, o.value)
		}
	}
	return selected
}

var novemberNow = time.Date(2026, 11, 26, 12, 0, 0, 0, time.UTC)

func TestAdminBackupsScheduleTimezoneIsASelectGroupedByRegion(t *testing.T) {
	body := renderBackupsPageForTest(t, scheduleBackupsView("America/Lima", novemberNow))
	if strings.Contains(body, `<input type="text" name="timezone"`) {
		t.Fatalf("the time zone must not be a text input, body=%q", body)
	}
	sel := backupTimezoneSelectHTML(t, body)
	tag := backupTimezoneSelectTag.FindString(sel)
	for _, attr := range []string{`id="backup-schedule-timezone"`, `required`} {
		if !strings.Contains(tag, attr) {
			t.Fatalf("select tag %q lacks %q", tag, attr)
		}
	}
	if !strings.Contains(backupScheduleFormHTML.FindString(body), `name="timezone"`) {
		t.Fatalf("the select must post with the schedule form, body=%q", body)
	}

	options := backupTimezoneOptions(sel)
	if len(options) < 300 || options[0].value != "UTC" || options[0].label != "UTC (UTC+00:00)" {
		t.Fatalf("UTC must be the first of the zone options, got %d options, first=%+v", len(options), options[0])
	}
	if first := strings.Index(sel, "<optgroup"); first == -1 || strings.Index(sel, `<option value="UTC"`) > first {
		t.Fatalf("UTC must come before every region group, select=%q", sel)
	}
	var regions []string
	for _, m := range backupSelectOptgroup.FindAllStringSubmatch(sel, -1) {
		regions = append(regions, m[1])
	}
	if got, want := strings.Join(regions, ","), "Africa,America,Antarctica,Asia,Atlantic,Australia,Europe,Indian,Pacific"; got != want {
		t.Fatalf("optgroups = %q, want %q", got, want)
	}
	for _, marker := range []string{
		`<option value="America/Lima" selected>America/Lima (UTC−05:00)</option>`,
		`<option value="Asia/Kolkata">Asia/Kolkata (UTC+05:30)</option>`,
		`<option value="Europe/Madrid">Europe/Madrid (UTC+01:00)</option>`,
		`<option value="Australia/Sydney">Australia/Sydney (UTC+11:00)</option>`,
		`<option value="Pacific/Chatham">Pacific/Chatham (UTC+13:45)</option>`,
	} {
		if !strings.Contains(sel, marker) {
			t.Fatalf("expected option %q in select=%q", marker, sel)
		}
	}
	if got := backupSelectedTimezones(sel); len(got) != 1 || got[0] != "America/Lima" {
		t.Fatalf("selected = %v, want only the saved America/Lima", got)
	}
}

func TestAdminBackupsScheduleTimezoneOffsetsFollowDaylightSaving(t *testing.T) {
	july := time.Date(2026, 7, 1, 12, 0, 0, 0, time.UTC)
	sel := backupTimezoneSelectHTML(t, renderBackupsPageForTest(t, scheduleBackupsView("UTC", july)))
	for _, marker := range []string{
		`<option value="Europe/Madrid">Europe/Madrid (UTC+02:00)</option>`,
		`<option value="Australia/Sydney">Australia/Sydney (UTC+10:00)</option>`,
		`<option value="America/Lima">America/Lima (UTC−05:00)</option>`,
		`<option value="UTC" selected>UTC (UTC+00:00)</option>`,
	} {
		if !strings.Contains(sel, marker) {
			t.Fatalf("expected option %q in July, select=%q", marker, sel)
		}
	}
}

func TestAdminBackupsScheduleKeepsAValidSavedZoneOutsideTheList(t *testing.T) {
	sel := backupTimezoneSelectHTML(t, renderBackupsPageForTest(t, scheduleBackupsView("Etc/GMT+5", novemberNow)))
	options := backupTimezoneOptions(sel)
	if len(options) < 2 || options[0].value != "UTC" || options[0].selected {
		t.Fatalf("UTC must stay first and unselected, got %+v", options[:2])
	}
	if options[1] != (renderedTimezoneOption{value: "Etc/GMT+5", label: "Etc/GMT+5 (UTC−05:00)", selected: true}) {
		t.Fatalf("the saved zone must follow UTC as the selected option, got %+v", options[1])
	}
	if got := backupSelectedTimezones(sel); len(got) != 1 {
		t.Fatalf("selected = %v, want exactly one", got)
	}
}

func TestAdminBackupsScheduleSelectsUTCWhenTheSavedZoneIsNotOffered(t *testing.T) {
	for _, zone := range []string{"", "Local", "Mars/Olympus_Mons"} {
		sel := backupTimezoneSelectHTML(t, renderBackupsPageForTest(t, scheduleBackupsView(zone, novemberNow)))
		if zone != "" && strings.Contains(sel, `value="`+zone+`"`) {
			t.Fatalf("zone %q must not be offered, select=%q", zone, sel)
		}
		if got := backupSelectedTimezones(sel); len(got) != 1 || got[0] != "UTC" {
			t.Fatalf("zone %q: selected = %v, want UTC", zone, got)
		}
	}
}

func TestAdminBackupsScheduleMarksTheRefusedField(t *testing.T) {
	v := scheduleBackupsView("America/Lima", novemberNow)
	v.ScheduleForm = BackupScheduleForm{Field: "timezone", Error: "time zone must be an IANA name such as UTC or America/Lima"}
	body := renderBackupsPageForTest(t, v)
	tag := backupTimezoneSelectTag.FindString(body)
	if !strings.Contains(tag, `aria-invalid="true"`) || !strings.Contains(tag, `aria-describedby="backup-schedule-timezone-error backup-schedule-timezone-hint"`) {
		t.Fatalf("the refused zone must be marked, tag=%q", tag)
	}
	if !strings.Contains(body, `<span class="field-error" id="backup-schedule-timezone-error">time zone must be an IANA name such as UTC or America/Lima</span>`) {
		t.Fatalf("expected the field error, body=%q", body)
	}
	if strings.Contains(backupInputTag(t, body, "time"), "aria-invalid") {
		t.Fatalf("only the refused field is marked")
	}

	v.ScheduleForm = BackupScheduleForm{Field: "time", Error: "time must be HH:MM on a 24-hour clock, such as 03:00"}
	body = renderBackupsPageForTest(t, v)
	if !strings.Contains(backupInputTag(t, body, "time"), `aria-invalid="true"`) || strings.Contains(backupTimezoneSelectTag.FindString(body), "aria-invalid") {
		t.Fatalf("the refused time must be marked alone, body=%q", body)
	}

	tag = backupTimezoneSelectTag.FindString(renderBackupsPageForTest(t, scheduleBackupsView("UTC", novemberNow)))
	if strings.Contains(tag, "aria-invalid") || !strings.Contains(tag, `aria-describedby="backup-schedule-timezone-hint"`) {
		t.Fatalf("an unrefused select is not marked, tag=%q", tag)
	}
}

func TestAdminBackupsScheduleActionsSeparateSaveFromBackUpNow(t *testing.T) {
	body := renderBackupsPageForTest(t, scheduleBackupsView("UTC", novemberNow))
	form := backupScheduleFormHTML.FindString(body)
	if !regexp.MustCompile(`<div class="backup-submit-row">\s*<p class="muted"[^>]*>[^<]*</p>\s*<button type="submit">Save schedule</button>\s*</div>`).MatchString(form) {
		t.Fatalf("Save schedule must be the primary submit of an actions row, form=%q", form)
	}
	if strings.Contains(form, "Back up now") || strings.Contains(form, "/dashboard/admin/backups/run") {
		t.Fatalf("Back up now must not sit inside the schedule form, form=%q", form)
	}
	if !regexp.MustCompile(`(?s)<div class="backup-run-now">\s*<form method="post" action="/dashboard/admin/backups/run">\s*<button type="submit" class="secondary">Back up now</button>\s*</form>\s*<p class="muted">Starts one upload`).MatchString(body) {
		t.Fatalf("Back up now must be a secondary action grouped with its helper, body=%q", body)
	}
	if strings.Index(body, "Save schedule") > strings.Index(body, "Back up now") {
		t.Fatalf("Back up now comes after the schedule form")
	}

	v := scheduleBackupsView("UTC", novemberNow)
	v.CanRunNow = false
	body = renderBackupsPageForTest(t, v)
	if strings.Contains(body, "Back up now") || strings.Contains(body, "backup-run-now") || strings.Contains(body, "/dashboard/admin/backups/run") {
		t.Fatalf("without a runner there is no Back up now, body=%q", body)
	}
	if !strings.Contains(body, "Save schedule") {
		t.Fatalf("the schedule form stays without a runner")
	}
}
