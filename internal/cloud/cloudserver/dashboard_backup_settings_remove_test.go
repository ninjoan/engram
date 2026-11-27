package cloudserver

import (
	"net/http"
	"strings"
	"testing"
)

const backupRemoveFormTag = `<form method="post" action="/dashboard/admin/backups/destination/remove" class="backup-confirm">`

// The status card carries the only remove control, a confirm step that
// posts to the existing route; the route keeps its guards and audit.
func TestDashboardBackupsPageRemoveControlIsOnTheStatusCardOnly(t *testing.T) {
	f := managedBackupFixture(t)
	rec := performDashboardRequest(f.srv, http.MethodGet, backupsPagePath, f.cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d body=%q", rec.Code, body)
	}
	if n := strings.Count(body, `action="/dashboard/admin/backups/destination/remove"`); n != 1 || !strings.Contains(body, backupRemoveFormTag) {
		t.Fatalf("expected exactly one remove form on the status card, got %d body=%q", n, body)
	}
	for _, marker := range []string{
		`<summary class="backup-remove-toggle">Remove destination</summary>`,
		`<button type="submit" class="backup-danger-fill">Yes, remove destination</button>`,
		"<details class=\"tech-details\"><summary>Technical details (13 tables included, 8 exclusions)</summary>",
		"<strong>Memories and sessions of every project</strong>",
	} {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected marker %q, body=%q", marker, body)
		}
	}
	if remove, change := strings.Index(body, backupRemoveFormTag), strings.Index(body, `<details class="backup-change"`); change < remove {
		t.Fatalf("the remove form must sit on the card, not inside Change destination (remove %d, change %d)", remove, change)
	}

	// The confirm posts to the unchanged route: cleared and audited.
	post := doBackupRequest(f.srv, backupRequest{method: http.MethodPost, path: backupDestinationRemovePath, cookie: f.cookie})
	if post.Code != http.StatusSeeOther || len(f.settings.clears) != 1 {
		t.Fatalf("expected the existing remove route to clear once and redirect, got %d clears=%d", post.Code, len(f.settings.clears))
	}
}

func TestDashboardBackupsPageRemoveControlIsAbsentForLegacyAdminAndMember(t *testing.T) {
	srv, audit, cookie := legacyAdminDashboardServer(t)
	legacy := wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
	rec := performDashboardRequest(legacy.srv, http.MethodGet, backupsPagePath, legacy.cookie)
	body := rec.Body.String()
	if rec.Code != http.StatusOK || !strings.Contains(body, "engram-backups/prod/") {
		t.Fatalf("legacy admin must see the read-only card, got %d body=%q", rec.Code, body)
	}
	for _, forbidden := range []string{"/destination/remove", "backup-remove", "Yes, remove destination"} {
		if strings.Contains(body, forbidden) {
			t.Fatalf("legacy admin must not see %q", forbidden)
		}
	}

	srv, audit, cookie = memberDashboardServer(t)
	member := wireBackupFixture(t, srv, audit, cookie, configuredBackupSettings())
	rec = performDashboardRequest(member.srv, http.MethodGet, backupsPagePath, member.cookie)
	if rec.Code == http.StatusOK || strings.Contains(rec.Body.String(), "/destination/remove") {
		t.Fatalf("a member must not get the backups page or a remove control, got %d body=%q", rec.Code, rec.Body.String())
	}
}
