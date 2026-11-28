package dashboard

import (
	"slices"
	"strings"
	"testing"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const backupRemoveAction = `action="/dashboard/admin/backups/destination/remove"`

// removeBackupsView is a managed admin with the backup key set and a stored
// destination: the only state that may remove it.
func removeBackupsView() BackupsPageView {
	v := readyBackupsView(configuredR2Destination())
	v.Tables, v.Exclusions = cloudstore.BackupTables(), cloudstore.BackupExclusions()
	return v
}

func TestAdminBackupsStatusCardHasAVisibleRemoveWithConfirmStep(t *testing.T) {
	body := renderBackupsPageForTest(t, removeBackupsView())
	assertBackupMarkers(t, body, []string{
		`<details class="backup-remove"><summary class="backup-remove-toggle">Remove destination</summary>`,
		`<form method="post" action="/dashboard/admin/backups/destination/remove" class="backup-confirm">`,
		"<strong>Remove this destination?</strong>",
		"Engram stops uploading to <strong>engram-backups</strong> and deletes the saved keys.",
		"Backups already uploaded stay in the bucket.",
		"each scheduled run is recorded as skipped until you save a new destination",
		`<button type="submit" class="backup-danger-fill">Yes, remove destination</button>`,
	}, []string{`<details class="backup-remove" open`, "backup-danger-zone", "Remove destination…"})
	if n := strings.Count(body, backupRemoveAction); n != 1 {
		t.Fatalf("the page must hold exactly one remove form, got %d", n)
	}
	// The remove control sits on the status card, before and outside the
	// collapsed Change destination form.
	remove := strings.Index(body, `<details class="backup-remove">`)
	facts := strings.Index(body, `<dl class="backup-facts backup-run-facts">`)
	change := strings.Index(body, `<details class="backup-change">`)
	if facts < 0 || remove < facts || change < remove {
		t.Fatalf("remove must follow the card facts and precede Change destination (facts %d, remove %d, change %d)", facts, remove, change)
	}
	if form := strings.Index(body, backupRemoveAction); form < remove || form > change {
		t.Fatalf("the remove form must be inside the card's confirm step (remove %d, form %d, change %d)", remove, form, change)
	}
}

func TestAdminBackupsRemoveIsAbsentWithoutTheRightToEdit(t *testing.T) {
	keyMissing := removeBackupsView()
	keyMissing.Settings = BackupSettingsKeyMissing
	legacy := removeBackupsView()
	legacy.CanManage = false
	unconfigured := readyBackupsView(cloudstore.BackupDestination{})
	unavailable := removeBackupsView()
	unavailable.Settings = BackupSettingsUnavailable
	cases := map[string]BackupsPageView{
		"key missing":    keyMissing,
		"legacy admin":   legacy,
		"no destination": unconfigured,
		"unavailable":    unavailable,
	}
	for name, v := range cases {
		t.Run(name, func(t *testing.T) {
			body := renderBackupsPageForTest(t, v)
			assertBackupMarkers(t, body, nil, []string{backupRemoveAction, "backup-remove", "Remove destination", "Yes, remove destination"})
		})
	}
}

func TestAdminBackupsContentsArePlainLanguageGroups(t *testing.T) {
	body := renderBackupsPageForTest(t, removeBackupsView())
	assertBackupMarkers(t, body, []string{
		`<h3 class="section-block-title">What a backup contains</h3>`,
		`<h4 id="backup-included-title">Included</h4>`,
		`<span class="backup-contents-mark" aria-hidden="true">✓</span><span class="backup-contents-text"><strong>Memories and sessions of every project</strong></span>`,
		`<span class="backup-contents-mark" aria-hidden="true">✓</span><span class="backup-contents-text"><strong>Users, permissions and project pauses</strong></span>`,
		`<span class="backup-contents-mark" aria-hidden="true">✓</span><span class="backup-contents-text"><strong>Audit logs</strong></span>`,
		`<h4 id="backup-excluded-title">Never included</h4>`,
		`<span class="backup-contents-mark" aria-hidden="true">✕</span><span class="backup-contents-text"><strong>Tokens and passwords</strong> — managed tokens are re-issued after a restore</span>`,
		`<span class="backup-contents-mark" aria-hidden="true">✕</span><span class="backup-contents-text"><strong>Backup destination, schedule and run history</strong> — configure them again after a restore</span>`,
		`<span class="backup-contents-mark" aria-hidden="true">✕</span><span class="backup-contents-text"><strong>Server secrets</strong><span> (environment variables such as <code>ENGRAM_CLOUD_TOKEN_PEPPER</code></span><span>, <code>ENGRAM_JWT_SECRET</code></span><span>, <code>ENGRAM_CLOUD_BACKUP_KEY</code>)</span></span>`,
		// The plaintext warning and the operator-only restore note stay.
		"The archive holds plaintext memories.",
		"Restoring is operator-only: run <code>engram cloud backup import</code>",
	}, []string{`<h3 class="section-block-title">Included</h3>`, `<h3 class="section-block-title">Never included</h3>`, "Environment secrets such as"})
	if included, excluded := strings.Count(body, "✓</span>"), strings.Count(body, "✕</span>"); included != 3 || excluded != 3 {
		t.Fatalf("expected 3 included and 3 never-included items, got %d and %d", included, excluded)
	}
	// The plain summary comes before the technical lists.
	if summary, details := strings.Index(body, "Memories and sessions of every project"), strings.Index(body, `<details class="tech-details">`); summary < 0 || details < summary {
		t.Fatalf("the plain summary must precede the technical details (summary %d, details %d)", summary, details)
	}
}

func TestAdminBackupsTechnicalDetailsAreCollapsedWithCounts(t *testing.T) {
	v := removeBackupsView()
	body := renderBackupsPageForTest(t, v)
	assertBackupMarkers(t, body, []string{
		`<details class="tech-details"><summary>Technical details (13 tables included, 9 exclusions)</summary>`,
	}, []string{`<details class="tech-details" open`})
	details := body[strings.Index(body, `<details class="tech-details">`):]
	details = details[:strings.Index(details, "</details>")]
	for _, table := range v.Tables {
		if !strings.Contains(details, "<td><code>"+table+"</code></td>") {
			t.Fatalf("technical details must list table %q, details=%q", table, details)
		}
	}
	for _, e := range v.Exclusions {
		row := "<td><code>" + e.Table + "</code></td><td>" + emptyDash(e.Column) + "</td><td>" + e.Reason + "</td>"
		if !strings.Contains(details, row) {
			t.Fatalf("technical details must list exclusion %q, details=%q", row, details)
		}
	}

	// The counts and the groups come from the lists the page is given.
	v.Tables = []string{"cloud_chunks"}
	v.Exclusions = []cloudstore.BackupExclusion{{Table: "cloud_principal_tokens", Reason: "credential table"}}
	body = renderBackupsPageForTest(t, v)
	assertBackupMarkers(t, body, []string{
		"<summary>Technical details (1 table included, 1 exclusion)</summary>",
		"<strong>Memories and sessions of every project</strong>",
		"<strong>Tokens and passwords</strong>",
		"<strong>Server secrets</strong>",
	}, []string{"Users, permissions and project pauses", "Audit logs", "Backup destination, schedule and run history"})
}

// Every table a backup carries and every exclusion must map to exactly one
// plain-language group, so the summary cannot drift from cloudstore: adding
// a table or an exclusion without a group fails here.
func TestBackupContentsMappingCoversEveryTableAndExclusion(t *testing.T) {
	groupIDs := func(groups []backupContentGroup) map[string]int {
		ids := map[string]int{}
		for _, g := range groups {
			ids[g.ID]++
		}
		return ids
	}
	included, excluded := groupIDs(backupIncludedGroups), groupIDs(backupExcludedGroups)
	for id, n := range included {
		if n != 1 || excluded[id] != 0 {
			t.Fatalf("group %q must be defined exactly once and only on one side", id)
		}
	}
	for id, n := range excluded {
		if n != 1 {
			t.Fatalf("group %q must be defined exactly once", id)
		}
	}

	tables := cloudstore.BackupTables()
	members := map[string]int{}
	for _, table := range tables {
		group, ok := backupTableGroups[table]
		if !ok || included[group] != 1 {
			t.Fatalf("backup table %q has no included group (got %q)", table, group)
		}
		members[group]++
	}
	for table := range backupTableGroups {
		if !slices.Contains(tables, table) {
			t.Fatalf("group mapping names %q, which is not a backup table", table)
		}
	}

	exclusions := cloudstore.BackupExclusions()
	keys := map[string]bool{}
	for _, e := range exclusions {
		key := backupExclusionKey(e)
		if keys[key] {
			t.Fatalf("two exclusions share the key %q", key)
		}
		keys[key] = true
		group, ok := backupExclusionGroups[key]
		if !ok || excluded[group] != 1 {
			t.Fatalf("backup exclusion %q has no never-included group (got %q)", key, group)
		}
		members[group]++
	}
	for key := range backupExclusionGroups {
		if !keys[key] {
			t.Fatalf("group mapping names %q, which is not a backup exclusion", key)
		}
	}

	// Every group the page can show is backed by real data, except the
	// server secrets, which live in the environment and never in a table.
	for _, g := range append(slices.Clone(backupIncludedGroups), backupExcludedGroups...) {
		if len(g.EnvVars) > 0 {
			continue
		}
		if members[g.ID] == 0 {
			t.Fatalf("group %q has no table or exclusion behind it", g.ID)
		}
	}
}
