package dashboard

import (
	"strings"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var backupStatusNow = time.Date(2026, 11, 26, 18, 15, 0, 0, time.UTC)

func statusBackupsView(test cloudstore.BackupDestinationTest, runs cloudstore.BackupRunOutcomes) BackupsPageView {
	v := readyBackupsView(configuredR2Destination())
	v.Now = backupStatusNow
	v.DestinationTest = test
	v.LastRuns = runs
	return v
}

func testedAt(succeeded bool, reason string) cloudstore.BackupDestinationTest {
	return cloudstore.BackupDestinationTest{
		OccurredAt: time.Date(2026, 11, 26, 18, 10, 0, 0, time.UTC), ActorPrincipalID: "7", ActorName: "ninjoan",
		Succeeded: succeeded, ReasonCode: reason,
	}
}

func assertBackupMarkers(t *testing.T, body string, want, forbidden []string) {
	t.Helper()
	for _, marker := range want {
		if !strings.Contains(body, marker) {
			t.Fatalf("expected marker %q, body=%q", marker, body)
		}
	}
	for _, marker := range forbidden {
		if strings.Contains(body, marker) {
			t.Fatalf("must not render %q, body=%q", marker, body)
		}
	}
}

func TestAdminBackupsStatusCardConnected(t *testing.T) {
	body := renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{}))
	assertBackupMarkers(t, body, []string{
		`<h4 class="backup-summary-title">Cloudflare R2 <span class="backup-pill is-connected">Connected</span></h4>`,
		"Last tested",
		`<time datetime="2026-11-26T18:10:00Z">5 min ago</time>`,
		"(2026-11-26 18:10 UTC)",
		"by ninjoan",
		"the bucket was listed with the saved keys",
		`<button type="submit" class="secondary">Test again</button>`,
	}, []string{"is-failing", "is-untested", "Failing", `badge badge-success">Configured`})
}

func TestAdminBackupsStatusCardFailingNamesTheReason(t *testing.T) {
	cases := map[string]string{
		"auth_failed":         "Keys rejected.",
		"bucket_not_found":    "Bucket not found.",
		"network":             "Endpoint unreachable.",
		"key_mismatch":        "Saved keys cannot be opened.",
		"unexpected_response": "Unexpected response.",
		"something_new":       "Connection test failed.",
	}
	for reason, title := range cases {
		t.Run(reason, func(t *testing.T) {
			body := renderBackupsPageForTest(t, statusBackupsView(testedAt(false, reason), cloudstore.BackupRunOutcomes{}))
			assertBackupMarkers(t, body, []string{
				`<span class="backup-pill is-failing">Failing</span>`,
				`<div class="backup-status-line"><p><strong>` + title + `</strong>`,
				`<time datetime="2026-11-26T18:10:00Z">5 min ago</time>`,
				`<button type="submit" class="secondary">Test again</button>`,
			}, []string{"is-connected", "is-untested"})
		})
	}
}

func TestAdminBackupsStatusCardNotTested(t *testing.T) {
	// The store reports no test since the last update for both a destination
	// that was never tested and one saved again after a test.
	body := renderBackupsPageForTest(t, statusBackupsView(cloudstore.BackupDestinationTest{}, cloudstore.BackupRunOutcomes{}))
	assertBackupMarkers(t, body, []string{
		`<span class="backup-pill is-untested">Not tested</span>`,
		"Not tested since it was saved",
		`<button type="submit">Test connection</button>`,
	}, []string{"is-connected", "is-failing", "Last tested", "Test again"})
}

func TestAdminBackupsStatusCardKeyMissingIsLockedWithoutControls(t *testing.T) {
	v := statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{})
	v.Settings = BackupSettingsKeyMissing
	body := renderBackupsPageForTest(t, v)
	assertBackupMarkers(t, body, []string{
		`<span class="backup-pill is-locked">Locked</span>`,
		"engram-cloud-backup-&lt;yyyymmddThhmmssZ&gt;-run&lt;id&gt;.tar.gz",
	}, []string{"is-connected", `action="/dashboard/admin/backups/destination`, "Test again", "<details"})
}

func TestAdminBackupsStatusCardReadOnlyShowsStatusWithoutControls(t *testing.T) {
	v := statusBackupsView(testedAt(false, "network"), cloudstore.BackupRunOutcomes{})
	v.CanManage = false
	body := renderBackupsPageForTest(t, v)
	assertBackupMarkers(t, body, []string{
		`<span class="backup-pill is-failing">Failing</span>`, "Endpoint unreachable.",
	}, []string{`action="/dashboard/admin/backups/destination`, "Test again", "Test connection</button>", "<details"})
}

func TestAdminBackupsStatusCardShowsTheExactObjectPath(t *testing.T) {
	body := renderBackupsPageForTest(t, statusBackupsView(cloudstore.BackupDestinationTest{}, cloudstore.BackupRunOutcomes{}))
	assertBackupMarkers(t, body, []string{
		`<div class="backup-path-strip" role="group" aria-label="Where the next backup lands">`,
		`<span class="backup-path-bucket">engram-backups/</span>`,
		`<span class="backup-path-prefix">prod/</span>`,
		`<span class="backup-path-file">engram-cloud-backup-&lt;yyyymmddThhmmssZ&gt;-run&lt;id&gt;.tar.gz</span>`,
	}, nil)

	d := configuredR2Destination()
	d.Prefix = ""
	v := readyBackupsView(d)
	body = renderBackupsPageForTest(t, v)
	strip := body[strings.Index(body, `class="backup-path-strip"`):]
	strip = strip[:strings.Index(strip, "</div>")]
	if strings.Contains(strip, "backup-path-prefix") {
		t.Fatalf("without a prefix the path strip has no prefix segment: %q", strip)
	}
}

func TestAdminBackupsStatusCardLastUploadAndFailure(t *testing.T) {
	success := cloudstore.BackupRun{ID: 12, Status: cloudstore.BackupRunStatusSuccess, ObjectKey: "prod/engram-cloud-backup-20261126T080000Z-run12.tar.gz", SizeBytes: 4096, FinishedAt: time.Date(2026, 11, 26, 8, 1, 0, 0, time.UTC)}
	failure := cloudstore.BackupRun{ID: 13, Status: cloudstore.BackupRunStatusFailure, ErrorMessage: "upload failed: endpoint unreachable", FinishedAt: time.Date(2026, 11, 26, 16, 0, 0, 0, time.UTC)}

	body := renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{LastSuccess: success, LastFailure: failure}))
	assertBackupMarkers(t, body, []string{
		"<dt>Last upload</dt>",
		`badge badge-success">success`,
		`<time datetime="2026-11-26T08:01:00Z">10 h ago</time>`,
		"(2026-11-26 08:01 UTC)",
		"4.0 KiB",
		"<code>prod/engram-cloud-backup-20261126T080000Z-run12.tar.gz</code>",
		"<dt>Last failure</dt>",
		`badge badge-danger">failure`,
		`<time datetime="2026-11-26T16:00:00Z">2 h ago</time>`,
		"upload failed: endpoint unreachable",
	}, nil)

	// A failure older than the last success is not shown.
	failure.FinishedAt = time.Date(2026, 11, 25, 8, 0, 0, 0, time.UTC)
	body = renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{LastSuccess: success, LastFailure: failure}))
	assertBackupMarkers(t, body, []string{"<dt>Last upload</dt>", "4.0 KiB"}, []string{"<dt>Last failure</dt>", "upload failed: endpoint unreachable"})

	// No run at all.
	body = renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{}))
	assertBackupMarkers(t, body, []string{"<dt>Last upload</dt>", "<dd>None yet</dd>"}, []string{"<dt>Last failure</dt>"})

	// Only failures: the failure shows next to "None yet".
	failure.ErrorMessage = "skipped: no destination"
	body = renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{LastFailure: failure}))
	assertBackupMarkers(t, body, []string{"<dd>None yet</dd>", "<dt>Last failure</dt>", "skipped: no destination", "1 day ago"}, nil)
}

func TestAdminBackupsStatusCardRemoveIsAConfirmInsideChangeDestination(t *testing.T) {
	body := renderBackupsPageForTest(t, statusBackupsView(testedAt(true, ""), cloudstore.BackupRunOutcomes{}))
	change := strings.Index(body, `<details class="backup-change">`)
	danger := strings.Index(body, `<details class="backup-danger-zone">`)
	remove := strings.Index(body, `action="/dashboard/admin/backups/destination/remove"`)
	if change < 0 || danger < change || remove < danger {
		t.Fatalf("remove must sit in a confirm disclosure inside Change destination (change %d, danger %d, remove %d)", change, danger, remove)
	}
	assertBackupMarkers(t, body, []string{
		"<summary>Remove destination…</summary>",
		"Stop uploading to <strong>engram-backups</strong>?",
	}, nil)
}

func TestBackupRelativeTime(t *testing.T) {
	now := backupStatusNow
	cases := []struct {
		at   time.Time
		want string
	}{
		{now.Add(-20 * time.Second), "just now"},
		{now.Add(time.Minute), "just now"},
		{now.Add(-time.Minute), "1 min ago"},
		{now.Add(-59 * time.Minute), "59 min ago"},
		{now.Add(-time.Hour), "1 h ago"},
		{now.Add(-23 * time.Hour), "23 h ago"},
		{now.Add(-24 * time.Hour), "1 day ago"},
		{now.Add(-72 * time.Hour), "3 days ago"},
	}
	for _, tc := range cases {
		if got := backupRelativeTime(tc.at, now); got != tc.want {
			t.Fatalf("backupRelativeTime(%v) = %q, want %q", now.Sub(tc.at), got, tc.want)
		}
	}
}
