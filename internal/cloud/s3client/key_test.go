package s3client

import (
	"strings"
	"testing"
	"time"
)

func TestBackupRunObjectKeyFormatting(t *testing.T) {
	at := time.Date(2026, 11, 25, 3, 4, 5, 987654321, time.UTC)
	lima := time.Date(2026, 11, 24, 22, 4, 5, 0, time.FixedZone("Lima", -5*3600))
	const name = "engram-cloud-backup-20261125T030405Z-run7.tar.gz"

	cases := []struct {
		prefix string
		at     time.Time
		runID  int64
		want   string
	}{
		{"backups", at, 7, "backups/" + name},
		{"/backups/", at, 7, "backups/" + name},
		{"", at, 7, name},
		{"/", at, 7, name},
		{"///", at, 7, name},
		{"a//b///", at, 7, "a/b/" + name},
		{"//team/prod/engram//", at, 7, "team/prod/engram/" + name},
		{"  team/prod  ", at, 7, "team/prod/" + name},
		{"backups", lima, 7, "backups/" + name},
		{"backups", at, 1234567890123, "backups/engram-cloud-backup-20261125T030405Z-run1234567890123.tar.gz"},
	}
	for _, tc := range cases {
		got := BackupRunObjectKey(tc.prefix, tc.at, tc.runID)
		if got != tc.want {
			t.Errorf("BackupRunObjectKey(%q, %s, %d) = %q, want %q", tc.prefix, tc.at, tc.runID, got, tc.want)
			continue
		}
		if strings.Contains(got, "//") || strings.HasPrefix(got, "/") {
			t.Errorf("BackupRunObjectKey(%q) = %q has a leading or double slash", tc.prefix, got)
		}
		if err := validateKey(got); err != nil {
			t.Errorf("BackupRunObjectKey(%q) = %q is not a valid object key: %v", tc.prefix, got, err)
		}
	}
}

// Two runs in the same second get distinct keys.
func TestBackupRunObjectKeyIsDistinctPerRunInTheSameSecond(t *testing.T) {
	at := time.Date(2026, 11, 25, 3, 4, 5, 0, time.UTC)
	first := BackupRunObjectKey("prod", at, 41)
	second := BackupRunObjectKey("prod", at.Add(900*time.Millisecond), 42)
	if first == second {
		t.Fatalf("two runs in the same second share the key %q", first)
	}
}
