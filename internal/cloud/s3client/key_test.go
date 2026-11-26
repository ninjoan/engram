package s3client

import (
	"strings"
	"testing"
	"time"
)

func TestBackupObjectKeyFormatting(t *testing.T) {
	at := time.Date(2026, 11, 25, 3, 4, 5, 987654321, time.UTC)
	lima := time.Date(2026, 11, 24, 22, 4, 5, 0, time.FixedZone("Lima", -5*3600))
	const name = "engram-cloud-backup-20261125T030405Z.tar.gz"

	cases := []struct {
		prefix string
		at     time.Time
		want   string
	}{
		{"backups", at, "backups/" + name},
		{"/backups/", at, "backups/" + name},
		{"", at, name},
		{"/", at, name},
		{"///", at, name},
		{"a//b///", at, "a/b/" + name},
		{"//team/prod/engram//", at, "team/prod/engram/" + name},
		{"  team/prod  ", at, "team/prod/" + name},
		{"backups", lima, "backups/" + name},
	}
	for _, tc := range cases {
		got := BackupObjectKey(tc.prefix, tc.at)
		if got != tc.want {
			t.Errorf("BackupObjectKey(%q, %s) = %q, want %q", tc.prefix, tc.at, got, tc.want)
			continue
		}
		if strings.Contains(got, "//") || strings.HasPrefix(got, "/") {
			t.Errorf("BackupObjectKey(%q) = %q has a leading or double slash", tc.prefix, got)
		}
		if err := validateKey(got); err != nil {
			t.Errorf("BackupObjectKey(%q) = %q is not a valid object key: %v", tc.prefix, got, err)
		}
	}
}
