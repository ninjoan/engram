package dashboard

import (
	"slices"
	"strings"
	"testing"
	"time"
)

func TestBackupTimezoneNamesAreCanonicalLoadableAndUnique(t *testing.T) {
	if len(backupTimezoneNames) < 300 {
		t.Fatalf("curated list has %d zones, want the IANA region zones", len(backupTimezoneNames))
	}
	seen := map[string]bool{}
	for _, name := range backupTimezoneNames {
		region, _, ok := strings.Cut(name, "/")
		if !ok || !slices.Contains(backupTimezoneRegions, region) {
			t.Fatalf("zone %q is not in a listed region", name)
		}
		if seen[name] {
			t.Fatalf("zone %q is listed twice", name)
		}
		seen[name] = true
		if _, err := time.LoadLocation(name); err != nil {
			t.Fatalf("zone %q does not load: %v", name, err)
		}
	}
	if seen["UTC"] {
		t.Fatalf("UTC is rendered first on its own, not in a region")
	}
}

func TestBackupTimezoneGroupsDropZonesThisServerCannotLoad(t *testing.T) {
	groups := backupTimezoneGroups([]string{"Europe/Madrid", "Nowhere/Fake", "America/Lima", "Africa/Atlantis_Gone"}, "America/Lima", novemberNow)
	var got []string
	for _, g := range groups {
		for _, o := range g.Options {
			label := g.Region + ":" + o.Value + "=" + o.Label
			if o.Selected {
				label += "*"
			}
			got = append(got, label)
		}
	}
	want := []string{
		":UTC=UTC (UTC+00:00)",
		"America:America/Lima=America/Lima (UTC−05:00)*",
		"Europe:Europe/Madrid=Europe/Madrid (UTC+01:00)",
	}
	if strings.Join(got, "|") != strings.Join(want, "|") {
		t.Fatalf("groups = %q, want %q", got, want)
	}
}

func TestBackupTimezoneOffsetLabel(t *testing.T) {
	for _, tc := range []struct {
		zone string
		want string
	}{
		{"UTC", "UTC (UTC+00:00)"},
		{"America/St_Johns", "America/St_Johns (UTC−03:30)"},
		{"Asia/Kathmandu", "Asia/Kathmandu (UTC+05:45)"},
		{"Pacific/Kiritimati", "Pacific/Kiritimati (UTC+14:00)"},
		{"Pacific/Pago_Pago", "Pacific/Pago_Pago (UTC−11:00)"},
	} {
		loc, err := time.LoadLocation(tc.zone)
		if err != nil {
			t.Fatalf("load %s: %v", tc.zone, err)
		}
		if got := backupTimezoneLabel(tc.zone, loc, novemberNow); got != tc.want {
			t.Fatalf("label(%s) = %q, want %q", tc.zone, got, tc.want)
		}
	}
}
