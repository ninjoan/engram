package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"testing"
)

// The asset URL changes whenever the file content changes, so a CDN or browser
// never pairs new HTML with a stylesheet or script cached from an older build.
func TestStaticURLCarriesContentHash(t *testing.T) {
	for _, name := range []string{"styles.css", "pico.min.css", "htmx.min.js", "backups-wizard.js"} {
		body, err := StaticFS.ReadFile("static/" + name)
		if err != nil {
			t.Fatalf("read %s: %v", name, err)
		}
		sum := sha256.Sum256(body)
		want := "/dashboard/static/" + name + "?v=" + hex.EncodeToString(sum[:])[:12]
		if got := StaticURL(name); got != want {
			t.Fatalf("StaticURL(%q) = %q, want %q", name, got, want)
		}
	}
	if got := StaticURL("missing.css"); got != "/dashboard/static/missing.css" {
		t.Fatalf("unknown asset url = %q, want the plain path", got)
	}
}

func TestLayoutReferencesVersionedAssets(t *testing.T) {
	for _, src := range []string{"layout.templ", "login.templ", "backups.templ"} {
		body, err := readTemplSource(src)
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(body, `"/dashboard/static/`) {
			t.Fatalf("%s still links an unversioned /dashboard/static/ asset; use StaticURL", src)
		}
	}
}
