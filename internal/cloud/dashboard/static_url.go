package dashboard

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
)

var (
	staticVersionsOnce sync.Once
	staticVersions     map[string]string
)

// StaticURL returns the URL of an embedded dashboard asset with a short hash of
// its content as the v query parameter. Every build that changes the file gets
// a new URL, so a CDN or browser cache can never serve a stale stylesheet or
// script next to newer HTML. The file server ignores the query string.
func StaticURL(name string) string {
	staticVersionsOnce.Do(loadStaticVersions)
	path := "/dashboard/static/" + name
	if v, ok := staticVersions[name]; ok {
		return path + "?v=" + v
	}
	return path
}

func loadStaticVersions() {
	staticVersions = map[string]string{}
	entries, err := StaticFS.ReadDir("static")
	if err != nil {
		return
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		body, err := StaticFS.ReadFile("static/" + entry.Name())
		if err != nil {
			continue
		}
		sum := sha256.Sum256(body)
		staticVersions[entry.Name()] = hex.EncodeToString(sum[:])[:12]
	}
}
