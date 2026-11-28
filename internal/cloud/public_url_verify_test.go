package cloud

import (
	"errors"
	"strings"
	"testing"
)

func TestParsePublicURLAcceptsOnlyBareOrigins(t *testing.T) {
	ok := map[string]string{
		"https://engram.example.com":        "https://engram.example.com",
		"https://Engram.Example.com/":       "https://engram.example.com",
		" HTTPS://engram.example.com:8443 ": "https://engram.example.com:8443",
		"http://localhost:18080":            "http://localhost:18080",
		"http://127.0.0.1":                  "http://127.0.0.1",
		"http://[::1]:8080":                 "http://[::1]:8080",
	}
	for in, want := range ok {
		got, err := ParsePublicURL(in)
		if err != nil || got != want {
			t.Errorf("%q -> %q %v want %q", in, got, err, want)
		}
	}
	bad := []string{
		"http://engram.example.com", "http://10.0.0.5", "http://localhost.evil.com", "http://127.0.0.1.nip.io",
		"https://engram.example.com/dash", "https://engram.example.com//", "https://u:p@engram.example.com", "https://u@engram.example.com",
		"https://engram.example.com?x=1", "https://engram.example.com?", "https://engram.example.com#f", "https://engram.example.com#",
		"https://", "engram.example.com", "//engram.example.com", "ftp://engram.example.com", "javascript:alert(1)",
		"https://engram.example.com:0", "https://engram.example.com:99999", "https://engram.example.com:", "https://engram.example.com:abc",
		"https://exa mple.com", "https://ex%41mple.com", "https://evil.com\\@engram.example.com",
	}
	for _, in := range bad {
		got, err := ParsePublicURL(in)
		if !errors.Is(err, ErrInvalidPublicURL) {
			t.Errorf("%q accepted -> %q", in, got)
		}
		if err != nil && strings.Contains(err.Error(), "u:p") {
			t.Errorf("echo")
		}
	}
}

func TestConfigFromEnvRefusesAnInvalidPublicURL(t *testing.T) {
	t.Setenv("ENGRAM_CLOUD_PUBLIC_URL", "https://u:secretpw@x.example.com")
	cfg := ConfigFromEnv()
	if cfg.PublicURL != "" || !errors.Is(cfg.PublicURLError, ErrInvalidPublicURL) || strings.Contains(cfg.PublicURLError.Error(), "secretpw") {
		t.Fatalf("%q %v", cfg.PublicURL, cfg.PublicURLError)
	}
	t.Setenv("ENGRAM_CLOUD_PUBLIC_URL", "  ")
	cfg = ConfigFromEnv()
	if cfg.PublicURL != "" || cfg.PublicURLError != nil {
		t.Fatalf("blank: %q %v", cfg.PublicURL, cfg.PublicURLError)
	}
}
