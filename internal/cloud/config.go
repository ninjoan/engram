package cloud

import (
	"errors"
	"net"
	"net/url"
	"os"
	"strconv"
	"strings"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
)

type Config struct {
	DSN              string
	JWTSecret        string
	CORSOrigins      []string
	MaxPool          int
	Port             int
	BindHost         string
	AdminToken       string
	AllowedProjects  []string
	MaxPushBodyBytes int64
	// StartupReceiptDir opts in to a startup proof cache in a private
	// directory. The audit feed is provisioned separately.
	StartupReceiptDir string
	// TokenPepper is the dedicated secret used to hash managed cloud tokens
	// (see internal/cloud/auth.ManagedTokenHasher). It MUST be distinct from
	// JWTSecret so rotating the dashboard/session signing secret does not
	// implicitly rotate or invalidate stored managed token verifiers.
	TokenPepper string
	// BackupKey is the dedicated key (ENGRAM_CLOUD_BACKUP_KEY, 32 bytes as
	// base64 or hex) that seals backup destination credentials at rest. It
	// MUST be distinct from JWTSecret and TokenPepper so rotating either of
	// those never changes whether stored destination credentials can be
	// opened. Nil means the variable is unset and external backup
	// destinations are disabled. The key never formats its bytes.
	BackupKey *backupcrypto.Key
	// BackupKeyError reports a set but invalid ENGRAM_CLOUD_BACKUP_KEY.
	// Callers that use backup destinations must fail loudly on it rather
	// than treating the feature as disabled. It never contains the key.
	BackupKeyError error
	// PublicURL is the dashboard's public origin (ENGRAM_CLOUD_PUBLIC_URL),
	// normalized to scheme://host[:port]: https, or http only for a loopback
	// host. It is the base of the Google Drive OAuth redirect URI, which is
	// never derived from request headers. Empty means unset: the dashboard
	// cannot offer "Connect with Google".
	PublicURL string
	// PublicURLError reports a set but invalid ENGRAM_CLOUD_PUBLIC_URL.
	// cloud serve refuses to start on it rather than dropping the value.
	PublicURLError error
}

// ErrInvalidPublicURL is the PublicURLError of an unusable
// ENGRAM_CLOUD_PUBLIC_URL.
var ErrInvalidPublicURL = errors.New("ENGRAM_CLOUD_PUBLIC_URL must be the dashboard's public origin, such as https://engram.example.com: https (http only for localhost or a loopback IP), no path, query, fragment or user info")

// ParsePublicURL validates a public origin and normalizes it to
// scheme://host[:port] with a lowercase scheme and host. Errors wrap
// ErrInvalidPublicURL and never echo the value.
func ParsePublicURL(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(raw, "#") ||
		(u.Path != "" && u.Path != "/") || u.Hostname() == "" {
		return "", ErrInvalidPublicURL
	}
	scheme := strings.ToLower(u.Scheme)
	host := strings.ToLower(u.Hostname())
	if strings.ContainsAny(host, " \t%") {
		return "", ErrInvalidPublicURL
	}
	switch scheme {
	case "https":
	case "http":
		if !isLoopbackHost(host) {
			return "", ErrInvalidPublicURL
		}
	default:
		return "", ErrInvalidPublicURL
	}
	hostport := host
	if strings.Contains(host, ":") {
		hostport = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 {
			return "", ErrInvalidPublicURL
		}
		hostport += ":" + port
	} else if strings.HasSuffix(u.Host, ":") {
		return "", ErrInvalidPublicURL
	}
	return scheme + "://" + hostport, nil
}

func isLoopbackHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

const DefaultJWTSecret = "engram-dev-jwt-secret-for-local-smoke-1234"
const DefaultMaxPushBodyBytes int64 = 8 * 1024 * 1024

func DefaultConfig() Config {
	return Config{
		DSN:              "postgres://engram:engram_dev@localhost:5433/engram_cloud?sslmode=disable",
		JWTSecret:        DefaultJWTSecret,
		CORSOrigins:      []string{"*"},
		MaxPool:          10,
		Port:             8080,
		BindHost:         "127.0.0.1",
		MaxPushBodyBytes: DefaultMaxPushBodyBytes,
	}
}

func IsDefaultJWTSecret(secret string) bool {
	return strings.TrimSpace(secret) == DefaultJWTSecret
}

func ConfigFromEnv() Config {
	cfg := DefaultConfig()
	cfg.StartupReceiptDir = strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_STARTUP_RECEIPT_DIR"))
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_BACKUP_KEY")); v != "" {
		cfg.BackupKey, cfg.BackupKeyError = backupcrypto.ParseKey(v)
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_PUBLIC_URL")); v != "" {
		cfg.PublicURL, cfg.PublicURLError = ParsePublicURL(v)
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_DATABASE_URL")); v != "" {
		cfg.DSN = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_JWT_SECRET")); v != "" {
		cfg.JWTSecret = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_ADMIN")); v != "" {
		cfg.AdminToken = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_TOKEN_PEPPER")); v != "" {
		cfg.TokenPepper = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_PORT")); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			cfg.Port = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_HOST")); v != "" {
		cfg.BindHost = v
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_MAX_PUSH_BYTES")); v != "" {
		if n, err := strconv.ParseInt(v, 10, 64); err == nil && n > 0 {
			cfg.MaxPushBodyBytes = n
		}
	}
	if v := strings.TrimSpace(os.Getenv("ENGRAM_CLOUD_ALLOWED_PROJECTS")); v != "" {
		parts := strings.Split(v, ",")
		projects := make([]string, 0, len(parts))
		seen := make(map[string]struct{})
		for _, part := range parts {
			project := strings.TrimSpace(part)
			if project == "" {
				continue
			}
			if _, ok := seen[project]; ok {
				continue
			}
			seen[project] = struct{}{}
			projects = append(projects, project)
		}
		cfg.AllowedProjects = projects
	}
	return cfg
}
