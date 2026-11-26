package s3client

import (
	"fmt"
	"strings"
	"time"
	"unicode/utf8"
)

const maxKeyBytes = 1024

// BackupObjectKey returns "<prefix>/engram-cloud-backup-YYYYMMDDTHHMMSSZ.tar.gz"
// for t in UTC. Surrounding spaces and empty path segments in prefix are
// dropped, so the key never starts with "/" or contains "//".
func BackupObjectKey(prefix string, t time.Time) string {
	name := "engram-cloud-backup-" + t.UTC().Format(amzDateFormat) + ".tar.gz"
	var segments []string
	for _, s := range strings.Split(strings.TrimSpace(prefix), "/") {
		if s != "" {
			segments = append(segments, s)
		}
	}
	return strings.Join(append(segments, name), "/")
}

// validateKey rejects keys that are ambiguous in a path-style URL or that
// servers may normalize differently from the signed canonical URI.
func validateKey(key string) error {
	switch {
	case key == "":
		return fmt.Errorf("%w: key is empty", ErrInvalidKey)
	case len(key) > maxKeyBytes:
		return fmt.Errorf("%w: key exceeds %d bytes", ErrInvalidKey, maxKeyBytes)
	case !utf8.ValidString(key):
		return fmt.Errorf("%w: key is not valid UTF-8", ErrInvalidKey)
	}
	for _, r := range key {
		if r < 0x20 || r == 0x7f {
			return fmt.Errorf("%w: key contains a control character", ErrInvalidKey)
		}
	}
	for _, segment := range strings.Split(key, "/") {
		switch segment {
		case "":
			return fmt.Errorf("%w: key has an empty path segment (leading, trailing or double slash)", ErrInvalidKey)
		case ".", "..":
			return fmt.Errorf("%w: key has a %q path segment", ErrInvalidKey, segment)
		}
	}
	return nil
}
