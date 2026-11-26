//go:build unix

package backuprunner

import (
	"os"
	"syscall"
)

// ownedByCurrentUser reports whether info (from lstat) belongs to the user
// this process runs as.
func ownedByCurrentUser(info os.FileInfo) bool {
	stat, ok := info.Sys().(*syscall.Stat_t)
	return ok && int64(stat.Uid) == int64(os.Getuid())
}
