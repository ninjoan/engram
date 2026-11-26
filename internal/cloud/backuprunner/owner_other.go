//go:build !unix

package backuprunner

import "os"

// ownedByCurrentUser reports true: outside Unix the temp directory is
// private to the user (per-user %TEMP% on Windows), so every file in it is
// treated as this user's.
func ownedByCurrentUser(os.FileInfo) bool { return true }
