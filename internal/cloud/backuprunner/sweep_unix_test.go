//go:build unix

package backuprunner

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// The startup sweep removes a hard link named like an upload temp file (only
// that name; the other link keeps the data) and leaves a FIFO alone.
func TestStartSweepRemovesHardLinkNamesAndKeepsFIFOs(t *testing.T) {
	h := newHarness(t, beforeSlot, nil)
	target := filepath.Join(t.TempDir(), "kept.tar.gz")
	writeTestFile(t, target)
	hardLink := filepath.Join(h.tempDir, "engram-cloud-backup-upload-hardlink.tar.gz")
	if err := os.Link(target, hardLink); err != nil {
		t.Skipf("hard links across the test temp dirs: %v", err)
	}
	fifo := filepath.Join(h.tempDir, "engram-cloud-backup-upload-fifo.tar.gz")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}
	fifoDir := filepath.Join(h.tempDir, "engram-cloud-backup-export-fifo")
	if err := syscall.Mkfifo(fifoDir, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	h.start(t)
	h.clock.waitSleeping(t)

	if _, err := os.Lstat(hardLink); !os.IsNotExist(err) {
		t.Errorf("hard link %s was not removed (%v)", hardLink, err)
	}
	if data, err := os.ReadFile(target); err != nil || string(data) != "plaintext archive" {
		t.Errorf("hard link target changed: %q %v", data, err)
	}
	for _, path := range []string{fifo, fifoDir} {
		if info, err := os.Lstat(path); err != nil || info.Mode()&os.ModeNamedPipe == 0 {
			t.Errorf("FIFO %s changed: %v %v", path, info, err)
		}
	}
}
