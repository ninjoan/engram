//go:build unix

package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backuprunner"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

// `engram cloud serve` is stopped with SIGTERM or SIGINT. These tests run
// runCloudServe in a child process (this test binary re-executed with
// TestBackupRunnerSignalHelperProcess) and send it a real signal.

const (
	signalHelperModeEnv   = "ENGRAM_TEST_CLOUD_SERVE_SIGNAL_HELPER"
	signalHelperMarkerEnv = "ENGRAM_TEST_CLOUD_SERVE_SIGNAL_MARKER"
	signalHelperDSNEnv    = "ENGRAM_TEST_CLOUD_SERVE_SIGNAL_DSN"

	signalHelperRuntimeStarted = "SIGNAL HELPER: runtime started"
	signalHelperManualStarted  = "SIGNAL HELPER: manual backup started"
	signalHelperServeReturned  = "SIGNAL HELPER: runCloudServe returned nil"
	signalHelperStartFailure   = "SIGNAL HELPER: flushing the runtime failed"
	signalHelperInitFailure    = "SIGNAL HELPER: initializing the runtime failed"
)

// signalFailingRuntime serves until the startup listener stops, then fails
// for a reason unrelated to the shutdown.
type signalFailingRuntime struct{}

func (signalFailingRuntime) Start(startup *cloudserver.StartupListener) error {
	fmt.Println(signalHelperRuntimeStarted)
	<-startup.InitializationContext().Done()
	return errors.New(signalHelperStartFailure)
}

// signalProbeRuntime serves until the startup listener stops, then leaves a
// marker so the parent can tell the shutdown path ran.
type signalProbeRuntime struct{ marker string }

func (r signalProbeRuntime) Start(startup *cloudserver.StartupListener) error {
	fmt.Println(signalHelperRuntimeStarted)
	ctx := startup.InitializationContext()
	<-ctx.Done()
	if err := os.WriteFile(r.marker, []byte("runtime stopped"), 0o600); err != nil {
		return err
	}
	return context.Cause(ctx)
}

// TestBackupRunnerSignalHelperProcess is the child process; it does nothing
// in a normal test run.
func TestBackupRunnerSignalHelperProcess(t *testing.T) {
	mode := os.Getenv(signalHelperModeEnv)
	if mode == "" {
		return
	}
	cfg := cloud.ConfigFromEnv()
	cfg.BindHost, cfg.Port = "127.0.0.1", 0
	switch mode {
	case "probe":
		newCloudRuntime = func(context.Context, cloud.Config) (cloudServerRuntime, error) {
			return signalProbeRuntime{marker: os.Getenv(signalHelperMarkerEnv)}, nil
		}
	case "start-error":
		newCloudRuntime = func(context.Context, cloud.Config) (cloudServerRuntime, error) {
			return signalFailingRuntime{}, nil
		}
	case "init-error", "init-canceled":
		newCloudRuntime = func(ctx context.Context, _ cloud.Config) (cloudServerRuntime, error) {
			fmt.Println(signalHelperRuntimeStarted)
			<-ctx.Done()
			if mode == "init-canceled" {
				return nil, fmt.Errorf("open store: %w", ctx.Err())
			}
			return nil, errors.New(signalHelperInitFailure)
		}
	case "backup":
		newCloudRuntime = func(_ context.Context, cfg cloud.Config) (cloudServerRuntime, error) {
			cs, err := cloudstore.New(cloud.Config{DSN: os.Getenv(signalHelperDSNEnv)})
			if err != nil {
				return nil, err
			}
			runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
			if err != nil {
				return nil, err
			}
			if runtime.backups == nil {
				return nil, errors.New("the backup runner is not wired")
			}
			go func() {
				for {
					_, err := runtime.backups.StartManualBackup(context.Background(), "")
					if err == nil {
						fmt.Println(signalHelperManualStarted)
						return
					}
					if !errors.Is(err, backuprunner.ErrRunnerStopped) {
						fmt.Println("SIGNAL HELPER: manual backup refused:", err)
						return
					}
					time.Sleep(5 * time.Millisecond)
				}
			}()
			return runtime, nil
		}
	default:
		t.Fatalf("unknown helper mode %q", mode)
	}
	if err := runCloudServe(cfg); err != nil {
		t.Fatalf("runCloudServe: %v", err)
	}
	fmt.Println(signalHelperServeReturned)
}

// lockedBuffer collects a child's output while the test polls it.
type lockedBuffer struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (b *lockedBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.Write(p)
}

func (b *lockedBuffer) String() string {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.buf.String()
}

type signalHelper struct {
	cmd    *exec.Cmd
	output *lockedBuffer
	done   chan error
}

func startSignalHelper(t *testing.T, env ...string) *signalHelper {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestBackupRunnerSignalHelperProcess$", "-test.count=1", "-test.timeout=120s")
	cmd.Env = append(os.Environ(), env...)
	h := &signalHelper{cmd: cmd, output: &lockedBuffer{}, done: make(chan error, 1)}
	cmd.Stdout, cmd.Stderr = h.output, h.output
	if err := cmd.Start(); err != nil {
		t.Fatalf("start helper: %v", err)
	}
	go func() { h.done <- cmd.Wait() }()
	t.Cleanup(func() {
		select {
		case <-h.done:
		default:
			_ = cmd.Process.Kill()
			<-h.done
		}
	})
	return h
}

func (h *signalHelper) waitOutput(t *testing.T, line string, timeout time.Duration) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for !strings.Contains(h.output.String(), line) {
		if time.Now().After(deadline) {
			t.Fatalf("helper never printed %q; output:\n%s", line, h.output.String())
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// stop sends sig and requires a clean exit (status 0).
func (h *signalHelper) stop(t *testing.T, sig os.Signal) {
	t.Helper()
	if err := h.cmd.Process.Signal(sig); err != nil {
		t.Fatalf("signal helper: %v", err)
	}
	select {
	case err := <-h.done:
		h.done <- err // for the cleanup
		if err != nil {
			t.Fatalf("helper exit after %s: %v (want status 0); output:\n%s", sig, err, h.output.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatalf("helper did not exit after %s; output:\n%s", sig, h.output.String())
	}
	if out := h.output.String(); !strings.Contains(out, signalHelperServeReturned) {
		t.Fatalf("runCloudServe did not return cleanly after %s; output:\n%s", sig, out)
	}
}

func archiveTempFiles(t *testing.T, dir string) []string {
	t.Helper()
	matches, err := filepath.Glob(filepath.Join(dir, "engram-cloud-backup-*"))
	if err != nil {
		t.Fatal(err)
	}
	return matches
}

// SIGTERM and SIGINT close the listener, stop the runtime through its
// shutdown path and make `engram cloud serve` exit with status 0.
func TestCloudServeSignalShutdownRunsTheRuntimeShutdownPath(t *testing.T) {
	for _, sig := range []os.Signal{syscall.SIGTERM, syscall.SIGINT} {
		t.Run(sig.String(), func(t *testing.T) {
			marker := filepath.Join(t.TempDir(), "stopped")
			h := startSignalHelper(t, signalHelperModeEnv+"=probe", signalHelperMarkerEnv+"="+marker, "ENGRAM_CLOUD_BACKUP_KEY=")
			h.waitOutput(t, signalHelperRuntimeStarted, 30*time.Second)
			h.stop(t, sig)
			if data, err := os.ReadFile(marker); err != nil || string(data) != "runtime stopped" {
				t.Fatalf("runtime shutdown path did not run: %q, %v", data, err)
			}
		})
	}
}

// SIGTERM during an upload cancels the run, records it as canceled,
// removes the plaintext archive temp file and exits with status 0.
func TestCloudServeSignalTermCancelsTheRunningBackupAndRemovesItsTempFile(t *testing.T) {
	cs, dsn := openCloudBackupRunnerStore(t)
	cfg := backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey)

	putReceived := make(chan struct{})
	var once sync.Once
	release := make(chan struct{})
	s3 := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.Copy(io.Discard, r.Body)
		once.Do(func() { close(putReceived) })
		select { // never answers: the upload is in flight at shutdown
		case <-r.Context().Done():
		case <-release:
		}
	}))
	t.Cleanup(s3.Close)
	t.Cleanup(func() { close(release) })
	sealer, err := backupcrypto.NewSealer(cfg.BackupKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.PutBackupDestination(context.Background(), cloudstore.PutBackupDestinationParams{
		Endpoint: s3.URL, Region: "auto", Bucket: "engram-backups",
		AccessKeyID: "AKIACMDSIGNAL0001", SecretAccessKey: "cmd-signal-secret", Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}, sealer); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}

	tempDir := t.TempDir()
	h := startSignalHelper(t, signalHelperModeEnv+"=backup", signalHelperDSNEnv+"="+dsn, "TMPDIR="+tempDir)
	h.waitOutput(t, signalHelperManualStarted, 30*time.Second)
	select {
	case <-putReceived:
	case <-time.After(30 * time.Second):
		t.Fatalf("the manual backup never reached the destination; output:\n%s", h.output.String())
	}
	if files := archiveTempFiles(t, tempDir); len(files) != 1 || !strings.HasSuffix(files[0], ".tar.gz") {
		t.Fatalf("archive temp files during the upload = %v, want the one archive", files)
	}

	h.stop(t, syscall.SIGTERM)

	if files := archiveTempFiles(t, tempDir); len(files) != 0 {
		t.Fatalf("plaintext backup temp files left after SIGTERM: %v", files)
	}
	runs, err := cs.ListBackupRuns(context.Background(), 5)
	if err != nil {
		t.Fatalf("ListBackupRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].Status != cloudstore.BackupRunStatusFailure || runs[0].ErrorMessage != backuprunner.CanceledMessage {
		t.Fatalf("runs after SIGTERM = %+v, want one failure %q", runs, backuprunner.CanceledMessage)
	}
	if out := h.output.String(); strings.Contains(out, "cmd-signal-secret") || strings.Contains(out, "AKIACMDSIGNAL0001") {
		t.Fatalf("server output leaks a credential:\n%s", out)
	}
}

// A signal does not hide a failure unrelated to the shutdown: the runtime
// or its initialization failing for another reason exits with that error.
func TestCloudServeSignalDoesNotHideAFailureUnrelatedToTheShutdown(t *testing.T) {
	for mode, want := range map[string]string{
		"start-error": signalHelperStartFailure,
		"init-error":  signalHelperInitFailure,
	} {
		t.Run(mode, func(t *testing.T) {
			h := startSignalHelper(t, signalHelperModeEnv+"="+mode, "ENGRAM_CLOUD_BACKUP_KEY=")
			h.waitOutput(t, signalHelperRuntimeStarted, 30*time.Second)
			if err := h.cmd.Process.Signal(syscall.SIGTERM); err != nil {
				t.Fatalf("signal helper: %v", err)
			}
			var err error
			select {
			case err = <-h.done:
				h.done <- err
			case <-time.After(60 * time.Second):
				t.Fatalf("helper did not exit; output:\n%s", h.output.String())
			}
			var exit *exec.ExitError
			if !errors.As(err, &exit) || exit.ExitCode() == 0 {
				t.Fatalf("helper exit = %v, want a failure; output:\n%s", err, h.output.String())
			}
			out := h.output.String()
			if !strings.Contains(out, "runCloudServe: "+want) || strings.Contains(out, signalHelperServeReturned) {
				t.Fatalf("output does not report the failure %q:\n%s", want, out)
			}
		})
	}
}

// Previous behavior: an initialization that ends because of the shutdown
// still exits with status 0.
func TestCloudServeSignalDuringInitializationExitsCleanly(t *testing.T) {
	h := startSignalHelper(t, signalHelperModeEnv+"=init-canceled", "ENGRAM_CLOUD_BACKUP_KEY=")
	h.waitOutput(t, signalHelperRuntimeStarted, 30*time.Second)
	h.stop(t, syscall.SIGTERM)
}
