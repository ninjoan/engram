package main

import (
	"context"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backuprunner"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudserver"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

var cloudBackupRunnerTestKey = hex.EncodeToString([]byte(strings.Repeat("r", backupcrypto.KeySize)))

func openCloudBackupRunnerStore(t *testing.T) (*cloudstore.CloudStore, string) {
	t.Helper()
	dsn := openIsolatedCloudRuntimeSchema(t)
	cs, err := cloudstore.New(cloud.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open cloudstore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	return cs, dsn
}

func assertCloudStoreClosed(t *testing.T, cs *cloudstore.CloudStore, closed bool) {
	t.Helper()
	_, err := cs.GetBackupSchedule(context.Background())
	isClosed := err != nil && strings.Contains(err.Error(), "database is closed")
	if isClosed != closed {
		t.Fatalf("store closed = %v (GetBackupSchedule error %v), want %v", isClosed, err, closed)
	}
}

func TestBackupRunnerAssemblyClosesTheStoreWhenBackupWiringFails(t *testing.T) {
	cs, _ := openCloudBackupRunnerStore(t)
	cfg := backupKeyConfigFromEnv(t, invalidBackupKey)
	runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
	assertInvalidBackupKeyError(t, err)
	if runtime != nil {
		t.Fatalf("a failed assembly returned a runtime: %+v", runtime)
	}
	assertCloudStoreClosed(t, cs, true)
}

func TestBackupRunnerAssemblyAppendsBackupWiring(t *testing.T) {
	for name, tc := range map[string]struct {
		key        string
		wantRunner bool
	}{
		"valid key":  {key: cloudBackupRunnerTestKey, wantRunner: true},
		"absent key": {key: ""},
	} {
		t.Run(name, func(t *testing.T) {
			cs, _ := openCloudBackupRunnerStore(t)
			cfg := backupKeyConfigFromEnv(t, tc.key)
			runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
			if err != nil {
				t.Fatalf("assembleCloudRuntime: %v", err)
			}
			if runtime.server == nil || runtime.store != cs {
				t.Fatalf("runtime = %+v", runtime)
			}
			if (runtime.backups != nil) != tc.wantRunner {
				t.Fatalf("backup runner wired = %v, want %v", runtime.backups != nil, tc.wantRunner)
			}
			assertCloudStoreClosed(t, cs, false)
		})
	}
}

// The runtime starts the backup runner with the server, cancels it on
// shutdown and waits for an in-flight run to record its result before the
// store is closed.
func TestBackupRunnerRuntimeWaitsForTheRunnerBeforeClosingTheStore(t *testing.T) {
	cs, dsn := openCloudBackupRunnerStore(t)
	cfg := backupKeyConfigFromEnv(t, cloudBackupRunnerTestKey)
	cfg.BindHost, cfg.Port = "127.0.0.1", 0
	// The runner sweeps stale archives from the temp dir: keep it private.
	t.Setenv("TMPDIR", t.TempDir())

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
	t.Cleanup(func() { close(release) }) // runs first: unblock the handler
	sealer, err := backupcrypto.NewSealer(cfg.BackupKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.PutBackupDestination(context.Background(), cloudstore.PutBackupDestinationParams{
		Endpoint: s3.URL, Region: "auto", Bucket: "engram-backups",
		AccessKeyID: "AKIACMDRUNNER0001", SecretAccessKey: "cmd-runner-secret", Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}, sealer); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}

	runtime, err := assembleCloudRuntime(cfg, cs, []string{"demo"}, nil, nil)
	if err != nil {
		t.Fatalf("assembleCloudRuntime: %v", err)
	}
	if runtime.backups == nil {
		t.Fatal("a valid key must wire the backup runner")
	}
	if _, err := runtime.backups.StartManualBackup(context.Background(), ""); !errors.Is(err, backuprunner.ErrRunnerStopped) {
		t.Fatalf("manual backup before the runtime starts: %v, want %v", err, backuprunner.ErrRunnerStopped)
	}
	startup, err := cloudserver.ListenDuringStartup(cfg.BindHost, cfg.Port, net.Listen)
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	done := make(chan error, 1)
	go func() { done <- runtime.Start(startup) }()

	var runID int64
	deadline := time.Now().Add(5 * time.Second)
	for {
		runID, err = runtime.backups.StartManualBackup(context.Background(), "")
		if err == nil || !errors.Is(err, backuprunner.ErrRunnerStopped) || time.Now().After(deadline) {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if err != nil {
		t.Fatalf("manual backup on the started runtime: %v", err)
	}
	select {
	case <-putReceived:
	case <-time.After(10 * time.Second):
		t.Fatal("the manual backup never reached the destination")
	}

	startup.Close()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("runtime did not stop")
	}
	assertCloudStoreClosed(t, cs, true)

	// A fresh connection shows the in-flight run was recorded before close.
	check, err := cloudstore.New(cloud.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("reopen store: %v", err)
	}
	t.Cleanup(func() { _ = check.Close() })
	runs, err := check.ListBackupRuns(context.Background(), 5)
	if err != nil {
		t.Fatalf("ListBackupRuns: %v", err)
	}
	if len(runs) != 1 || runs[0].ID != runID || runs[0].Status != cloudstore.BackupRunStatusFailure || runs[0].ErrorMessage != backuprunner.CanceledMessage {
		t.Fatalf("runs after shutdown = %+v, want the canceled run recorded", runs)
	}
	if _, err := runtime.backups.StartManualBackup(context.Background(), ""); !errors.Is(err, backuprunner.ErrRunnerStopped) {
		t.Fatalf("manual backup after shutdown: %v, want %v", err, backuprunner.ErrRunnerStopped)
	}
}
