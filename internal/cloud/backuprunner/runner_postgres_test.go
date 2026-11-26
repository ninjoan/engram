package backuprunner

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	_ "github.com/jackc/pgx/v5/stdlib"
)

var runnerSchemaCounter atomic.Int64

// openRunnerTestStore opens a CloudStore and a raw connection on a fresh
// schema of CLOUDSTORE_TEST_DSN; the schema is dropped when the test ends.
func openRunnerTestStore(t *testing.T) (*cloudstore.CloudStore, *sql.DB) {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CLOUDSTORE_TEST_DSN"))
	if dsn == "" {
		t.Skip("CLOUDSTORE_TEST_DSN not set — skipping backup runner integration test (requires Postgres)")
	}
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test requires URL-style CLOUDSTORE_TEST_DSN so a per-test search_path can be attached")
	}
	schema := fmt.Sprintf("backup_runner_%d_%d", time.Now().UnixNano(), runnerSchemaCounter.Add(1))
	adminDB, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open admin db: %v", err)
	}
	t.Cleanup(func() { _ = adminDB.Close() })
	if _, err := adminDB.Exec(`CREATE SCHEMA ` + schema); err != nil {
		t.Fatalf("create schema: %v", err)
	}
	t.Cleanup(func() { _, _ = adminDB.Exec(`DROP SCHEMA IF EXISTS ` + schema + ` CASCADE`) })
	sep := "?"
	if strings.Contains(dsn, "?") {
		sep = "&"
	}
	cs, err := cloudstore.New(cloud.Config{DSN: dsn + sep + "search_path=" + schema})
	if err != nil {
		t.Fatalf("open cloudstore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	db, err := sql.Open("pgx", dsn+sep+"search_path="+schema)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return cs, db
}

// storeTestDestination stores a destination at endpoint sealed by a test
// key and returns that key.
func storeTestDestination(t *testing.T, cs *cloudstore.CloudStore, endpoint string) *backupcrypto.Sealer {
	t.Helper()
	key, err := backupcrypto.ParseKey(hex.EncodeToString(bytes.Repeat([]byte{7}, backupcrypto.KeySize)))
	if err != nil {
		t.Fatal(err)
	}
	sealer, err := backupcrypto.NewSealer(key)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.PutBackupDestination(context.Background(), cloudstore.PutBackupDestinationParams{
		Endpoint: endpoint, Region: "auto", Bucket: "engram-backups", Prefix: "shared",
		AccessKeyID: testAccessKeyID, SecretAccessKey: testSecretKey, Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}, sealer); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}
	return sealer
}

// countingS3 accepts PUTs and records them; it never deletes anything.
type countingS3 struct {
	mu      sync.Mutex
	puts    []string
	bodies  [][]byte
	methods []string
}

func (c *countingS3) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	body, _ := io.ReadAll(r.Body)
	c.mu.Lock()
	defer c.mu.Unlock()
	c.methods = append(c.methods, r.Method)
	if r.Method == http.MethodPut {
		c.puts = append(c.puts, r.URL.Path)
		c.bodies = append(c.bodies, body)
	}
	w.WriteHeader(http.StatusOK)
}

func (c *countingS3) snapshot() ([]string, [][]byte, []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.puts...), append([][]byte(nil), c.bodies...), append([]string(nil), c.methods...)
}

// Two servers share the database: exactly one of them uploads a slot.
func TestTwoRunnersOnOneDatabaseUploadASlotOnce(t *testing.T) {
	cs, _ := openRunnerTestStore(t)
	ctx := context.Background()
	s3 := &countingS3{}
	srv := httptest.NewServer(s3)
	t.Cleanup(srv.Close)

	sealer := storeTestDestination(t, cs, srv.URL)
	actor := cloudstore.BackupDestinationActor{Source: "test"}
	if err := cs.PutBackupSchedule(ctx, cloudstore.PutBackupScheduleParams{Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC", Actor: actor}); err != nil {
		t.Fatalf("PutBackupSchedule: %v", err)
	}

	tempDir := t.TempDir()
	type server struct {
		runner *Runner
		clock  *fakeClock
		logs   *logSink
	}
	var servers []server
	runCtx, cancel := context.WithCancel(ctx)
	for range 2 {
		s := server{clock: newFakeClock(beforeSlot), logs: &logSink{}}
		runner, err := New(Config{Store: cs, Key: sealer, Clock: s.clock, TempDir: tempDir, Logf: s.logs.Logf, EngramVersion: "test"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		s.runner = runner
		runner.Start(runCtx)
		servers = append(servers, s)
	}
	t.Cleanup(func() {
		cancel()
		for _, s := range servers {
			waitDone(t, "runner shutdown", s.runner.Wait)
		}
	})
	for _, s := range servers {
		s.clock.waitSleeping(t)
	}
	for _, s := range servers {
		s.clock.Advance(time.Minute)
	}
	waitFor(t, "the slot to finish", func() bool {
		runs, err := cs.ListBackupRuns(ctx, 10)
		return err == nil && len(runs) == 1 && runs[0].Status != cloudstore.BackupRunStatusRunning
	})
	for _, s := range servers {
		s.clock.waitSleeping(t)
	}

	puts, bodies, methods := s3.snapshot()
	if len(puts) != 1 {
		t.Fatalf("PUT requests = %v, want exactly one", puts)
	}
	for _, m := range methods {
		if m != http.MethodPut {
			t.Fatalf("runner sent %s; it only ever uploads (never deletes)", m)
		}
	}
	wantPath := "/engram-backups/shared/engram-cloud-backup-20261130T030000Z.tar.gz"
	if puts[0] != wantPath || len(bodies[0]) < 2 || bodies[0][0] != 0x1f || bodies[0][1] != 0x8b {
		t.Fatalf("PUT %s with %d bytes, want %s holding a gzip archive", puts[0], len(bodies[0]), wantPath)
	}
	runs, err := cs.ListBackupRuns(ctx, 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(runs) != 1 || runs[0].Status != cloudstore.BackupRunStatusSuccess || runs[0].ObjectKey != "shared/engram-cloud-backup-20261130T030000Z.tar.gz" || runs[0].SizeBytes != int64(len(bodies[0])) {
		t.Fatalf("runs = %+v", runs)
	}
	entries, _ := os.ReadDir(tempDir)
	if len(entries) != 0 {
		t.Fatalf("temp files left: %d", len(entries))
	}
	for _, s := range servers {
		if logs := s.logs.text(); strings.Contains(logs, testSecretKey) || strings.Contains(logs, testAccessKeyID) {
			t.Fatalf("logs leak a credential: %s", logs)
		}
	}
}

// A manual run refuses while another server's run is running, and a
// stale running row left by a stopped server is reclaimed first.
func TestManualRunAgainstPostgresHonorsRunningAndStaleRows(t *testing.T) {
	cs, db := openRunnerTestStore(t)
	ctx := context.Background()
	sealer := storeTestDestination(t, cs, "https://acct.r2.example.test")
	h := newHarness(t, beforeSlot, func(cfg *Config) { cfg.Store, cfg.Key = cs, sealer })
	h.start(t)

	other, err := cs.StartBackupRun(ctx, cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerManual})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.runner.StartManualBackup(ctx, ""); err == nil || !strings.Contains(err.Error(), "already running") {
		t.Fatalf("manual run beside a running row: %v, want already running", err)
	}

	// Simulate the other server dying 7 hours ago.
	if _, err := db.ExecContext(ctx, `UPDATE cloud_backup_runs SET started_at = NOW() - INTERVAL '7 hours' WHERE id = $1`, other.ID); err != nil {
		t.Fatalf("backdate: %v", err)
	}
	id, err := h.runner.StartManualBackup(ctx, "")
	if err != nil {
		t.Fatalf("manual run after the stale row: %v", err)
	}
	waitFor(t, "the manual run", func() bool {
		runs, err := cs.ListBackupRuns(ctx, 10)
		return err == nil && len(runs) == 2 && runs[0].ID == id && runs[0].Status == cloudstore.BackupRunStatusSuccess
	})
	runs, _ := cs.ListBackupRuns(ctx, 10)
	if runs[1].ID != other.ID || runs[1].Status != cloudstore.BackupRunStatusFailure || runs[1].ErrorMessage != cloudstore.BackupRunInterruptedMessage {
		t.Fatalf("stale run = %+v, want interrupted", runs[1])
	}
}

// A server busy with a manual run does not claim a scheduled slot, so a
// free server on the same database uploads it.
func TestBusyRunnerLeavesTheSlotToAFreeRunnerOnPostgres(t *testing.T) {
	cs, _ := openRunnerTestStore(t)
	ctx := context.Background()
	manualPut := make(chan struct{})
	release := make(chan struct{})
	var manualOnce sync.Once
	s3 := &countingS3{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "20261130T025900Z") { // the manual run started at 02:59
			_, _ = io.Copy(io.Discard, r.Body)
			manualOnce.Do(func() { close(manualPut) })
			select {
			case <-release:
			case <-r.Context().Done():
			}
			return
		}
		s3.ServeHTTP(w, r)
	}))
	t.Cleanup(srv.Close)
	t.Cleanup(func() { close(release) }) // runs before srv.Close
	sealer := storeTestDestination(t, cs, srv.URL)
	if err := cs.PutBackupSchedule(ctx, cloudstore.PutBackupScheduleParams{Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC", Actor: cloudstore.BackupDestinationActor{Source: "test"}}); err != nil {
		t.Fatalf("PutBackupSchedule: %v", err)
	}

	runCtx, cancel := context.WithCancel(ctx)
	newServer := func() (*Runner, *fakeClock, *logSink) {
		clock, logs := newFakeClock(beforeSlot), &logSink{}
		runner, err := New(Config{Store: cs, Key: sealer, Clock: clock, TempDir: t.TempDir(), Logf: logs.Logf, EngramVersion: "test"})
		if err != nil {
			t.Fatalf("New: %v", err)
		}
		runner.Start(runCtx)
		t.Cleanup(func() { waitDone(t, "runner shutdown", runner.Wait) })
		return runner, clock, logs
	}
	busy, busyClock, busyLogs := newServer()
	_, freeClock, _ := newServer()
	t.Cleanup(cancel) // registered last: runs before the Wait cleanups
	busyClock.waitSleeping(t)
	freeClock.waitSleeping(t)

	if _, err := busy.StartManualBackup(ctx, ""); err != nil {
		t.Fatalf("manual run: %v", err)
	}
	select {
	case <-manualPut:
	case <-time.After(10 * time.Second):
		t.Fatal("the manual upload never reached the destination")
	}
	busyClock.Advance(time.Minute)
	waitFor(t, "the busy server to pass the slot", func() bool {
		return strings.Contains(busyLogs.text(), "not claimed: this server is still running another backup")
	})
	busyClock.waitSleeping(t)
	if runs, err := cs.ListBackupRuns(ctx, 10); err != nil || len(runs) != 1 || runs[0].Trigger != cloudstore.BackupRunTriggerManual {
		t.Fatalf("runs after the busy server passed the slot = %+v, %v; want only the manual run", runs, err)
	}

	freeClock.Advance(time.Minute)
	waitFor(t, "the free server's upload", func() bool {
		runs, err := cs.ListBackupRuns(ctx, 10)
		return err == nil && len(runs) == 2 && runs[0].Trigger == cloudstore.BackupRunTriggerScheduled && runs[0].Status == cloudstore.BackupRunStatusSuccess
	})
	if puts, _, _ := s3.snapshot(); len(puts) != 1 || puts[0] != "/engram-backups/shared/engram-cloud-backup-20261130T030000Z.tar.gz" {
		t.Fatalf("scheduled PUTs = %v, want the 03:00 slot once", puts)
	}
}
