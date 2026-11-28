package main

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/chunkcodec"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	"github.com/Gentleman-Programming/engram/v3/internal/store"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// runCloudBackupCommand runs `engram cloud <args...>` through the real cloud
// dispatcher and returns its output and the first exit code (0 when the
// command never called exitFunc).
func runCloudBackupCommand(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	withArgs(t, append([]string{"engram", "cloud"}, args...)...)
	oldExit := exitFunc
	exited := false
	exitFunc = func(c int) {
		if !exited {
			exited, code = true, c
		}
	}
	t.Cleanup(func() { exitFunc = oldExit })
	stdout, stderr = captureOutput(t, func() { cmdCloud(store.Config{}) })
	return stdout, stderr, code
}

// stubCloudBackupStore replaces the store opener; the returned counter
// records how often a command tried to open the Cloud database.
func stubCloudBackupStore(t *testing.T, open func(context.Context, cloud.Config) (cloudBackupStore, error)) *atomic.Int32 {
	t.Helper()
	var calls atomic.Int32
	old := openCloudBackupStore
	openCloudBackupStore = func(ctx context.Context, cfg cloud.Config) (cloudBackupStore, error) {
		calls.Add(1)
		return open(ctx, cfg)
	}
	t.Cleanup(func() { openCloudBackupStore = old })
	return &calls
}

func refuseCloudBackupStore(t *testing.T) *atomic.Int32 {
	t.Helper()
	return stubCloudBackupStore(t, func(context.Context, cloud.Config) (cloudBackupStore, error) {
		return nil, errors.New("test: the database must not be opened")
	})
}

var errCloudBackupTestSnapshot = errors.New("test: snapshot failed")

// failingCloudBackupStore fails every snapshot and restore.
type failingCloudBackupStore struct{}

func (failingCloudBackupStore) ReadBackupSnapshot(context.Context, func(*cloudstore.BackupReader) error) error {
	return errCloudBackupTestSnapshot
}

func (failingCloudBackupStore) RestoreBackup(context.Context, cloudstore.BackupRestoreOptions, func(*cloudstore.BackupWriter) error) error {
	return errCloudBackupTestSnapshot
}

func (failingCloudBackupStore) Close() error { return nil }

func dirEntries(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read dir %s: %v", dir, err)
	}
	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		names = append(names, entry.Name())
	}
	return names
}

func TestCloudBackupHelpListsCommands(t *testing.T) {
	stdout, _, code := runCloudBackupCommand(t, "--help")
	if code != 0 || !strings.Contains(stdout, "backup") {
		t.Fatalf("cloud --help (exit %d) does not list backup:\n%s", code, stdout)
	}
	for _, args := range [][]string{{"backup", "--help"}, {"backup", "-h"}, {"backup", "help"}} {
		stdout, stderr, code := runCloudBackupCommand(t, args...)
		if code != 0 || stderr != "" {
			t.Fatalf("%v exit %d stderr %q", args, code, stderr)
		}
		for _, want := range []string{"engram cloud backup export --output <path|-> [--force]", "engram cloud backup import --input <path|-> (--dry-run|--apply)", "ENGRAM_DATABASE_URL"} {
			if !strings.Contains(stdout, want) {
				t.Errorf("%v output missing %q:\n%s", args, want, stdout)
			}
		}
	}
	for _, sub := range []string{"export", "import"} {
		for _, flag := range []string{"--help", "-h"} {
			stdout, stderr, code := runCloudBackupCommand(t, "backup", sub, flag)
			if code != 0 || stderr != "" || !strings.Contains(stdout, "engram cloud backup "+sub) {
				t.Errorf("backup %s %s: exit %d stdout %q stderr %q", sub, flag, code, stdout, stderr)
			}
		}
	}
}

func TestCloudBackupUsageErrors(t *testing.T) {
	opened := refuseCloudBackupStore(t)
	t.Setenv("ENGRAM_DATABASE_URL", "postgres://unused.invalid/engram")
	dir := t.TempDir()
	input := filepath.Join(dir, "in.tar.gz")
	if err := os.WriteFile(input, []byte("not used"), 0o600); err != nil {
		t.Fatal(err)
	}
	cases := []struct {
		name string
		args []string
		want string
	}{
		{"no subcommand", []string{"backup"}, "error: a backup subcommand is required"},
		{"unknown subcommand", []string{"backup", "restore"}, "error: unknown cloud backup subcommand: restore"},
		{"export without output", []string{"backup", "export"}, "error: --output is required"},
		{"export output without value", []string{"backup", "export", "--output"}, "error: --output requires a value"},
		{"export unknown option", []string{"backup", "export", "--output", filepath.Join(dir, "x"), "--zip"}, "error: unknown option: --zip"},
		{"import without input", []string{"backup", "import", "--apply"}, "error: --input is required"},
		{"import without mode", []string{"backup", "import", "--input", input}, "error: exactly one of --dry-run or --apply is required"},
		{"import with both modes", []string{"backup", "import", "--input", input, "--dry-run", "--apply"}, "error: exactly one of --dry-run or --apply is required"},
		{"import unknown option", []string{"backup", "import", "--input", input, "--apply", "--force"}, "error: unknown option: --force"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			stdout, stderr, code := runCloudBackupCommand(t, tc.args...)
			if code != 1 {
				t.Fatalf("exit code %d, want 1 (stderr %q)", code, stderr)
			}
			if !strings.Contains(stderr, tc.want) || !strings.Contains(stderr, "usage: engram cloud backup") {
				t.Errorf("stderr %q, want usage and %q", stderr, tc.want)
			}
			if stdout != "" {
				t.Errorf("stdout %q, want empty", stdout)
			}
		})
	}
	if n := opened.Load(); n != 0 {
		t.Errorf("usage errors opened the database %d times", n)
	}
	if got := dirEntries(t, dir); len(got) != 1 {
		t.Errorf("usage errors wrote files: %v", got)
	}
}

func TestCloudBackupRequiresDatabaseURL(t *testing.T) {
	opened := refuseCloudBackupStore(t)
	t.Setenv("ENGRAM_DATABASE_URL", "")
	dir := t.TempDir()
	input := filepath.Join(dir, "in.tar.gz")
	if err := os.WriteFile(input, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"backup", "export", "--output", filepath.Join(dir, "out.tar.gz")},
		{"backup", "import", "--input", input, "--dry-run"},
	} {
		_, stderr, code := runCloudBackupCommand(t, args...)
		if code != 1 || !strings.Contains(stderr, "requires ENGRAM_DATABASE_URL") {
			t.Errorf("%v: exit %d stderr %q, want ENGRAM_DATABASE_URL error", args, code, stderr)
		}
	}
	if n := opened.Load(); n != 0 {
		t.Errorf("database opened %d times without ENGRAM_DATABASE_URL", n)
	}
	if got := dirEntries(t, dir); len(got) != 1 {
		t.Errorf("files written without ENGRAM_DATABASE_URL: %v", got)
	}
}

func TestCloudBackupExportRefusesToOverwriteWithoutForce(t *testing.T) {
	opened := refuseCloudBackupStore(t)
	t.Setenv("ENGRAM_DATABASE_URL", "postgres://unused.invalid/engram")
	dir := t.TempDir()
	output := filepath.Join(dir, "existing.tar.gz")
	if err := os.WriteFile(output, []byte("keep me"), 0o600); err != nil {
		t.Fatal(err)
	}
	stdout, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", output)
	if code != 1 || !strings.Contains(stderr, "already exists") || !strings.Contains(stderr, "--force") {
		t.Fatalf("exit %d stderr %q, want overwrite refusal mentioning --force", code, stderr)
	}
	if stdout != "" {
		t.Errorf("stdout %q, want empty", stdout)
	}
	if n := opened.Load(); n != 0 {
		t.Errorf("overwrite refusal opened the database %d times", n)
	}
	if data, _ := os.ReadFile(output); string(data) != "keep me" {
		t.Errorf("existing file changed to %q", data)
	}
}

func TestCloudBackupExportFailureLeavesNoPartialFile(t *testing.T) {
	stubCloudBackupStore(t, func(context.Context, cloud.Config) (cloudBackupStore, error) {
		return failingCloudBackupStore{}, nil
	})
	t.Setenv("ENGRAM_DATABASE_URL", "postgres://unused.invalid/engram")

	t.Run("new file", func(t *testing.T) {
		dir := t.TempDir()
		_, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", filepath.Join(dir, "new.tar.gz"))
		if code != 1 || !strings.Contains(stderr, errCloudBackupTestSnapshot.Error()) {
			t.Fatalf("exit %d stderr %q, want export failure", code, stderr)
		}
		if got := dirEntries(t, dir); len(got) != 0 {
			t.Errorf("failed export left files: %v", got)
		}
	})
	t.Run("forced overwrite keeps the old file", func(t *testing.T) {
		dir := t.TempDir()
		output := filepath.Join(dir, "existing.tar.gz")
		if err := os.WriteFile(output, []byte("previous backup"), 0o600); err != nil {
			t.Fatal(err)
		}
		_, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", output, "--force")
		if code != 1 || !strings.Contains(stderr, errCloudBackupTestSnapshot.Error()) {
			t.Fatalf("exit %d stderr %q, want export failure", code, stderr)
		}
		if got := dirEntries(t, dir); len(got) != 1 {
			t.Errorf("failed export left files: %v", got)
		}
		if data, _ := os.ReadFile(output); string(data) != "previous backup" {
			t.Errorf("existing file changed to %q", data)
		}
	})
}

// --- Postgres-gated round trip -------------------------------------------

var cloudBackupSchemaCounter atomic.Int64

// openCloudBackupTestDSN returns a DSN bound to a fresh schema via
// search_path; the schema is dropped when the test ends.
func openCloudBackupTestDSN(t *testing.T) string {
	t.Helper()
	dsn := strings.TrimSpace(os.Getenv("CLOUDSTORE_TEST_DSN"))
	if dsn == "" {
		t.Skip("CLOUDSTORE_TEST_DSN not set — skipping cloud backup CLI test (requires Postgres)")
	}
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test requires URL-style CLOUDSTORE_TEST_DSN so a per-test search_path can be attached")
	}
	schema := fmt.Sprintf("cloud_backup_cli_%d_%d", time.Now().UnixNano(), cloudBackupSchemaCounter.Add(1))
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
	return dsn + sep + "search_path=" + schema
}

type cloudBackupTestDB struct {
	dsn string
	cs  *cloudstore.CloudStore
	db  *sql.DB
}

func openCloudBackupTestDB(t *testing.T) cloudBackupTestDB {
	t.Helper()
	dsn := openCloudBackupTestDSN(t)
	cs, err := cloudstore.New(cloud.Config{DSN: dsn})
	if err != nil {
		t.Fatalf("open cloudstore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return cloudBackupTestDB{dsn: dsn, cs: cs, db: db}
}

func (d cloudBackupTestDB) rowCounts(t *testing.T) map[string]int {
	t.Helper()
	counts := map[string]int{}
	for _, table := range append(cloudstore.BackupTables(), "cloud_principal_tokens") {
		var n int
		if err := d.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&n); err != nil {
			t.Fatalf("count %s: %v", table, err)
		}
		counts[table] = n
	}
	return counts
}

func (d cloudBackupTestDB) assertEmpty(t *testing.T) {
	t.Helper()
	for table, n := range d.rowCounts(t) {
		if n != 0 {
			t.Errorf("table %s has %d rows, want 0", table, n)
		}
	}
}

func seedCloudBackupSource(t *testing.T, d cloudBackupTestDB) {
	t.Helper()
	ctx := context.Background()
	admin, err := d.cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Email: "admin@example.test", DisplayName: "Admin", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.cs.CreatePrincipalToken(ctx, cloudstore.CreatePrincipalTokenParams{PrincipalID: admin.PrincipalID, TokenPrefix: "egc_cliprefix", TokenHash: "cli-backup-token-hash-should-not-leak", Name: "cli", CreatedByPrincipalID: admin.PrincipalID}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.cs.CreateProjectGrant(ctx, cloudstore.CreateProjectGrantParams{PrincipalID: admin.PrincipalID, Project: "alpha", GrantedByPrincipalID: admin.PrincipalID}); err != nil {
		t.Fatal(err)
	}
	payload, err := chunkcodec.CanonicalizeForProject([]byte(`{"sessions":[{"id":"s1","project":"alpha","directory":"/w","started_at":"2026-01-02 03:04:05"}],"observations":[{"sync_id":"o1","session_id":"s1","type":"note","title":"t","content":"c","project":"alpha","scope":"project","created_at":"2026-01-02 03:04:06","updated_at":"2026-01-02 03:04:06"}],"prompts":[]}`), "alpha")
	if err != nil {
		t.Fatal(err)
	}
	if err := d.cs.WriteChunk(ctx, "alpha", chunkcodec.ChunkID(payload), "alice", "", payload); err != nil {
		t.Fatal(err)
	}
	if _, err := d.cs.InsertMutationBatch(ctx, []cloudstore.MutationEntry{
		{Project: "alpha", Entity: "observation", EntityKey: "o2", Op: "upsert", CreatedBy: "alice", Payload: json.RawMessage(`{"sync_id":"o2","session_id":"s1","type":"note","title":"t2","content":"c2","project":"alpha","scope":"project"}`)},
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := d.cs.CreateUser("legacy", "legacy@example.test", ""); err != nil {
		t.Fatal(err)
	}
	if err := d.cs.SetProjectSyncEnabled("alpha", false, "admin", "maintenance"); err != nil {
		t.Fatal(err)
	}
}

func TestCloudBackupExportImportRoundTrip(t *testing.T) {
	src := openCloudBackupTestDB(t)
	seedCloudBackupSource(t, src)
	dir := t.TempDir()
	archive := filepath.Join(dir, "cloud.tar.gz")

	t.Setenv("ENGRAM_DATABASE_URL", src.dsn)
	stdout, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", archive)
	if code != 0 {
		t.Fatalf("export exit %d stderr %q", code, stderr)
	}
	info, err := os.Stat(archive)
	if err != nil {
		t.Fatalf("stat archive: %v", err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Errorf("archive mode %v, want 0600", info.Mode().Perm())
	}
	srcCounts := src.rowCounts(t)
	wantSummary := []string{"path: " + archive, fmt.Sprintf("bytes: %d", info.Size()), "max_mutation_seq: 3\n", fmt.Sprintf("tables: %d\n", len(cloudstore.BackupTables()))}
	for _, table := range cloudstore.BackupTables() {
		wantSummary = append(wantSummary, fmt.Sprintf("  %s: %d\n", table, srcCounts[table]))
	}
	for _, want := range wantSummary {
		if !strings.Contains(stdout, want) {
			t.Errorf("export summary missing %q:\n%s", want, stdout)
		}
	}
	if got := dirEntries(t, dir); len(got) != 1 {
		t.Errorf("export left extra files: %v", got)
	}

	// --force replaces an existing file atomically and still yields 0600.
	forced := filepath.Join(dir, "forced.tar.gz")
	if err := os.WriteFile(forced, []byte("old"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", forced, "--force"); code != 0 {
		t.Fatalf("forced export exit %d stderr %q", code, stderr)
	}
	if info, err := os.Stat(forced); err != nil || info.Size() < 100 || (runtime.GOOS != "windows" && info.Mode().Perm() != 0o600) {
		t.Errorf("forced export result %v %v, want replaced 0600 archive", info, err)
	}

	dst := openCloudBackupTestDB(t)
	t.Setenv("ENGRAM_DATABASE_URL", dst.dsn)
	stdout, stderr, code = runCloudBackupCommand(t, "backup", "import", "--input", archive, "--apply")
	if code != 0 {
		t.Fatalf("import exit %d stderr %q", code, stderr)
	}
	want := src.rowCounts(t)
	want["cloud_principal_tokens"] = 0
	got := dst.rowCounts(t)
	for table, n := range want {
		if got[table] != n {
			t.Errorf("table %s restored %d rows, source has %d", table, got[table], n)
		}
	}
	for _, text := range []string{"backup: imported", "tables: ", "rows: ", "re-issue", "recover-token", "Legacy cloud_users", "bootstrap admin"} {
		if !strings.Contains(stdout, text) {
			t.Errorf("import output missing %q:\n%s", text, stdout)
		}
	}
}

func TestCloudBackupImportDryRunLeavesTargetEmpty(t *testing.T) {
	src := openCloudBackupTestDB(t)
	seedCloudBackupSource(t, src)
	archive := filepath.Join(t.TempDir(), "cloud.tar.gz")
	t.Setenv("ENGRAM_DATABASE_URL", src.dsn)
	if _, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", archive); code != 0 {
		t.Fatalf("export exit %d stderr %q", code, stderr)
	}

	dst := openCloudBackupTestDB(t)
	t.Setenv("ENGRAM_DATABASE_URL", dst.dsn)
	in, err := os.Open(archive)
	if err != nil {
		t.Fatal(err)
	}
	defer in.Close()
	oldStdin := os.Stdin
	os.Stdin = in
	t.Cleanup(func() { os.Stdin = oldStdin })
	stdout, stderr, code := runCloudBackupCommand(t, "backup", "import", "--input", "-", "--dry-run")
	if code != 0 {
		t.Fatalf("dry-run exit %d stderr %q", code, stderr)
	}
	if !strings.Contains(stdout, "backup: dry run passed") || strings.Contains(stdout, "re-issue") {
		t.Errorf("dry-run output:\n%s", stdout)
	}
	dst.assertEmpty(t)
}

func TestCloudBackupImportRefusesNonEmptyTarget(t *testing.T) {
	src := openCloudBackupTestDB(t)
	seedCloudBackupSource(t, src)
	archive := filepath.Join(t.TempDir(), "cloud.tar.gz")
	t.Setenv("ENGRAM_DATABASE_URL", src.dsn)
	if _, stderr, code := runCloudBackupCommand(t, "backup", "export", "--output", archive); code != 0 {
		t.Fatalf("export exit %d stderr %q", code, stderr)
	}

	dst := openCloudBackupTestDB(t)
	if _, err := dst.cs.CreateHumanUser(context.Background(), cloudstore.CreateHumanUserParams{Username: "existing", DisplayName: "Existing", Role: cloudstore.PrincipalRoleAdmin}); err != nil {
		t.Fatal(err)
	}
	before := dst.rowCounts(t)
	t.Setenv("ENGRAM_DATABASE_URL", dst.dsn)
	for _, mode := range []string{"--apply", "--dry-run"} {
		stdout, stderr, code := runCloudBackupCommand(t, "backup", "import", "--input", archive, mode)
		if code != 1 {
			t.Fatalf("%s exit %d, want 1 (stderr %q)", mode, code, stderr)
		}
		if !strings.Contains(stderr, "target database is not empty") || !strings.Contains(stderr, "fresh") {
			t.Errorf("%s stderr %q, want clear non-empty target message", mode, stderr)
		}
		if strings.Contains(stdout, "backup: imported") {
			t.Errorf("%s stdout reports success: %q", mode, stdout)
		}
	}
	after := dst.rowCounts(t)
	for table, n := range before {
		if after[table] != n {
			t.Errorf("table %s changed from %d to %d rows", table, n, after[table])
		}
	}
}
