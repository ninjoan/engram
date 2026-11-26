package cloudbackup

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/Gentleman-Programming/engram/v3/internal/cloud"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/backupcrypto"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/chunkcodec"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// restoredTables is the independent expectation of every table a backup
// restores verbatim; cloud_principal_tokens, cloud_backup_destinations,
// cloud_backup_schedule and cloud_backup_runs must never be exported or
// restored.
var restoredTables = []string{
	"cloud_users", "cloud_principals", "cloud_human_users", "cloud_project_grants",
	"cloud_project_controls", "cloud_auth_audit_log", "cloud_sync_audit_log",
	"cloud_session_authority", "cloud_prompt_pair_claims", "cloud_prompt_source_attestations",
	"cloud_chunks", "cloud_project_sessions", "cloud_mutations",
}

var allCloudTables = append(append([]string{}, restoredTables...), "cloud_principal_tokens", "cloud_backup_destinations", "cloud_backup_schedule", "cloud_backup_runs")

var schemaCounter atomic.Int64

type isolatedStore struct {
	cs *cloudstore.CloudStore
	db *sql.DB
}

func openIsolatedStore(t *testing.T) isolatedStore {
	t.Helper()
	dsn := os.Getenv("CLOUDSTORE_TEST_DSN")
	if dsn == "" {
		t.Skip("CLOUDSTORE_TEST_DSN not set — skipping integration test (requires Postgres)")
	}
	if !strings.HasPrefix(dsn, "postgres://") && !strings.HasPrefix(dsn, "postgresql://") {
		t.Skip("test requires URL-style CLOUDSTORE_TEST_DSN so a per-test search_path can be attached")
	}
	schema := fmt.Sprintf("cloudbackup_%d_%d", time.Now().UnixNano(), schemaCounter.Add(1))
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
	testDSN := dsn + sep + "search_path=" + schema
	cs, err := cloudstore.New(cloud.Config{DSN: testDSN})
	if err != nil {
		t.Fatalf("open cloudstore: %v", err)
	}
	t.Cleanup(func() { _ = cs.Close() })
	db, err := sql.Open("pgx", testDSN)
	if err != nil {
		t.Fatalf("open schema db: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return isolatedStore{cs: cs, db: db}
}

type seededSource struct {
	tokenHash   string
	tokenPrefix string
	chunks      map[string][]string // project -> chunk ids
}

func must(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatal(err)
	}
}

func writeTestChunk(t *testing.T, ctx context.Context, cs *cloudstore.CloudStore, project, createdBy, clientCreatedAt, raw string) string {
	t.Helper()
	payload, err := chunkcodec.CanonicalizeForProject([]byte(raw), project)
	if err != nil {
		t.Fatalf("canonicalize chunk: %v", err)
	}
	chunkID := chunkcodec.ChunkID(payload)
	if err := cs.WriteChunk(ctx, project, chunkID, createdBy, clientCreatedAt, payload); err != nil {
		t.Fatalf("write chunk %s/%s: %v", project, chunkID, err)
	}
	return chunkID
}

func seedSource(t *testing.T, s isolatedStore) seededSource {
	t.Helper()
	ctx := context.Background()
	cs := s.cs

	admin, err := cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "admin", Email: "admin@example.test", DisplayName: "Admin", Role: cloudstore.PrincipalRoleAdmin})
	must(t, err)
	member, err := cs.CreatePrincipal(ctx, cloudstore.CreatePrincipalParams{Kind: cloudstore.PrincipalKindServiceAccount, DisplayName: "ci-bot", Role: cloudstore.PrincipalRoleMember})
	must(t, err)
	seeded := seededSource{tokenHash: "backup-secret-token-hash-6f1c2d9e7a", tokenPrefix: "egc_seedprefix", chunks: map[string][]string{}}
	_, err = cs.CreatePrincipalToken(ctx, cloudstore.CreatePrincipalTokenParams{PrincipalID: member.ID, TokenPrefix: seeded.tokenPrefix, TokenHash: seeded.tokenHash, Name: "ci", CreatedByPrincipalID: admin.PrincipalID})
	must(t, err)
	_, err = cs.CreateProjectGrant(ctx, cloudstore.CreateProjectGrantParams{PrincipalID: member.ID, Project: "alpha", GrantedByPrincipalID: admin.PrincipalID})
	must(t, err)
	must(t, cs.InsertAuthAuditEvent(ctx, cloudstore.AuthAuditEvent{ActorPrincipalID: admin.PrincipalID, ActorSource: "dashboard", TargetPrincipalID: member.ID, Project: "alpha", Action: "grant.create", Outcome: "success", Metadata: map[string]any{"note": "seed"}}))
	must(t, cs.InsertAuthAuditEvent(ctx, cloudstore.AuthAuditEvent{ActorSource: "bootstrap_cli", Action: "bootstrap.cli", Outcome: "success"}))
	must(t, cs.InsertAuditEntry(ctx, cloudstore.AuditEntry{Contributor: "ci-bot", Project: "beta", Action: cloudstore.AuditActionChunkPush, Outcome: cloudstore.AuditOutcomeRejectedProjectPaused, EntryCount: 2}))
	_, err = cs.CreateUser("legacy", "legacy@example.test", "")
	must(t, err)
	must(t, cs.RegisterSessionAuthority(ctx, "sess-alpha-1", "alpha", "admin"))
	must(t, cs.ClaimPromptPair(ctx, "sess-alpha-1", "inbox-1", "prompt-sync-1", "beta", "admin"))
	_, err = cs.AttestPromptSource(ctx, "sess-alpha-1", "inbox-1", "prompt-sync-1", "alpha", "beta", "admin")
	must(t, err)

	adminID, err := strconv.ParseInt(admin.PrincipalID, 10, 64)
	must(t, err)
	submitted := cloudstore.WithManagedChunkSubmitter(ctx, adminID)
	relation := `{"sync_id":"rel-1","source_id":"obs-alpha-1","target_id":"obs-alpha-0","relation":"related","judgment_status":"judged","marked_by_actor":"agent-a","marked_by_kind":"agent"}`
	alpha := fmt.Sprintf(`{
		"sessions":[{"id":"sess-alpha-1","project":"alpha","directory":"/work/alpha","started_at":"2026-01-02 03:04:05"}],
		"observations":[{"sync_id":"obs-alpha-1","session_id":"sess-alpha-1","type":"decision","title":"Use <tags> & \"quotes\"","content":"line1\nline2 ünïcode  ","project":"alpha","scope":"project","created_at":"2026-01-02 03:04:06","updated_at":"2026-01-02 03:04:06","revision_count":3,"weight":1.5}],
		"prompts":[],
		"mutations":[
			{"entity":"relation","entity_key":"rel-1","op":"upsert","payload":%q},
			{"entity":"observation","entity_key":"obs-alpha-0","op":"delete","payload":"{\"sync_id\":\"obs-alpha-0\"}"}
		]}`, relation)
	seeded.chunks["alpha"] = append(seeded.chunks["alpha"], writeTestChunk(t, submitted, cs, "alpha", "alice", "2026-01-02T03:04:07Z", alpha))
	beta := `{
		"sessions":[{"id":"sess-beta-1","project":"beta","directory":"/work/beta","started_at":"2026-01-03 03:04:05"}],
		"observations":[],
		"prompts":[{"sync_id":"prompt-sync-1","session_id":"sess-beta-1","content":"hello <world>","project":"beta","created_at":"2026-01-03 03:04:06"}]}`
	seeded.chunks["beta"] = append(seeded.chunks["beta"], writeTestChunk(t, ctx, cs, "beta", "bob", "", beta))

	batch := []cloudstore.MutationEntry{
		{Project: "alpha", Entity: "observation", EntityKey: "obs-alpha-2", Op: "upsert", CreatedBy: "carol", Payload: json.RawMessage(`{"sync_id":"obs-alpha-2","session_id":"sess-alpha-1","type":"note","title":"t2","content":"c2","project":"alpha","scope":"project"}`)},
		{Project: "beta", Entity: "observation", EntityKey: "obs-beta-1", Op: "delete", CreatedBy: "carol", Payload: json.RawMessage(`{"sync_id":"obs-beta-1"}`)},
	}
	_, err = cs.InsertMutationBatch(submitted, batch)
	must(t, err)
	// An identical client retry appends a second journal copy with new seqs.
	_, err = cs.InsertMutationBatch(submitted, batch)
	must(t, err)
	must(t, cs.SetProjectSyncEnabled("beta", false, "admin", "maintenance window"))

	for _, project := range []string{"alpha", "beta"} {
		manifest, err := cs.ReadManifest(ctx, project)
		must(t, err)
		seeded.chunks[project] = seeded.chunks[project][:0]
		for _, entry := range manifest.Chunks {
			seeded.chunks[project] = append(seeded.chunks[project], entry.ID)
		}
	}
	return seeded
}

func tableRows(t *testing.T, db *sql.DB, table string) []string {
	t.Helper()
	rows, err := db.Query(`SELECT to_jsonb(t)::text FROM ` + table + ` t ORDER BY 1`)
	if err != nil {
		t.Fatalf("read %s: %v", table, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var row string
		must(t, rows.Scan(&row))
		out = append(out, row)
	}
	must(t, rows.Err())
	return out
}

func rowCounts(t *testing.T, db *sql.DB) map[string]int {
	t.Helper()
	counts := make(map[string]int, len(allCloudTables))
	for _, table := range allCloudTables {
		var n int
		must(t, db.QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&n))
		counts[table] = n
	}
	return counts
}

func mutationSequenceUntouched(t *testing.T, db *sql.DB) bool {
	t.Helper()
	var last sql.NullInt64
	must(t, db.QueryRow(`SELECT pg_sequence_last_value(pg_get_serial_sequence('cloud_mutations', 'seq')::regclass)`).Scan(&last))
	return !last.Valid
}

func assertEmptyTarget(t *testing.T, target isolatedStore) {
	t.Helper()
	for table, n := range rowCounts(t, target.db) {
		if n != 0 {
			t.Errorf("target table %s has %d rows, want 0", table, n)
		}
	}
	if !mutationSequenceUntouched(t, target.db) {
		t.Errorf("target cloud_mutations sequence was advanced")
	}
}

func exportArchive(t *testing.T, src isolatedStore) ([]byte, Summary) {
	t.Helper()
	var archive bytes.Buffer
	summary, err := Export(context.Background(), src.cs, &archive, ExportOptions{EngramVersion: "test"})
	if err != nil {
		t.Fatalf("Export: %v", err)
	}
	return archive.Bytes(), summary
}

type archiveMember struct {
	name string
	data []byte
}

func readArchive(t *testing.T, archive []byte) []archiveMember {
	t.Helper()
	gz, err := gzip.NewReader(bytes.NewReader(archive))
	must(t, err)
	tr := tar.NewReader(gz)
	var members []archiveMember
	for {
		header, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		must(t, err)
		data, err := io.ReadAll(tr)
		must(t, err)
		members = append(members, archiveMember{name: header.Name, data: data})
	}
	return members
}

func writeArchive(t *testing.T, members []archiveMember) []byte {
	t.Helper()
	var out bytes.Buffer
	gz := gzip.NewWriter(&out)
	tw := tar.NewWriter(gz)
	for _, member := range members {
		must(t, tw.WriteHeader(&tar.Header{Name: member.name, Mode: 0o600, Size: int64(len(member.data)), Typeflag: tar.TypeReg}))
		_, err := tw.Write(member.data)
		must(t, err)
	}
	must(t, tw.Close())
	must(t, gz.Close())
	return out.Bytes()
}

// rewriteArchive edits one data member and/or the manifest. When reseal is
// true the manifest checksum and size of every member are recomputed.
func rewriteArchive(t *testing.T, archive []byte, member string, edit func([]byte) []byte, editManifest func(map[string]any), reseal bool) []byte {
	t.Helper()
	members := readArchive(t, archive)
	last := len(members) - 1
	var manifest map[string]any
	must(t, json.Unmarshal(members[last].data, &manifest))
	for i := range members[:last] {
		if members[i].name == member && edit != nil {
			members[i].data = edit(members[i].data)
		}
	}
	if reseal {
		for _, raw := range manifest["tables"].([]any) {
			entry := raw.(map[string]any)
			for _, m := range members[:last] {
				if m.name == entry["member"] {
					sum := sha256.Sum256(m.data)
					entry["sha256"] = hex.EncodeToString(sum[:])
					entry["size"] = len(m.data)
				}
			}
		}
	}
	if editManifest != nil {
		editManifest(manifest)
	}
	encoded, err := json.Marshal(manifest)
	must(t, err)
	members[last].data = encoded
	return writeArchive(t, members)
}

func pullAll(t *testing.T, cs *cloudstore.CloudStore, since int64, projects []string) []cloudstore.StoredMutation {
	t.Helper()
	var all []cloudstore.StoredMutation
	for {
		page, hasMore, latest, err := cs.ListMutationsSince(context.Background(), since, 3, projects)
		must(t, err)
		all = append(all, page...)
		if !hasMore {
			return all
		}
		since = latest
	}
}

func TestExportImportRoundTripRestoresEveryTableVerbatim(t *testing.T) {
	ctx := context.Background()
	source := openIsolatedStore(t)
	seeded := seedSource(t, source)
	target := openIsolatedStore(t)

	archive, exported := exportArchive(t, source)
	imported, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{})
	if err != nil {
		t.Fatalf("Import: %v", err)
	}

	for _, table := range restoredTables {
		want, got := tableRows(t, source.db, table), tableRows(t, target.db, table)
		if len(want) == 0 {
			t.Errorf("seed left %s empty; the round trip would prove nothing", table)
		}
		if !reflect.DeepEqual(want, got) {
			t.Errorf("table %s differs after restore\nsource: %v\ntarget: %v", table, want, got)
		}
	}
	if n := rowCounts(t, target.db)["cloud_principal_tokens"]; n != 0 {
		t.Errorf("restored %d token rows, want 0", n)
	}

	sourceCounts := rowCounts(t, source.db)
	var maxSeq int64
	must(t, source.db.QueryRow(`SELECT MAX(seq) FROM cloud_mutations`).Scan(&maxSeq))
	for _, summary := range []Summary{exported, imported} {
		if summary.FormatVersion != FormatVersion || summary.MaxMutationSeq != maxSeq {
			t.Errorf("summary = %+v, want format %d max seq %d", summary, FormatVersion, maxSeq)
		}
		if len(summary.Tables) != len(restoredTables) {
			t.Fatalf("summary tables = %+v, want %d tables", summary.Tables, len(restoredTables))
		}
		for _, table := range summary.Tables {
			if int64(sourceCounts[table.Name]) != table.Rows {
				t.Errorf("summary %s rows = %d, want %d", table.Name, table.Rows, sourceCounts[table.Name])
			}
		}
	}
	if imported.DryRun {
		t.Errorf("imported summary reports DryRun")
	}

	for project, chunkIDs := range seeded.chunks {
		wantManifest, err := source.cs.ReadManifest(ctx, project)
		must(t, err)
		gotManifest, err := target.cs.ReadManifest(ctx, project)
		must(t, err)
		if !reflect.DeepEqual(wantManifest, gotManifest) {
			t.Errorf("manifest %s differs: source %+v target %+v", project, wantManifest, gotManifest)
		}
		for _, chunkID := range chunkIDs {
			want, err := source.cs.ReadChunk(ctx, project, chunkID)
			must(t, err)
			got, err := target.cs.ReadChunk(ctx, project, chunkID)
			must(t, err)
			if !bytes.Equal(want, got) {
				t.Errorf("chunk %s/%s differs", project, chunkID)
			}
		}
		wantSessions, err := source.cs.KnownSessionIDs(ctx, project)
		must(t, err)
		gotSessions, err := target.cs.KnownSessionIDs(ctx, project)
		must(t, err)
		if !reflect.DeepEqual(wantSessions, gotSessions) {
			t.Errorf("sessions %s differ: %v vs %v", project, wantSessions, gotSessions)
		}
	}
	enabled, err := target.cs.IsProjectSyncEnabled("beta")
	must(t, err)
	if enabled {
		t.Errorf("project beta pause was not restored")
	}
	control, err := target.cs.GetProjectSyncControl("beta")
	must(t, err)
	if control == nil || control.PausedReason == nil || *control.PausedReason != "maintenance window" {
		t.Errorf("project beta control = %+v, want paused reason preserved", control)
	}
}

func TestRestoredStoreServesEverySourceCursorAndContinuesPastSourceSequence(t *testing.T) {
	ctx := context.Background()
	source := openIsolatedStore(t)
	seedSource(t, source)
	// A rolled-back insert consumes a seq the journal never shows.
	var sourceLast int64
	must(t, source.db.QueryRow(`SELECT nextval(pg_get_serial_sequence('cloud_mutations', 'seq'))`).Scan(&sourceLast))
	var maxSeq int64
	must(t, source.db.QueryRow(`SELECT MAX(seq) FROM cloud_mutations`).Scan(&maxSeq))
	if sourceLast <= maxSeq {
		t.Fatalf("source sequence %d not past journal max %d", sourceLast, maxSeq)
	}

	target := openIsolatedStore(t)
	archive, _ := exportArchive(t, source)
	if _, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	for cursor := int64(0); cursor <= sourceLast; cursor++ {
		for _, projects := range [][]string{nil, {"alpha"}, {"beta"}} {
			want, got := pullAll(t, source.cs, cursor, projects), pullAll(t, target.cs, cursor, projects)
			if !reflect.DeepEqual(want, got) {
				t.Errorf("cursor %d projects %v: source %+v target %+v", cursor, projects, want, got)
			}
		}
	}

	seqs, err := target.cs.InsertMutationBatch(ctx, []cloudstore.MutationEntry{{Project: "alpha", Entity: "observation", EntityKey: "obs-after", Op: "delete", Payload: json.RawMessage(`{"sync_id":"obs-after"}`)}})
	must(t, err)
	if len(seqs) != 1 || seqs[0] <= sourceLast {
		t.Fatalf("post-restore write seqs = %v, want > source sequence %d", seqs, sourceLast)
	}
	after := pullAll(t, target.cs, maxSeq, nil)
	if len(after) != 1 || after[0].EntityKey != "obs-after" {
		t.Fatalf("caught-up client at %d pulled %+v, want the post-restore write", maxSeq, after)
	}
}

func TestExportArchiveExcludesCredentialsAndPutsManifestLast(t *testing.T) {
	source := openIsolatedStore(t)
	seeded := seedSource(t, source)
	destination := seedBackupDestination(t, source)
	archive, _ := exportArchive(t, source)

	gz, err := gzip.NewReader(bytes.NewReader(archive))
	must(t, err)
	raw, err := io.ReadAll(gz)
	must(t, err)
	for _, secret := range append([]string{seeded.tokenHash, seeded.tokenPrefix, "cloud_principal_tokens.jsonl", "password_hash\":", "cloud_backup_destinations.jsonl", "cloud_backup_schedule.jsonl", "cloud_backup_runs.jsonl", "run-history-object-key-excluded"}, destination...) {
		if bytes.Contains(raw, []byte(secret)) {
			t.Errorf("archive contains %q", secret)
		}
	}

	members := readArchive(t, archive)
	last := members[len(members)-1]
	if last.name != ManifestName {
		t.Fatalf("last member = %q, want %q", last.name, ManifestName)
	}
	var manifest struct {
		Format        string `json:"format"`
		FormatVersion int    `json:"format_version"`
		CreatedAt     string `json:"created_at"`
		EngramVersion string `json:"engram_version"`
		Source        struct {
			MaxMutationSeq int64 `json:"max_mutation_seq"`
		} `json:"source"`
		Tables []struct {
			Name    string   `json:"name"`
			Member  string   `json:"member"`
			Columns []string `json:"columns"`
			Rows    int64    `json:"rows"`
			Size    int64    `json:"size"`
			SHA256  string   `json:"sha256"`
		} `json:"tables"`
		Excluded []struct {
			Table  string `json:"table"`
			Column string `json:"column"`
			Reason string `json:"reason"`
		} `json:"excluded"`
	}
	must(t, json.Unmarshal(last.data, &manifest))
	if manifest.Format != FormatName || manifest.FormatVersion != 1 || manifest.EngramVersion != "test" {
		t.Errorf("manifest header = %+v", manifest)
	}
	if created, err := time.Parse(time.RFC3339Nano, manifest.CreatedAt); err != nil || created.Location() != time.UTC {
		t.Errorf("created_at %q is not UTC RFC3339: %v", manifest.CreatedAt, err)
	}
	var maxSeq int64
	must(t, source.db.QueryRow(`SELECT MAX(seq) FROM cloud_mutations`).Scan(&maxSeq))
	if manifest.Source.MaxMutationSeq != maxSeq {
		t.Errorf("manifest max seq = %d, want %d", manifest.Source.MaxMutationSeq, maxSeq)
	}
	dataMembers := map[string][]byte{}
	for _, member := range members[:len(members)-1] {
		dataMembers[member.name] = member.data
	}
	if len(manifest.Tables) != len(restoredTables) || len(dataMembers) != len(restoredTables) {
		t.Fatalf("manifest lists %d tables and archive has %d data members, want %d", len(manifest.Tables), len(dataMembers), len(restoredTables))
	}
	for i, table := range manifest.Tables {
		if table.Name != restoredTables[i] || table.Member != "tables/"+table.Name+".jsonl" {
			t.Errorf("manifest table %d = %s (%s)", i, table.Name, table.Member)
		}
		data := dataMembers[table.Member]
		sum := sha256.Sum256(data)
		if table.SHA256 != hex.EncodeToString(sum[:]) || table.Size != int64(len(data)) || len(table.Columns) == 0 {
			t.Errorf("manifest entry %s does not describe its member", table.Name)
		}
		if lines := int64(bytes.Count(data, []byte("\n"))); lines != table.Rows {
			t.Errorf("manifest %s rows = %d, member has %d lines", table.Name, table.Rows, lines)
		}
	}
	excluded := map[string]bool{}
	for _, entry := range manifest.Excluded {
		if entry.Reason == "" {
			t.Errorf("exclusion %+v has no reason", entry)
		}
		excluded[entry.Table+"."+entry.Column] = true
	}
	for _, want := range []string{"cloud_principal_tokens.", "cloud_users.password_hash", "receipt_audit.*.", "cloud_backup_destinations.", "cloud_backup_schedule.", "cloud_backup_runs."} {
		if !excluded[want] {
			t.Errorf("manifest exclusions %+v miss %q", manifest.Excluded, want)
		}
	}
}

// seedBackupDestination stores a sealed destination in s and returns the
// values an archive must never carry.
func seedBackupDestination(t *testing.T, s isolatedStore) []string {
	t.Helper()
	ctx := context.Background()
	key, err := backupcrypto.ParseKey(hex.EncodeToString(bytes.Repeat([]byte{7}, backupcrypto.KeySize)))
	must(t, err)
	sealer, err := backupcrypto.NewSealer(key)
	must(t, err)
	const accessKeyID, secret = "AKIAARCHIVEEXCLUDED9", "archive-excluded-destination-secret"
	must(t, s.cs.PutBackupDestination(ctx, cloudstore.PutBackupDestinationParams{
		Endpoint: "https://destination-excluded.example.test", Region: "auto", Bucket: "destination-excluded-bucket",
		AccessKeyID: accessKeyID, SecretAccessKey: secret,
		Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}, sealer))
	var accessCipher, secretCipher string
	must(t, s.db.QueryRow(`SELECT access_key_id_ciphertext, secret_access_key_ciphertext FROM cloud_backup_destinations`).Scan(&accessCipher, &secretCipher))
	// The schedule and run history are operational state of this server and
	// are excluded too; the run's object key must not reach the archive.
	must(t, s.cs.PutBackupSchedule(ctx, cloudstore.PutBackupScheduleParams{
		Enabled: true, Weekdays: []time.Weekday{time.Monday}, TimeOfDay: "03:00", Timezone: "UTC",
		Actor: cloudstore.BackupDestinationActor{Source: "test"},
	}))
	run, err := s.cs.StartBackupRun(ctx, cloudstore.StartBackupRunParams{Trigger: cloudstore.BackupRunTriggerManual})
	must(t, err)
	_, err = s.cs.FinishBackupRun(ctx, cloudstore.FinishBackupRunParams{ID: run.ID, Status: cloudstore.BackupRunStatusSuccess, ObjectKey: "run-history-object-key-excluded", SizeBytes: 1})
	must(t, err)
	// The audit log (which is archived) describes the destination without
	// secrets, so only credentials and their ciphertexts are checked here.
	return []string{accessKeyID, secret, accessCipher, secretCipher}
}

func TestImportRejectsInvalidArchivesAndLeavesTargetUnchanged(t *testing.T) {
	source := openIsolatedStore(t)
	seedSource(t, source)
	archive, _ := exportArchive(t, source)
	replace := func(old, new string) func([]byte) []byte {
		return func(data []byte) []byte {
			if !bytes.Contains(data, []byte(old)) {
				t.Fatalf("member does not contain %q", old)
			}
			return bytes.Replace(data, []byte(old), []byte(new), 1)
		}
	}

	cases := []struct {
		name    string
		archive []byte
		wantErr error
	}{
		{
			name:    "corrupted member checksum",
			archive: rewriteArchive(t, archive, "tables/cloud_mutations.jsonl", replace(`"obs-alpha-2"`, `"obs-alpha-9"`), nil, false),
			wantErr: ErrChecksumMismatch,
		},
		{
			name:    "tampered chunk payload",
			archive: rewriteArchive(t, archive, "tables/cloud_chunks.jsonl", replace("line1", "LINE1"), nil, true),
			wantErr: cloudstore.ErrBackupChunkHashMismatch,
		},
		{
			name:    "unknown format version",
			archive: rewriteArchive(t, archive, "", nil, func(m map[string]any) { m["format_version"] = 2 }, false),
			wantErr: ErrUnsupportedFormat,
		},
		{
			name:    "unknown format name",
			archive: rewriteArchive(t, archive, "", nil, func(m map[string]any) { m["format"] = "other" }, false),
			wantErr: ErrUnsupportedFormat,
		},
		{
			name:    "excluded credential column injected",
			archive: rewriteArchive(t, archive, "tables/cloud_users.jsonl", replace(`"username":`, `"password_hash":"injected","username":`), nil, true),
			wantErr: cloudstore.ErrBackupInvalidRow,
		},
		{
			name: "manifest row count disagrees with member lines",
			archive: rewriteArchive(t, archive, "", nil, func(m map[string]any) {
				for _, raw := range m["tables"].([]any) {
					if entry := raw.(map[string]any); entry["name"] == "cloud_mutations" {
						entry["rows"] = entry["rows"].(float64) + 1
					}
				}
			}, false),
			wantErr: ErrInvalidArchive,
		},
		{
			name:    "missing manifest",
			archive: writeArchive(t, readArchive(t, archive)[:len(restoredTables)]),
			wantErr: ErrInvalidArchive,
		},
		{
			name:    "truncated stream",
			archive: archive[:len(archive)/2],
			wantErr: ErrInvalidArchive,
		},
		{
			name:    "truncated before gzip trailer",
			archive: archive[:len(archive)-4],
			wantErr: ErrInvalidArchive,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			target := openIsolatedStore(t)
			_, err := Import(context.Background(), target.cs, bytes.NewReader(tc.archive), ImportOptions{})
			if !errors.Is(err, tc.wantErr) {
				t.Fatalf("Import error = %v, want %v", err, tc.wantErr)
			}
			assertEmptyTarget(t, target)
		})
	}
}

func TestImportRefusesNonEmptyTargetWithoutChangingIt(t *testing.T) {
	source := openIsolatedStore(t)
	seedSource(t, source)
	archive, _ := exportArchive(t, source)

	target := openIsolatedStore(t)
	must(t, target.cs.SetProjectSyncEnabled("gamma", false, "admin", "existing"))
	before := tableRows(t, target.db, "cloud_project_controls")

	_, err := Import(context.Background(), target.cs, bytes.NewReader(archive), ImportOptions{})
	if !errors.Is(err, cloudstore.ErrBackupTargetNotEmpty) {
		t.Fatalf("Import error = %v, want %v", err, cloudstore.ErrBackupTargetNotEmpty)
	}
	if !strings.Contains(err.Error(), "cloud_project_controls") {
		t.Errorf("error %q does not name the populated table", err)
	}
	for table, n := range rowCounts(t, target.db) {
		want := 0
		if table == "cloud_project_controls" {
			want = 1
		}
		if n != want {
			t.Errorf("target %s has %d rows, want %d", table, n, want)
		}
	}
	if after := tableRows(t, target.db, "cloud_project_controls"); !reflect.DeepEqual(before, after) {
		t.Errorf("existing control changed: %v -> %v", before, after)
	}
	if !mutationSequenceUntouched(t, target.db) {
		t.Errorf("target sequence advanced")
	}
}

func TestImportKeepsTargetSequenceThatIsAlreadyPastTheSource(t *testing.T) {
	ctx := context.Background()
	source := openIsolatedStore(t)
	seedSource(t, source)
	archive, exported := exportArchive(t, source)
	const used = 500
	if exported.MaxMutationSeq >= used {
		t.Fatalf("source max seq %d must stay below %d", exported.MaxMutationSeq, used)
	}

	// A target that issued seqs and was then emptied keeps its sequence.
	target := openIsolatedStore(t)
	must(t, target.db.QueryRow(`SELECT setval(pg_get_serial_sequence('cloud_mutations', 'seq'), $1, true)`, used).Err())
	if _, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{}); err != nil {
		t.Fatalf("Import: %v", err)
	}

	var last int64
	must(t, target.db.QueryRow(`SELECT pg_sequence_last_value(pg_get_serial_sequence('cloud_mutations', 'seq')::regclass)`).Scan(&last))
	if last < used {
		t.Errorf("restore lowered cloud_mutations seq to %d, want >= %d", last, used)
	}
	seqs, err := target.cs.InsertMutationBatch(ctx, []cloudstore.MutationEntry{{Project: "alpha", Entity: "observation", EntityKey: "obs-after", Op: "delete", Payload: json.RawMessage(`{"sync_id":"obs-after"}`)}})
	must(t, err)
	if len(seqs) != 1 || seqs[0] <= used {
		t.Fatalf("post-restore write seqs = %v, want > %d", seqs, used)
	}
}

func archiveUncompressedSize(t *testing.T, archive []byte) int64 {
	t.Helper()
	var total int64
	for _, member := range readArchive(t, archive) {
		total += int64(len(member.data))
	}
	return total
}

func TestImportRefusesArchiveOverSizeLimitAndRemovesSpool(t *testing.T) {
	ctx := context.Background()
	source := openIsolatedStore(t)
	seedSource(t, source)
	archive, _ := exportArchive(t, source)
	total := archiveUncompressedSize(t, archive)

	for _, limit := range []int64{64, total - 1} {
		t.Run(fmt.Sprintf("limit %d", limit), func(t *testing.T) {
			target := openIsolatedStore(t)
			spool := t.TempDir()
			_, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{TempDir: spool, MaxArchiveBytes: limit})
			if !errors.Is(err, ErrArchiveTooLarge) {
				t.Fatalf("Import error = %v, want %v", err, ErrArchiveTooLarge)
			}
			if !strings.Contains(err.Error(), strconv.FormatInt(limit, 10)) {
				t.Errorf("error %q does not name the limit %d", err, limit)
			}
			assertEmptyTarget(t, target)
			entries, err := os.ReadDir(spool)
			must(t, err)
			if len(entries) != 0 {
				t.Errorf("spool dir kept %d entries after the refused import", len(entries))
			}
		})
	}

	t.Run("limit equal to archive size", func(t *testing.T) {
		target := openIsolatedStore(t)
		if _, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{MaxArchiveBytes: total}); err != nil {
			t.Fatalf("Import at exact limit: %v", err)
		}
	})
}

func TestImportDryRunValidatesWithoutWriting(t *testing.T) {
	ctx := context.Background()
	source := openIsolatedStore(t)
	seedSource(t, source)
	archive, exported := exportArchive(t, source)
	target := openIsolatedStore(t)

	summary, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{DryRun: true})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !summary.DryRun || !reflect.DeepEqual(summary.Tables, exported.Tables) || summary.MaxMutationSeq != exported.MaxMutationSeq {
		t.Errorf("dry-run summary = %+v, want tables of %+v", summary, exported)
	}
	assertEmptyTarget(t, target)

	tampered := rewriteArchive(t, archive, "tables/cloud_chunks.jsonl", func(data []byte) []byte {
		return bytes.Replace(data, []byte("line1"), []byte("LINE1"), 1)
	}, nil, true)
	if _, err := Import(ctx, target.cs, bytes.NewReader(tampered), ImportOptions{DryRun: true}); !errors.Is(err, cloudstore.ErrBackupChunkHashMismatch) {
		t.Fatalf("dry run of tampered archive error = %v, want chunk hash mismatch", err)
	}

	if _, err := Import(ctx, target.cs, bytes.NewReader(archive), ImportOptions{}); err != nil {
		t.Fatalf("import after dry run: %v", err)
	}
}
