package cloudstore

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strings"
)

// Logical backup support. A backup carries Cloud tables verbatim (including
// mutation journal seq values and identity ids) so a restored server answers
// existing client cursors exactly like its source. Credentials never leave
// the database: token rows and credential hashes are excluded by construction
// because every table is read and written through an explicit column list.

var (
	ErrBackupTargetNotEmpty    = errors.New("cloudstore: backup restore target is not empty")
	ErrBackupChunkHashMismatch = errors.New("cloudstore: backup chunk id does not match its payload hash")
	ErrBackupUnknownTable      = errors.New("cloudstore: table is not part of a cloud backup")
	ErrBackupInvalidRow        = errors.New("cloudstore: invalid backup row")
	ErrBackupInvalidSequence   = errors.New("cloudstore: invalid backup sequence floor")
)

const backupChunksTable = "cloud_chunks"

// backupTableSpec is the backup contract of one table. Specs are listed in
// restore order so foreign keys are satisfied while rows are inserted.
type backupTableSpec struct {
	name    string
	columns []string
	orderBy []string
	// serial names the serial/identity column whose sequence must move past
	// the restored rows and the source sequence after a restore.
	serial string
	// identityAlways marks GENERATED ALWAYS identity columns, which require
	// OVERRIDING SYSTEM VALUE to keep their original ids.
	identityAlways bool
}

var backupTableSpecs = []backupTableSpec{
	{name: "cloud_users", columns: []string{"id", "username", "email", "created_at"}, orderBy: []string{"id"}, serial: "id"},
	{name: "cloud_principals", columns: []string{"id", "kind", "display_name", "role", "enabled", "created_at", "updated_at"}, orderBy: []string{"id"}, serial: "id"},
	{name: "cloud_human_users", columns: []string{"principal_id", "username", "email", "created_at"}, orderBy: []string{"principal_id"}},
	{name: "cloud_project_grants", columns: []string{"principal_id", "project", "granted_by_principal_id", "created_at"}, orderBy: []string{"principal_id", "project"}},
	{name: "cloud_project_controls", columns: []string{"project", "sync_enabled", "paused_reason", "updated_by", "updated_at"}, orderBy: []string{"project"}},
	{name: "cloud_auth_audit_log", columns: []string{"id", "occurred_at", "actor_principal_id", "actor_source", "target_principal_id", "project", "action", "outcome", "reason_code", "metadata"}, orderBy: []string{"id"}, serial: "id"},
	{name: "cloud_sync_audit_log", columns: []string{"id", "occurred_at", "contributor", "project", "action", "outcome", "entry_count", "reason_code", "metadata"}, orderBy: []string{"id"}, serial: "id"},
	{name: "cloud_session_authority", columns: []string{"session_id", "owner_project", "registered_by", "registered_at"}, orderBy: []string{"session_id"}},
	{name: "cloud_prompt_pair_claims", columns: []string{"session_id", "source_inbox_id", "sync_id", "prompt_project", "claimed_by", "claimed_at"}, orderBy: []string{"session_id", "source_inbox_id"}},
	{name: "cloud_prompt_source_attestations", columns: []string{"id", "session_id", "source_inbox_id", "sync_id", "owner_project", "prompt_project", "actor_id", "attested_at"}, orderBy: []string{"id"}, serial: "id", identityAlways: true},
	{name: backupChunksTable, columns: []string{"project_name", "chunk_id", "created_by", "submitted_by_principal_id", "client_created_at", "created_at", "payload", "sessions_count", "observations_count", "prompts_count"}, orderBy: []string{"created_at", "project_name", "chunk_id"}},
	// The session index is exported verbatim rather than rebuilt: rebuilding
	// would reset indexed_at and could refuse historical padded session ids.
	{name: "cloud_project_sessions", columns: []string{"project_name", "session_id", "indexed_at"}, orderBy: []string{"project_name", "session_id"}},
	{name: "cloud_mutations", columns: []string{"seq", "project", "entity", "entity_key", "op", "payload", "occurred_at"}, orderBy: []string{"seq"}, serial: "seq"},
}

// backupGuardedTables must be empty in a restore target in addition to every
// backup table; they are never restored.
var backupGuardedTables = []string{"cloud_principal_tokens"}

// BackupExclusion documents data a backup deliberately does not carry.
type BackupExclusion struct {
	Table  string `json:"table"`
	Column string `json:"column,omitempty"`
	Reason string `json:"reason"`
}

// BackupExclusions lists every table and column a backup omits and why.
func BackupExclusions() []BackupExclusion {
	return []BackupExclusion{
		{Table: "cloud_principal_tokens", Reason: "credential table (token hashes); managed tokens must be re-issued after restore"},
		{Table: "cloud_users", Column: "password_hash", Reason: "credential hash; restored as empty"},
		{Table: "cloud_chunks", Column: "user_id,imported_at,sessions,memories,prompts", Reason: "legacy pre-migration columns superseded by current columns"},
		{Table: "cloud_mutations", Column: "user_id", Reason: "legacy pre-migration column"},
		{Table: "receipt_audit.*", Reason: "startup receipt audit bound to the physical PostgreSQL instance"},
	}
}

// BackupTables lists the tables a backup carries, in restore order.
func BackupTables() []string {
	names := make([]string, 0, len(backupTableSpecs))
	for _, spec := range backupTableSpecs {
		names = append(names, spec.name)
	}
	return names
}

// BackupTableColumns returns the exact columns a backup carries for table.
func BackupTableColumns(table string) ([]string, bool) {
	spec, ok := backupTableSpecFor(table)
	if !ok {
		return nil, false
	}
	return slices.Clone(spec.columns), true
}

// backupSequenceKey names the serial column of a table as "table.column".
func backupSequenceKey(spec backupTableSpec) string {
	return spec.name + "." + spec.serial
}

func backupTableSpecFor(table string) (backupTableSpec, bool) {
	for _, spec := range backupTableSpecs {
		if spec.name == table {
			return spec, true
		}
	}
	return backupTableSpec{}, false
}

// BackupReader reads every backup table from one REPEATABLE READ snapshot.
type BackupReader struct {
	tx *sql.Tx
}

// ReadBackupSnapshot runs fn inside one read-only REPEATABLE READ transaction
// so every table it streams comes from the same snapshot.
func (cs *CloudStore) ReadBackupSnapshot(ctx context.Context, fn func(*BackupReader) error) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	tx, err := cs.db.BeginTx(ctx, &sql.TxOptions{Isolation: sql.LevelRepeatableRead, ReadOnly: true})
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup snapshot: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	return fn(&BackupReader{tx: tx})
}

// MaxMutationSeq reports the highest journal seq visible in the snapshot.
func (r *BackupReader) MaxMutationSeq(ctx context.Context) (int64, error) {
	var seq int64
	if err := r.tx.QueryRowContext(ctx, `SELECT COALESCE(MAX(seq), 0) FROM cloud_mutations`).Scan(&seq); err != nil {
		return 0, fmt.Errorf("cloudstore: backup max mutation seq: %w", err)
	}
	return seq, nil
}

// SequenceValues reports the last value of every backed-up serial sequence,
// keyed "table.column". Sequences are not transactional, so a value can exceed
// the snapshot rows; restoring past it keeps every issued cursor valid.
func (r *BackupReader) SequenceValues(ctx context.Context) (map[string]int64, error) {
	values := make(map[string]int64)
	for _, spec := range backupTableSpecs {
		if spec.serial == "" {
			continue
		}
		var value int64
		if err := r.tx.QueryRowContext(ctx,
			`SELECT COALESCE(pg_sequence_last_value(pg_get_serial_sequence($1, $2)::regclass), 0)`,
			spec.name, spec.serial,
		).Scan(&value); err != nil {
			return nil, fmt.Errorf("cloudstore: backup sequence %s: %w", backupSequenceKey(spec), err)
		}
		values[backupSequenceKey(spec)] = value
	}
	return values, nil
}

// StreamTable emits each row of table as one compact JSON object holding
// exactly the backed-up columns. Chunk payloads are re-marshaled to the
// canonical bytes their chunk id hashes, and a mismatch fails the export.
func (r *BackupReader) StreamTable(ctx context.Context, table string, emit func(row []byte) error) (int64, error) {
	spec, ok := backupTableSpecFor(table)
	if !ok {
		return 0, fmt.Errorf("%w: %q", ErrBackupUnknownTable, table)
	}
	orderBy := make([]string, 0, len(spec.orderBy))
	for _, column := range spec.orderBy {
		orderBy = append(orderBy, "t."+column)
	}
	query := fmt.Sprintf(`SELECT row_to_json(t)::text FROM (SELECT %s FROM %s) t ORDER BY %s`,
		strings.Join(spec.columns, ", "), spec.name, strings.Join(orderBy, ", "))
	rows, err := r.tx.QueryContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("cloudstore: backup read %s: %w", table, err)
	}
	defer rows.Close()

	var count int64
	for rows.Next() {
		var row []byte
		if err := rows.Scan(&row); err != nil {
			return count, fmt.Errorf("cloudstore: backup scan %s: %w", table, err)
		}
		if spec.name == backupChunksTable {
			row, err = canonicalBackupChunkRow(row)
			if err != nil {
				return count, err
			}
		}
		if err := emit(row); err != nil {
			return count, err
		}
		count++
	}
	if err := rows.Err(); err != nil {
		return count, fmt.Errorf("cloudstore: backup iterate %s: %w", table, err)
	}
	return count, nil
}

// canonicalBackupChunkRow replaces the JSONB rendering of a chunk payload with
// the canonical bytes whose hash is the chunk id, and verifies that identity.
func canonicalBackupChunkRow(row []byte) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(row, &fields); err != nil {
		return nil, fmt.Errorf("%w: cloud_chunks: %v", ErrBackupInvalidRow, err)
	}
	var project, chunkID string
	if err := json.Unmarshal(fields["project_name"], &project); err != nil {
		return nil, fmt.Errorf("%w: cloud_chunks.project_name: %v", ErrBackupInvalidRow, err)
	}
	if err := json.Unmarshal(fields["chunk_id"], &chunkID); err != nil {
		return nil, fmt.Errorf("%w: cloud_chunks.chunk_id: %v", ErrBackupInvalidRow, err)
	}
	payload, ok := marshalNormalizedJSON(fields["payload"])
	if !ok {
		return nil, fmt.Errorf("%w: cloud_chunks project %q chunk %q: payload is not JSON", ErrBackupInvalidRow, project, chunkID)
	}
	if computed := chunkIDFromPayload(payload); computed != chunkID {
		return nil, fmt.Errorf("%w: project %q chunk %q hashes to %q", ErrBackupChunkHashMismatch, project, chunkID, computed)
	}
	fields["payload"] = payload
	encoded, err := json.Marshal(fields)
	if err != nil {
		return nil, fmt.Errorf("%w: cloud_chunks project %q chunk %q: %v", ErrBackupInvalidRow, project, chunkID, err)
	}
	return encoded, nil
}

// BackupRestoreOptions controls RestoreBackup.
type BackupRestoreOptions struct {
	// DryRun validates every row inside the restore transaction and then
	// rolls it back; sequences are not touched.
	DryRun bool
	// SequenceFloors holds source sequence values keyed "table.column". Each
	// restored sequence continues after max(restored ids, floor).
	SequenceFloors map[string]int64
}

// BackupWriter inserts backup rows inside the restore transaction.
type BackupWriter struct {
	tx *sql.Tx
}

// RestoreBackup runs fn inside one transaction on an empty target, then
// advances every serial sequence and commits. Any error, or DryRun, rolls the
// whole restore back so the target is left unchanged.
func (cs *CloudStore) RestoreBackup(ctx context.Context, opts BackupRestoreOptions, fn func(*BackupWriter) error) error {
	if cs == nil || cs.db == nil {
		return fmt.Errorf("cloudstore: not initialized")
	}
	for key, floor := range opts.SequenceFloors {
		if !isBackupSequenceKey(key) {
			return fmt.Errorf("%w: unknown sequence %q", ErrBackupInvalidSequence, key)
		}
		if floor < 0 {
			return fmt.Errorf("%w: sequence %q is negative", ErrBackupInvalidSequence, key)
		}
	}

	tx, err := cs.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("cloudstore: begin backup restore: %w", err)
	}
	defer func() {
		if tx != nil {
			_ = tx.Rollback()
		}
	}()

	guarded := append(BackupTables(), backupGuardedTables...)
	if _, err := tx.ExecContext(ctx, `LOCK TABLE `+strings.Join(guarded, ", ")+` IN ACCESS EXCLUSIVE MODE`); err != nil {
		return fmt.Errorf("cloudstore: lock backup restore target: %w", err)
	}
	for _, table := range guarded {
		var populated bool
		if err := tx.QueryRowContext(ctx, `SELECT EXISTS (SELECT 1 FROM `+table+`)`).Scan(&populated); err != nil {
			return fmt.Errorf("cloudstore: check backup restore target %s: %w", table, err)
		}
		if populated {
			return fmt.Errorf("%w: table %s has rows", ErrBackupTargetNotEmpty, table)
		}
	}

	if err := fn(&BackupWriter{tx: tx}); err != nil {
		return err
	}
	if opts.DryRun {
		return nil
	}
	// setval is not transactional, so sequences move only once every row is in.
	for _, spec := range backupTableSpecs {
		if spec.serial == "" {
			continue
		}
		if err := advanceBackupSequence(ctx, tx, spec, opts.SequenceFloors[backupSequenceKey(spec)]); err != nil {
			return err
		}
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("cloudstore: commit backup restore: %w", err)
	}
	tx = nil
	cs.invalidateDashboardReadModel()
	return nil
}

func isBackupSequenceKey(key string) bool {
	for _, spec := range backupTableSpecs {
		if spec.serial != "" && backupSequenceKey(spec) == key {
			return true
		}
	}
	return false
}

func advanceBackupSequence(ctx context.Context, tx *sql.Tx, spec backupTableSpec, floor int64) error {
	var restoredMax int64
	if err := tx.QueryRowContext(ctx, fmt.Sprintf(`SELECT COALESCE(MAX(%s), 0) FROM %s`, spec.serial, spec.name)).Scan(&restoredMax); err != nil {
		return fmt.Errorf("cloudstore: restored max %s: %w", backupSequenceKey(spec), err)
	}
	last := max(restoredMax, floor)
	var err error
	if last > 0 {
		_, err = tx.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence($1, $2), $3, true)`, spec.name, spec.serial, last)
	} else {
		_, err = tx.ExecContext(ctx, `SELECT setval(pg_get_serial_sequence($1, $2), 1, false)`, spec.name, spec.serial)
	}
	if err != nil {
		return fmt.Errorf("cloudstore: advance sequence %s: %w", backupSequenceKey(spec), err)
	}
	return nil
}

// InsertRows inserts backup rows into table, keeping their original ids and
// seq values. Every row must hold exactly the backed-up columns; chunk rows
// must hash to their chunk id.
func (w *BackupWriter) InsertRows(ctx context.Context, table string, rows []json.RawMessage) error {
	spec, ok := backupTableSpecFor(table)
	if !ok {
		return fmt.Errorf("%w: %q", ErrBackupUnknownTable, table)
	}
	if len(rows) == 0 {
		return nil
	}
	var batch bytes.Buffer
	batch.WriteByte('[')
	for i, row := range rows {
		checked, err := checkBackupRow(spec, row)
		if err != nil {
			return err
		}
		if i > 0 {
			batch.WriteByte(',')
		}
		batch.Write(checked)
	}
	batch.WriteByte(']')

	overriding := ""
	if spec.identityAlways {
		overriding = " OVERRIDING SYSTEM VALUE"
	}
	columns := strings.Join(spec.columns, ", ")
	query := fmt.Sprintf(`INSERT INTO %s (%s)%s SELECT %s FROM json_populate_recordset(NULL::%s, $1::json)`,
		spec.name, columns, overriding, columns, spec.name)
	if _, err := w.tx.ExecContext(ctx, query, batch.String()); err != nil {
		return fmt.Errorf("cloudstore: restore %s: %w", table, err)
	}
	return nil
}

// checkBackupRow requires the exact column set and, for chunks, verifies that
// the canonical payload still hashes to the chunk id.
func checkBackupRow(spec backupTableSpec, row json.RawMessage) ([]byte, error) {
	var fields map[string]json.RawMessage
	if err := json.Unmarshal(row, &fields); err != nil || fields == nil {
		return nil, fmt.Errorf("%w: %s: row must be a JSON object", ErrBackupInvalidRow, spec.name)
	}
	if len(fields) != len(spec.columns) {
		return nil, fmt.Errorf("%w: %s: row has %d columns, want %d", ErrBackupInvalidRow, spec.name, len(fields), len(spec.columns))
	}
	for _, column := range spec.columns {
		if _, ok := fields[column]; !ok {
			return nil, fmt.Errorf("%w: %s: missing column %q", ErrBackupInvalidRow, spec.name, column)
		}
	}
	if spec.name == backupChunksTable {
		return canonicalBackupChunkRow(row)
	}
	return row, nil
}
