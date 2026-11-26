package cloudstore

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"
)

func TestReadBackupSnapshotRefusesChunkWhosePayloadDoesNotHashToItsID(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	if _, err := cs.db.ExecContext(ctx, `
		INSERT INTO cloud_chunks (project_name, chunk_id, created_by, payload)
		VALUES ('alpha', 'not-hash', 'fixture', '{"sessions":[]}')`); err != nil {
		t.Fatalf("seed chunk: %v", err)
	}

	emitted := 0
	err := cs.ReadBackupSnapshot(ctx, func(r *BackupReader) error {
		_, err := r.StreamTable(ctx, "cloud_chunks", func([]byte) error { emitted++; return nil })
		return err
	})
	if !errors.Is(err, ErrBackupChunkHashMismatch) {
		t.Fatalf("StreamTable error = %v, want %v", err, ErrBackupChunkHashMismatch)
	}
	if emitted != 0 {
		t.Fatalf("emitted %d rows before the mismatch, want 0", emitted)
	}
}

func TestRestoreBackupFailureLeavesSequencesUnchanged(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	read := func() (v int64, c bool) {
		t.Helper()
		if err := cs.db.QueryRowContext(ctx, `SELECT last_value, is_called FROM cloud_users_id_seq`).Scan(&v, &c); err != nil {
			t.Fatal(err)
		}
		return v, c
	}
	bv, bc := read()
	// cloud_users.id is valid and ordered first; the audit floor exceeds the
	// int4 serial bound, so the restore must fail before any setval runs.
	floors := map[string]int64{"cloud_users.id": 777, "cloud_sync_audit_log.id": 3000000000}
	noRows := func(*BackupWriter) error { return nil }

	if err := cs.RestoreBackup(ctx, BackupRestoreOptions{DryRun: true, SequenceFloors: floors}, noRows); !errors.Is(err, ErrBackupInvalidSequence) {
		t.Errorf("dry-run error = %v, want %v", err, ErrBackupInvalidSequence)
	}
	err := cs.RestoreBackup(ctx, BackupRestoreOptions{SequenceFloors: floors}, noRows)
	if !errors.Is(err, ErrBackupInvalidSequence) {
		t.Fatalf("restore error = %v, want %v", err, ErrBackupInvalidSequence)
	}
	if !strings.Contains(err.Error(), "cloud_sync_audit_log.id") {
		t.Errorf("error %q does not name the out-of-range sequence", err)
	}
	if av, ac := read(); av != bv || ac != bc {
		t.Fatalf("failed restore moved cloud_users_id_seq: (%d,%v) -> (%d,%v)", bv, bc, av, ac)
	}
}

func TestRestoreBackupRejectsUnknownTablesAndSequencesWithoutWriting(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)

	err := cs.RestoreBackup(ctx, BackupRestoreOptions{SequenceFloors: map[string]int64{"cloud_principal_tokens.id": 5}}, func(*BackupWriter) error { return nil })
	if !errors.Is(err, ErrBackupInvalidSequence) {
		t.Fatalf("unknown sequence error = %v, want %v", err, ErrBackupInvalidSequence)
	}

	err = cs.RestoreBackup(ctx, BackupRestoreOptions{}, func(w *BackupWriter) error {
		if err := w.InsertRows(ctx, "cloud_project_controls", []json.RawMessage{json.RawMessage(`{"project":"p","sync_enabled":false,"paused_reason":null,"updated_by":null,"updated_at":"2026-01-01T00:00:00Z"}`)}); err != nil {
			return err
		}
		return w.InsertRows(ctx, "cloud_principal_tokens", []json.RawMessage{json.RawMessage(`{}`)})
	})
	if !errors.Is(err, ErrBackupUnknownTable) {
		t.Fatalf("token table error = %v, want %v", err, ErrBackupUnknownTable)
	}
	var controls int
	if err := cs.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM cloud_project_controls`).Scan(&controls); err != nil {
		t.Fatalf("count controls: %v", err)
	}
	if controls != 0 {
		t.Fatalf("failed restore left %d control rows, want 0", controls)
	}
}
