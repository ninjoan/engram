package cloudstore

import (
	"context"
	"encoding/json"
	"errors"
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
