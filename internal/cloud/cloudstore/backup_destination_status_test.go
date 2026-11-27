package cloudstore

import (
	"context"
	"testing"
	"time"
)

// insertDestinationTestAudit records a backup.destination.test row at an
// explicit time relative to the stored destination's updated_at.
func insertDestinationTestAudit(t *testing.T, cs *CloudStore, actorID, action, outcome, reason string, offset time.Duration) {
	t.Helper()
	_, err := cs.db.ExecContext(context.Background(), `
		INSERT INTO cloud_auth_audit_log (occurred_at, actor_principal_id, actor_source, action, outcome, reason_code, metadata)
		SELECT d.updated_at + make_interval(secs => $1), $2, 'dashboard', $3, $4, NULLIF($5, ''), '{"result":"x"}'::jsonb
		FROM cloud_backup_destinations d WHERE d.id = 1`,
		offset.Seconds(), nullableID(actorID), action, outcome, reason)
	if err != nil {
		t.Fatalf("insert test audit: %v", err)
	}
}

func TestLatestBackupDestinationTestWithoutDestinationIsZero(t *testing.T) {
	cs := openIsolatedCloudStore(t)
	got, err := cs.LatestBackupDestinationTest(context.Background())
	if err != nil {
		t.Fatalf("LatestBackupDestinationTest: %v", err)
	}
	if got.Tested() || got != (BackupDestinationTest{}) {
		t.Fatalf("no destination must report no test, got %+v", got)
	}
}

func TestLatestBackupDestinationTestOnlyCountsTestsSinceTheLastUpdate(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatalf("PutBackupDestination: %v", err)
	}
	destination, err := cs.GetBackupDestination(ctx)
	if err != nil {
		t.Fatal(err)
	}

	// Saved, never tested since: a test older than updated_at is ignored.
	insertDestinationTestAudit(t, cs, adminID, AuthAuditActionBackupDestinationTest, "success", "", -time.Minute)
	if got, err := cs.LatestBackupDestinationTest(ctx); err != nil || got.Tested() {
		t.Fatalf("a test older than the last update must be ignored, got %+v, %v", got, err)
	}

	// Newest test since the update wins; other actions never count.
	insertDestinationTestAudit(t, cs, adminID, AuthAuditActionBackupDestinationTest, "success", "", 10*time.Second)
	insertDestinationTestAudit(t, cs, adminID, AuthAuditActionBackupDestinationTest, "failure", "auth_failed", 20*time.Second)
	insertDestinationTestAudit(t, cs, adminID, AuthAuditActionBackupDestinationUpdate, "success", "", 30*time.Second)
	got, err := cs.LatestBackupDestinationTest(ctx)
	if err != nil {
		t.Fatalf("LatestBackupDestinationTest: %v", err)
	}
	if !got.Tested() || got.Succeeded || got.ReasonCode != "auth_failed" || got.ActorPrincipalID != adminID || got.ActorName != "Backup Admin" {
		t.Fatalf("newest test = %+v, want the failed auth_failed test by Backup Admin", got)
	}
	if want := destination.UpdatedAt.Add(20 * time.Second); !got.OccurredAt.Equal(want) {
		t.Fatalf("OccurredAt = %v, want %v", got.OccurredAt, want)
	}

	insertDestinationTestAudit(t, cs, "", AuthAuditActionBackupDestinationTest, "success", "", 40*time.Second)
	got, err = cs.LatestBackupDestinationTest(ctx)
	if err != nil || !got.Succeeded || got.ReasonCode != "" || got.ActorPrincipalID != "" || got.ActorName != "" {
		t.Fatalf("newest successful test without an actor = %+v, %v", got, err)
	}

	// Saving the destination again resets the status: every earlier test
	// predates the new updated_at.
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_destinations SET updated_at = updated_at + interval '1 minute' WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.LatestBackupDestinationTest(ctx); err != nil || got.Tested() {
		t.Fatalf("after an update no earlier test may count, got %+v, %v", got, err)
	}

	// Removing the destination leaves nothing to report.
	insertDestinationTestAudit(t, cs, adminID, AuthAuditActionBackupDestinationTest, "success", "", time.Second)
	if err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.LatestBackupDestinationTest(ctx); err != nil || got.Tested() {
		t.Fatalf("without a destination no test may count, got %+v, %v", got, err)
	}
}

func TestLatestBackupDestinationTestFollowsARealSave(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if err := cs.InsertAuthAuditEvent(ctx, AuthAuditEvent{ActorPrincipalID: adminID, ActorSource: "dashboard", Action: AuthAuditActionBackupDestinationTest, Outcome: "success", Metadata: map[string]any{"result": "ok"}}); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.LatestBackupDestinationTest(ctx); err != nil || !got.Tested() || !got.Succeeded {
		t.Fatalf("a test after the save must count, got %+v, %v", got, err)
	}
	if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if got, err := cs.LatestBackupDestinationTest(ctx); err != nil || got.Tested() {
		t.Fatalf("saving again must reset the status to not tested, got %+v, %v", got, err)
	}
}
