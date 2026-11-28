package cloudstore

import (
	"context"
	"errors"
	"sync"
	"testing"
)

// S7/S15: verifier sealed with AD bound to the state hash: swapping two
// rows' ciphertexts or using another key refuses without consuming.
func TestBackupOAuthVerifierIsBoundToTheStateHash(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	a, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatal(err)
	}
	b, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier+"B")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_oauth_states SET verifier_ciphertext = (SELECT verifier_ciphertext FROM cloud_backup_oauth_states WHERE state_hash = $1) WHERE state_hash = $2`, oauthStateHash(a), oauthStateHash(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, b, adminID); err == nil {
		t.Fatalf("swapped ciphertext accepted")
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, testBackupSealer(t, 2), a, adminID); err == nil {
		t.Fatalf("other key accepted")
	}
	if n := oauthStateRows(t, cs); n != 2 {
		t.Fatalf("refusals consumed: rows=%d", n)
	}
	g, err := cs.ConsumeBackupOAuthState(ctx, sealer, a, adminID)
	if err != nil || g.Verifier != testOAuthVerifier {
		t.Fatalf("valid consume %v", err)
	}
}

// S15: an identical re-save, and a completed authorization, invalidate
// other pending states; the cap is per principal.
func TestBackupOAuthStatesFollowTheBindingAndCapPerPrincipal(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	other := seedSecondAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	s1, _ := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, s1, adminID); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
		t.Fatalf("identical re-save: %v", err)
	}
	o1, _ := cs.CreateBackupOAuthState(ctx, sealer, other, testOAuthVerifier)
	for i := 0; i < 8; i++ {
		if _, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier); err != nil {
			t.Fatal(err)
		}
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_oauth_states WHERE principal_id::text = '`+adminID+`'`); n != 5 {
		t.Fatalf("admin pending = %d", n)
	}
	t1, _ := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	g, err := cs.ConsumeBackupOAuthState(ctx, sealer, t1, adminID)
	if err != nil {
		t.Fatal(err)
	}
	if err := cs.SetGDriveRefreshToken(ctx, sealer, g.Binding, "1//refresh-token-value", BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	if err := cs.CheckBackupOAuthBinding(ctx, g.Binding); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
		t.Fatalf("binding after authorize: %v", err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, o1, other); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
		t.Fatalf("other admin's state after authorize: %v (cap must not have dropped it)", err)
	}
}

// S15: concurrent callbacks with the same state: exactly one consume wins.
func TestBackupOAuthConcurrentConsumesWinOnce(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	st, _ := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, st, adminID); err == nil {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 || oauthStateRows(t, cs) != 0 {
		t.Fatalf("wins=%d", wins)
	}
}

// DOCS: saving again drops the authorization.
func TestGDriveBackupDestinationResaveDropsTheAuthorization(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	if err := cs.SetGDriveRefreshToken(ctx, sealer, gdriveBinding(t, cs), "1//refresh-token-value", BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
		t.Fatal(err)
	}
	d, err := cs.OpenBackupDestination(ctx, sealer)
	if err != nil || !d.GDrive.Authorized() {
		t.Fatalf("authorized: %v", err)
	}
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatal(err)
	}
	d, err = cs.OpenBackupDestination(ctx, sealer)
	if err != nil || d.GDrive.Authorized() || d.GDrive.RefreshToken != "" {
		t.Fatalf("re-save kept authorization: %v", err)
	}
	if err := cs.SetGDriveRefreshToken(ctx, testBackupSealer(t, 2), gdriveBinding(t, cs), "1//refresh-token-value", BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); !errors.Is(err, ErrBackupDestinationKeyChanged) {
		t.Fatalf("other key: %v", err)
	}
}
