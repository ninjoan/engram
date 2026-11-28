package cloudstore

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

const testOAuthVerifier = "pkce-verifier-do-not-leak-0123456789abcdefghijklmn"

func seedSecondAdmin(t *testing.T, cs *CloudStore) string {
	t.Helper()
	admin, err := cs.CreateHumanUser(context.Background(), CreateHumanUserParams{Username: "backup-admin-2", Email: "backup-admin-2@example.test", DisplayName: "Second Admin", Role: PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("seed second admin: %v", err)
	}
	return admin.PrincipalID
}

// gdriveOAuthStore is a store with a pending Google Drive destination.
func gdriveOAuthStore(t *testing.T) (*CloudStore, string) {
	t.Helper()
	cs := openIsolatedCloudStore(t)
	adminID := seedDestinationAdmin(t, cs)
	if err := cs.PutGDriveDestination(context.Background(), validGDriveParams(adminID), testBackupSealer(t, 1)); err != nil {
		t.Fatalf("PutGDriveDestination: %v", err)
	}
	return cs, adminID
}

func oauthStateRows(t *testing.T, cs *CloudStore) int {
	t.Helper()
	return countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_oauth_states`)
}

func oauthStateHash(state string) string {
	sum := sha256.Sum256([]byte(state))
	return hex.EncodeToString(sum[:])
}

// S15/S7: a state is 32 random bytes (43 base64url characters); only its
// SHA-256 is stored, with the principal, the destination binding, the
// verifier sealed with the backup key and a 10 minute expiry. Consuming it
// returns the verifier exactly once.
func TestBackupOAuthStateCreateAndConsumeOnce(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatalf("CreateBackupOAuthState: %v", err)
	}
	if len(state) != 43 || strings.Trim(state, "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_") != "" {
		t.Fatalf("state %q is not 43 base64url characters", state)
	}
	var row, hash, principal string
	var ttl float64
	if err := cs.db.QueryRowContext(ctx, `SELECT row_to_json(s)::text, state_hash, principal_id::text, EXTRACT(EPOCH FROM expires_at - created_at) FROM cloud_backup_oauth_states s`).Scan(&row, &hash, &principal, &ttl); err != nil {
		t.Fatalf("read state row: %v", err)
	}
	if hash != oauthStateHash(state) || principal != adminID || ttl != BackupOAuthStateTTL.Seconds() {
		t.Fatalf("row hash %q principal %q ttl %v, want %q %q %v", hash, principal, ttl, oauthStateHash(state), adminID, BackupOAuthStateTTL.Seconds())
	}
	if strings.Contains(row, state) || strings.Contains(row, testOAuthVerifier) {
		t.Fatalf("state row stores the raw state or verifier: %s", row)
	}
	grant, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID)
	if err != nil {
		t.Fatalf("ConsumeBackupOAuthState: %v", err)
	}
	if grant.Verifier != testOAuthVerifier || grant.Binding == "" {
		t.Fatalf("grant = %+v", grant)
	}
	if text := fmtAnyValue(grant); strings.Contains(text, testOAuthVerifier) {
		t.Fatalf("grant formats its verifier: %s", text)
	}
	if err := cs.CheckBackupOAuthBinding(ctx, grant.Binding); err != nil {
		t.Fatalf("CheckBackupOAuthBinding: %v", err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID); !errors.Is(err, ErrBackupOAuthStateNotFound) {
		t.Fatalf("second consume = %v, want %v", err, ErrBackupOAuthStateNotFound)
	}
	if n := oauthStateRows(t, cs); n != 0 {
		t.Fatalf("%d state rows after consume", n)
	}
}

// An expired state is refused and left in place (no write); the next create
// purges expired rows.
func TestBackupOAuthStateExpiryAndPurge(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_oauth_states SET created_at = NOW() - interval '11 minutes', expires_at = NOW() - interval '1 minute'`); err != nil {
		t.Fatalf("age the state: %v", err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID); !errors.Is(err, ErrBackupOAuthStateExpired) {
		t.Fatalf("expired consume = %v, want %v", err, ErrBackupOAuthStateExpired)
	}
	if n := oauthStateRows(t, cs); n != 1 {
		t.Fatalf("a refused consume changed the state rows: %d", n)
	}
	if _, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier); err != nil {
		t.Fatalf("second create: %v", err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_backup_oauth_states WHERE expires_at <= NOW()`); n != 0 {
		t.Fatalf("create kept %d expired rows", n)
	}
	if n := oauthStateRows(t, cs); n != 1 {
		t.Fatalf("state rows = %d, want only the new one", n)
	}
}

// A state belongs to the admin who started it: another admin's consume is
// refused without consuming it.
func TestBackupOAuthStateIsBoundToThePrincipal(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	otherID := seedSecondAdmin(t, cs)
	sealer := testBackupSealer(t, 1)
	state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	for _, principal := range []string{otherID, "", "999999"} {
		if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, principal); !errors.Is(err, ErrBackupOAuthStatePrincipal) {
			t.Fatalf("consume as %q = %v, want %v", principal, err, ErrBackupOAuthStatePrincipal)
		}
	}
	if n := oauthStateRows(t, cs); n != 1 {
		t.Fatalf("refused consumes changed the state rows: %d", n)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID); err != nil {
		t.Fatalf("owner consume: %v", err)
	}
}

// A state is bound to the destination as it was when the authorization
// started: saving the settings again, switching kind, removing it or the
// authorization itself all invalidate it.
func TestBackupOAuthStateIsBoundToTheDestination(t *testing.T) {
	ctx := context.Background()
	for name, change := range map[string]func(t *testing.T, cs *CloudStore, adminID string){
		"saved again": func(t *testing.T, cs *CloudStore, adminID string) {
			if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), testBackupSealer(t, 1)); err != nil {
				t.Fatal(err)
			}
		},
		"other client": func(t *testing.T, cs *CloudStore, adminID string) {
			p := validGDriveParams(adminID)
			p.ClientID = "999999999999-other.apps.googleusercontent.com"
			if err := cs.PutGDriveDestination(ctx, p, testBackupSealer(t, 1)); err != nil {
				t.Fatal(err)
			}
		},
		"switched to s3": func(t *testing.T, cs *CloudStore, adminID string) {
			if err := cs.PutBackupDestination(ctx, validDestinationParams(adminID), testBackupSealer(t, 1)); err != nil {
				t.Fatal(err)
			}
		},
		"removed": func(t *testing.T, cs *CloudStore, adminID string) {
			if err := cs.ClearBackupDestination(ctx, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
				t.Fatal(err)
			}
		},
	} {
		t.Run(name, func(t *testing.T) {
			cs, adminID := gdriveOAuthStore(t)
			sealer := testBackupSealer(t, 1)
			state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
			if err != nil {
				t.Fatalf("create: %v", err)
			}
			time.Sleep(5 * time.Millisecond) // updated_at must move past the state's binding
			change(t, cs, adminID)
			if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
				t.Fatalf("consume after change = %v, want %v", err, ErrBackupOAuthDestinationChanged)
			}
			if n := oauthStateRows(t, cs); n != 1 {
				t.Fatalf("a refused consume changed the state rows: %d", n)
			}
		})
	}
	t.Run("authorized meanwhile", func(t *testing.T) {
		cs, adminID := gdriveOAuthStore(t)
		sealer := testBackupSealer(t, 1)
		state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
		if err != nil {
			t.Fatalf("create: %v", err)
		}
		grant, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID)
		if err != nil {
			t.Fatalf("consume: %v", err)
		}
		time.Sleep(5 * time.Millisecond)
		if err := cs.SetGDriveRefreshToken(ctx, sealer, grant.Binding, testGDriveRefreshToken, BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}); err != nil {
			t.Fatalf("SetGDriveRefreshToken: %v", err)
		}
		if err := cs.CheckBackupOAuthBinding(ctx, grant.Binding); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
			t.Fatalf("binding after authorize = %v, want %v", err, ErrBackupOAuthDestinationChanged)
		}
	})
}

// gdriveBinding is the binding of the stored Google Drive destination, the
// value a consumed state returns; "" when there is none.
func gdriveBinding(t *testing.T, cs *CloudStore) string {
	t.Helper()
	binding, err := readBackupOAuthBinding(context.Background(), cs.db)
	if err != nil {
		return ""
	}
	return binding
}

// The token write compares the consumed state's binding under the
// destination row lock: a destination saved again between the consume and
// the write (or a missing binding) is refused with
// ErrBackupOAuthDestinationChanged, and nothing is written.
func TestSetGDriveRefreshTokenRefusesAChangedOAuthBinding(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	actor := BackupDestinationActor{PrincipalID: adminID, Source: "dashboard"}
	state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	grant, err := cs.ConsumeBackupOAuthState(ctx, sealer, state, adminID)
	if err != nil {
		t.Fatalf("consume: %v", err)
	}
	time.Sleep(5 * time.Millisecond) // updated_at must move
	if err := cs.PutGDriveDestination(ctx, validGDriveParams(adminID), sealer); err != nil {
		t.Fatalf("save again: %v", err)
	}
	before := destinationRowText(t, cs)
	for name, binding := range map[string]string{"stale": grant.Binding, "empty": ""} {
		if err := cs.SetGDriveRefreshToken(ctx, sealer, binding, testGDriveRefreshToken, actor); !errors.Is(err, ErrBackupOAuthDestinationChanged) {
			t.Fatalf("%s binding = %v, want %v", name, err, ErrBackupOAuthDestinationChanged)
		}
	}
	if after := destinationRowText(t, cs); after != before {
		t.Fatalf("a refused write changed the destination row:\nbefore %s\nafter  %s", before, after)
	}
	if got, err := cs.GetBackupDestination(ctx); err != nil || got.GDrive.Authorized {
		t.Fatalf("a refused write authorized the destination: %+v, %v", got, err)
	}
	if n := countRows(t, cs, `SELECT COUNT(*) FROM cloud_auth_audit_log WHERE action = 'backup.destination.authorize'`); n != 0 {
		t.Fatalf("refused writes recorded %d authorize audits", n)
	}
	// The current binding still authorizes.
	if err := cs.SetGDriveRefreshToken(ctx, sealer, gdriveBinding(t, cs), testGDriveRefreshToken, actor); err != nil {
		t.Fatalf("current binding: %v", err)
	}
	if got, err := cs.GetBackupDestination(ctx); err != nil || !got.GDrive.Authorized {
		t.Fatalf("current binding did not authorize: %+v, %v", got, err)
	}
}

// Unknown, malformed or tampered states are refused without touching any
// row; a verifier sealed for one state does not open for another, and a
// verifier sealed with another key does not open at all.
func TestBackupOAuthStateRefusesTamperedStatesAndCiphertexts(t *testing.T) {
	ctx := context.Background()
	cs, adminID := gdriveOAuthStore(t)
	sealer := testBackupSealer(t, 1)
	state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	flipped := []byte(state)
	flipped[0] ^= 1
	if flipped[0] == '-' || flipped[0] == '_' {
		flipped[0] = 'A'
	}
	for _, bad := range []string{"", "short", strings.Repeat("A", 43), string(flipped), state + "A", " " + state, state[:42] + "=", oauthStateHash(state)} {
		if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, bad, adminID); !errors.Is(err, ErrBackupOAuthStateNotFound) {
			t.Fatalf("consume %q = %v, want %v", bad, err, ErrBackupOAuthStateNotFound)
		}
	}
	if n := oauthStateRows(t, cs); n != 1 {
		t.Fatalf("refused consumes changed the state rows: %d", n)
	}

	// Another key cannot open the verifier, and the state stays unconsumed.
	if _, err := cs.ConsumeBackupOAuthState(ctx, testBackupSealer(t, 2), state, adminID); err == nil || errors.Is(err, ErrBackupOAuthStateNotFound) {
		t.Fatalf("consume with another key = %v, want an open error", err)
	}
	if n := oauthStateRows(t, cs); n != 1 {
		t.Fatalf("a consume with another key changed the state rows: %d", n)
	}

	// The verifier is bound to its own state: swapping ciphertexts breaks it.
	second, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, "another-verifier-0123456789abcdefghijklmnopqrstuv")
	if err != nil {
		t.Fatalf("second create: %v", err)
	}
	if _, err := cs.db.ExecContext(ctx, `UPDATE cloud_backup_oauth_states SET verifier_ciphertext = (SELECT verifier_ciphertext FROM cloud_backup_oauth_states WHERE state_hash = $1) WHERE state_hash = $2`, oauthStateHash(state), oauthStateHash(second)); err != nil {
		t.Fatalf("swap ciphertexts: %v", err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, second, adminID); err == nil || errors.Is(err, ErrBackupOAuthStateNotFound) {
		t.Fatalf("consume with a swapped verifier = %v, want an open error", err)
	}
}

// Create needs a Google Drive destination, the key, a principal and a valid
// PKCE verifier; a refusal writes nothing. Each admin keeps at most
// maxBackupOAuthStatesPerPrincipal pending states.
func TestBackupOAuthStateCreateRefusalsAndCap(t *testing.T) {
	ctx := context.Background()
	empty := openIsolatedCloudStore(t)
	emptyAdmin := seedDestinationAdmin(t, empty)
	sealer := testBackupSealer(t, 1)
	if _, err := empty.CreateBackupOAuthState(ctx, sealer, emptyAdmin, testOAuthVerifier); !errors.Is(err, ErrBackupDestinationNotConfigured) {
		t.Fatalf("create without destination = %v", err)
	}
	if err := empty.PutBackupDestination(ctx, validDestinationParams(emptyAdmin), sealer); err != nil {
		t.Fatal(err)
	}
	if _, err := empty.CreateBackupOAuthState(ctx, sealer, emptyAdmin, testOAuthVerifier); !errors.Is(err, ErrBackupDestinationKindMismatch) {
		t.Fatalf("create for s3 = %v", err)
	}
	if n := oauthStateRows(t, empty); n != 0 {
		t.Fatalf("refused creates wrote %d rows", n)
	}

	cs, adminID := gdriveOAuthStore(t)
	for name, call := range map[string]func() error{
		"nil sealer": func() error { _, err := cs.CreateBackupOAuthState(ctx, nil, adminID, testOAuthVerifier); return err },
		"no principal": func() error {
			_, err := cs.CreateBackupOAuthState(ctx, sealer, " ", testOAuthVerifier)
			return err
		},
		"short verifier": func() error { _, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, "short"); return err },
		"spaced verifier": func() error {
			_, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, strings.Repeat("a", 40)+" bcdefg")
			return err
		},
	} {
		if err := call(); err == nil {
			t.Fatalf("%s: create accepted", name)
		}
	}
	if n := oauthStateRows(t, cs); n != 0 {
		t.Fatalf("refused creates wrote %d rows", n)
	}
	var states []string
	for i := 0; i < maxBackupOAuthStatesPerPrincipal+2; i++ {
		state, err := cs.CreateBackupOAuthState(ctx, sealer, adminID, testOAuthVerifier)
		if err != nil {
			t.Fatalf("create %d: %v", i, err)
		}
		states = append(states, state)
	}
	if n := oauthStateRows(t, cs); n != maxBackupOAuthStatesPerPrincipal {
		t.Fatalf("pending states = %d, want %d", n, maxBackupOAuthStatesPerPrincipal)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, states[0], adminID); !errors.Is(err, ErrBackupOAuthStateNotFound) {
		t.Fatalf("oldest state = %v, want it dropped", err)
	}
	if _, err := cs.ConsumeBackupOAuthState(ctx, sealer, states[len(states)-1], adminID); err != nil {
		t.Fatalf("newest state: %v", err)
	}
}

// The state table is never exported, is listed among the exclusions, and is
// one of the tables a restore target must have empty, like the other backup
// tables.
func TestBackupExcludesTheOAuthStateTable(t *testing.T) {
	if slices.Contains(BackupTables(), backupOAuthStatesTable) {
		t.Fatalf("BackupTables() carries %s", backupOAuthStatesTable)
	}
	if _, ok := BackupTableColumns(backupOAuthStatesTable); ok {
		t.Fatalf("%s has backup columns", backupOAuthStatesTable)
	}
	found := false
	for _, exclusion := range BackupExclusions() {
		if exclusion.Table == backupOAuthStatesTable && exclusion.Column == "" && exclusion.Reason != "" {
			found = true
		}
	}
	if !found || !slices.Contains(backupGuardedTables, backupOAuthStatesTable) {
		t.Fatalf("exclusions %+v / guarded %v miss %s", BackupExclusions(), backupGuardedTables, backupOAuthStatesTable)
	}
}

func fmtAnyValue(v any) string { return fmt.Sprintf("%v %+v %#v", v, v, v) }
