package main

import (
	"context"
	"strings"
	"testing"

	cloudauth "github.com/Gentleman-Programming/engram/v3/internal/cloud/auth"
	"github.com/Gentleman-Programming/engram/v3/internal/cloud/cloudstore"
)

const recoverPrincipalTestPepper = "dedicated-cloud-token-pepper-for-tests"

func TestParseCloudBootstrapRecoverTokenArgsPrincipal(t *testing.T) {
	args, err := parseCloudBootstrapRecoverTokenArgs([]string{"--principal", " second-admin ", "--name", "restored"})
	if err != nil || args.principal != "second-admin" || args.name != "restored" || args.revokeExisting {
		t.Fatalf("parse --principal = %+v, %v", args, err)
	}
	for _, bad := range [][]string{{"--principal"}, {"--principal", "--name"}, {"--principal", "  "}} {
		if _, err := parseCloudBootstrapRecoverTokenArgs(bad); err == nil || !strings.Contains(err.Error(), "--principal requires a") {
			t.Fatalf("parseCloudBootstrapRecoverTokenArgs(%q) = %v, want --principal value error", bad, err)
		}
	}
}

func TestCloudBootstrapRecoverTokenPassesSelectedPrincipalAndAuditsSelection(t *testing.T) {
	stubExitWithPanic(t)
	t.Setenv("ENGRAM_CLOUD_TOKEN_PEPPER", recoverPrincipalTestPepper)
	store := &fakeCloudBootstrapStore{}
	stubNewCloudBootstrapStore(t, store)

	withArgs(t, "engram", "cloud", "bootstrap", "recover-token", "--principal", "second-admin")
	stdout, _, recovered := captureOutputAndRecover(t, cmdCloudBootstrap)
	if recovered != nil {
		t.Fatalf("expected selected recovery to succeed, got %v", recovered)
	}
	if store.recoverTokenCalls != 1 || store.recoverTokenParams.Principal != "second-admin" || store.recoverTokenParams.RevokeExisting {
		t.Fatalf("expected the selector to reach the store, calls=%d params=%+v", store.recoverTokenCalls, store.recoverTokenParams)
	}
	if strings.Count(stdout, "egc_live_") != 1 {
		t.Fatalf("expected the raw token exactly once, got %q", stdout)
	}
	if len(store.auditEvents) != 1 || store.auditEvents[0].ReasonCode != "selected_admin_token_recovered" || store.auditEvents[0].Metadata["principal_selector"] != "second-admin" || store.auditEvents[0].Metadata["recovered"] != true {
		t.Fatalf("expected selected recovery audit, got %+v", store.auditEvents)
	}
}

func TestCloudBootstrapRecoverTokenWithoutPrincipalKeepsStrandedAudit(t *testing.T) {
	stubExitWithPanic(t)
	t.Setenv("ENGRAM_CLOUD_TOKEN_PEPPER", recoverPrincipalTestPepper)
	store := &fakeCloudBootstrapStore{}
	stubNewCloudBootstrapStore(t, store)

	withArgs(t, "engram", "cloud", "bootstrap", "recover-token")
	stdout, stderr, recovered := captureOutputAndRecover(t, cmdCloudBootstrap)
	if recovered != nil || stderr != "" {
		t.Fatalf("expected stranded recovery to succeed silently on stderr, got %v stderr=%q", recovered, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	if len(lines) != 2 || lines[0] != "Managed admin token recovered — SHOWN ONCE, copy and store it now, it cannot be retrieved again:" || !strings.HasPrefix(lines[1], "egc_live_") {
		t.Fatalf("stranded recovery output changed: %q", stdout)
	}
	if store.recoverTokenParams.Principal != "" || store.recoverTokenParams.Name != "cli-bootstrap-recovery" {
		t.Fatalf("no-flag recovery must not select a principal, got %+v", store.recoverTokenParams)
	}
	event := store.auditEvents[0]
	if event.ReasonCode != "stranded_admin_token_recovered" || len(event.Metadata) != 2 || event.Metadata["recovered"] != true {
		t.Fatalf("no-flag recovery audit changed: %+v", event)
	}
}

func TestCloudBootstrapHelpDocumentsRecoverTokenPrincipal(t *testing.T) {
	withArgs(t, "engram", "cloud", "bootstrap", "--help")
	stdout, _, recovered := captureOutputAndRecover(t, cmdCloudBootstrap)
	if recovered != nil {
		t.Fatalf("expected help to return normally, got %v", recovered)
	}
	for _, want := range []string{
		"engram cloud bootstrap recover-token [--principal <id|username>] [--name <name>] [--revoke-existing]",
		"--principal selects one enabled managed admin by principal id or exact username",
	} {
		if !strings.Contains(stdout, want) {
			t.Fatalf("help missing %q: %q", want, stdout)
		}
	}
}

// --- Postgres-gated: real cloudstore through the CLI ---------------------

type recoverPrincipalDB struct {
	cloudBackupTestDB
	first, second cloudstore.HumanUser
}

func openRecoverPrincipalDB(t *testing.T) recoverPrincipalDB {
	t.Helper()
	d := openCloudBackupTestDB(t)
	t.Setenv("ENGRAM_DATABASE_URL", d.dsn)
	t.Setenv("ENGRAM_CLOUD_TOKEN_PEPPER", recoverPrincipalTestPepper)
	ctx := context.Background()
	first, err := d.cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "restored-first", DisplayName: "Restored First", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	second, err := d.cs.CreateHumanUser(ctx, cloudstore.CreateHumanUserParams{Username: "restored-second", DisplayName: "Restored Second", Role: cloudstore.PrincipalRoleAdmin})
	if err != nil {
		t.Fatal(err)
	}
	return recoverPrincipalDB{cloudBackupTestDB: d, first: first, second: second}
}

func (d recoverPrincipalDB) count(t *testing.T, query string) int {
	t.Helper()
	var n int
	if err := d.db.QueryRow(query).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func runRecoverToken(t *testing.T, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	stubExitWithPanic(t)
	withArgs(t, append([]string{"engram", "cloud", "bootstrap", "recover-token"}, args...)...)
	stdout, stderr, recovered := captureOutputAndRecover(t, cmdCloudBootstrap)
	if recovered != nil {
		c, ok := recovered.(exitCode)
		if !ok {
			t.Fatalf("unexpected panic: %v", recovered)
		}
		code = int(c)
	}
	return stdout, stderr, code
}

func TestCloudBootstrapRecoverTokenPrincipalIssuesAuthenticatingTokenAfterRestore(t *testing.T) {
	d := openRecoverPrincipalDB(t)

	stdout, stderr, code := runRecoverToken(t, "--principal", "restored-second", "--name", "restored")
	if code != 0 {
		t.Fatalf("exit %d stderr=%q", code, stderr)
	}
	lines := strings.Split(strings.TrimSpace(stdout), "\n")
	rawToken := strings.TrimSpace(lines[len(lines)-1])
	if strings.Count(stdout, "egc_live_") != 1 || !strings.HasPrefix(rawToken, "egc_live_") {
		t.Fatalf("expected the raw token exactly once, got %q", stdout)
	}
	ctx := context.Background()
	if tokens, err := d.cs.ListPrincipalTokens(ctx, d.first.PrincipalID); err != nil || len(tokens) != 0 {
		t.Fatalf("unselected admin must get no token, tokens=%+v err=%v", tokens, err)
	}
	tokens, err := d.cs.ListPrincipalTokens(ctx, d.second.PrincipalID)
	if err != nil || len(tokens) != 1 || tokens[0].Name != "restored" {
		t.Fatalf("selected admin must get exactly one token, tokens=%+v err=%v", tokens, err)
	}
	events, err := d.cs.ListAuthAuditEvents(ctx, cloudstore.AuthAuditQuery{Limit: 10})
	if err != nil || len(events) != 1 || events[0].TargetPrincipalID != d.second.PrincipalID || events[0].ReasonCode != "selected_admin_token_recovered" || events[0].Metadata["principal_selector"] != "restored-second" {
		t.Fatalf("expected one selected recovery audit, events=%+v err=%v", events, err)
	}
	for _, value := range events[0].Metadata {
		if s, ok := value.(string); ok && strings.Contains(s, rawToken) {
			t.Fatalf("audit metadata leaked the raw token: %+v", events[0].Metadata)
		}
	}

	hasher, err := cloudauth.NewManagedTokenHasher([]byte(recoverPrincipalTestPepper))
	if err != nil {
		t.Fatal(err)
	}
	resolver := cloudauth.NewPrincipalResolver(cloudauth.ResolverConfig{Hasher: hasher, ManagedTokens: cloudstoreManagedTokenLookup{store: d.cs}})
	principal, err := resolver.ResolveBearerToken(ctx, rawToken)
	if err != nil || principal.ID != d.second.PrincipalID || principal.Role != cloudauth.RoleAdmin || principal.Source != cloudauth.PrincipalSourceManagedToken {
		t.Fatalf("issued token must authenticate as the selected admin, principal=%+v err=%v", principal, err)
	}
}

func TestCloudBootstrapRecoverTokenWithoutPrincipalStillRefusesMultipleAdmins(t *testing.T) {
	d := openRecoverPrincipalDB(t)

	stdout, stderr, code := runRecoverToken(t)
	if code != 1 || !strings.Contains(stderr, "requires exactly one enabled managed human admin, found 2") || strings.Contains(stdout, "egc_live_") {
		t.Fatalf("no-flag recovery must keep refusing multiple admins: exit %d stdout=%q stderr=%q", code, stdout, stderr)
	}
	if n := d.count(t, `SELECT COUNT(*) FROM cloud_principal_tokens`); n != 0 {
		t.Fatalf("refusal wrote %d tokens", n)
	}
	if n := d.count(t, `SELECT COUNT(*) FROM cloud_auth_audit_log`); n != 0 {
		t.Fatalf("refusal wrote %d audit rows", n)
	}
}

func TestCloudBootstrapRecoverTokenPrincipalRefusals(t *testing.T) {
	cases := []struct {
		name       string
		setup      func(t *testing.T, d recoverPrincipalDB) string
		wantStderr string
		wantTokens int
	}{
		{
			name:       "unknown principal",
			setup:      func(*testing.T, recoverPrincipalDB) string { return "nobody" },
			wantStderr: `selected principal "nobody" was not found`,
		},
		{
			name: "disabled admin",
			setup: func(t *testing.T, d recoverPrincipalDB) string {
				if err := d.cs.SetHumanUserEnabled(context.Background(), d.second.PrincipalID, false); err != nil {
					t.Fatal(err)
				}
				return d.second.PrincipalID
			},
			wantStderr: "is disabled",
		},
		{
			name: "non-admin principal",
			setup: func(t *testing.T, d recoverPrincipalDB) string {
				if _, err := d.cs.CreateHumanUser(context.Background(), cloudstore.CreateHumanUserParams{Username: "restored-member", DisplayName: "Member", Role: cloudstore.PrincipalRoleMember}); err != nil {
					t.Fatal(err)
				}
				return "restored-member"
			},
			wantStderr: "is not a managed human admin",
		},
		{
			name: "token already exists for another admin",
			setup: func(t *testing.T, d recoverPrincipalDB) string {
				if _, err := d.cs.CreatePrincipalToken(context.Background(), cloudstore.CreatePrincipalTokenParams{PrincipalID: d.first.PrincipalID, TokenPrefix: "egc_live_existing", TokenHash: "hmac-sha256:v1:existing", Name: "existing", CreatedByPrincipalID: d.first.PrincipalID}); err != nil {
					t.Fatal(err)
				}
				return "restored-second"
			},
			wantStderr: "requires zero principal tokens, found 1",
			wantTokens: 1,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			d := openRecoverPrincipalDB(t)
			selector := tt.setup(t, d)

			stdout, stderr, code := runRecoverToken(t, "--principal", selector)
			if code != 1 || !strings.Contains(stderr, tt.wantStderr) || strings.Contains(stdout, "egc_live_") {
				t.Fatalf("exit %d stdout=%q stderr=%q, want exit 1 with %q and no token", code, stdout, stderr, tt.wantStderr)
			}
			if n := d.count(t, `SELECT COUNT(*) FROM cloud_principal_tokens`); n != tt.wantTokens {
				t.Fatalf("refusal changed token rows: %d, want %d", n, tt.wantTokens)
			}
			if n := d.count(t, `SELECT COUNT(*) FROM cloud_auth_audit_log WHERE outcome = 'success'`); n != 0 {
				t.Fatalf("refusal wrote %d success audit rows", n)
			}
		})
	}
}

func TestCloudBootstrapRecoverTokenRejectsRepeatedPrincipal(t *testing.T) {
	if _, err := parseCloudBootstrapRecoverTokenArgs([]string{"--principal", "restored-first", "--principal", "restored-second"}); err == nil || !strings.Contains(err.Error(), "--principal") {
		t.Fatalf("repeated --principal must be rejected by the parser, err=%v", err)
	}
	d := openRecoverPrincipalDB(t)
	_, stderr, code := runRecoverToken(t, "--principal", "restored-first", "--principal", "restored-second")
	if code != 1 || !strings.Contains(stderr, "--principal") {
		t.Fatalf("repeated --principal must be refused, code=%d stderr=%q", code, stderr)
	}
	if got := d.count(t, `SELECT COUNT(*) FROM cloud_principal_tokens`); got != 0 {
		t.Fatalf("repeated --principal wrote %d token rows, want 0", got)
	}
}
