package cloudstore

import (
	"context"
	"errors"
	"strings"
	"testing"
)

// selectedRecoveryAudit is the caller-supplied audit for explicit-principal
// recovery; the store must still force every marker dimension.
func selectedRecoveryAudit() AuthAuditEvent {
	return AuthAuditEvent{
		ActorSource: "bootstrap_cli",
		Action:      "bootstrap.cli",
		Outcome:     "success",
		ReasonCode:  "selected_admin_token_recovered",
		Metadata:    map[string]any{"recovered": true, "principal_selector": "selector"},
	}
}

func createTwoRestoredAdmins(t *testing.T, cs *CloudStore) (HumanUser, HumanUser) {
	t.Helper()
	ctx := context.Background()
	first, err := cs.CreateHumanUser(ctx, CreateHumanUserParams{Username: "restored-first", DisplayName: "Restored First", Role: PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("CreateHumanUser first admin: %v", err)
	}
	second, err := cs.CreateHumanUser(ctx, CreateHumanUserParams{Username: "restored-second", DisplayName: "Restored Second", Role: PrincipalRoleAdmin})
	if err != nil {
		t.Fatalf("CreateHumanUser second admin: %v", err)
	}
	return first, second
}

func countAllPrincipalTokens(t *testing.T, cs *CloudStore) int {
	t.Helper()
	var n int
	if err := cs.db.QueryRowContext(context.Background(), `SELECT COUNT(*) FROM cloud_principal_tokens`).Scan(&n); err != nil {
		t.Fatalf("count principal tokens: %v", err)
	}
	return n
}

func TestRecoverStrandedAdminTokenWithAuditSelectsPrincipalAmongMultipleAdmins(t *testing.T) {
	for _, selectBy := range []string{"username", "id"} {
		t.Run(selectBy, func(t *testing.T) {
			ctx := context.Background()
			cs := openIsolatedCloudStore(t)
			first, second := createTwoRestoredAdmins(t, cs)
			selector := second.Username
			if selectBy == "id" {
				selector = second.PrincipalID
			}

			token, err := cs.RecoverStrandedAdminTokenWithAudit(ctx, RecoverStrandedAdminTokenParams{Principal: selector, TokenPrefix: "egc_live_selected", TokenHash: "hmac-sha256:v1:selected", Name: "restored"}, AuthAuditEvent{
				ActorPrincipalID:  first.PrincipalID,
				ActorSource:       "caller_supplied",
				TargetPrincipalID: first.PrincipalID,
				Project:           "caller-project",
				Action:            "caller.action",
				Outcome:           "denied",
				ReasonCode:        "caller_reason",
				Metadata:          map[string]any{"recovered": true, "principal_selector": selector},
			})
			if err != nil {
				t.Fatalf("RecoverStrandedAdminTokenWithAudit selected: %v", err)
			}
			if token.PrincipalID != second.PrincipalID || token.CreatedByPrincipalID != second.PrincipalID || token.Name != "restored" {
				t.Fatalf("selected recovery token must belong to the selected admin, got %+v", token)
			}
			firstTokens, err := cs.ListPrincipalTokens(ctx, first.PrincipalID)
			if err != nil {
				t.Fatalf("ListPrincipalTokens first: %v", err)
			}
			if len(firstTokens) != 0 || countAllPrincipalTokens(t, cs) != 1 {
				t.Fatalf("selected recovery must create exactly one token for the selected admin only, first=%+v", firstTokens)
			}
			_, principal, err := cs.FindPrincipalTokenByHash(ctx, "hmac-sha256:v1:selected")
			if err != nil || principal.ID != second.PrincipalID || principal.Role != PrincipalRoleAdmin || !principal.Enabled {
				t.Fatalf("selected recovery token must resolve to the selected enabled admin, principal=%+v err=%v", principal, err)
			}
			events, err := cs.ListAuthAuditEvents(ctx, AuthAuditQuery{Limit: 10})
			if err != nil {
				t.Fatalf("ListAuthAuditEvents: %v", err)
			}
			if len(events) != 1 {
				t.Fatalf("expected exactly one selected recovery audit, got %+v", events)
			}
			event := events[0]
			if event.ActorPrincipalID != "" || event.ActorSource != "bootstrap_cli" || event.TargetPrincipalID != second.PrincipalID || event.Project != "" || event.Action != "bootstrap.cli" || event.Outcome != "success" || event.ReasonCode != "selected_admin_token_recovered" || event.Metadata["principal_selector"] != selector {
				t.Fatalf("selected recovery audit must use store-owned marker dimensions, got %+v", event)
			}
		})
	}
}

func TestRecoverStrandedAdminTokenWithAuditSelectedPrincipalReplacesOnlyItsOwnUnusedToken(t *testing.T) {
	ctx := context.Background()
	cs := openIsolatedCloudStore(t)
	first, second := createTwoRestoredAdmins(t, cs)
	issued, err := cs.RecoverStrandedAdminTokenWithAudit(ctx, RecoverStrandedAdminTokenParams{Principal: second.Username, TokenPrefix: "egc_live_lost", TokenHash: "hmac-sha256:v1:lost"}, selectedRecoveryAudit())
	if err != nil {
		t.Fatalf("initial selected recovery: %v", err)
	}

	_, err = cs.RecoverStrandedAdminTokenWithAudit(ctx, RecoverStrandedAdminTokenParams{Principal: first.Username, TokenPrefix: "egc_live_other", TokenHash: "hmac-sha256:v1:other", RevokeExisting: true}, selectedRecoveryAudit())
	if !errors.Is(err, ErrStrandedAdminRecoveryIneligible) || !strings.Contains(err.Error(), "owned by the selected enabled managed human admin") {
		t.Fatalf("replacement for another admin's token must be refused, got %v", err)
	}

	replacement, err := cs.RecoverStrandedAdminTokenWithAudit(ctx, RecoverStrandedAdminTokenParams{Principal: second.Username, TokenPrefix: "egc_live_again", TokenHash: "hmac-sha256:v1:again", RevokeExisting: true}, selectedRecoveryAudit())
	if err != nil {
		t.Fatalf("selected replacement of own unused token: %v", err)
	}
	tokens, err := cs.ListPrincipalTokens(ctx, second.PrincipalID)
	if err != nil {
		t.Fatalf("ListPrincipalTokens: %v", err)
	}
	if len(tokens) != 2 || tokens[0].ID != issued.ID || tokens[0].RevokedAt == nil || tokens[1].ID != replacement.ID || tokens[1].RevokedAt != nil {
		t.Fatalf("expected the lost token revoked and one active replacement, got %+v", tokens)
	}
	events, err := cs.ListAuthAuditEvents(ctx, AuthAuditQuery{Limit: 10})
	if err != nil {
		t.Fatalf("ListAuthAuditEvents: %v", err)
	}
	if len(events) != 2 {
		t.Fatalf("expected two selected recovery audits (refusal writes none), got %+v", events)
	}
}

func TestRecoverStrandedAdminTokenWithAuditRejectsIneligibleSelectedPrincipal(t *testing.T) {
	cases := []struct {
		name           string
		setup          func(t *testing.T, cs *CloudStore, first, second HumanUser) string
		wantErr        string
		wantTokenCount int
	}{
		{
			name:    "unknown principal",
			setup:   func(*testing.T, *CloudStore, HumanUser, HumanUser) string { return "no-such-admin" },
			wantErr: `selected principal "no-such-admin" was not found`,
		},
		{
			name: "disabled admin",
			setup: func(t *testing.T, cs *CloudStore, _, second HumanUser) string {
				t.Helper()
				if err := cs.SetHumanUserEnabled(context.Background(), second.PrincipalID, false); err != nil {
					t.Fatalf("disable second admin: %v", err)
				}
				return second.Username
			},
			wantErr: `selected principal "restored-second" is disabled`,
		},
		{
			name: "member principal",
			setup: func(t *testing.T, cs *CloudStore, _, _ HumanUser) string {
				t.Helper()
				member, err := cs.CreateHumanUser(context.Background(), CreateHumanUserParams{Username: "restored-member", DisplayName: "Restored Member", Role: PrincipalRoleMember})
				if err != nil {
					t.Fatalf("create member: %v", err)
				}
				return member.PrincipalID
			},
			wantErr: "is not a managed human admin",
		},
		{
			name: "service account admin",
			setup: func(t *testing.T, cs *CloudStore, _, _ HumanUser) string {
				t.Helper()
				sa, err := cs.CreatePrincipal(context.Background(), CreatePrincipalParams{Kind: PrincipalKindServiceAccount, DisplayName: "Robot Admin", Role: PrincipalRoleAdmin})
				if err != nil {
					t.Fatalf("create service account: %v", err)
				}
				return sa.ID
			},
			wantErr: "is not a managed human admin",
		},
		{
			name: "ambiguous id and username",
			setup: func(t *testing.T, cs *CloudStore, first, _ HumanUser) string {
				t.Helper()
				if _, err := cs.CreateHumanUser(context.Background(), CreateHumanUserParams{Username: first.PrincipalID, DisplayName: "Numeric Name", Role: PrincipalRoleAdmin}); err != nil {
					t.Fatalf("create numeric-name admin: %v", err)
				}
				return first.PrincipalID
			},
			wantErr: "matches more than one principal",
		},
		{
			name: "token already exists for another admin",
			setup: func(t *testing.T, cs *CloudStore, first, second HumanUser) string {
				t.Helper()
				if _, err := cs.CreatePrincipalToken(context.Background(), CreatePrincipalTokenParams{PrincipalID: first.PrincipalID, TokenPrefix: "egc_live_existing", TokenHash: "hmac-sha256:v1:existing", Name: "existing", CreatedByPrincipalID: first.PrincipalID}); err != nil {
					t.Fatalf("create existing token: %v", err)
				}
				return second.Username
			},
			wantErr:        "requires zero principal tokens, found 1",
			wantTokenCount: 1,
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			ctx := context.Background()
			cs := openIsolatedCloudStore(t)
			first, second := createTwoRestoredAdmins(t, cs)
			selector := tt.setup(t, cs, first, second)

			_, err := cs.RecoverStrandedAdminTokenWithAudit(ctx, RecoverStrandedAdminTokenParams{Principal: selector, TokenPrefix: "egc_live_rejected", TokenHash: "hmac-sha256:v1:rejected"}, selectedRecoveryAudit())
			if !errors.Is(err, ErrStrandedAdminRecoveryIneligible) || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("expected ineligible selected recovery containing %q, got %v", tt.wantErr, err)
			}
			if got := countAllPrincipalTokens(t, cs); got != tt.wantTokenCount {
				t.Fatalf("refused selected recovery must not change token rows, got %d want %d", got, tt.wantTokenCount)
			}
			events, err := cs.ListAuthAuditEvents(ctx, AuthAuditQuery{Limit: 10})
			if err != nil {
				t.Fatalf("ListAuthAuditEvents: %v", err)
			}
			if len(events) != 0 {
				t.Fatalf("refused selected recovery must not write an audit event, got %+v", events)
			}
		})
	}
}
