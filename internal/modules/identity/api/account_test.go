package api_test

import (
	"testing"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// Every authenticated read must ask about the CALLER, and the caller comes from
// the principal. None of these request messages carries a subject id, so the only
// way a handler could get one wrong is by reaching for something else — which is
// what this test would catch, because the fakes answer for otherSubject and the
// assertions are on which subject was asked about.
func TestEveryAuthenticatedReadAsksAboutTheCaller(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	ctx := t.Context()

	if _, err := h.client.GetUser(ctx,
		connect.NewRequest(&identityv1.GetUserRequest{})); err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	if _, err := h.client.ListSessions(ctx,
		connect.NewRequest(&identityv1.ListSessionsRequest{})); err != nil {
		t.Fatalf("ListSessions: %v", err)
	}
	if _, err := h.client.ListMethods(ctx,
		connect.NewRequest(&identityv1.ListMethodsRequest{})); err != nil {
		t.Fatalf("ListMethods: %v", err)
	}
	if _, err := h.client.ListLoginHistory(ctx,
		connect.NewRequest(&identityv1.ListLoginHistoryRequest{})); err != nil {
		t.Fatalf("ListLoginHistory: %v", err)
	}

	calls := h.queries.recorded()
	if len(calls) != 4 {
		t.Fatalf("read side called %d times, want 4: %+v", len(calls), calls)
	}
	for _, c := range calls {
		if c.subjectID != callerSubject {
			t.Errorf("%s asked about %q, want the principal's %q",
				c.method, c.subjectID, callerSubject)
		}
		if c.subjectID == otherSubject {
			t.Errorf("%s asked about somebody else's account", c.method)
		}
	}
}

func TestGetUser(t *testing.T) {
	t.Parallel()

	registered := time.Date(2025, 1, 2, 3, 4, 5, 0, time.UTC)
	activated := time.Date(2025, 1, 3, 3, 4, 5, 0, time.UTC)

	t.Run("the account view is mapped onto the response", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.queries.accountFn = func(string) (app.AccountView, error) {
			return app.AccountView{
				SubjectID:     callerSubject,
				UserID:        callerUser,
				State:         domain.StateActive,
				EmailVerified: true,
				RegisteredAt:  registered,
				ActivatedAt:   activated,
			}, nil
		}

		resp, err := h.client.GetUser(t.Context(),
			connect.NewRequest(&identityv1.GetUserRequest{}))
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if resp.Msg.GetSubjectId() != callerSubject {
			t.Errorf("subject_id = %q", resp.Msg.GetSubjectId())
		}
		if resp.Msg.GetUserId() != callerUser.String() {
			t.Errorf("user_id = %q, want %q", resp.Msg.GetUserId(), callerUser.String())
		}
		if resp.Msg.GetState() != identityv1.AccountState_ACCOUNT_STATE_ACTIVE {
			t.Errorf("state = %v", resp.Msg.GetState())
		}
		if !resp.Msg.GetEmailVerified() {
			t.Error("email_verified = false")
		}
		if !resp.Msg.GetRegisteredAt().AsTime().Equal(registered) {
			t.Errorf("registered_at = %v", resp.Msg.GetRegisteredAt().AsTime())
		}
		if !resp.Msg.GetActivatedAt().AsTime().Equal(activated) {
			t.Errorf("activated_at = %v", resp.Msg.GetActivatedAt().AsTime())
		}
	})

	// "Never" is an ABSENT timestamp, not 1970. A zero time on the wire renders as
	// a date, and "deactivated in 1970" is worse than saying nothing.
	t.Run("a transition that never happened is absent, not 1970", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.queries.accountFn = func(string) (app.AccountView, error) {
			return app.AccountView{
				SubjectID: callerSubject, UserID: callerUser,
				State: domain.StatePending, RegisteredAt: registered,
			}, nil
		}

		resp, err := h.client.GetUser(t.Context(),
			connect.NewRequest(&identityv1.GetUserRequest{}))
		if err != nil {
			t.Fatalf("GetUser: %v", err)
		}
		if resp.Msg.GetActivatedAt() != nil {
			t.Errorf("activated_at = %v, want unset", resp.Msg.GetActivatedAt().AsTime())
		}
		if resp.Msg.GetDeactivatedAt() != nil {
			t.Errorf("deactivated_at = %v, want unset", resp.Msg.GetDeactivatedAt().AsTime())
		}
		if resp.Msg.GetSuspendedAt() != nil {
			t.Errorf("suspended_at = %v, want unset", resp.Msg.GetSuspendedAt().AsTime())
		}
	})

	// No address reaches this response, by construction rather than by omission.
	// Asserted against the DESCRIPTOR rather than against one rendered message: a
	// value-level check passes for as long as the fake happens not to supply an
	// address, while a field that could carry one is a field a later commit fills.
	t.Run("the response has no field that could carry an address", func(t *testing.T) {
		t.Parallel()
		fields := (&identityv1.GetUserResponse{}).ProtoReflect().Descriptor().Fields()
		allowed := map[string]bool{
			"subject_id": true, "user_id": true, "state": true, "email_verified": true,
			"registered_at": true, "activated_at": true, "deactivated_at": true,
			"suspended_at": true,
		}
		for i := range fields.Len() {
			name := string(fields.Get(i).Name())
			if !allowed[name] {
				t.Errorf("GetUserResponse grew the field %q; identity's account screen "+
					"returns a pseudonym and the vault resolves it (ADR-002)", name)
			}
		}
	})
}

func TestListSessions(t *testing.T) {
	t.Parallel()

	created := time.Date(2025, 5, 5, 5, 5, 5, 0, time.UTC)
	sessionID := ids.FromUUID[ids.Session]([16]byte{2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2, 2})

	t.Run("the page token and size go through to the session list", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		cursor := "cursor-for-sessions"
		_, err := h.client.ListSessions(t.Context(), connect.NewRequest(
			&identityv1.ListSessionsRequest{PageSize: 25, PageToken: cursor}))
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}

		calls := h.queries.recorded()
		if len(calls) != 1 {
			t.Fatalf("read side called %d times, want 1", len(calls))
		}
		if calls[0].method != "ListSessions" {
			t.Fatalf("the session page token was routed to %s", calls[0].method)
		}
		if calls[0].token != page.Token("cursor-for-sessions") {
			t.Errorf("token = %q", calls[0].token)
		}
		if calls[0].size != 25 {
			t.Errorf("size = %d, want 25", calls[0].size)
		}
	})

	t.Run("a page is mapped, next token included", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.queries.sessionsFn = func(string, page.Token, int) (page.Page[app.SessionSummary], error) {
			return page.Page[app.SessionSummary]{
				Items: []app.SessionSummary{{
					SessionID:         sessionID,
					DeviceID:          "dev_9f2c1b7e",
					AAL:               contract.AAL2,
					IdleExpiresAt:     created.Add(time.Hour),
					AbsoluteExpiresAt: created.Add(24 * time.Hour),
					CreatedAt:         created,
				}},
				Next: page.Token("next-cursor"),
			}, nil
		}

		resp, err := h.client.ListSessions(t.Context(),
			connect.NewRequest(&identityv1.ListSessionsRequest{}))
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if resp.Msg.GetNextPageToken() != "next-cursor" {
			t.Errorf("next_page_token = %q", resp.Msg.GetNextPageToken())
		}
		got := resp.Msg.GetSessions()
		if len(got) != 1 {
			t.Fatalf("sessions = %d, want 1", len(got))
		}
		if got[0].GetSessionId() != sessionID.String() {
			t.Errorf("session_id = %q", got[0].GetSessionId())
		}
		if got[0].GetDeviceId() != "dev_9f2c1b7e" {
			t.Errorf("device_id = %q", got[0].GetDeviceId())
		}
		if got[0].GetAssuranceLevel() != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
			t.Errorf("assurance_level = %v", got[0].GetAssuranceLevel())
		}
		if !got[0].GetCreatedAt().AsTime().Equal(created) {
			t.Errorf("created_at = %v", got[0].GetCreatedAt().AsTime())
		}
		// A session that has made no request since it was issued.
		if got[0].GetLastSeenAt() != nil {
			t.Errorf("last_seen_at = %v, want unset", got[0].GetLastSeenAt().AsTime())
		}
	})

	// Empty means DONE, and it is the only termination signal a client has.
	t.Run("an exhausted list returns an empty next token", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		resp, err := h.client.ListSessions(t.Context(),
			connect.NewRequest(&identityv1.ListSessionsRequest{}))
		if err != nil {
			t.Fatalf("ListSessions: %v", err)
		}
		if resp.Msg.GetNextPageToken() != "" {
			t.Errorf("next_page_token = %q, want empty", resp.Msg.GetNextPageToken())
		}
	})
}

func TestListMethods(t *testing.T) {
	t.Parallel()

	added := time.Date(2025, 2, 2, 2, 2, 2, 0, time.UTC)
	credential := ids.FromUUID[ids.Credential](
		[16]byte{3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3})

	tests := map[string]struct {
		method     app.AuthMethod
		wantUsable bool
		wantKind   identityv1.MethodKind
		wantEnable bool
	}{
		"a proven authenticator is usable": {
			method: app.AuthMethod{
				Method: domain.Method{
					ID: credential, Kind: contract.MethodTOTP, EnabledAt: added.Add(time.Minute),
				},
				AddedAt: added,
			},
			wantUsable: true,
			wantKind:   identityv1.MethodKind_METHOD_KIND_TOTP,
			wantEnable: true,
		},
		"a provisioned but unproven one is not": {
			method: app.AuthMethod{
				Method:  domain.Method{ID: credential, Kind: contract.MethodTOTP},
				AddedAt: added,
			},
			wantUsable: false,
			wantKind:   identityv1.MethodKind_METHOD_KIND_TOTP,
			wantEnable: false,
		},
		"a locked-out one is not": {
			method: app.AuthMethod{
				Method: domain.Method{
					ID: credential, Kind: contract.MethodPassword,
					EnabledAt: added, DisabledAt: added.Add(time.Hour),
				},
				AddedAt: added,
			},
			wantUsable: false,
			wantKind:   identityv1.MethodKind_METHOD_KIND_PASSWORD,
			wantEnable: true,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.queries.methodsFn = func(string) ([]app.AuthMethod, error) {
				return []app.AuthMethod{tt.method}, nil
			}

			resp, err := h.client.ListMethods(t.Context(),
				connect.NewRequest(&identityv1.ListMethodsRequest{}))
			if err != nil {
				t.Fatalf("ListMethods: %v", err)
			}
			got := resp.Msg.GetMethods()
			if len(got) != 1 {
				t.Fatalf("methods = %d, want 1", len(got))
			}
			if got[0].GetCredentialId() != credential.String() {
				t.Errorf("credential_id = %q", got[0].GetCredentialId())
			}
			if got[0].GetKind() != tt.wantKind {
				t.Errorf("kind = %v, want %v", got[0].GetKind(), tt.wantKind)
			}
			if got[0].GetUsable() != tt.wantUsable {
				t.Errorf("usable = %v, want %v", got[0].GetUsable(), tt.wantUsable)
			}
			if !got[0].GetAddedAt().AsTime().Equal(added) {
				t.Errorf("added_at = %v", got[0].GetAddedAt().AsTime())
			}
			if (got[0].GetEnabledAt() != nil) != tt.wantEnable {
				t.Errorf("enabled_at set = %v, want %v", got[0].GetEnabledAt() != nil, tt.wantEnable)
			}
			// "Never used" is the interesting value on this screen.
			if got[0].GetLastUsedAt() != nil {
				t.Errorf("last_used_at = %v, want unset", got[0].GetLastUsedAt().AsTime())
			}
		})
	}
}

func TestListLoginHistory(t *testing.T) {
	t.Parallel()

	occurred := time.Date(2025, 6, 6, 6, 6, 6, 0, time.UTC)

	t.Run("the page token and size go through to the history list", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)

		cursor := "cursor-for-history"
		_, err := h.client.ListLoginHistory(t.Context(), connect.NewRequest(
			&identityv1.ListLoginHistoryRequest{PageSize: 7, PageToken: cursor}))
		if err != nil {
			t.Fatalf("ListLoginHistory: %v", err)
		}

		calls := h.queries.recorded()
		if len(calls) != 1 {
			t.Fatalf("read side called %d times, want 1", len(calls))
		}
		if calls[0].method != "ListLoginHistory" {
			t.Fatalf("the history page token was routed to %s", calls[0].method)
		}
		if calls[0].token != page.Token("cursor-for-history") {
			t.Errorf("token = %q", calls[0].token)
		}
		if calls[0].size != 7 {
			t.Errorf("size = %d, want 7", calls[0].size)
		}
	})

	// FAILURES are the point of this screen, and the reason is the account
	// holder's to see even though a failing caller is told nothing.
	t.Run("a failure carries its reason and no assurance level", func(t *testing.T) {
		t.Parallel()
		h := newHarness(t)
		h.queries.historyFn = func(string, page.Token, int) (page.Page[app.LoginRecord], error) {
			return page.Page[app.LoginRecord]{
				Items: []app.LoginRecord{{
					ID:         42,
					Succeeded:  false,
					Reason:     contract.ReasonWrongSecondFactor,
					Methods:    []contract.MethodKind{contract.MethodPassword, contract.MethodTOTP},
					AAL:        contract.AAL0,
					DeviceID:   "dev_9f2c1b7e",
					OccurredAt: occurred,
				}},
				Next: page.Token("next-history-cursor"),
			}, nil
		}

		resp, err := h.client.ListLoginHistory(t.Context(),
			connect.NewRequest(&identityv1.ListLoginHistoryRequest{}))
		if err != nil {
			t.Fatalf("ListLoginHistory: %v", err)
		}
		if resp.Msg.GetNextPageToken() != "next-history-cursor" {
			t.Errorf("next_page_token = %q", resp.Msg.GetNextPageToken())
		}
		got := resp.Msg.GetAttempts()
		if len(got) != 1 {
			t.Fatalf("attempts = %d, want 1", len(got))
		}
		if got[0].GetSucceeded() {
			t.Error("succeeded = true")
		}
		if got[0].GetReason() != identityv1.FailureReason_FAILURE_REASON_WRONG_SECOND_FACTOR {
			t.Errorf("reason = %v", got[0].GetReason())
		}
		if got[0].GetAssuranceLevel() != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
			t.Errorf("assurance_level = %v, want unspecified for a failure",
				got[0].GetAssuranceLevel())
		}
		if len(got[0].GetMethods()) != 2 {
			t.Errorf("methods = %v, want two", got[0].GetMethods())
		}
		if got[0].GetDeviceId() != "dev_9f2c1b7e" {
			t.Errorf("device_id = %q", got[0].GetDeviceId())
		}
		if !got[0].GetOccurredAt().AsTime().Equal(occurred) {
			t.Errorf("occurred_at = %v", got[0].GetOccurredAt().AsTime())
		}
		// The row's global sequence number must not be rendered: its gaps leak how
		// much authentication traffic the whole system carries. Asserted on the
		// descriptor, so a field added to carry it fails here even before anything
		// populates it.
		fields := (&identityv1.LoginAttempt{}).ProtoReflect().Descriptor().Fields()
		for i := range fields.Len() {
			switch string(fields.Get(i).Name()) {
			case "id", "sequence", "row_id":
				t.Errorf("LoginAttempt grew the field %q; the sequence is global across "+
					"accounts and its gaps leak system-wide traffic",
					string(fields.Get(i).Name()))
			}
		}
	})
}
