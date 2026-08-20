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
	"github.com/chronos/chronos-go/internal/platform/page"
)

// The conversions are unexported, so they are exercised through the RPCs that use
// them — which is the better test anyway: it checks the mapping AND that the
// handler reaches for it.

func TestAccountStateMapping(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		state domain.State
		want  identityv1.AccountState
	}{
		"pending":     {domain.StatePending, identityv1.AccountState_ACCOUNT_STATE_PENDING},
		"active":      {domain.StateActive, identityv1.AccountState_ACCOUNT_STATE_ACTIVE},
		"deactivated": {domain.StateDeactivated, identityv1.AccountState_ACCOUNT_STATE_DEACTIVATED},
		"suspended":   {domain.StateSuspended, identityv1.AccountState_ACCOUNT_STATE_SUSPENDED},
		// StateNone means "no such account". It is not a lifecycle position a
		// signed-in caller can be shown, so it has no wire member.
		"none":                             {domain.StateNone, identityv1.AccountState_ACCOUNT_STATE_UNSPECIFIED},
		"a state this build does not know": {domain.State(99), identityv1.AccountState_ACCOUNT_STATE_UNSPECIFIED},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.queries.accountFn = func(string) (app.AccountView, error) {
				return app.AccountView{
					SubjectID: callerSubject, UserID: callerUser, State: tt.state,
					RegisteredAt: time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC),
				}, nil
			}
			resp, err := h.client.GetUser(t.Context(),
				connect.NewRequest(&identityv1.GetUserRequest{}))
			if err != nil {
				t.Fatalf("GetUser: %v", err)
			}
			if resp.Msg.GetState() != tt.want {
				t.Fatalf("state = %v, want %v", resp.Msg.GetState(), tt.want)
			}
		})
	}
}

func TestMethodKindMapping(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		kind contract.MethodKind
		want identityv1.MethodKind
	}{
		"password":      {contract.MethodPassword, identityv1.MethodKind_METHOD_KIND_PASSWORD},
		"totp":          {contract.MethodTOTP, identityv1.MethodKind_METHOD_KIND_TOTP},
		"recovery code": {contract.MethodRecoveryCode, identityv1.MethodKind_METHOD_KIND_RECOVERY_CODE},
		"passkey":       {contract.MethodPasskey, identityv1.MethodKind_METHOD_KIND_PASSKEY},
		"federated":     {contract.MethodFederated, identityv1.MethodKind_METHOD_KIND_FEDERATED},
		// A label stored by a later build. It stays in the list, unnamed, because
		// hiding it would make "is there something enrolled here that I did not
		// enrol" answer no for exactly the method that could not be named.
		"a kind this build does not know": {
			contract.MethodKind("webauthn_platform"),
			identityv1.MethodKind_METHOD_KIND_UNSPECIFIED,
		},
		"the empty label": {contract.MethodKind(""), identityv1.MethodKind_METHOD_KIND_UNSPECIFIED},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.queries.methodsFn = func(string) ([]app.AuthMethod, error) {
				return []app.AuthMethod{{Method: domain.Method{ID: enrolCredential, Kind: tt.kind}}}, nil
			}
			resp, err := h.client.ListMethods(t.Context(),
				connect.NewRequest(&identityv1.ListMethodsRequest{}))
			if err != nil {
				t.Fatalf("ListMethods: %v", err)
			}
			got := resp.Msg.GetMethods()
			if len(got) != 1 {
				t.Fatalf("an unmapped kind removed the row: %v", got)
			}
			if got[0].GetKind() != tt.want {
				t.Fatalf("kind = %v, want %v", got[0].GetKind(), tt.want)
			}
		})
	}
}

// A list keeps its LENGTH and its ORDER. Dropping an unrecognised entry would
// silently shorten an inventory a client counts.
func TestMethodKindListsKeepTheirLengthAndOrder(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
		return app.AuthenticateResult{
			SecondFactorRequired: true,
			Offered: []contract.MethodKind{
				contract.MethodTOTP,
				contract.MethodKind("something_new"),
				contract.MethodRecoveryCode,
			},
		}, nil
	}

	resp, err := h.client.Authenticate(t.Context(), withKey(
		&identityv1.AuthenticateRequest{Identifier: "ada@example.com"}, "idem-kinds"))
	if err != nil {
		t.Fatalf("Authenticate: %v", err)
	}
	want := []identityv1.MethodKind{
		identityv1.MethodKind_METHOD_KIND_TOTP,
		identityv1.MethodKind_METHOD_KIND_UNSPECIFIED,
		identityv1.MethodKind_METHOD_KIND_RECOVERY_CODE,
	}
	got := resp.Msg.GetOffered()
	if len(got) != len(want) {
		t.Fatalf("offered = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("offered = %v, want %v", got, want)
		}
	}
}

func TestAssuranceLevelMapping(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		aal  contract.AssuranceLevel
		want optionsv1.AssuranceLevel
	}{
		"aal1": {contract.AAL1, optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1},
		"aal2": {contract.AAL2, optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2},
		"aal3": {contract.AAL3, optionsv1.AssuranceLevel_ASSURANCE_LEVEL_3},
		// AAL0 is "not an authentication". It has no wire member, and reporting it
		// as AAL1 would make a failed attempt read as a partial success.
		"aal0":           {contract.AAL0, optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED},
		"a bogus level":  {contract.AssuranceLevel(9), optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED},
		"a negative one": {contract.AssuranceLevel(-1), optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.queries.sessionsFn = func(string, page.Token, int) (page.Page[app.SessionSummary], error) {
				return page.Page[app.SessionSummary]{
					Items: []app.SessionSummary{{AAL: tt.aal}},
				}, nil
			}
			resp, err := h.client.ListSessions(t.Context(),
				connect.NewRequest(&identityv1.ListSessionsRequest{}))
			if err != nil {
				t.Fatalf("ListSessions: %v", err)
			}
			got := resp.Msg.GetSessions()
			if len(got) != 1 {
				t.Fatalf("sessions = %d, want 1", len(got))
			}
			if got[0].GetAssuranceLevel() != tt.want {
				t.Fatalf("assurance_level = %v, want %v", got[0].GetAssuranceLevel(), tt.want)
			}
		})
	}
}

func TestFailureReasonMapping(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		reason contract.FailureReason
		want   identityv1.FailureReason
	}{
		"no such identifier": {
			contract.ReasonNoSuchIdentifier,
			identityv1.FailureReason_FAILURE_REASON_NO_SUCH_IDENTIFIER,
		},
		"wrong password": {
			contract.ReasonWrongPassword,
			identityv1.FailureReason_FAILURE_REASON_WRONG_PASSWORD,
		},
		"wrong second factor": {
			contract.ReasonWrongSecondFactor,
			identityv1.FailureReason_FAILURE_REASON_WRONG_SECOND_FACTOR,
		},
		"replayed code": {
			contract.ReasonReplayedCode,
			identityv1.FailureReason_FAILURE_REASON_REPLAYED_CODE,
		},
		"unverified email": {
			contract.ReasonUnverifiedEmail,
			identityv1.FailureReason_FAILURE_REASON_UNVERIFIED_EMAIL,
		},
		"incomplete enrolment": {
			contract.ReasonIncomplete,
			identityv1.FailureReason_FAILURE_REASON_INCOMPLETE_ENROLLMENT,
		},
		"deactivated": {
			contract.ReasonDeactivated,
			identityv1.FailureReason_FAILURE_REASON_DEACTIVATED,
		},
		"suspended": {
			contract.ReasonSuspended,
			identityv1.FailureReason_FAILURE_REASON_SUSPENDED,
		},
		"rate limited": {
			contract.ReasonRateLimited,
			identityv1.FailureReason_FAILURE_REASON_RATE_LIMITED,
		},
		"a success carries none": {
			contract.FailureReason(""),
			identityv1.FailureReason_FAILURE_REASON_UNSPECIFIED,
		},
		"a reason this build does not know": {
			contract.FailureReason("impossible"),
			identityv1.FailureReason_FAILURE_REASON_UNSPECIFIED,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.queries.historyFn = func(string, page.Token, int) (page.Page[app.LoginRecord], error) {
				return page.Page[app.LoginRecord]{
					Items: []app.LoginRecord{{Reason: tt.reason}},
				}, nil
			}
			resp, err := h.client.ListLoginHistory(t.Context(),
				connect.NewRequest(&identityv1.ListLoginHistoryRequest{}))
			if err != nil {
				t.Fatalf("ListLoginHistory: %v", err)
			}
			got := resp.Msg.GetAttempts()
			if len(got) != 1 {
				t.Fatalf("attempts = %d, want 1", len(got))
			}
			if got[0].GetReason() != tt.want {
				t.Fatalf("reason = %v, want %v", got[0].GetReason(), tt.want)
			}
		})
	}
}

// Every timestamp on the wire is UTC (ADR-008), including one handed in with a
// non-UTC location. A response carrying a wall clock in somebody's local zone is
// a response two clients render differently.
func TestTimestampsAreUTC(t *testing.T) {
	t.Parallel()

	zone := time.FixedZone("UTC+7", 7*60*60)
	instant := time.Date(2025, 8, 9, 10, 11, 12, 0, zone)

	h := newHarness(t)
	h.queries.accountFn = func(string) (app.AccountView, error) {
		return app.AccountView{
			SubjectID: callerSubject, UserID: callerUser,
			State: domain.StateActive, RegisteredAt: instant,
		}, nil
	}

	resp, err := h.client.GetUser(t.Context(), connect.NewRequest(&identityv1.GetUserRequest{}))
	if err != nil {
		t.Fatalf("GetUser: %v", err)
	}
	got := resp.Msg.GetRegisteredAt().AsTime()
	if !got.Equal(instant) {
		t.Fatalf("registered_at = %v, want the same instant as %v", got, instant)
	}
	if got.Location() != time.UTC {
		t.Fatalf("registered_at location = %v, want UTC", got.Location())
	}
}
