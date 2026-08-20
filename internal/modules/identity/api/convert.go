package api

import (
	"time"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// This file is the whole of the DTO boundary: module types on the left, generated
// protobuf types on the right, and no other file in the module holds a mapping
// between the two.
//
// Every one of these is TOTAL — an unrecognised value maps to the enum's
// UNSPECIFIED member rather than to a plausible neighbour, and a client is
// documented to treat UNSPECIFIED as "something this build does not render".
// Guessing would be worse than saying nothing: a method kind this build has never
// heard of, rendered as a password, is a screen that lies about what is enrolled
// on the account.

// protoTime renders a UTC timestamp, and NOTHING for a zero time.
//
// A nil Timestamp is how every optional time in identity.proto spells "never":
// never activated, never used, never seen. The alternative — a zero timestamp
// on the wire — is 1970, which a client renders as a date rather than as an
// absence, and "this authenticator was last used in 1970" is the one answer the
// security-settings screen must not give.
//
// UTC unconditionally (ADR-008). The app layer already stores UTC; converting
// again here costs nothing and means a caller that ever hands this a local time
// still produces a correct instant.
func protoTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.UTC())
}

// protoState maps the account lifecycle onto the wire enum.
//
// domain.StateNone — "no such account" — deliberately has no wire member and maps
// to UNSPECIFIED. It is not a lifecycle position a client can be shown: an account
// that does not exist is a NotFound, and giving absence its own renderable state
// would put "this account does not exist" on the account screen of somebody who is
// signed in to it.
func protoState(s domain.State) identityv1.AccountState {
	switch s {
	case domain.StatePending:
		return identityv1.AccountState_ACCOUNT_STATE_PENDING
	case domain.StateActive:
		return identityv1.AccountState_ACCOUNT_STATE_ACTIVE
	case domain.StateDeactivated:
		return identityv1.AccountState_ACCOUNT_STATE_DEACTIVATED
	case domain.StateSuspended:
		return identityv1.AccountState_ACCOUNT_STATE_SUSPENDED
	default:
		return identityv1.AccountState_ACCOUNT_STATE_UNSPECIFIED
	}
}

// protoMethodKind maps a stored method label onto the wire enum.
//
// The module's labels are STRINGS that live in events forever, so this switch is
// the join between a value the log will still hold in ten years and an enum a
// client compiled against. A label this build does not know maps to UNSPECIFIED
// and stays visible in the list — the credential id, the usable flag and the
// timestamps are all still true, and hiding the row would make the one screen
// whose job is "is there something enrolled here that I did not enrol" answer no
// for exactly the method it could not name.
func protoMethodKind(k contract.MethodKind) identityv1.MethodKind {
	switch k {
	case contract.MethodPassword:
		return identityv1.MethodKind_METHOD_KIND_PASSWORD
	case contract.MethodTOTP:
		return identityv1.MethodKind_METHOD_KIND_TOTP
	case contract.MethodRecoveryCode:
		return identityv1.MethodKind_METHOD_KIND_RECOVERY_CODE
	case contract.MethodPasskey:
		return identityv1.MethodKind_METHOD_KIND_PASSKEY
	case contract.MethodFederated:
		return identityv1.MethodKind_METHOD_KIND_FEDERATED
	default:
		return identityv1.MethodKind_METHOD_KIND_UNSPECIFIED
	}
}

// protoMethodKinds maps a list, preserving order and length.
//
// Length is preserved deliberately: the list is "the factors presented" or "the
// kinds you may complete with", and dropping an unrecognised entry would silently
// shorten an inventory a client counts.
func protoMethodKinds(kinds []contract.MethodKind) []identityv1.MethodKind {
	if len(kinds) == 0 {
		return nil
	}
	out := make([]identityv1.MethodKind, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, protoMethodKind(k))
	}
	return out
}

// protoAAL maps an assurance level onto the shared options enum.
//
// AAL0 is "not an authentication" and has no wire member — the options enum's
// zero value is UNSPECIFIED, which is the honest rendering of it. That matters
// beyond tidiness: LoginAttempt.assurance_level is UNSPECIFIED for every failure,
// and a failure that reported AAL1 would read as a partial success.
func protoAAL(a contract.AssuranceLevel) optionsv1.AssuranceLevel {
	switch a {
	case contract.AAL1:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
	case contract.AAL2:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2
	case contract.AAL3:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_3
	default:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED
	}
}

// protoFailureReason maps a recorded failure classification onto the wire enum.
//
// This is the ONE place a failure's cause is allowed to reach a client, and it is
// not a contradiction of ADR-036: it is the account holder's own security log,
// read after the fact, about their own account, from a call that already required
// a session. The refusal a FAILING caller receives is produced by `fail` and
// carries none of this.
func protoFailureReason(r contract.FailureReason) identityv1.FailureReason {
	switch r {
	case contract.ReasonNoSuchIdentifier:
		return identityv1.FailureReason_FAILURE_REASON_NO_SUCH_IDENTIFIER
	case contract.ReasonWrongPassword:
		return identityv1.FailureReason_FAILURE_REASON_WRONG_PASSWORD
	case contract.ReasonWrongSecondFactor:
		return identityv1.FailureReason_FAILURE_REASON_WRONG_SECOND_FACTOR
	case contract.ReasonReplayedCode:
		return identityv1.FailureReason_FAILURE_REASON_REPLAYED_CODE
	case contract.ReasonUnverifiedEmail:
		return identityv1.FailureReason_FAILURE_REASON_UNVERIFIED_EMAIL
	case contract.ReasonIncomplete:
		return identityv1.FailureReason_FAILURE_REASON_INCOMPLETE_ENROLLMENT
	case contract.ReasonDeactivated:
		return identityv1.FailureReason_FAILURE_REASON_DEACTIVATED
	case contract.ReasonSuspended:
		return identityv1.FailureReason_FAILURE_REASON_SUSPENDED
	case contract.ReasonRateLimited:
		return identityv1.FailureReason_FAILURE_REASON_RATE_LIMITED
	default:
		return identityv1.FailureReason_FAILURE_REASON_UNSPECIFIED
	}
}
