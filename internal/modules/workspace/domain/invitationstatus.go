package domain

import "fmt"

// InvitationStatus is where an invitation sits in workspace.md §5's lifecycle.
//
// Five of the six terminal states exist because an invitation can end in five
// genuinely different ways, and collapsing any pair loses something an operator
// needs. A revoked invitation was withdrawn by the organization; an expired one
// simply ran out; a declined one was refused by the person; an undeliverable one
// never reached them at all. They differ in who acted, in whether a resend makes
// sense, and in what an inviter should be told.
type InvitationStatus string

const (
	// InvitationUnknown is the zero value, and it grants nothing. An invitation
	// whose status has not been loaded must never be treated as redeemable — the
	// same fail-closed property authz.Decision's zero value has (ADR-010).
	InvitationUnknown InvitationStatus = ""

	// InvitationPending is issued and outstanding. It is the ONLY state holding
	// a seat.
	InvitationPending InvitationStatus = "pending"

	// InvitationAccepted is redeemed. Terminal, and the seat it held becomes the
	// membership's — it is never released on this path, because the person is
	// now in the organization.
	InvitationAccepted InvitationStatus = "accepted"

	// InvitationRevoked is withdrawn by the organization. Terminal; the seat
	// goes back.
	InvitationRevoked InvitationStatus = "revoked"

	// InvitationExpired ran out of time. Terminal; the seat goes back.
	//
	// It is reached by the Temporal workflow rather than by a lazy check at
	// redemption, because the SEAT has to come back whether or not anyone ever
	// clicks the link (workspace.md §5) — and a lazy check only runs when
	// somebody does.
	InvitationExpired InvitationStatus = "expired"

	// InvitationDeclined was refused by the person invited. Terminal; the seat
	// goes back.
	//
	// Distinct from revoked, and the distinction is not cosmetic: re-inviting
	// somebody who declined is a decision a human should make deliberately,
	// while re-inviting after an accidental revocation is routine.
	InvitationDeclined InvitationStatus = "declined"

	// InvitationUndeliverable is a hard bounce. Terminal; the seat goes back and
	// the inviter is told.
	//
	// Separate from expired because the address is wrong rather than the timing:
	// resending changes nothing, and an inviter who is not told will resend
	// forever.
	InvitationUndeliverable InvitationStatus = "undeliverable"
)

// invitationTransitions is the whole state machine, as data.
//
// A table rather than a switch, for the reason organization's is: a test can
// enumerate a table and assert every ILLEGAL transition as well as every legal
// one. It cannot enumerate the branches of a conditional, so the illegal half
// would go untested exactly where it matters most.
//
// Every terminal state is terminal. In particular nothing returns to Pending: a
// resend rotates the token of an invitation that is ALREADY pending, and
// re-inviting after any terminal state is a NEW invitation with a new id — which
// is what makes "the old token stays dead" true by construction rather than by
// remembering to invalidate it.
var invitationTransitions = map[InvitationStatus][]InvitationStatus{
	InvitationUnknown: {InvitationPending},
	InvitationPending: {
		InvitationAccepted,
		InvitationRevoked,
		InvitationExpired,
		InvitationDeclined,
		InvitationUndeliverable,
	},
	InvitationAccepted:      nil,
	InvitationRevoked:       nil,
	InvitationExpired:       nil,
	InvitationDeclined:      nil,
	InvitationUndeliverable: nil,
}

// CanTransitionTo reports whether the machine allows this move.
func (s InvitationStatus) CanTransitionTo(next InvitationStatus) bool {
	for _, allowed := range invitationTransitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// InvitationStatuses is every status, for exhaustive tests.
//
// Written out rather than derived from the transition map, so a status reachable
// from nothing still appears — deriving it from the keys would let an
// unreachable state hide from the very test that should catch it.
func InvitationStatuses() []InvitationStatus {
	return []InvitationStatus{
		InvitationUnknown, InvitationPending, InvitationAccepted,
		InvitationRevoked, InvitationExpired, InvitationDeclined,
		InvitationUndeliverable,
	}
}

// HoldsSeat reports whether an invitation in this state is consuming one.
//
// Only Pending does. Accepted does not, and that is the subtle one: the seat
// still exists, but it belongs to the MEMBERSHIP now, and counting it here as
// well would double-count the person for as long as they stay.
func (s InvitationStatus) HoldsSeat() bool { return s == InvitationPending }

// ReleasesSeat reports whether ARRIVING in this state returns a seat to the
// pool.
//
// Every terminal state except Accepted. Getting this wrong in the permissive
// direction leaks a seat per invitation that was never taken up; getting it
// wrong on Accepted hands back a seat the new member is holding, and the pool
// then grows by one for every person who joins.
func (s InvitationStatus) ReleasesSeat() bool {
	switch s {
	case InvitationRevoked, InvitationExpired, InvitationDeclined, InvitationUndeliverable:
		return true
	default:
		return false
	}
}

// Terminal reports whether anything can follow.
func (s InvitationStatus) Terminal() bool { return len(invitationTransitions[s]) == 0 }

func (s InvitationStatus) String() string {
	if s == InvitationUnknown {
		return "unknown"
	}
	return string(s)
}

// errIllegalInvitationTransition names both ends, because "invalid state
// transition" sends the reader back to the table to work out which move was
// refused.
func errIllegalInvitationTransition(from, to InvitationStatus) error {
	return fmt.Errorf("workspace: an invitation cannot go from %s to %s", from, to)
}
