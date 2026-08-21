package domain

import "fmt"

// Status is the master switch for an entire tenant.
//
// Gate 3 reads it on every request, and it decides what the whole organization
// may do — so every value here is a state the operation-class table in
// organization.md §5.2 has a column for, and nothing else.
//
// # Two states from that document are deliberately absent
//
// `PendingActivation` and `Expired` were both about a card at signup. The trial
// is cardless (BILLING-PLAN.md §1), so there is no initial payment to be
// incomplete and nothing to abandon before the org exists: `incomplete` has no
// producer at signup, and `incomplete_expired` cannot occur. Carrying either
// would mean a state no event can reach and a column in the enforcement table
// no request can land in.
type Status string

const (
	// StatusUnknown is the zero value, and it denies. An organization whose
	// status has not been loaded must never be treated as usable — the same
	// fail-closed property authz.Decision's zero value has (ADR-010).
	StatusUnknown Status = ""

	// StatusProvisioning is the seconds-long window between the organization
	// being created and its Stripe subscription existing.
	//
	// It is NOT PendingActivation returning under another name. That state
	// waited on a human to pay and lasted days, which is why it needed expiry,
	// purging and a near-powerless relation. This one waits on a reactor. It
	// needs a spinner and a timeout alarm, not a lifecycle.
	StatusProvisioning Status = "provisioning"

	// StatusTrialing is a working organization on a cardless trial.
	StatusTrialing Status = "trialing"

	// StatusActive is a paying organization.
	StatusActive Status = "active"

	// StatusPastDue is a failed renewal with Stripe's Smart Retries running.
	// Writes continue during the grace period; `grow` does not.
	StatusPastDue Status = "past_due"

	// StatusSuspended is unreachable, not gone, and always recoverable.
	StatusSuspended Status = "suspended"

	// StatusClosed ends the commercial relationship and opens the export
	// window. Terminal: nothing transitions out of it, and closure never
	// deletes.
	StatusClosed Status = "closed"
)

// transitions is the whole state machine, as data.
//
// A table rather than a switch, because organization.md §13 asks for "the full
// lifecycle transition table, including every illegal transition" to be
// asserted — and a test can enumerate a table. It cannot enumerate the branches
// of a conditional, so the illegal half would go untested exactly where it
// matters most.
var transitions = map[Status][]Status{
	StatusUnknown:      {StatusProvisioning},
	StatusProvisioning: {StatusTrialing, StatusClosed},
	// A trial can convert, lapse, or be abandoned. It cannot go past due:
	// nothing has been charged.
	StatusTrialing: {StatusActive, StatusSuspended, StatusClosed},
	StatusActive:   {StatusPastDue, StatusSuspended, StatusClosed},
	// Recovery from past due goes to Active, not back to a trial — the trial is
	// spent and cannot be re-entered.
	StatusPastDue: {StatusActive, StatusSuspended, StatusClosed},
	// Suspension is always reversible while the org exists. A lapsed trial that
	// adds a card resumes, and a paying customer whose payment recovers
	// reinstates; both land in Active, because a resumed subscription is a
	// paying one either way.
	StatusSuspended: {StatusActive, StatusClosed},
	StatusClosed:    nil,
}

// CanTransitionTo reports whether the machine allows this move.
func (s Status) CanTransitionTo(next Status) bool {
	for _, allowed := range transitions[s] {
		if allowed == next {
			return true
		}
	}
	return false
}

// Statuses is every status, for exhaustive tests.
//
// Written out rather than derived from the transition map, so that a status
// which is reachable from nothing still appears — deriving it from the keys
// would let an unreachable state hide from the very test that should catch it.
func Statuses() []Status {
	return []Status{
		StatusUnknown, StatusProvisioning, StatusTrialing,
		StatusActive, StatusPastDue, StatusSuspended, StatusClosed,
	}
}

// Usable reports whether the tenant may do anything beyond reading and
// exporting.
//
// Not a substitute for gate 3, which reads the operation class as well; this is
// the coarse question the aggregate itself needs when refusing a command.
func (s Status) Usable() bool {
	return s == StatusTrialing || s == StatusActive || s == StatusPastDue
}

// Terminal reports whether anything can follow.
func (s Status) Terminal() bool { return len(transitions[s]) == 0 }

func (s Status) String() string {
	if s == StatusUnknown {
		return "unknown"
	}
	return string(s)
}

// errIllegalTransition names both ends, because "invalid state transition" sends
// the reader back to the table to work out which move was refused.
func errIllegalTransition(from, to Status) error {
	return fmt.Errorf("organization: cannot go from %s to %s", from, to)
}
