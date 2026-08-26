package domain

import "slices"

// AuditAction is what an audit entry says happened.
//
// # This vocabulary lives in THREE places, and this is the one that owns it
//
// The same eight words appear as a protobuf enum (the wire declaration), as
// values in `operator_audit_log.action` (guarded by a CHECK constraint), and
// here. They cannot be collapsed into one artefact — one is generated code, one
// is a migration, one is Go — so the question is not how to avoid three copies
// but which is authoritative and how the other two are held to it.
//
// This is authoritative. The projection writes these constants rather than
// string literals; `ActionFor` maps the wire enum onto them, and it is total by
// test; and an integration test reads the CHECK constraint out of `pg_constraint`
// and asserts it admits exactly this set and no more.
//
// Before this file existed the projection wrote bare literals — `"signed_in"`,
// `"changed_tenant"` — so the vocabulary had no Go definition at all and a typo
// would have been caught by a database constraint at runtime, on the one table
// whose completeness is the plane's entire claim.
type AuditAction string

// The eight actions. Every one of these strings is PERMANENT: it is stored in
// `operator_audit_log.action` and named in a CHECK constraint, so changing one
// is a migration and a rewrite of history's vocabulary.
const (
	// ActionSignedIn is a completed sign-in — both factors.
	ActionSignedIn AuditAction = "signed_in"

	// ActionSignedOut is a deliberately ended session, as distinct from an
	// expired one.
	ActionSignedOut AuditAction = "signed_out"

	// ActionViewedCustomer is a read of the directory or of one customer.
	ActionViewedCustomer AuditAction = "viewed_customer"

	// ActionViewedPersonalData is a vault resolution for one named subject.
	// Carries a mandatory justification.
	ActionViewedPersonalData AuditAction = "viewed_personal_data"

	// ActionElevated is a break-glass. Carries a mandatory justification.
	ActionElevated AuditAction = "elevated"

	// ActionElevationExpired closes a break-glass window in the log.
	ActionElevationExpired AuditAction = "elevation_expired"

	// ActionManagedOperators is a change to who may use this plane.
	ActionManagedOperators AuditAction = "managed_operators"

	// ActionChangedTenant is a write against a tenant — a suspension, a
	// reinstatement, a legal hold. Carries a mandatory justification.
	ActionChangedTenant AuditAction = "changed_tenant"
)

// AuditActions is every action the log can hold.
//
// Written out rather than derived, for the reason organization's `Statuses()`
// gives: deriving it from a map's keys would let an action that is reachable
// from nothing hide from the very test that should catch it.
func AuditActions() []AuditAction {
	return []AuditAction{
		ActionSignedIn,
		ActionSignedOut,
		ActionViewedCustomer,
		ActionViewedPersonalData,
		ActionElevated,
		ActionElevationExpired,
		ActionManagedOperators,
		ActionChangedTenant,
	}
}

// DeclarableActions are the seven an RPC can declare on itself.
//
// # Why this is not the same list, and the distinction was found by a test
//
// Audit entries have two sources. Most are written because somebody CALLED
// something, and the method declares which action it records — that is what
// `chronos.operator.v1.AuditAction` is for, and what the policy loader requires.
//
// `elevation_expired` has no caller. A break-glass window closes because time
// passed, and the sweep records it; there is no RPC to hang the declaration on,
// and adding a wire enum value for it would mean declaring an action no method
// could ever use.
//
// The first version of this file had one list and a test asserting the wire
// enum covered it. That test failed on exactly this — which is the test working:
// the asymmetry is real, and conflating the two would have meant either a
// phantom enum value or a domain action nothing could record.
//
// So: AuditActions is what the LOG holds; this is what a METHOD may declare;
// and the difference is precisely the actions produced by background work.
func DeclarableActions() []AuditAction {
	out := make([]AuditAction, 0, len(AuditActions()))
	for _, a := range AuditActions() {
		if slices.Contains(sweepWritten, a) {
			continue
		}
		out = append(out, a)
	}
	return out
}

// sweepWritten are the actions recorded by background work rather than by a
// call.
//
// One member today. It is a list rather than a single constant because the
// second one is predictable — an expiring impersonation window (operator.md §6)
// closes the same way a break-glass does — and because a list is what
// DeclarableActions subtracts.
var sweepWritten = []AuditAction{ActionElevationExpired}

// WrittenBySweep reports whether an action is recorded by background work, so
// no RPC declares it.
func WrittenBySweep(a AuditAction) bool { return slices.Contains(sweepWritten, a) }

// KnownAuditAction reports whether a string is one this build knows.
func KnownAuditAction(a AuditAction) bool { return slices.Contains(AuditActions(), a) }

// JustifiedActions are the three whose lawfulness rests on a recorded reason.
//
// Named as a set rather than checked one at a time, because the rule is the
// same for all three and the database enforces it with one constraint per
// action — so a fourth added without a constraint is the failure this list
// makes visible.
//
// The three are: reading a person's data (operator.md §4), taking a capability
// your role does not hold (§5), and changing a tenant (§7). Each is an act
// somebody may be asked to defend, and a record of it without the account of
// why documents that a rule was followed while omitting the only evidence.
func JustifiedActions() []AuditAction {
	return []AuditAction{
		ActionViewedPersonalData,
		ActionElevated,
		ActionChangedTenant,
	}
}

// RequiresJustification reports whether an action may not be recorded without a
// reason.
func RequiresJustification(a AuditAction) bool {
	return slices.Contains(JustifiedActions(), a)
}
