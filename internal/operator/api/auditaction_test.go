package api

import (
	"slices"
	"testing"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// TestEveryWireActionMapsToTheDomain holds two of this vocabulary's three
// copies together.
//
// The eight actions exist as a protobuf enum, as Go constants, and as values a
// CHECK constraint admits. They cannot be one artefact — generated code, Go,
// and a migration — so what keeps them honest is that each pair has a test.
// This is the proto ↔ Go pair; the Go ↔ SQL pair is
// TestTheAuditActionConstraintMatchesTheDomain, which reads pg_constraint.
//
// # Total, and injective
//
// TOTAL catches an enum value added to the proto without a domain constant: the
// method would declare an action the projection cannot name, and the entry
// would be written under an empty string, which the CHECK constraint would then
// refuse at runtime — on the one table whose completeness is this plane's whole
// claim.
//
// INJECTIVE catches a copy-paste filing one action under another's name. That
// one is worse, because nothing fails: both rows look correct, and the audit
// log quietly says a personal-data read was a customer view.
func TestEveryWireActionMapsToTheDomain(t *testing.T) {
	values := operatorv1.AuditAction_name

	seen := map[domain.AuditAction]operatorv1.AuditAction{}
	for number := range values {
		wire := operatorv1.AuditAction(number)
		if wire == operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED {
			continue
		}

		got, ok := actionFor(wire)
		if !ok {
			t.Errorf("%s maps to no domain action.\n\n"+
				"A method declaring it would write an audit entry under an empty "+
				"action, which the CHECK constraint refuses at runtime — on the one "+
				"table whose completeness is this plane's whole claim.", wire)
			continue
		}
		if !domain.KnownAuditAction(got) {
			t.Errorf("%s maps to %q, which domain.AuditActions() does not list", wire, got)
		}
		if prev, dup := seen[got]; dup {
			t.Errorf("%s and %s both map to %q. Nothing fails at runtime — both rows "+
				"look correct, and the audit log quietly says one action was another.",
				prev, wire, got)
		}
		seen[got] = wire
	}

	// And the other direction, over the DECLARABLE set rather than over every
	// action.
	//
	// The difference is `elevation_expired`, which has no caller: a break-glass
	// window closes because time passed, and the sweep records it. This
	// assertion originally ran over AuditActions() and failed on exactly that —
	// which is the test working. Conflating the two would have meant either a
	// wire enum value no method could use, or a domain action nothing recorded.
	for _, action := range domain.DeclarableActions() {
		if _, ok := seen[action]; !ok {
			t.Errorf("no wire enum value maps to %q, so no method can declare it and "+
				"nothing will ever record one", action)
		}
	}

	// The sweep-written ones must NOT be declarable, or a method could claim to
	// record something only background work can produce.
	for _, action := range domain.AuditActions() {
		if !domain.WrittenBySweep(action) {
			continue
		}
		if wire, ok := seen[action]; ok {
			t.Errorf("%s declares %q, which is written by the sweep and has no caller",
				wire, action)
		}
	}
}

// TestTheTwoActionListsDifferOnlyBySweepWrittenOnes keeps the split honest.
//
// DeclarableActions is derived by subtraction, so the two lists can only
// disagree by exactly the sweep-written set. Asserting it means an action moved
// into `sweepWritten` without a reason shows up as a declarable action that
// vanished.
func TestTheTwoActionListsDifferOnlyBySweepWrittenOnes(t *testing.T) {
	declarable := map[domain.AuditAction]bool{}
	for _, a := range domain.DeclarableActions() {
		declarable[a] = true
	}

	for _, a := range domain.AuditActions() {
		switch {
		case domain.WrittenBySweep(a) && declarable[a]:
			t.Errorf("%q is written by the sweep and is also declarable", a)
		case !domain.WrittenBySweep(a) && !declarable[a]:
			t.Errorf("%q is neither declarable nor written by the sweep, so nothing "+
				"produces it", a)
		}
	}
}

// TestUnspecifiedIsNotAnAction guards the exemption the policy loader depends
// on.
//
// A ceremony step declares no audit action, and the loader permits that only
// for `unauthenticated` and `sso_only` methods. If UNSPECIFIED ever mapped to a
// real action, those steps would start writing entries naming a caller nobody
// has identified.
func TestUnspecifiedIsNotAnAction(t *testing.T) {
	if _, ok := actionFor(operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED); ok {
		t.Fatal("UNSPECIFIED maps to an action, so the sign-in ceremony would record " +
			"entries for a caller nobody has identified")
	}
}

// TestAnUnknownWireValueIsNotGuessed is the rolling-deploy case.
//
// A newer build declares a ninth action; this one receives it. Guessing — or
// falling through to a default action — would file it under a word that does
// not describe it, and the entry would look correct forever.
func TestAnUnknownWireValueIsNotGuessed(t *testing.T) {
	if _, ok := actionFor(operatorv1.AuditAction(9999)); ok {
		t.Fatal("an unknown audit action was mapped to a known word")
	}
}

// TestJustifiedActionsAreTheThreeThatCarryAReason keeps the set that names them
// honest against the reasons themselves.
//
// The rule is enforced three times over for each — protovalidate, the audit
// aggregate, and a CHECK constraint — and this list is what a fourth action
// added later has to be measured against. A justified action missing from it
// would lose the database's half silently.
func TestJustifiedActionsAreTheThreeThatCarryAReason(t *testing.T) {
	want := map[domain.AuditAction]bool{
		domain.ActionViewedPersonalData: true,
		domain.ActionElevated:           true,
		domain.ActionChangedTenant:      true,
	}

	for _, a := range domain.JustifiedActions() {
		if !want[a] {
			t.Errorf("%q is listed as justified and is not one of the three", a)
		}
		delete(want, a)
	}
	for a := range want {
		t.Errorf("%q requires a justification and JustifiedActions() omits it, so the "+
			"database constraint that enforces it would be the only thing left", a)
	}

	// And RequiresJustification agrees with the list, so a caller asking the
	// predicate and a test reading the list cannot get different answers.
	for _, a := range domain.AuditActions() {
		listed := contains(domain.JustifiedActions(), a)
		if domain.RequiresJustification(a) != listed {
			t.Errorf("RequiresJustification(%q) = %v while JustifiedActions() says %v",
				a, domain.RequiresJustification(a), listed)
		}
	}
}

func contains(list []domain.AuditAction, a domain.AuditAction) bool {
	return slices.Contains(list, a)
}
