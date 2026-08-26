package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var at = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

func provisioned(t *testing.T, role contract.Role) *domain.Operator {
	t.Helper()
	o := eventsourcing.NewAggregate(domain.NewOperator)
	if err := o.Provision("opr_1", "subj_1", "https://idp.example", "sub-1", role, "", at); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	return o
}

// journal accumulates what a sequence of commands recorded, so a test can
// rebuild an aggregate from its WHOLE history rather than from the last append.
//
// The distinction is not pedantry, and getting it wrong is instructive: an
// earlier version of this helper replayed only the most recent Uncommitted()
// batch, so the second rebuild in a two-command test lost the provisioning and
// the aggregate came back as "no such operator". That is precisely the class of
// bug replay testing exists to catch — a fold that is correct for one event and
// wrong for a sequence — so the helper has to model the store honestly.
type journal struct {
	events []eventsourcing.Event
}

// record runs a command and appends whatever it produced.
func (j *journal) record(t *testing.T, o *domain.Operator, err error) *domain.Operator {
	t.Helper()
	if err != nil {
		t.Fatalf("command failed: %v", err)
	}
	j.events = append(j.events, o.Uncommitted()...)
	return j.replay(t)
}

// replay rebuilds from the whole history.
//
// A test that asserts on the aggregate it just mutated proves the setter ran.
// One that asserts on a replay proves the EVENT carries what the state needs —
// and a field left out of an event is the failure that survives every
// in-memory test and appears the first time a process restarts.
func (j *journal) replay(t *testing.T) *domain.Operator {
	t.Helper()
	out := eventsourcing.NewAggregate(domain.NewOperator)
	for _, e := range j.events {
		out.Apply(e)
	}
	return out
}

// replay is the single-command shorthand, for the tests that only ever perform
// one.
func replay(t *testing.T, from *domain.Operator) *domain.Operator {
	t.Helper()
	j := &journal{}
	j.events = append(j.events, from.Uncommitted()...)
	return j.replay(t)
}

func TestProvisioningRecordsWhatSignInResolvesOn(t *testing.T) {
	o := replay(t, provisioned(t, contract.RoleSupport))

	if !o.Exists() {
		t.Fatal("a provisioned operator does not exist after replay")
	}
	if o.Role() != contract.RoleSupport {
		t.Errorf("role = %q after replay", o.Role())
	}
	if o.SubjectID() != "subj_1" {
		t.Errorf("subject = %q after replay", o.SubjectID())
	}
	issuer, sub := o.Binding()
	if issuer != "https://idp.example" || sub != "sub-1" {
		t.Errorf("binding = (%q, %q) after replay; sign-in resolves on exactly this pair",
			issuer, sub)
	}
	if o.Disabled() {
		t.Error("a freshly provisioned operator is disabled")
	}
}

// TestProvisioningRefusesAnIncompleteBinding is the guard on the pair sign-in
// matches.
//
// An operator row with an empty issuer or an empty provider subject would match
// any identity whose claims were also empty — and the interesting case is not
// malice but a provider that omitted a claim, which the OIDC adapter would then
// have handed through as "".
func TestProvisioningRefusesAnIncompleteBinding(t *testing.T) {
	cases := []struct {
		name                             string
		id, subject, issuer, providerSub string
		role                             contract.Role
	}{
		{"no operator id", "", "subj", "iss", "sub", contract.RoleSupport},
		{"no subject pseudonym", "opr", "", "iss", "sub", contract.RoleSupport},
		{"no issuer", "opr", "subj", "", "sub", contract.RoleSupport},
		{"no provider subject", "opr", "subj", "iss", "", contract.RoleSupport},
		{"a role this build cannot evaluate", "opr", "subj", "iss", "sub", "root"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			o := eventsourcing.NewAggregate(domain.NewOperator)
			err := o.Provision(tc.id, tc.subject, tc.issuer, tc.providerSub, tc.role, "", at)
			if err == nil {
				t.Fatal("accepted")
			}
			if len(o.Uncommitted()) != 0 {
				t.Error("a refused provisioning still recorded an event")
			}
		})
	}
}

// TestProvisioningTwiceIsRefusedRatherThanTolerated is the one place
// idempotency would be actively harmful.
//
// The second call carries a ROLE. Honouring it silently would make provisioning
// a back-door role change that skips OperatorRoleChanged — so the escalation
// would be invisible to the one query an audit runs.
func TestProvisioningTwiceIsRefusedRatherThanTolerated(t *testing.T) {
	o := provisioned(t, contract.RoleSupport)
	o = replay(t, o)

	err := o.Provision("opr_1", "subj_1", "https://idp.example", "sub-1",
		contract.RoleOperatorAdmin, "opr_2", at)
	if err == nil {
		t.Fatal("a second provisioning was accepted, which would be an unrecorded escalation")
	}
	if o.Role() != contract.RoleSupport {
		t.Errorf("the role moved to %q anyway", o.Role())
	}
}

func TestARoleChangeRecordsBothSides(t *testing.T) {
	o := replay(t, provisioned(t, contract.RoleSupport))

	if err := o.ChangeRole(contract.RoleBillingOps, "opr_admin", at); err != nil {
		t.Fatalf("changing the role: %v", err)
	}

	pending := o.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("recorded %d events, want 1", len(pending))
	}
	ev, ok := pending[0].(*contract.OperatorRoleChanged)
	if !ok {
		t.Fatalf("recorded %T", pending[0])
	}
	// BOTH sides. The old role is derivable by replaying the stream, and
	// carrying it anyway is what makes "was this an escalation" answerable from
	// a single record — which is what makes the alert on escalation cheap
	// enough to actually run.
	if ev.PreviousRole != contract.RoleSupport || ev.NewRole != contract.RoleBillingOps {
		t.Errorf("recorded %q -> %q", ev.PreviousRole, ev.NewRole)
	}
	if ev.ChangedBy != "opr_admin" {
		t.Errorf("changed by %q", ev.ChangedBy)
	}
	if ev.SubjectID != "subj_1" {
		t.Errorf("subject %q; the audit log needs the pseudonym, not the operator id alone", ev.SubjectID)
	}
}

// TestAnOperatorCannotRaiseTheirOwnRole is the failure this domain exists to
// make impossible.
//
// It has to be refused HERE rather than only in the handler. An operator_admin
// holds CapManageOperators, so nothing in the capability table stops them
// raising themselves — the aggregate is the only place that knows the actor and
// the target are the same.
func TestAnOperatorCannotRaiseTheirOwnRole(t *testing.T) {
	o := replay(t, provisioned(t, contract.RoleOperatorAdmin))

	err := o.ChangeRole(contract.RoleOperatorAdmin, "opr_1", at)
	if err == nil {
		t.Fatal("an operator changed their own role")
	}
	if !strings.Contains(err.Error(), "own role") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
	if len(o.Uncommitted()) != 0 {
		t.Error("a refused self-change still recorded an event")
	}
}

// TestChangingToTheSameRoleRecordsNothing is the one idempotency that is right
// here.
//
// The caller asked for a state that holds, and an event saying "support became
// support" would be noise in precisely the stream an escalation alert reads.
func TestChangingToTheSameRoleRecordsNothing(t *testing.T) {
	o := replay(t, provisioned(t, contract.RoleSupport))

	if err := o.ChangeRole(contract.RoleSupport, "opr_admin", at); err != nil {
		t.Fatalf("changing to the same role: %v", err)
	}
	if len(o.Uncommitted()) != 0 {
		t.Error("a no-op role change recorded an event")
	}
}

// TestADisabledOperatorCannotBeReGranted is the shape of offboarding.
//
// Re-granting access is a NEW provisioning by a second person, which is an
// audited act. A role change that quietly revived a disabled account would make
// offboarding a toggle.
func TestADisabledOperatorCannotBeReGranted(t *testing.T) {
	j := &journal{}
	o := j.record(t, provisioned(t, contract.RoleSupport), nil)
	o = j.record(t, o, o.Disable("opr_admin", at))

	if !o.Exists() {
		t.Fatal("the operator vanished across the replay")
	}
	if !o.Disabled() {
		t.Fatal("the disable did not survive replay")
	}
	if err := o.ChangeRole(contract.RoleBillingOps, "opr_admin", at); err == nil {
		t.Fatal("a disabled operator was re-granted through a role change")
	}
}

// TestDisablingIsIdempotentAndSelfServiceable covers both halves of a decision
// that differs from ChangeRole's.
//
// Disabling twice records nothing — the caller asked for a state that holds.
// And unlike a role change it permits SELF-action: an operator locking
// themselves out is not an escalation, and a suspected-compromise path where
// the person who noticed must first find an admin costs minutes at the worst
// possible time.
func TestDisablingIsIdempotentAndSelfServiceable(t *testing.T) {
	j := &journal{}
	o := j.record(t, provisioned(t, contract.RoleSupport), nil)

	err := o.Disable("opr_1", at)
	if err != nil {
		t.Fatalf("an operator could not disable themselves: %v", err)
	}
	if len(o.Uncommitted()) != 1 {
		t.Fatalf("recorded %d events, want 1", len(o.Uncommitted()))
	}
	o = j.record(t, o, nil)

	if !o.Exists() {
		t.Fatal("the operator vanished across the replay, which means the journal lost the provisioning")
	}
	if err := o.Disable("opr_admin", at); err != nil {
		t.Fatalf("disabling twice: %v", err)
	}
	if len(o.Uncommitted()) != 0 {
		t.Error("a second disable recorded an event")
	}
}

// TestPermitsIsFalseForADisabledOperatorWhateverTheirRole is the check that
// must not live at the call sites.
//
// There will be many call sites and one of them will forget. Putting the
// disabled test inside the only function that answers "may they" means
// forgetting is not expressible.
func TestPermitsIsFalseForADisabledOperatorWhateverTheirRole(t *testing.T) {
	j := &journal{}
	o := j.record(t, provisioned(t, contract.RoleOperatorAdmin), nil)
	if !o.Permits(domain.CapViewCustomers) {
		t.Fatal("a live operator_admin cannot view customers")
	}

	o = j.record(t, o, o.Disable("opr_admin", at))

	for _, cap := range domain.Capabilities() {
		if o.Permits(cap) {
			t.Errorf("a disabled operator_admin still holds %q", cap)
		}
	}
}

// TestAnUnprovisionedOperatorPermitsNothing is the zero value's behaviour, and
// it is reachable: Repository.Load returns a new aggregate for a stream that
// does not exist, which is what lets a caller treat create and modify as one
// path.
func TestAnUnprovisionedOperatorPermitsNothing(t *testing.T) {
	o := domain.NewOperator()
	for _, cap := range domain.Capabilities() {
		if o.Permits(cap) {
			t.Errorf("an operator who was never provisioned holds %q", cap)
		}
	}
	if err := o.ChangeRole(contract.RoleSupport, "opr_admin", at); err == nil {
		t.Error("a role was granted to an operator who does not exist")
	}
	if err := o.Disable("opr_admin", at); err == nil {
		t.Error("an operator who does not exist was disabled")
	}
}

// TestEveryRecordedInstantIsUTC guards the invariant CLAUDE.md states plainly.
//
// A local-time instant in an audit trail makes ordering depend on the process's
// timezone, which surfaces only when somebody tries to use the trail as
// evidence.
func TestEveryRecordedInstantIsUTC(t *testing.T) {
	local := time.FixedZone("UTC+6", 6*3600)
	when := time.Date(2026, 8, 26, 15, 0, 0, 0, local)

	o := eventsourcing.NewAggregate(domain.NewOperator)
	if err := o.Provision("opr_1", "subj_1", "iss", "sub", contract.RoleSupport, "", when); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	ev := o.Uncommitted()[0].(*contract.OperatorProvisioned)
	if ev.ProvisionedAt.Location() != time.UTC {
		t.Errorf("recorded in %v, not UTC", ev.ProvisionedAt.Location())
	}
	if !ev.ProvisionedAt.Equal(when) {
		t.Errorf("the instant moved: %v vs %v", ev.ProvisionedAt, when)
	}
}
