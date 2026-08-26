package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// OperatorCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every operator ever provisioned.
const OperatorCategory eventsourcing.Category = "operator"

// OperatorStreamKey is the operator's own id.
//
// One stream per operator rather than one per employee-and-role, because the
// facts that matter are a sequence about one person's access: provisioned,
// escalated, offboarded. A stream per grant would make "can this operator sign
// in right now" a question about the latest of several streams.
func OperatorStreamKey(operatorID string) string { return operatorID }

// Operator is one employee's access to this plane.
//
// # It is an aggregate rather than a row, and that is not ceremony
//
// The whole point of operator.md §3 is that operator access is auditable and
// revocable with evidence. A row records the CURRENT grant; the question an
// auditor asks is "who gave this person the ability to read every customer, and
// when" — which is a question about the sequence, not about the current value.
// Replaying the stream answers it; reading a row cannot.
//
// It also makes offboarding provable. `Disabled` is an appended fact with an
// actor and an instant, and a projection derived from it, rather than a column
// somebody could set back.
type Operator struct {
	eventsourcing.Base

	operatorID      string
	subjectID       string
	issuer          string
	providerSubject string
	role            contract.Role
	disabled        bool
}

var _ eventsourcing.Root = (*Operator)(nil)

// NewOperator returns an empty aggregate for the repository to rebuild into.
func NewOperator() *Operator { return &Operator{} }

// Exists reports whether this operator was ever provisioned.
func (o *Operator) Exists() bool { return o.operatorID != "" }

// Role is the current role. Meaningless unless Exists.
func (o *Operator) Role() contract.Role { return o.role }

// SubjectID is the vault pseudonym for this employee.
func (o *Operator) SubjectID() string { return o.subjectID }

// Disabled reports whether the operator has been offboarded.
func (o *Operator) Disabled() bool { return o.disabled }

// Binding is the IdP identity this operator signs in with.
func (o *Operator) Binding() (issuer, providerSubject string) {
	return o.issuer, o.providerSubject
}

// Permits reports whether this operator's CURRENT role holds a capability, and
// returns false for a disabled operator regardless of role.
//
// The disabled check lives here rather than at the call sites on purpose. There
// will be many call sites and one of them will forget; putting the check inside
// the only function that answers "may they" means forgetting is not expressible.
func (o *Operator) Permits(cap Capability) bool {
	if !o.Exists() || o.disabled {
		return false
	}
	return Permits(o.role, cap)
}

// Apply rebuilds state from the log.
func (o *Operator) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.OperatorProvisioned:
		o.operatorID = ev.OperatorID
		o.subjectID = ev.SubjectID
		o.issuer = ev.Issuer
		o.providerSubject = ev.ProviderSubject
		o.role = ev.Role
		o.disabled = false
	case *contract.OperatorRoleChanged:
		o.role = ev.NewRole
	case *contract.OperatorDisabled:
		o.disabled = true
	}
}

// Provision records that an employee gained access.
//
// # Why this refuses rather than tolerates a repeat
//
// Provisioning twice is not idempotent the way restricting twice is. The second
// call carries a ROLE, and honouring it silently would make provisioning a
// back-door role change that skips OperatorRoleChanged — so the escalation would
// be invisible to the one query an audit runs. Refusing sends the caller to
// ChangeRole, which records what happened.
func (o *Operator) Provision(
	operatorID, subjectID, issuer, providerSubject string,
	role contract.Role,
	provisionedBy string,
	at time.Time,
) error {
	switch {
	case o.Exists():
		return fmt.Errorf("operator: %s is already provisioned", o.operatorID)
	case operatorID == "":
		return fmt.Errorf("operator: provisioning needs an operator id")
	case subjectID == "":
		return fmt.Errorf("operator: provisioning needs a subject pseudonym")
	case issuer == "":
		return fmt.Errorf("operator: provisioning needs an issuer")
	case providerSubject == "":
		return fmt.Errorf("operator: provisioning needs a provider subject")
	case !ValidRole(role):
		return fmt.Errorf("operator: %q is not a role", role)
	}
	eventsourcing.Record(o, &contract.OperatorProvisioned{
		OperatorID:      operatorID,
		SubjectID:       subjectID,
		Issuer:          issuer,
		ProviderSubject: providerSubject,
		Role:            role,
		ProvisionedBy:   provisionedBy,
		ProvisionedAt:   at.UTC(),
	})
	return nil
}

// ChangeRole records a privilege change.
//
// A change to the SAME role records nothing and succeeds. That is the one place
// idempotency is right here: the caller asked for a state that holds, and an
// event saying "support became support" would be noise in precisely the stream
// an escalation alert reads.
func (o *Operator) ChangeRole(newRole contract.Role, changedBy string, at time.Time) error {
	switch {
	case !o.Exists():
		return fmt.Errorf("operator: no such operator")
	case o.disabled:
		return fmt.Errorf("operator: %s is disabled; re-provision rather than re-grant", o.operatorID)
	case !ValidRole(newRole):
		return fmt.Errorf("operator: %q is not a role", newRole)
	case changedBy == "":
		return fmt.Errorf("operator: a role change needs an actor")
	case changedBy == o.operatorID:
		// Self-escalation is the failure this domain exists to make
		// impossible, and it is worth refusing HERE rather than only in the
		// handler: an operator_admin holds CapManageOperators, so nothing in
		// the capability table stops them raising themselves, and the only
		// place that knows the actor and the target are the same is the
		// aggregate.
		return fmt.Errorf("operator: an operator may not change their own role")
	}
	if o.role == newRole {
		return nil
	}
	eventsourcing.Record(o, &contract.OperatorRoleChanged{
		OperatorID:   o.operatorID,
		SubjectID:    o.subjectID,
		PreviousRole: o.role,
		NewRole:      newRole,
		ChangedBy:    changedBy,
		ChangedAt:    at.UTC(),
	})
	return nil
}

// Disable offboards an operator. Idempotent: disabling twice records nothing.
//
// Unlike ChangeRole this permits self-action. An operator locking themselves
// out is not an escalation, and a suspected-compromise path where the person
// who noticed cannot act until they find an admin is a path that costs minutes
// at the worst possible time.
func (o *Operator) Disable(disabledBy string, at time.Time) error {
	if !o.Exists() {
		return fmt.Errorf("operator: no such operator")
	}
	if o.disabled {
		return nil
	}
	eventsourcing.Record(o, &contract.OperatorDisabled{
		OperatorID: o.operatorID,
		SubjectID:  o.subjectID,
		DisabledBy: disabledBy,
		DisabledAt: at.UTC(),
	})
	return nil
}
