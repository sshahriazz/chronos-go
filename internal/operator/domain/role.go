// Package domain is the operator plane's aggregates and its authorization
// model.
//
// # This is a SECOND authorization model, deliberately
//
// operator.md §10: "Tenant permissions → `access`; operator authorization is a
// separate model." That is not duplication to be cleaned up later. The tenant
// model answers "may this principal touch this object", evaluated in OpenFGA
// over a relationship graph, and every question it answers is scoped to one
// organization. The operator model answers "may this employee perform this
// class of action, across every organization" — there is no object, no graph,
// and the scope is the opposite one.
//
// Expressing the second in the first would mean giving OpenFGA a type whose
// relations grant cross-tenant reads, which is exactly the shape of the field
// operator.md §3 refuses to allow anywhere: "a boolean that grants cross-tenant
// reads is exactly the field that gets set by an injection bug". Keeping them
// apart means a bug in one model cannot produce a grant in the other, because
// they share no storage, no evaluation path and no vocabulary.
package domain

import (
	"fmt"

	"github.com/chronos/chronos-go/internal/operator/contract"
)

// Capability is one class of operator action.
//
// Named capabilities rather than a comparison on the role itself, because the
// roles are NOT a clean total order in the spec's own table: `catalogue_admin`
// holds the catalogue, `billing_ops` holds refunds, and neither is a superset
// of the other in any sense a customer would recognise. operator.md §3 renders
// them as a ladder with "+" rows, and reading that ladder as `>=` would silently
// grant a catalogue admin the power to issue refunds.
//
// So the ladder is written out as a table below, once, and every check asks for
// a capability.
type Capability string

// The capabilities. Slice 1 declares the whole set from operator.md §7 rather
// than only the ones it uses, because a capability added later, next to the
// handler that needs it, is a capability nobody reviewed against the role
// table.
const (
	// CapSelfSession acts on the caller's OWN session — signing out, and
	// nothing else.
	//
	// Held by every role, which makes it look like it need not exist. It does,
	// for the reason the policy loader depends on: every authenticated method
	// declares a capability, so that "this endpoint needs no permission" is not
	// expressible. Signing out genuinely needs no privilege, and the honest way
	// to say that is a capability everybody has rather than an exemption
	// somebody could copy onto an endpoint that does.
	CapSelfSession Capability = "self_session"

	// CapViewCustomers reads the customer directory and one customer's detail.
	// Every role holds it; it is what `support` means.
	CapViewCustomers Capability = "view_customers"

	// CapViewPersonalData resolves a vault field for one named subject
	// (operator.md §4). Held by every role, and gated by a mandatory
	// justification rather than by rank — the reason is that support is exactly
	// the role that legitimately needs an address to answer a ticket, so
	// restricting it by role would push the work to somebody with MORE
	// privilege, not less.
	CapViewPersonalData Capability = "view_personal_data"

	// CapIssueRefund executes a refund in Stripe (operator.md §7).
	CapIssueRefund Capability = "issue_refund"

	// CapManageCoupons creates and revokes coupons (billing §6).
	CapManageCoupons Capability = "manage_coupons"

	// CapGrantOverride grants an entitlement override, reason mandatory.
	CapGrantOverride Capability = "grant_override"

	// CapExtendTrial extends a trial, and CapResolveDispute clears a dispute
	// flag. Both are billing_ops work.
	CapExtendTrial     Capability = "extend_trial"
	CapResolveDispute  Capability = "resolve_dispute"
	CapRepairSubscript Capability = "repair_subscription"

	// CapManageCatalogue publishes and archives plan versions and migrates
	// subscribers between them (billing §2).
	CapManageCatalogue Capability = "manage_catalogue"

	// CapSuspendOrganization suspends or reinstates a tenant. operator.md §7
	// puts this at `operator_admin` — above billing, and above the catalogue —
	// because it is the only operator action that stops a paying customer
	// working.
	CapSuspendOrganization Capability = "suspend_organization"

	// CapManageOperators provisions operators, changes their roles and disables
	// them. The capability that grants capabilities, held by one role.
	CapManageOperators Capability = "manage_operators"
)

// capabilities is the role table from operator.md §3 and §7, written out.
//
// Exhaustive per role rather than layered by inheritance: an inherited table
// makes "what can billing_ops do" a question you answer by reading three
// entries and merging them in your head, and the merge is where a reviewer
// stops checking.
var capabilities = map[contract.Role]map[Capability]bool{
	contract.RoleSupport: {
		CapSelfSession:      true,
		CapViewCustomers:    true,
		CapViewPersonalData: true,
	},
	contract.RoleBillingOps: {
		CapSelfSession:      true,
		CapViewCustomers:    true,
		CapViewPersonalData: true,
		CapIssueRefund:      true,
		CapManageCoupons:    true,
		CapGrantOverride:    true,
		CapExtendTrial:      true,
		CapResolveDispute:   true,
		CapRepairSubscript:  true,
	},
	contract.RoleCatalogueAdmin: {
		CapSelfSession:      true,
		CapViewCustomers:    true,
		CapViewPersonalData: true,
		CapIssueRefund:      true,
		CapManageCoupons:    true,
		CapGrantOverride:    true,
		CapExtendTrial:      true,
		CapResolveDispute:   true,
		CapRepairSubscript:  true,
		CapManageCatalogue:  true,
	},
	contract.RoleOperatorAdmin: {
		CapSelfSession:         true,
		CapViewCustomers:       true,
		CapViewPersonalData:    true,
		CapIssueRefund:         true,
		CapManageCoupons:       true,
		CapGrantOverride:       true,
		CapExtendTrial:         true,
		CapResolveDispute:      true,
		CapRepairSubscript:     true,
		CapManageCatalogue:     true,
		CapSuspendOrganization: true,
		CapManageOperators:     true,
	},
}

// Permits reports whether a role holds a capability.
//
// An UNKNOWN role holds nothing, and an unknown capability is held by nobody.
// Both are the fail-closed answer, and both are reachable in ways that matter:
// a role string read back from an event written by a future build is unknown to
// this one, and a capability constant deleted in a refactor leaves call sites
// asking for a name the table no longer has. Neither should grant.
func Permits(role contract.Role, cap Capability) bool {
	return capabilities[role][cap]
}

// ValidRole reports whether a role is one this build knows.
//
// Separate from Permits because the two questions differ at provisioning time:
// granting somebody a role this build cannot evaluate must FAIL, loudly, rather
// than silently produce an operator who can do nothing and whose ticket says
// they should be able to.
func ValidRole(role contract.Role) bool {
	_, ok := capabilities[role]
	return ok
}

// Roles reports every known role. Used by the conformance test that asserts the
// table covers each one, so a role added to the contract without a row here
// fails the build instead of quietly granting nothing.
func Roles() []contract.Role {
	return []contract.Role{
		contract.RoleSupport,
		contract.RoleBillingOps,
		contract.RoleCatalogueAdmin,
		contract.RoleOperatorAdmin,
	}
}

// Capabilities reports every declared capability, for the same reason.
func Capabilities() []Capability {
	return []Capability{
		CapSelfSession,
		CapViewCustomers, CapViewPersonalData,
		CapIssueRefund, CapManageCoupons, CapGrantOverride,
		CapExtendTrial, CapResolveDispute, CapRepairSubscript,
		CapManageCatalogue,
		CapSuspendOrganization, CapManageOperators,
	}
}

// ParseRole validates a role string arriving from outside the log.
func ParseRole(s string) (contract.Role, error) {
	r := contract.Role(s)
	if !ValidRole(r) {
		return "", fmt.Errorf("operator: %q is not a role", s)
	}
	return r, nil
}
