package domain_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// TestTheRoleTableCoversEveryRole is the guard that makes the table exhaustive.
//
// A role declared in the contract with no row in the capability table holds
// NOTHING — `Permits` returns false for every capability. That is the
// fail-closed answer and it is the right default, but as a permanent state it
// is a role somebody can be granted that silently does nothing, and the ticket
// says they should be able to work.
func TestTheRoleTableCoversEveryRole(t *testing.T) {
	for _, role := range domain.Roles() {
		if !domain.ValidRole(role) {
			t.Errorf("%q is declared as a role and has no row in the capability table", role)
		}
		holds := 0
		for _, cap := range domain.Capabilities() {
			if domain.Permits(role, cap) {
				holds++
			}
		}
		if holds == 0 {
			t.Errorf("%q holds no capability at all, so granting it does nothing", role)
		}
	}
}

// TestTheLadderIsNotATotalOrder is the test that documents why capabilities
// exist at all.
//
// operator.md §3 renders the roles as a ladder with "+" rows, and the obvious
// implementation is a rank comparison. It would be wrong, and this is the case
// that proves it: `catalogue_admin` sits ABOVE `billing_ops` in the spec's
// table, so a `>=` check would grant a catalogue admin every billing power —
// including issuing refunds, which is real money moving on the authority of
// somebody whose job is plan versions.
//
// The table happens to grant catalogue_admin the billing capabilities today,
// which is the spec's own "+" reading. What this asserts is the property that
// makes CHANGING that safe: the answer comes from a table, so narrowing
// catalogue_admin later is an edit to one map rather than a re-derivation of an
// ordering.
func TestTheLadderIsNotATotalOrder(t *testing.T) {
	// The one capability that is genuinely not cumulative: suspending a
	// customer is operator_admin's alone, above billing AND above the
	// catalogue, because it is the only operator action that stops a paying
	// customer working.
	for _, role := range []contract.Role{
		contract.RoleSupport, contract.RoleBillingOps, contract.RoleCatalogueAdmin,
	} {
		if domain.Permits(role, domain.CapSuspendOrganization) {
			t.Errorf("%q can suspend a customer; operator.md §7 puts that on operator_admin alone", role)
		}
		if domain.Permits(role, domain.CapManageOperators) {
			t.Errorf("%q can manage operators; that is the capability that grants capabilities", role)
		}
	}
	if !domain.Permits(contract.RoleOperatorAdmin, domain.CapSuspendOrganization) {
		t.Error("operator_admin cannot suspend a customer")
	}
}

// TestSupportIsReadOnly is operator.md §3's first row, asserted.
//
// "support | read-only: customer list, status, payment state". A support role
// that could issue a refund would be the least-privilege default failing at the
// exact place it matters most — the role every new hire gets.
func TestSupportIsReadOnly(t *testing.T) {
	mutating := []domain.Capability{
		domain.CapIssueRefund,
		domain.CapManageCoupons,
		domain.CapGrantOverride,
		domain.CapExtendTrial,
		domain.CapResolveDispute,
		domain.CapRepairSubscript,
		domain.CapManageCatalogue,
		domain.CapSuspendOrganization,
		domain.CapManageOperators,
	}
	for _, cap := range mutating {
		if domain.Permits(contract.RoleSupport, cap) {
			t.Errorf("support holds %q, which is a write; operator.md §3 says read-only", cap)
		}
	}

	// And the two it must hold, or it cannot do the job it exists for.
	for _, cap := range []domain.Capability{domain.CapViewCustomers, domain.CapViewPersonalData} {
		if !domain.Permits(contract.RoleSupport, cap) {
			t.Errorf("support does not hold %q, so it cannot answer a ticket", cap)
		}
	}
}

// TestEveryRoleCanEndItsOwnSession guards the reason CapSelfSession exists.
//
// Signing out is not a privilege. An operator on a shared machine who cannot
// end their session has their safest action unavailable, and the failure is
// invisible until it matters.
func TestEveryRoleCanEndItsOwnSession(t *testing.T) {
	for _, role := range domain.Roles() {
		if !domain.Permits(role, domain.CapSelfSession) {
			t.Errorf("%q cannot sign out", role)
		}
	}
}

// TestUnknownRolesAndCapabilitiesDeny is the fail-closed property, and both
// halves are reachable.
//
// A role string read back from an event written by a FUTURE build is unknown to
// this one — that is not hypothetical, it is what a rolling deploy does. A
// capability constant deleted in a refactor leaves call sites asking for a name
// the table no longer has. Neither may grant.
func TestUnknownRolesAndCapabilitiesDeny(t *testing.T) {
	if domain.Permits("root", domain.CapViewCustomers) {
		t.Error("an unknown role was granted a capability")
	}
	if domain.Permits(contract.RoleOperatorAdmin, "read_everything") {
		t.Error("an unknown capability was granted to operator_admin")
	}
	if domain.Permits("", "") {
		t.Error("the empty role holds the empty capability")
	}
	if domain.ValidRole("root") {
		t.Error("an unknown role validated")
	}
}

// TestParseRoleRefusesWhatTheTableDoesNotKnow is provisioning's guard.
//
// Granting somebody a role this build cannot evaluate must FAIL loudly rather
// than produce an operator who can do nothing while their ticket says otherwise.
func TestParseRoleRefusesWhatTheTableDoesNotKnow(t *testing.T) {
	for _, ok := range domain.Roles() {
		got, err := domain.ParseRole(string(ok))
		if err != nil {
			t.Errorf("ParseRole(%q): %v", ok, err)
		}
		if got != ok {
			t.Errorf("ParseRole(%q) = %q", ok, got)
		}
	}
	for _, bad := range []string{"", "root", "admin", "Support", "support "} {
		if _, err := domain.ParseRole(bad); err == nil {
			t.Errorf("ParseRole(%q) was accepted", bad)
		}
	}
}
