package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// TestNothingReachesTheTwoCapabilitiesNobodyMayElevateTo is the most important
// assertion about break-glass.
//
// operator.md §5 describes the controls — justification, time box, alert —
// without saying how far "beyond a role's default" reaches. Read literally it
// permits a support engineer elevating to `manage_operators`, which is
// self-promotion with a fifteen-minute delay: the elevated operator changes
// their own role, and the window bounds nothing because the role change
// outlives it.
//
// `suspend_organization` is the other, for a different reason — it is the only
// operator action that stops a paying customer working, and it is reversible
// only by another operator action while the customer is down.
//
// Both are absences from the table rather than special cases in the code, and
// this is what makes the absence deliberate rather than an oversight somebody
// later "fixes".
func TestNothingReachesTheTwoCapabilitiesNobodyMayElevateTo(t *testing.T) {
	for _, cap := range domain.NeverElevatable() {
		for _, role := range domain.Roles() {
			if domain.MayElevateTo(role, cap) {
				t.Errorf("%s may break the glass to %q, which nothing may reach", role, cap)
			}
		}
	}

	// And the pair is the one the code names, not a different one that happens
	// to be unreachable today. A capability nobody has granted yet is trivially
	// unreachable; these two are unreachable ON PURPOSE.
	never := map[domain.Capability]bool{}
	for _, c := range domain.NeverElevatable() {
		never[c] = true
	}
	if !never[domain.CapManageOperators] || !never[domain.CapSuspendOrganization] {
		t.Errorf("NeverElevatable() = %v, and it must name manage_operators and "+
			"suspend_organization — the two whose time box would bound nothing",
			domain.NeverElevatable())
	}
}

// TestARoleCannotElevateToWhatItAlreadyHolds guards the signal, not the
// security.
//
// An elevation to a capability you already hold grants nothing, and it produces
// an alert, an audit entry and a justification for an action that needed none.
// A stream of those is how an alert stops being read — which is the failure
// operator.md §5 names when it insists the alert reach somebody "at the time of
// use, not in a report someone reads next quarter".
func TestARoleCannotElevateToWhatItAlreadyHolds(t *testing.T) {
	for _, role := range domain.Roles() {
		for _, cap := range domain.Capabilities() {
			if !domain.Permits(role, cap) {
				continue
			}
			if domain.MayElevateTo(role, cap) {
				t.Errorf("%s may elevate to %q, which it already holds", role, cap)
			}
			err := domain.ValidateElevation(role, cap, "a perfectly good reason")
			if err == nil {
				t.Errorf("%s was permitted a meaningless elevation to %q", role, cap)
			} else if !strings.Contains(err.Error(), "already holds") {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		}
	}
}

// TestEveryElevationTargetIsSomethingTheRoleLacks is the table's own coherence.
//
// The rule is "a role reaches what the role ABOVE it holds", and the way that
// goes wrong is an entry naming a capability the role already has — which
// MayElevateTo would then silently report as unreachable, making the table
// disagree with itself.
func TestEveryElevationTargetIsSomethingTheRoleLacks(t *testing.T) {
	for _, role := range domain.Roles() {
		for _, cap := range domain.ElevatableBy(role) {
			if domain.Permits(role, cap) {
				t.Errorf("the elevation table lets %s reach %q, which it already holds — "+
					"so the entry is inert and the table says two things", role, cap)
			}
			if !domain.MayElevateTo(role, cap) {
				t.Errorf("ElevatableBy(%s) lists %q and MayElevateTo denies it", role, cap)
			}
		}
	}
}

// TestSupportReachesBillingAndNoFurther pins the ladder the table encodes.
//
// It is the case the rule was written for — a support engineer at 3am who needs
// one action a billing_ops would have taken — and the case it deliberately
// excludes: the catalogue, where a plan version published by somebody whose job
// is tickets is a mistake with a long tail.
func TestSupportReachesBillingAndNoFurther(t *testing.T) {
	reach := map[domain.Capability]bool{}
	for _, c := range domain.ElevatableBy(contract.RoleSupport) {
		reach[c] = true
	}

	for _, want := range []domain.Capability{
		domain.CapIssueRefund, domain.CapManageCoupons, domain.CapGrantOverride,
		domain.CapExtendTrial, domain.CapResolveDispute, domain.CapRepairSubscript,
	} {
		if !reach[want] {
			t.Errorf("support cannot reach %q, which billing_ops holds", want)
		}
	}
	for _, notWant := range []domain.Capability{
		domain.CapManageCatalogue, domain.CapSuspendOrganization, domain.CapManageOperators,
	} {
		if reach[notWant] {
			t.Errorf("support reaches %q, which is more than one step up", notWant)
		}
	}
}

// TestTheTopTwoRolesReachNothing is the other end of the ladder.
//
// `catalogue_admin` already holds everything below operator_admin, and
// operator_admin's two additions are the two nothing may reach. So both tables
// are EMPTY — and empty is different from missing, which is what this asserts:
// a role with no entry at all would behave identically today and would silently
// start granting if somebody added one without reading the rule.
func TestTheTopTwoRolesReachNothing(t *testing.T) {
	for _, role := range []contract.Role{
		contract.RoleCatalogueAdmin, contract.RoleOperatorAdmin,
	} {
		if got := domain.ElevatableBy(role); len(got) != 0 {
			t.Errorf("%s may elevate to %v; it should reach nothing", role, got)
		}
	}
}

// TestValidateElevationRefusesAThinJustification.
//
// Eight characters, matching the wire bound, and for the reason the wire bound
// gives: a rule that can be satisfied by "x" is a rule that will be.
func TestValidateElevationRefusesAThinJustification(t *testing.T) {
	cases := []struct {
		name, reason, want string
	}{
		{"empty", "", "justification"},
		{"one character", "x", "justification"},
		{"seven characters", "1234567", "justification"},
		{"longer than the column", strings.Repeat("a", domain.MaxElevationReason+1), "longer than"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := domain.ValidateElevation(contract.RoleSupport, domain.CapIssueRefund, tc.reason)
			if err == nil {
				t.Fatal("accepted")
			}
			if !strings.Contains(err.Error(), tc.want) {
				t.Errorf("refused for the wrong reason: %v", err)
			}
		})
	}

	// And eight is accepted, so the bound is a floor rather than an
	// approximation of one.
	if err := domain.ValidateElevation(contract.RoleSupport, domain.CapIssueRefund, "12345678"); err != nil {
		t.Errorf("an eight-character justification was refused: %v", err)
	}
}

// TestValidateElevationRefusesACapabilityThatDoesNotExist.
//
// A typo'd capability must not be granted, and it must not be silently
// unreachable either — the operator would retry the same string and get the
// same nothing.
func TestValidateElevationRefusesACapabilityThatDoesNotExist(t *testing.T) {
	err := domain.ValidateElevation(contract.RoleSupport, "read_everything", "a good reason")
	if err == nil {
		t.Fatal("an unknown capability was accepted")
	}
	if !strings.Contains(err.Error(), "is not a capability") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// TestTheZeroElevationGrantsNothing is the fail-closed property.
//
// It is reachable three ways and all three matter: a session read that did not
// populate it, a store that does not set it, and a window that has closed.
// Every one produces the zero value, and the zero value must deny — the same
// construction `authz.Decision` uses.
func TestTheZeroElevationGrantsNothing(t *testing.T) {
	var zero domain.Elevation
	now := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

	if zero.Live(now) {
		t.Error("the zero Elevation reads as live")
	}
	for _, cap := range domain.Capabilities() {
		if zero.Grants(cap, now) {
			t.Errorf("the zero Elevation grants %q", cap)
		}
	}

	// A capability with NO DEADLINE is the dangerous partial: a zero time is
	// before every instant, so a naive `now.Before(zero)` would be false and a
	// naive `!now.After(zero)` would be true. Live() requires the capability to
	// be set AND the deadline to be ahead, so a half-populated grant denies.
	half := domain.Elevation{Capability: domain.CapIssueRefund}
	if half.Live(now) {
		t.Error("an elevation with a capability and no deadline reads as live, which is " +
			"the one way a fifteen-minute grant becomes permanent")
	}
}

// TestAnExpiredElevationGrantsNothing, and the boundary is exclusive.
func TestAnExpiredElevationGrantsNothing(t *testing.T) {
	now := time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)
	e := domain.Elevation{
		Capability: domain.CapIssueRefund,
		Reason:     "incident 4711",
		ExpiresAt:  now.Add(domain.ElevationWindow),
	}

	if !e.Grants(domain.CapIssueRefund, now) {
		t.Fatal("a live elevation grants nothing")
	}
	if e.Grants(domain.CapManageCoupons, now) {
		t.Error("an elevation to one capability granted another")
	}
	if e.Grants(domain.CapIssueRefund, e.ExpiresAt) {
		t.Error("an elevation is still live AT its deadline; the window must be exclusive, " +
			"or a grant outlives the instant it was recorded as ending")
	}
	if e.Grants(domain.CapIssueRefund, e.ExpiresAt.Add(time.Nanosecond)) {
		t.Error("an expired elevation still grants")
	}
}

// TestTheWindowIsMinutesNotHours is operator.md §5's own wording, asserted.
//
// A number is easy to change and hard to notice changing. This is the test that
// makes lengthening it a deliberate act with a failing suite in front of it.
func TestTheWindowIsMinutesNotHours(t *testing.T) {
	if domain.ElevationWindow > time.Hour {
		t.Errorf("the break-glass window is %v; operator.md §5 says minutes, not hours",
			domain.ElevationWindow)
	}
	if domain.ElevationWindow < time.Minute {
		t.Errorf("the break-glass window is %v, which is too short to do anything in — "+
			"a control nobody can use is one people route around", domain.ElevationWindow)
	}
}
