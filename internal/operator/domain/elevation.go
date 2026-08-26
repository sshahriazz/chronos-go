package domain

import (
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
)

// ElevationWindow is how long a break-glass lasts.
//
// Fifteen minutes. operator.md §5 says "minutes, not hours", and the number has
// to be long enough to do the thing and short enough that forgetting to end it
// is not how it ends. Fifteen is a support engineer finding the customer,
// checking the account and acting; it is not a shift.
//
// It is ABSOLUTE and nothing extends it. A second elevation is a second event
// with its own justification and its own alert, which is the property that
// makes the alert meaningful — an extendable window produces one alert and an
// unbounded grant.
const ElevationWindow = 15 * time.Minute

// MaxElevationReason bounds the recorded justification.
//
// Long enough for a ticket reference and a sentence, short enough that the
// audit log does not become a place people paste transcripts — which would put
// customer content into the one operator table that is retained beyond
// employment.
const MaxElevationReason = 500

// elevatable is which capabilities a role may break the glass to reach.
//
// # The spec leaves this open, and it cannot be left open
//
// operator.md §5 says elevation is "beyond a role's default" and describes the
// controls — justification, time box, alert — without saying how far beyond.
// Read literally that permits a support engineer elevating to
// `manage_operators`, which is self-promotion with a fifteen-minute delay and
// an alert nobody can act on faster than the grant.
//
// So the reachable set is enumerated, and the rule behind the enumeration is:
// A ROLE MAY REACH WHAT THE ROLE ABOVE IT HOLDS, AND NO FURTHER. Break-glass is
// for "the person one step up would have done this and is asleep", not for
// "there is no supervision at this hour".
//
// # Two capabilities are NEVER reachable, by anybody
//
//   - CapManageOperators, because it grants capabilities. An elevation to it is
//     an elevation to every other one, permanently, by way of a role change the
//     operator makes for themselves — so the time box would bound nothing and
//     the alert would arrive after the door was already open.
//   - CapSuspendOrganization, because it is the only operator action that stops
//     a paying customer working, and it is reversible only by another operator
//     action while the customer is down. operator.md §7 puts it at
//     `operator_admin` alone; an operator_admin needs no elevation to use it,
//     and nobody else should reach it without one of them saying so.
//
// Both refusals are absences from this table rather than special cases in the
// checking code, which is what makes them hold for a role added later.
var elevatable = map[contract.Role]map[Capability]bool{
	// Support reaches what billing_ops holds: the actions a support engineer is
	// most often one approval away from needing. Not the catalogue — a plan
	// version published at 3am by somebody whose job is tickets is a mistake
	// with a long tail.
	contract.RoleSupport: {
		CapIssueRefund:     true,
		CapManageCoupons:   true,
		CapGrantOverride:   true,
		CapExtendTrial:     true,
		CapResolveDispute:  true,
		CapRepairSubscript: true,
	},

	// billing_ops reaches the catalogue, which is catalogue_admin's addition.
	contract.RoleBillingOps: {
		CapManageCatalogue: true,
	},

	// catalogue_admin already holds everything below operator_admin, and
	// operator_admin's two additions are the two nothing may reach. So the
	// table is empty for both — not missing, empty, and the test below asserts
	// the difference.
	contract.RoleCatalogueAdmin: {},
	contract.RoleOperatorAdmin:  {},
}

// MayElevateTo reports whether a role may break the glass to a capability.
//
// False for a capability the role ALREADY holds, which is not a rejection of a
// dangerous act but of a meaningless one: an elevation to something you can
// already do produces an alert, an audit entry and a justification for an
// action that needed none, and a stream of those is how an alert stops being
// read.
func MayElevateTo(role contract.Role, cap Capability) bool {
	if Permits(role, cap) {
		return false
	}
	return elevatable[role][cap]
}

// ElevatableBy reports every capability a role may reach, for the console and
// for the conformance test.
func ElevatableBy(role contract.Role) []Capability {
	out := make([]Capability, 0, len(elevatable[role]))
	for _, cap := range Capabilities() {
		if elevatable[role][cap] {
			out = append(out, cap)
		}
	}
	return out
}

// NeverElevatable is the pair no role may reach, named so a test can assert it
// rather than infer it from the table's gaps.
func NeverElevatable() []Capability {
	return []Capability{CapManageOperators, CapSuspendOrganization}
}

// Elevation is a break-glass grant on one session.
type Elevation struct {
	Capability Capability
	Reason     string
	ExpiresAt  time.Time
}

// Live reports whether the grant is still in its window.
//
// The zero Elevation is NOT live, which is the answer a forgotten branch and a
// failed lookup both produce — the same construction `authz.Decision` uses to
// make denial the default (ADR-010).
func (e Elevation) Live(now time.Time) bool {
	return e.Capability != "" && now.Before(e.ExpiresAt)
}

// Grants reports whether this elevation covers a capability right now.
func (e Elevation) Grants(cap Capability, now time.Time) bool {
	return e.Live(now) && e.Capability == cap
}

// ValidateElevation checks a break-glass request before anything is recorded.
//
// It returns a message a person can act on, unlike most refusals on this plane
// — and the asymmetry is deliberate. The opaque errors elsewhere protect
// against an attacker learning which check failed; here the caller is an
// authenticated operator asking for a privilege, and telling them "your role
// cannot reach that one" is how they find out to ask a human instead of
// retrying.
func ValidateElevation(role contract.Role, cap Capability, reason string) error {
	switch {
	case cap == "":
		return fmt.Errorf("operator: an elevation needs a capability")

	case !knownCapability(cap):
		return fmt.Errorf("operator: %q is not a capability", cap)

	case len(reason) < 8:
		// Eight, matching the wire bound, and for the same reason: a
		// one-character justification is the shape a mandatory field takes when
		// nobody means it, and a rule that can be satisfied by "x" is one that
		// will be.
		return fmt.Errorf("operator: a break-glass needs a recorded justification of " +
			"at least 8 characters")

	case len(reason) > MaxElevationReason:
		return fmt.Errorf("operator: this justification is longer than %d characters",
			MaxElevationReason)

	case Permits(role, cap):
		return fmt.Errorf("operator: the %s role already holds %q; elevating to it would "+
			"raise an alert for an action that needs none", role, cap)

	case !elevatable[role][cap]:
		return fmt.Errorf("operator: the %s role may not break the glass to %q. "+
			"Break-glass reaches what the role above holds and no further, and "+
			"%q and %q are reachable by nobody",
			role, cap, CapManageOperators, CapSuspendOrganization)
	}
	return nil
}

func knownCapability(c Capability) bool { return slices.Contains(Capabilities(), c) }
