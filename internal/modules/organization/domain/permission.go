package domain

import "fmt"

// OperationClass is what an RPC does, coarsely enough for payment to decide.
//
// Declared here rather than reused from `optionsv1` because the domain may not
// import generated wire types (ADR-007). The API layer maps the proto enum onto
// this, and the mapping is asserted so the two cannot drift.
type OperationClass string

const (
	// ClassUnknown is the zero value, and it denies. An RPC whose class was
	// never declared must not be treated as a read.
	ClassUnknown OperationClass = ""

	ClassRead  OperationClass = "read"
	ClassWrite OperationClass = "write"

	// ClassGrow consumes seats or quota. Blocked BEFORE write, deliberately.
	ClassGrow OperationClass = "grow"

	ClassBillingView   OperationClass = "billing:view"
	ClassBillingManage OperationClass = "billing:manage"
	ClassExport        OperationClass = "export"
)

// OperationClasses is every class, for exhaustive tests.
func OperationClasses() []OperationClass {
	return []OperationClass{
		ClassUnknown, ClassRead, ClassWrite, ClassGrow,
		ClassBillingView, ClassBillingManage, ClassExport,
	}
}

// permitted is organization.md §5.2, as data.
//
// Gate 3 consults this on every request, so it is a lookup and not a chain of
// conditionals — and being a table is what lets a test assert every cell, which
// organization.md §13 asks for by name: "the operation-class × status matrix as
// an exhaustive table test — this is the payment enforcement contract and
// deserves every cell asserted".
//
// # Three rules that are easy to get wrong and expensive when you do
//
//  1. NEITHER BILLING CLASS IS EVER BLOCKED. Locking a past-due customer out of
//     the page where they would pay you is self-inflicted revenue loss. The two
//     are gated differently by ROLE — `billing_manager` is the owner alone — and
//     identically by STATUS, which is ADR-027.
//
//  2. EXPORT IS NEVER BLOCKED once there is anything to export. Withholding a
//     suspended tenant's own data is a GDPR portability violation, not leverage.
//
//  3. GROW IS BLOCKED BEFORE WRITE. Stop them adding seats before you stop them
//     working: it protects revenue, stays far less hostile, and reverses the
//     moment payment lands.
//
// Provisioning takes the shape §5.2 gives Pending — the org exists and is not
// yet usable. It differs in duration only: seconds, waiting on a reactor.
var permitted = map[Status]map[OperationClass]bool{
	StatusProvisioning: {
		ClassRead: true, ClassBillingView: true, ClassBillingManage: true,
		// Nothing to write into, nothing to grow, nothing to export yet.
	},
	StatusTrialing: {
		ClassRead: true, ClassWrite: true, ClassGrow: true,
		ClassBillingView: true, ClassBillingManage: true, ClassExport: true,
	},
	StatusActive: {
		ClassRead: true, ClassWrite: true, ClassGrow: true,
		ClassBillingView: true, ClassBillingManage: true, ClassExport: true,
	},
	StatusPastDue: {
		// Writes continue during the grace period; growth does not.
		ClassRead: true, ClassWrite: true,
		ClassBillingView: true, ClassBillingManage: true, ClassExport: true,
	},
	StatusSuspended: {
		// Unreachable for work, still able to pay and still able to leave.
		ClassRead:        true,
		ClassBillingView: true, ClassBillingManage: true, ClassExport: true,
	},
	StatusClosed: {
		ClassRead:        true,
		ClassBillingView: true, ClassBillingManage: true, ClassExport: true,
	},
}

// Permits reports whether an organization in this status may perform class.
//
// Fails closed twice over: an unknown status permits nothing because it has no
// row, and an unknown class is permitted by no row because no row lists it.
func (s Status) Permits(class OperationClass) bool {
	if class == ClassUnknown {
		return false
	}
	return permitted[s][class]
}

// SubscriptionError explains a refusal in the terms the customer can act on.
//
// The message names the STATUS and what to do, because "operation not permitted"
// sends a paying customer to support to find out that their card expired.
func (s Status) SubscriptionError(class OperationClass) error {
	switch s {
	case StatusProvisioning:
		return fmt.Errorf("this organization is still being set up; %s becomes available in "+
			"a moment", class)
	case StatusPastDue:
		return fmt.Errorf("a payment failed and this organization cannot add seats or "+
			"workspaces until it succeeds; existing work continues. Update the payment "+
			"method to restore %s", class)
	case StatusSuspended:
		return fmt.Errorf("this organization is suspended; reading and exporting still work, "+
			"and adding a payment method restores %s", class)
	case StatusClosed:
		return fmt.Errorf("this organization is closed; its data can still be read and "+
			"exported, but %s is no longer available", class)
	case StatusUnknown:
		return fmt.Errorf("this organization's subscription state could not be determined, so "+
			"%s is refused", class)
	default:
		return fmt.Errorf("%s is not available while this organization is %s", class, s)
	}
}
