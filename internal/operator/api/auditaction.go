package api

import (
	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// actionFor maps the WIRE enum onto the domain's vocabulary.
//
// # The one place the two representations meet
//
// A method declares `chronos.operator.v1.AuditAction`; the projection stores
// `domain.AuditAction`. They are the same eight facts in two type systems, and
// this is the only translation between them — so the only place they can
// disagree.
//
// TestEveryWireActionMapsToTheDomain asserts the mapping is TOTAL (every
// non-unspecified enum value lands somewhere) and INJECTIVE (no two land on the
// same word). Total catches an enum value added without a domain constant;
// injective catches a copy-paste that silently files one action under another's
// name — which would be invisible in the audit log, because both rows would
// look correct.
func actionFor(a operatorv1.AuditAction) (domain.AuditAction, bool) {
	switch a {
	case operatorv1.AuditAction_AUDIT_ACTION_SIGNED_IN:
		return domain.ActionSignedIn, true
	case operatorv1.AuditAction_AUDIT_ACTION_SIGNED_OUT:
		return domain.ActionSignedOut, true
	case operatorv1.AuditAction_AUDIT_ACTION_VIEWED_CUSTOMER:
		return domain.ActionViewedCustomer, true
	case operatorv1.AuditAction_AUDIT_ACTION_VIEWED_PERSONAL_DATA:
		return domain.ActionViewedPersonalData, true
	case operatorv1.AuditAction_AUDIT_ACTION_ELEVATED:
		return domain.ActionElevated, true
	case operatorv1.AuditAction_AUDIT_ACTION_MANAGED_OPERATORS:
		return domain.ActionManagedOperators, true
	case operatorv1.AuditAction_AUDIT_ACTION_CHANGED_TENANT:
		return domain.ActionChangedTenant, true
	case operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED:
		// Not an action. The policy loader already refuses it on every method
		// that has a caller to name, so reaching this means a ceremony step —
		// which records nothing.
		return "", false
	default:
		// An enum value this build does not know, which a rolling deploy makes
		// reachable. Reported as unmapped rather than guessed: filing an unknown
		// action under a known word is how an audit log comes to say something
		// that did not happen.
		return "", false
	}
}
