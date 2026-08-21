// Package app holds organization's use cases and the ports they depend on.
package app

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// StatusReader answers "what is this organization's subscription status".
//
// A port, because gate 3 reads it on EVERY request and the implementation is
// the most performance-critical projection in the system — tiny, cacheable, and
// invalidated by event rather than by TTL (organization.md §10). None of that
// belongs in the decision.
type StatusReader interface {
	StatusOf(ctx context.Context, orgID string) (domain.Status, error)
}

// SubscriptionGate is gate 3: payment enforcement.
//
// It answers one question — may an organization in its current status perform
// an operation of this class — and the answer is a table lookup
// (organization.md §5.2), never a chain of conditionals.
type SubscriptionGate struct {
	reads StatusReader
}

func NewSubscriptionGate(reads StatusReader) (*SubscriptionGate, error) {
	if reads == nil {
		return nil, fmt.Errorf("organization: a status reader is required; without one gate 3 " +
			"could only fail open or fail closed, and neither is enforcement")
	}
	return &SubscriptionGate{reads: reads}, nil
}

// Permit refuses an operation the organization's subscription does not allow.
//
// # Why the org comes from the context and not from the caller
//
// The tenant scope is attached by gate 1, which runs first, and every later gate
// and the handler read it from there. A gate that took an org id as an argument
// could be handed one the caller supplied — and "which organization is this
// request in" is precisely the question a caller must not answer for itself.
//
// # Why a missing scope is INTERNAL and not a denial
//
// It means the pipeline ran out of order: gate 3 executed without gate 1 having
// resolved anything. That is our bug, not the caller's, and dressing it as
// ACCESS_DENIED would send an operator looking at permissions for a wiring
// fault (CONVENTIONS §5).
func (g *SubscriptionGate) Permit(ctx context.Context, class domain.OperationClass) error {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return errs.Internalf("the subscription gate ran with no tenant scope, so there is " +
			"no organization whose status could be read").Wrap(err)
	}

	status, err := g.reads.StatusOf(ctx, tenant.OrgID)
	if err != nil {
		// FAILS CLOSED. An unreadable status is not an absent restriction: the
		// alternative is that a projection outage silently lifts payment
		// enforcement for every tenant at once, which is the failure mode a
		// billing system can least afford.
		return errs.OrgSuspendedf("this organization's subscription state is unavailable, so "+
			"%s is refused", class).Wrap(err)
	}

	if !status.Permits(class) {
		return errs.OrgSuspendedf("%s", status.SubscriptionError(class))
	}
	return nil
}
