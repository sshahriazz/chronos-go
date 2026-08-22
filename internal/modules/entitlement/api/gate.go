// Package api adapts entitlement's use cases to the enforcement pipeline.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/modules/entitlement/app"
	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// reservationKey carries a granted reservation to the handler that consumes it.
type reservationKey struct{}

// ReservationFrom returns the reservation gate 4 granted this request.
//
// A handler that consumes quota MUST commit what it was granted. Reading it from
// the context rather than being passed it is the same rule the principal
// follows: only the gate can write this, so a handler cannot claim a reservation
// it was not given.
func ReservationFrom(ctx context.Context) (app.Reservation, bool) {
	r, ok := ctx.Value(reservationKey{}).(app.Reservation)
	return r, ok
}

// Reserver is the use case this gate drives.
type Reserver interface {
	Reserve(ctx context.Context, orgID string, key domain.LimitKey, subjectRef string) (app.Reservation, error)
	Release(ctx context.Context, reservationID string) error
}

// Gate is gate 4: is the feature purchased, and is there quota left.
type Gate struct {
	reserver Reserver
	log      *slog.Logger
}

var _ interceptor.Entitlements = (*Gate)(nil)

func NewGate(reserver Reserver, log *slog.Logger) (*Gate, error) {
	if reserver == nil {
		return nil, fmt.Errorf("entitlement: a reserver is required; without one gate 4 could " +
			"only fail open or fail closed, and neither is enforcement")
	}
	if log == nil {
		return nil, fmt.Errorf("entitlement: a logger is required")
	}
	return &Gate{reserver: reserver, log: log}, nil
}

// Reserve claims one unit of the limit an RPC declared.
//
// # What the three return values mean here
//
// The CONTEXT carries the reservation so the handler can commit it. The FUNC
// releases, and the pipeline defers it after every request — success or failure
// — which is safe because releasing a committed reservation does nothing.
//
// # Why a missing tenant scope is INTERNAL
//
// It means the pipeline ran out of order: gate 4 executed without gate 1 having
// resolved an organization. That is our bug, and reporting it as QUOTA_EXCEEDED
// would tell a customer to upgrade a plan that was never the problem.
func (g *Gate) Reserve(ctx context.Context, key string) (context.Context, func(), error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return ctx, nil, errs.Internalf("the entitlement gate ran with no tenant scope, so " +
			"there is no organization whose quota could be reserved").Wrap(err)
	}

	reservation, err := g.reserver.Reserve(ctx, tenant.OrgID, domain.LimitKey(key),
		// The subject that consumed it. Recorded for reporting; the resource it
		// creates is not known until the handler runs.
		tenant.UserID)
	if err != nil {
		if errors.Is(err, app.ErrQuotaExhausted) {
			// The one failure a CUSTOMER can act on: upgrade, or free one up.
			return ctx, nil, errs.QuotaExceededf("%s", err)
		}
		// Anything else is ours — an unknown limit, an unreadable plan, a
		// database fault. FAILS CLOSED: an unevaluable quota is not an absent
		// one, or a projection outage would lift every cap at once.
		return ctx, nil, errs.QuotaExceededf(
			"this organization's quota could not be evaluated, so %s is refused", key).Wrap(err)
	}

	release := func() {
		// A background context deliberately: this runs from a deferred call
		// after the handler, and the request's context may already be cancelled
		// — which is exactly when a release matters most.
		if err := g.reserver.Release(context.WithoutCancel(ctx), reservation.ID); err != nil {
			// Logged, not returned: there is nobody to return it to. The cost of
			// a failed release is one unit held until its TTL, which is what the
			// TTL exists for.
			g.log.WarnContext(ctx, "a quota reservation could not be released; it will expire",
				"error", err, "reservation_id", reservation.ID, "limit", key)
		}
	}
	return context.WithValue(ctx, reservationKey{}, reservation), release, nil
}
