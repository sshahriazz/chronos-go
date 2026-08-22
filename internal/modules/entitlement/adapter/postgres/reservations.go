// Package postgres holds entitlement's durable reservation store.
package postgres

import (
	"context"
	"fmt"

	entitlementdb "github.com/chronos/chronos-go/gen/sqlc/entitlement"
	"github.com/chronos/chronos-go/internal/modules/entitlement/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Reservations is the reservation protocol, in the durable store.
//
// It holds both transaction shapes because it does two different jobs: the
// reservation protocol is TENANT-scoped, and the expiry sweep spans every
// tenant at once and therefore cannot be.
type Reservations struct {
	tx     db.TX
	system db.SystemTX
}

var _ app.Store = (*Reservations)(nil)

func NewReservations(tx db.TX, system db.SystemTX) (*Reservations, error) {
	if tx == nil {
		return nil, fmt.Errorf("entitlement: a tenant transaction source is required")
	}
	if system == nil {
		return nil, fmt.Errorf("entitlement: a system transaction source is required for the " +
			"expiry sweep, which spans every tenant")
	}
	return &Reservations{tx: tx, system: system}, nil
}

// Reserve counts what is live and claims one more, in ONE transaction.
//
// # Why the count and the insert cannot be separated
//
// This is the entire mechanism. entitlement.md §4 opens with the failure it
// prevents: "two admins inviting the last seat simultaneously both read
// `49 < 50` and both proceed". Counting in one statement and inserting in
// another — even microseconds apart — reproduces exactly that.
//
// An ADVISORY TRANSACTION LOCK on (org, limit) is what serialises them, taken
// before the count. `SELECT count(*) ... FOR UPDATE` is the obvious choice and
// is doubly wrong: PostgreSQL refuses it outright, and it could not work anyway
// — with no rows yet there is nothing to lock, so the first two concurrent
// reservations would not serialise, which is exactly the case that matters.
//
// A TENANT transaction, so the RLS predicate and the WHERE clause say the same
// thing. The policy is what holds when somebody forgets the predicate.
func (r *Reservations) Reserve(ctx context.Context, res app.Reservation, limit int) error {
	return r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		// FIRST, and in the same transaction as the count and the insert.
		// Released automatically at COMMIT or ROLLBACK.
		if _, err := q.Exec(ctx, entitlementdb.LockQuota,
			res.OrgID, string(res.Limit)); err != nil {
			return fmt.Errorf("locking %s for %s: %w", res.Limit, res.OrgID, err)
		}

		var used int64
		if err := q.QueryRow(ctx, entitlementdb.CountLiveQuota,
			res.OrgID, string(res.Limit)).Scan(&used); err != nil {
			return fmt.Errorf("counting %s for %s: %w", res.Limit, res.OrgID, err)
		}

		// The `+1` question, asked here rather than in the domain, because only
		// here is the count under a lock. domain.Allowance.Permits asks the same
		// thing for the read-side CHECK.
		if limit >= 0 && used >= int64(limit) {
			return fmt.Errorf("%w: %s allows %d and %d are in use",
				app.ErrQuotaExhausted, res.Limit, limit, used)
		}

		if _, err := q.Exec(ctx, entitlementdb.InsertQuotaReservation,
			res.ID, res.OrgID, string(res.Limit), res.ExpireAt, res.SubjectRef); err != nil {
			return fmt.Errorf("reserving %s for %s: %w", res.Limit, res.OrgID, err)
		}
		return nil
	})
}

// Commit turns a held reservation into usage.
func (r *Reservations) Commit(ctx context.Context, reservationID string) (bool, error) {
	var committed bool
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, entitlementdb.CommitQuotaReservation, reservationID)
		if err != nil {
			return err
		}
		committed = rows > 0
		return nil
	})
	return committed, err
}

// Release returns a held reservation. A committed one is untouched, which is
// what makes the gate's unconditional `defer release()` safe.
func (r *Reservations) Release(ctx context.Context, reservationID string) error {
	return r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, entitlementdb.ReleaseQuotaReservation, reservationID)
		return err
	})
}

// Sweep deletes reservations that lapsed without being committed.
//
// entitlement.md §4 wants this on a Temporal Schedule rather than a lazy check,
// so a leaked reservation cannot sit unnoticed until somebody hits the limit.
// The queries already exclude expired rows from the count, so a leak costs
// nothing until then — this is hygiene, not correctness.
func (r *Reservations) Sweep(ctx context.Context) (int64, error) {
	var removed int64
	err := r.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, entitlementdb.ExpireQuotaReservations)
		if err != nil {
			return err
		}
		removed = rows
		return nil
	})
	return removed, err
}
