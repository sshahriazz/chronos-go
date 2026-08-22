// Package postgres holds entitlement's durable reservation store.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	entitlementdb "github.com/chronos/chronos-go/gen/sqlc/entitlement"
	"github.com/chronos/chronos-go/internal/modules/entitlement/app"
	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
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
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		// FIRST, and in the same transaction as the count and the insert.
		// Released automatically at COMMIT or ROLLBACK.
		if _, err := q.Exec(ctx, entitlementdb.LockQuota,
			res.OrgID, string(res.Limit)); err != nil {
			return fmt.Errorf("locking %s for %s: %w", res.Limit, res.OrgID, err)
		}

		// A PER-PERSON limit that this subject already holds is not a second
		// unit — it is the same seat. Asked under the lock taken above, so "do
		// they already hold one" and "take one" cannot interleave.
		//
		// This is what makes "a seat is per person per organization" true across
		// callers that cannot see each other. A pending invitation holds a seat
		// and creates no membership row, so the invite path and the direct-add
		// path each ask "is this person already a member", each get no, and each
		// reserve — charging the organization twice for one person. The unique
		// index added in migration 00024 makes the second row impossible; this
		// turns that impossibility into a reuse rather than an error.
		if res.Limit.PerSubject() && res.SubjectRef != "" {
			var existing string
			err := q.QueryRow(ctx, entitlementdb.SeatHeldBy,
				res.OrgID, string(res.Limit), res.SubjectRef).Scan(&existing)
			switch {
			case err == nil:
				return errAlreadyHeld{reservationID: existing}
			case !errors.Is(err, pgx.ErrNoRows):
				return fmt.Errorf("reading the %s held by %s: %w",
					res.Limit, res.SubjectRef, err)
			}
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

	// A seat this subject already holds is a SUCCESS, and it is reported as
	// app.ErrSeatAlreadyHeld so the caller can tell "took one" from "already had
	// one" — which is the difference between charging the customer and not, and
	// is what `seat_consumed` publishes.
	var held errAlreadyHeld
	if errors.As(err, &held) {
		return app.SeatAlreadyHeld{ReservationID: held.reservationID}
	}
	return err
}

// errAlreadyHeld carries the existing reservation out of the transaction.
//
// A sentinel rather than a nil return, because returning nil from inside
// InTenantTx would COMMIT the transaction as a successful reservation that
// inserted nothing — indistinguishable, from the outside, from one that did.
type errAlreadyHeld struct{ reservationID string }

func (errAlreadyHeld) Error() string { return "entitlement: seat already held" }

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

// ReleaseFor returns whatever a subject holds of a limit, committed or not.
//
// Committed rows INCLUDED, which is the difference from Release: a committed
// reservation is usage, and usage going away is exactly what a departure is. A
// version that spared committed rows would release only seats whose holder left
// within the reservation TTL, which is to say almost none of them.
func (r *Reservations) ReleaseFor(
	ctx context.Context, orgID string, key domain.LimitKey, subjectRef string,
) (bool, error) {
	var released bool
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, entitlementdb.ReleaseQuotaForSubject,
			orgID, string(key), subjectRef)
		if err != nil {
			return err
		}
		released = rows > 0
		return nil
	})
	return released, err
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
