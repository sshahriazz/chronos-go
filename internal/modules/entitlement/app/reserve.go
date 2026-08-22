// Package app is entitlement's use cases and the ports they depend on.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
)

// ErrQuotaExhausted is the limit being reached. Distinguished from every other
// failure because it is the only one a CUSTOMER can act on — the answer is
// "upgrade or free one up", not "try again".
var ErrQuotaExhausted = errors.New("quota exhausted")

// Reservation is a claim on one unit of a limit.
type Reservation struct {
	ID       string
	OrgID    string
	Limit    domain.LimitKey
	ExpireAt time.Time

	// SubjectRef names what consumed the unit — a workspace id, a subject
	// pseudonym. Not used for enforcement; it is what answers the operator
	// question "which workspace is using this seat", and what lets a deletion
	// return exactly the units that resource held.
	SubjectRef string
}

// Store is the durable half of the reservation protocol.
//
// A port, and its methods are exactly entitlement.md §4's steps. It lives in
// Postgres rather than Valkey and the reason is a standing invariant: Valkey
// must survive FLUSHALL, and a reservation cannot — flushing would destroy every
// in-flight one and let two requests take the last seat.
type Store interface {
	// Reserve counts what is live and claims one more, ATOMICALLY.
	//
	// The count and the insert must be one transaction under one lock, or the
	// race this protocol exists to close is simply moved inside the port.
	Reserve(ctx context.Context, r Reservation, limit int) error

	// Commit turns a held reservation into usage. Reports whether it found one
	// to commit: a lapsed reservation must not be resurrected, because the unit
	// it held went back to the pool and may already be taken.
	Commit(ctx context.Context, reservationID string) (bool, error)

	// Release returns a held reservation. A committed one is untouched.
	Release(ctx context.Context, reservationID string) error

	// ReleaseFor returns whatever a named subject holds of a limit, committed
	// or not, and reports whether it found anything.
	//
	// Identified by SUBJECT rather than by reservation id, because a seat is
	// held for as long as the person is in the organization — days or years —
	// and by then no caller still has the id that claimed it. The subject is the
	// identity of the holding, which is why subject_ref is on the row.
	ReleaseFor(ctx context.Context, orgID string, key domain.LimitKey, subjectRef string) (bool, error)
}

// Plans resolves the allowance an organization is entitled to.
type Plans interface {
	AllowanceFor(ctx context.Context, orgID string) (domain.Allowance, error)
}

// Reserver is gate 4's use case.
type Reserver struct {
	store Store
	plans Plans
	ttl   time.Duration
	now   func() time.Time
	newID func() string
}

// ReserverDeps is what Reserver needs.
type ReserverDeps struct {
	Store Store
	Plans Plans
	TTL   time.Duration
	Now   func() time.Time
	NewID func() string
}

// DefaultTTL bounds how long a reservation may be held without being committed.
//
// It has to outlast the slowest request that could commit one and be far shorter
// than a human notices a seat missing. A minute is generous for an append and a
// projection, and short enough that a crashed process returns its seat before
// anybody counts.
const DefaultTTL = time.Minute

func NewReserver(d ReserverDeps) (*Reserver, error) {
	switch {
	case d.Store == nil:
		return nil, fmt.Errorf("entitlement: a reservation store is required")
	case d.Plans == nil:
		return nil, fmt.Errorf("entitlement: a plan resolver is required")
	case d.Now == nil:
		return nil, fmt.Errorf("entitlement: a clock is required")
	case d.NewID == nil:
		return nil, fmt.Errorf("entitlement: an id source is required")
	}
	ttl := d.TTL
	if ttl <= 0 {
		ttl = DefaultTTL
	}
	return &Reserver{store: d.Store, plans: d.Plans, ttl: ttl, now: d.Now, newID: d.NewID}, nil
}

// SeatAlreadyHeld reports that a PER-PERSON limit was already held by this
// subject, so nothing new was taken.
//
// An error type rather than a bool return, because it has to survive being
// returned from inside a transaction closure — and because every existing caller
// of Reserve treats a nil error as "a unit was taken", which is exactly the
// belief that must not silently become wrong.
//
// It is a SUCCESS. The reservation named by it is the seat the subject already
// holds, and it is the one to commit.
type SeatAlreadyHeld struct{ ReservationID string }

func (SeatAlreadyHeld) Error() string {
	return "entitlement: this subject already holds a seat in that pool"
}

// Reserve claims one unit of a limit for an organization.
//
// # Why the allowance is read first and the count second
//
// The allowance comes from the plan and changes only when a subscription does.
// The count is what races. Reading the allowance outside the store's transaction
// keeps the lock as short as possible, and a plan that changed underneath is not
// a correctness problem: the worst case is one request gated against the
// previous plan, which the next request corrects.
func (r *Reserver) Reserve(
	ctx context.Context, orgID string, key domain.LimitKey, subjectRef string,
) (Reservation, error) {
	if orgID == "" {
		return Reservation{}, fmt.Errorf("entitlement: no organization to reserve against")
	}

	allowance, err := r.plans.AllowanceFor(ctx, orgID)
	if err != nil {
		return Reservation{}, fmt.Errorf("entitlement: resolving the plan for %s: %w", orgID, err)
	}

	limit, known := allowance.Of(key)
	if !known {
		// An RPC declared an entitlement the organization's plan says nothing
		// about. Refused rather than allowed: treating it as unlimited would
		// silently ungate that RPC for every customer on that plan.
		return Reservation{}, fmt.Errorf("entitlement: plan %q grants no %q, so there is no "+
			"allowance to reserve against", allowance.Name, key)
	}

	reservation := Reservation{
		ID:         r.newID(),
		OrgID:      orgID,
		Limit:      key,
		ExpireAt:   r.now().UTC().Add(r.ttl),
		SubjectRef: subjectRef,
	}
	if err := r.store.Reserve(ctx, reservation, limit); err != nil {
		// Already held is a SUCCESS with a different reservation id: the seat is
		// the one they already have, and committing THAT is what keeps the
		// caller's commit from failing against a row that was never inserted.
		var held SeatAlreadyHeld
		if errors.As(err, &held) {
			reservation.ID = held.ReservationID
			return reservation, held
		}
		return Reservation{}, err
	}
	return reservation, nil
}

// Commit records that the reservation was used.
func (r *Reserver) Commit(ctx context.Context, reservationID string) error {
	committed, err := r.store.Commit(ctx, reservationID)
	if err != nil {
		return fmt.Errorf("entitlement: committing %s: %w", reservationID, err)
	}
	if !committed {
		// The reservation lapsed before the handler finished. The unit went back
		// to the pool and may already be taken, so this is a real failure rather
		// than a no-op — the caller has consumed something it no longer holds.
		return fmt.Errorf("entitlement: reservation %s had already expired; the quota it held "+
			"was returned to the pool", reservationID)
	}
	return nil
}

// Release returns an uncommitted reservation.
//
// Errors are swallowed by design at the call site, not here: the gate defers
// this after every request and a failure to release costs one unit until the
// TTL, which is exactly what the TTL is for.
func (r *Reserver) Release(ctx context.Context, reservationID string) error {
	return r.store.Release(ctx, reservationID)
}

// ReserveFor claims one unit and returns just its id.
//
// A convenience over Reserve for the callers that reserve CONDITIONALLY — the
// seat rule, where whether to reserve at all is decided by the caller — and that
// therefore have no use for the rest of the Reservation. Same protocol, same
// lock, same allowance.
func (r *Reserver) ReserveFor(
	ctx context.Context, orgID, limitKey, subjectRef string,
) (string, error) {
	reservation, err := r.Reserve(ctx, orgID, domain.LimitKey(limitKey), subjectRef)
	var held SeatAlreadyHeld
	switch {
	case errors.As(err, &held):
		// The seat they already hold. Returned WITH the sentinel, so the seat
		// rule can report `seat_consumed: false` — the customer is not charged
		// twice, and the caller is told which of the two happened.
		return reservation.ID, held
	case err != nil:
		return "", err
	}
	return reservation.ID, nil
}

// ReleaseFor returns the unit a named subject holds.
//
// # Why a missing row is an ERROR and not a no-op
//
// This is the seat rule's release path, and the two ways it can be wrong are not
// symmetric. Releasing a unit that was never taken inflates the allowance by one
// every time it happens, and nothing ever notices — the pool simply grows. So
// "there was nothing to release" is reported rather than swallowed: it means the
// caller's model of who holds what disagrees with the store, and the answer is
// to find out why, not to carry on.
func (r *Reserver) ReleaseFor(ctx context.Context, orgID, limitKey, subjectRef string) error {
	if orgID == "" || subjectRef == "" {
		return fmt.Errorf("entitlement: releasing %q needs both an organization and a subject",
			limitKey)
	}
	released, err := r.store.ReleaseFor(ctx, orgID, domain.LimitKey(limitKey), subjectRef)
	if err != nil {
		return fmt.Errorf("entitlement: releasing %s for %s: %w", limitKey, subjectRef, err)
	}
	if !released {
		return fmt.Errorf("entitlement: %s held no %s to release", subjectRef, limitKey)
	}
	return nil
}
