package projection

import (
	"context"
	"fmt"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// ReservationName keys the checkpoint row and the single-writer lease.
const ReservationName = "identity_reservation"

// Reservation builds email_reservation_view.
//
// A projection SEPARATE from User, and the separation is not organisational.
// This table has no foreign key in either direction, so it can be reset and
// rebuilt on its own — where session_view and user_view must be truncated
// together and therefore share one projection's Reset.
//
// What it is for is narrow: the sweep that frees lapsed reservations needs a work
// list, and "which unverified claims have expired?" is the one question about
// reservations that cannot be answered from the log without scanning every
// reservation stream in the system. Everything else — is this address taken, may
// this subject confirm it — is decided against the STREAM, where the answer is
// not eventually consistent (ADR-044).
//
// So this projection enforces nothing and is never read to make a decision. A row
// that is stale, missing or left over costs the sweep one wasted aggregate load,
// because the sweep re-loads the aggregate and issues the release against the
// stream, which refuses it if the claim is no longer there to release.
type Reservation struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Reservation)(nil)

// NewReservation wires the three reservation handlers.
func NewReservation(codec eventsourcing.Codec) *Reservation {
	d := projection.NewDispatch(codec)

	projection.On[contract.EmailReserved](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailReserved,
	) error {
		w.Exec(identitydb.UpsertEmailReservation,
			string(e.Index), e.SubjectID, e.ExpiresAt, e.ReservedAt)
		return nil
	})

	projection.On[contract.EmailReservationConfirmed](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailReservationConfirmed,
	) error {
		w.Exec(identitydb.ConfirmEmailReservation, string(e.Index), e.SubjectID)
		return nil
	})

	projection.On[contract.EmailReleased](d, func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailReleased,
	) error {
		// The reason is deliberately not projected. Three causes reach here — a
		// lapsed lease, an address the owner changed away from, an erasure — and
		// they differ in what they mean, not in what the sweep must do next, which
		// is nothing in all three cases. The log keeps the distinction for anyone
		// asking why an address became free.
		w.Exec(identitydb.ReleaseEmailReservation,
			string(e.Index), e.SubjectID, e.ReleasedAt)
		return nil
	})

	return &Reservation{dispatch: d}
}

func (r *Reservation) Name() string { return ReservationName }

// Filter selects the reservation category.
//
// By STREAM prefix rather than event-type prefix, and the choice is worth a note
// because the other two identity projections go the other way. A filter that
// resolves to exactly one category rebuilds from $ce-reservation_email instead of
// scanning $all; the three event types this projection handles are three whole
// types, and the runner only takes the $et- shortcut when a filter names exactly
// one (projection.Runner.rebuildFromLinkStreams). One category beats three types.
//
// It is also the only identity projection that CAN do this: user and session
// events are spread across two categories, so nothing narrower than the shared
// "identity." type prefix selects them.
func (r *Reservation) Filter() eventsourcing.SubscriptionFilter {
	// The trailing dash is what makes this a whole category rather than a prefix
	// that could also match a longer category name.
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{blindindex.Category + "-"},
	}
}

func (r *Reservation) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return r.dispatch.Apply(ctx, w, env)
}

func (r *Reservation) Handles(eventType string) bool { return r.dispatch.Handles(eventType) }

// Reset empties the projection so it can be rebuilt from zero.
func (r *Reservation) Reset(ctx context.Context, q db.Querier) error {
	if _, err := q.Exec(ctx, identitydb.TruncateEmailReservations); err != nil {
		return fmt.Errorf("identity reservation projection: resetting: %w", err)
	}
	return nil
}
