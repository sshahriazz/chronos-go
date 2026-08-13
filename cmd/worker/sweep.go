package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// newReservationCodec builds the codec and upcaster registry the reservation
// REPOSITORY reads with.
//
// A second codec in one binary needs justifying, and the justification is that
// the two answer different questions. newCodec is the REACTOR's codec: every
// event it can decode must have a notification decision recorded against it, and
// events_test.go fails the build otherwise. This one is the write side's — it
// exists to rebuild one aggregate from one stream — and holding identity's whole
// event set to a notification decision it does not yet have would couple the
// sweep to work that has not landed.
//
// It is built from the module's own declarations rather than from a list of the
// three reservation events, so it cannot drift from what identity writes: a
// second list is a second place to forget an event, and the failure mode is a
// repository that cannot decode the stream it is responsible for.
// The registry is returned alongside the codec because the repository needs the
// SAME one: the codec applies it on the way in and the repository applies it on
// the way out, and two registries would let those two disagree about which
// schema version a stored event is (ADR-029).
func newReservationCodec() (*eventcodec.JSON, *eventsourcing.UpcasterRegistry) {
	upcasters := eventsourcing.NewUpcasterRegistry()
	identity.RegisterSchemas(upcasters)

	codec := eventcodec.NewJSON(upcasters)
	identity.RegisterEvents(codec)
	return codec, upcasters
}

// sweepAdapter presents the identity use case as the durable-work port.
//
// Two counter structs rather than one shared type, because the alternative is
// internal/adapter/temporal importing an identity use case — and an adapter that
// knows a module is an adapter that will eventually make a decision for it. The
// conversion is mechanical and total; there is nothing here for it to get wrong
// beyond the compiler's reach.
type sweepAdapter struct{ sweep *app.ReservationSweep }

var _ temporaladapter.ReservationSweeper = sweepAdapter{}

func (s sweepAdapter) SweepOnce(
	ctx context.Context, now time.Time, limit int,
) (temporaladapter.SweepPass, error) {
	res, err := s.sweep.SweepOnce(ctx, now, limit)
	return temporaladapter.SweepPass{
		Scanned:  res.Scanned,
		Released: res.Released,
		Stale:    res.Stale,
		Failed:   res.Failed,
		More:     res.More,
	}, err
}

// newReservationSweep builds the lapsed-reservation sweep, or reports why it
// could not be.
//
// Both halves are required and neither has a safe stand-in: without the work
// list nothing is ever found, and without the event store nothing can be
// released. A sweep constructed with either missing would run to completion and
// report success while freeing nothing.
func newReservationSweep(d *dependencies, log *slog.Logger) (*app.ReservationSweep, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: the sweep's work list lives in " +
			"email_reservation_view and cannot be read")
	}
	if d.store == nil {
		return nil, errors.New("no event store: a release is an event on the address's " +
			"stream, so it cannot be recorded")
	}

	codec, upcasters := newReservationCodec()
	repo := eventsourcing.NewRepository(
		d.store, codec, upcasters, blindindex.Category, domain.NewReservation,
	)
	reservations, err := identitypg.NewReservations(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}
	return app.NewReservationSweep(reservations, repo, log)
}
