// Package reactor is the side-effect side of the event log.
//
// A reactor sends email, starts workflows, calls payment providers and pushes
// notifications. It is the mirror image of a projector, and the differences are
// deliberate and structural rather than conventional (ADR-019):
//
//	                Projector                 Reactor
//	produces        rows                      side effects on the outside world
//	checkpoint      ours, in Postgres         the SERVER's, in KurrentDB
//	rebuildable     yes, routinely            NEVER
//	new deployment  starts at position zero   starts at the END of the log
//	failure         stops, loudly             retries, then parks
//
// There is no Rebuild method in this package and no way to rewind a group.
// Replaying a reactor sends every email in history a second time; making that
// impossible to express beats remembering not to do it.
package reactor

import (
	"context"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Reactor turns events into effects on the outside world.
type Reactor interface {
	// Name is the persistent subscription group. It is PERMANENT: renaming one
	// creates a fresh group starting at the end of the log, silently dropping
	// anything the old group had not yet processed.
	Name() string

	// Filter narrows $all server-side.
	Filter() eventsourcing.SubscriptionFilter

	// React performs the effect.
	//
	// Returning an error asks for redelivery, so it must be safe to run twice —
	// delivery is at-least-once and no amount of bookkeeping makes a network
	// call and a database write atomic. Return ErrPoison (from eventsourcing)
	// for events that can never succeed; they are parked immediately instead of
	// consuming every retry.
	React(ctx context.Context, env eventsourcing.Envelope) error
}

// Dedup records which events a reactor has already handled.
//
// This is a filter over redelivery, not a correctness guarantee. It catches the
// common cases — a restart, a lost ack, a redelivery after a slow handler — and
// cannot catch a crash between performing the effect and recording it. That
// residue is why React must be idempotent anyway, and why reactors that start
// Temporal workflows key them by event ID: Temporal's own deduplication is the
// backstop under this one (ADR-017).
type Dedup interface {
	// Seen reports whether this reactor already handled this event.
	Seen(ctx context.Context, reactor string, id ids.EventID) (bool, error)

	// MarkSeen records the event as handled.
	MarkSeen(ctx context.Context, reactor string, id ids.EventID) error
}
