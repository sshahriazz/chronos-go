// Package projection is the read-side kernel: it turns the event log into
// PostgreSQL rows.
//
// A projection here is a PROJECTOR in the ADR-019 sense — it owns its
// checkpoint, it is idempotent, and it can be rebuilt from position zero at any
// time. Anything that touches the outside world (email, webhooks, payment
// calls) is a REACTOR and does not belong in this package; replaying a reactor
// sends a thousand real emails, which is why the two transports are separate
// types with no shared base.
//
// Nothing here imports a driver or a client. The ports are declared by this
// package because this package is their consumer (CONVENTIONS §2).
package projection

import (
	"context"
	"errors"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/realtime"
)

// Envelope is re-exported from the kernel. It is the SAME type a reactor
// receives: one decoded event is one decoded event, and two structurally
// identical envelopes would drift the moment one gained a field.
type Envelope = eventsourcing.Envelope

// Projection is a read model built from the log.
//
// Name is permanent: it keys the checkpoint row and the advisory lock, so
// renaming one silently restarts it from zero.
type Projection interface {
	Name() string

	// Filter narrows $all server-side: without it every event in the system is
	// shipped to every projector over the wire.
	//
	// It must select on ONE dimension — stream prefixes, event-type prefixes, or
	// whole event types — because a KurrentDB filter matches streams or types
	// and never both. A mixed filter is refused at startup rather than silently
	// reduced to whichever half the adapter honours; see
	// eventsourcing.SubscriptionFilter.Validate.
	//
	// The narrower it is, the cheaper a REBUILD becomes: one whole category
	// reads $ce-, one whole event type reads $et-, and anything else scans $all.
	Filter() eventsourcing.SubscriptionFilter

	// Apply queues one event's effect. It runs inside a batch already scoped to
	// the event's tenant, and it MUST be idempotent: the same event can arrive
	// twice after a restart, and a rebuild replays everything.
	//
	// It receives a Writer, not a Querier, so a projection cannot read. That is
	// deliberate on two counts. It lets every statement ship in one round trip.
	// And a projector that reads its own tables and branches on what it finds
	// is not replay-safe in general — the same event applied against a
	// different starting state produces a different result, which is exactly
	// what a rebuild is not allowed to do. Read-modify-write belongs in SQL
	// (`UPDATE ... SET n = n + 1`, `INSERT ... SELECT`), where the database
	// evaluates it atomically.
	Apply(ctx context.Context, w db.Writer, env Envelope) error

	// Reset empties this projection's tables so it can be rebuilt from zero.
	// It runs in the same transaction that clears the checkpoint, so a rebuild
	// can never half-happen.
	Reset(ctx context.Context, q db.Querier) error
}

// Emitter is an optional capability: a projection that also announces its
// changes to connected browsers.
//
// Emit is a PURE function from event to messages — it performs no I/O. The
// runner publishes what it returns AFTER the rows commit, which matters twice
// over: a publish inside Apply would put network latency inside the batch that
// holds the projection's atomicity, and announcing a row that then failed to
// commit would tell a browser about something that never happened.
//
// The runner drops emissions when the projector is not caught up, so a rebuild
// replays rows without replaying announcements.
type Emitter interface {
	Emit(env Envelope) []realtime.Message
}

// Checkpoint is a projector's position in the log, plus enough operational
// detail to answer "is it stuck, or is nothing happening?" without a query
// against the event store.
type Checkpoint struct {
	Position        eventsourcing.Position
	EventsProcessed int64
}

// Checkpoints stores projector positions.
//
// No method opens its own transaction: the checkpoint must commit with the rows
// it describes, and a store that could open its own transaction would make that
// impossible to guarantee. Save takes a Writer so it lands in the same batch as
// the projected rows; Load and Clear take a Querier because they run on their
// own, outside the per-event path.
type Checkpoints interface {
	Load(ctx context.Context, q db.Querier, name string) (Checkpoint, error)
	Save(ctx context.Context, w db.Writer, name string, c Checkpoint, holder string)
	Clear(ctx context.Context, q db.Querier, name string) error
}

// Lease is single-writer mutual exclusion across processes.
//
// A projector is a single writer by construction (ARCHITECTURE §3.3): two
// instances applying the same event race on the checkpoint and can interleave
// writes that neither ordering would produce. Scaling a projector means more
// projections, not more copies of one.
type Lease interface {
	// Acquire returns held=false when someone else holds the lease. It is not a
	// queue: the caller retries.
	Acquire(ctx context.Context, name string) (rel Release, held bool, err error)
}

// Release surrenders a lease. It takes its own context because it must still
// run when the context that acquired the lease has been cancelled.
type Release func(context.Context)

// ErrNoCheckpoint is returned by Load when a projector has never run. Callers
// treat it as position zero rather than as a failure.
var ErrNoCheckpoint = errors.New("projection: no checkpoint")
