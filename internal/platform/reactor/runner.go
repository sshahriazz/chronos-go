package reactor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Deps is what a Runner needs.
type Deps struct {
	Subscriber eventsourcing.PersistentSubscriber
	Codec      eventsourcing.Codec
	Dedup      Dedup
	Log        *slog.Logger
	Metrics    Metrics
	Clock      clock.Clock

	// Retry is the backoff after the subscription drops. Zero takes the default.
	Retry time.Duration
}

const defaultRetry = 2 * time.Second

// Runner drives one reactor.
//
// Unlike a projector there is no lease: a persistent subscription group is
// designed for competing consumers, so running N instances is how a reactor
// scales AND how it fails over. The server hands each event to exactly one
// consumer (ARCHITECTURE §3.3).
type Runner struct {
	reactor Reactor
	deps    Deps
	name    string
}

func NewRunner(r Reactor, deps Deps) *Runner {
	if deps.Retry <= 0 {
		deps.Retry = defaultRetry
	}
	if deps.Log == nil {
		deps.Log = slog.Default()
	}
	if deps.Metrics == nil {
		deps.Metrics = noMetrics{}
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	deps.Log = deps.Log.With("reactor", r.Name())
	return &Runner{reactor: r, deps: deps, name: r.Name()}
}

// Run consumes until the context ends.
//
// A dropped subscription is reconnected rather than fatal (ADR-010). Unlike a
// projector, a handler error does NOT stop the runner: the server owns the
// retry policy and parks what keeps failing, so one bad event cannot halt every
// notification in the system.
func (r *Runner) Run(ctx context.Context) error {
	for {
		r.consumeOnce(ctx)
		if !sleep(ctx, r.deps.Retry) {
			// The context ended: an orderly stop, not a failure.
			return nil
		}
	}
}

// consumeOnce runs until the subscription ends, and reports why unless the
// reason was our own shutdown. It returns nothing because there is no outcome
// the caller can act on — reconnecting is the only response to any of them.
func (r *Runner) consumeOnce(ctx context.Context) {
	err := r.deps.Subscriber.Consume(ctx, r.name, r.reactor.Filter(), r.handle)
	if err == nil || ctx.Err() != nil || errors.Is(err, context.Canceled) {
		return
	}
	r.deps.Log.Warn("subscription ended; reconnecting", "error", err)
}

// handle decodes one event, skips it if already done, and reacts.
//
// Order matters and is the opposite of a projector's. The effect happens FIRST
// and is recorded after: recording first would mean a crash before the effect
// leaves it permanently unsent, and an unsent password reset is worse than a
// duplicated one. The residual risk — effect done, record lost — produces a
// duplicate, which React is required to tolerate.
func (r *Runner) handle(ctx context.Context, e eventsourcing.RecordedEvent) error {
	if e.IsSystem() {
		return nil
	}

	seen, err := r.deps.Dedup.Seen(ctx, r.name, e.ID)
	if err != nil {
		// Unknown whether it ran. Ask for redelivery rather than risk skipping.
		return fmt.Errorf("reactor %s: checking dedup for %s: %w", r.name, e.ID, err)
	}
	if seen {
		r.deps.Metrics.Duplicate(r.name)
		r.deps.Log.Debug("already handled; skipping redelivery", "event_id", e.ID.String())
		return nil
	}

	meta, err := r.deps.Codec.UnmarshalMetadata(e.Metadata)
	if err != nil {
		// Metadata we cannot read will never become readable. Park it.
		r.deps.Metrics.Poison(r.name)
		return fmt.Errorf("%w: reactor %s: metadata of %s: %w",
			eventsourcing.ErrPoison, r.name, e.Type, err)
	}

	env := eventsourcing.Envelope{
		ID:       e.ID,
		Type:     e.Type,
		Stream:   e.Stream,
		Revision: e.Revision,
		Position: e.Position,
		Meta:     meta,
		Payload:  e.Payload,
	}

	started := r.deps.Clock.Now()
	if err := r.reactor.React(ctx, env); err != nil {
		if errors.Is(err, eventsourcing.ErrPoison) {
			r.deps.Metrics.Poison(r.name)
		} else {
			r.deps.Metrics.Failed(r.name)
		}
		return err
	}
	r.deps.Metrics.Handled(r.name, r.deps.Clock.Now().Sub(started).Seconds())

	if err := r.deps.Dedup.MarkSeen(ctx, r.name, e.ID); err != nil {
		// The effect already happened. Failing here asks for redelivery, which
		// repeats it — so report rather than retry, and let the ack stand.
		r.deps.Log.Error("effect performed but not recorded; a redelivery would repeat it",
			"event_id", e.ID.String(), "error", err)
	}
	return nil
}

func sleep(ctx context.Context, d time.Duration) bool {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-t.C:
		return true
	}
}
