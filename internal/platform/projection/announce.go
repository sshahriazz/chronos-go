package projection

import (
	"context"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/platform/realtime"
)

// announcer publishes realtime messages from its own goroutine.
//
// The projector's loop must not wait on Centrifugo. A publish is a network call
// to a service that is not the system of record, and putting it in the per-event
// path means the read model advances at the speed of the slowest notification
// hop — for a payload a browser could recover by simply reading the row.
//
// The queue is bounded and drops when full, deliberately. Blocking would restore
// exactly the coupling this removes, and an unbounded queue would turn a
// Centrifugo outage into memory growth in the process that owns the read model.
type announcer struct {
	pub     realtime.Publisher
	log     *slog.Logger
	metrics Metrics
	name    string
	ctx     context.Context
	work    chan []realtime.Message
	done    chan struct{}
}

// newAnnouncer keeps the projector's context WITHOUT its cancellation.
//
// The values matter — tracing, request scope — and the cancellation must not:
// every queued message describes rows that are already committed, so dropping
// them at shutdown would announce nothing for work that did happen. Draining is
// bounded by the queue size, so shutdown stays prompt anyway.
func newAnnouncer(
	ctx context.Context, name string, pub realtime.Publisher, log *slog.Logger,
	metrics Metrics, buffer int,
) *announcer {
	return &announcer{
		pub:     pub,
		log:     log,
		metrics: metrics,
		name:    name,
		ctx:     context.WithoutCancel(ctx),
		work:    make(chan []realtime.Message, buffer),
		done:    make(chan struct{}),
	}
}

// start runs the publisher until stop is called.
func (a *announcer) start() {
	go func() {
		defer close(a.done)
		for msgs := range a.work {
			if err := a.pub.PublishMany(a.ctx, msgs); err != nil {
				a.log.Warn("realtime announcement failed; the change is still in the read model",
					"messages", len(msgs), "error", err)
			}
		}
	}()
}

// announceDrainTimeout bounds how long shutdown waits for queued announcements.
//
// Unbounded would mean a Centrifugo that has stopped answering can hold the
// projector's shutdown open for as long as its own publish takes to give up —
// the exact coupling the queue exists to remove, moved from the per-event path
// to the shutdown path.
const announceDrainTimeout = 5 * time.Second

// stop closes the queue and waits, briefly, for what is already in it.
//
// If the wait expires the publisher goroutine is left to finish on its own. It
// touches nothing the runner owns, and the alternative — blocking shutdown on
// an unresponsive service — is worse than a goroutine that outlives its owner by
// one publish.
func (a *announcer) stop() {
	close(a.work)
	select {
	case <-a.done:
	case <-time.After(announceDrainTimeout):
		a.log.Warn("realtime publisher did not drain within the shutdown budget; "+
			"abandoning queued announcements", "timeout", announceDrainTimeout)
	}
}

// enqueue hands messages to the publisher, dropping them if it is behind.
//
// Dropping is COUNTED as well as logged. A browser missing a toast is cosmetic,
// but a queue that is persistently full means the realtime path is failing —
// and that failure is otherwise invisible, because every row is correct and
// every checkpoint advances while users simply stop seeing updates arrive.
func (a *announcer) enqueue(msgs []realtime.Message) {
	select {
	case a.work <- msgs:
	default:
		a.metrics.AnnouncementsDropped(a.name, len(msgs))
		a.log.Warn("realtime announcement dropped; the publisher is behind and the "+
			"read model must not wait for it", "messages", len(msgs))
	}
}
