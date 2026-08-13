package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

var _ eventsourcing.CatchUpSubscriber = (*Store)(nil)

// ErrSubscriptionClosed reports that the stream ended without the context being
// cancelled. It is expected — a server restart, a failover — and the caller
// reconnects from its checkpoint (ADR-010).
var ErrSubscriptionClosed = errors.New("kurrentdb: subscription closed")

// Filtered subscriptions are tuned here rather than left to the SDK defaults,
// which are MaxSearchWindow=32 and CheckpointInterval=1.
//
// The server scans MaxSearchWindow events looking for matches before yielding
// control. At 32, a projection interested in one module's streams pays a round
// trip for every 32 events in the entire system — on a busy log that is almost
// all overhead. 4096 is a window the server can scan well within a request, and
// checkpointing every 8 windows keeps the position notifications from becoming
// their own traffic.
const (
	searchWindow       = 4096
	checkpointInterval = 8
)

// SubscribeAll streams $all forwards from a position, applying h to every
// matching event, and returns when ctx ends or the subscription drops.
//
// from is EXCLUSIVE: the first event delivered is the one after it. That is
// what makes resuming from a stored checkpoint correct rather than a guaranteed
// double-apply of the last event — though h must be idempotent regardless,
// because a crash between applying rows and committing the checkpoint replays
// the event either way.
func (s *Store) SubscribeAll(
	ctx context.Context,
	from eventsourcing.StartFrom,
	sopts eventsourcing.SubscribeOptions,
	h eventsourcing.Handler,
) error {
	filter, err := toFilter(sopts.Filter)
	if err != nil {
		return err
	}

	opts := kurrentdb.SubscribeToAllOptions{
		From:               allStart(from),
		Filter:             filter,
		MaxSearchWindow:    searchWindow,
		CheckpointInterval: checkpointInterval,
	}

	sub, err := s.client.SubscribeToAll(ctx, opts)
	if err != nil {
		return fmt.Errorf("kurrentdb: subscribing to $all: %w", err)
	}
	defer func() { _ = sub.Close() }()

	for {
		// Recv blocks; ctx cancellation surfaces here as an error, so the loop
		// does not need its own select.
		ev := sub.Recv()
		switch {
		case ctx.Err() != nil:
			return ctx.Err()

		case ev == nil:
			// The client closed the stream without telling us why. Returning
			// nil here would read as "finished cleanly" and put the caller in a
			// silent reconnect loop, with the projection frozen and nothing
			// saying so.
			return ErrSubscriptionClosed

		case ev.SubscriptionDropped != nil:
			dropped := ev.SubscriptionDropped.Error
			if errors.Is(dropped, io.EOF) {
				return ErrSubscriptionClosed
			}
			// A drop is normal operation — a restart, a failover, a network
			// blip. The caller reconnects from its checkpoint (ADR-010).
			return fmt.Errorf("kurrentdb: subscription dropped: %w", dropped)

		case ev.CaughtUp != nil:
			// The server says we have reached the head of the log. This is the
			// only reliable way to distinguish "idle" from "far behind".
			if sopts.OnLive != nil {
				// A caller that buffers while catching up commits here, so a
				// failure is fatal to the subscription: continuing would leave
				// applied rows above a checkpoint that never advanced past them.
				if err := sopts.OnLive(ctx); err != nil {
					return fmt.Errorf("kurrentdb: reaching the head of the log: %w", err)
				}
			}

		case ev.FellBehind != nil:
			if sopts.OnBehind != nil {
				sopts.OnBehind()
			}

		case ev.CheckPointReached != nil:
			// Nothing matched in this window — and that is worth persisting.
			//
			// The server has scanned up to this position and guarantees no
			// matching event lies between here and the last one delivered, so
			// resuming from it skips no work. Discarding it instead, and letting
			// the position advance only on a match, means a projection filtered
			// to a quiet module never advances while the rest of the system
			// writes, and re-scans the whole intervening log on every restart.
			if sopts.OnCheckpoint == nil {
				continue
			}
			cp := ev.CheckPointReached
			if err := sopts.OnCheckpoint(ctx, eventsourcing.Position{
				Commit: cp.Commit, Prepare: cp.Prepare,
			}); err != nil {
				return fmt.Errorf("kurrentdb: recording checkpoint at %d: %w", cp.Commit, err)
			}

		case ev.EventAppeared != nil:
			resolved := ev.EventAppeared
			if resolved.Event == nil {
				// A link whose target was deleted or scavenged.
				continue
			}
			rec := toRecorded(resolved.Event)
			// $all really does mean all: $metadata streams, $scavenges, $stats
			// and per-stream settings ride along with domain events. The
			// server-side filter excludes them too, so this is the second of
			// two locks on the same door — the one that still holds when a
			// projection declares no filter at all.
			if rec.IsSystem() {
				continue
			}
			if err := h(ctx, rec); err != nil {
				return err
			}
		}
	}
}

// allStart converts a resume point into the client's start position.
//
// The distinction StartFrom carries is the whole reason it exists: Start{} is
// inclusive of the first event in the log, while a Position is exclusive of the
// event at it. Collapsing "no checkpoint" and "checkpoint at zero" into one
// value would make a restart replay everything.
func allStart(from eventsourcing.StartFrom) kurrentdb.AllPosition {
	if from.IsBeginning() {
		return kurrentdb.Start{}
	}
	p := from.Position()
	return kurrentdb.Position{Commit: p.Commit, Prepare: p.Prepare}
}

// toFilter builds the server-side filter.
//
// Filtering server-side rather than client-side is not an optimisation detail:
// an unfiltered $all subscription ships every event in the system to every
// projector over the wire, so a filter is the difference between one module's
// traffic and all of it.
//
// It returns an error rather than picking a winner when a filter names more than
// one dimension. A KurrentDB filter matches streams OR event types, so the
// switch below can only honour one — and honouring one silently is a projection
// that never sees half the events it declared, with a checkpoint advancing
// happily past them. Validate is called here as well as at consumer startup
// because this is the last point before the wire, and the check that matters is
// the one no code path can go around.
func toFilter(f eventsourcing.SubscriptionFilter) (*kurrentdb.SubscriptionFilter, error) {
	if err := f.Validate(); err != nil {
		return nil, fmt.Errorf("kurrentdb: %w", err)
	}

	switch {
	case len(f.EventTypes) > 0:
		// A regex anchored at both ends, not a prefix. "notification.Created.v1"
		// as a prefix also matches "notification.Created.v10", which would hand a
		// projection a version it does not understand the moment one is added.
		alts := make([]string, 0, len(f.EventTypes))
		for _, t := range f.EventTypes {
			alts = append(alts, regexp.QuoteMeta(t))
		}
		return &kurrentdb.SubscriptionFilter{
			Type:  kurrentdb.EventFilterType,
			Regex: "^(" + strings.Join(alts, "|") + ")$",
		}, nil

	case len(f.StreamPrefixes) > 0:
		// A stream-prefix filter also excludes system streams for free: no
		// domain category starts with '$'.
		return &kurrentdb.SubscriptionFilter{
			Type:     kurrentdb.StreamFilterType,
			Prefixes: f.StreamPrefixes,
		}, nil
	case len(f.EventTypePrefixes) > 0:
		return &kurrentdb.SubscriptionFilter{
			Type:     kurrentdb.EventFilterType,
			Prefixes: f.EventTypePrefixes,
		}, nil
	default:
		// Everything except KurrentDB's own events. A projection that declares
		// no filter still must not be handed $stats or $scavenge records, so
		// the empty case is the SDK's exclude-system filter and never nil.
		return kurrentdb.ExcludeSystemEventsFilter(), nil
	}
}
