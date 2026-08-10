package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

var _ eventsourcing.PersistentSubscriber = (*Store)(nil)

// Reactor tuning. A reactor sends email, starts workflows and calls payment
// providers, so its settings are chosen for "never lose one, never send twice"
// rather than for throughput.
const (
	// reactorMaxRetries is how often a failing event is redelivered before the
	// server parks it. Ten attempts over a rising backoff is long enough to
	// ride out a provider outage and short enough that a genuinely poisonous
	// event stops blocking the queue.
	reactorMaxRetries = 10

	// reactorReadBatch and reactorBuffer are modest on purpose: a reactor
	// performing side effects gains nothing from deep pipelining, and a large
	// in-flight window means more duplicate work after a crash.
	reactorReadBatch = 20
	reactorBuffer    = 100
)

// EnsureGroup creates the persistent subscription group if it does not exist.
//
// Idempotent: an existing group is left exactly as it is, never reconfigured.
// Silently updating settings would change redelivery behaviour for a running
// reactor as a side effect of a deploy.
//
// New groups start from the CURRENT end of the log, not the beginning. A
// freshly deployed reactor must not treat all of history as things that just
// happened — that is how a new notification handler emails every user who ever
// registered (ADR-019). Backfilling is a deliberate, separate act.
func (s *Store) EnsureGroup(ctx context.Context, group string, filter eventsourcing.SubscriptionFilter) error {
	settings := kurrentdb.SubscriptionSettingsDefault()
	settings.MaxRetryCount = reactorMaxRetries
	settings.ReadBatchSize = reactorReadBatch
	settings.HistoryBufferSize = reactorBuffer

	// ResolveLinkTos MUST stay off on a $all subscription. $all already carries
	// the original events; with the system projections running it ALSO carries
	// the link events they write into $streams, $et- and $ce-. Resolving those
	// links yields the same original event again, once per projection, and the
	// filter matches on the resolved stream name — so every event is delivered
	// FOUR times, all with retryCount=0, and a reactor sends four emails.
	//
	// Verified against the running server: with it on, three appended events
	// produced twelve deliveries. Link resolution belongs on reads of link
	// streams ($ce-), never here.
	settings.ResolveLinkTos = false

	err := s.client.CreatePersistentSubscriptionToAll(ctx, group, kurrentdb.PersistentAllSubscriptionOptions{
		Settings:  &settings,
		StartFrom: kurrentdb.End{},
		Filter:    toFilter(filter),
	})
	if err == nil {
		return nil
	}

	var kerr *kurrentdb.Error
	if errors.As(err, &kerr) && kerr.Code() == kurrentdb.ErrorCodeResourceAlreadyExists {
		// The group exists and keeps the settings it was created with. That is
		// deliberate — silently reconfiguring a running reactor's redelivery
		// behaviour as a side effect of a deploy is worse than leaving it alone.
		//
		// What is NOT acceptable is leaving it alone in silence. Editing the
		// constants above changes nothing for any group that already exists, and
		// nothing anywhere reports that, so the code and the running server drift
		// apart with every deploy and only diverge further. Report it; changing
		// it stays a deliberate operator act.
		s.reportSettingsDrift(ctx, group, settings)
		return nil
	}
	return fmt.Errorf("kurrentdb: creating subscription group %q: %w", group, err)
}

// reportSettingsDrift logs where a live group differs from what this build would
// create.
//
// Best-effort by design: it runs on the startup path of every reactor, and a
// server that cannot answer must not stop the reactor from consuming.
func (s *Store) reportSettingsDrift(ctx context.Context, group string, want kurrentdb.PersistentSubscriptionSettings) {
	info, err := s.client.GetPersistentSubscriptionInfoToAll(ctx, group, kurrentdb.GetPersistentSubscriptionOptions{})
	if err != nil || info == nil || info.Settings == nil {
		return
	}
	live := *info.Settings

	var drift []any
	add := func(name string, live, want any) {
		if live != want {
			drift = append(drift, name, fmt.Sprintf("live=%v want=%v", live, want))
		}
	}
	add("max_retry_count", live.MaxRetryCount, want.MaxRetryCount)
	add("read_batch_size", live.ReadBatchSize, want.ReadBatchSize)
	add("history_buffer_size", live.HistoryBufferSize, want.HistoryBufferSize)
	// The one that is not a tuning knob: with link resolution on, every event
	// arrives once per system projection and a reactor sends four emails.
	add("resolve_link_tos", live.ResolveLinkTos, want.ResolveLinkTos)

	if len(drift) == 0 {
		return
	}
	slog.Default().Warn("persistent subscription settings differ from this build; the existing "+
		"group keeps its own and is NOT reconfigured automatically — delete and recreate it "+
		"deliberately if the change is wanted",
		append([]any{"group", group}, drift...)...)
}

// Consume runs a reactor against a server-managed subscription.
//
// The checkpoint belongs to the SERVER here, which is the whole point of using
// a different transport from projectors: there is no rebuild API to call by
// accident, so "reactors are never replayed" is structural rather than a
// convention someone has to remember (ADR-019).
//
// Handler outcomes:
//   - nil          → Ack. The event is done and will not be seen again.
//   - any error    → Nack(Retry). The server redelivers with backoff, and parks
//     the event after MaxRetryCount attempts.
//   - ErrPoison    → Nack(Park) immediately. For events this reactor can never
//     handle, where retrying is pure noise.
func (s *Store) Consume(
	ctx context.Context,
	group string,
	filter eventsourcing.SubscriptionFilter,
	h eventsourcing.Handler,
) error {
	if err := s.EnsureGroup(ctx, group, filter); err != nil {
		return err
	}

	sub, err := s.client.SubscribeToPersistentSubscriptionToAll(ctx, group,
		kurrentdb.SubscribeToPersistentSubscriptionOptions{BufferSize: reactorBuffer})
	if err != nil {
		return fmt.Errorf("kurrentdb: subscribing to group %q: %w", group, err)
	}
	defer func() { _ = sub.Close() }()

	for {
		ev := sub.Recv()
		switch {
		case ctx.Err() != nil:
			return ctx.Err()

		case ev == nil:
			return ErrSubscriptionClosed

		case ev.SubscriptionDropped != nil:
			return fmt.Errorf("kurrentdb: group %q dropped: %w", group, ev.SubscriptionDropped.Error)

		case ev.CheckPointReached != nil:
			continue

		case ev.EventAppeared != nil:
			resolved := ev.EventAppeared.Event
			if resolved == nil || resolved.Event == nil {
				continue
			}
			if rec := toRecorded(resolved.Event); rec.IsSystem() {
				// Ack rather than skip: an unacked system event would be
				// redelivered forever and eventually park.
				_ = sub.Ack(resolved)
			} else if err := h(ctx, rec); err != nil {
				if nackErr := s.nack(sub, resolved, err); nackErr != nil {
					return nackErr
				}
			} else if err := sub.Ack(resolved); err != nil {
				return fmt.Errorf("kurrentdb: acking in group %q: %w", group, err)
			}
		}
	}
}

func (s *Store) nack(
	sub *kurrentdb.PersistentSubscription, resolved *kurrentdb.ResolvedEvent, cause error,
) error {
	action := kurrentdb.NackActionRetry
	if errors.Is(cause, eventsourcing.ErrPoison) {
		action = kurrentdb.NackActionPark
	}
	if err := sub.Nack(cause.Error(), action, resolved); err != nil {
		return fmt.Errorf("kurrentdb: nacking: %w", err)
	}
	return nil
}

// ReplayParked returns parked events to the live queue.
//
// The operator action after fixing whatever caused the parking. Deliberately
// explicit and deliberately not automatic: parked events are the ones that
// already failed every retry, and replaying them without understanding why is
// how an outage repeats itself.
func (s *Store) ReplayParked(ctx context.Context, group string, stopAt int) error {
	if err := s.client.ReplayParkedMessagesToAll(ctx, group,
		kurrentdb.ReplayParkedMessagesOptions{StopAt: stopAt}); err != nil {
		return fmt.Errorf("kurrentdb: replaying parked messages for %q: %w", group, err)
	}
	return nil
}

// GroupStats reports what a reactor's queue looks like: how far behind it is and
// how many events it has given up on.
func (s *Store) GroupStats(ctx context.Context, group string) (eventsourcing.GroupStats, error) {
	info, err := s.client.GetPersistentSubscriptionInfoToAll(ctx, group,
		kurrentdb.GetPersistentSubscriptionOptions{})
	if err != nil {
		return eventsourcing.GroupStats{}, fmt.Errorf("kurrentdb: reading group %q: %w", group, err)
	}

	out := eventsourcing.GroupStats{Group: group}
	if info.Stats != nil {
		out.InFlight = info.Stats.LiveBufferCount
		out.Unacked = info.Stats.TotalInFlightMessages
		out.Parked = info.Stats.ParkedMessagesCount
		out.ProcessedSinceLast = info.Stats.CountSinceLastMeasurement
	}
	return out, nil
}
