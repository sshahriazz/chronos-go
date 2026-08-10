//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// A reactor consumes through a SERVER-managed subscription, which is what makes
// "reactors are never replayed" structural: there is no client checkpoint to
// rewind.
//
// The exactly-once assertion at the end is a regression guard with a specific
// history. With the system projections running, $all carries the link events
// that $streams, $et- and $ce- write. Turning on ResolveLinkTos resolves each
// of those links back to the SAME original event, and since the filter matches
// the resolved stream name, every event arrives four times with retryCount=0 —
// four welcome emails. Measured: three appends produced twelve deliveries.
func TestPersistentSubscriptionDelivers(t *testing.T) {
	store, _, sfx := snapHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cat := eventsourcing.Category("react" + sfx)
	group := "grp_" + sfx
	filter := eventsourcing.SubscriptionFilter{StreamPrefixes: []string{string(cat) + "-"}}

	// The group must exist before the events, or they land before its start
	// position and are never delivered — a new reactor starts at the END of the
	// log on purpose (ADR-019).
	if err := store.EnsureGroup(ctx, group, filter); err != nil {
		t.Fatalf("ensure group: %v", err)
	}
	// EnsureGroup is idempotent; a redeploy must not disturb a running reactor.
	if err := store.EnsureGroup(ctx, group, filter); err != nil {
		t.Fatalf("ensure group is not idempotent: %v", err)
	}

	const total = 5
	for i := range total {
		stream, _ := eventsourcing.NewStreamID(cat, "s"+hex.EncodeToString([]byte{byte(i)}))
		if _, err := store.Append(ctx, stream, eventsourcing.AnyRevision(),
			[]eventsourcing.PendingEvent{{
				ID:    eventsourcing.DeriveEventID(sfx+"react", i),
				Event: &Joined{Member: "m"},
				Meta:  eventsourcing.Metadata{OccurredAt: time.Now().UTC()},
			}}); err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
	}

	var mu sync.Mutex
	seen := map[string]int{}
	done := make(chan struct{})

	consumeCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		_ = store.Consume(consumeCtx, group, filter, func(_ context.Context, e eventsourcing.RecordedEvent) error {
			mu.Lock()
			seen[e.ID.String()]++
			n := len(seen)
			mu.Unlock()
			if n == total {
				select {
				case <-done:
				default:
					close(done)
				}
			}
			return nil
		})
	}()

	select {
	case <-done:
	case <-ctx.Done():
		mu.Lock()
		got := len(seen)
		mu.Unlock()
		t.Fatalf("received %d of %d events before timing out", got, total)
	}
	stop()

	mu.Lock()
	defer mu.Unlock()
	for id, n := range seen {
		if n != 1 {
			t.Errorf("event %s delivered %d times within one run", id, n)
		}
	}
}

// A poisonous event is parked immediately rather than retried ten times.
func TestPersistentSubscriptionParksPoison(t *testing.T) {
	store, _, sfx := snapHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cat := eventsourcing.Category("poison" + sfx)
	group := "grp_poison_" + sfx
	filter := eventsourcing.SubscriptionFilter{StreamPrefixes: []string{string(cat) + "-"}}

	if err := store.EnsureGroup(ctx, group, filter); err != nil {
		t.Fatalf("ensure group: %v", err)
	}

	stream, _ := eventsourcing.NewStreamID(cat, "s1")
	if _, err := store.Append(ctx, stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID:    eventsourcing.DeriveEventID(sfx+"poison", 0),
			Event: &Joined{Member: "m"},
			Meta:  eventsourcing.Metadata{OccurredAt: time.Now().UTC()},
		}}); err != nil {
		t.Fatalf("append: %v", err)
	}

	var attempts int
	var mu sync.Mutex
	consumeCtx, stop := context.WithTimeout(ctx, 12*time.Second)
	defer stop()
	go func() {
		_ = store.Consume(consumeCtx, group, filter, func(context.Context, eventsourcing.RecordedEvent) error {
			mu.Lock()
			attempts++
			mu.Unlock()
			return eventsourcing.ErrPoison
		})
	}()

	deadline := time.After(20 * time.Second)
	for {
		stats, err := store.GroupStats(ctx, group)
		if err == nil && stats.Parked > 0 {
			mu.Lock()
			n := attempts
			mu.Unlock()
			if n > 3 {
				t.Errorf("poison was retried %d times; it should park on the first failure", n)
			}
			return
		}
		select {
		case <-deadline:
			mu.Lock()
			n := attempts
			mu.Unlock()
			t.Fatalf("event never parked after %d attempts", n)
		case <-time.After(500 * time.Millisecond):
		}
	}
}
