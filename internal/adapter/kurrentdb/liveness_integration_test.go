//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/google/uuid"
)

// The projector's readiness gate depends on the server emitting CaughtUp. If it
// never does, /readyz reports 503 forever and the deployment never comes up —
// a self-inflicted outage caused by a feature meant to prevent one.
//
// So this asserts the signal actually arrives from the real server, on a
// FILTERED $all subscription, which is the only shape we use.
func TestServerReportsCaughtUp(t *testing.T) {
	store, _, sfx := snapHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	cat := eventsourcing.Category("live" + sfx)
	stream, _ := eventsourcing.NewStreamID(cat, "s1")
	if _, err := store.Append(ctx, stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID:    eventsourcing.DeriveEventID(sfx+"live", 0),
			Event: &Joined{Member: "m"},
			Meta:  eventsourcing.Metadata{OccurredAt: time.Now().UTC()},
		}}); err != nil {
		t.Fatalf("append: %v", err)
	}

	var live atomic.Bool
	caughtUp := make(chan struct{})
	var once atomic.Bool

	subCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		_ = store.SubscribeAll(subCtx, eventsourcing.FromBeginning(),
			eventsourcing.SubscribeOptions{
				Filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{string(cat) + "-"}},
				OnLive: func(context.Context) error {
					live.Store(true)
					if once.CompareAndSwap(false, true) {
						close(caughtUp)
					}
					return nil
				},
			},
			func(context.Context, eventsourcing.RecordedEvent) error { return nil })
	}()

	select {
	case <-caughtUp:
		if !live.Load() {
			t.Fatal("OnLive fired but the flag was not set")
		}
	case <-ctx.Done():
		t.Fatal("the server never reported CaughtUp on a filtered $all subscription — " +
			"the readiness gate in cmd/projector would report 503 forever")
	}
}

// Unfiltered too, since a projection may declare no filter.
func TestServerReportsCaughtUpUnfiltered(t *testing.T) {
	store, _, _ := snapHarness(t)
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()

	raw := uuid.New()
	_ = hex.EncodeToString(raw[:2])

	caughtUp := make(chan struct{})
	var once atomic.Bool

	subCtx, stop := context.WithCancel(ctx)
	defer stop()
	go func() {
		_ = store.SubscribeAll(subCtx, eventsourcing.FromBeginning(),
			eventsourcing.SubscribeOptions{
				OnLive: func(context.Context) error {
					if once.CompareAndSwap(false, true) {
						close(caughtUp)
					}
					return nil
				},
			},
			func(context.Context, eventsourcing.RecordedEvent) error { return nil })
	}()

	select {
	case <-caughtUp:
	case <-ctx.Done():
		t.Fatal("no CaughtUp on an unfiltered $all subscription")
	}
}
