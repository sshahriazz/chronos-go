//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"fmt"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	adapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/google/uuid"
)

// ---------------------------------------------------------------------------
// aggregate under test
// ---------------------------------------------------------------------------

type Joined struct{ Member string }

func (*Joined) EventType() string { return "snaptest.Joined.v1" }

type RosterSnapshot struct{ Members []string }

func (*RosterSnapshot) EventType() string { return "snaptest.RosterSnapshot.v1" }

type roster struct {
	eventsourcing.Base
	Members []string
}

func newRoster() *roster { return &roster{} }

func (r *roster) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *Joined:
		r.Members = append(r.Members, ev.Member)
	case *RosterSnapshot:
		r.Members = append([]string(nil), ev.Members...)
	}
}

func (r *roster) Snapshot() eventsourcing.Event {
	return &RosterSnapshot{Members: append([]string(nil), r.Members...)}
}

func (r *roster) Restore(e eventsourcing.Event) error {
	s, ok := e.(*RosterSnapshot)
	if !ok {
		return fmt.Errorf("not a roster snapshot: %T", e)
	}
	r.Members = append([]string(nil), s.Members...)
	return nil
}

func snapHarness(t testing.TB) (*adapter.Store, *eventcodec.JSON, string) {
	t.Helper()
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	eventcodec.Register[Joined](codec)
	eventcodec.Register[RosterSnapshot](codec)

	client, err := adapter.Dial("kurrentdb://localhost:2113?tls=false")
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })

	raw := uuid.New()
	return adapter.NewStore(client, codec), codec, hex.EncodeToString(raw[:4])
}

// ---------------------------------------------------------------------------

func TestSnapshotRoundTripThroughKurrentDB(t *testing.T) {
	store, codec, sfx := snapHarness(t)
	ctx := context.Background()
	repo := eventsourcing.NewRepository(store, codec, nil, eventsourcing.Category("roster"+sfx), newRoster,
		eventsourcing.WithSnapshots(store, 10),
		eventsourcing.OnSnapshotError(func(s eventsourcing.StreamID, err error) {
			t.Errorf("snapshot problem on %s: %v", s, err)
		}))

	const total = 35
	for i := range total {
		agg, err := repo.Load(ctx, "r1")
		if err != nil {
			t.Fatalf("load %d: %v", i, err)
		}
		eventsourcing.Record(agg, &Joined{Member: fmt.Sprintf("m%02d", i)})
		if _, err := repo.Save(ctx, "r1", agg, fmt.Sprintf("%s-cmd-%d", sfx, i), eventsourcing.Metadata{}); err != nil {
			t.Fatalf("save %d: %v", i, err)
		}
	}

	agg, err := repo.Load(ctx, "r1")
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	if len(agg.Members) != total {
		t.Fatalf("loaded %d members, want %d", len(agg.Members), total)
	}
	for i, m := range agg.Members {
		if want := fmt.Sprintf("m%02d", i); m != want {
			t.Fatalf("member %d is %q, want %q — snapshot and replay were stitched in the wrong order", i, m, want)
		}
	}
	if agg.Version() != total-1 {
		t.Errorf("version %d, want %d", agg.Version(), total-1)
	}

	// The snapshot stream must be self-bounding, or it grows forever and the
	// cheap backwards read sits on a pile of dead state.
	snapStream, _ := eventsourcing.SnapshotStreamID(eventsourcing.Category("roster"+sfx), "r1")
	ret, err := store.Retention(ctx, snapStream)
	if err != nil {
		t.Fatalf("retention: %v", err)
	}
	if ret.MaxCount != 1 {
		t.Errorf("snapshot stream $maxCount is %d, want 1", ret.MaxCount)
	}
}

// Without snapshots the same history must load identically — the property that
// makes snapshots safe to turn off, or to lose entirely.
func TestSnapshotIsOptionalAndEquivalent(t *testing.T) {
	store, codec, sfx := snapHarness(t)
	ctx := context.Background()
	cat := eventsourcing.Category("roster" + sfx)

	writer := eventsourcing.NewRepository(store, codec, nil, cat, newRoster,
		eventsourcing.WithSnapshots(store, 5))
	for i := range 23 {
		agg, _ := writer.Load(ctx, "r1")
		eventsourcing.Record(agg, &Joined{Member: fmt.Sprintf("m%02d", i)})
		if _, err := writer.Save(ctx, "r1", agg, fmt.Sprintf("%s-c-%d", sfx, i), eventsourcing.Metadata{}); err != nil {
			t.Fatal(err)
		}
	}

	withSnap, err := writer.Load(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}
	// A repository that knows nothing about snapshots replays the stream.
	plain := eventsourcing.NewRepository(store, codec, nil, cat, newRoster)
	withoutSnap, err := plain.Load(ctx, "r1")
	if err != nil {
		t.Fatal(err)
	}

	if len(withSnap.Members) != len(withoutSnap.Members) {
		t.Fatalf("snapshot load gave %d members, replay gave %d",
			len(withSnap.Members), len(withoutSnap.Members))
	}
	for i := range withSnap.Members {
		if withSnap.Members[i] != withoutSnap.Members[i] {
			t.Fatalf("member %d differs: %q vs %q", i, withSnap.Members[i], withoutSnap.Members[i])
		}
	}
	if withSnap.Version() != withoutSnap.Version() {
		t.Fatalf("version %d vs %d", withSnap.Version(), withoutSnap.Version())
	}
}

func TestStreamRetention(t *testing.T) {
	store, _, sfx := snapHarness(t)
	ctx := context.Background()
	stream := eventsourcing.StreamID("retention" + sfx + "-s1")

	if _, err := store.Append(ctx, stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID: eventsourcing.DeriveEventID(sfx, 0), Event: &Joined{Member: "a"},
			Meta: eventsourcing.Metadata{OccurredAt: time.Now().UTC()},
		}}); err != nil {
		t.Fatalf("append: %v", err)
	}

	// A stream with no policy reports the zero value, not an error.
	if ret, err := store.Retention(ctx, stream); err != nil {
		t.Fatalf("reading absent retention: %v", err)
	} else if !ret.IsZero() {
		t.Fatalf("expected no policy, got %+v", ret)
	}

	want := eventsourcing.Retention{MaxCount: 50, MaxAge: 72 * time.Hour, TruncateBefore: 3}
	if err := store.SetRetention(ctx, stream, want); err != nil {
		t.Fatalf("set: %v", err)
	}
	got, err := store.Retention(ctx, stream)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.MaxCount != want.MaxCount {
		t.Errorf("MaxCount %d, want %d", got.MaxCount, want.MaxCount)
	}
	if got.MaxAge != want.MaxAge {
		t.Errorf("MaxAge %v, want %v", got.MaxAge, want.MaxAge)
	}
	if got.TruncateBefore != want.TruncateBefore {
		t.Errorf("TruncateBefore %d, want %d", got.TruncateBefore, want.TruncateBefore)
	}
}

// ---------------------------------------------------------------------------
// the number that justifies the whole mechanism
// ---------------------------------------------------------------------------

func benchmarkLoad(b *testing.B, events int, snapshots bool) {
	store, codec, sfx := snapHarness(b)
	ctx := context.Background()
	cat := eventsourcing.Category("bench" + sfx)

	opts := []eventsourcing.Option{}
	if snapshots {
		opts = append(opts, eventsourcing.WithSnapshots(store, eventsourcing.SnapshotEvery))
	}
	repo := eventsourcing.NewRepository(store, codec, nil, cat, newRoster, opts...)

	// Seed one aggregate with `events` events, in batches so setup is not the
	// dominant cost of the benchmark.
	agg, _ := repo.Load(ctx, "b1")
	for i := range events {
		eventsourcing.Record(agg, &Joined{Member: fmt.Sprintf("m%05d", i)})
	}
	if _, err := repo.Save(ctx, "b1", agg, sfx+"-seed", eventsourcing.Metadata{}); err != nil {
		b.Fatalf("seed: %v", err)
	}
	if snapshots {
		// Force a snapshot at the head, which is the steady state a long-lived
		// aggregate is in.
		cur, _ := repo.Load(ctx, "b1")
		eventsourcing.Record(cur, &Joined{Member: "tip"})
		if _, err := repo.Save(ctx, "b1", cur, sfx+"-tip", eventsourcing.Metadata{}); err != nil {
			b.Fatal(err)
		}
	}

	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		got, err := repo.Load(ctx, "b1")
		if err != nil {
			b.Fatalf("load: %v", err)
		}
		if len(got.Members) < events {
			b.Fatalf("loaded %d members, want at least %d", len(got.Members), events)
		}
	}
}

func BenchmarkLoad1000EventsReplay(b *testing.B)   { benchmarkLoad(b, 1000, false) }
func BenchmarkLoad1000EventsSnapshot(b *testing.B) { benchmarkLoad(b, 1000, true) }
func BenchmarkLoad5000EventsReplay(b *testing.B)   { benchmarkLoad(b, 5000, false) }
func BenchmarkLoad5000EventsSnapshot(b *testing.B) { benchmarkLoad(b, 5000, true) }
