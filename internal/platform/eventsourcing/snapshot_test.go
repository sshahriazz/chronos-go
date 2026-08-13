package eventsourcing_test

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// ---------------------------------------------------------------------------
// a realistic aggregate: order matters, and some events undo others
// ---------------------------------------------------------------------------

type memberAdded struct{ Name string }
type memberRemoved struct{ Name string }
type renamed struct{ Title string }

func (*memberAdded) EventType() string   { return "test.MemberAdded.v1" }
func (*memberRemoved) EventType() string { return "test.MemberRemoved.v1" }
func (*renamed) EventType() string       { return "test.Renamed.v1" }

// team state is order-sensitive on purpose: a snapshot that drops or reorders
// anything produces a different answer, which is what the equivalence test is
// looking for.
type team struct {
	eventsourcing.Base
	Title   string
	Members []string
}

func newTeam() *team { return &team{} }

func (t *team) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *memberAdded:
		t.Members = append(t.Members, ev.Name)
	case *memberRemoved:
		for i, m := range t.Members {
			if m == ev.Name {
				t.Members = append(t.Members[:i], t.Members[i+1:]...)
				break
			}
		}
	case *renamed:
		t.Title = ev.Title
	case *teamSnapshot:
		t.Title = ev.Title
		t.Members = append([]string(nil), ev.Members...)
	}
}

// teamSnapshot is a plain domain struct — no wire tags, like every other event.
type teamSnapshot struct {
	Title   string
	Members []string
}

func (*teamSnapshot) EventType() string { return "test.TeamSnapshot.v1" }

func (t *team) Snapshot() eventsourcing.Event {
	return &teamSnapshot{Title: t.Title, Members: append([]string(nil), t.Members...)}
}

func (t *team) Restore(e eventsourcing.Event) error {
	snap, ok := e.(*teamSnapshot)
	if !ok {
		return fmt.Errorf("test: %T is not a team snapshot", e)
	}
	t.Title = snap.Title
	t.Members = append([]string(nil), snap.Members...)
	return nil
}

// brokenRestore refuses every snapshot, standing in for an aggregate whose
// snapshot schema changed underneath it.
type brokenTeam struct{ team }

func (b *brokenTeam) Restore(eventsourcing.Event) error {
	return errors.New("test: this snapshot is from an older schema")
}

// ---------------------------------------------------------------------------
// THE test: a snapshot may change how long a load takes, never what it returns
// ---------------------------------------------------------------------------

func TestSnapshotLoadEqualsFullReplay(t *testing.T) {
	// Seeded, so a failure is reproducible. 60 trials of up to 250 events each
	// is ~9,000 load/save round trips through the repository — enough to catch
	// an ordering or off-by-one bug (both were caught by mutation testing)
	// without the race detector making this the slowest test in the suite.
	rng := rand.New(rand.NewPCG(42, 1))

	for trial := range 60 {
		events := randomHistory(rng, 1+rng.IntN(250))

		withSnap := loadTeam(t, events, true)
		withoutSnap := loadTeam(t, events, false)

		if withSnap.Title != withoutSnap.Title {
			t.Fatalf("trial %d: title differs — snapshot %q, replay %q",
				trial, withSnap.Title, withoutSnap.Title)
		}
		if len(withSnap.Members) != len(withoutSnap.Members) {
			t.Fatalf("trial %d: %d members from snapshot, %d from replay (history of %d events)",
				trial, len(withSnap.Members), len(withoutSnap.Members), len(events))
		}
		for i := range withSnap.Members {
			if withSnap.Members[i] != withoutSnap.Members[i] {
				t.Fatalf("trial %d: member %d differs — snapshot %q, replay %q",
					trial, i, withSnap.Members[i], withoutSnap.Members[i])
			}
		}
		// Loading from a snapshot must not lose the concurrency precondition:
		// the aggregate has to report the revision it ACTUALLY reached, not the
		// snapshot's.
		if withSnap.Version() != withoutSnap.Version() {
			t.Fatalf("trial %d: version %d from snapshot, %d from replay — "+
				"the append precondition would be wrong and a concurrent write could be lost",
				trial, withSnap.Version(), withoutSnap.Version())
		}
	}
}

func randomHistory(rng *rand.Rand, n int) []eventsourcing.Event {
	out := make([]eventsourcing.Event, 0, n)
	var live []string
	for i := range n {
		switch {
		case len(live) > 0 && rng.IntN(3) == 0:
			victim := live[rng.IntN(len(live))]
			out = append(out, &memberRemoved{Name: victim})
			for j, m := range live {
				if m == victim {
					live = append(live[:j], live[j+1:]...)
					break
				}
			}
		case rng.IntN(5) == 0:
			out = append(out, &renamed{Title: fmt.Sprintf("title-%d", i)})
		default:
			name := fmt.Sprintf("member-%d", i)
			out = append(out, &memberAdded{Name: name})
			live = append(live, name)
		}
	}
	return out
}

// loadTeam writes a history through a repository, then loads it back — with
// snapshots enabled or not.
func loadTeam(t *testing.T, events []eventsourcing.Event, snapshots bool) *team {
	t.Helper()
	store := newMemStore()
	opts := []eventsourcing.Option{}
	if snapshots {
		// A small interval so a few hundred events cross it many times.
		opts = append(opts, eventsourcing.WithSnapshots(store, 10))
	}
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "team", newTeam, opts...)

	ctx := context.Background()
	for i, e := range events {
		agg, err := repo.Load(ctx, "t1")
		if err != nil {
			t.Fatalf("load: %v", err)
		}
		eventsourcing.Record(agg, e)
		if _, err := repo.Save(ctx, "t1", agg, fmt.Sprintf("cmd-%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatalf("save: %v", err)
		}
	}

	final, err := repo.Load(ctx, "t1")
	if err != nil {
		t.Fatalf("final load: %v", err)
	}
	return final
}

// ---------------------------------------------------------------------------
// degrading to slow is allowed; degrading to wrong is not
// ---------------------------------------------------------------------------

func TestUnrestorableSnapshotFallsBackToReplay(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "team", newTeam,
		eventsourcing.WithSnapshots(store, 5))

	ctx := context.Background()
	for i := range 20 {
		agg, _ := repo.Load(ctx, "t1")
		eventsourcing.Record(agg, &memberAdded{Name: fmt.Sprintf("m%d", i)})
		if _, err := repo.Save(ctx, "t1", agg, fmt.Sprintf("c%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.snapshots) == 0 {
		t.Fatal("no snapshot was written, so this proves nothing")
	}

	// Same history, but the aggregate now rejects every snapshot.
	var failures int
	broken := eventsourcing.NewRepository(store, memCodec{}, nil, "team",
		func() *brokenTeam { return &brokenTeam{} },
		eventsourcing.WithSnapshots(store, 5),
		eventsourcing.OnSnapshotError(func(eventsourcing.StreamID, error) { failures++ }))

	agg, err := broken.Load(ctx, "t1")
	if err != nil {
		t.Fatalf("a rejected snapshot must not fail the load: %v", err)
	}
	if failures == 0 {
		t.Error("the rejection was not reported; a silently ignored snapshot is invisible in production")
	}
	if len(agg.Members) != 20 {
		t.Fatalf("fell back to replay but got %d members, want 20", len(agg.Members))
	}
	if agg.Version() != 19 {
		t.Fatalf("version %d after fallback, want 19", agg.Version())
	}
}

func TestUndecodableSnapshotFallsBackToReplay(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "team", newTeam,
		eventsourcing.WithSnapshots(store, 5))

	ctx := context.Background()
	for i := range 12 {
		agg, _ := repo.Load(ctx, "t1")
		eventsourcing.Record(agg, &memberAdded{Name: fmt.Sprintf("m%d", i)})
		if _, err := repo.Save(ctx, "t1", agg, fmt.Sprintf("c%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatal(err)
		}
	}

	// Corrupt every stored snapshot, as a retired event type would look.
	for k, rec := range store.snapshots {
		rec.Type = "test.SomeTypeWeNoLongerHave.v1"
		store.snapshots[k] = rec
	}

	agg, err := repo.Load(ctx, "t1")
	if err != nil {
		t.Fatalf("an undecodable snapshot must not fail the load: %v", err)
	}
	if len(agg.Members) != 12 {
		t.Fatalf("got %d members, want 12", len(agg.Members))
	}
}

// A snapshot is an optimisation. Failing to write one must not fail the command
// whose events are already durable.
func TestSnapshotWriteFailureDoesNotFailSave(t *testing.T) {
	store := newMemStore()
	store.failSnapshotWrites = true

	var reported int
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "team", newTeam,
		eventsourcing.WithSnapshots(store, 2),
		eventsourcing.OnSnapshotError(func(eventsourcing.StreamID, error) { reported++ }))

	ctx := context.Background()
	for i := range 6 {
		agg, _ := repo.Load(ctx, "t1")
		eventsourcing.Record(agg, &memberAdded{Name: fmt.Sprintf("m%d", i)})
		if _, err := repo.Save(ctx, "t1", agg, fmt.Sprintf("c%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatalf("a failed snapshot must not fail the append: %v", err)
		}
	}
	if reported == 0 {
		t.Error("snapshot write failures were never reported")
	}

	agg, err := repo.Load(ctx, "t1")
	if err != nil {
		t.Fatal(err)
	}
	if len(agg.Members) != 6 {
		t.Fatalf("got %d members, want 6 — the events themselves must be unaffected", len(agg.Members))
	}
}

// An aggregate that does not implement Snapshotter must be unaffected by a
// repository configured with snapshots.
func TestAggregateWithoutSnapshotterIsUnaffected(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "plain", newPlain,
		eventsourcing.WithSnapshots(store, 2))

	ctx := context.Background()
	for i := range 8 {
		agg, _ := repo.Load(ctx, "p1")
		eventsourcing.Record(agg, &memberAdded{Name: fmt.Sprintf("m%d", i)})
		if _, err := repo.Save(ctx, "p1", agg, fmt.Sprintf("c%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatal(err)
		}
	}
	if len(store.snapshots) != 0 {
		t.Fatalf("wrote %d snapshots for an aggregate that cannot restore them", len(store.snapshots))
	}
	agg, _ := repo.Load(ctx, "p1")
	if agg.Count != 8 {
		t.Fatalf("count %d, want 8", agg.Count)
	}
}

type plain struct {
	eventsourcing.Base
	Count int
}

func newPlain() *plain { return &plain{} }

func (p *plain) Apply(eventsourcing.Event) { p.Count++ }

func TestSnapshotCadence(t *testing.T) {
	store := newMemStore()
	repo := eventsourcing.NewRepository(store, memCodec{}, nil, "team", newTeam,
		eventsourcing.WithSnapshots(store, 10))

	ctx := context.Background()
	for i := range 100 {
		agg, _ := repo.Load(ctx, "t1")
		eventsourcing.Record(agg, &memberAdded{Name: fmt.Sprintf("m%d", i)})
		if _, err := repo.Save(ctx, "t1", agg, fmt.Sprintf("c%d", i), eventsourcing.Metadata{}); err != nil {
			t.Fatal(err)
		}
	}
	// Revisions 0..99; a snapshot each time the revision crosses a multiple of
	// 10, so at 10, 20 … 90 — nine of them.
	if got := store.snapshotWrites; got != 9 {
		t.Errorf("wrote %d snapshots over 100 events with interval 10, want 9", got)
	}
	if len(store.snapshots) != 1 {
		t.Errorf("kept %d snapshots; each write must replace the last", len(store.snapshots))
	}
}

func TestSnapshotStreamNaming(t *testing.T) {
	s, err := eventsourcing.SnapshotStreamID("organization", "org_123")
	if err != nil {
		t.Fatal(err)
	}
	if got := string(s); got != "organizationSnapshot-org_123" {
		t.Fatalf("snapshot stream %q", got)
	}
	// A projector filtering the aggregate category must NOT pick up snapshots.
	if hasPrefix(string(s), "organization-") {
		t.Fatal("the snapshot stream matches the aggregate's own prefix filter, " +
			"so every projector would be handed snapshots as if they were history")
	}
}

func hasPrefix(s, p string) bool { return len(s) >= len(p) && s[:len(p)] == p }

// ---------------------------------------------------------------------------
// in-memory store
// ---------------------------------------------------------------------------

type memStore struct {
	streams            map[eventsourcing.StreamID][]eventsourcing.RecordedEvent
	snapshots          map[eventsourcing.StreamID]eventsourcing.RecordedEvent
	snapshotWrites     int
	failSnapshotWrites bool
}

func newMemStore() *memStore {
	return &memStore{
		streams:   map[eventsourcing.StreamID][]eventsourcing.RecordedEvent{},
		snapshots: map[eventsourcing.StreamID]eventsourcing.RecordedEvent{},
	}
}

func (m *memStore) Append(
	_ context.Context, stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision, events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	existing := m.streams[stream]
	if rev, ok := expected.Exact(); ok && rev != eventsourcing.Revision(len(existing))-1 {
		return eventsourcing.AppendResult{}, eventsourcing.ErrWrongExpectedRevision
	}
	for _, pe := range events {
		payload, _ := memCodec{}.Marshal(pe.Event)
		meta, _ := memCodec{}.MarshalMetadata(pe.Meta)
		existing = append(existing, eventsourcing.RecordedEvent{
			ID: pe.ID, Type: pe.Event.EventType(), Stream: stream,
			Revision: eventsourcing.Revision(len(existing)),
			Payload:  payload, Metadata: meta,
		})
	}
	m.streams[stream] = existing
	return eventsourcing.AppendResult{Revision: eventsourcing.Revision(len(existing) - 1)}, nil
}

func (m *memStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	all, ok := m.streams[stream]
	if !ok {
		return nil, eventsourcing.ErrStreamNotFound
	}
	if int(from) >= len(all) {
		return nil, nil
	}
	return all[from:], nil
}

func (m *memStore) LoadSnapshot(
	_ context.Context, stream eventsourcing.StreamID,
) (eventsourcing.RecordedEvent, bool, error) {
	rec, ok := m.snapshots[stream]
	return rec, ok, nil
}

func (m *memStore) SaveSnapshot(
	_ context.Context, stream eventsourcing.StreamID, e eventsourcing.PendingEvent,
) error {
	if m.failSnapshotWrites {
		return errors.New("mem: snapshot store is down")
	}
	payload, err := memCodec{}.Marshal(e.Event)
	if err != nil {
		return err
	}
	meta, _ := memCodec{}.MarshalMetadata(e.Meta)
	m.snapshotWrites++
	// $maxCount = 1 in the real store; one entry here.
	m.snapshots[stream] = eventsourcing.RecordedEvent{
		ID: e.ID, Type: e.Event.EventType(), Stream: stream,
		Payload: payload, Metadata: meta,
	}
	return nil
}

// memCodec mirrors the real codec closely enough that a snapshot round trips
// through serialization rather than being handed back as the same pointer —
// otherwise the equivalence test would pass on aliasing alone.
type memCodec struct{}

func (memCodec) Marshal(e eventsourcing.Event) ([]byte, error) { return codec.Marshal(e) }

func (memCodec) Unmarshal(eventType string, payload []byte) (eventsourcing.Event, error) {
	var e eventsourcing.Event
	switch eventType {
	case "test.MemberAdded.v1":
		e = &memberAdded{}
	case "test.MemberRemoved.v1":
		e = &memberRemoved{}
	case "test.Renamed.v1":
		e = &renamed{}
	case "test.TeamSnapshot.v1":
		e = &teamSnapshot{}
	default:
		return nil, fmt.Errorf("mem: unknown type %q", eventType)
	}
	// TOLERANT, because the real codec is: a payload comes off an append-only
	// log and may carry a newer producer's fields (ADR-029). A double that was
	// stricter than the thing it stands in for would pass on payloads the real
	// system rejects, and fail on ones it accepts.
	if err := codec.IntoTolerant(payload, e); err != nil {
		return nil, err
	}
	return e, nil
}

func (memCodec) MarshalMetadata(m eventsourcing.Metadata) ([]byte, error) {
	return codec.Marshal(map[string]any{"snapshotRevision": int64(m.SnapshotRevision)})
}

func (memCodec) UnmarshalMetadata(b []byte) (eventsourcing.Metadata, error) {
	if len(b) == 0 {
		return eventsourcing.Metadata{}, nil
	}
	// Tolerant for the same reason as the payload above: stored metadata gains
	// keys over time, and the real codec reads them all.
	w, err := codec.Tolerant[struct {
		SnapshotRevision int64 `json:"snapshotRevision"`
	}](b)
	if err != nil {
		return eventsourcing.Metadata{}, err
	}
	return eventsourcing.Metadata{SnapshotRevision: eventsourcing.Revision(w.SnapshotRevision)}, nil
}

// ---------------------------------------------------------------------------
// filter → category resolution, which decides how a rebuild reads the log
// ---------------------------------------------------------------------------

func TestSubscriptionFilterCategories(t *testing.T) {
	cases := []struct {
		name   string
		filter eventsourcing.SubscriptionFilter
		want   []eventsourcing.Category
		ok     bool
	}{
		{
			name:   "one whole category",
			filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"organization-"}},
			want:   []eventsourcing.Category{"organization"}, ok: true,
		},
		{
			name:   "several whole categories",
			filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"organization-", "workspace-"}},
			want:   []eventsourcing.Category{"organization", "workspace"}, ok: true,
		},
		{
			// "org" would also match "organization-..." — a partial prefix is
			// not a category, and treating it as one would rebuild from the
			// wrong stream set.
			name:   "partial prefix is not a category",
			filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"organiz"}},
			ok:     false,
		},
		{
			name:   "event type filters cannot resolve to categories",
			filter: eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{"identity."}},
			ok:     false,
		},
		{
			name:   "no filter",
			filter: eventsourcing.SubscriptionFilter{},
			ok:     false,
		},
		{
			name:   "system streams are never a category",
			filter: eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"$ce-"}},
			ok:     false,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, ok := tc.filter.Categories()
			if ok != tc.ok {
				t.Fatalf("ok=%v want %v (got %v)", ok, tc.ok, got)
			}
			if !ok {
				return
			}
			if len(got) != len(tc.want) {
				t.Fatalf("got %v want %v", got, tc.want)
			}
			for i := range got {
				if got[i] != tc.want[i] {
					t.Fatalf("got %v want %v", got, tc.want)
				}
			}
		})
	}
}
