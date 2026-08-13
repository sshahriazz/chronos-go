package eventsourcing_test

import (
	"context"
	"testing"

	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---------------------------------------------------------------------------
// a store that keeps what it was handed, so the test can inspect metadata
// ---------------------------------------------------------------------------

type capturingStore struct{ appended []es.PendingEvent }

func (c *capturingStore) Append(
	_ context.Context, _ es.StreamID, _ es.ExpectedRevision, events []es.PendingEvent,
) (es.AppendResult, error) {
	c.appended = append(c.appended, events...)
	return es.AppendResult{Revision: es.Revision(len(c.appended) - 1)}, nil
}

func (c *capturingStore) ReadStream(
	context.Context, es.StreamID, es.Revision,
) ([]es.RecordedEvent, error) {
	return nil, es.ErrStreamNotFound
}

type traced struct{ N int }

func (*traced) EventType() string { return "test.Traced.v1" }

type tracedAggregate struct{ es.Base }

func (a *tracedAggregate) Apply(es.Event) {}

// raise appends through the aggregate so Save sees uncommitted events.
func (a *tracedAggregate) raise(n int) {
	for i := range n {
		es.Record(a, &traced{N: i})
	}
}

func saveTraced(ctx context.Context, t *testing.T, key string, meta es.Metadata, n int) []es.PendingEvent {
	t.Helper()
	store := &capturingStore{}
	repo := es.NewRepository(store, memCodec{}, nil, "traced",
		func() *tracedAggregate { return &tracedAggregate{} })

	agg, err := repo.Load(ctx, "t1")
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	agg.raise(n)
	if _, err := repo.Save(ctx, "t1", agg, key, meta); err != nil {
		t.Fatalf("save: %v", err)
	}
	return store.appended
}

// Every event must be traceable to what caused it. The log is append-only, so a
// correlation id missing at append time can never be added — which is why the
// repository fills it in rather than trusting each handler to remember.
func TestSaveAlwaysWritesACausationChain(t *testing.T) {
	events := saveTraced(context.Background(), t, "cmd-key-1", es.Metadata{}, 2)
	if len(events) != 2 {
		t.Fatalf("appended %d events, want 2", len(events))
	}
	for i, e := range events {
		if e.Meta.CorrelationID == "" {
			t.Errorf("event %d has no correlation id", i)
		}
		if e.Meta.CausationID == "" {
			t.Errorf("event %d has no causation id", i)
		}
	}
	// One command, one correlation id: the events it produced are one unit of
	// work and have to come out of the log together.
	if events[0].Meta.CorrelationID != events[1].Meta.CorrelationID {
		t.Errorf("two events of one command carry different correlation ids: %q and %q",
			events[0].Meta.CorrelationID, events[1].Meta.CorrelationID)
	}
	// A root event's cause is the command that produced it.
	if events[0].Meta.CausationID != "cmd-key-1" {
		t.Errorf("causation %q, want the command's idempotency key", events[0].Meta.CausationID)
	}
}

// A retried command must not open a second chain: the whole point of the
// derived event id is that a retry is the same write, and a trace that differed
// would make one command look like two in the log.
func TestTheChainIsDeterministicAcrossRetries(t *testing.T) {
	first := saveTraced(context.Background(), t, "cmd-key-2", es.Metadata{}, 1)
	again := saveTraced(context.Background(), t, "cmd-key-2", es.Metadata{}, 1)

	if first[0].Meta.CorrelationID != again[0].Meta.CorrelationID {
		t.Errorf("a retry produced a different correlation id: %q then %q",
			first[0].Meta.CorrelationID, again[0].Meta.CorrelationID)
	}
	if first[0].ID != again[0].ID {
		t.Errorf("a retry produced a different event id: %s then %s", first[0].ID, again[0].ID)
	}
}

// A write made while handling something inherits that something's chain.
func TestSaveInheritsTheTraceFromTheContext(t *testing.T) {
	ctx := es.WithTrace(context.Background(), es.Trace{
		CorrelationID: "corr-1", CausationID: "cause-1",
	})
	events := saveTraced(ctx, t, "cmd-key-3", es.Metadata{}, 1)

	if got := events[0].Meta.CorrelationID; got != "corr-1" {
		t.Errorf("correlation %q, want the context's corr-1", got)
	}
	if got := events[0].Meta.CausationID; got != "cause-1" {
		t.Errorf("causation %q, want the context's cause-1", got)
	}
}

// An explicit value beats the ambient context: a caller replaying or importing
// from another system knows the chain better than whatever it runs under.
func TestExplicitMetadataWinsOverTheContext(t *testing.T) {
	ctx := es.WithTrace(context.Background(), es.Trace{
		CorrelationID: "corr-1", CausationID: "cause-1",
	})
	events := saveTraced(ctx, t, "cmd-key-4",
		es.Metadata{CorrelationID: "explicit", CausationID: "explicit-cause"}, 1)

	if got := events[0].Meta.CorrelationID; got != "explicit" {
		t.Errorf("correlation %q, want the caller's explicit value", got)
	}
	if got := events[0].Meta.CausationID; got != "explicit-cause" {
		t.Errorf("causation %q, want the caller's explicit value", got)
	}
}

// CausedBy is what a reactor attaches before it acts: the correlation id is
// inherited so the whole chain shares one, and the causation id becomes this
// event, so the chain is a tree rather than a flat list.
func TestCausedByInheritsCorrelationAndReplacesCausation(t *testing.T) {
	id := ids.FromUUID[ids.Event]([16]byte{1, 2, 3, 4})
	env := es.Envelope{ID: id, Meta: es.Metadata{
		CorrelationID: "corr-9", CausationID: "something-earlier",
	}}

	got := es.CausedBy(env)
	if got.CorrelationID != "corr-9" {
		t.Errorf("correlation %q, want the inherited corr-9", got.CorrelationID)
	}
	if got.CausationID != id.String() {
		t.Errorf("causation %q, want this event's own id %s", got.CausationID, id)
	}
}

// An event with no chain of its own becomes the root of one. Propagating an
// empty string instead would group every such event together under "".
func TestCausedByRootsAnUncorrelatedEvent(t *testing.T) {
	id := ids.FromUUID[ids.Event]([16]byte{5, 6, 7, 8})
	got := es.CausedBy(es.Envelope{ID: id})

	if got.CorrelationID != id.String() {
		t.Errorf("correlation %q, want the event's own id %s", got.CorrelationID, id)
	}
	if got.CausationID != id.String() {
		t.Errorf("causation %q, want the event's own id %s", got.CausationID, id)
	}
}

func TestTraceFromAnEmptyContextIsZero(t *testing.T) {
	if got := es.TraceFrom(context.Background()); !got.IsZero() {
		t.Errorf("got %+v, want the zero Trace — an absent trace is a root write, not an error", got)
	}
}
