//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kdb "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
	"time"
)

// claimed stands in for a uniqueness reservation.
type claimed struct {
	Value string `json:"value"`
}

func (*claimed) EventType() string { return "multitest.Claimed.v1" }

// created stands in for the aggregate that owns the claim.
type created struct {
	Name string `json:"name"`
}

func (*created) EventType() string { return "multitest.Created.v1" }

func multiStore(t *testing.T) *kdb.Store {
	t.Helper()
	c, _ := typeStore(t)

	codec := eventcodec.NewJSON(es.NewUpcasterRegistry())
	codec.Register("multitest.Claimed.v1", func() es.Event { return &claimed{} })
	codec.Register("multitest.Created.v1", func() es.Event { return &created{} })
	return kdb.NewStore(c, codec)
}

func pending(e es.Event) es.PendingEvent {
	return es.PendingEvent{
		ID:    ids.New[ids.Event](time.Now(), ids.Entropy()),
		Event: e,
		Meta:  es.Metadata{SchemaVersion: 1, OrgID: "org_multitest"},
	}
}

func uniqueSuffix(t *testing.T) string {
	t.Helper()
	raw := uuid.New()
	return hex.EncodeToString(raw[:4])
}

// A claim and the aggregate that owns it must land together or not at all.
//
// As two appends this needs compensation or a workflow: a crash between them
// leaves a reservation nobody owns, and the address is then unclaimable forever
// with no aggregate to explain why.
func TestAtomicAppendWritesBothStreams(t *testing.T) {
	store := multiStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix(t)

	reservation := es.StreamID("multiresv" + sfx + "-alice")
	aggregate := es.StreamID("multitest" + sfx + "-user1")

	results, err := store.AppendToMany(ctx, []es.StreamAppend{
		{Stream: reservation, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&claimed{Value: "alice"})}},
		{Stream: aggregate, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&created{Name: "Alice"})}},
	})
	if err != nil {
		t.Fatalf("atomic append: %v", err)
	}
	if len(results) != 2 {
		t.Fatalf("got %d results, want 2", len(results))
	}
	for i, r := range results {
		if r.Revision != 0 {
			t.Errorf("stream %d landed at revision %d, want 0", i, r.Revision)
		}
		if r.Position.Commit == 0 {
			t.Errorf("stream %d reported no log position", i)
		}
	}

	for _, s := range []es.StreamID{reservation, aggregate} {
		events, err := store.ReadStream(ctx, s, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", s, err)
		}
		if len(events) != 1 {
			t.Fatalf("%s holds %d events, want 1", s, len(events))
		}
	}
}

// The property the whole feature rests on: if ONE precondition fails, NOTHING is
// written — including the streams whose preconditions were fine.
//
// Without this the operation is worse than two appends, because a caller would
// believe it atomic while it left a partial write behind.
func TestAtomicAppendRollsBackEveryStreamOnOneFailure(t *testing.T) {
	store := multiStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix(t)

	taken := es.StreamID("multiresv" + sfx + "-bob")
	fresh := es.StreamID("multitest" + sfx + "-user2")

	// Somebody already claimed it.
	if _, err := store.Append(ctx, taken, es.NoStream(),
		[]es.PendingEvent{pending(&claimed{Value: "bob"})}); err != nil {
		t.Fatalf("seeding the existing claim: %v", err)
	}

	// A second registration tries to claim the same value and create its
	// aggregate. The claim's precondition cannot hold.
	_, err := store.AppendToMany(ctx, []es.StreamAppend{
		{Stream: taken, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&claimed{Value: "bob"})}},
		{Stream: fresh, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&created{Name: "Bob 2"})}},
	})
	if err == nil {
		t.Fatal("claiming a taken value must fail")
	}
	if !errors.Is(err, es.ErrWrongExpectedRevision) {
		t.Fatalf("got %v, want ErrWrongExpectedRevision so the caller reloads and re-decides", err)
	}

	// The claim stream must still hold ONLY the original event.
	events, err := store.ReadStream(ctx, taken, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", taken, err)
	}
	if len(events) != 1 {
		t.Fatalf("%s holds %d events, want 1: the failed append wrote to it anyway", taken, len(events))
	}

	// And the stream whose precondition WAS satisfiable must not exist. This is
	// the assertion that distinguishes a real atomic append from a loop.
	if _, err := store.ReadStream(ctx, fresh, 0); !errors.Is(err, es.ErrStreamNotFound) {
		t.Fatalf("%s exists after a failed atomic append: the write was partial, so "+
			"callers relying on atomicity would leave an aggregate with no claim (err=%v)",
			fresh, err)
	}
}

// A stream named twice has two preconditions against one revision, so at most
// one can hold. Rejecting it names the mistake instead of surfacing a confusing
// revision conflict from the server.
func TestAtomicAppendRejectsDuplicateStreams(t *testing.T) {
	store := multiStore(t)
	sfx := uniqueSuffix(t)
	s := es.StreamID("multitest" + sfx + "-dup")

	_, err := store.AppendToMany(context.Background(), []es.StreamAppend{
		{Stream: s, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&created{Name: "a"})}},
		{Stream: s, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&created{Name: "b"})}},
	})
	if err == nil {
		t.Fatal("naming one stream twice must be refused")
	}
}

// One stream is an ordinary append and must behave identically.
func TestAtomicAppendWithOneStream(t *testing.T) {
	store := multiStore(t)
	sfx := uniqueSuffix(t)
	s := es.StreamID("multitest" + sfx + "-single")

	results, err := store.AppendToMany(context.Background(), []es.StreamAppend{
		{Stream: s, Expected: es.NoStream(), Events: []es.PendingEvent{pending(&created{Name: "only"})}},
	})
	if err != nil {
		t.Fatalf("single-stream atomic append: %v", err)
	}
	if len(results) != 1 || results[0].Revision != 0 {
		t.Fatalf("got %+v", results)
	}
}

func TestAtomicAppendWithNothingToWrite(t *testing.T) {
	store := multiStore(t)
	results, err := store.AppendToMany(context.Background(), nil)
	if err != nil || results != nil {
		t.Fatalf("an empty append must be a no-op, got %v / %v", results, err)
	}
}
