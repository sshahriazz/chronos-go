//go:build integration

package kurrentdb_test

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kdb "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	es "github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
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

// TestAtomicAppendUnderConcurrencyHasExactlyOneWinner is the property ADR-044
// rests on, and until now nothing demonstrated it.
//
// The two tests above contend SEQUENTIALLY: the first claim is already durable
// before the second is attempted, so they show that the server rejects a
// precondition it can already see is violated. That is not the interesting
// case. The interesting case is N callers whose preconditions are all
// satisfiable at the moment each request is formed, arriving together — because
// that is what a registration race actually is, and because a server that
// evaluated multi-stream preconditions outside the per-stream write lock would
// pass both sequential tests and admit two winners here.
//
// The losers' OWN aggregate streams are checked too, and that is the half a
// "count the claims" assertion misses: a loser that lost the claim but still
// created its aggregate is exactly the state that produces two accounts holding
// one address.
func TestAtomicAppendUnderConcurrencyHasExactlyOneWinner(t *testing.T) {
	const racers = 8
	store := multiStore(t)
	ctx := context.Background()
	sfx := uniqueSuffix(t)

	reservation := es.StreamID("multiresv" + sfx + "-contended")
	aggregates := make([]es.StreamID, racers)
	for i := range aggregates {
		aggregates[i] = es.StreamID(fmt.Sprintf("multitest%s-racer%d", sfx, i))
	}

	// Indexed rather than collected through a channel: each goroutine owns one
	// slot, so there is no shared mutable state and no ordering to reason about.
	errsOf := make([]error, racers)
	start := make(chan struct{})
	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := store.AppendToMany(ctx, []es.StreamAppend{
				{Stream: reservation, Expected: es.NoStream(),
					Events: []es.PendingEvent{pending(&claimed{Value: "contended"})}},
				{Stream: aggregates[i], Expected: es.NoStream(),
					Events: []es.PendingEvent{pending(&created{Name: fmt.Sprintf("racer %d", i)})}},
			})
			errsOf[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	winners := make([]int, 0, racers)
	for i, err := range errsOf {
		switch {
		case err == nil:
			winners = append(winners, i)
		case errors.Is(err, es.ErrWrongExpectedRevision):
		default:
			t.Errorf("racer %d failed with %v, want either success or ErrWrongExpectedRevision: "+
				"an infrastructure error here would make ordinary contention look like an outage",
				i, err)
		}
	}
	if len(winners) != 1 {
		t.Errorf("%d of %d racers won the claim, want exactly 1 (winners=%v)",
			len(winners), racers, winners)
	}

	events, err := store.ReadStream(ctx, reservation, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", reservation, err)
	}
	if len(events) != 1 {
		t.Errorf("the contended stream holds %d claims, want 1", len(events))
	}

	// The decisive assertion. A loser must have written NOTHING, including to
	// the stream whose own precondition was perfectly satisfiable.
	for i, s := range aggregates {
		_, err := store.ReadStream(ctx, s, 0)
		won := len(winners) == 1 && winners[0] == i
		switch {
		case won && err != nil:
			t.Errorf("the winner's aggregate %s is missing: %v", s, err)
		case !won && !errors.Is(err, es.ErrStreamNotFound):
			t.Errorf("loser %d's aggregate %s exists after losing the claim (err=%v): the "+
				"append was partial, so a caller relying on atomicity ends up with an "+
				"aggregate that holds a claim it never won", i, s, err)
		}
	}
}

// TestAtomicAppendPreservesRequestOrderInAll pins the ordering a takeover
// depends on.
//
// When a lapsed claim is taken over, ONE multi-append carries the release and
// the new claim on the reservation stream and the new aggregate on its own —
// reservation entry first, as app.Registration.appendBoth builds it. Consumers
// read $all, and a projection that must retire the previous holder before the
// new one is written needs the release to arrive first.
//
// The append is atomic, so nothing guarantees an interleaving a priori: the
// server could order one commit's events any way it liked. This asserts that it
// follows the order of the request, which is what makes "reservation entry
// first" a decision the caller gets to make rather than a coincidence.
func TestAtomicAppendPreservesRequestOrderInAll(t *testing.T) {
	client, store := multiStore2(t)
	ctx := context.Background()
	sfx := uniqueSuffix(t)

	reservation := es.StreamID("multiresv" + sfx + "-ordered")
	aggregate := es.StreamID("multitest" + sfx + "-ordered")

	// The tail BEFORE the append, so the read below is bounded by the append
	// itself rather than by a window of N recent events. A fixed window is a
	// flake waiting to happen: creating streams also writes system events, so
	// "the last 512" is not a stable amount of history.
	from := tailOfAll(t, client)

	if _, err := store.AppendToMany(ctx, []es.StreamAppend{
		{Stream: reservation, Expected: es.NoStream(), Events: []es.PendingEvent{
			pending(&claimed{Value: "first"}),
			pending(&claimed{Value: "second"}),
		}},
		{Stream: aggregate, Expected: es.NoStream(), Events: []es.PendingEvent{
			pending(&created{Name: "third"}),
			pending(&created{Name: "fourth"}),
		}},
	}); err != nil {
		t.Fatalf("atomic append: %v", err)
	}

	rs, err := client.ReadAll(ctx, kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	var got []es.StreamID
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		// System streams carry the suffix too: KurrentDB indexes a new stream
		// by writing to $$$category-<category>, and it does so AFTER the events
		// that created it. Those are the server's bookkeeping, not this
		// append's events, and counting them made this test flake.
		if ev.Event == nil || strings.HasPrefix(ev.Event.StreamID, "$") ||
			!strings.Contains(ev.Event.StreamID, sfx) {
			continue
		}
		got = append(got, es.StreamID(ev.Event.StreamID))
	}

	want := []es.StreamID{reservation, reservation, aggregate, aggregate}
	if len(got) != len(want) {
		t.Fatalf("$all holds %d events for this append, want %d: %v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("$all order is %v, want %v: the commit does not follow the order of the "+
				"request, so a consumer cannot rely on the reservation entry being applied "+
				"before the aggregate it belongs to", got, want)
		}
	}
}

// multiStore2 is multiStore plus the raw client, for the one test that has to
// read $all rather than a stream.
func multiStore2(t *testing.T) (*kurrentdb.Client, *kdb.Store) {
	t.Helper()
	c, _ := typeStore(t)
	codec := eventcodec.NewJSON(es.NewUpcasterRegistry())
	codec.Register("multitest.Claimed.v1", func() es.Event { return &claimed{} })
	codec.Register("multitest.Created.v1", func() es.Event { return &created{} })
	return c, kdb.NewStore(c, codec)
}

// tailOfAll reports the position just past the end of $all.
func tailOfAll(t *testing.T, client *kurrentdb.Client) kurrentdb.AllPosition {
	t.Helper()
	rs, err := client.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Backwards, From: kurrentdb.End{},
	}, 1)
	if err != nil {
		t.Fatalf("reading the tail of $all: %v", err)
	}
	defer rs.Close()
	ev, err := rs.Recv()
	if errors.Is(err, io.EOF) {
		return kurrentdb.Start{}
	}
	if err != nil {
		t.Fatalf("reading the tail of $all: %v", err)
	}
	return kurrentdb.Position{
		Commit:  ev.Event.Position.Commit,
		Prepare: ev.Event.Position.Prepare,
	}
}
