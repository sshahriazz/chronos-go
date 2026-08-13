package reactor_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// The property reactors exist to protect: an event delivered twice produces the
// effect once.
func TestRedeliveryProducesOneEffect(t *testing.T) {
	mailer := &spyReactor{name: "welcome_email"}
	dedup := newMemDedup()
	sub := newSub(
		recorded("evt_1", "identity-u1"),
		recorded("evt_1", "identity-u1"), // the SAME event, redelivered
		recorded("evt_2", "identity-u2"),
	)

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, dedup)), sub)

	if got := mailer.calls(); got != 2 {
		t.Fatalf("reacted %d times to 3 deliveries of 2 distinct events, want 2 — "+
			"a redelivered event sent a second email", got)
	}
}

// A failure asks for redelivery, and the retry must actually run: marking an
// event handled before it succeeded would lose it permanently.
func TestFailureIsRetriedNotSwallowed(t *testing.T) {
	boom := errors.New("smtp: connection refused")
	mailer := &spyReactor{name: "welcome_email", failFirst: 1, failWith: boom}
	dedup := newMemDedup()
	sub := newSub(recorded("evt_1", "identity-u1"))

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, dedup)), sub)

	if !errors.Is(sub.lastErr, boom) {
		t.Fatalf("the handler error was not returned to the transport: %v", sub.lastErr)
	}
	if dedup.count() != 0 {
		t.Fatal("a failed event was recorded as handled; it would never be retried")
	}
}

// Metadata that cannot be decoded will never become decodable, so it is parked
// rather than retried ten times.
func TestUndecodableMetadataIsPoison(t *testing.T) {
	mailer := &spyReactor{name: "welcome_email"}
	sub := newSub(eventsourcing.RecordedEvent{
		ID: mustID("evt_bad"), Type: "identity.X.v1",
		Stream: "identity-u1", Metadata: []byte(`{not json`),
	})

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, newMemDedup())), sub)

	if !errors.Is(sub.lastErr, eventsourcing.ErrPoison) {
		t.Fatalf("undecodable metadata must be poison, got %v", sub.lastErr)
	}
	if mailer.calls() != 0 {
		t.Fatal("the reactor was handed an event whose metadata could not be read")
	}
}

// If dedup itself is unavailable we cannot tell whether the effect already
// happened. Asking for redelivery is the only safe answer.
func TestDedupFailureAsksForRedelivery(t *testing.T) {
	mailer := &spyReactor{name: "welcome_email"}
	dedup := newMemDedup()
	dedup.readFails = true
	sub := newSub(recorded("evt_1", "identity-u1"))

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, dedup)), sub)

	if sub.lastErr == nil {
		t.Fatal("an unreadable dedup store must not be treated as 'not yet handled'")
	}
	if mailer.calls() != 0 {
		t.Fatal("reacted without knowing whether the effect had already happened")
	}
}

// The effect happens before it is recorded. If recording fails the effect has
// still happened, so the runner must NOT ask for redelivery — that would repeat
// it.
func TestRecordFailureDoesNotRepeatTheEffect(t *testing.T) {
	mailer := &spyReactor{name: "welcome_email"}
	dedup := newMemDedup()
	dedup.writeFails = true
	sub := newSub(recorded("evt_1", "identity-u1"))

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, dedup)), sub)

	if mailer.calls() != 1 {
		t.Fatalf("reacted %d times, want 1", mailer.calls())
	}
	if sub.lastErr != nil {
		t.Fatalf("a failed dedup WRITE must not request redelivery — the email is already sent: %v", sub.lastErr)
	}
}

func TestSystemEventsAreIgnored(t *testing.T) {
	mailer := &spyReactor{name: "welcome_email"}
	sub := newSub(recorded("evt_1", "$$identity-u1"), recorded("evt_2", "identity-u1"))

	runUntilDrained(t, reactor.NewRunner(mailer, deps(sub, newMemDedup())), sub)

	if mailer.calls() != 1 {
		t.Fatalf("reacted %d times, want 1 — system streams are not domain facts", mailer.calls())
	}
}

// The package must offer no way to replay a reactor. This is a compile-time
// statement of ADR-019, kept as a test so the intent is visible.
func TestRunnerHasNoRebuild(t *testing.T) {
	var r any = reactor.NewRunner(&spyReactor{name: "x"}, deps(newSub(), newMemDedup()))
	if _, bad := r.(interface{ Rebuild(context.Context) error }); bad {
		t.Fatal("Runner grew a Rebuild method: replaying a reactor re-sends every effect in history")
	}
	if _, bad := r.(interface{ Reset(context.Context) error }); bad {
		t.Fatal("Runner grew a Reset method")
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func deps(sub *fakeSub, d reactor.Dedup) reactor.Deps {
	return reactor.Deps{
		Subscriber: sub,
		Codec:      metaCodec{},
		Dedup:      d,
		Log:        slog.New(slog.NewTextHandler(io.Discard, nil)),
		Retry:      time.Millisecond,
	}
}

func runUntilDrained(t *testing.T, r *reactor.Runner, sub *fakeSub) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- r.Run(ctx) }()

	select {
	case <-sub.drained:
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for delivery")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("run: %v", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("the runner did not stop when cancelled")
	}
}

func mustID(seed string) ids.EventID { return eventsourcing.DeriveEventID(seed, 0) }

func recorded(seed, stream string) eventsourcing.RecordedEvent {
	meta, _ := codec.Marshal(map[string]string{"orgId": "org_A"})
	return eventsourcing.RecordedEvent{
		ID: mustID(seed), Type: "identity.UserRegistered.v1",
		Stream: eventsourcing.StreamID(stream), Metadata: meta,
		Payload: []byte(`{}`),
	}
}

type spyReactor struct {
	mu        sync.Mutex
	name      string
	n         int
	failFirst int
	failWith  error
}

func (s *spyReactor) Name() string { return s.name }
func (s *spyReactor) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"identity-"}}
}

func (s *spyReactor) React(context.Context, eventsourcing.Envelope) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.failFirst > 0 {
		s.failFirst--
		return s.failWith
	}
	s.n++
	return nil
}

func (s *spyReactor) calls() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.n
}

type memDedup struct {
	mu         sync.Mutex
	seen       map[string]bool
	readFails  bool
	writeFails bool
}

func newMemDedup() *memDedup { return &memDedup{seen: map[string]bool{}} }

func (m *memDedup) Seen(_ context.Context, name string, id ids.EventID) (bool, error) {
	if m.readFails {
		return false, errors.New("mem: dedup unavailable")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.seen[name+id.String()], nil
}

func (m *memDedup) MarkSeen(_ context.Context, name string, id ids.EventID) error {
	if m.writeFails {
		return errors.New("mem: dedup write failed")
	}
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen[name+id.String()] = true
	return nil
}

func (m *memDedup) count() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return len(m.seen)
}

// fakeSub stands in for a persistent subscription: it delivers each event and
// records what the handler said, exactly as the server would use the ack/nack.
type fakeSub struct {
	events  []eventsourcing.RecordedEvent
	drained chan struct{}
	lastErr error
}

func newSub(events ...eventsourcing.RecordedEvent) *fakeSub {
	return &fakeSub{events: events, drained: make(chan struct{})}
}

func (s *fakeSub) Consume(
	ctx context.Context, _ string,
	_ eventsourcing.SubscriptionFilter, h eventsourcing.Handler,
) error {
	for _, e := range s.events {
		if err := h(ctx, e); err != nil {
			// The server would nack and redeliver; the test inspects the reason.
			s.lastErr = err
		}
	}
	close(s.drained)
	<-ctx.Done()
	return ctx.Err()
}

type metaCodec struct{}

func (metaCodec) Marshal(eventsourcing.Event) ([]byte, error) { return nil, nil }
func (metaCodec) Unmarshal(string, []byte) (eventsourcing.Event, error) {
	return nil, errors.New("not used")
}
func (metaCodec) MarshalMetadata(eventsourcing.Metadata) ([]byte, error) { return nil, nil }

func (metaCodec) UnmarshalMetadata(b []byte) (eventsourcing.Metadata, error) {
	var w struct {
		OrgID string `json:"orgId"`
	}
	// Tolerant, matching the real codec: stored metadata carries keys this
	// double does not model, and a reactor must not park an event over one.
	if err := codec.IntoTolerant(b, &w); err != nil {
		return eventsourcing.Metadata{}, err
	}
	return eventsourcing.Metadata{OrgID: w.OrgID}, nil
}

// ---------------------------------------------------------------------------
// causation and filters
// ---------------------------------------------------------------------------

// tracingReactor records the causation chain its context carried.
type tracingReactor struct {
	mu    sync.Mutex
	trace eventsourcing.Trace
}

func (*tracingReactor) Name() string { return "tracing" }
func (*tracingReactor) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"identity-"}}
}

func (r *tracingReactor) React(ctx context.Context, _ eventsourcing.Envelope) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.trace = eventsourcing.TraceFrom(ctx)
	return nil
}

// Anything a reaction writes must name the event that caused it. Left to each
// reactor to remember, this is forgotten once and the resulting event's origin
// is unrecoverable — the log cannot be amended.
func TestReactionCarriesTheCausationChain(t *testing.T) {
	spy := &tracingReactor{}
	e := recorded("evt_trace", "identity-u1")
	sub := newSub(e)

	runUntilDrained(t, reactor.NewRunner(spy, deps(sub, newMemDedup())), sub)

	spy.mu.Lock()
	defer spy.mu.Unlock()
	if got := spy.trace.CausationID; got != e.ID.String() {
		t.Errorf("causation %q, want the handled event's id %s", got, e.ID)
	}
	// This event carries no correlation of its own, so it roots the chain.
	if got := spy.trace.CorrelationID; got != e.ID.String() {
		t.Errorf("correlation %q, want the handled event's id %s", got, e.ID)
	}
}

type mixedFilterReactor struct{ spyReactor }

func (*mixedFilterReactor) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{"identity-"}, EventTypes: []string{"identity.X.v1"},
	}
}

// A filter naming two dimensions cannot be expressed server-side, so one half
// would be dropped. For a reactor that means mail nobody receives, with no
// error anywhere — so it refuses to start.
func TestReactorRefusesAFilterThatMixesSelectors(t *testing.T) {
	sub := newSub()
	r := reactor.NewRunner(&mixedFilterReactor{spyReactor: spyReactor{name: "mixed"}}, deps(sub, newMemDedup()))

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	if err := r.Run(ctx); !errors.Is(err, eventsourcing.ErrAmbiguousFilter) {
		t.Fatalf("got %v, want ErrAmbiguousFilter", err)
	}
}
