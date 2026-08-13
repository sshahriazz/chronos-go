//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/google/uuid"
)

func idempotency(t *testing.T) *pgadapter.Idempotency {
	t.Helper()
	return pgadapter.NewIdempotency(pgadapter.New(poolWith(t, 8)))
}

// A fresh scope per test. A shared one would let a previous run's record decide
// this run's outcome — and this table's whole job is to remember previous runs.
func freshScope(t *testing.T) cqrs.Scope {
	t.Helper()
	s := cqrs.Scope{
		Principal: "usr_" + strings.ReplaceAll(uuid.New().String(), "-", ""),
		Operation: "/chronos.workspace.v1/CreateWorkspace",
		Key:       cqrs.Key(uuid.New().String()),
	}
	t.Cleanup(func() { _ = pgadapter.NewIdempotency(pgadapter.New(poolWith(t, 2))).Release(context.Background(), s) })
	return s
}

func fp(body string) [32]byte { return cqrs.Fingerprint([]byte(body)) }

// The full lifecycle against a real database: claim, complete, replay.
func TestClaimCompleteReplay(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{"name":"eng"}`)

	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if rec.State != cqrs.StateNew {
		t.Fatalf("a fresh scope reported state %d, want StateNew", rec.State)
	}

	if err := store.Complete(ctx, s, []byte("ws_1")); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	rec, err = store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("replay Claim: %v", err)
	}
	if rec.State != cqrs.StateDone {
		t.Fatalf("a completed scope reported state %d, want StateDone", rec.State)
	}
	if string(rec.Response) != "ws_1" {
		t.Fatalf("replay returned %q, want ws_1", rec.Response)
	}
	if rec.Fingerprint != body {
		t.Fatal("the stored fingerprint did not survive the round trip, so a reused key " +
			"could not be told apart from a genuine replay")
	}
}

// Concurrent duplicates: exactly ONE receives StateNew.
//
// This is the property the whole table exists for, and it cannot be tested
// against a fake — the atomicity lives in `INSERT … ON CONFLICT`, which is
// Postgres behaviour, not Go behaviour. A check-then-act implementation passes
// every unit test and fails here.
func TestExactlyOneConcurrentClaimWins(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	body := fp(`{}`)

	const racers = 16
	states := make([]cqrs.State, racers)
	errs := make([]error, racers)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			rec, err := store.Claim(context.Background(), s, body, time.Minute)
			states[i], errs[i] = rec.State, err
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for i, err := range errs {
		if err != nil {
			t.Fatalf("racer %d: %v", i, err)
		}
		if states[i] == cqrs.StateNew {
			won++
		}
	}
	if won != 1 {
		t.Fatalf("%d of %d concurrent claims were told to execute; a double-click runs the "+
			"mutation %d times", won, racers, won)
	}
}

// A released claim can be re-claimed, so a failed attempt is retryable.
func TestAReleasedClaimIsRetryable(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{}`)

	if _, err := store.Claim(ctx, s, body, time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Release(ctx, s); err != nil {
		t.Fatalf("Release: %v", err)
	}
	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("re-Claim: %v", err)
	}
	if rec.State != cqrs.StateNew {
		t.Fatalf("after Release the scope reported state %d; a failed attempt is not "+
			"retryable and every retry with the same key is refused until the TTL", rec.State)
	}
}

// Release must NOT delete a completed record.
//
// It would let the mutation execute a second time under the same key — the gate
// failing open, which is worse than the gate not existing, because callers
// believe they are protected.
func TestReleaseDoesNotDeleteACompletedRecord(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{}`)

	if _, err := store.Claim(ctx, s, body, time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, []byte("ws_1")); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	if err := store.Release(ctx, s); err != nil {
		t.Fatalf("Release: %v", err)
	}

	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("Claim after Release: %v", err)
	}
	if rec.State != cqrs.StateDone {
		t.Fatal("Release deleted a COMPLETED record: the same key now executes the mutation " +
			"a second time")
	}
	if string(rec.Response) != "ws_1" {
		t.Fatalf("the stored response became %q", rec.Response)
	}
}

// Completing a claim that is not held is an error, not a silent success.
//
// Zero rows affected means the record expired or was taken over while the
// handler ran, so the response was NOT stored. A caller told "recorded" would
// believe a retry will replay it.
func TestCompletingAClaimThatIsNotHeldIsAnError(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)

	err := store.Complete(context.Background(), s, []byte("ws_1"))
	if err == nil {
		t.Fatal("completing a claim that does not exist reported success; the response was " +
			"not stored and nothing said so")
	}
}

// Completing twice fails the second time. The first response stands.
//
// Overwriting would replace an answer a client has already been given with a
// different one.
func TestASecondCompleteDoesNotOverwriteTheFirst(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()

	if _, err := store.Claim(ctx, s, fp(`{}`), time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, []byte("first")); err != nil {
		t.Fatalf("first Complete: %v", err)
	}
	if err := store.Complete(ctx, s, []byte("second")); err == nil {
		t.Fatal("a second Complete succeeded; the response a client already received was " +
			"replaced with a different one")
	}
	rec, err := store.Claim(ctx, s, fp(`{}`), time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if string(rec.Response) != "first" {
		t.Fatalf("the stored response is %q, want first", rec.Response)
	}
}

// A nil response is refused: NULL is what marks a claim as in flight.
//
// Storing one would leave the record looking permanently running, so every retry
// of a mutation that already succeeded is refused as a duplicate.
func TestANilResponseIsRefused(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()

	if _, err := store.Claim(ctx, s, fp(`{}`), time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, nil); err == nil {
		t.Fatal("a nil response was stored; the claim now looks permanently in flight")
	}
}

// An expired claim is taken over rather than blocking forever.
//
// Otherwise a request that died mid-flight holds its key until the retention
// sweep runs — and the client, correctly retrying with the same key, is refused
// the whole time.
func TestAnExpiredClaimIsTakenOver(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{}`)

	// A claim that expires almost immediately, never completed.
	if _, err := store.Claim(ctx, s, body, 50*time.Millisecond); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if rec, err := store.Claim(ctx, s, body, time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	} else if rec.State != cqrs.StateRunning {
		t.Fatalf("a live claim reported state %d, want StateRunning — the takeover fires "+
			"before the TTL", rec.State)
	}

	time.Sleep(150 * time.Millisecond)

	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("Claim after expiry: %v", err)
	}
	if rec.State != cqrs.StateNew {
		t.Fatalf("an expired claim reported state %d; a request that died mid-flight holds "+
			"its key until the retention sweep", rec.State)
	}
}

// An expired COMPLETED record is not replayed.
//
// The TTL bounds how long a response — which can contain personal data — may be
// kept and returned (ADR-002).
func TestAnExpiredResponseIsNotReplayed(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{}`)

	if _, err := store.Claim(ctx, s, body, 50*time.Millisecond); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, []byte("ws_1")); err != nil {
		t.Fatalf("Complete: %v", err)
	}
	time.Sleep(150 * time.Millisecond)

	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if rec.State == cqrs.StateDone {
		t.Fatal("a response was replayed past its TTL; the retention bound is not enforced " +
			"on the read path, only by the sweep")
	}
}

// The sweep deletes expired records and reports how many.
//
// A sweep that silently deletes nothing for a week looks identical to a sweep
// that is working.
func TestTheSweepDeletesExpiredRecords(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()

	if _, err := store.Claim(ctx, s, fp(`{}`), 50*time.Millisecond); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, []byte("ws_1")); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	// A live record that must SURVIVE — otherwise a sweep deleting everything
	// would pass this test.
	live := freshScope(t)
	if _, err := store.Claim(ctx, live, fp(`{}`), time.Hour); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, live, []byte("ws_live")); err != nil {
		t.Fatalf("Complete: %v", err)
	}

	time.Sleep(150 * time.Millisecond)

	deleted, err := store.Sweep(ctx)
	if err != nil {
		t.Fatalf("Sweep: %v", err)
	}
	if deleted < 1 {
		t.Fatalf("the sweep deleted %d records although one had expired", deleted)
	}

	rec, err := store.Claim(ctx, live, fp(`{}`), time.Hour)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if rec.State != cqrs.StateDone || string(rec.Response) != "ws_live" {
		t.Fatal("the sweep deleted a LIVE record: every in-flight client loses its ability " +
			"to replay")
	}
}

// A malformed scope never reaches the database.
func TestAMalformedScopeIsRefused(t *testing.T) {
	store := idempotency(t)
	ctx := context.Background()

	bad := freshScope(t)
	bad.Principal = ""
	if _, err := store.Claim(ctx, bad, fp(`{}`), time.Minute); err == nil {
		t.Error("a scope with no principal was accepted")
	}
	if err := store.Complete(ctx, bad, []byte("x")); err == nil {
		t.Error("a scope with no principal was completed")
	}
	if err := store.Release(ctx, bad); err == nil {
		t.Error("a scope with no principal was released")
	}
}

// A non-positive TTL is refused: without one the record would be replayable
// forever, and a stored response is retained data.
func TestANonPositiveTTLIsRefused(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)

	if _, err := store.Claim(context.Background(), s, fp(`{}`), 0); err == nil {
		t.Fatal("a zero TTL was accepted")
	} else if !errors.Is(err, cqrs.ErrInvalid) {
		t.Errorf("not reported as invalid: %v", err)
	}
}

// The end-to-end property, through cqrs.Once against real Postgres: a
// double-click executes the mutation exactly once.
func TestOnceOverPostgresExecutesADoubleClickOnce(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)

	o, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store, Wait: 5 * time.Second})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}

	var mu sync.Mutex
	calls := 0
	const clicks = 8
	responses := make([]string, clicks)
	errs := make([]error, clicks)
	start := make(chan struct{})

	var wg sync.WaitGroup
	for i := range clicks {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := o.Do(context.Background(), s, []byte(`{"name":"eng"}`),
				func(context.Context) ([]byte, error) {
					mu.Lock()
					calls++
					mu.Unlock()
					time.Sleep(80 * time.Millisecond)
					return []byte("ws_1"), nil
				})
			responses[i], errs[i] = string(resp), err
		}(i)
	}
	close(start)
	wg.Wait()

	if calls != 1 {
		t.Fatalf("the mutation executed %d times; a double-click created %d workspaces",
			calls, calls)
	}
	for i := range responses {
		if errs[i] != nil {
			t.Errorf("click %d: %v", i, errs[i])
		} else if responses[i] != "ws_1" {
			t.Errorf("click %d got %q, want the one stored response", i, responses[i])
		}
	}
}

// And the reused-key case end to end: same key, different body, refused.
func TestOnceOverPostgresRefusesAReusedKey(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	o, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}
	ctx := context.Background()
	calls := 0
	run := func(context.Context) ([]byte, error) { calls++; return []byte("ws_1"), nil }

	if _, err := o.Do(ctx, s, []byte(`{"name":"eng"}`), run); err != nil {
		t.Fatalf("first: %v", err)
	}
	resp, err := o.Do(ctx, s, []byte(`{"name":"sales"}`), run)
	if !errors.Is(err, cqrs.ErrKeyReused) {
		t.Fatalf("got (%q, %v); want ErrKeyReused", resp, err)
	}
	if resp != nil {
		t.Fatal("the stored response was returned for a different body")
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times", calls)
	}
}

// An EMPTY response is stored and replayed as empty — not confused with "no
// response".
//
// This is not hypothetical: a Delete returning google.protobuf.Empty marshals to
// zero bytes, and that is the common case for mutations. The distinction rests
// on NULL vs a zero-length bytea surviving a round trip through pgx, which is a
// driver behaviour worth probing rather than assuming — if an empty bytea came
// back as nil, every retry of such a method would be refused as still in flight.
func TestAnEmptyResponseIsNotConfusedWithNoResponse(t *testing.T) {
	store := idempotency(t)
	s := freshScope(t)
	ctx := context.Background()
	body := fp(`{}`)

	if _, err := store.Claim(ctx, s, body, time.Minute); err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if err := store.Complete(ctx, s, []byte{}); err != nil {
		t.Fatalf("Complete with an empty response: %v", err)
	}

	rec, err := store.Claim(ctx, s, body, time.Minute)
	if err != nil {
		t.Fatalf("Claim: %v", err)
	}
	if rec.State != cqrs.StateDone {
		t.Fatalf("a record completed with an empty response reports state %d; a method "+
			"returning an empty message can never be retried", rec.State)
	}
	if rec.Response == nil {
		t.Fatal("an empty response came back as nil, which is how the store spells 'still " +
			"in flight': the replay path cannot tell them apart")
	}
	if len(rec.Response) != 0 {
		t.Fatalf("the empty response came back as %d bytes", len(rec.Response))
	}
}
