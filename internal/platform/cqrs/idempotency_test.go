package cqrs_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/cqrs"
)

// memStore is an in-memory Store whose Claim is genuinely atomic, so the
// concurrency test exercises the executor rather than a racy fake.
type memStore struct {
	mu      sync.Mutex
	records map[string]cqrs.Record

	claimErr    error
	completeErr error
	releaseErr  error

	claims int
}

func newStore() *memStore { return &memStore{records: map[string]cqrs.Record{}} }

func (m *memStore) Claim(_ context.Context, s cqrs.Scope, fp [32]byte, _ time.Duration) (cqrs.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.claimErr != nil {
		return cqrs.Record{}, m.claimErr
	}
	m.claims++
	if rec, ok := m.records[s.String()]; ok {
		return rec, nil
	}
	m.records[s.String()] = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
	return cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}, nil
}

func (m *memStore) Complete(_ context.Context, s cqrs.Scope, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.completeErr != nil {
		return m.completeErr
	}
	rec := m.records[s.String()]
	rec.State = cqrs.StateDone
	rec.Response = response
	m.records[s.String()] = rec
	return nil
}

func (m *memStore) Release(_ context.Context, s cqrs.Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.releaseErr != nil {
		return m.releaseErr
	}
	delete(m.records, s.String())
	return nil
}

func (m *memStore) state(s cqrs.Scope) (cqrs.Record, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec, ok := m.records[s.String()]
	return rec, ok
}

func once(t *testing.T, s cqrs.Store) *cqrs.Once {
	t.Helper()
	o, err := cqrs.NewOnce(cqrs.OnceDeps{Store: s})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}
	return o
}

func scope(key string) cqrs.Scope {
	return cqrs.Scope{Principal: "usr_alice", Operation: "/chronos.workspace.v1/Create", Key: cqrs.Key(key)}
}

func returns(resp string, calls *int) func(context.Context) ([]byte, error) {
	return func(context.Context) ([]byte, error) {
		*calls++
		return []byte(resp), nil
	}
}

// The same key with the same body returns the stored response and does NOT run
// the handler again. This is the whole point of the gate.
func TestAReplayReturnsTheStoredResponseWithoutExecuting(t *testing.T) {
	store := newStore()
	o := once(t, store)
	body := []byte(`{"name":"eng"}`)
	calls := 0

	first, err := o.Do(context.Background(), scope("k1"), body, returns("ws_1", &calls))
	if err != nil {
		t.Fatalf("first: %v", err)
	}
	second, err := o.Do(context.Background(), scope("k1"), body, returns("ws_2", &calls))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times; a retried request executed the mutation twice", calls)
	}
	if string(first) != "ws_1" || string(second) != "ws_1" {
		t.Fatalf("got %q then %q; the replay did not return the stored response",
			first, second)
	}
}

// The same key with a DIFFERENT body is a client bug, and the stored response
// must not be handed back.
//
// Returning it would tell the client its request succeeded when a different
// request is what actually ran.
func TestAReusedKeyWithADifferentBodyIsRefused(t *testing.T) {
	store := newStore()
	o := once(t, store)
	calls := 0

	if _, err := o.Do(context.Background(), scope("k1"), []byte(`{"name":"eng"}`),
		returns("ws_1", &calls)); err != nil {
		t.Fatalf("first: %v", err)
	}
	resp, err := o.Do(context.Background(), scope("k1"), []byte(`{"name":"sales"}`),
		returns("ws_2", &calls))
	if !errors.Is(err, cqrs.ErrKeyReused) {
		t.Fatalf("a reused key with a different body returned (%q, %v); want ErrKeyReused",
			resp, err)
	}
	if resp != nil {
		t.Fatal("the stored response was returned for a different request body: the client " +
			"is told its request succeeded when another one is what ran")
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times", calls)
	}
}

// A key is unique per PRINCIPAL.
//
// Without that, one tenant sending another's key is handed that request's stored
// response — a cross-tenant read reachable by guessing a ULID.
func TestAKeyFromAnotherPrincipalDoesNotReplay(t *testing.T) {
	store := newStore()
	o := once(t, store)
	body := []byte(`{"name":"eng"}`)
	calls := 0

	mine := scope("k1")
	if _, err := o.Do(context.Background(), mine, body, returns("ws_mine", &calls)); err != nil {
		t.Fatalf("first: %v", err)
	}

	theirs := mine
	theirs.Principal = "usr_mallory"
	resp, err := o.Do(context.Background(), theirs, body, returns("ws_theirs", &calls))
	if err != nil {
		t.Fatalf("second principal: %v", err)
	}
	if string(resp) == "ws_mine" {
		t.Fatal("another principal's stored response was returned: an idempotency key is a " +
			"cross-tenant read if the scope omits the principal")
	}
	if calls != 2 {
		t.Fatalf("the handler ran %d times; the second principal's request was not executed", calls)
	}
}

// The same key on a DIFFERENT operation does not replay either.
func TestAKeyOnAnotherOperationDoesNotReplay(t *testing.T) {
	store := newStore()
	o := once(t, store)
	body := []byte(`{}`)
	calls := 0

	a := scope("k1")
	if _, err := o.Do(context.Background(), a, body, returns("a", &calls)); err != nil {
		t.Fatalf("first: %v", err)
	}
	b := a
	b.Operation = "/chronos.workspace.v1/Delete"
	resp, err := o.Do(context.Background(), b, body, returns("b", &calls))
	if err != nil {
		t.Fatalf("second operation: %v", err)
	}
	if string(resp) != "b" {
		t.Fatalf("got %q; the same key on a different RPC replayed the first one's response", resp)
	}
}

// A failed handler releases its claim, so a retry can run.
//
// Keeping it would turn a transient failure into a permanent one for the whole
// TTL — and the client's retries, correctly using the same key, would all be
// refused.
func TestAFailedHandlerReleasesItsClaim(t *testing.T) {
	store := newStore()
	o := once(t, store)
	body := []byte(`{}`)
	boom := errors.New("kurrentdb unavailable")

	_, err := o.Do(context.Background(), scope("k1"), body,
		func(context.Context) ([]byte, error) { return nil, boom })
	if !errors.Is(err, boom) {
		t.Fatalf("got %v, want the handler's error", err)
	}
	if _, held := store.state(scope("k1")); held {
		t.Fatal("a failed attempt kept its claim: every retry with the same key is now " +
			"refused until the record expires")
	}

	calls := 0
	resp, err := o.Do(context.Background(), scope("k1"), body, returns("ws_1", &calls))
	if err != nil {
		t.Fatalf("retry after failure: %v", err)
	}
	if string(resp) != "ws_1" || calls != 1 {
		t.Fatalf("the retry did not execute (resp=%q calls=%d)", resp, calls)
	}
}

// A failed handler must NOT be recorded as a completed response.
//
// Storing the error would replay it for a day: a transient outage becomes a
// permanent refusal that no client action clears.
func TestAFailureIsNotRecordedAsAResponse(t *testing.T) {
	store := newStore()
	o := once(t, store)

	_, _ = o.Do(context.Background(), scope("k1"), []byte(`{}`),
		func(context.Context) ([]byte, error) { return nil, errors.New("boom") })

	if rec, ok := store.state(scope("k1")); ok && rec.State == cqrs.StateDone {
		t.Fatal("a failed attempt was stored as a completed response")
	}
}

// Concurrent duplicates execute the mutation exactly once.
//
// This is the double-click case, and it is the one a naive check-then-act gets
// wrong: two requests both read "nothing stored" and both proceed.
func TestConcurrentDuplicatesExecuteOnce(t *testing.T) {
	store := newStore()
	o, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store, Wait: 2 * time.Second})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}
	body := []byte(`{}`)

	var mu sync.Mutex
	calls := 0
	start := make(chan struct{})
	results := make([]string, 8)
	errs := make([]error, 8)

	var wg sync.WaitGroup
	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			resp, err := o.Do(context.Background(), scope("k1"), body,
				func(context.Context) ([]byte, error) {
					mu.Lock()
					calls++
					mu.Unlock()
					time.Sleep(50 * time.Millisecond) // hold the claim
					return []byte("ws_1"), nil
				})
			results[i], errs[i] = string(resp), err
		}(i)
	}
	close(start)
	wg.Wait()

	if calls != 1 {
		t.Fatalf("the mutation executed %d times; a double-click created %d workspaces",
			calls, calls)
	}
	for i, err := range errs {
		if err != nil {
			t.Errorf("caller %d: %v", i, err)
		} else if results[i] != "ws_1" {
			t.Errorf("caller %d got %q, want the one stored response", i, results[i])
		}
	}
}

// With no wait configured, an in-flight duplicate is refused rather than
// executed.
func TestAnInFlightDuplicateIsNotExecuted(t *testing.T) {
	store := newStore()
	o := once(t, store) // Wait: 0
	s := scope("k1")

	// Take the claim without completing it.
	if _, err := store.Claim(context.Background(), s, cqrs.Fingerprint([]byte(`{}`)), time.Hour); err != nil {
		t.Fatalf("Claim: %v", err)
	}

	calls := 0
	_, err := o.Do(context.Background(), s, []byte(`{}`), returns("ws_2", &calls))
	if !errors.Is(err, cqrs.ErrInFlight) {
		t.Fatalf("got %v, want ErrInFlight", err)
	}
	if calls != 0 {
		t.Fatal("a duplicate executed while the first request was still running")
	}
}

// A store that cannot answer must NOT let the request through.
//
// Executing anyway defeats the gate exactly when it matters most: a struggling
// store is a store under the retry storm the gate exists for.
func TestAnUnavailableStoreDoesNotExecute(t *testing.T) {
	store := newStore()
	store.claimErr = errors.New("postgres unavailable")
	o := once(t, store)

	calls := 0
	_, err := o.Do(context.Background(), scope("k1"), []byte(`{}`), returns("ws_1", &calls))
	if !errors.Is(err, cqrs.ErrStoreUnavailable) {
		t.Fatalf("got %v, want ErrStoreUnavailable", err)
	}
	if calls != 0 {
		t.Fatal("the mutation ran although idempotency could not be checked: every retry " +
			"during the outage executes it again")
	}
}

// A scope with no principal is refused before anything is stored.
func TestAScopeWithoutAPrincipalIsRefused(t *testing.T) {
	store := newStore()
	o := once(t, store)

	bad := scope("k1")
	bad.Principal = ""
	calls := 0
	if _, err := o.Do(context.Background(), bad, []byte(`{}`), returns("x", &calls)); err == nil {
		t.Fatal("a scope with no principal was accepted")
	}
	if store.claims != 0 {
		t.Error("the store was consulted with an invalid scope")
	}
	if calls != 0 {
		t.Error("the handler ran under an invalid scope")
	}
}

// Every mutating RPC requires a key (CONVENTIONS §6).
func TestAMissingKeyIsRefused(t *testing.T) {
	store := newStore()
	o := once(t, store)

	bad := scope("")
	calls := 0
	if _, err := o.Do(context.Background(), bad, []byte(`{}`), returns("x", &calls)); err == nil {
		t.Fatal("a mutation with no idempotency key was accepted")
	}
	if calls != 0 {
		t.Error("the handler ran with no idempotency key")
	}
}

// The separator cannot be injected through a scope component.
//
// principal="a|b", operation="c" and principal="a", operation="b|c" must not
// address the same record.
func TestTheScopeSeparatorCannotBeInjected(t *testing.T) {
	store := newStore()
	o := once(t, store)

	bad := scope("k1")
	bad.Principal = "usr_a|/chronos.workspace.v1/Delete"
	calls := 0
	if _, err := o.Do(context.Background(), bad, []byte(`{}`), returns("x", &calls)); err == nil {
		t.Fatal("a principal containing the scope separator was accepted")
	}
}

// A Once with no store is refused at construction.
//
// Optional would mean a deployment could lose the gate silently, and a
// double-click executing twice is indistinguishable from a client sending two
// requests.
func TestAOnceWithoutAStoreIsRefused(t *testing.T) {
	if _, err := cqrs.NewOnce(cqrs.OnceDeps{}); err == nil {
		t.Fatal("a Once was constructed with no store")
	}
}

// The TTL is capped. A record kept longer is a response — possibly carrying
// personal data — retained past any use for it.
func TestAnExcessiveTTLIsRefused(t *testing.T) {
	if _, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newStore(), TTL: 90 * 24 * time.Hour}); err == nil {
		t.Fatal("an idempotency TTL of 90 days was accepted")
	}
	if _, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newStore(), TTL: time.Hour}); err != nil {
		t.Fatalf("a one-hour TTL was refused: %v", err)
	}
}

// A response recorded against a failed Complete is still returned.
//
// The effect already happened. Reporting only a failure would make the client
// retry a mutation that succeeded.
func TestAResponseSurvivesAFailureToRecordIt(t *testing.T) {
	store := newStore()
	store.completeErr = errors.New("postgres unavailable")
	o := once(t, store)

	calls := 0
	resp, err := o.Do(context.Background(), scope("k1"), []byte(`{}`), returns("ws_1", &calls))
	if string(resp) != "ws_1" {
		t.Fatalf("got %q; the response was discarded although the mutation succeeded", resp)
	}
	if err == nil {
		t.Fatal("the failure to record the response was swallowed; nothing reports that this " +
			"key is now un-replayable")
	}
}

// Different keys execute independently.
func TestDifferentKeysBothExecute(t *testing.T) {
	store := newStore()
	o := once(t, store)
	calls := 0

	if _, err := o.Do(context.Background(), scope("k1"), []byte(`{}`), returns("a", &calls)); err != nil {
		t.Fatalf("k1: %v", err)
	}
	if _, err := o.Do(context.Background(), scope("k2"), []byte(`{}`), returns("b", &calls)); err != nil {
		t.Fatalf("k2: %v", err)
	}
	if calls != 2 {
		t.Fatalf("the handler ran %d times for two distinct keys", calls)
	}
}

// A key reused with a different body is refused even while the FIRST request is
// still running.
//
// The completed case is the obvious one; this is the same client bug arriving a
// few milliseconds earlier. Left unchecked it falls through to the in-flight
// path, where the caller either waits for — and then receives — a response to
// somebody else's request, or executes a second mutation under a key that is
// about to record a different one.
func TestAReusedKeyIsRefusedWhileTheFirstIsStillRunning(t *testing.T) {
	store := newStore()
	o, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store, Wait: time.Second})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}
	s := scope("k1")

	// A claim taken with one body and never completed.
	if _, cerr := store.Claim(context.Background(), s,
		cqrs.Fingerprint([]byte(`{"name":"eng"}`)), time.Hour); cerr != nil {
		t.Fatalf("Claim: %v", cerr)
	}

	calls := 0
	resp, err := o.Do(context.Background(), s, []byte(`{"name":"sales"}`), returns("ws_2", &calls))
	if !errors.Is(err, cqrs.ErrKeyReused) {
		t.Fatalf("got (%q, %v); want ErrKeyReused — a different body under a running claim "+
			"must be refused immediately, not queued behind it", resp, err)
	}
	if calls != 0 {
		t.Fatal("a second mutation executed under a key that is about to record a different one")
	}
}

// The in-flight wait is bounded from the FIRST observation, not reset on every
// poll — otherwise a duplicate waits forever behind a stuck request.
//
// The poll cap is what makes a broken bound FAIL rather than HANG. Without it a
// deadline reset on every iteration spins until go test's ten-minute panic,
// which reports as a timeout rather than as this property being broken.
func TestTheInFlightWaitIsBounded(t *testing.T) {
	store := newStore()
	const maxPolls = 20
	polls := 0
	o, err := cqrs.NewOnce(cqrs.OnceDeps{
		Store: store,
		Wait:  30 * time.Millisecond,
		Sleep: func(_ context.Context, _ time.Duration) bool {
			polls++
			if polls > maxPolls {
				t.Errorf("the executor polled more than %d times for a %s wait: the deadline "+
					"is being reset on every poll, so a duplicate waits forever behind a "+
					"stuck request", maxPolls, 30*time.Millisecond)
				return false
			}
			time.Sleep(10 * time.Millisecond)
			return true
		},
	})
	if err != nil {
		t.Fatalf("NewOnce: %v", err)
	}

	s := scope("k1")
	// A claim that is never completed.
	if _, cerr := store.Claim(context.Background(), s, cqrs.Fingerprint([]byte(`{}`)), time.Hour); cerr != nil {
		t.Fatalf("Claim: %v", cerr)
	}

	calls := 0
	_, err = o.Do(context.Background(), s, []byte(`{}`), returns("x", &calls))
	if !errors.Is(err, cqrs.ErrInFlight) {
		t.Fatalf("got %v, want ErrInFlight after the wait expired", err)
	}
	if calls != 0 {
		t.Fatal("the duplicate executed after waiting")
	}
	if polls == 0 {
		t.Fatal("the executor never waited at all, so the bound is untested")
	}
}

// Key.Validate is the rule BOTH paths use, and the public path is the one with
// no other protection.
//
// An authenticated mutation reaches this rule through Scope.Validate, with a
// store claim behind it. A PUBLIC mutation has no principal, builds no scope and
// claims nothing — `Gates.WrapUnary` calls Key.Validate directly and then uses
// the key as the command's causation id. So for public writes this function is
// the entire bound on a client-supplied header that ends up in an append-only
// log, which is why it is tested apart from the scope that usually carries it.
func TestKeyValidate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		key  cqrs.Key
		ok   bool
	}{
		{name: "a ULID", key: "01ARZ3NDEKTSV4RRFFQ69G5FAV", ok: true},
		{name: "a UUID", key: "6ba7b810-9dad-11d1-80b4-00c04fd430c8", ok: true},
		{name: "any other bounded text", key: "idem_evt_01ARZ3NDEKTSV4RRFFQ69G5FAV", ok: true},
		{name: "exactly the maximum", key: cqrs.Key(strings.Repeat("A", cqrs.MaxKeyLen)), ok: true},
		{name: "empty"},
		{name: "one past the maximum", key: cqrs.Key(strings.Repeat("A", cqrs.MaxKeyLen+1))},
		{name: "carrying the scope separator", key: "01ARZ3NDEKTSV4RRFFQ69G5FAV|other"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.key.Validate()
			if tt.ok && err != nil {
				t.Errorf("Validate(%q) = %v, want nil", tt.key, err)
			}
			if !tt.ok {
				if err == nil {
					t.Errorf("Validate(%q) = nil; the key reaches the event log unbounded", tt.key)
				} else if !errors.Is(err, cqrs.ErrInvalid) {
					t.Errorf("Validate(%q) = %v, which does not wrap ErrInvalid — callers "+
						"branch on that to answer VALIDATION_FAILED", tt.key, err)
				}
			}
		})
	}
}

// The published ceiling and the enforced one are the same number.
//
// internal/tools/checkopenapi asserts the OpenAPI document says MaxKeyLen; this
// asserts the value itself is one a documented key can actually reach, so the two
// documented forms are not silently refused by the bound that is supposed to
// admit them.
func TestMaxKeyLenAdmitsBothDocumentedForms(t *testing.T) {
	t.Parallel()

	for _, k := range []cqrs.Key{
		"01ARZ3NDEKTSV4RRFFQ69G5FAV",           // ULID, 26
		"6ba7b810-9dad-11d1-80b4-00c04fd430c8", // UUID, 36
	} {
		if len(k) > cqrs.MaxKeyLen {
			t.Errorf("MaxKeyLen (%d) refuses %q (%d), which the contract recommends",
				cqrs.MaxKeyLen, k, len(k))
		}
	}
}
