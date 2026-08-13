package ratelimit_test

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// counter is an in-memory fixed-window counter.
type counter struct {
	mu     sync.Mutex
	counts map[string]int64
	ttls   map[string]time.Duration
	fail   error
	calls  []string
}

func newCounter() *counter {
	return &counter{counts: map[string]int64{}, ttls: map[string]time.Duration{}}
}

func (c *counter) Incr(_ context.Context, key string, window time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.calls = append(c.calls, key)
	if c.fail != nil {
		return 0, c.fail
	}
	c.counts[key]++
	if c.counts[key] == 1 {
		c.ttls[key] = window
	}
	return c.counts[key], nil
}

func (c *counter) keys() []string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]string(nil), c.calls...)
}

func newLimiter(t *testing.T, c *counter, rules ...ratelimit.Rule) *ratelimit.Limiter {
	t.Helper()
	l, err := ratelimit.New(c, "login", rules...)
	if err != nil {
		t.Fatalf("limiter: %v", err)
	}
	return l
}

// Attempts are permitted up to the limit and refused past it.
func TestAttemptsAreRefusedPastTheLimit(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute})

	for i := 1; i <= 3; i++ {
		d, err := l.Allow(ctx, "usr_1")
		if err != nil {
			t.Fatalf("attempt %d: %v", i, err)
		}
		if !d.Allowed() {
			t.Fatalf("attempt %d of 3 was refused", i)
		}
	}

	d, err := l.Allow(ctx, "usr_1")
	if err != nil {
		t.Fatalf("fourth attempt: %v", err)
	}
	if d.Allowed() {
		t.Fatal("the fourth attempt against a limit of 3 was permitted")
	}
	if d.Rule != "burst" {
		t.Errorf("the decision names rule %q, want \"burst\"; an operator cannot tell which "+
			"window tripped", d.Rule)
	}
	if d.RetryAfter != time.Minute {
		t.Errorf("RetryAfter is %v, want %v", d.RetryAfter, time.Minute)
	}
}

// A refused attempt is still COUNTED.
//
// Counting only the allowed ones freezes the counter at exactly the threshold,
// so an attacker who is already over the limit keeps trying for free — and every
// subsequent attempt reads the same value, which never grows into any longer
// window either.
func TestRefusedAttemptsAreStillCounted(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 2, Window: time.Minute})

	for range 10 {
		if _, err := l.Allow(ctx, "usr_1"); err != nil {
			t.Fatalf("allow: %v", err)
		}
	}
	c.mu.Lock()
	got := c.counts["login:burst:usr_1"]
	c.mu.Unlock()

	if got != 10 {
		t.Fatalf("the counter reached %d after 10 attempts: attempts past the limit are not "+
			"counted, so an attacker over the ceiling keeps trying at no cost", got)
	}
}

// Scopes do not share a budget.
func TestScopesAreIndependent(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 2, Window: time.Minute})

	for range 3 {
		if _, err := l.Allow(ctx, "usr_1"); err != nil {
			t.Fatal(err)
		}
	}
	d, err := l.Allow(ctx, "usr_2")
	if err != nil {
		t.Fatal(err)
	}
	if !d.Allowed() {
		t.Fatal("one identifier's attempts exhausted another's budget: a single attacker " +
			"locks out every user")
	}
}

// The STRICTEST rule wins, and both shapes of abuse are covered.
//
// One rule cannot express both: a per-minute limit permits thousands a day, and
// a per-day limit permits all of them in one second.
func TestTheStrictestRuleDecides(t *testing.T) {
	ctx := context.Background()

	t.Run("a burst trips the short window", func(t *testing.T) {
		c := newCounter()
		l := newLimiter(t, c,
			ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute},
			ratelimit.Rule{Name: "daily", Limit: 100, Window: 24 * time.Hour},
		)
		var refused ratelimit.Decision
		for range 5 {
			d, err := l.Allow(ctx, "usr_1")
			if err != nil {
				t.Fatal(err)
			}
			if !d.Allowed() {
				refused = d
			}
		}
		if refused.Rule != "burst" {
			t.Fatalf("a burst was refused by rule %q, want \"burst\"", refused.Rule)
		}
	})

	t.Run("a grind trips the long window", func(t *testing.T) {
		c := newCounter()
		l := newLimiter(t, c,
			ratelimit.Rule{Name: "burst", Limit: 1000, Window: time.Minute},
			ratelimit.Rule{Name: "daily", Limit: 4, Window: 24 * time.Hour},
		)
		var refused ratelimit.Decision
		for range 6 {
			d, err := l.Allow(ctx, "usr_1")
			if err != nil {
				t.Fatal(err)
			}
			if !d.Allowed() {
				refused = d
			}
		}
		if refused.Rule != "daily" {
			t.Fatalf("a slow grind was refused by rule %q, want \"daily\": the long window is "+
				"not being evaluated, so an attacker paces themselves under the burst limit "+
				"and gets unlimited attempts", refused.Rule)
		}
	})
}

// The zero Decision denies.
//
// Same discipline as authz.Decision: a forgotten branch, a short read and an
// ignored error must all deny by construction rather than by remembering to.
func TestTheZeroDecisionDenies(t *testing.T) {
	var d ratelimit.Decision
	if d.Allowed() {
		t.Fatal("the zero Decision permits: any code path that returns one without setting " +
			"it explicitly silently disables the ceiling")
	}
}

// An unreachable counter FAILS OPEN, marked Degraded, with an error.
//
// The trade is documented on Limiter.Allow and rests on the hasher's concurrency
// bound and on the mandatory second factor. What must not happen is failing open
// SILENTLY — a ceiling that stopped counting looks exactly like one never reached.
func TestAnUnreachableCounterFailsOpenLoudly(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	c.fail = errors.New("valkey is unreachable")
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute})

	d, err := l.Allow(ctx, "usr_1")
	if !d.Allowed() {
		t.Fatal("an unreachable counter refused the attempt: an outage of the rate limiter " +
			"becomes a total authentication outage")
	}
	if !d.Degraded {
		t.Fatal("a fail-open decision was not marked Degraded: the ceiling silently stopped " +
			"counting and nothing distinguishes that from it never being reached")
	}
	if err == nil {
		t.Fatal("an unreachable counter reported no error")
	}
}

// A healthy decision is not marked Degraded.
func TestAHealthyDecisionIsNotDegraded(t *testing.T) {
	ctx := context.Background()
	l := newLimiter(t, newCounter(), ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute})

	d, err := l.Allow(ctx, "usr_1")
	if err != nil {
		t.Fatal(err)
	}
	if d.Degraded {
		t.Error("a successful check was marked Degraded, so the signal means nothing")
	}
}

// Keys are namespaced by prefix, rule and scope.
//
// Without the prefix, a login attempt and an API-key attempt for the same
// identifier share a counter and each consumes the other's budget.
func TestKeysAreNamespaced(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 5, Window: time.Minute})

	if _, err := l.Allow(ctx, "usr_1"); err != nil {
		t.Fatal(err)
	}
	keys := c.keys()
	if len(keys) != 1 {
		t.Fatalf("made %d increments, want 1", len(keys))
	}
	for _, part := range []string{"login", "burst", "usr_1"} {
		if !strings.Contains(keys[0], part) {
			t.Errorf("the key %q does not contain %q", keys[0], part)
		}
	}
}

// The TTL is set on the FIRST increment and not extended afterwards.
//
// Refreshing it every time turns a fixed window into a sliding ban: an attacker
// at one attempt per second holds the counter above the limit forever, and so
// does a stuck client retrying in a loop.
func TestTheWindowIsNotExtendedByLaterAttempts(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 100, Window: time.Minute})

	for range 5 {
		if _, err := l.Allow(ctx, "usr_1"); err != nil {
			t.Fatal(err)
		}
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.ttls["login:burst:usr_1"]; got != time.Minute {
		t.Fatalf("the window is %v after five attempts, want %v", got, time.Minute)
	}
}

// A misconfigured limiter refuses to build.
//
// Each of these produces a limiter that permits everything or refuses
// everything, and both are invisible at runtime.
func TestAMisconfiguredLimiterRefusesToBuild(t *testing.T) {
	c := newCounter()

	if _, err := ratelimit.New(nil, "login", ratelimit.Rule{Name: "a", Limit: 1, Window: time.Minute}); err == nil {
		t.Error("a limiter was built with no counter: every attempt is unlimited")
	}
	if _, err := ratelimit.New(c, ""); err == nil {
		t.Error("a limiter was built with no prefix")
	}
	if _, err := ratelimit.New(c, "login"); err == nil {
		t.Error("a limiter was built with no rules: it permits everything, which reads as a " +
			"configured ceiling and is not one")
	}
	for _, tc := range []struct {
		name string
		rule ratelimit.Rule
	}{
		{"unnamed", ratelimit.Rule{Limit: 1, Window: time.Minute}},
		{"zero limit", ratelimit.Rule{Name: "a", Limit: 0, Window: time.Minute}},
		{"negative limit", ratelimit.Rule{Name: "a", Limit: -1, Window: time.Minute}},
		{"zero window", ratelimit.Rule{Name: "a", Limit: 1}},
		{"negative window", ratelimit.Rule{Name: "a", Limit: 1, Window: -time.Minute}},
	} {
		if _, err := ratelimit.New(c, "login", tc.rule); err == nil {
			t.Errorf("a limiter was built with a %s rule", tc.name)
		}
	}

	if _, err := ratelimit.New(c, "login",
		ratelimit.Rule{Name: "dup", Limit: 1, Window: time.Minute},
		ratelimit.Rule{Name: "dup", Limit: 9, Window: time.Hour},
	); err == nil {
		t.Error("two rules with the same name were accepted: they share a key, so the shorter " +
			"window's counter is consumed by the longer one and the decision cannot say which " +
			"refused")
	}
}

// An empty scope is refused rather than pooling everyone into one bucket.
func TestAnEmptyScopeIsRefused(t *testing.T) {
	l := newLimiter(t, newCounter(), ratelimit.Rule{Name: "burst", Limit: 5, Window: time.Minute})
	for _, scope := range []string{"", "   "} {
		if _, err := l.Allow(context.Background(), scope); err == nil {
			t.Errorf("scope %q was accepted: every caller shares one counter, so the first few "+
				"attempts anywhere exhaust the budget for everyone", scope)
		}
	}
}

// Rules are reported shortest window first, so the cheapest refusal is checked
// first and a composition-root test can assert a policy exists.
func TestRulesAreOrderedShortestWindowFirst(t *testing.T) {
	l := newLimiter(t, newCounter(),
		ratelimit.Rule{Name: "daily", Limit: 100, Window: 24 * time.Hour},
		ratelimit.Rule{Name: "burst", Limit: 3, Window: time.Minute},
		ratelimit.Rule{Name: "hourly", Limit: 20, Window: time.Hour},
	)
	rules := l.Rules()
	if len(rules) != 3 {
		t.Fatalf("reported %d rules, want 3", len(rules))
	}
	for i := 1; i < len(rules); i++ {
		if rules[i-1].Window > rules[i].Window {
			t.Fatalf("rule %q (%v) precedes %q (%v): the expensive long window is evaluated "+
				"before the cheap short one", rules[i-1].Name, rules[i-1].Window,
				rules[i].Name, rules[i].Window)
		}
	}
}

// Evaluation stops at the first refusal.
//
// Continuing would charge every longer window for an attempt already refused,
// so a burst would consume the daily budget it never got to use.
func TestEvaluationStopsAtTheFirstRefusal(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c,
		ratelimit.Rule{Name: "burst", Limit: 1, Window: time.Minute},
		ratelimit.Rule{Name: "daily", Limit: 100, Window: 24 * time.Hour},
	)

	if _, err := l.Allow(ctx, "usr_1"); err != nil { // allowed, charges both
		t.Fatal(err)
	}
	for range 5 { // refused by burst
		if _, err := l.Allow(ctx, "usr_1"); err != nil {
			t.Fatal(err)
		}
	}

	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.counts["login:daily:usr_1"]; got != 1 {
		t.Fatalf("the daily counter reached %d, want 1: refused attempts are charged to every "+
			"longer window, so a burst silently consumes the whole day's budget", got)
	}
}

// Concurrent attempts are all counted.
func TestConcurrentAttemptsAreAllCounted(t *testing.T) {
	ctx := context.Background()
	c := newCounter()
	l := newLimiter(t, c, ratelimit.Rule{Name: "burst", Limit: 1000, Window: time.Minute})

	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, err := l.Allow(ctx, "usr_1"); err != nil {
				t.Error(err)
			}
		}()
	}
	wg.Wait()

	c.mu.Lock()
	defer c.mu.Unlock()
	if got := c.counts["login:burst:usr_1"]; got != 50 {
		t.Fatalf("50 concurrent attempts produced a count of %d: attempts are lost under "+
			"concurrency, which is exactly the load an attacker generates", got)
	}
}
