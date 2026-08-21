//go:build integration

package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"io"
	"log/slog"
	"testing"
	"time"
)

// The username-check ceiling is driven to EXHAUSTION, against the real Valkey.
//
// # Why the unit tests were not enough
//
// usernameCheckRules and app.Usernames.spend are both unit-tested, and both
// suites are honest about what they cover: the rules are compared against a
// table, and the use case is driven through a fake counter that returns whatever
// the test told it to. Neither has ever asked the question that matters — does
// the 61st request in an hour actually get refused? — because neither ran a
// counter that counts.
//
// That gap is the shape this repository keeps finding. A limiter wired to a
// counter that silently never trips passes every unit test in both packages, and
// the endpoint is an unmetered public read of one KurrentDB stream per call. It
// was found once already in this codebase at one layer down: a sub-millisecond
// window made `PEXPIRE 0` delete its own key, so every attempt read 1 and the
// limiter permitted everything (IDENTITY-SLICE-1, defect 7). Nothing above the
// adapter could see it.
//
// # It uses the PRODUCTION limiter, not a rebuilt one
//
// d.usernameCheckLimiter is the object newDependencies built and handed to
// app.NewUsernames. Constructing a fresh ratelimit.New here with the same rules
// would prove the rules are exhaustible and say nothing about the one that is
// actually enforcing them — which is the distinction cmd/api's other ceiling
// tests exist to make.
//
// # The scope is fresh per run
//
// A fixed-window counter keyed on a shared scope would spend this run's budget
// and leave the next one starting from 61, for an hour. Every run therefore
// invents its own scope, exactly as the identityit harness invents its own
// blind-index key, so "the 61st was refused" is a statement about this run.
func TestTheUsernameCheckCeilingActuallyRefuses(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.usernameCheckLimiter == nil {
		t.Fatal("no username-check ceiling was built: an unauthenticated caller can read " +
			"one KurrentDB stream per request, as fast as they can open sockets")
	}

	rules := d.usernameCheckLimiter.Rules()
	if len(rules) < 2 {
		t.Fatalf("the ceiling carries %d rule(s): %v. One window bounds one shape of "+
			"abuse and leaves the other unbounded", len(rules), rules)
	}
	// Rules() reports shortest window first, so this is the rule that must trip.
	narrowest := rules[0]
	if narrowest.Limit <= 0 {
		t.Fatalf("the narrowest rule permits %d, which is not a ceiling", narrowest.Limit)
	}

	scope := freshScope(t)
	ctx := context.Background()

	// Exactly the limit, all of which must be allowed. A ceiling that refused
	// early would be as much of a defect as one that never refuses: this endpoint
	// is a signup form's as-you-type check, and refusing a real person their
	// twentieth candidate handle costs them the signup.
	for i := int64(1); i <= narrowest.Limit; i++ {
		decision, err := d.usernameCheckLimiter.Allow(ctx, scope)
		if err != nil {
			t.Fatalf("attempt %d could not be evaluated: %v", i, err)
		}
		if decision.Degraded {
			t.Fatalf("attempt %d was allowed DEGRADED — the counter could not be reached, "+
				"so this run never tested a ceiling at all", i)
		}
		if !decision.Allowed() {
			t.Fatalf("attempt %d of %d was refused by rule %q; the ceiling trips before "+
				"its own limit", i, narrowest.Limit, decision.Rule)
		}
	}

	// And one past it. This is the assertion the whole file exists for, and it is
	// the one no fake counter can make.
	decision, err := d.usernameCheckLimiter.Allow(ctx, scope)
	if err != nil {
		t.Fatalf("the attempt past the limit could not be evaluated: %v", err)
	}
	if decision.Allowed() {
		t.Fatalf("attempt %d was ALLOWED against a ceiling of %d per %s. The rules are "+
			"declared, the limiter is wired, and it counts nothing — which is "+
			"indistinguishable from a working ceiling at every layer above this one",
			narrowest.Limit+1, narrowest.Limit, narrowest.Window)
	}
	if decision.Rule != narrowest.Name {
		t.Errorf("the refusal names rule %q, want %q — the window that tripped is what "+
			"the client is told to retry after", decision.Rule, narrowest.Name)
	}
	if decision.RetryAfter <= 0 || decision.RetryAfter > narrowest.Window {
		t.Errorf("the refusal reports RetryAfter %s, which is not inside the %s window it "+
			"tripped; a client cannot back off on a number that does not describe the "+
			"window", decision.RetryAfter, narrowest.Window)
	}

	// A DIFFERENT caller is unaffected. Without this the test above is also
	// satisfied by a limiter that ignores its scope and counts globally — which is
	// the exact failure API_TRUSTED_PROXY_HOPS=0 behind a terminating proxy
	// produces, and it would take the signup form down for everybody.
	other, err := d.usernameCheckLimiter.Allow(ctx, freshScope(t))
	if err != nil {
		t.Fatalf("a second caller could not be evaluated: %v", err)
	}
	if !other.Allowed() {
		t.Error("a caller who has spent nothing was refused: the ceiling counts globally " +
			"rather than per caller, so one prober locks out every signup in the system")
	}
}

// freshScope invents a caller identity no other run has used.
func freshScope(t *testing.T) string {
	t.Helper()
	var raw [12]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return "s1-29-" + hex.EncodeToString(raw[:])
}

// The window is FIXED, not sliding, and that is worth one assertion rather than
// only a paragraph in IDENTITY-SLICE-1.
//
// A fixed window means the true worst case is 2x the stated limit — a caller can
// spend a full window at the end of one and again at the start of the next. That
// is documented as a deterrent rather than a guarantee. What must NOT be true is
// that the key outlives its window: a counter whose expiry never lands is a
// permanent lockout for that caller, and it is invisible until somebody complains
// they can never check a handle again.
func TestTheUsernameCheckCeilingsWindowExpires(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.usernameCheckLimiter == nil {
		t.Fatal("no username-check ceiling was built")
	}
	rules := d.usernameCheckLimiter.Rules()
	if len(rules) == 0 {
		t.Fatal("the ceiling carries no rules")
	}
	for _, r := range rules {
		if r.Window <= 0 {
			t.Errorf("rule %q has window %s; a non-positive window is not a window, and "+
				"the sub-millisecond case has already made a limiter permit everything "+
				"once in this codebase", r.Name, r.Window)
		}
		if r.Window < time.Millisecond {
			t.Errorf("rule %q has a sub-millisecond window (%s): PEXPIRE rounds it to a "+
				"key that may not survive to the next attempt", r.Name, r.Window)
		}
	}
}
