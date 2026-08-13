// Package ratelimit is the attempt ceiling: a fixed-window counter over a port,
// with several windows evaluated together.
//
// # Why several windows rather than one
//
// A single rule cannot express both shapes of abuse. "Five attempts a minute"
// stops a burst and permits 7,200 attempts a day against one address. "Two
// hundred a day" stops the grind and lets an attacker fire two hundred in one
// second. Real policies need both, so a rule is a list and the STRICTEST answer
// wins.
//
// # Why fixed windows and not a token bucket
//
// A fixed window is one INCR. A token bucket needs a stored timestamp and a
// read-modify-write, which is either a round trip plus a race or a script that
// has to be correct. The cost of the simpler choice is the boundary burst: a
// caller can spend a full window's budget at the end of one window and again at
// the start of the next, so the real worst case is 2× the stated limit across
// the boundary. That is acceptable for an attempt ceiling — the number is a
// deterrent, not a guarantee — and stating it is better than implying a
// precision the mechanism does not have.
package ratelimit

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// Counter is the atomic increment this depends on.
//
// Atomicity is the entire contract. An implementation that reads then writes
// lets two simultaneous attempts both observe the pre-increment value, which is
// exactly the concurrency an attacker produces.
//
// The TTL must be applied in the SAME operation as the increment. A separate
// EXPIRE leaves a window in which a crash strands a key with no expiry — and
// everything in the cache must expire (INFRA), because FLUSHALL has to be
// survivable and a permanent counter would silently ban an address forever.
type Counter interface {
	Incr(ctx context.Context, key string, window time.Duration) (count int64, err error)
}

// Rule is one window.
type Rule struct {
	// Name appears in the decision and in logs, so an operator can tell which
	// window tripped without recomputing them.
	Name string

	// Limit is the number of attempts permitted within Window.
	Limit int64

	Window time.Duration
}

func (r Rule) validate() error {
	switch {
	case strings.TrimSpace(r.Name) == "":
		return errors.New("ratelimit: a rule needs a name; an unnamed rule produces a refusal " +
			"nobody can trace to a policy")
	case r.Limit < 1:
		return fmt.Errorf("ratelimit: rule %q has a limit of %d, which refuses everything "+
			"including the first attempt", r.Name, r.Limit)
	case r.Window <= 0:
		return fmt.Errorf("ratelimit: rule %q has a non-positive window", r.Name)
	}
	return nil
}

// Decision is the outcome of a check.
type Decision struct {
	// allowed is unexported and the zero value is FALSE, so a Decision nobody
	// filled in denies. Same discipline as authz.Decision: a forgotten branch, a
	// short read and an ignored error all deny by construction.
	allowed bool

	// Rule is the window that tripped, empty when allowed.
	Rule string

	// RetryAfter is how long until the tripped window rolls over. It is an upper
	// bound: the window may have started before this attempt.
	RetryAfter time.Duration

	// Degraded reports that the counter could not be consulted and the attempt
	// was allowed anyway. See Limiter.Allow.
	Degraded bool
}

// Allowed reports whether the attempt may proceed.
func (d Decision) Allowed() bool { return d.allowed }

// Limiter evaluates a set of rules against a scope.
type Limiter struct {
	counter Counter
	rules   []Rule
	prefix  string
}

// New builds a limiter.
//
// Rules are sorted shortest-window-first so the cheapest and most likely refusal
// is evaluated before the expensive ones — a burst trips the short window, and
// stopping there saves the round trips for the longer ones.
func New(counter Counter, prefix string, rules ...Rule) (*Limiter, error) {
	if counter == nil {
		return nil, errors.New("ratelimit: a limiter needs a counter; without one every " +
			"attempt is unlimited and nothing reports it")
	}
	if strings.TrimSpace(prefix) == "" {
		// The prefix namespaces keys. Without one, a login attempt and an API-key
		// attempt for the same identifier share a counter, and each consumes the
		// other's budget.
		return nil, errors.New("ratelimit: a key prefix is required")
	}
	if len(rules) == 0 {
		return nil, errors.New("ratelimit: a limiter with no rules permits everything; " +
			"declare the policy rather than defaulting to none")
	}
	seen := make(map[string]bool, len(rules))
	for _, r := range rules {
		if err := r.validate(); err != nil {
			return nil, err
		}
		if seen[r.Name] {
			return nil, fmt.Errorf("ratelimit: two rules are named %q; the decision could not "+
				"say which one refused", r.Name)
		}
		seen[r.Name] = true
	}
	ordered := make([]Rule, len(rules))
	copy(ordered, rules)
	sort.Slice(ordered, func(i, j int) bool { return ordered[i].Window < ordered[j].Window })

	return &Limiter{counter: counter, rules: ordered, prefix: prefix}, nil
}

// Allow records an attempt against a scope and reports whether it may proceed.
//
// The attempt is COUNTED whether or not it is allowed. Counting only the allowed
// ones would let an attacker who is already over the limit keep trying for free,
// with the counter frozen at exactly the threshold.
//
// # Fail-open, and what it depends on
//
// When the counter cannot be reached, the attempt is ALLOWED and the decision is
// marked Degraded. That is a real trade and it rests on two other controls:
//
//   - The password hasher is concurrency-bounded, so an unthrottled burst cannot
//     exhaust memory however many attempts arrive.
//   - A second factor is MANDATORY before an account activates (identity.md §2),
//     so guessing a password alone does not produce a session.
//
// If either of those changes — particularly if password-only authentication ever
// becomes reachable — this decision has to be revisited, because unthrottled
// guessing would then be sufficient on its own. Failing closed instead would mean
// an outage of the counter is a total authentication outage, which is the more
// likely event by a wide margin.
//
// The caller must surface Degraded. A ceiling that silently stopped counting is
// indistinguishable from one that is never reached.
func (l *Limiter) Allow(ctx context.Context, scope string) (Decision, error) {
	if strings.TrimSpace(scope) == "" {
		// An empty scope would put every caller in one bucket, so the first few
		// attempts anywhere would exhaust the budget for everyone.
		return Decision{}, errors.New("ratelimit: a scope is required")
	}

	for _, rule := range l.rules {
		key := l.prefix + ":" + rule.Name + ":" + scope
		count, err := l.counter.Incr(ctx, key, rule.Window)
		if err != nil {
			return Decision{allowed: true, Degraded: true},
				fmt.Errorf("ratelimit: rule %q could not be evaluated: %w", rule.Name, err)
		}
		if count > rule.Limit {
			return Decision{
				allowed:    false,
				Rule:       rule.Name,
				RetryAfter: rule.Window,
			}, nil
		}
	}
	return Decision{allowed: true}, nil
}

// Rules reports the configured policy, shortest window first. For the
// composition-root test that asserts a policy was actually configured.
func (l *Limiter) Rules() []Rule {
	out := make([]Rule, len(l.rules))
	copy(out, l.rules)
	return out
}
