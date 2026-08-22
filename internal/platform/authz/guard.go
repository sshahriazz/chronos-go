package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Tombstones record revocations that must take effect before the projector has
// caught up.
//
// Grants and revokes have opposite risk profiles, so they use opposite
// mechanisms (access.md §6.1). Being late to GRANT costs someone a moment of not
// seeing their own new access — harmless. Being late to REVOKE is a security
// failure, so a denial must never wait for a projector.
//
// A tombstone can therefore only ever produce a DENY. There is no shape of this
// interface that can grant anything, which is what makes consulting an
// eventually-consistent store on the hot path safe.
type Tombstones interface {
	// Revoked reports whether this exact access has been revoked ahead of the
	// projector. An error means "unknown", and unknown denies.
	Revoked(ctx context.Context, q Query) (bool, error)
}

// Revoker LAYS a tombstone, which is the half of the mechanism the Guard never
// touches.
//
// Split from Tombstones for the same reason Revocations is split from it: the
// hot path may only ever ASK, and an interface it holds that could also write
// one is an interface a bug on the read path can use to deny everybody. Three
// interfaces over one store, each naming exactly one verb — ask (Guard), lay
// (the command that revokes), clear (the projector that confirms).
//
// The command handler that removes a grant is what implements the caller side.
// Being late to revoke is a security failure (access.md §6.1), so the denial has
// to exist before the projector has seen the event that causes it.
type Revoker interface {
	// Revoke denies this exact access from now until a projector confirms the
	// tuple behind it is gone. Never cleared by a timer (ADR-045).
	Revoke(ctx context.Context, q Query) error
}

// Decisions caches POSITIVE decisions only.
//
// A deny is never cached: it must be able to become an allow the instant a grant
// lands, and a cached refusal would outlive the grant that fixed it. The
// asymmetry is the whole design — caching in the permissive direction is bounded
// by the revocation epoch, caching in the restrictive direction is bounded by
// nothing a user can do.
type Decisions interface {
	// Allowed reports a cached permit. Absence and error are both "not cached".
	Allowed(ctx context.Context, q Query, epoch uint64) (bool, error)

	// Remember stores a permit under the subject's current epoch. Any revocation
	// affecting that subject bumps the epoch, which invalidates every decision
	// cached for them at once — conservative and O(1), rather than working out
	// which entries to evict.
	Remember(ctx context.Context, q Query, epoch uint64, ttl time.Duration) error

	// Epoch returns the principal's current revocation epoch. An error must
	// yield an epoch nothing can match, so a cache that cannot be reasoned about
	// is a cache that is skipped rather than trusted.
	Epoch(ctx context.Context, p Principal) (uint64, error)
}

// Observer records authorization outcomes. Plain strings, so a metrics
// implementation satisfies it structurally without importing the kernel.
type Observer interface {
	Allowed(relation, resourceType, source string)
	Denied(relation, resourceType, reason string)
	// Failed counts checks that could not be evaluated. Every one of them
	// DENIED, so this is the metric that distinguishes "refused" from "broken".
	Failed(relation, resourceType string)
}

type noObserver struct{}

func (noObserver) Allowed(string, string, string) {}
func (noObserver) Denied(string, string, string)  {}
func (noObserver) Failed(string, string)          {}

// Guard is the only thing application code should hold.
//
// It composes the checker, the revocation tombstones and the decision cache in
// the one order that is safe, and it converts every failure into a denial. A
// handler that talked to a Checker directly would have to remember to do that
// itself, and the first one to forget would turn an outage into an escalation.
type Guard struct {
	checker Checker
	tombs   Tombstones
	cache   Decisions
	ttl     time.Duration
	obs     Observer
	log     *slog.Logger
}

// GuardDeps is what a Guard needs. Only Checker is required.
type GuardDeps struct {
	// Checker is required. A nil one is refused at construction rather than
	// producing a Guard that denies everything for a reason nobody can find.
	Checker Checker

	// Tombstones makes revocation immediate. Optional, and its absence is a
	// REAL weakening: without it a revoked user keeps access until the projector
	// removes the tuple. NewGuard logs that plainly.
	Tombstones Tombstones

	// Decisions caches permits. Optional; without it every check is a round trip.
	Decisions Decisions

	// CacheTTL bounds a cached permit. Zero takes DefaultDecisionTTL.
	CacheTTL time.Duration

	Observer Observer
	Log      *slog.Logger
}

// DefaultDecisionTTL bounds a cached permit even if its epoch is never bumped.
// Short, because it is the window in which a revocation that failed to bump the
// epoch still grants access.
const DefaultDecisionTTL = 5 * time.Minute

// MaxDecisionTTL caps CacheTTL. A permit cached for longer than this is a
// revocation that has not taken effect, and no performance argument outweighs
// that.
const MaxDecisionTTL = 15 * time.Minute

func NewGuard(d GuardDeps) (*Guard, error) {
	if d.Checker == nil {
		return nil, fmt.Errorf("authz: a Checker is required")
	}
	if d.CacheTTL <= 0 {
		d.CacheTTL = DefaultDecisionTTL
	}
	if d.CacheTTL > MaxDecisionTTL {
		return nil, fmt.Errorf("authz: a decision TTL of %s exceeds the %s cap: it is the "+
			"window in which a revoked principal keeps access", d.CacheTTL, MaxDecisionTTL)
	}
	if d.Observer == nil {
		d.Observer = noObserver{}
	}
	if d.Log == nil {
		d.Log = slog.Default()
	}
	g := &Guard{
		checker: d.Checker, tombs: d.Tombstones, cache: d.Decisions,
		ttl: d.CacheTTL, obs: d.Observer, log: d.Log,
	}
	if d.Tombstones == nil {
		d.Log.Warn("authz: no revocation tombstones are wired; a revoked principal keeps " +
			"access until the access projector removes the tuple")
	}
	return g, nil
}

// HasTombstones reports whether immediate revocation is wired. Exposed so the
// composition root can be asserted rather than assumed — an absent port here is
// invisible at runtime and only shows up as a revocation that did not take.
func (g *Guard) HasTombstones() bool { return g.tombs != nil }

// HasCache reports whether positive decisions are cached.
func (g *Guard) HasCache() bool { return g.cache != nil }

// Check answers one question, denying on any doubt.
//
// The order is the design:
//
//  1. Validate. A malformed query is a programming error and is never sent on.
//  2. Consult the decision cache. Permits only.
//  3. Ask the authorization service. Any error denies.
//  4. If and only if the answer is ALLOW, consult the tombstones.
//  5. Cache the permit.
//
// Step 4 runs only on allow because a deny needs no second opinion — that keeps
// the extra lookup off the majority path, and it cannot weaken anything: a
// tombstone can only turn an allow into a deny.
func (g *Guard) Check(ctx context.Context, q Query) Decision {
	if err := q.Validate(); err != nil {
		g.obs.Failed(string(q.Relation), q.Resource.Type)
		g.log.Error("authz: refusing a malformed query", "error", err,
			"relation", q.Relation, "resource", q.Resource.String())
		return Deny("invalid query")
	}

	epoch, cacheUsable := g.epochFor(ctx, q.Principal)

	if g.cache != nil && cacheUsable {
		if ok, err := g.cache.Allowed(ctx, q, epoch); err != nil {
			// A cache that cannot answer is skipped, never trusted, and never
			// fatal: the source of truth is one round trip away.
			g.log.Debug("authz: decision cache unavailable", "error", err)
		} else if ok {
			// A cached permit still has to survive the tombstone check, or a
			// revocation would not take effect until the entry expired.
			if denied, reason := g.revoked(ctx, q); denied {
				g.obs.Denied(string(q.Relation), q.Resource.Type, reason)
				return Deny(reason)
			}
			g.obs.Allowed(string(q.Relation), q.Resource.Type, "cache")
			return Allow("cached")
		}
	}

	decision, err := g.checker.Check(ctx, q)
	if err != nil {
		// THE rule. An unreachable or misbehaving authorization service denies.
		// Anything else makes degrading a dependency a way to gain access
		// (ADR-010).
		g.obs.Failed(string(q.Relation), q.Resource.Type)
		g.log.Error("authz: check failed; denying",
			"error", err, "relation", q.Relation, "resource", q.Resource.String())
		return Deny("authorization unavailable")
	}
	if !decision.Allowed() {
		g.obs.Denied(string(q.Relation), q.Resource.Type, decision.Reason())
		return decision
	}

	if denied, reason := g.revoked(ctx, q); denied {
		g.obs.Denied(string(q.Relation), q.Resource.Type, reason)
		return Deny(reason)
	}

	if g.cache != nil && cacheUsable {
		if err := g.cache.Remember(ctx, q, epoch, g.ttl); err != nil {
			g.log.Debug("authz: could not cache a permit", "error", err)
		}
	}
	g.obs.Allowed(string(q.Relation), q.Resource.Type, "checker")
	return decision
}

// BatchCheck answers a page of questions in one round trip.
//
// Every position gets an answer. A short or misaligned response from the
// implementation is treated as a failure of the whole batch and denies all of
// it: answers shifted by one position would attach somebody else's permit to
// this resource, which is worse than denying the page.
func (g *Guard) BatchCheck(ctx context.Context, qs []Query) []Decision {
	out := make([]Decision, len(qs))
	if len(qs) == 0 {
		return out
	}
	for i, q := range qs {
		if err := q.Validate(); err != nil {
			g.obs.Failed(string(q.Relation), q.Resource.Type)
			out[i] = Deny("invalid query")
			// One malformed entry does not condemn the page, but it must not be
			// sent on either.
			qs[i] = Query{}
		}
	}

	decisions, err := g.checker.BatchCheck(ctx, qs)
	if err != nil || len(decisions) != len(qs) {
		if err == nil {
			err = fmt.Errorf("%w: %d answers for %d questions",
				ErrUnavailable, len(decisions), len(qs))
		}
		g.log.Error("authz: batch check failed; denying the whole page", "error", err)
		for i := range out {
			g.obs.Failed(string(qs[i].Relation), qs[i].Resource.Type)
			out[i] = Deny("authorization unavailable")
		}
		return out
	}

	for i, d := range decisions {
		if out[i].Reason() == "invalid query" {
			continue
		}
		if !d.Allowed() {
			g.obs.Denied(string(qs[i].Relation), qs[i].Resource.Type, d.Reason())
			out[i] = d
			continue
		}
		if denied, reason := g.revoked(ctx, qs[i]); denied {
			g.obs.Denied(string(qs[i].Relation), qs[i].Resource.Type, reason)
			out[i] = Deny(reason)
			continue
		}
		g.obs.Allowed(string(qs[i].Relation), qs[i].Resource.Type, "checker")
		out[i] = d
	}
	return out
}

// revoked consults the tombstones. It reports a denial for an error as well as
// for a real revocation: "I could not tell whether this was revoked" is not a
// reason to allow.
func (g *Guard) revoked(ctx context.Context, q Query) (bool, string) {
	if g.tombs == nil {
		return false, ""
	}
	revoked, err := g.tombs.Revoked(ctx, q)
	if err != nil {
		g.obs.Failed(string(q.Relation), q.Resource.Type)
		g.log.Error("authz: revocation check failed; denying",
			"error", err, "relation", q.Relation, "resource", q.Resource.String())
		return true, "revocation state unknown"
	}
	if revoked {
		return true, "revoked"
	}
	return false, ""
}

// epochFor reads the principal's revocation epoch.
//
// If it cannot be read the cache is SKIPPED rather than used with a stale or
// guessed epoch: an epoch that does not reflect revocations would serve permits
// a revocation was supposed to invalidate.
func (g *Guard) epochFor(ctx context.Context, p Principal) (uint64, bool) {
	if g.cache == nil {
		return 0, false
	}
	epoch, err := g.cache.Epoch(ctx, p)
	if err != nil {
		g.log.Debug("authz: revocation epoch unavailable; bypassing the decision cache",
			"error", err, "principal", p.String())
		return 0, false
	}
	return epoch, true
}

// DenyAll is a Checker that refuses everything.
//
// It is what a composition root wires when authorization cannot be reached at
// startup, so the failure is an explicit, named object rather than a nil that
// panics on the first request.
type DenyAll struct{ Reason string }

func (d DenyAll) Check(context.Context, Query) (Decision, error) {
	return Deny(d.reason()), nil
}

func (d DenyAll) BatchCheck(_ context.Context, qs []Query) ([]Decision, error) {
	out := make([]Decision, len(qs))
	for i := range out {
		out[i] = Deny(d.reason())
	}
	return out, nil
}

func (d DenyAll) reason() string {
	if d.Reason == "" {
		return "authorization is not configured"
	}
	return d.Reason
}

var _ Checker = DenyAll{}

// IsUnavailable reports whether an error means the service could not answer, as
// opposed to answering "no".
func IsUnavailable(err error) bool { return errors.Is(err, ErrUnavailable) }
