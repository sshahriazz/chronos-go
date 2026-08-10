package authz_test

import (
	"context"
	"errors"
	"log/slog"
	"strconv"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/authz"
)

func quiet() *slog.Logger { return slog.New(slog.DiscardHandler) }

func query() authz.Query {
	return authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "usr_1"},
		Relation:  "viewer",
		Resource:  authz.ResourceRef{Type: "folder", ID: "fld_1"},
	}
}

// The zero Decision must deny.
//
// Every path that fails — an error, a timeout, an unhandled branch, a struct
// somebody forgot to fill in — produces this value. If it permitted, forgetting
// would grant access.
func TestZeroDecisionDenies(t *testing.T) {
	var d authz.Decision
	if d.Allowed() {
		t.Fatal("the zero Decision permits; every forgotten branch is now a grant")
	}
	many := make([]authz.Decision, 3)
	for i, d := range many {
		if d.Allowed() {
			t.Fatalf("element %d of a fresh slice permits", i)
		}
	}
}

// ---- fail closed ---------------------------------------------------------

type stubChecker struct {
	decision authz.Decision
	err      error
	calls    int

	batch    []authz.Decision
	batchErr error
}

func (s *stubChecker) Check(context.Context, authz.Query) (authz.Decision, error) {
	s.calls++
	return s.decision, s.err
}

func (s *stubChecker) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	s.calls++
	if s.batch != nil || s.batchErr != nil {
		return s.batch, s.batchErr
	}
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = s.decision
	}
	return out, s.err
}

func newGuard(t *testing.T, d authz.GuardDeps) *authz.Guard {
	t.Helper()
	if d.Log == nil {
		d.Log = quiet()
	}
	g, err := authz.NewGuard(d)
	if err != nil {
		t.Fatalf("NewGuard: %v", err)
	}
	return g
}

// An unreachable authorization service must DENY. This is the one deliberate
// exception to "the server stays resilient" (ADR-010): if an outage permitted,
// degrading a dependency would become a way to gain access.
func TestCheckerFailureDenies(t *testing.T) {
	for name, stub := range map[string]*stubChecker{
		"connection refused": {err: errors.New("connection refused")},
		"timeout":            {err: context.DeadlineExceeded},
		"unavailable":        {err: authz.ErrUnavailable},
		// The nastiest case: an implementation that returns an allow AND an
		// error. The error must win.
		"allow with an error": {decision: authz.Allow("yes"), err: errors.New("but also broken")},
	} {
		t.Run(name, func(t *testing.T) {
			g := newGuard(t, authz.GuardDeps{Checker: stub})
			if d := g.Check(context.Background(), query()); d.Allowed() {
				t.Fatalf("a failing checker produced %s", d)
			}
		})
	}
}

// A malformed query must never reach the authorization service. It is a
// programming error, and sending it on risks asking about a DIFFERENT object
// than the caller named.
func TestMalformedQueriesAreRefusedWithoutAsking(t *testing.T) {
	cases := map[string]authz.Query{
		"no principal id": {Principal: authz.Principal{Kind: authz.KindUser}, Relation: "viewer",
			Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
		"unknown principal kind": {Principal: authz.Principal{Kind: "wizard", ID: "u1"},
			Relation: "viewer", Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
		"no relation": {Principal: authz.Principal{Kind: authz.KindUser, ID: "u1"},
			Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
		"no resource type": {Principal: authz.Principal{Kind: authz.KindUser, ID: "u1"},
			Relation: "viewer", Resource: authz.ResourceRef{ID: "f1"}},
		// ':' separates type from id and '#' introduces a userset. Either would
		// address a different object than the caller named.
		"injected separator in id": {Principal: authz.Principal{Kind: authz.KindUser, ID: "u1"},
			Relation: "viewer", Resource: authz.ResourceRef{Type: "folder", ID: "f1:other"}},
		"injected userset in principal": {Principal: authz.Principal{Kind: authz.KindUser, ID: "team#member"},
			Relation: "viewer", Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
		"injected separator in relation": {Principal: authz.Principal{Kind: authz.KindUser, ID: "u1"},
			Relation: "viewer:admin", Resource: authz.ResourceRef{Type: "folder", ID: "f1"}},
	}
	for name, q := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &stubChecker{decision: authz.Allow("would have said yes")}
			g := newGuard(t, authz.GuardDeps{Checker: stub})
			if d := g.Check(context.Background(), q); d.Allowed() {
				t.Fatalf("a malformed query was permitted: %s", d)
			}
			if stub.calls != 0 {
				t.Errorf("a malformed query reached the authorization service")
			}
		})
	}
}

func TestAllowPassesThrough(t *testing.T) {
	g := newGuard(t, authz.GuardDeps{Checker: &stubChecker{decision: authz.Allow("direct")}})
	if d := g.Check(context.Background(), query()); !d.Allowed() {
		t.Fatalf("a legitimate allow was denied: %s", d)
	}
}

// ---- revocation ----------------------------------------------------------

type stubTombstones struct {
	revoked bool
	err     error
	calls   int
}

func (s *stubTombstones) Revoked(context.Context, authz.Query) (bool, error) {
	s.calls++
	return s.revoked, s.err
}

// A revocation must take effect before the projector has removed the tuple.
// Being late to deny is a security failure, so denial never waits.
func TestTombstoneOverridesAnAllow(t *testing.T) {
	tombs := &stubTombstones{revoked: true}
	g := newGuard(t, authz.GuardDeps{
		Checker:    &stubChecker{decision: authz.Allow("tuple still present")},
		Tombstones: tombs,
	})
	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("a revoked principal was permitted because the projector had not caught up")
	}
	if tombs.calls != 1 {
		t.Errorf("tombstones consulted %d times, want 1", tombs.calls)
	}
}

// "I could not tell whether this was revoked" is not a reason to allow.
func TestTombstoneFailureDenies(t *testing.T) {
	g := newGuard(t, authz.GuardDeps{
		Checker:    &stubChecker{decision: authz.Allow("yes")},
		Tombstones: &stubTombstones{err: errors.New("valkey down")},
	})
	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("an unreadable revocation store permitted access")
	}
}

// A deny needs no second opinion. Consulting tombstones on the majority path
// would spend a lookup that cannot change the answer.
func TestTombstonesAreNotConsultedOnADeny(t *testing.T) {
	tombs := &stubTombstones{}
	g := newGuard(t, authz.GuardDeps{
		Checker:    &stubChecker{decision: authz.Deny("no tuple")},
		Tombstones: tombs,
	})
	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("permitted")
	}
	if tombs.calls != 0 {
		t.Errorf("tombstones were consulted for a denial (%d calls)", tombs.calls)
	}
}

// ---- decision cache ------------------------------------------------------

type stubCache struct {
	allowed   bool
	allowErr  error
	epoch     uint64
	epochErr  error
	remembers int
	lastTTL   time.Duration
}

func (s *stubCache) Allowed(context.Context, authz.Query, uint64) (bool, error) {
	return s.allowed, s.allowErr
}

func (s *stubCache) Remember(_ context.Context, _ authz.Query, _ uint64, ttl time.Duration) error {
	s.remembers++
	s.lastTTL = ttl
	return nil
}

func (s *stubCache) Epoch(context.Context, authz.Principal) (uint64, error) {
	return s.epoch, s.epochErr
}

// A cached permit must still face the tombstones, or a revocation would not take
// effect until the entry expired.
func TestCachedAllowStillFacesTheTombstone(t *testing.T) {
	checker := &stubChecker{decision: authz.Allow("should not be reached")}
	g := newGuard(t, authz.GuardDeps{
		Checker:    checker,
		Decisions:  &stubCache{allowed: true},
		Tombstones: &stubTombstones{revoked: true},
	})
	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("a cached permit survived a revocation")
	}
}

// A cache hit must not cost a round trip.
func TestCacheHitSkipsTheChecker(t *testing.T) {
	checker := &stubChecker{decision: authz.Deny("would have said no")}
	g := newGuard(t, authz.GuardDeps{Checker: checker, Decisions: &stubCache{allowed: true}})
	if d := g.Check(context.Background(), query()); !d.Allowed() {
		t.Fatalf("a cached permit was not honoured: %s", d)
	}
	if checker.calls != 0 {
		t.Errorf("the checker was called despite a cache hit")
	}
}

// A deny must NEVER be cached: it has to become an allow the instant a grant
// lands, and a cached refusal would outlive the grant that fixed it.
func TestDenialsAreNeverCached(t *testing.T) {
	cache := &stubCache{}
	g := newGuard(t, authz.GuardDeps{
		Checker:   &stubChecker{decision: authz.Deny("no tuple")},
		Decisions: cache,
	})
	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("permitted")
	}
	if cache.remembers != 0 {
		t.Fatalf("a denial was cached %d times: a later grant would not take effect "+
			"until the entry expired", cache.remembers)
	}
}

// An unreadable epoch means the cache cannot be reasoned about, so it is skipped
// rather than used with a guessed epoch that would serve permits a revocation
// was meant to invalidate.
func TestUnreadableEpochBypassesTheCache(t *testing.T) {
	cache := &stubCache{allowed: true, epochErr: errors.New("valkey down")}
	checker := &stubChecker{decision: authz.Deny("the truth")}
	g := newGuard(t, authz.GuardDeps{Checker: checker, Decisions: cache})

	if d := g.Check(context.Background(), query()); d.Allowed() {
		t.Fatal("a cached permit was served under an unknown epoch")
	}
	if checker.calls != 1 {
		t.Errorf("the source of truth was not consulted (%d calls)", checker.calls)
	}
	if cache.remembers != 0 {
		t.Error("a permit was cached under an unknown epoch")
	}
}

// A permit cached longer than the cap is a revocation that has not taken effect.
func TestCacheTTLIsCapped(t *testing.T) {
	_, err := authz.NewGuard(authz.GuardDeps{
		Checker:  &stubChecker{},
		CacheTTL: time.Hour,
		Log:      quiet(),
	})
	if err == nil {
		t.Fatal("an hour-long decision cache must be refused")
	}
}

func TestGuardRequiresAChecker(t *testing.T) {
	if _, err := authz.NewGuard(authz.GuardDeps{Log: quiet()}); err == nil {
		t.Fatal("a Guard with no Checker must be refused, not built to deny silently")
	}
}

// ---- batch ---------------------------------------------------------------

// A misaligned batch response must deny the whole page. Answers shifted by one
// position would attach somebody else's permit to this resource.
func TestMisalignedBatchDeniesEverything(t *testing.T) {
	qs := []authz.Query{query(), query(), query()}
	g := newGuard(t, authz.GuardDeps{
		Checker: &stubChecker{batch: []authz.Decision{authz.Allow("a"), authz.Allow("b")}},
	})
	for i, d := range g.BatchCheck(context.Background(), qs) {
		if d.Allowed() {
			t.Fatalf("position %d permitted from a short batch response", i)
		}
	}
}

func TestBatchFailureDeniesEverything(t *testing.T) {
	qs := []authz.Query{query(), query()}
	g := newGuard(t, authz.GuardDeps{
		Checker: &stubChecker{batchErr: errors.New("connection refused")},
	})
	for i, d := range g.BatchCheck(context.Background(), qs) {
		if d.Allowed() {
			t.Fatalf("position %d permitted from a failed batch", i)
		}
	}
}

// One malformed entry must not condemn the page, but must not be sent on either.
func TestBatchIsolatesAMalformedEntry(t *testing.T) {
	qs := []authz.Query{query(), {Relation: "viewer"}, query()}
	g := newGuard(t, authz.GuardDeps{Checker: &stubChecker{decision: authz.Allow("ok")}})

	out := g.BatchCheck(context.Background(), qs)
	if !out[0].Allowed() || !out[2].Allowed() {
		t.Error("valid entries were denied because a sibling was malformed")
	}
	if out[1].Allowed() {
		t.Error("the malformed entry was permitted")
	}
}

func TestBatchTombstoneOverridesPositions(t *testing.T) {
	qs := []authz.Query{query(), query()}
	g := newGuard(t, authz.GuardDeps{
		Checker:    &stubChecker{decision: authz.Allow("tuple present")},
		Tombstones: &stubTombstones{revoked: true},
	})
	for i, d := range g.BatchCheck(context.Background(), qs) {
		if d.Allowed() {
			t.Fatalf("position %d permitted a revoked principal", i)
		}
	}
}

func TestEmptyBatch(t *testing.T) {
	g := newGuard(t, authz.GuardDeps{Checker: &stubChecker{}})
	if got := g.BatchCheck(context.Background(), nil); len(got) != 0 {
		t.Fatalf("got %d decisions for no questions", len(got))
	}
}

// ---- DenyAll -------------------------------------------------------------

// What a composition root wires when authorization is unreachable at startup: an
// explicit object that refuses, rather than a nil that panics on first request.
func TestDenyAllRefusesEverything(t *testing.T) {
	var c authz.Checker = authz.DenyAll{}
	d, err := c.Check(context.Background(), query())
	if err != nil || d.Allowed() {
		t.Fatalf("DenyAll permitted: %s (err=%v)", d, err)
	}
	batch, err := c.BatchCheck(context.Background(), []authz.Query{query(), query()})
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(batch) != 2 {
		t.Fatalf("got %d decisions, want 2", len(batch))
	}
	for i, d := range batch {
		if d.Allowed() {
			t.Fatalf("position %d permitted", i)
		}
	}
}

// The composition root must be able to see what is wired. An absent tombstone
// port is invisible at runtime and only shows up as a revocation that did not
// take.
func TestGuardReportsItsWiring(t *testing.T) {
	bare := newGuard(t, authz.GuardDeps{Checker: &stubChecker{}})
	if bare.HasTombstones() || bare.HasCache() {
		t.Error("a bare Guard reports ports it does not have")
	}
	full := newGuard(t, authz.GuardDeps{
		Checker: &stubChecker{}, Tombstones: &stubTombstones{}, Decisions: &stubCache{},
	})
	if !full.HasTombstones() || !full.HasCache() {
		t.Error("a fully wired Guard reports missing ports")
	}
}

// ---- depth ---------------------------------------------------------------

func path(n int) authz.Path {
	p := make(authz.Path, 0, n)
	for i := range n {
		p = append(p, authz.ResourceRef{Type: "folder", ID: "f" + strconv.Itoa(i)})
	}
	return p
}

// The cap is enforced on WRITE, and the reason is the failure mode it avoids.
// Past OpenFGA's own limit a check ERRORS, and an erroring check fails closed —
// so an over-deep tree does not warn, it locks people out of their own
// resources.
func TestDepthCapIsEnforcedAtTheLimit(t *testing.T) {
	if err := path(authz.MaxDepth).Validate(); err != nil {
		t.Fatalf("a path exactly at the limit must be allowed: %v", err)
	}
	err := path(authz.MaxDepth + 1).Validate()
	if !errors.Is(err, authz.ErrTooDeep) {
		t.Fatalf("a path one level over the limit must be refused, got %v", err)
	}
}

// Our cap must sit BELOW OpenFGA's hard error, or the guard is useless: the
// server would fail the read before we ever refused the write.
func TestDepthCapLeavesHeadroomBelowTheServerLimit(t *testing.T) {
	const openFGAHardError = 25
	if authz.MaxDepth >= openFGAHardError {
		t.Fatalf("MaxDepth is %d and OpenFGA errors at %d: a tree could be accepted on "+
			"write and then be unreadable, which fails closed and locks users out",
			authz.MaxDepth, openFGAHardError)
	}
}

// A cycle makes depth unbounded, and OpenFGA answers by exhausting its traversal
// limit rather than by returning a decision.
func TestCyclicPathIsRefused(t *testing.T) {
	p := authz.Path{
		{Type: "folder", ID: "a"},
		{Type: "folder", ID: "b"},
		{Type: "folder", ID: "a"},
	}
	if err := p.Validate(); !errors.Is(err, authz.ErrInvalid) {
		t.Fatalf("a cycle must be refused, got %v", err)
	}
}

func TestEmptyPathIsRefused(t *testing.T) {
	if err := (authz.Path{}).Validate(); !errors.Is(err, authz.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}

// Re-parenting is where the cap bites hardest: each resource is individually
// within the limit, and the combined tree is not. Checking only the resource
// being moved would let a move create a tree nothing can read.
func TestReparentingChecksTheCombinedDepth(t *testing.T) {
	parent := path(authz.MaxDepth - 2)

	if err := authz.WouldExceedDepth(parent, 2); err != nil {
		t.Fatalf("a move that exactly reaches the limit must be allowed: %v", err)
	}
	if err := authz.WouldExceedDepth(parent, 3); !errors.Is(err, authz.ErrTooDeep) {
		t.Fatalf("a move that breaches the limit must be refused, got %v", err)
	}
	if err := authz.WouldExceedDepth(parent, 0); !errors.Is(err, authz.ErrInvalid) {
		t.Fatalf("a subtree has at least one level, got %v", err)
	}
}

// The same injection guard as a query: a path segment carrying a separator would
// name a different object than the caller meant.
func TestPathRejectsInjectedSeparators(t *testing.T) {
	p := authz.Path{{Type: "folder", ID: "a:b"}}
	if err := p.Validate(); !errors.Is(err, authz.ErrInvalid) {
		t.Fatalf("got %v", err)
	}
}
