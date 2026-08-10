//go:build integration

package valkey_test

import (
	"context"
	"encoding/hex"
	"testing"
	"time"

	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/google/uuid"
)

func authzStore(t *testing.T) *valkeyadapter.Authz {
	t.Helper()
	return valkeyadapter.NewAuthz(dial(t))
}

// A fresh principal per test: a shared one would let a previous run's epoch or
// tombstone decide this run's outcome.
func freshQuery(t *testing.T) authz.Query {
	t.Helper()
	raw := uuid.New()
	sfx := hex.EncodeToString(raw[:6])
	return authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "usr" + sfx},
		Relation:  "editor",
		Resource:  authz.ResourceRef{Type: "folder", ID: "fld" + sfx},
	}
}

// A revocation must take effect immediately, before the access projector has
// removed the tuple. Being late to deny is a security failure.
func TestRevocationIsImmediate(t *testing.T) {
	a := authzStore(t)
	q := freshQuery(t)
	ctx := context.Background()

	revoked, err := a.Revoked(ctx, q)
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if revoked {
		t.Fatal("a fresh principal is already revoked")
	}

	if err := a.Revoke(ctx, q); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	revoked, err = a.Revoked(ctx, q)
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if !revoked {
		t.Fatal("a revocation did not take effect; the principal keeps access until the " +
			"projector catches up")
	}

	t.Cleanup(func() { _ = a.Confirm(context.Background(), q) })
}

// The tombstone is cleared by CONFIRMATION, never by a timer. Deleting on a
// schedule races the projector, and losing that race restores access to a
// revoked principal.
func TestTombstoneIsClearedByConfirmation(t *testing.T) {
	a := authzStore(t)
	q := freshQuery(t)
	ctx := context.Background()

	if err := a.Revoke(ctx, q); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	if err := a.Confirm(ctx, q); err != nil {
		t.Fatalf("Confirm: %v", err)
	}
	revoked, err := a.Revoked(ctx, q)
	if err != nil {
		t.Fatalf("Revoked: %v", err)
	}
	if revoked {
		t.Fatal("the tombstone survived confirmation")
	}
}

// A revocation must invalidate decisions cached for OTHER resources too.
//
// Without the epoch bump, a permit cached a moment earlier for a different
// folder would outlive the revocation — the user loses access to one thing and
// keeps it everywhere else until the entries expire.
func TestRevocationInvalidatesEveryCachedDecision(t *testing.T) {
	a := authzStore(t)
	ctx := context.Background()
	q := freshQuery(t)

	// A permit for a DIFFERENT resource, held by the same principal.
	other := q
	other.Resource = authz.ResourceRef{Type: "folder", ID: q.Resource.ID + "other"}

	epoch, err := a.Epoch(ctx, q.Principal)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if err := a.Remember(ctx, other, epoch, time.Minute); err != nil {
		t.Fatalf("Remember: %v", err)
	}
	cached, err := a.Allowed(ctx, other, epoch)
	if err != nil || !cached {
		t.Fatalf("the permit was not cached (cached=%v err=%v)", cached, err)
	}

	if err := a.Revoke(ctx, q); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	t.Cleanup(func() { _ = a.Confirm(context.Background(), q) })

	next, err := a.Epoch(ctx, q.Principal)
	if err != nil {
		t.Fatalf("Epoch: %v", err)
	}
	if next == epoch {
		t.Fatal("the revocation epoch did not move, so decisions cached for this " +
			"principal's other resources survive the revocation")
	}
	if cached, err := a.Allowed(ctx, other, next); err != nil {
		t.Fatalf("Allowed: %v", err)
	} else if cached {
		t.Fatal("a permit cached before the revocation is still readable at the new epoch")
	}
}

// The end-to-end property, through the Guard: a revoked principal is denied even
// while the authorization service still says yes, because the tuple is still
// there.
func TestGuardDeniesARevokedPrincipalTheServiceStillPermits(t *testing.T) {
	a := authzStore(t)
	q := freshQuery(t)
	ctx := context.Background()

	g, err := authz.NewGuard(authz.GuardDeps{
		// Stands in for OpenFGA before the projector has removed the tuple.
		Checker:    alwaysAllow{},
		Tombstones: a,
		Decisions:  a,
	})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	if d := g.Check(ctx, q); !d.Allowed() {
		t.Fatalf("expected an allow before revocation, got %s", d)
	}
	if err := a.Revoke(ctx, q); err != nil {
		t.Fatalf("Revoke: %v", err)
	}
	t.Cleanup(func() { _ = a.Confirm(context.Background(), q) })

	if d := g.Check(ctx, q); d.Allowed() {
		t.Fatal("a revoked principal was permitted because the tuple had not been removed yet")
	}
}

// Permits carry an expiry. A cached permit that never expired would be a
// revocation that never took effect if the epoch bump were ever lost.
func TestCachedPermitsCarryAnExpiry(t *testing.T) {
	client := dial(t)
	a := valkeyadapter.NewAuthz(client)
	q := freshQuery(t)
	ctx := context.Background()

	if err := a.Remember(ctx, q, 0, 30*time.Second); err != nil {
		t.Fatalf("Remember: %v", err)
	}

	// Read the TTL back from the SERVER rather than trusting our intention.
	keys, err := client.Do(ctx, client.B().Keys().Pattern("authz.allow:*"+q.Resource.ID+"*").Build()).AsStrSlice()
	if err != nil {
		t.Fatalf("KEYS: %v", err)
	}
	if len(keys) == 0 {
		t.Fatal("no cached decision was written")
	}
	ttl, err := client.Do(ctx, client.B().Pttl().Key(keys[0]).Build()).AsInt64()
	if err != nil {
		t.Fatalf("PTTL: %v", err)
	}
	if ttl <= 0 {
		t.Fatalf("PTTL returned %d: the permit was stored without an expiry", ttl)
	}
	t.Cleanup(func() {
		_, _ = client.Do(context.Background(), client.B().Del().Key(keys...).Build()).AsInt64()
	})
}

// A malformed query must never become a key. ':' is both our key separator and
// OpenFGA's type/id separator, so an unvalidated id could address a different
// principal's tombstone — denying the wrong person, or nobody.
func TestMalformedQueriesNeverBecomeKeys(t *testing.T) {
	a := authzStore(t)
	bad := authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "usr:other"},
		Relation:  "editor",
		Resource:  authz.ResourceRef{Type: "folder", ID: "f1"},
	}
	if _, err := a.Revoked(context.Background(), bad); err == nil {
		t.Fatal("a principal id containing the separator was accepted as a key")
	}
	if err := a.Revoke(context.Background(), bad); err == nil {
		t.Fatal("a malformed query was written as a tombstone")
	}
}

type alwaysAllow struct{}

func (alwaysAllow) Check(context.Context, authz.Query) (authz.Decision, error) {
	return authz.Allow("tuple still present"), nil
}

func (alwaysAllow) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Allow("tuple still present")
	}
	return out, nil
}

// An unreadable tombstone store must report an ERROR, not "not revoked".
//
// This exercises the failure path deliberately, by closing the client. Every
// other test here runs against a healthy Valkey, so the error branch was never
// executed — and a mutation that swallowed the error and returned (false, nil)
// passed the whole suite. "I could not tell whether this was revoked" is not a
// reason to allow, and the adapter is where that is decided.
func TestUnreadableTombstoneStoreIsAnError(t *testing.T) {
	client := dial(t)
	a := valkeyadapter.NewAuthz(client)
	q := freshQuery(t)

	// Prove the query is well-formed against a live client first, so a failure
	// below is the closed connection and not a rejected key.
	if _, err := a.Revoked(context.Background(), q); err != nil {
		t.Fatalf("precondition: %v", err)
	}

	client.Close() // t.Cleanup closes it again; valkey-go tolerates that.

	if _, err := a.Revoked(context.Background(), q); err == nil {
		t.Fatal("an unreadable revocation store reported 'not revoked': a revocation now " +
			"fails to take effect whenever the cache is briefly unreachable")
	}
}

// And the Guard must turn that error into a denial, end to end.
func TestGuardDeniesWhenTheTombstoneStoreIsUnreadable(t *testing.T) {
	client := dial(t)
	a := valkeyadapter.NewAuthz(client)
	q := freshQuery(t)
	client.Close()

	g, err := authz.NewGuard(authz.GuardDeps{Checker: alwaysAllow{}, Tombstones: a})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	if d := g.Check(context.Background(), q); d.Allowed() {
		t.Fatal("access was permitted while revocation state was unknown")
	}
}
