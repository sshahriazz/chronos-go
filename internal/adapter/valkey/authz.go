package valkey

import (
	"context"
	"fmt"
	"strconv"
	"time"

	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cache"
	"github.com/valkey-io/valkey-go"
)

// Namespaces for the authorization keys. Separate prefixes so an operator
// reading raw keys can tell a tombstone from a cached permit at a glance, and so
// one can be swept without touching the other.
const (
	tombstoneNS = cache.Namespace("authz.revoked")
	decisionNS  = cache.Namespace("authz.allow")
	epochNS     = cache.Namespace("authz.epoch")
)

// TombstoneTTL is garbage collection, NOT the lifetime of a revocation.
//
// A tombstone is deleted by the access projector once it has CONFIRMED the tuple
// is gone. The TTL exists only for a tombstone whose projector died, and a
// tombstone reaching it is an alert rather than a routine expiry — it means the
// access projector is broken (access.md §6.1).
//
// An earlier formulation had the tombstone "expire once the projector has
// certainly caught up". That is a bug: if the TTL fires BEFORE the projector
// removes the tuple, access silently returns — a revoked user regains entry with
// no event, no log line, and no way to notice.
const TombstoneTTL = time.Hour

// Authz implements the authorization kernel's Tombstones and Decisions ports.
//
// Everything it stores is derived and rebuildable: a lost tombstone is recovered
// by the projector removing the tuple, and a lost permit is recomputed by one
// round trip. Losing Valkey entirely therefore costs latency and a shorter
// revocation window, never a wrong answer — because every failure here is
// reported as an error, and the Guard turns every error into a denial.
type Authz struct {
	client valkey.Client
}

var (
	_ authz.Tombstones = (*Authz)(nil)
	_ authz.Decisions  = (*Authz)(nil)
)

func NewAuthz(c valkey.Client) *Authz { return &Authz{client: c} }

// Revoked reports whether this exact access was revoked ahead of the projector.
//
// An error is NOT swallowed. "I could not tell" must reach the Guard, which
// denies — the alternative is a revocation that silently fails to take effect
// because the cache was briefly unreachable.
func (a *Authz) Revoked(ctx context.Context, q authz.Query) (bool, error) {
	if a.client == nil {
		return false, errNoClient
	}
	key, err := tombstoneKey(q)
	if err != nil {
		return false, err
	}
	_, err = a.client.Do(ctx, a.client.B().Get().Key(key).Build()).AsBytes()
	switch {
	case valkey.IsValkeyNil(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("valkey: reading revocation for %s: %w", q.Resource, err)
	}
	return true, nil
}

// Revoke records a revocation so it takes effect before the projector runs.
//
// Being late to deny is a security failure, so denial never waits for a
// projector. A tombstone can only ever produce a deny, which is what makes
// consulting an eventually-consistent store on the hot path safe.
//
// It also bumps the principal's epoch, invalidating every decision cached for
// them at once — without that, a cached permit for a DIFFERENT resource would
// outlive this revocation.
func (a *Authz) Revoke(ctx context.Context, q authz.Query) error {
	if a.client == nil {
		return errNoClient
	}
	key, err := tombstoneKey(q)
	if err != nil {
		return err
	}
	cmd := a.client.B().Set().Key(key).Value("1").Px(TombstoneTTL).Build()
	if err := a.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("valkey: recording revocation for %s: %w", q.Resource, err)
	}
	if err := a.BumpEpoch(ctx, q.Principal); err != nil {
		return err
	}
	return nil
}

// Confirm deletes a tombstone once the projector has removed the tuple.
//
// Positive confirmation, never a timer. This is the ONLY correct way to clear
// one: deleting on a schedule races the projector, and losing that race restores
// access to a revoked principal.
func (a *Authz) Confirm(ctx context.Context, q authz.Query) error {
	if a.client == nil {
		return errNoClient
	}
	key, err := tombstoneKey(q)
	if err != nil {
		return err
	}
	if err := a.client.Do(ctx, a.client.B().Del().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("valkey: clearing revocation for %s: %w", q.Resource, err)
	}
	return nil
}

// Allowed reports a cached permit.
func (a *Authz) Allowed(ctx context.Context, q authz.Query, epoch uint64) (bool, error) {
	if a.client == nil {
		return false, errNoClient
	}
	key, err := decisionKey(q, epoch)
	if err != nil {
		return false, err
	}
	_, err = a.client.Do(ctx, a.client.B().Get().Key(key).Build()).AsBytes()
	switch {
	case valkey.IsValkeyNil(err):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("valkey: reading cached decision: %w", err)
	}
	return true, nil
}

// Remember stores a permit under the principal's current epoch.
//
// Only permits are ever stored — the kernel never calls this for a denial, and
// there is no method here that could. A cached refusal would outlive the grant
// that fixed it.
func (a *Authz) Remember(ctx context.Context, q authz.Query, epoch uint64, ttl time.Duration) error {
	if a.client == nil {
		return errNoClient
	}
	if err := cache.ValidateTTL(ttl); err != nil {
		return err
	}
	key, err := decisionKey(q, epoch)
	if err != nil {
		return err
	}
	cmd := a.client.B().Set().Key(key).Value("1").Px(ttl).Build()
	if err := a.client.Do(ctx, cmd).Error(); err != nil {
		return fmt.Errorf("valkey: caching decision: %w", err)
	}
	return nil
}

// Epoch returns the principal's revocation epoch.
//
// An absent key is epoch 0, not an error: a principal who has never had anything
// revoked is the normal case.
func (a *Authz) Epoch(ctx context.Context, p authz.Principal) (uint64, error) {
	if a.client == nil {
		return 0, errNoClient
	}
	key, err := epochNS.Key(string(p.Kind), p.ID)
	if err != nil {
		return 0, err
	}
	raw, err := a.client.Do(ctx, a.client.B().Get().Key(key).Build()).AsBytes()
	switch {
	case valkey.IsValkeyNil(err):
		return 0, nil
	case err != nil:
		return 0, fmt.Errorf("valkey: reading revocation epoch for %s: %w", p, err)
	}
	n, err := strconv.ParseUint(string(raw), 10, 64)
	if err != nil {
		return 0, fmt.Errorf("valkey: revocation epoch for %s is not a number (%q): %w", p, raw, err)
	}
	return n, nil
}

// BumpEpoch invalidates every decision cached for a principal at once.
//
// Conservative and O(1), rather than working out which entries to evict. The
// counter has NO expiry, and that is deliberate: if it expired and reset to
// zero, previously-cached permits keyed on the old epoch would become live
// again — a revocation undone by garbage collection.
func (a *Authz) BumpEpoch(ctx context.Context, p authz.Principal) error {
	if a.client == nil {
		return errNoClient
	}
	key, err := epochNS.Key(string(p.Kind), p.ID)
	if err != nil {
		return err
	}
	if err := a.client.Do(ctx, a.client.B().Incr().Key(key).Build()).Error(); err != nil {
		return fmt.Errorf("valkey: bumping revocation epoch for %s: %w", p, err)
	}
	return nil
}

// tombstoneKey and decisionKey build keys from validated parts.
//
// The query is validated first because ':' is the key separator AND OpenFGA's
// type/id separator: an unvalidated id could otherwise address a different
// principal's tombstone, which is the difference between denying the right
// person and denying nobody.
func tombstoneKey(q authz.Query) (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	return tombstoneNS.Key(string(q.Principal.Kind), q.Principal.ID,
		string(q.Relation), q.Resource.Type, q.Resource.ID)
}

func decisionKey(q authz.Query, epoch uint64) (string, error) {
	if err := q.Validate(); err != nil {
		return "", err
	}
	return decisionNS.Key(string(q.Principal.Kind), q.Principal.ID,
		string(q.Relation), q.Resource.Type, q.Resource.ID,
		strconv.FormatUint(epoch, 10))
}
