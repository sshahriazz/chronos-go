package piivault

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/platform/cache"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// KeyCache holds unwrapped subject data keys for a short time, in this process
// only.
//
// # Why the key and not the profile
//
// Resolving one subject costs three round trips: read the wrapped key from
// PostgreSQL, unwrap it at OpenBao, read the sealed values. Caching the decrypted
// PROFILE would collapse all three, and would also put names and email addresses
// in a shared cache — a projection with a personal-data column, which
// compliance.md §1 forbids and which would make erasure a cache-eviction problem
// on top of a key-destruction one. Caching the KEY collapses two of the three
// and keeps every byte of personal data in PostgreSQL, sealed.
//
// # Why in-process and never in Valkey
//
// An unwrapped DEK is the plaintext of the thing OpenBao exists to protect.
// Valkey is Degradable, unauthenticated in development, and its whole contract is
// that its contents are disposable. Key material does not go there. What DOES go
// to Valkey is the invalidation message — a SubjectID, which is a pseudonym and
// already appears in events, logs and projections (ADR-002).
//
// # Why an invalidation bus is mandatory, not an optimisation
//
// The package comment on this adapter states the rule plainly: a key cached
// indefinitely in this process is a key that survives its own destruction, and
// erasure would then be a lie until the next restart. A TTL alone makes that
// window shorter, not absent. The bus makes an erasure in one replica reach every
// other replica in milliseconds; the TTL is the backstop for when the bus was
// unreachable, and it is short for exactly that reason.
type KeyCache struct {
	memo    *cache.Memo[pii.SubjectID, cachedKey]
	bus     cache.Bus
	channel string
	obs     cache.Observer
	log     *slog.Logger
}

// cachedKey is either a live data key or a tombstone.
//
// Caching the ERASED state as well as the key is safe in one direction only, and
// that is the direction it runs: erasure is terminal — Erase refuses to
// resurrect a subject under a fresh key — so a cached "erased" can never become
// wrong. A cached "not erased" can, which is what the TTL and the bus are for.
type cachedKey struct {
	dek    []byte
	erased bool
}

// KeyCacheOptions configures the cache.
type KeyCacheOptions struct {
	// TTL bounds how long a key can outlive an erasure whose invalidation this
	// process never received. Short by design.
	TTL time.Duration

	// Capacity bounds memory: without it, a process that has served a million
	// distinct subjects holds a million keys.
	Capacity int

	// Bus carries invalidations between replicas. Required — see the type
	// comment. NewKeyCache refuses to build without one.
	Bus cache.Bus

	// Channel is the pub/sub channel invalidations travel on.
	Channel string

	Observer cache.Observer
	Log      *slog.Logger
}

// Defaults for KeyCacheOptions.
const (
	// DefaultKeyCacheTTL is one minute. Long enough to collapse the burst of
	// lookups one notification fan-out causes, short enough that a key surviving
	// its own destruction is measured in seconds if the bus is down.
	DefaultKeyCacheTTL = time.Minute

	// DefaultKeyCacheCapacity is 4096 subjects — a few hundred kilobytes of key
	// material, and far more than one process handles inside one TTL.
	DefaultKeyCacheCapacity = 4096

	// DefaultKeyCacheChannel is the invalidation channel.
	DefaultKeyCacheChannel = "pii.key.invalidate"
)

// NewKeyCache builds the cache.
//
// It returns an error without a Bus rather than degrading to TTL-only. A
// TTL-only key cache is silently incorrect the moment a second replica exists,
// and "it worked in development" is exactly how that ships.
func NewKeyCache(opts KeyCacheOptions) (*KeyCache, error) {
	if opts.Bus == nil {
		return nil, fmt.Errorf("piivault: a cache.Bus is required: without one, " +
			"an erasure in another replica cannot reach this process's cached keys")
	}
	if opts.TTL <= 0 {
		opts.TTL = DefaultKeyCacheTTL
	}
	if opts.Capacity <= 0 {
		opts.Capacity = DefaultKeyCacheCapacity
	}
	if opts.Channel == "" {
		opts.Channel = DefaultKeyCacheChannel
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	if opts.Observer == nil {
		opts.Observer = noCacheObserver{}
	}

	kc := &KeyCache{
		bus: opts.Bus, channel: opts.Channel,
		obs: opts.Observer, log: opts.Log,
	}
	kc.memo = cache.NewMemo[pii.SubjectID](cache.MemoOptions[cachedKey]{
		TTL:      opts.TTL,
		Capacity: opts.Capacity,
		// The cache owns its copy of every key, so zeroing on the way out is
		// safe: callers were handed copies and are zeroing those themselves.
		Dispose: func(c cachedKey) { crypto.Zero(c.dek) },
	})
	return kc, nil
}

// get returns a copy of the cached key, or reports the subject as erased.
//
// A COPY, always. Handing out the cached slice would let a caller's ordinary
// `defer crypto.Zero(dek)` blank the cache's own entry, and every subsequent hit
// would decrypt with 32 zero bytes — a failure that looks like corruption rather
// than like the aliasing bug it is.
func (k *KeyCache) get(id pii.SubjectID) (dek []byte, erased bool, ok bool) {
	entry, hit := k.memo.Get(id)
	if !hit {
		k.obs.Miss(cacheName)
		return nil, false, false
	}
	k.obs.Hit(cacheName)
	if entry.erased {
		return nil, true, true
	}
	out := make([]byte, len(entry.dek))
	copy(out, entry.dek)
	return out, false, true
}

// put caches a copy of a live key, unless a tombstone is already present.
//
// The refusal closes a race that a plain Put would leave open. A reader that
// fetched the wrapped key from PostgreSQL, then had its subject erased by
// another request before it finished unwrapping, would otherwise write the key
// back into the cache AFTER the invalidation had cleared it — resurrecting a
// destroyed key for a full TTL. Erasure is terminal, so a tombstone is allowed to
// be sticky, and stickiness is exactly what makes the write-back impossible.
func (k *KeyCache) put(id pii.SubjectID, dek []byte) {
	stored := make([]byte, len(dek))
	copy(stored, dek)
	if !k.memo.PutIf(id, cachedKey{dek: stored},
		func(existing cachedKey, found bool) bool { return !found || !existing.erased }) {
		crypto.Zero(stored)
	}
}

// putErased caches the tombstone, so a subject who exercised erasure stops
// costing a database round trip per notification attempt.
func (k *KeyCache) putErased(id pii.SubjectID) {
	k.memo.Put(id, cachedKey{erased: true})
}

// Invalidate drops a subject's key here and everywhere else.
//
// The local drop happens FIRST and unconditionally: if the publish fails, this
// process at least is already correct. The error is still returned, because the
// caller's operation — erasure — is idempotent and retrying it is cheap, whereas
// leaving another replica holding a destroyed key is not something to swallow.
func (k *KeyCache) Invalidate(ctx context.Context, id pii.SubjectID) error {
	// A tombstone rather than a delete: it zeroes the key exactly as a delete
	// would, and additionally blocks the in-flight reader that is about to write
	// the same key back. See put.
	k.putErased(id)
	k.obs.Invalidated(cacheName, 1)
	if err := k.bus.Publish(ctx, k.channel, []byte(id)); err != nil {
		k.obs.Error(cacheName, "publish")
		return fmt.Errorf("piivault: publishing key invalidation for %s "+
			"(this process is correct; other replicas may hold the key until it expires): %w", id, err)
	}
	return nil
}

// Watch applies invalidations published by other replicas. Blocking; run it in a
// goroutine and restart it when it returns.
//
// On return it PURGES. A subscription that dropped is a subscription that may
// have missed an invalidation, and there is no way to find out which one — so
// every key held becomes suspect at once. Purging costs a burst of cache misses;
// not purging costs a destroyed key still in use.
func (k *KeyCache) Watch(ctx context.Context) error {
	err := k.bus.Subscribe(ctx, k.channel, func(message []byte) {
		id := pii.SubjectID(message)
		if id == "" {
			return
		}
		k.putErased(id)
		k.obs.Invalidated(cacheName, 1)
		k.log.Debug("subject key invalidated by another replica", "subject", id)
	})
	if purged := k.memo.Purge(); purged > 0 {
		k.obs.Invalidated(cacheName, purged)
		k.log.Warn("key-invalidation subscription ended; purged cached subject keys",
			"purged", purged, "error", err)
	}
	return err
}

// Sweep frees expired keys without waiting for someone to ask for them again.
// Run on a ticker: lazy expiry would leave a destroyed key resident in memory
// indefinitely, which is the thing this cache is not allowed to do.
func (k *KeyCache) Sweep() int { return k.memo.Sweep() }

// SweepEvery runs Sweep until ctx is cancelled, then zeroes everything held.
func (k *KeyCache) SweepEvery(ctx context.Context, every time.Duration) {
	k.memo.SweepEvery(ctx, every)
}

// Len reports how many subjects are cached. For tests and metrics.
func (k *KeyCache) Len() int { return k.memo.Len() }

const cacheName = "pii_key"

type noCacheObserver struct{}

func (noCacheObserver) Hit(string)              {}
func (noCacheObserver) Miss(string)             {}
func (noCacheObserver) Error(string, string)    {}
func (noCacheObserver) Invalidated(string, int) {}
