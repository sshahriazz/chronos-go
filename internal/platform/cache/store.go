package cache

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/platform/codec"
	"golang.org/x/sync/singleflight"
)

// Codec turns a value into bytes and back.
//
// A port rather than a hard dependency on JSON, because the thing worth
// caching most often — a rendered page, a protobuf message — already has a
// cheaper encoding than JSON, and paying JSON's cost to save a database round
// trip can undo the saving.
type Codec[T any] interface {
	Encode(T) ([]byte, error)
	Decode([]byte) (T, error)
}

// JSONCodec is the default. Correct for anything, optimal for nothing.
type JSONCodec[T any] struct{}

// Encode writes the cache entry.
//
// No NullEmpty: a cache entry is written and read by this process alone and
// never leaves it, so the v2 shape for a nil slice — `[]` rather than v1's
// `null` — is observed by nothing but the matching Decode below.
func (JSONCodec[T]) Encode(v T) ([]byte, error) { return codec.Marshal(v) }

// Decode reads a cache entry, STRICTLY.
//
// A cached value is a document this build wrote, so an unrecognised member
// means the entry predates a shape change. Tolerating it would silently serve a
// half-populated value under whatever the old field meant; rejecting it makes
// Store.Get drop the entry and reload from the source, which is the only outcome
// that is correct in both directions.
func (JSONCodec[T]) Decode(b []byte) (T, error) { return codec.Unmarshal[T](b) }

// Store is a typed view of a Cache for one namespace.
//
// It owns three things the raw port does not: encoding, a single-flight guard so
// N concurrent misses cause one load rather than N, and the decision that every
// cache fault is survivable. A Store method never returns a cache error — it
// records it and falls through to the source.
type Store[T any] struct {
	cache  Cache
	codec  Codec[T]
	ns     Namespace
	ttl    time.Duration
	obs    Observer
	log    *slog.Logger
	flight singleflight.Group
}

// StoreOptions configures a Store. TTL and Namespace are required.
type StoreOptions[T any] struct {
	Namespace Namespace
	TTL       time.Duration
	Codec     Codec[T]
	Observer  Observer
	Log       *slog.Logger
}

// NewStore builds a typed store.
//
// It returns an error rather than defaulting a missing TTL, because a default
// TTL is a number nobody chose, applied to data nobody thought about. The
// namespace and the lifetime are the two decisions the caller must actually
// make.
func NewStore[T any](c Cache, opts StoreOptions[T]) (*Store[T], error) {
	if c == nil {
		return nil, fmt.Errorf("cache: a Cache is required")
	}
	if opts.Namespace == "" {
		return nil, fmt.Errorf("%w: namespace is required", ErrBadKey)
	}
	if err := ValidateTTL(opts.TTL); err != nil {
		return nil, err
	}
	if opts.Codec == nil {
		opts.Codec = JSONCodec[T]{}
	}
	if opts.Observer == nil {
		opts.Observer = noObserver{}
	}
	if opts.Log == nil {
		opts.Log = slog.Default()
	}
	return &Store[T]{
		cache: c, codec: opts.Codec, ns: opts.Namespace,
		ttl: opts.TTL, obs: opts.Observer, log: opts.Log,
	}, nil
}

// Name reports the namespace, which is what the Observer labels metrics by.
func (s *Store[T]) Name() string { return string(s.ns) }

// Get returns a cached value.
//
// A cache fault is reported as a miss, not an error: the caller's only correct
// response to either is to consult the source, and forcing every call site to
// distinguish them would eventually produce one that returns 500 because Valkey
// was restarting.
func (s *Store[T]) Get(ctx context.Context, parts ...string) (T, bool) {
	var zero T
	key, err := s.ns.Key(parts...)
	if err != nil {
		s.obs.Error(s.Name(), "key")
		return zero, false
	}
	raw, found, err := s.cache.Get(ctx, key)
	if err != nil {
		s.obs.Error(s.Name(), "get")
		s.log.Debug("cache read failed; falling back to source",
			"namespace", s.Name(), "error", err)
		return zero, false
	}
	if !found {
		s.obs.Miss(s.Name())
		return zero, false
	}
	v, err := s.codec.Decode(raw)
	if err != nil {
		// A value this process cannot decode is one an older or newer build
		// wrote. Drop it rather than serve it: a stale shape is how a cache
		// starts returning a field that no longer means what it did.
		s.obs.Error(s.Name(), "decode")
		_ = s.cache.Delete(ctx, key)
		return zero, false
	}
	s.obs.Hit(s.Name())
	return v, true
}

// Set stores a value under the store's TTL.
func (s *Store[T]) Set(ctx context.Context, v T, parts ...string) error {
	key, err := s.ns.Key(parts...)
	if err != nil {
		return err
	}
	raw, err := s.codec.Encode(v)
	if err != nil {
		return fmt.Errorf("cache: encoding %s: %w", s.Name(), err)
	}
	if err := s.cache.Set(ctx, key, raw, s.ttl); err != nil {
		s.obs.Error(s.Name(), "set")
		return fmt.Errorf("cache: storing %s: %w", key, err)
	}
	return nil
}

// Delete removes one entry.
func (s *Store[T]) Delete(ctx context.Context, parts ...string) error {
	key, err := s.ns.Key(parts...)
	if err != nil {
		return err
	}
	if err := s.cache.Delete(ctx, key); err != nil {
		s.obs.Error(s.Name(), "delete")
		return fmt.Errorf("cache: deleting %s: %w", key, err)
	}
	s.obs.Invalidated(s.Name(), 1)
	return nil
}

// Load returns the cached value, or calls load and caches the result.
//
// Concurrent misses for the same key collapse into one load. Without that, a
// popular key expiring under load sends every in-flight request to the source at
// once — the cache stampede, which is at its worst exactly when the cache was
// helping most.
//
// A failure to WRITE the cache is logged, never returned: the value was loaded
// successfully, and failing the caller because the optimisation failed inverts
// the point of having one.
func (s *Store[T]) Load(ctx context.Context, load func(context.Context) (T, error), parts ...string) (T, error) {
	if v, ok := s.Get(ctx, parts...); ok {
		return v, nil
	}
	key, err := s.ns.Key(parts...)
	if err != nil {
		return load(ctx)
	}

	v, err, _ := s.flight.Do(key, func() (any, error) {
		// Re-check under the flight: a request that queued behind the leader
		// would otherwise load again immediately after the leader stored.
		if cached, ok := s.Get(ctx, parts...); ok {
			return cached, nil
		}
		loaded, loadErr := load(ctx)
		if loadErr != nil {
			return loaded, loadErr
		}
		if setErr := s.Set(ctx, loaded, parts...); setErr != nil {
			s.log.Debug("cache write failed; value still returned",
				"namespace", s.Name(), "error", setErr)
		}
		return loaded, nil
	})
	if err != nil {
		var zero T
		return zero, err
	}
	return v.(T), nil
}
