package cache

import (
	"container/list"
	"context"
	"sync"
	"time"

	"golang.org/x/sync/singleflight"
)

// Memo is an in-process cache with a TTL and a size bound.
//
// It exists for the values that must NOT be sent to a shared cache: key
// material, and anything else whose disclosure to whoever can read the cache
// server is unacceptable. What Memo gives up in exchange is coherence — each
// process holds its own copy — which is why it takes a Dispose hook and why
// anything security-relevant that uses it must also subscribe to a Bus so
// another process's invalidation reaches it before the TTL does.
//
// Both bounds are load-bearing. The TTL bounds how long a stale entry can
// survive an invalidation that never arrived. The capacity bounds memory, which
// for a per-subject cache is otherwise a function of how many distinct people
// the process has served since it started.
type Memo[K comparable, V any] struct {
	mu      sync.Mutex
	entries map[K]*list.Element
	order   *list.List // front = most recently used
	cap     int
	ttl     time.Duration
	now     func() time.Time
	dispose func(V)
	flight  singleflight.Group
}

type memoEntry[K comparable, V any] struct {
	key     K
	value   V
	expires time.Time
}

// MemoOptions configures a Memo. TTL and Capacity are required.
type MemoOptions[V any] struct {
	// TTL is how long an entry may live. Required and positive: see the package
	// comment on why there is no permanent entry.
	TTL time.Duration

	// Capacity is the maximum number of entries. Required and positive.
	Capacity int

	// Dispose is called with a value as it leaves the cache — evicted, expired,
	// invalidated or purged. For key material this is where the bytes are
	// zeroed.
	//
	// It runs while the cache is locked, so it must not call back into the
	// Memo. It must also be safe to call on a value a caller may still hold a
	// COPY of; it must never be used to invalidate something shared by
	// reference.
	Dispose func(V)

	// Now overrides the clock, for tests.
	Now func() time.Time
}

// NewMemo builds an in-process cache. It panics on a missing bound, which is a
// programming error: both bounds are the reason this type is safe to hold
// secrets in at all.
func NewMemo[K comparable, V any](opts MemoOptions[V]) *Memo[K, V] {
	if opts.TTL <= 0 {
		panic("cache: Memo requires a positive TTL")
	}
	if opts.Capacity <= 0 {
		panic("cache: Memo requires a positive capacity")
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.Dispose == nil {
		opts.Dispose = func(V) {}
	}
	return &Memo[K, V]{
		entries: make(map[K]*list.Element, opts.Capacity),
		order:   list.New(),
		cap:     opts.Capacity,
		ttl:     opts.TTL,
		now:     opts.Now,
		dispose: opts.Dispose,
	}
}

// Get returns a live entry. An expired entry is disposed of and reported as
// absent, so expiry frees the value rather than merely hiding it.
func (m *Memo[K, V]) Get(key K) (V, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.entries[key]
	if !ok {
		var zero V
		return zero, false
	}
	e := el.Value.(*memoEntry[K, V])
	if !m.now().Before(e.expires) {
		m.removeLocked(el)
		var zero V
		return zero, false
	}
	m.order.MoveToFront(el)
	return e.value, true
}

// Put stores an entry, evicting the least recently used one if the cache is
// full.
func (m *Memo[K, V]) Put(key K, value V) {
	m.mu.Lock()
	defer m.mu.Unlock()

	if el, ok := m.entries[key]; ok {
		e := el.Value.(*memoEntry[K, V])
		m.dispose(e.value)
		e.value = value
		e.expires = m.now().Add(m.ttl)
		m.order.MoveToFront(el)
		return
	}
	if m.order.Len() >= m.cap {
		if oldest := m.order.Back(); oldest != nil {
			m.removeLocked(oldest)
		}
	}
	el := m.order.PushFront(&memoEntry[K, V]{
		key: key, value: value, expires: m.now().Add(m.ttl),
	})
	m.entries[key] = el
}

// PutIf stores an entry only when allow says so, deciding and storing under the
// same lock.
//
// The atomicity is the whole point. A caller that reads with Get, decides, then
// writes with Put has a window in between, and for an invalidation that window is
// where a value the cache was just told to forget gets written back. allow
// receives the current entry and whether one was present; an expired entry is
// reported as absent.
func (m *Memo[K, V]) PutIf(key K, value V, allow func(existing V, found bool) bool) bool {
	m.mu.Lock()
	defer m.mu.Unlock()

	el, ok := m.entries[key]
	if ok && !m.now().Before(el.Value.(*memoEntry[K, V]).expires) {
		m.removeLocked(el)
		el, ok = nil, false
	}

	var current V
	if ok {
		current = el.Value.(*memoEntry[K, V]).value
	}
	if !allow(current, ok) {
		return false
	}

	if ok {
		e := el.Value.(*memoEntry[K, V])
		m.dispose(e.value)
		e.value = value
		e.expires = m.now().Add(m.ttl)
		m.order.MoveToFront(el)
		return true
	}
	if m.order.Len() >= m.cap {
		if oldest := m.order.Back(); oldest != nil {
			m.removeLocked(oldest)
		}
	}
	m.entries[key] = m.order.PushFront(&memoEntry[K, V]{
		key: key, value: value, expires: m.now().Add(m.ttl),
	})
	return true
}

// Delete removes one entry and disposes of its value. Deleting an absent key is
// not an error: invalidation runs on paths that cannot know what is cached.
func (m *Memo[K, V]) Delete(key K) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if el, ok := m.entries[key]; ok {
		m.removeLocked(el)
	}
}

// Purge empties the cache, disposing of every value.
//
// This is the response to losing the invalidation bus: if this process can no
// longer hear that a key was destroyed, it must stop trusting the keys it
// already holds.
func (m *Memo[K, V]) Purge() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	n := m.order.Len()
	for el := m.order.Front(); el != nil; {
		next := el.Next()
		m.removeLocked(el)
		el = next
	}
	return n
}

// Sweep removes every expired entry and returns how many went.
//
// Lazy expiry alone would leave a destroyed key sitting in memory until somebody
// happened to ask for it again. For key material that is the difference between
// "expired" and "gone", so the composition root runs this on a ticker.
func (m *Memo[K, V]) Sweep() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	now, removed := m.now(), 0
	for el := m.order.Front(); el != nil; {
		next := el.Next()
		if !now.Before(el.Value.(*memoEntry[K, V]).expires) {
			m.removeLocked(el)
			removed++
		}
		el = next
	}
	return removed
}

// SweepEvery runs Sweep until ctx is cancelled, then purges. Blocking; the
// caller runs it in a goroutine.
func (m *Memo[K, V]) SweepEvery(ctx context.Context, interval time.Duration) {
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			// Shutdown is the last chance to zero anything still held.
			m.Purge()
			return
		case <-t.C:
			m.Sweep()
		}
	}
}

// Len reports how many entries are held, expired ones included — it is a memory
// measure, not a hit-rate one.
func (m *Memo[K, V]) Len() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.order.Len()
}

// Load returns the cached value or calls load once, collapsing concurrent misses
// for the same key into a single call.
func (m *Memo[K, V]) Load(ctx context.Context, key K, keyString string, load func(context.Context) (V, error)) (V, error) {
	if v, ok := m.Get(key); ok {
		return v, nil
	}
	v, err, _ := m.flight.Do(keyString, func() (any, error) {
		if cached, ok := m.Get(key); ok {
			return cached, nil
		}
		loaded, loadErr := load(ctx)
		if loadErr != nil {
			return loaded, loadErr
		}
		m.Put(key, loaded)
		return loaded, nil
	})
	if err != nil {
		var zero V
		return zero, err
	}
	return v.(V), nil
}

func (m *Memo[K, V]) removeLocked(el *list.Element) {
	e := el.Value.(*memoEntry[K, V])
	m.order.Remove(el)
	delete(m.entries, e.key)
	m.dispose(e.value)
}
