// Package cache is the caching kernel: a small port for shared, expiring state
// and a typed store built on top of it.
//
// Two rules shape everything here.
//
// Every entry has a TTL. There is no Set without one, and a non-positive TTL is
// rejected rather than treated as "forever" — a cache entry that never expires
// is a second source of truth, and this one lives in a store whose stated
// property is that FLUSHALL must be survivable. Expiry is what keeps it a cache.
//
// A cache miss is never an error. Callers get (value, found, err) and must treat
// a miss and an unreachable cache the same way: go to the source. That is what
// makes the whole package Degradable — losing it costs latency, not correctness.
//
// What must NOT go in here: personal data of any kind, and key material of any
// kind. Projections may not hold a personal-data column (compliance.md §1) and a
// cache is a projection with a shorter life. The PII vault's cache is built from
// these pieces but keeps its secrets in-process; see internal/adapter/piivault.
package cache

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Cache is shared, expiring, byte-oriented storage.
//
// Bytes rather than a generic value type, because the port is implemented by an
// adapter that speaks a wire protocol. Typing happens one layer up, in Store.
type Cache interface {
	// Get returns the stored bytes. A miss returns (nil, false, nil): absence is
	// the normal case, not a failure.
	Get(ctx context.Context, key string) ([]byte, bool, error)

	// Set stores bytes under a TTL. A non-positive TTL is an error.
	Set(ctx context.Context, key string, value []byte, ttl time.Duration) error

	// Delete removes keys. Deleting an absent key is not an error — invalidation
	// runs on paths that cannot know whether anything was cached.
	Delete(ctx context.Context, keys ...string) error
}

// Bus carries invalidation messages between processes.
//
// Separate from Cache because it answers a different question. Cache asks "do
// you have this?"; Bus says "whatever you have, drop it." An in-process cache
// with no Bus is correct only until a second replica exists.
type Bus interface {
	// Publish sends a message to every subscriber of a channel. Delivery is
	// best-effort and at-most-once: subscribers that are down miss it, which is
	// why anything relying on Bus must also be bounded by a TTL.
	Publish(ctx context.Context, channel string, message []byte) error

	// Subscribe blocks, calling fn for each message, until ctx is cancelled or
	// the connection fails. Callers run it in a goroutine and restart it.
	Subscribe(ctx context.Context, channel string, fn func(message []byte)) error
}

// Observer records cache outcomes. Optional.
//
// Plain strings rather than this package's types, so a metrics implementation
// satisfies it structurally without importing the kernel — the same arrangement
// projection.Metrics and notify.Observer use.
type Observer interface {
	Hit(name string)
	Miss(name string)
	// Error reports a cache fault. It is deliberately not fatal anywhere: the
	// caller has already fallen back to the source by the time this is called.
	Error(name, op string)
	// Invalidated counts entries dropped ahead of their TTL, locally or by a
	// message from another process.
	Invalidated(name string, count int)
}

type noObserver struct{}

func (noObserver) Hit(string)              {}
func (noObserver) Miss(string)             {}
func (noObserver) Error(string, string)    {}
func (noObserver) Invalidated(string, int) {}

var (
	// ErrNoTTL means Set was called without a positive TTL. Everything in the
	// cache expires; there is no permanent entry.
	ErrNoTTL = errors.New("cache: a positive TTL is required")

	// ErrBadKey means the key is empty or contains a separator, which would let
	// one namespace address another's entries.
	ErrBadKey = errors.New("cache: invalid key")
)

// Separator divides a namespace from a key. Chosen to match the convention
// every Valkey/Redis tool already assumes when it groups keys for inspection.
const Separator = ":"

// Namespace prefixes keys so two subsystems cannot collide, and so an operator
// can see at a glance what a key is for.
type Namespace string

// Key builds a fully-qualified key.
//
// It rejects parts containing the separator rather than escaping them: escaping
// invites a key that reads as one namespace and lands in another, and there is
// no legitimate reason for a caller to embed one.
func (n Namespace) Key(parts ...string) (string, error) {
	if n == "" {
		return "", fmt.Errorf("%w: namespace is empty", ErrBadKey)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%w: no key parts", ErrBadKey)
	}
	for _, p := range parts {
		if p == "" {
			return "", fmt.Errorf("%w: empty key part", ErrBadKey)
		}
		if strings.Contains(p, Separator) {
			return "", fmt.Errorf("%w: key part %q contains %q", ErrBadKey, p, Separator)
		}
	}
	return string(n) + Separator + strings.Join(parts, Separator), nil
}

// MustKey is Key for a caller that has already validated its parts — a constant
// prefix plus an ID from a closed generator. It panics on a bad key, which is a
// programming error rather than a runtime condition.
func (n Namespace) MustKey(parts ...string) string {
	k, err := n.Key(parts...)
	if err != nil {
		panic(err)
	}
	return k
}

// ValidateTTL is the single place the TTL rule is enforced, so every adapter
// rejects the same inputs rather than each inventing its own tolerance.
func ValidateTTL(ttl time.Duration) error {
	if ttl <= 0 {
		return fmt.Errorf("%w (got %s)", ErrNoTTL, ttl)
	}
	return nil
}
