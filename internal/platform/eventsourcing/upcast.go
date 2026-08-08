package eventsourcing

import (
	"fmt"
	"sync"
)

// Upcaster transforms one stored schema version into the next (ADR-029).
//
// Stored events are NEVER rewritten — not even for a "harmless" backfill. The
// log is permanent, so history stays byte-accurate and the domain only ever
// sees the current shape.
type Upcaster func(payload []byte) ([]byte, error)

// UpcasterRegistry holds the chains, keyed by event type.
//
// Safe for concurrent use: registration happens at startup, reads happen on
// every event read.
type UpcasterRegistry struct {
	mu     sync.RWMutex
	chains map[string]map[int]Upcaster // type -> fromVersion -> upcaster
	latest map[string]int              // type -> current version
}

func NewUpcasterRegistry() *UpcasterRegistry {
	return &UpcasterRegistry{
		chains: make(map[string]map[int]Upcaster),
		latest: make(map[string]int),
	}
}

// Register declares the current schema version for an event type. Every type
// must be registered, so an unknown version fails loudly rather than being
// decoded into the wrong shape.
func (r *UpcasterRegistry) Register(eventType string, currentVersion int) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.latest[eventType] = currentVersion
	if _, ok := r.chains[eventType]; !ok {
		r.chains[eventType] = make(map[int]Upcaster)
	}
}

// Upcast registers the transformation from `from` to `from+1`.
//
// It is written in the same commit as the schema change: a new version with no
// upcaster is a build failure by convention, and a load failure in fact.
func (r *UpcasterRegistry) Upcast(eventType string, from int, fn Upcaster) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, ok := r.chains[eventType]; !ok {
		r.chains[eventType] = make(map[int]Upcaster)
	}
	r.chains[eventType][from] = fn
}

// CurrentVersion reports the version the domain expects.
func (r *UpcasterRegistry) CurrentVersion(eventType string) (int, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	v, ok := r.latest[eventType]
	return v, ok
}

// Apply walks the chain from the stored version to the current one.
func (r *UpcasterRegistry) Apply(eventType string, storedVersion int, payload []byte) ([]byte, error) {
	r.mu.RLock()
	current, known := r.latest[eventType]
	chain := r.chains[eventType]
	r.mu.RUnlock()

	if !known {
		return nil, fmt.Errorf("eventsourcing: event type %q is not registered", eventType)
	}
	if storedVersion > current {
		// Written by a newer deployment than this one. Refusing is correct:
		// guessing at a shape we do not know produces silent corruption.
		return nil, fmt.Errorf(
			"eventsourcing: %s is at schema v%d but this build understands only v%d — deploy is behind",
			eventType, storedVersion, current)
	}

	out := payload
	for v := storedVersion; v < current; v++ {
		fn, ok := chain[v]
		if !ok {
			return nil, fmt.Errorf(
				"eventsourcing: no upcaster for %s v%d -> v%d; the schema changed without one",
				eventType, v, v+1)
		}
		next, err := fn(out)
		if err != nil {
			return nil, fmt.Errorf("eventsourcing: upcasting %s v%d -> v%d: %w", eventType, v, v+1, err)
		}
		out = next
	}
	return out, nil
}
