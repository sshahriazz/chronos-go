package eventcodec

import (
	"sync"
	"sync/atomic"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// The registry read happens once per EVENT, on every projector and reactor, and
// a rebuild runs it on N goroutines at once (ADR-044).
//
// These two benchmarks exist to justify the copy-on-write design against the
// mutex it replaced, rather than asserting that atomics are faster. The lookup
// is isolated from decoding on purpose: at ~1.6 µs per payload decode, a
// difference of tens of nanoseconds here is invisible in an end-to-end number
// and would be dismissed as noise — which is exactly how a contention point
// survives a benchmark suite.

type mutexRegistry struct {
	mu        sync.RWMutex
	factories map[string]func() eventsourcing.Event
}

func (m *mutexRegistry) lookup(t string) (func() eventsourcing.Event, bool) {
	m.mu.RLock()
	f, ok := m.factories[t]
	m.mu.RUnlock()
	return f, ok
}

type atomicRegistry struct {
	table atomic.Pointer[map[string]func() eventsourcing.Event]
}

func (a *atomicRegistry) lookup(t string) (func() eventsourcing.Event, bool) {
	f, ok := (*a.table.Load())[t]
	return f, ok
}

func registries() (*mutexRegistry, *atomicRegistry) {
	factories := map[string]func() eventsourcing.Event{}
	for _, name := range []string{
		"a.one", "a.two", "a.three", "b.one", "b.two", "c.one", "c.two", "c.three",
	} {
		factories[name] = func() eventsourcing.Event { return nil }
	}
	m := &mutexRegistry{factories: factories}
	a := &atomicRegistry{}
	a.table.Store(&factories)
	return m, a
}

func BenchmarkRegistryLookupMutexParallel(b *testing.B) {
	m, _ := registries()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := m.lookup("c.two"); !ok {
				b.Fatal("missing")
			}
		}
	})
}

func BenchmarkRegistryLookupAtomicParallel(b *testing.B) {
	_, a := registries()
	b.ReportAllocs()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, ok := a.lookup("c.two"); !ok {
				b.Fatal("missing")
			}
		}
	})
}

func BenchmarkRegistryLookupMutexSerial(b *testing.B) {
	m, _ := registries()
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := m.lookup("c.two"); !ok {
			b.Fatal("missing")
		}
	}
}

func BenchmarkRegistryLookupAtomicSerial(b *testing.B) {
	_, a := registries()
	b.ReportAllocs()
	for b.Loop() {
		if _, ok := a.lookup("c.two"); !ok {
			b.Fatal("missing")
		}
	}
}
