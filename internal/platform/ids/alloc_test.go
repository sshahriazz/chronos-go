package ids_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Allocation budgets, asserted rather than hoped for.
func TestAllocationBudget(t *testing.T) {
	id := ids.New[ids.Org](at, ent)
	s := id.String()
	buf := make([]byte, 0, 64)

	tests := []struct {
		name  string
		limit float64
		fn    func()
	}{
		// The zero-allocation rendering path, for callers already holding a buffer.
		{"AppendTo is allocation-free", 0, func() { bufSink = id.AppendTo(buf[:0]) }},
		// Parsing must never allocate: it runs on every request naming a resource.
		{"Parse is allocation-free", 0, func() { idSink, _ = ids.Parse[ids.Org](s) }},
		// One allocation: the returned string, unavoidable.
		{"String allocates once", 1, func() { strSink = id.String() }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := testing.AllocsPerRun(200, tc.fn); got > tc.limit {
				t.Errorf("allocations regressed: got %.0f want <= %.0f", got, tc.limit)
			}
		})
	}
}
