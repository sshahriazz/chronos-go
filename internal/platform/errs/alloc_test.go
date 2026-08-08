package errs_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// Allocation budgets, asserted. A benchmark reports a regression; this fails
// the build. Numbers come from measurement, not aspiration — see bench_test.go.
func TestAllocationBudget(t *testing.T) {
	tests := []struct {
		name  string
		limit float64
		fn    func()
	}{
		// The single most-called function on the error path.
		{"ReasonOf is allocation-free", 0, func() { reasonSink = errs.ReasonOf(errSink) }},
		// One allocation: the *Error itself, which must escape.
		{"constructor with no args allocates once", 1, func() {
			errSink = errs.AccessDeniedf("permission denied")
		}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			errSink = errs.QuotaExceededf("seed")
			if got := testing.AllocsPerRun(200, tc.fn); got > tc.limit {
				t.Errorf("allocations regressed: got %.0f want <= %.0f", got, tc.limit)
			}
		})
	}
}
