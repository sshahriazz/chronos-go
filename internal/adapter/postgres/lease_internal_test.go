package postgres

import "testing"

var sinkKey int64

// The lease key must be stable across processes and runs: two projectors that
// hash the same name to different keys both take a lock and both believe they
// are the single writer.
func TestLeaseKeyIsStable(t *testing.T) {
	// Pinned literals, not a recomputation — a recomputed expectation would
	// pass no matter which hash function this switched to.
	cases := map[string]int64{
		"identity_users":    -6589067065501066259,
		"organization_orgs": 5308441330386198751,
		"workspace_members": -6551996061167467791,
	}
	for name, want := range cases {
		if got := leaseKey(name); got != want {
			t.Errorf("leaseKey(%q) = %d, want %d — the key changed, so a deploy "+
				"straddling the change would run two writers on one projection", name, got, want)
		}
	}
}

func TestLeaseKeysDiffer(t *testing.T) {
	if leaseKey("a") == leaseKey("b") {
		t.Fatal("distinct projections collided on one lock; one would never run")
	}
}

func BenchmarkLeaseKey(b *testing.B) {
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sinkKey = leaseKey("identity_users")
	}
}
