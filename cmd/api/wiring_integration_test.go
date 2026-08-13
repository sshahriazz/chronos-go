//go:build integration

package main

import (
	"log/slog"
	"testing"
)

// Revocation must be immediate, and that depends entirely on ports the Guard
// takes from Valkey. Both are optional in the kernel, and their absence is
// INVISIBLE at runtime: checks still work, they just keep permitting a principal
// whose access was revoked seconds ago.
//
// INTEGRATION-TAGGED, and that tag is the point. This asserts on a Valkey client
// that only exists when Valkey is reachable, so in the default suite it does not
// test the wiring — it tests whether the developer happened to have the stack
// running. It failed exactly that way once, in `make check`, on a machine where
// the stack was down.
//
// The infra-free half of this property — that the typed-nil guards return real
// nil interfaces — lives in wiring_test.go and runs everywhere.
func TestRevocationPortsAreWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if !d.authz.HasTombstones() {
		t.Error("no revocation tombstones are wired: a revoked principal keeps access " +
			"until the access projector removes the tuple, with nothing reporting it")
	}
	if !d.authz.HasCache() {
		t.Error("no decision cache is wired: every check is a round trip to OpenFGA")
	}
	if d.authzCache == nil {
		t.Error("the access projector has no handle to confirm revocations, so tombstones " +
			"can only be cleared by their TTL — which races the projector")
	}
}
