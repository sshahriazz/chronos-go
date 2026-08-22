package main

import (
	"log/slog"
	"testing"
)

// The access projector uses a CONFIRMING writer, never a bare one.
//
// ADR-045: a revocation tombstone is cleared by confirmation and never by a
// timer. A bare writer removes tuples and confirms nothing, so every tombstone
// survives to its TTL — and reaching the TTL is supposed to be an alert, not the
// normal path. The failure is completely silent: tuples do disappear, so
// permissions do eventually change, and the only symptom is that revocation is
// slower than it claims to be.
//
// Asserted by construction rather than by inspecting a field: a bare writer
// would still satisfy the reactor's interface, so the only thing that can catch
// this is whether the code path builds one.
func TestTheAccessProjectorConfirmsWhatItRemoves(t *testing.T) {
	cfg := testConfig(t)
	// Set BOTH, so the failure below can only come from the revocation store.
	// Without a store id construction fails earlier, and the test would pass
	// while never reaching the code it is about.
	cfg.OpenFGA.StoreID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	cfg.Valkey.Addr = []string{"127.0.0.1:1"} // nothing listens here

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if _, err := newAccessTuples(newCodec(), d, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("the access projector was constructed with no reachable revocation store. " +
			"It would remove tuples and confirm nothing, leaving every tombstone to expire " +
			"on its TTL while the system looked healthy")
	}
}
