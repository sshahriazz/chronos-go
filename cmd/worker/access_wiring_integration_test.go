//go:build integration

package main

import (
	"log/slog"
	"testing"
)

// storeID is any syntactically valid store id.
//
// The tests below never reach OpenFGA with it — construction only needs the
// value to be non-empty — but they DO reach Valkey, which is dialled eagerly,
// which is why this file carries the integration tag.
const storeID = "01ARZ3NDEKTSV4RRFFQ69G5FAV"

// The binary that WRITES the authorization graph probes it.
//
// # Why this assertion lives here now
//
// It used to be in cmd/projector, because that binary built the tuple writer.
// It no longer does: no transaction spans PostgreSQL and OpenFGA, so tuple
// writing is at-least-once work and belongs with the other at-least-once work,
// which is this process.
//
// The concern is unchanged, and it is the reason the assertion moved rather than
// being deleted. A permission graph that has stopped changing reports HEALTHY
// unless something probes it: grants stop landing, revocations stop being
// confirmed, and every dashboard stays green while the tenant slowly loses the
// ability to do anything new.
func TestTheWorkerProbesOpenFGA(t *testing.T) {
	cfg := testConfig(t)
	// A store id, because its absence short-circuits construction before the
	// probe is registered — and a test that skips there asserts nothing about
	// the wiring it exists to check. The gRPC dial is lazy, so no server has to
	// be listening.
	cfg.OpenFGA.StoreID = storeID

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	// Constructing the access reactor is what registers the probe, exactly as it
	// is in reactors(). Calling it here rather than asserting on a field keeps
	// the test measuring the real wiring path.
	if _, err := newAccessTuples(newCodec(), d, slog.New(slog.DiscardHandler)); err != nil {
		t.Fatalf("the access reactor could not be constructed: %v", err)
	}

	var found bool
	for _, p := range d.probes {
		if p.Name() == "openfga" {
			found = true
		}
	}
	if !found {
		t.Error("no openfga probe is registered on the worker, which is the binary that " +
			"writes tuples. A permission graph that has stopped changing would report " +
			"healthy: grants stop landing, revocations stop being confirmed, and every " +
			"dashboard stays green")
	}
}

// Without a store id the writer must NOT be constructed.
//
// A writer pointed at no store accepts every tuple and applies none of them,
// which is the worst outcome available on this path: the reactor records the
// event as handled, its cursor advances past it, and the grant is gone with no
// replay that can bring it back.
//
// Migrated from cmd/projector along with the writer itself. The positive
// control runs FIRST and in the same process; without it this test passes
// whenever Valkey is merely unreachable — a refusal for a reason that has
// nothing to do with the store id, which is a test that cannot fail.
func TestNoTupleWriterWithoutAStore(t *testing.T) {
	cfg := testConfig(t)
	cfg.OpenFGA.StoreID = storeID
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	if _, err := newAccessTuples(newCodec(), d, slog.New(slog.DiscardHandler)); err != nil {
		closeAll()
		t.Fatalf("precondition: construction fails even WITH a store id, so this test "+
			"would pass without exercising anything: %v", err)
	}
	closeAll()

	cfg.OpenFGA.StoreID = ""
	d, closeAll = newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if _, err := newAccessTuples(newCodec(), d, slog.New(slog.DiscardHandler)); err == nil {
		t.Error("a tuple writer was constructed with no store id: every write would be " +
			"accepted and none applied, and the cursor would advance past it anyway")
	}
}
