package main

import (
	"context"
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// Authorization must be wired, and must DENY when it cannot work.
//
// Three adapters in this codebase were once built, fully tested, and constructed
// by no binary at all — every component test passed while three notification
// channels delivered nothing. Authorization has a worse version of that failure:
// a Guard that is nil, or never consulted, does not deny. It is skipped.
//
// So the assertion is on the COMPOSITION ROOT, not on the kernel.
func TestAuthzIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.authz == nil {
		t.Fatal("no authorization guard was constructed: every handler that asks for one " +
			"gets nil, and a nil guard does not deny — it panics or is skipped")
	}
}

// With no store id configured — the state of a fresh environment — the guard
// must still exist and must refuse everything.
//
// This is the case that would otherwise ship: OpenFGA reachable, no store, and a
// checker that quietly evaluates against no tuples. Denying is correct; denying
// LOUDLY, from an explicit DenyAll, is what makes it findable.
func TestAuthzDeniesWithoutAStore(t *testing.T) {
	cfg := testConfig(t)
	cfg.OpenFGA.StoreID = ""

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.authz == nil {
		t.Fatal("no guard was constructed")
	}
	decision := d.authz.Check(context.Background(), authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "usr_1"},
		Relation:  "viewer",
		Resource:  authz.ResourceRef{Type: "folder", ID: "fld_1"},
	})
	if decision.Allowed() {
		t.Fatal("an unconfigured authorization service permitted access")
	}
}

// The probe must report OpenFGA as FAIL_CLOSED. A Degradable probe here would
// tell an operator that losing authorization is survivable, when in fact every
// request is being denied.
func TestOpenFGAProbeIsFailClosed(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	var found bool
	for _, p := range d.probes {
		if p.Name() != "openfga" {
			continue
		}
		found = true
		if got := p.Criticality().String(); got != "fail_closed" {
			t.Errorf("the openfga probe is %s; losing authorization denies every request "+
				"and must be reported as fail_closed", got)
		}
	}
	if !found {
		t.Error("no openfga probe is registered: an authorization outage would be invisible")
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// Revocation must be immediate, and that depends entirely on ports the Guard
// takes from Valkey. Both are optional in the kernel, and their absence is
// INVISIBLE at runtime: checks still work, they just keep permitting a principal
// whose access was revoked seconds ago.
//
// Only a test of the composition root can see that, which is why this asserts
// here rather than in the kernel.
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
