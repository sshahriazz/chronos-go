package main

import (
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/identity"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k", "OPENFGA_STORE_ID": "01JQTESTSTORE0000000000000",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// The projector must report OpenFGA's health.
//
// An authorization graph that has stopped being updated is invisible otherwise:
// the read model stays fresh, every projection reports healthy, and nothing in
// the process looks wrong while grants quietly stop landing.
//
// Infra-free — Dial does not connect, so this holds whether or not OpenFGA is
// running. The assertions that need a live Valkey are in
// wiring_integration_test.go, because a composition-root test that silently
// depends on a running service fails in CI for a reason that has nothing to do
// with the code.
func TestTheProjectorProbesOpenFGA(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	defer closeAll()

	var found bool
	for _, p := range d.probes {
		if p.Name() == "openfga" {
			found = true
		}
	}
	if !found {
		t.Error("no openfga probe is registered on the projector: a permission graph that " +
			"has stopped changing would report healthy")
	}
}

// Every read model in the system must appear in the registry, because a
// projection that is not listed there does not run.
//
// This is the failure this repository has already had once: three notification
// adapters were built, tested and constructed by no binary, and every component
// test passed while three channels delivered nothing. A projection is worse — it
// fails silently and permanently, with a read model that is simply empty.
func TestEveryProjectionIsRegistered(t *testing.T) {
	registered := make(map[string]bool)
	for _, p := range projections(newCodec()) {
		if registered[p.Name()] {
			// Two projections under one name share a checkpoint row and a lease,
			// so one of them would never run and which one is undefined.
			t.Errorf("two projections are registered as %q", p.Name())
		}
		registered[p.Name()] = true

		// Checked here rather than only at startup: a filter that mixes selectors
		// is refused by the runner, so this projection would take the process down
		// on deploy instead of failing in a test.
		if err := p.Filter().Validate(); err != nil {
			t.Errorf("projection %q has an unusable filter: %v", p.Name(), err)
		}
	}

	for _, name := range []string{
		identityprojection.UserName,
		identityprojection.SessionName,
		identityprojection.ReservationName,
	} {
		if !registered[name] {
			t.Errorf("projection %q is not registered on the projector, so it never runs "+
				"and its table stays empty", name)
		}
	}
}

// The projector must be able to DECODE every event type it might be handed.
//
// An unregistered type is a hard read error, not a skip (adapter/eventcodec), so
// a projector running identity projections without identity's types stops dead on
// the first identity event in the log — including events for projections it does
// not own, because the filter is by prefix.
//
// Compared against a codec built from the module's own registration rather than
// against a list written here: a second list is a second place to forget an event.
func TestTheProjectorDecodesEveryIdentityEvent(t *testing.T) {
	reference := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	identity.RegisterEvents(reference)

	known := make(map[string]bool)
	for _, typ := range newCodec().Types() {
		known[typ] = true
	}

	for _, typ := range reference.Types() {
		if !known[typ] {
			t.Errorf("the projector cannot decode %q; every identity event it is handed "+
				"would stop the projection", typ)
		}
	}
}
