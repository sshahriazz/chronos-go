package main

import (
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
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
