//go:build integration

package main

import (
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// The end-to-end half of the key cache wiring: with the stack up, the real
// composition root must actually build one.
//
// Integration-tagged because constructing a Valkey client dials eagerly, unlike
// the PostgreSQL pool and the KurrentDB client, which are lazy. A plain unit test
// of newDependencies would therefore pass on a developer's machine and fail in
// CI — which is the same shape of mistake as a test that depends on an ambient
// .env, and it is caught here rather than in a pipeline.
func TestNewDependenciesWiresTheKeyCache(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.keyCache == nil {
		t.Fatal("Valkey is reachable but no subject key cache was constructed: every " +
			"notification will unwrap its subject key at OpenBao")
	}
	if d.cacheEvery <= 0 || d.cacheEvery > d.cacheTTL {
		t.Errorf("sweep %s must be positive and no longer than the TTL %s, or keys expire "+
			"without being zeroed", d.cacheEvery, d.cacheTTL)
	}
	if d.cacheTTL > config.MaxKeyCacheTTL {
		t.Errorf("key cache TTL %s exceeds the %s ceiling", d.cacheTTL, config.MaxKeyCacheTTL)
	}
}

// With it enabled, the worker must exist AND register the workflows — the two
// halves are useless apart. Three adapters in this repository were once fully
// built, fully tested, and constructed by no binary; only a composition-root
// test sees that.
func TestEnablingDurableWorkRegistersTheWorkflows(t *testing.T) {
	t.Setenv("TEMPORAL_ENABLED", "true")
	cfg := testConfig(t)
	log := slog.New(slog.DiscardHandler)

	d, closeAll := newDependencies(cfg, log, newCodec())
	defer closeAll()

	if d.temporal == nil {
		t.Fatal("TEMPORAL_ENABLED=true built no client, so no durable work can be started")
	}
	if d.temporalWorker == nil {
		t.Fatal("a client was built with no worker: durable work would be accepted and " +
			"never run, and the caller would be told it started")
	}
	if len(d.temporalWorker.Registered()) == 0 {
		t.Fatal("the worker registered no workflows; every task would fail to find a handler")
	}
	// The starter the kernel sees is the client, so it must satisfy the port.
	var _ workflow.Starter = d.temporal

	// And the reactor must actually USE it. A client and a worker that the
	// notification path never reaches is the same failure as not building them:
	// every send still goes inline, and the retry policy the workflow owns never
	// applies.
	for _, r := range reactors(newCodec(), d) {
		er, ok := r.(*notify.EventReactor)
		if !ok {
			continue
		}
		if !er.Durable() {
			t.Fatal("the notification reactor still delivers inline while durable work is " +
				"enabled; an SMTP outage would park a backlog instead of being retried")
		}
	}
}
