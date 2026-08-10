//go:build integration

package main

import (
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
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
