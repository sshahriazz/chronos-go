package main

import (
	"log/slog"
	"testing"
)

// Probe results must reach Prometheus, not just the status endpoint.
//
// The observer landed wired into nothing: all three binaries compiled, every test
// passed, and dependency health was exported by none of them. Nothing detects
// that at runtime either — the registry answers /readyz and GetStatus exactly as
// it should while every dashboard silently falls back to `up{job=...}`, which
// reports whether Prometheus can scrape the process rather than whether its
// dependencies work.
//
// Infra-free: building the registry dials nothing.
func TestHealthProbesAreExportedToPrometheus(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec(), 2)
	defer closeAll()

	if !newHealthRegistry(d).Exports() {
		t.Error("the health registry has no observer, so no probe result reaches " +
			"Prometheus and no alert can fire on a dependency going down")
	}
}
