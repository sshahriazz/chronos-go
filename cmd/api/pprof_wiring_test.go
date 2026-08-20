package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/config"
)

// The profiler must be built BY THE COMPOSITION ROOT, not merely be buildable.
//
// This is the seventh time a seam in this repository has been fully written,
// fully tested and constructed by no binary, and profiling has the worst
// signature of the lot: nothing fails, nothing logs, and the absence is
// discovered by an engineer who is already in the middle of an incident and now
// has no heap profile, no CPU profile and no goroutineleak profile to look at.
//
// So the assertion is on newDependencies — the exact function main calls — and
// it goes all the way to a socket.
func TestTheProfilerIsBuiltByTheCompositionRoot(t *testing.T) {
	cfg := testConfig(t)
	if cfg.Profiling.Enabled {
		t.Fatal("PPROF_ENABLED defaults to true: an unconfigured deployment would publish " +
			"live heap contents and every goroutine's stack")
	}
	cfg.Profiling.Enabled = true
	cfg.Profiling.Addr = "127.0.0.1:0"

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.profiling == nil {
		t.Fatal("no profiler was constructed: /debug/pprof exists nowhere, so the Go 1.27 " +
			"goroutineleak profile has nothing to be read from and neither does CPU or heap")
	}
	if !d.profiling.Enabled() || d.profiling.Addr() == "" {
		t.Fatal("PPROF_ENABLED=true and nothing bound a port: the toggle reaches the " +
			"configuration and not the listener")
	}

	code, body := getDebug(t, d.profiling.Addr(), "/debug/pprof/goroutineleak?debug=1", "")
	if code != http.StatusOK {
		t.Fatalf("GET /debug/pprof/goroutineleak = %d, want 200", code)
	}
	if !strings.Contains(body, "goroutineleak profile: total ") {
		t.Fatalf("the goroutineleak profile is not being served; got %.200q", body)
	}
}

// The TOKEN must survive the mapping from config to obs.
//
// This is the one field whose loss is not merely invisible but inverted: drop
// `Token:` from the three-line struct literal in deps.go and every test above
// still passes, the listener still binds, the profiles still answer — and they
// answer to anybody. Only a request WITHOUT the credential can tell the
// difference, so that is what this asserts.
func TestTheProfilingTokenReachesTheListener(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	cfg := testConfig(t)
	cfg.Profiling.Enabled = true
	cfg.Profiling.Addr = "127.0.0.1:0"
	cfg.Profiling.Token = config.Secret(token)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if !d.profiling.Enabled() {
		t.Fatal("no listener")
	}
	if code, _ := getDebug(t, d.profiling.Addr(), "/debug/pprof/heap?debug=1", ""); code != http.StatusUnauthorized {
		t.Fatalf("an unauthenticated GET /debug/pprof/heap returned %d, want 401: PPROF_TOKEN "+
			"is set and the listener does not enforce it", code)
	}
	if code, _ := getDebug(t, d.profiling.Addr(), "/debug/pprof/heap?debug=1", token); code != http.StatusOK {
		t.Fatalf("an authenticated GET /debug/pprof/heap returned %d, want 200", code)
	}
}

// With PPROF_ENABLED unset — the default, and the state make check runs in —
// nothing may listen.
func TestNoProfilerListensByDefault(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}

	cfg := testConfig(t)
	cfg.Profiling.Addr = addr // Enabled left at its default.

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.profiling.Enabled() || d.profiling.Addr() != "" {
		t.Fatalf("the default configuration started a profiler on %q", d.profiling.Addr())
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	conn, err := dialer.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("something is serving on %s with PPROF_ENABLED unset", addr)
	}
}

// pprof must NOT be reachable on the tenant API port.
//
// The API mux is the one surface every customer can reach, and none of the
// ADR-021 gates would cover a /debug route on it: those are Connect
// interceptors and /debug/pprof is not a Connect handler. A pprof route mounted
// there would therefore be unauthenticated no matter what the policy set says,
// and nothing in the enforcement pipeline would report it.
func TestPprofIsNotServedOnTheAPIPort(t *testing.T) {
	mux, _, _ := serveTestMux(t)

	for _, path := range []string{
		"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/goroutineleak",
		"/debug/pprof/profile", "/debug/pprof/cmdline",
	} {
		req, err := http.NewRequestWithContext(t.Context(), http.MethodGet,
			"http://api.invalid"+path, nil)
		if err != nil {
			t.Fatalf("building the request: %v", err)
		}
		if _, pattern := mux.Handler(req); pattern != "" {
			t.Errorf("the API mux routes %s via %q: the profiler is reachable by every "+
				"client that can reach the product, with no gate in front of it",
				path, pattern)
		}
	}
}

func getDebug(t *testing.T, addr, path, token string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), http.MethodGet, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<20))
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return res.StatusCode, string(body)
}
