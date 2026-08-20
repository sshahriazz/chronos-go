package obs_test

import (
	"context"
	"io"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/obs"
)

func discard() *slog.Logger { return slog.New(slog.DiscardHandler) }

// get issues a REAL HTTP request against a REAL listener.
//
// httptest.NewServer would test the handler; it would not test that anything
// bound a port, and "the handler exists but nothing serves it" is precisely the
// shape this repository keeps shipping.
func get(t *testing.T, addr, path, token string) (int, string) {
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

func startProfiler(t *testing.T, cfg obs.ProfilingConfig) *obs.Profiler {
	t.Helper()
	p, err := obs.StartProfiling(t.Context(), cfg, discard())
	if err != nil {
		t.Fatalf("starting the profiler: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := p.Shutdown(ctx); err != nil {
			t.Errorf("shutting the profiler down: %v", err)
		}
	})
	return p
}

// Enabled: the endpoints must ANSWER, over real HTTP, on a real port.
func TestTheProfilerServesEveryProfileWhenEnabled(t *testing.T) {
	p := startProfiler(t, obs.ProfilingConfig{Enabled: true, Addr: "127.0.0.1:0"})
	if !p.Enabled() || p.Addr() == "" {
		t.Fatal("StartProfiling reported success and bound nothing")
	}

	for _, tc := range []struct {
		name string
		path string
		want string
	}{
		// The Go 1.27 profile this whole change exists for. If it 404s, `make
		// leaks` has a detector and operators have no way to read one.
		{"goroutineleak", "/debug/pprof/goroutineleak?debug=1", "goroutineleak profile: total "},
		{"heap", "/debug/pprof/heap?debug=1", "heap profile:"},
		{"goroutine", "/debug/pprof/goroutine?debug=1", "goroutine profile: total "},
		{"allocs", "/debug/pprof/allocs?debug=1", "heap profile:"},
		{"block", "/debug/pprof/block?debug=1", "--- contention:"},
		{"mutex", "/debug/pprof/mutex?debug=1", "--- mutex:"},
		{"index", "/debug/pprof/", "goroutineleak"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, body := get(t, p.Addr(), tc.path, "")
			if code != http.StatusOK {
				t.Fatalf("GET %s = %d, want 200", tc.path, code)
			}
			if tc.want != "" && !strings.Contains(body, tc.want) {
				t.Fatalf("GET %s did not contain %q; got %.200q", tc.path, tc.want, body)
			}
		})
	}
}

// Disabled: nothing may listen, anywhere.
//
// The assertion is on the SOCKET, not on a boolean. A profiler that reports
// Enabled()==false while a goroutine somewhere still serves /debug/pprof is
// exactly the bug this test has to be able to catch, and only a connection
// attempt catches it.
func TestNothingListensWhenProfilingIsDisabled(t *testing.T) {
	// Reserve a port, learn its number, release it. Whatever the profiler does
	// with the address, it must not be serving here afterwards.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}

	p := startProfiler(t, obs.ProfilingConfig{Enabled: false, Addr: addr})
	if p.Enabled() {
		t.Fatal("a disabled profiler reports itself enabled")
	}
	if p.Addr() != "" {
		t.Fatalf("a disabled profiler reports address %q", p.Addr())
	}

	d := net.Dialer{Timeout: 2 * time.Second}
	conn, err := d.DialContext(t.Context(), "tcp", addr)
	if err == nil {
		_ = conn.Close()
		t.Fatalf("something is serving on %s with PPROF_ENABLED=false: the toggle does "+
			"not control the listener", addr)
	}
}

// The token must be REQUIRED, not merely accepted.
func TestTheProfilerRefusesRequestsWithoutTheToken(t *testing.T) {
	const token = "0123456789abcdef0123456789abcdef"
	p := startProfiler(t, obs.ProfilingConfig{Enabled: true, Addr: "127.0.0.1:0", Token: token})

	for _, tc := range []struct {
		name string
		send string
		want int
	}{
		{"no credential", "", http.StatusUnauthorized},
		{"wrong credential", "00000000000000000000000000000000", http.StatusUnauthorized},
		{"prefix of the token", "0123456789abcdef", http.StatusUnauthorized},
		{"the token", token, http.StatusOK},
	} {
		t.Run(tc.name, func(t *testing.T) {
			code, _ := get(t, p.Addr(), "/debug/pprof/heap?debug=1", tc.send)
			if code != tc.want {
				t.Fatalf("GET /debug/pprof/heap with %q = %d, want %d", tc.name, code, tc.want)
			}
		})
	}

	// Every path, not just the one above. A gate applied to the mux and not to
	// each route is the failure that leaves /debug/pprof/cmdline open while the
	// test on /heap passes.
	for _, path := range []string{
		"/debug/pprof/", "/debug/pprof/heap", "/debug/pprof/trace?seconds=1",
		"/debug/pprof/profile?seconds=1",
		"/debug/pprof/goroutineleak?debug=1", "/debug/pprof/goroutine?debug=1",
	} {
		if code, _ := get(t, p.Addr(), path, ""); code != http.StatusUnauthorized {
			t.Errorf("GET %s with no credential = %d, want 401", path, code)
		}
	}
}

// A bind failure must be an error the caller can survive, never a panic and
// never a silent success.
func TestABindFailureIsReportedAndSurvivable(t *testing.T) {
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("occupying a port: %v", err)
	}
	defer func() { _ = ln.Close() }()

	p, err := obs.StartProfiling(t.Context(),
		obs.ProfilingConfig{Enabled: true, Addr: ln.Addr().String()}, discard())
	if err == nil {
		t.Fatal("binding an occupied port succeeded")
	}
	if p == nil {
		t.Fatal("StartProfiling returned a nil Profiler on failure; every caller that " +
			"defers Shutdown now panics because a DEBUG surface could not take its port")
	}
	if p.Enabled() || p.Addr() != "" {
		t.Fatalf("a failed profiler reports enabled=%v addr=%q", p.Enabled(), p.Addr())
	}
	if err := p.Shutdown(t.Context()); err != nil {
		t.Fatalf("shutting down a failed profiler: %v", err)
	}
}

// pprof must not reach http.DefaultServeMux.
//
// `import _ "net/http/pprof"` registers there, and DefaultServeMux is a
// process-global that any http.Server built with a nil Handler will serve. That
// is how a profiler ends up published on a port nobody meant to publish it on,
// years after the import was added, with nothing in review to catch it.
func TestPprofIsNotRegisteredOnTheDefaultServeMux(t *testing.T) {
	req, err := http.NewRequestWithContext(
		t.Context(), http.MethodGet, "http://example.invalid/debug/pprof/heap", nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	if _, pattern := http.DefaultServeMux.Handler(req); pattern != "" {
		t.Fatalf("http.DefaultServeMux routes /debug/pprof/heap via %q: something in this "+
			"binary blank-imports net/http/pprof, which publishes the profiler on every "+
			"server built with a nil Handler", pattern)
	}
}
