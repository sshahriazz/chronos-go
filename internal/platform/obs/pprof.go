package obs

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"html"
	"io"
	"log/slog"
	"net"
	"net/http"
	"runtime"
	"runtime/pprof"
	"runtime/trace"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ProfilingConfig is what a binary needs to serve the Go runtime profiler.
//
// It mirrors config.ProfilingConfig deliberately rather than importing it: obs
// sits beneath the composition root in the import contract (CONVENTIONS §2), and
// a kernel package that reads the application's configuration type cannot be
// used by a test that wants a different one. The mapping is three lines in the
// composition root, and a test asserts that those three lines are there.
type ProfilingConfig struct {
	// Enabled creates the listener. Off means net.Listen is never called.
	Enabled bool

	// Addr is the listener's own host:port. It is NEVER the API's: see the
	// reasoning on StartProfiling.
	Addr string

	// Token, when non-empty, is the bearer credential every request must carry.
	Token string
}

// MaxProfileSeconds caps ?seconds= on the CPU profile and the execution trace.
//
// The stdlib imposes no ceiling, which is fine for a handler you reach over a
// port-forward and wrong for one that is listening continuously: each in-flight
// request pins a goroutine, a buffer and — for the CPU profile — a
// process-global that no second request can take. Five minutes is longer than
// any diagnostic anyone runs by hand and short enough that a forgotten request
// clears itself.
const MaxProfileSeconds = 300

// Profiler owns the debug listener.
//
// The zero value and the disabled value are both usable: Enabled reports false,
// Addr returns "", Shutdown returns nil, and nothing listens. That is
// deliberate — a composition root that forgets a nil check must get a profiler
// that does nothing rather than a panic, because the alternative is a crash loop
// caused by an OPTIONAL debug surface.
type Profiler struct {
	addr string
	http *http.Server
}

// Enabled reports whether a listener is actually serving.
func (p *Profiler) Enabled() bool { return p != nil && p.http != nil }

// Addr is the resolved listen address, or "" when nothing is listening.
//
// Resolved, not configured: with a port of 0 this is the port the kernel picked,
// which is what a test needs and what the startup log line should say.
func (p *Profiler) Addr() string {
	if p == nil {
		return ""
	}
	return p.addr
}

// Shutdown drains the debug listener.
func (p *Profiler) Shutdown(ctx context.Context) error {
	if !p.Enabled() {
		return nil
	}
	return p.http.Shutdown(ctx)
}

// StartProfiling binds and serves /debug/pprof on its OWN listener.
//
// # Why its own listener, and not a route on the API mux
//
// The API port is the tenant surface. A handler mounted there is reachable by
// every client that can reach the product, and none of the ADR-021 enforcement
// gates would protect it: those are Connect interceptors, they run inside a
// Connect handler, and /debug/pprof is not one — so an "authenticated" pprof
// route on that mux would in fact be an unauthenticated one, and nothing in the
// codebase would report the difference.
//
// A second listener also makes exposure a network decision as well as an
// application one. The port is not published in docker-compose.yml and needs no
// ingress rule, so reaching it means already being inside the pod. Two
// independent locks, either of which is sufficient.
//
// It keeps the two servers' limits apart as well. /debug/pprof/profile?seconds=30
// holds a request open for thirty seconds by design; the API server's timeouts
// exist to refuse exactly that shape.
//
// # Failure policy
//
// A bind failure is RETURNED and the returned Profiler is a working disabled
// one, so a composition root can log and continue. ADR-010 applies at full
// strength: a debug surface that could not take its port — most often because
// something else already owns it — must not stop a server from serving.
func StartProfiling(ctx context.Context, cfg ProfilingConfig, log *slog.Logger) (*Profiler, error) {
	if !cfg.Enabled {
		log.Info("profiling is disabled; /debug/pprof is served nowhere in this process",
			"reason", "PPROF_ENABLED=false")
		return &Profiler{}, nil
	}

	// Listen synchronously, so a bind failure is an error the caller sees and so
	// Addr reports the port the kernel actually gave us. ctx bounds the bind
	// only; the listener outlives it and is stopped by Shutdown.
	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return &Profiler{}, fmt.Errorf("obs: binding the profiling listener on %q: %w",
			cfg.Addr, err)
	}

	srv := &http.Server{
		Handler: ProfilingHandler(cfg.Token),
		// No ReadTimeout and no WriteTimeout: the CPU profile and the execution
		// trace stream for as long as the caller asked for, and a write deadline
		// would truncate every profile longer than it. MaxProfileSeconds is the
		// bound instead, and it bounds the thing that actually varies.
		//
		// ReadHeaderTimeout is set regardless, because it covers the one phase
		// that has nothing to do with how long a profile runs.
		ReadHeaderTimeout: 5 * time.Second,
		IdleTimeout:       60 * time.Second,
		// A handful of fixed paths and one bearer token. Nothing legitimate here
		// needs the 1 MiB and 500 values the stdlib defaults to.
		MaxHeaderBytes:      8 << 10,
		MaxHeaderValueCount: 64,
	}

	p := &Profiler{addr: ln.Addr().String(), http: srv}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("profiling listener stopped", "error", err)
		}
	}()

	log.Info("profiling enabled",
		"addr", p.addr,
		"authenticated", cfg.Token != "",
		"index", "/debug/pprof/")
	return p, nil
}

// ProfilingHandler is the /debug/pprof surface, optionally behind a bearer token.
//
// # Why this does not use net/http/pprof
//
// Because importing it is not free and not local. net/http/pprof has an init()
// that calls http.HandleFunc for all five of its paths, so the mere fact of the
// import — blank or named, used or not — publishes the profiler on
// http.DefaultServeMux. DefaultServeMux is a process-global that every
// http.Server built with a nil Handler serves, and obs is imported by cmd/api,
// cmd/worker and cmd/projector alike. One import in this file would therefore
// have armed a pprof surface in three binaries, on any port any of them ever
// serves with a nil handler, with nothing at the call site to hint at it. That
// is verified, not assumed: TestPprofIsNotRegisteredOnTheDefaultServeMux failed
// against the net/http/pprof version of this file and passes against this one.
//
// The cost of not importing it is this function. The profiles themselves come
// from runtime/pprof and runtime/trace, which is where net/http/pprof gets them
// too, so the bytes on the wire are identical — `go tool pprof <url>` is the
// test that says so.
//
// Two stdlib paths are deliberately NOT served:
//
//   - /debug/pprof/cmdline returns os.Args. Nothing here needs it, and a
//     process's argv is a routine place for a credential passed as a flag.
//   - /debug/pprof/symbol resolves raw addresses to names. Go's profiles are
//     already symbolised in the protobuf, so `go tool pprof` needs it only for
//     profiles this handler does not produce.
func ProfilingHandler(token string) http.Handler {
	mux := http.NewServeMux()
	// The CPU profile and the execution trace are not runtime/pprof Profiles —
	// they stream for a duration — so they are routed before the catch-all.
	mux.HandleFunc("GET /debug/pprof/profile", serveCPUProfile)
	mux.HandleFunc("GET /debug/pprof/trace", serveExecutionTrace)
	// Everything else is a named profile, /debug/pprof/goroutineleak among them.
	mux.HandleFunc("GET /debug/pprof/", serveNamedProfile)
	return requireBearer(token, mux)
}

// serveNamedProfile serves one runtime/pprof profile by name, or the index.
func serveNamedProfile(w http.ResponseWriter, r *http.Request) {
	name, _ := strings.CutPrefix(r.URL.Path, "/debug/pprof/")
	if name == "" {
		serveIndex(w)
		return
	}

	p := pprof.Lookup(name)
	if p == nil {
		// Named rather than a bare 404: "goroutineleak" 404ing on a toolchain
		// that should have it is a finding, and a blank 404 hides it.
		w.Header().Set("X-Content-Type-Options", "nosniff")
		http.Error(w, "unknown profile: "+name, http.StatusNotFound)
		return
	}

	debug := intParam(r, "debug", 0)
	// gc=1 on the heap profile forces a collection first, so the numbers
	// describe live objects rather than whatever survived the last cycle.
	if name == "heap" && intParam(r, "gc", 0) > 0 {
		runtime.GC()
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	if debug != 0 {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Disposition", `attachment; filename="`+name+`"`)
	}
	// Errors here happen after the status line is out. Nothing to report to the
	// caller; the truncated profile is the report.
	_ = p.WriteTo(w, debug)
}

// serveCPUProfile streams a CPU profile for ?seconds= (default 30).
func serveCPUProfile(w http.ResponseWriter, r *http.Request) {
	seconds, ok := durationParam(r, 30)
	if !ok {
		profileError(w, http.StatusBadRequest, badSecondsMessage)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="profile"`)

	if err := pprof.StartCPUProfile(w); err != nil {
		// The CPU profiler is process-global and takes one writer. A second
		// concurrent request is refused rather than queued: queueing would make
		// the ?seconds= the caller asked for mean something else.
		profileError(w, http.StatusConflict, "a CPU profile is already running: "+err.Error())
		return
	}
	sleepOrCancel(r, seconds)
	pprof.StopCPUProfile()
}

// serveExecutionTrace streams a runtime/trace for ?seconds= (default 1).
func serveExecutionTrace(w http.ResponseWriter, r *http.Request) {
	seconds, ok := durationParam(r, 1)
	if !ok {
		profileError(w, http.StatusBadRequest, badSecondsMessage)
		return
	}

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", `attachment; filename="trace"`)

	if err := trace.Start(w); err != nil {
		profileError(w, http.StatusConflict, "a trace is already running: "+err.Error())
		return
	}
	sleepOrCancel(r, seconds)
	trace.Stop()
}

// sleepOrCancel waits out the requested duration, or returns early when the
// caller hangs up — so a disconnected client stops paying for a profile nobody
// will read.
func sleepOrCancel(r *http.Request, d time.Duration) {
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-t.C:
	case <-r.Context().Done():
	}
}

// serveIndex lists what this handler serves, with each profile's current count.
func serveIndex(w http.ResponseWriter) {
	profiles := pprof.Profiles()
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Name() < profiles[j].Name() })

	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	var b strings.Builder
	b.WriteString("<html><head><title>/debug/pprof/</title></head><body>\n")
	b.WriteString("<h1>/debug/pprof/</h1><table>\n")
	for _, p := range profiles {
		name := html.EscapeString(p.Name())
		// Count() on goroutineleak reports what the LAST detection found, so it
		// reads 0 until something has fetched the profile at least once. Said
		// here rather than left to surprise whoever reads the page.
		fmt.Fprintf(&b, "<tr><td>%d</td><td><a href=%q>%s</a></td></tr>\n",
			p.Count(), name+"?debug=1", name)
	}
	for _, extra := range []string{"profile?seconds=30", "trace?seconds=1"} {
		fmt.Fprintf(&b, "<tr><td></td><td><a href=%q>%s</a></td></tr>\n",
			extra, html.EscapeString(extra))
	}
	b.WriteString("</table></body></html>\n")
	_, _ = io.WriteString(w, b.String())
}

func intParam(r *http.Request, name string, def int) int {
	raw := r.URL.Query().Get(name)
	if raw == "" {
		return def
	}
	n, err := strconv.Atoi(raw)
	if err != nil {
		return def
	}
	return n
}

// badSecondsMessage is a CONSTANT, and the reason is not tidiness.
//
// The obvious version of this — an error naming the value the caller sent — puts
// request input straight back into a response body. On a text/plain endpoint
// behind a bearer token that is not an exploit, but it is the pattern that
// becomes one the first time somebody copies it somewhere that renders HTML, and
// gosec's taint analysis is right to refuse it. Nothing derived from the request
// reaches the writer here.
var badSecondsMessage = "seconds must be an integer between 1 and " +
	strconv.Itoa(MaxProfileSeconds)

// durationParam reads ?seconds=, reporting false for anything out of range.
func durationParam(r *http.Request, defSeconds int) (time.Duration, bool) {
	raw := r.URL.Query().Get("seconds")
	if raw == "" {
		return time.Duration(defSeconds) * time.Second, true
	}
	n, err := strconv.Atoi(raw)
	if err != nil || n <= 0 || n > MaxProfileSeconds {
		return 0, false
	}
	return time.Duration(n) * time.Second, true
}

// profileError reports a failure in the way `go tool pprof` expects: a status
// code plus X-Go-Pprof, which is what tells it the body is a message and not a
// truncated profile.
func profileError(w http.ResponseWriter, code int, msg string) {
	w.Header().Del("Content-Disposition")
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Header().Set("X-Go-Pprof", "1")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.WriteHeader(code)
	_, _ = fmt.Fprintln(w, msg)
}

// requireBearer refuses every request that does not present the token.
//
// An empty token means no check, which config.validate() permits only for a
// loopback bind inside local. The comparison is constant-time: a debug listener
// has no lockout and no rate limit, so a byte-at-a-time timing oracle would
// reduce a 32-character token to a few hundred requests.
func requireBearer(token string, next http.Handler) http.Handler {
	if token == "" {
		return next
	}
	want := []byte("Bearer " + token)
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got := []byte(r.Header.Get("Authorization"))
		if subtle.ConstantTimeCompare(got, want) != 1 {
			w.Header().Set("WWW-Authenticate", `Bearer realm="pprof"`)
			// No detail: the response says nothing about whether the header was
			// missing, malformed or simply wrong.
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}
