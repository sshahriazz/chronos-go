package main

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// clockControlPath is the read surface: what time does this process think it is.
const clockControlPath = "/debug/clock"

// clockAdvancePath is the write surface: move that time FORWARD.
const clockAdvancePath = "/debug/clock/advance"

// clockControl is the movable clock's listener (ADR-054).
//
// # Why this is a separate listener and not a route on the API mux
//
// The same reason obs.StartProfiling gives, and it applies with more force
// here. The API port is the tenant surface, and the ADR-021 enforcement gates
// that protect it are Connect interceptors — they run inside a Connect handler,
// and a plain HTTP route is not one. A "protected" clock route on that mux
// would in fact be unprotected, and nothing in the codebase would report the
// difference. On its own loopback listener, reaching it means already being on
// the machine.
//
// # Why a bind failure REFUSES the boot
//
// This is the one place cmd/api deliberately breaks ADR-010's "never exit
// because something is unreachable", and the exception is narrow enough to
// state exactly: ADR-010 is about dependencies of the SERVICE. This is not a
// dependency, it is a control the operator explicitly asked for, and it exists
// in local only — so a refusal here can never crash-loop anything a customer
// touches.
//
// The alternative is worse than a dead process. A harness that asked for a
// movable clock and got a server whose clock nothing can move does not fail: it
// hangs, or it silently falls back to real time and every "advance" is a no-op
// answered by a connection refused nobody checks. That is the exact shape of
// failure this repository keeps finding — a thing built, configured, and
// connected to nothing, with a green suite over it.
//
// The zero value is a usable disabled control: Enabled reports false, Addr
// returns "", Shutdown returns nil.
type clockControl struct {
	addr string
	http *http.Server
}

// Enabled reports whether a listener is actually serving.
func (c *clockControl) Enabled() bool { return c != nil && c.http != nil }

// Addr is the resolved listen address, or "" when nothing is listening.
//
// Resolved rather than configured: with a port of 0 this is the port the kernel
// picked, which is what the startup log line has to say for a harness to find
// it.
func (c *clockControl) Addr() string {
	if c == nil {
		return ""
	}
	return c.addr
}

// Shutdown drains the control listener.
func (c *clockControl) Shutdown(ctx context.Context) error {
	if !c.Enabled() {
		return nil
	}
	return c.http.Shutdown(ctx)
}

// startClockControl binds the movable clock's listener, or refuses.
//
// clk is the process's offset clock, and it is nil exactly when the control is
// disabled — the composition root builds one only in that case, so a disabled
// build holds no movable clock at all rather than holding one nothing happens
// to move.
//
// The environment is re-checked HERE even though config.validate has already
// refused a non-local deployment. That duplication is deliberate: the two
// checks fail for different reasons and one of them can be deleted by accident.
// A single guard on a control that can expire anyone's lockout is one edit away
// from no guard.
func startClockControl(
	ctx context.Context,
	env config.Environment,
	cfg config.ClockControlConfig,
	clk *clock.Offset,
	log *slog.Logger,
) (*clockControl, error) {
	if !cfg.Enabled {
		return &clockControl{}, nil
	}
	if !env.IsLocal() {
		return &clockControl{}, fmt.Errorf(
			"the movable clock is enabled and APP_ENV=%s: it is a local-only test control "+
				"and this process refuses to serve with it (ADR-054)", env)
	}
	if clk == nil {
		return &clockControl{}, errors.New(
			"the movable clock is enabled but this process holds no offset clock: the " +
				"control would bind a port and move nothing, and every test using it would " +
				"pass while advancing no time at all")
	}

	var lc net.ListenConfig
	ln, err := lc.Listen(ctx, "tcp", cfg.Addr)
	if err != nil {
		return &clockControl{}, fmt.Errorf("binding the clock control on %q: %w", cfg.Addr, err)
	}

	srv := &http.Server{
		Handler:           clockControlHandler(clk),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       10 * time.Second,
		WriteTimeout:      10 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    8 << 10,
	}
	c := &clockControl{addr: ln.Addr().String(), http: srv}
	go func() {
		if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
			log.Error("clock control listener stopped", "error", err)
		}
	}()

	// Logged at WARN rather than INFO, and it names what is now negotiable. A
	// process running with a movable clock is not an ordinary process, and the
	// line that says so should be the one an operator notices in a log they are
	// skimming for something else.
	log.Warn("THE CLOCK OF THIS PROCESS CAN BE MOVED FORWARD BY ANY CALLER ON LOOPBACK: "+
		"session deadlines, token expiry, attempt ceilings and TOTP steps are all "+
		"derived from it. Local only (ADR-054)",
		"addr", c.addr, "read", clockControlPath, "advance", clockAdvancePath)
	return c, nil
}

// clockControlHandler serves the two routes.
//
// The response is two lines of `key=value` rather than JSON, for the least
// interesting reason available: the codec kernel is the only place this
// repository serializes JSON (ADR-047), and a debug surface is not worth a
// schema. `offset` is a Go duration, `now` is RFC 3339 with nanoseconds.
func clockControlHandler(clk *clock.Offset) http.Handler {
	mux := http.NewServeMux()

	write := func(w http.ResponseWriter) {
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "offset=%s\nnow=%s\n",
			clk.Offset(), clk.Now().Format(time.RFC3339Nano))
	}

	mux.HandleFunc("GET "+clockControlPath, func(w http.ResponseWriter, _ *http.Request) {
		write(w)
	})

	mux.HandleFunc("POST "+clockAdvancePath, func(w http.ResponseWriter, r *http.Request) {
		raw := r.URL.Query().Get("by")
		by, err := time.ParseDuration(raw)
		if err != nil {
			http.Error(w, fmt.Sprintf("by=%q is not a Go duration: %v", raw, err),
				http.StatusBadRequest)
			return
		}
		// The refusal lives in clock.Offset, not here. This handler must not be
		// able to grant something the type does not offer, so it reports the
		// type's error rather than deciding anything itself.
		if _, err := clk.Advance(by); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		write(w)
	})

	return requireLoopback(mux)
}

// requireLoopback refuses any caller that is not on this machine.
//
// The listener is already bound to a loopback address, so this is the second of
// two locks rather than the first. It is here because the bind address is
// configuration and this is code: CLOCK_CONTROL_ADDR is validated at startup,
// and if that validation is ever loosened, weakened, or bypassed by a future
// flag, this check is what still refuses the caller.
func requireLoopback(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		host, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil {
			host = r.RemoteAddr
		}
		ip := net.ParseIP(host)
		if ip == nil || !ip.IsLoopback() {
			http.Error(w, "the clock control answers loopback only", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// newClock builds the process clock.
//
// System unless the movable clock was explicitly asked for, and the second
// return is non-nil in exactly that case. Every collaborator takes the
// clock.Clock; only the control listener takes the *clock.Offset, so nothing
// else in this binary is even able to move time.
func newClock(cfg *config.Config) (clock.Clock, *clock.Offset) {
	if !cfg.ClockControl.Enabled {
		return clock.System{}, nil
	}
	o := clock.NewOffset(clock.System{})
	return o, o
}
