package main

import (
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/config"
)

// ---------------------------------------------------------------------------
// Lock 2: the server REFUSES TO START with the movable clock outside local
// ---------------------------------------------------------------------------

// The assertion is on run() — the exact function main calls — rather than on
// config.Load, because "the configuration package would have complained" is not
// the property that matters. The property is that this binary does not serve.
//
// run() validates configuration as its first act, so this returns before a
// socket is bound, a pool is opened or a dependency is dialled: no running
// stack is needed and nothing is left behind.
func TestTheServerRefusesToStartWithAMovableClockOutsideLocal(t *testing.T) {
	for _, env := range []string{"staging", "production"} {
		t.Run(env, func(t *testing.T) {
			productionEnv(t, env)
			t.Setenv("CLOCK_CONTROL_ENABLED", "true")

			err := run("127.0.0.1:0", slog.New(slog.DiscardHandler))
			if err == nil {
				t.Fatalf("cmd/api started with APP_ENV=%s and a movable clock. Every "+
					"session deadline, token expiry, attempt ceiling and TOTP step in "+
					"that process is now something a caller can step over, and none of "+
					"them produce an error, a metric or a log line when they are", env)
			}
			if !strings.Contains(err.Error(), "CLOCK_CONTROL_ENABLED") {
				t.Fatalf("the refusal does not name the control that caused it, so it is "+
					"not attributable to this change:\n%v", err)
			}
		})
	}
}

// The control case, and the reason the assertion above is attributable.
//
// The same production environment with the flag OFF must produce no complaint
// about the clock. It is asserted through config.Load rather than run() for a
// practical reason: an otherwise-valid production configuration makes run()
// bind a socket and serve until it is signalled, and a test that called it
// would hang rather than assert. An unrelated defect — a bad timezone — is
// planted so there is an error to inspect at all.
func TestTheServerDoesNotComplainAboutAClockItWasNotAsked(t *testing.T) {
	productionEnv(t, "production")
	t.Setenv("CLOCK_CONTROL_ENABLED", "false")
	t.Setenv("APP_TIMEZONE", "Mars/Olympus")

	_, err := config.Load()
	if err == nil {
		t.Fatal("the planted defect did not fail validation, so this test compares nothing")
	}
	if strings.Contains(err.Error(), "CLOCK_CONTROL") {
		t.Fatalf("a disabled control was still complained about, so the refusal in the "+
			"test above is not attributable to the flag:\n%v", err)
	}
}

// ---------------------------------------------------------------------------
// Lock 2b: the SECOND guard, in the composition root itself
// ---------------------------------------------------------------------------

// startClockControl refuses a non-local environment on its own.
//
// This duplicates config.validate deliberately, and the duplication is the
// point: the two guards fail for different reasons and either can be deleted by
// somebody who has just satisfied the other. A control that expires anybody's
// lockout should not be one edit away from unguarded.
func TestTheClockControlRefusesANonLocalEnvironmentByItself(t *testing.T) {
	clk := clock.NewOffset(clock.System{})
	cfg := config.ClockControlConfig{Enabled: true, Addr: "127.0.0.1:0"}

	for _, env := range []config.Environment{config.Staging, config.Production} {
		ctl, err := startClockControl(t.Context(), env, cfg, clk, slog.New(slog.DiscardHandler))
		if err == nil {
			t.Fatalf("APP_ENV=%s bound a clock control on %s", env, ctl.Addr())
		}
		if ctl.Enabled() {
			t.Fatalf("APP_ENV=%s: the call errored AND still left a listener serving", env)
		}
	}
}

// Asking for a movable clock and being given a fixed one is a failure, not a
// fallback: the control would bind a port, answer every advance, and move
// nothing — and every test relying on it would pass while asserting nothing.
func TestTheClockControlRefusesToBindOverAClockItCannotMove(t *testing.T) {
	ctl, err := startClockControl(t.Context(), config.Local,
		config.ClockControlConfig{Enabled: true, Addr: "127.0.0.1:0"},
		nil, slog.New(slog.DiscardHandler))
	if err == nil {
		t.Fatalf("a control was bound on %s over a nil clock", ctl.Addr())
	}
	if ctl.Enabled() {
		t.Fatal("the call errored and still left a listener serving")
	}
}

// ---------------------------------------------------------------------------
// Lock 1: nothing listens, and no clock is movable, by default
// ---------------------------------------------------------------------------

func TestNoClockControlListensByDefault(t *testing.T) {
	cfg := testConfig(t)
	if cfg.ClockControl.Enabled {
		t.Fatal("CLOCK_CONTROL_ENABLED defaults to true")
	}

	// A port reserved and released, so "nothing is serving here" is a statement
	// about this address rather than about an address nobody chose.
	var lc net.ListenConfig
	ln, err := lc.Listen(t.Context(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("reserving a port: %v", err)
	}
	addr := ln.Addr().String()
	if err := ln.Close(); err != nil {
		t.Fatalf("releasing the port: %v", err)
	}
	cfg.ClockControl.Addr = addr // Enabled left at its default.

	ctl, err := startClockControl(t.Context(), cfg.Env, cfg.ClockControl,
		clock.NewOffset(clock.System{}), slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("a disabled control must be a no-op, not an error: %v", err)
	}
	if ctl.Enabled() || ctl.Addr() != "" {
		t.Fatalf("a disabled control is serving on %q", ctl.Addr())
	}
	dialer := net.Dialer{Timeout: 2 * time.Second}
	if conn, err := dialer.DialContext(t.Context(), "tcp", addr); err == nil {
		_ = conn.Close()
		t.Fatalf("something is serving on %s with CLOCK_CONTROL_ENABLED unset", addr)
	}
}

// The default build holds NO movable clock at all — not one that nothing
// happens to move. There is nothing in the process to reach.
func TestTheDefaultProcessHoldsNoMovableClock(t *testing.T) {
	cfg := testConfig(t)

	clk, movable := newClock(cfg)
	if movable != nil {
		t.Fatal("the default configuration built a movable clock")
	}
	if _, ok := clk.(clock.System); !ok {
		t.Fatalf("the default clock is %T, want clock.System", clk)
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()
	if d.movableClock != nil {
		t.Fatal("the composition root built a movable clock with the control disabled")
	}
	if d.clock == nil {
		t.Fatal("the composition root built no clock at all; everything time-derived " +
			"would be constructed over nil")
	}
}

// ---------------------------------------------------------------------------
// The composition root: ONE clock, and identity reads it
// ---------------------------------------------------------------------------

// Enabled, the process's clock and its movable clock must be the SAME object.
//
// Two would be worse than none. The control would move a clock that some rules
// follow and others do not, so a test could advance past a TOTP step while the
// session deadline it also depends on stayed put — and the disagreement would
// surface as an unrelated flake somewhere else.
func TestTheMovableClockIsTheProcessClock(t *testing.T) {
	cfg := testConfig(t)
	cfg.ClockControl.Enabled = true
	cfg.ClockControl.Addr = "127.0.0.1:0"

	clk, movable := newClock(cfg)
	if movable == nil {
		t.Fatal("CLOCK_CONTROL_ENABLED=true built no movable clock")
	}
	if clk != clock.Clock(movable) {
		t.Fatalf("the process clock (%T) is not the movable clock: the control would "+
			"move a clock only some rules read", clk)
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()
	if d.movableClock == nil {
		t.Fatal("the composition root built no movable clock with the control enabled")
	}
	if d.clock != clock.Clock(d.movableClock) {
		t.Fatal("dependencies.clock and dependencies.movableClock are different objects")
	}
}

// ---------------------------------------------------------------------------
// The control surface itself
// ---------------------------------------------------------------------------

func TestTheClockControlAdvancesAndRefusesToRewind(t *testing.T) {
	clk := clock.NewOffset(clock.System{})
	ctl, err := startClockControl(t.Context(), config.Local,
		config.ClockControlConfig{Enabled: true, Addr: "127.0.0.1:0"},
		clk, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("startClockControl: %v", err)
	}
	t.Cleanup(func() { _ = ctl.Shutdown(t.Context()) })

	if code, body := callClock(t, ctl.Addr(), http.MethodGet, "/debug/clock"); code != http.StatusOK {
		t.Fatalf("GET /debug/clock = %d %q", code, body)
	}

	code, body := callClock(t, ctl.Addr(), http.MethodPost, "/debug/clock/advance?by=31s")
	if code != http.StatusOK {
		t.Fatalf("advancing by 31s = %d %q", code, body)
	}
	if !strings.Contains(body, "offset=31s") {
		t.Errorf("after a 31s advance the control reports %q", body)
	}
	if clk.Offset() != 31*time.Second {
		t.Fatalf("the handler answered 200 and the clock is %s ahead, want 31s: the "+
			"route is wired to a clock nothing in the process reads", clk.Offset())
	}

	// Backwards. THE security property: a rewind un-expires an expired token,
	// restores an elapsed lockout, and re-enters a TOTP step whose code has
	// already been observed.
	for _, by := range []string{"-1s", "-1h", "0s"} {
		code, body := callClock(t, ctl.Addr(), http.MethodPost, "/debug/clock/advance?by="+by)
		if code != http.StatusBadRequest {
			t.Errorf("advancing by %s = %d %q, want 400", by, code, body)
		}
		if clk.Offset() != 31*time.Second {
			t.Fatalf("by=%s moved the clock to %s despite being refused", by, clk.Offset())
		}
	}

	if code, _ := callClock(t, ctl.Addr(), http.MethodPost, "/debug/clock/advance?by=banana"); code != http.StatusBadRequest {
		t.Errorf("a malformed duration returned %d, want 400", code)
	}
}

// Lock 3: loopback only, enforced in code and not only by the bind address.
//
// Exercised through the handler rather than a socket, because a connection from
// this test is loopback by construction — the refusal can only be reached by
// presenting a remote address the kernel would never give us.
func TestTheClockControlRefusesANonLoopbackCaller(t *testing.T) {
	clk := clock.NewOffset(clock.System{})
	h := clockControlHandler(clk)

	for _, remote := range []string{"203.0.113.7:5555", "192.168.1.10:5555", "[2001:db8::1]:5555"} {
		req := httptest.NewRequest(http.MethodPost, "/debug/clock/advance?by=1h", nil)
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)

		if rec.Code != http.StatusForbidden {
			t.Errorf("a caller from %s got %d, want 403", remote, rec.Code)
		}
		if clk.Offset() != 0 {
			t.Fatalf("a caller from %s moved the clock to %s", remote, clk.Offset())
		}
	}

	req := httptest.NewRequest(http.MethodPost, "/debug/clock/advance?by=1h", nil)
	req.RemoteAddr = "127.0.0.1:5555"
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("a loopback caller got %d, want 200: the guard refuses everybody", rec.Code)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// productionEnv is testConfig's variable set plus everything else a non-local
// APP_ENV requires, so the only thing a test adds is the control under test.
func productionEnv(t *testing.T, env string) {
	t.Helper()
	for k, v := range map[string]string{
		"APP_ENV":               env,
		"POSTGRES_DB":           "chronos",
		"POSTGRES_USER":         "chronos",
		"POSTGRES_PASSWORD":     "x",
		"POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
		"IDENTITY_EMAIL_INDEX_KEY": "" +
			"1111111111111111111111111111111111111111111111111111111111111111",
		"IDENTITY_PASSWORD_PEPPER_KEY": "" +
			"2222222222222222222222222222222222222222222222222222222222222222",
		"IDENTITY_TOTP_SEAL_KEY": "" +
			"3333333333333333333333333333333333333333333333333333333333333333",
		"KURRENTDB_CONNECTION_STRING":  "kurrentdb://kurrent:2113?tls=true",
		"CENTRIFUGO_TOKEN_HMAC_SECRET": "s",
		"SMTP_STARTTLS":                "true",
		"OPENBAO_DEV_TOKEN":            "not-a-dev-token",
	} {
		t.Setenv(k, v)
	}
}

func callClock(t *testing.T, addr, method, path string) (int, string) {
	t.Helper()
	req, err := http.NewRequestWithContext(t.Context(), method, "http://"+addr+path, nil)
	if err != nil {
		t.Fatalf("building the request: %v", err)
	}
	res, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("%s %s: %v", method, path, err)
	}
	defer func() { _ = res.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(res.Body, 1<<16))
	if err != nil {
		t.Fatalf("reading the response: %v", err)
	}
	return res.StatusCode, string(body)
}
