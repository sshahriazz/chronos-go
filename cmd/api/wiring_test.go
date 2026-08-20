package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/obs"
	"github.com/chronos/chronos-go/internal/server/connect"
)

// Authorization must be wired, and must DENY when it cannot work.
//
// Three adapters in this codebase were once built, fully tested, and constructed
// by no binary at all — every component test passed while three notification
// channels delivered nothing. Authorization has a worse version of that failure:
// a Guard that is nil, or never consulted, does not deny. It is skipped.
//
// So the assertion is on the COMPOSITION ROOT, not on the kernel.
func TestAuthzIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.authz == nil {
		t.Fatal("no authorization guard was constructed: every handler that asks for one " +
			"gets nil, and a nil guard does not deny — it panics or is skipped")
	}
}

// With no store id configured — the state of a fresh environment — the guard
// must still exist and must refuse everything.
//
// This is the case that would otherwise ship: OpenFGA reachable, no store, and a
// checker that quietly evaluates against no tuples. Denying is correct; denying
// LOUDLY, from an explicit DenyAll, is what makes it findable.
func TestAuthzDeniesWithoutAStore(t *testing.T) {
	cfg := testConfig(t)
	cfg.OpenFGA.StoreID = ""

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.authz == nil {
		t.Fatal("no guard was constructed")
	}
	decision := d.authz.Check(context.Background(), authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "usr_1"},
		Relation:  "viewer",
		Resource:  authz.ResourceRef{Type: "folder", ID: "fld_1"},
	})
	if decision.Allowed() {
		t.Fatal("an unconfigured authorization service permitted access")
	}
}

// The probe must report OpenFGA as FAIL_CLOSED. A Degradable probe here would
// tell an operator that losing authorization is survivable, when in fact every
// request is being denied.
func TestOpenFGAProbeIsFailClosed(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	var found bool
	for _, p := range d.probes {
		if p.Name() != "openfga" {
			continue
		}
		found = true
		if got := p.Criticality().String(); got != "fail_closed" {
			t.Errorf("the openfga probe is %s; losing authorization denies every request "+
				"and must be reported as fail_closed", got)
		}
	}
	if !found {
		t.Error("no openfga probe is registered: an authorization outage would be invisible")
	}
}

// testConfig is the environment every untagged test in this package builds
// dependencies from.
//
// It carries REAL identity key material, because the composition-root tests
// below assert on a fully-constructed identity service and a config without keys
// would make every one of them assert that nothing was built. The keys are
// syntactically valid and cryptographically worthless, which is the correct
// combination for a test fixture.
func testConfig(t *testing.T) *config.Config {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",

		// 32 bytes each, hex. Distinct from one another so a wiring bug that
		// swapped two of them would not still pass every length check.
		"IDENTITY_EMAIL_INDEX_KEY": "" +
			"1111111111111111111111111111111111111111111111111111111111111111",
		"IDENTITY_PASSWORD_PEPPER_KEY": "" +
			"2222222222222222222222222222222222222222222222222222222222222222",
		"IDENTITY_TOTP_SEAL_KEY": "" +
			"3333333333333333333333333333333333333333333333333333333333333333",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

// The idempotency gate must be wired.
//
// Its absence is invisible at runtime: every request still succeeds, and a
// double-click simply executes the mutation twice — which looks exactly like a
// client sending two requests. Nothing logs, nothing fails, and the duplicate
// charge is discovered by the customer.
func TestTheIdempotencyGateIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.once == nil {
		t.Fatal("no idempotency gate was constructed: every mutating RPC is ungated, and a " +
			"double-click executes the mutation twice with nothing reporting it")
	}
	if d.idempotency == nil {
		t.Fatal("no idempotency store was constructed, so nothing can sweep expired records")
	}
}

// The retention sweep must be STARTED, not merely constructible.
//
// This is the Dedup.Forget failure in its exact original shape: the function was
// written, documented and indexed for, and called by no binary at all while its
// unit test passed. A test that calls Sweep directly reproduces that blind spot,
// so the assertion is on the list main iterates.
func TestTheIdempotencySweepIsStarted(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	var found bool
	for _, task := range backgroundTasks(d) {
		if task.name == "idempotency-retention" {
			found = true
		}
	}
	if !found {
		t.Fatal("no idempotency retention task is started: idempotency_key grows for the " +
			"lifetime of the deployment, and every stored response in it is retained data")
	}
}

// Every listed task must actually return when the context ends, or shutdown
// hangs on a goroutine nobody can name.
func TestEveryBackgroundTaskStopsWithTheContext(t *testing.T) {
	cfg := testConfig(t)
	// A short interval so the ticker is not what the test waits on.
	cfg.API.IdempotencySweepEvery = 10 * time.Millisecond
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	tasks := backgroundTasks(d)
	if len(tasks) == 0 {
		t.Fatal("no background tasks are registered, so this test asserts nothing")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan string, len(tasks))
	for _, task := range tasks {
		go func(task backgroundTask) {
			task.run(ctx, d, slog.New(slog.DiscardHandler))
			done <- task.name
		}(task)
	}
	cancel()

	for range tasks {
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			t.Fatal("a background task did not stop when the context ended: shutdown hangs")
		}
	}
}

// The gate's TTL comes from configuration, and an out-of-range one is a refusal
// to BOOT rather than a constructor error found later in wiring.
func TestAnExcessiveIdempotencyTTLStopsStartup(t *testing.T) {
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
		"API_IDEMPOTENCY_TTL":   "720h",
	} {
		t.Setenv(k, v)
	}
	if _, err := config.Load(); err == nil {
		t.Fatal("a 30-day idempotency TTL was accepted: every mutation's response, personal " +
			"data included, would be retained that long")
	}
}

// The caller-scope trust boundary, asserted at the composition root because
// that is the only place the environment variable and the resolver meet.
//
// Every value of API_TRUSTED_PROXY_HOPS produces a server that starts, serves,
// and passes every other test in this repository. The difference between "trusts
// one proxy" and "trusts whatever the caller wrote" shows up in no log line, no
// metric and no failed request — only as an abuse incident — so the boot is the
// last place it can be caught.
func TestAnOutOfRangeTrustedProxyHopCountStopsStartup(t *testing.T) {
	for name, value := range map[string]string{
		"negative":      "-1",
		"above the cap": "64",
	} {
		t.Run(name, func(t *testing.T) {
			for k, v := range map[string]string{
				"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
				"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
				"OPENFGA_PRESHARED_KEY":  "k",
				"API_TRUSTED_PROXY_HOPS": value,
			} {
				t.Setenv(k, v)
			}
			if _, err := config.Load(); err == nil {
				t.Fatalf("API_TRUSTED_PROXY_HOPS=%s was accepted; a hop count above the "+
					"number of proxies that append to X-Forwarded-For makes every "+
					"per-caller rate-limit bucket attacker-chosen", value)
			}
		})
	}
}

// The default boundary trusts nothing, end to end from the environment to the
// resolver cmd/api actually builds.
//
// buildIdentity needs a pool, a store and a vault, so the whole graph cannot be
// constructed here — but the one line that turns configuration into a trust
// boundary can be, and it is the line whose wrong answer has no symptom.
func TestTheDefaultTrustBoundaryReadsNoHeader(t *testing.T) {
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	resolver, err := clientip.NewResolver(cfg.API.TrustedProxyHops)
	if err != nil {
		t.Fatalf("building the caller-scope resolver from the default config: %v", err)
	}
	if resolver.TrustedHops() != 0 {
		t.Fatalf("the default trust boundary is %d hops, want 0", resolver.TrustedHops())
	}
	got := resolver.Scope("203.0.113.9:44321", []string{"192.0.2.111, 198.51.100.222"})
	if got != "203.0.113.9" {
		t.Fatalf("with no configuration the scope is %q; it must be the connection's "+
			"peer address 203.0.113.9, because X-Forwarded-For is written by the caller",
			got)
	}
}

// The typed-nil guards return a genuinely nil interface.
//
// This is the infra-free half of the revocation wiring, and it is the half that
// can actually go wrong silently. `tombstonesOrNil` exists because returning a
// nil *valkeyadapter.Authz directly into an authz.Tombstones interface produces
// a value that is NOT == nil — the type descriptor is set. The Guard's
// `g.tombs != nil` check would then pass, it would call through, and every
// request would panic instead of being refused.
//
// Asserted here rather than in the kernel because the trap only exists at the
// composition root, where a concrete type meets an interface field.
func TestTypedNilGuardsReturnNilInterfaces(t *testing.T) {
	if tombs := tombstonesOrNil(nil); tombs != nil {
		t.Errorf("tombstonesOrNil(nil) returned a non-nil interface (%T): the Guard would "+
			"call it and panic rather than treating revocation as unwired", tombs)
	}
	if dec := decisionsOrNil(nil); dec != nil {
		t.Errorf("decisionsOrNil(nil) returned a non-nil interface (%T)", dec)
	}
}

// The error gate must be wired into the handler options, not merely written.
//
// This is the composition-root half of the outage that produced it. The gate can
// be complete, unit-tested and correct, and if `registerServices` does not put it
// in front of every service then an unclassified failure still reaches the wire
// as `internal: internal error` with nothing in the log — which is exactly the
// state this repository was in, and exactly the shape of the three adapters that
// were fully built and constructed by no binary.
//
// So the assertion drives a real request through the handler `registerServices`
// actually mounts, over a real server, and reads the log the binary would have
// written. GetStatus is public, so the gate pipeline passes it through to the
// handler that fails.
func TestTheErrorGateIsWiredIntoEveryService(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.gates == nil {
		t.Fatal("no gate pipeline was constructed, so registerServices mounts nothing")
	}

	var captured bytes.Buffer
	log := slog.New(obs.NewTraceHandler(
		slog.NewJSONHandler(&captured, &slog.HandlerOptions{Level: slog.LevelInfo})))

	mux := http.NewServeMux()
	registerServices(mux, d, failingStatus{}, log)

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := systemv1connect.NewSystemServiceClient(srv.Client(), srv.URL)
	_, err := client.GetStatus(t.Context(), connectrpc.NewRequest(&systemv1.GetStatusRequest{}))
	if err == nil {
		t.Fatal("GetStatus succeeded; the stub was supposed to fail")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeInternal {
		t.Fatalf("code = %v, want internal", got)
	}
	if strings.Contains(err.Error(), "the status projection") {
		t.Errorf("the response carries the cause: %q", err.Error())
	}

	logged := captured.String()
	if !strings.Contains(logged, "rpc failed with a cause the caller was not told") {
		t.Fatalf("the cause of an INTERNAL reached nobody. Log was:\n%s", logged)
	}
	if !strings.Contains(logged, systemv1connect.SystemServiceGetStatusProcedure) {
		t.Errorf("the log line does not name the procedure. Log was:\n%s", logged)
	}
	if !strings.Contains(logged, "the status projection") {
		t.Errorf("the log line does not carry the cause. Log was:\n%s", logged)
	}
}

// failingStatus is a SystemService whose one RPC fails the way the identity slice
// did: an error that never passed through errs.
type failingStatus struct{}

func (failingStatus) GetStatus(
	context.Context, *connectrpc.Request[systemv1.GetStatusRequest],
) (*connectrpc.Response[systemv1.GetStatusResponse], error) {
	return nil, connect.Error(fmt.Errorf("reading the status projection: %w",
		errors.New("dial tcp 127.0.0.1:5432: connection refused")))
}
