package main

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"runtime"
	"slices"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/server/health"
)

// Everything in this file asserts on the COMPOSITION ROOT and nothing else.
//
// The whole identity slice — twenty-odd packages, every one with its own tests,
// every one green — was reachable from no binary at all before S1-27. That is
// the sixth time this repository has shipped that exact shape, so the assertions
// here are deliberately about wiring rather than behaviour: each one fails if a
// specific line in deps.go, identity.go, gates.go or main.go is deleted, and
// none of them can pass by exercising a package directly.
//
// They are also INFRA-FREE. Nothing below connects to anything: pgxpool.New does
// not dial, kurrentdb.Dial parses a connection string, and openbao.Dial builds a
// client. Verified by pointing every dependency at 127.0.0.1:1 — see
// TestTheCompositionRootNeedsNoInfrastructure.

// The identity service must be REGISTERED on the mux, not merely constructed.
//
// Constructed-and-unregistered is the failure this repository keeps shipping and
// it is invisible from every other vantage point: the handler exists, its tests
// pass, its OpenAPI is published, and every RPC answers `unimplemented`. So the
// assertion is on the routing table the server actually serves from.
func TestIdentityServiceIsRegisteredOnTheMux(t *testing.T) {
	mux, d, served := serveTestMux(t)

	if d.identity == nil {
		t.Fatal("no identity service was constructed: registration, login, sessions and " +
			"second factors are all unreachable")
	}
	if !slices.Contains(served, identityv1connect.IdentityServiceName) {
		t.Fatalf("registerServices returned %v; IdentityService is not among them", served)
	}

	// The list is one half. The mux is the other: a name in a slice that nothing
	// mounted routes to a 404, and this is the check that would catch it.
	procedure := identityv1connect.IdentityServiceRegisterProcedure
	req := httptest.NewRequestWithContext(t.Context(), http.MethodPost, procedure, nil)
	if _, pattern := mux.Handler(req); pattern == "" {
		t.Fatalf("the mux does not route %s: IdentityService was named but never mounted",
			procedure)
	}
}

// SystemService must survive the change. Adding a second service to a
// registration path that previously handled one is exactly the edit that drops
// the first.
func TestSystemServiceIsStillRegistered(t *testing.T) {
	_, _, served := serveTestMux(t)
	if !slices.Contains(served, systemv1connect.SystemServiceName) {
		t.Fatalf("registerServices returned %v; SystemService is not among them — /readyz "+
			"still answers, so the loss is invisible to a health check", served)
	}
}

// Every service the mux serves must have a declared policy loaded for it.
//
// The two lists live apart by necessity — one is protoreflect names for
// policy.Load, the other is Connect handlers on a mux — and drift between them
// is silent in the dangerous direction: a service registered but not gated is
// served with no declared enforcement at all.
func TestEveryRegisteredServiceIsGated(t *testing.T) {
	_, _, served := serveTestMux(t)

	gated := make([]string, 0, len(gatedServices()))
	for _, name := range gatedServices() {
		gated = append(gated, string(name))
	}
	for _, name := range served {
		if !slices.Contains(gated, name) {
			t.Errorf("%s is registered on the mux and is not in gatedServices(): its methods "+
				"are served with no declared policy", name)
		}
	}
}

// The gates must exist AND carry an authenticator.
//
// Gates with a nil Authn is not a broken build: it constructs, it serves, and it
// refuses every non-public method with ErrGateUnavailable. That is safe and
// completely useless, and the only place it is visible is here.
func TestGatesAreConstructedWithAnAuthenticator(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.gates == nil {
		t.Fatal("no enforcement pipeline was built: no Connect service can be registered " +
			"at all")
	}
	if d.authn == nil {
		t.Fatal("no session authenticator was constructed: every non-public RPC is refused, " +
			"so a correctly-registered identity service still cannot log anybody in")
	}
	if d.policies == nil {
		t.Fatal("no policy set was loaded")
	}

	// A gate that is DECLARED by some method and implemented by none is refused
	// at request time. authn is the one this slice cannot do without.
	for _, missing := range d.gates.Missing() {
		if string(missing) == "authn" {
			t.Fatal("the authn gate is declared and unimplemented: every authenticated " +
				"identity RPC is refused")
		}
	}
}

// The idempotency gate must reach the interceptor, not just the dependencies
// struct. `once` being non-nil says the kernel was built; only this says the
// pipeline holds it.
func TestTheIdempotencyGateReachesThePipeline(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.idempotencyGate == nil {
		t.Fatal("gate 5 was never built from cqrs.Once: every mutating RPC is ungated, " +
			"and a double-click executes the mutation twice")
	}
	for _, missing := range d.gates.Missing() {
		if string(missing) == "idempotency" {
			t.Fatal("the idempotency gate is declared and unimplemented")
		}
	}
}

// The authentication observer must be wired.
//
// app.NewAuthentication defaults it to a nop, so its absence changes nothing
// anybody can see: logins still work, throttled attempts are still refused, and
// the two outcomes that leave NO EVENT behind — a throttled attempt and a
// ceiling that could not be evaluated — are counted nowhere. A degraded attempt
// ceiling then looks exactly like one that is never reached.
func TestTheAuthObserverIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.authObserver == nil {
		t.Fatal("no AuthObserver was passed to app.NewAuthentication: throttled attempts " +
			"and a degraded attempt-ceiling are counted nowhere, and neither leaves an event")
	}
	// It must be the METRICS observer, not some other implementation that also
	// satisfies the interface and exports nothing.
	if _, ok := d.authObserver.(interface{ CeilingUnavailable() }); !ok {
		t.Fatalf("the AuthObserver is %T, which does not report a degraded ceiling",
			d.authObserver)
	}
}

// The TOTP enroller must be wired.
//
// It is a func type, so a missing one is a nil the second-factor constructor
// refuses — but only if the composition root ever tried. This asserts the lambda
// exists AND that it reaches the real adapter, by minting an enrolment and
// checking the two fields that must never be empty.
func TestTheTotpEnrollerIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.totpEnroller == nil {
		t.Fatal("no TotpEnroller was built: nobody can enrol a second factor, and a second " +
			"factor is mandatory before an account activates")
	}
	enrollment, err := d.totpEnroller("someone@example.test")
	if err != nil {
		t.Fatalf("the enroller is wired to something that cannot mint a secret: %v", err)
	}
	if enrollment.Secret == "" {
		t.Error("the enroller returned no secret: the lambda drops the adapter's Secret field")
	}
	if enrollment.URI == "" {
		t.Error("the enroller returned no provisioning URI: nothing can be scanned")
	}
}

// The attempt ceiling must carry MORE THAN ONE rule.
//
// One window cannot express both shapes of abuse, and the ratelimit package says
// so in its own documentation: a per-minute rule permits thousands of attempts a
// day, a per-day rule permits the whole budget in one second. A limiter built
// with a single rule constructs cleanly, refuses bursts, and lets a slow grind
// through forever with nothing reporting it.
func TestTheAttemptCeilingHasMoreThanOneWindow(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.limiter == nil {
		t.Fatal("no attempt ceiling was built: password guessing is unlimited")
	}
	rules := d.limiter.Rules()
	if len(rules) < 2 {
		t.Fatalf("the limiter carries %d rule(s): %v. One window cannot bound both a burst "+
			"and a grind", len(rules), rules)
	}

	// The windows must differ by orders of magnitude, or the second rule is
	// decoration: two rules a minute apart both trip on the same burst and
	// neither bounds a slow grind.
	shortest, longest := rules[0].Window, rules[len(rules)-1].Window
	if longest < 60*shortest {
		t.Errorf("the widest window (%s) is less than 60x the narrowest (%s): the rules "+
			"bound the same shape of abuse twice and nothing bounds the other",
			longest, shortest)
	}
}

// The hasher's concurrency bound must not exceed the CPU limit this process
// actually has.
//
// argon2id.New defaults the bound to runtime.GOMAXPROCS(0), which is the HOST's
// core count under a CFS quota — a 2-CPU pod on a 64-core node would permit 64
// simultaneous hashes at 32 MiB each. That is 2 GiB of resident memory reachable
// by unauthenticated requests, to do the work of two.
func TestTheHasherBoundDoesNotExceedTheCPULimit(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.hasher == nil {
		t.Fatal("no password hasher was constructed")
	}
	if d.cpuLimit < 1 {
		t.Fatalf("the resolved CPU limit is %d, which is not a usable bound", d.cpuLimit)
	}
	if got := d.hasher.Limit(); got != d.hashConcurrency {
		t.Errorf("the hasher's bound is %d but the composition root resolved %d: "+
			"WithConcurrencyLimit is not reaching the hasher", got, d.hashConcurrency)
	}
	if got := d.hasher.Limit(); got > d.cpuLimit {
		t.Errorf("the hasher permits %d concurrent hashes on a %d-CPU limit: that is "+
			"%d MiB of Argon2id working set to do the work of %d",
			got, d.cpuLimit, got*32, d.cpuLimit)
	}
}

// An explicit configuration value must WIN over the resolved limit, and must
// still reach the hasher.
//
// A knob the composition root reads and then ignores is worse than no knob:
// somebody tunes it from a measurement, restarts, and measures the same thing.
func TestAnExplicitHashConcurrencyIsHonoured(t *testing.T) {
	cfg := testConfig(t)
	cfg.Identity.PasswordHashConcurrency = 3

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.hasher == nil {
		t.Fatal("no password hasher was constructed")
	}
	if got := d.hasher.Limit(); got != 3 {
		t.Errorf("IDENTITY_PASSWORD_HASH_CONCURRENCY=3 produced a bound of %d: the setting "+
			"is read and discarded", got)
	}
}

// resolveCPULimit must never return something unusable, and must never exceed
// what the runtime will actually run in parallel.
//
// A quota of 8 on a runtime pinned to 2 is still 2 real parallel hashes; sizing
// from the quota alone would buy memory and no throughput.
func TestTheResolvedCPULimitIsBounded(t *testing.T) {
	got := resolveCPULimit(slog.New(slog.DiscardHandler))
	if got < 1 {
		t.Fatalf("resolveCPULimit returned %d; a bound below 1 blocks every login forever", got)
	}
	if procs := runtime.GOMAXPROCS(0); got > procs {
		t.Errorf("resolveCPULimit returned %d above GOMAXPROCS %d: the extra slots hold "+
			"32 MiB each and run no faster", got, procs)
	}
}

// cpusFrom rounds UP, and refuses anything it cannot read.
//
// Table-driven because the arithmetic is the part with a wrong answer that looks
// plausible: rounding a 1.5-CPU quota DOWN halves throughput on the strength of
// an accounting detail.
func TestCPUsFromRoundsUpAndRefusesNonsense(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name          string
		quota, period int64
		parsed        bool
		want          int
		wantOK        bool
	}{
		{"one cpu", 100000, 100000, true, 1, true},
		{"half a cpu rounds up to one", 50000, 100000, true, 1, true},
		{"one and a half rounds up to two", 150000, 100000, true, 2, true},
		{"four cpus", 400000, 100000, true, 4, true},
		{"unlimited quota", -1, 100000, true, 0, false},
		{"zero period", 100000, 0, true, 0, false},
		{"unparsed", 100000, 100000, false, 0, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, ok := cpusFrom(tc.quota, tc.period, tc.parsed)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if ok && got != tc.want {
				t.Errorf("cpus = %d, want %d", got, tc.want)
			}
		})
	}
}

// The typed-nil guards this file's wiring depends on must return genuinely nil
// interfaces.
//
// Same trap as tombstonesOrNil, one layer along: a nil *valkeyadapter.Counter
// inside a non-nil ratelimit.Counter passes ratelimit.New's nil check and panics
// on the first login attempt, and a nil *piivault.Vault inside a non-nil
// app.SubjectVault passes NewRegistration's check and panics with somebody's
// address already in hand.
func TestIdentityTypedNilGuardsReturnNilInterfaces(t *testing.T) {
	t.Parallel()
	if c := counterOrNil(nil); c != nil {
		t.Errorf("counterOrNil(nil) returned a non-nil interface (%T): the limiter would "+
			"call it and panic rather than being refused at construction", c)
	}
	if v := vaultOrNil(nil); v != nil {
		t.Errorf("vaultOrNil(nil) returned a non-nil interface (%T)", v)
	}
	// The bearer composer replaced authenticatorOrNil, and it carries the same
	// obligation: a nil *SessionAuthenticator placed directly into
	// interceptor.Authenticator is NOT == nil, so the authn gate would call
	// through it and PANIC rather than refusing the request. Returning an untyped
	// nil is what makes Gates.Missing report the gate instead.
	if a := composeAuthenticator(&dependencies{}, nil, slog.New(slog.DiscardHandler)); a != nil {
		t.Errorf("composeAuthenticator with no session resolver returned a non-nil "+
			"interface (%T): the authn gate would panic instead of refusing the request", a)
	}
}

// Without key material, identity must NOT be registered — and the server must
// still start.
//
// This is the state of a fresh local environment, and both halves matter. A
// server that refused to boot would make `make up` unusable before keys are
// provisioned; a server that registered a handler over nil collaborators would
// answer the first registration with a panic.
func TestIdentityIsUnregisteredWithoutKeys(t *testing.T) {
	cfg := testConfig(t)
	cfg.Identity.EmailIndexKey = ""
	cfg.Identity.PasswordPepperKey = ""
	cfg.Identity.TotpSealKey = ""

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.identity != nil {
		t.Fatal("an identity service was built with no key material: it would hash under a " +
			"zero pepper and index under a zero key")
	}

	mux := http.NewServeMux()
	served := registerServices(mux, d, testConfig(t), testSystemService(t), slog.New(slog.DiscardHandler))
	if slices.Contains(served, identityv1connect.IdentityServiceName) {
		t.Fatal("IdentityService was registered without key material")
	}
	// SystemService must still be served: an unconfigured identity module is not
	// a reason to take health reporting off the air.
	if !slices.Contains(served, systemv1connect.SystemServiceName) {
		t.Fatal("SystemService was dropped along with identity")
	}
}

// The gates must actually be IN the handler option list, and they must be
// outermost.
//
// Asserted by pushing a request through a real handler rather than by counting
// options: a length check passes for a handler carrying the wrong interceptor.
// A request with a malformed email AND no credentials must come back as an
// authentication failure, not as an invalid argument — the gates run first, so a
// caller below the disclosure boundary never learns which field they got wrong
// (ADR-036).
func TestTheGatesRunBeforeValidation(t *testing.T) {
	mux, d, _ := serveTestMux(t)
	if d.gates == nil {
		t.Fatal("no enforcement pipeline was built")
	}

	// The mux registerServices actually built, NOT a handler assembled here.
	// Building one locally from handlerOptions(d.gates) proves the option list is
	// right and proves nothing about the server: registerServices could call
	// handlerOptions() with no arguments and every identity RPC would be served
	// completely ungated while this test stayed green.
	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := identityv1connect.NewIdentityServiceClient(srv.Client(), srv.URL)

	// ListSessions is not public: it acts on the caller's own account, so it
	// needs a session. With no bearer token the authn gate must refuse it before
	// anything else looks at the message.
	_, err := client.ListSessions(t.Context(),
		connectrpc.NewRequest(&identityv1.ListSessionsRequest{PageSize: -1}))
	if err == nil {
		t.Fatal("an unauthenticated ListSessions succeeded: the gates are not in " +
			"handlerOptions(), so every non-public identity RPC is unguarded")
	}
	if code := connectrpc.CodeOf(err); code == connectrpc.CodeInvalidArgument {
		t.Fatalf("an unauthenticated caller was told their request was malformed (%v): "+
			"validation is running ahead of the gates, which discloses request detail "+
			"below the ADR-036 boundary", err)
	}
}

// The stand-in counter must FAIL, not report zero.
//
// The two are read completely differently by the limiter: an error produces a
// Degraded decision the caller must surface and the app layer counts through
// AuthObserver.CeilingUnavailable, while a count of zero is an ordinary allow
// that nobody reports. A counter returning (0, nil) is an attempt ceiling that
// is present, constructed, green in every test, and silently permitting
// everything — which is why the substitution is asserted rather than trusted.
func TestTheUnavailableCounterFailsRatherThanPermitting(t *testing.T) {
	t.Parallel()

	count, err := unavailableCounter{}.Incr(t.Context(), "authn:burst:someone", time.Minute)
	if err == nil {
		t.Fatalf("the stand-in counter reported success (count=%d): every attempt would be "+
			"an ordinary allow, the decision would not be Degraded, and nothing would "+
			"count chronos_auth_ceiling_unavailable_total", count)
	}
}

// With Valkey unreachable the ceiling must be DEGRADED, not absent.
//
// A limiter is still built, so the login path still has a ceiling object that
// reports its own failure. Refusing to build identity instead would make Valkey
// reachability at boot a precondition for serving authentication at all — and
// valkey.NewClient dials, so a blip during a rolling restart would take login
// off until somebody restarted again.
func TestTheCeilingIsDegradedRatherThanAbsentWithoutValkey(t *testing.T) {
	t.Setenv("VALKEY_ADDR", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.counter != nil {
		t.Skip("valkey answered on 127.0.0.1:1, so this test asserts nothing")
	}
	if d.identity == nil {
		t.Fatal("identity was refused because valkey is down: a cache outage must not be " +
			"an authentication outage")
	}
	if d.limiter == nil {
		t.Fatal("no limiter was built at all: attempts would not even be counted as degraded")
	}

	decision, err := d.limiter.Allow(t.Context(), "someone")
	if err == nil {
		t.Fatal("the limiter reported no error with no counter behind it")
	}
	if !decision.Degraded {
		t.Error("the decision is not marked Degraded: a ceiling that stopped counting is " +
			"indistinguishable from one that is never reached")
	}
}

// The whole composition root must build with every dependency pointed at a
// closed port.
//
// This is the check that keeps the rest of this file honest. An untagged test
// that quietly depends on a running stack passes on the developer's machine and
// fails in CI — it has already happened once here, in `make check`, on a machine
// where the stack was down. 127.0.0.1:1 is closed on every platform, so anything
// that dials would fail loudly rather than succeeding by accident.
//
// It asserts on the full identity graph rather than on "it did not panic",
// because the failure it guards against is a future edit that moves a connection
// attempt into construction — at which point identity would come back nil here
// while every other test in this file still passed for the wrong reason.
func TestTheCompositionRootNeedsNoInfrastructure(t *testing.T) {
	for k, v := range map[string]string{
		"POSTGRES_HOST": "127.0.0.1", "POSTGRES_PORT": "1",
		"KURRENTDB_CONNECTION_STRING": "kurrentdb://127.0.0.1:1?tls=false",
		"VALKEY_ADDR":                 "127.0.0.1:1",
		"OPENBAO_ADDR":                "http://127.0.0.1:1",
		"OPENFGA_ENDPOINT":            "127.0.0.1:1",
	} {
		t.Setenv(k, v)
	}
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	defer closeAll()

	if d.identity == nil {
		t.Fatal("identity could not be constructed against closed ports: construction is " +
			"reaching the network, which makes every wiring test in this file a test of " +
			"whether the stack happened to be running (ADR-010)")
	}
	if d.gates == nil {
		t.Fatal("the enforcement pipeline could not be built against closed ports")
	}

	mux := http.NewServeMux()
	served := registerServices(mux, d, testConfig(t), testSystemService(t), slog.New(slog.DiscardHandler))
	if !slices.Contains(served, identityv1connect.IdentityServiceName) {
		t.Fatalf("registerServices returned %v against closed ports", served)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// serveTestMux drives the exact production registration path and hands back
// everything it produced.
func serveTestMux(t *testing.T) (*http.ServeMux, *dependencies, []string) {
	t.Helper()
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler))
	t.Cleanup(closeAll)

	mux := http.NewServeMux()
	served := registerServices(mux, d, testConfig(t), testSystemService(t), slog.New(slog.DiscardHandler))
	return mux, d, served
}

func testSystemService(t *testing.T) systemv1connect.SystemServiceHandler {
	t.Helper()
	clk := clock.System{}
	return health.NewService(health.New(clk, 0), "test", "UTC", clk.Now())
}
