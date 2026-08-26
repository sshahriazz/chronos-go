package main

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	connectvalidate "connectrpc.com/validate"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/operator/v1/operatorv1connect"
	"github.com/chronos/chronos-go/internal/operator/api"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/policy"
	"github.com/chronos/chronos-go/internal/platform/clientip"
)

// This file tests the COMPOSITION ROOT, which is the thing this repository has
// been burned by twice: three notification adapters were built, fully tested,
// and constructed by no binary, and every component test passed while three
// channels delivered nothing.
//
// So these do not test the guard or the validator. They test that THIS BINARY
// applies them, by building a handler the same way run() does and pushing a
// request through it.

// stubSessions refuses everything, which is all these tests need: they exercise
// the paths BEFORE a session is resolved, or the refusal itself.
type stubSessions struct{ app.Sessions }

func (stubSessions) Resolve(context.Context, []byte, time.Time) (app.SessionRecord, error) {
	return app.SessionRecord{}, app.ErrSessionRefused
}

func (stubSessions) MarkElevationUsed(context.Context, []byte, time.Time) error { return nil }

// recordingAlerter is how TestTheAlerterIsWired asserts the alert FIRED rather
// than that a counter exists somewhere.
//
// "The adapter was built, fully tested, and constructed by no binary" is this
// repository's named failure — it happened to three notification channels at
// once — and an alerting adapter nobody wired has exactly that shape.
type recordingAlerter struct{ calls int }

func (r *recordingAlerter) Alert(context.Context, app.Actor, string, string, time.Time) {
	r.calls++
}

type fixedClock struct{}

func (fixedClock) Now() time.Time { return time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC) }

// handler builds the operator handler exactly as run() does.
//
// It takes the same two interceptors in the same order, so a change to that
// order in main.go without a change here makes these tests measure something
// the binary does not do — which is why the order is asserted below rather than
// only assumed.
func handler(t *testing.T, allowed []netip.Prefix) http.Handler {
	t.Helper()

	catalogue, err := policy.LoadByName("chronos.operator.v1.OperatorService")
	if err != nil {
		t.Fatalf("loading the policy: %v", err)
	}

	resolver, err := clientip.NewResolver(0)
	if err != nil {
		t.Fatalf("building the resolver: %v", err)
	}

	guard, err := api.NewGuard(api.GuardConfig{
		Catalogue: catalogue,
		Sessions:  stubSessions{},
		Clock:     fixedClock{},
		Resolver:  resolver,
		Allowed:   allowed,
	})
	if err != nil {
		t.Fatalf("building the guard: %v", err)
	}

	svc, err := api.NewService(stubSignIn(t), stubCustomers(t), stubElevation(t))
	if err != nil {
		t.Fatalf("building the service: %v", err)
	}

	mux := http.NewServeMux()
	path, h := operatorv1connect.NewOperatorServiceHandler(svc,
		connect.WithInterceptors(guard, connectvalidate.NewInterceptor()))
	mux.Handle(path, h)
	return mux
}

// TestValidationIsWired is the assertion that every bound in operator.proto is
// enforced rather than documented.
//
// Without the validate interceptor, `reason`'s min_len of 8 would document a
// rule while accepting "x" — and a justification requirement that can be
// satisfied by one character is a requirement that will be. The page size's
// ceiling would likewise document a limit while serving a bulk export of the
// customer base, which operator.md §2 lists as explicitly out of scope.
//
// It pushes through an UNAUTHENTICATED method, because that is the only one
// reachable without a session — and it is enough: the interceptor is applied to
// the whole service or to none of it.
func TestValidationIsWired(t *testing.T) {
	srv := httptest.NewServer(handler(t, nil))
	defer srv.Close()

	client := operatorv1connect.NewOperatorServiceClient(srv.Client(), srv.URL)

	// `code` declares min_len: 1. An empty one must be refused by the schema.
	_, err := client.CompleteSignIn(t.Context(), connect.NewRequest(&operatorv1.CompleteSignInRequest{
		Code:  "",
		State: "some-state",
	}))
	if err == nil {
		t.Fatal("an empty authorization code was accepted; protovalidate is not wired, " +
			"so every bound in operator.proto is a comment")
	}
	if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
		t.Fatalf("want invalid_argument from the schema, got %v: %v", got, err)
	}
}

// TestTheGuardRunsBeforeValidation asserts the ORDER, not just the presence.
//
// Connect applies the first interceptor outermost, so the guard must be first.
// Validating ahead of authenticating would answer an unauthenticated caller
// with a field-level description of a request they were never entitled to make
// — and on this plane that description names the shape of the cross-tenant
// surface.
//
// The test sends a request that is BOTH unauthenticated and invalid. Whichever
// interceptor runs first decides the answer, so the code that comes back names
// the order.
func TestTheGuardRunsBeforeValidation(t *testing.T) {
	srv := httptest.NewServer(handler(t, nil))
	defer srv.Close()

	client := operatorv1connect.NewOperatorServiceClient(srv.Client(), srv.URL)

	// No bearer, AND a reason far below the declared min_len of 8.
	_, err := client.RevealPersonalData(t.Context(), connect.NewRequest(&operatorv1.RevealPersonalDataRequest{
		SubjectId: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		OrgId:     "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Fields:    []string{"email"},
		Reason:    "x",
	}))
	if err == nil {
		t.Fatal("an unauthenticated, invalid request was served")
	}
	if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
		t.Fatalf("want unauthenticated — the guard runs first — got %v: %v\n\n"+
			"An invalid_argument here means protovalidate is outermost, so an "+
			"unauthenticated caller learns the request schema before being refused.",
			got, err)
	}
}

// TestTheNetworkRestrictionIsWired asserts the guard's IP check reaches the
// handler chain.
//
// httptest connects over loopback, so a permitted set that EXCLUDES loopback
// must refuse — and the same set with loopback in it must not. Asserting both
// directions is what stops this passing because the restriction rejects
// everything.
func TestTheNetworkRestrictionIsWired(t *testing.T) {
	elsewhere := netip.MustParsePrefix("10.0.0.0/8")
	loopback4 := netip.MustParsePrefix("127.0.0.0/8")
	loopback6 := netip.MustParsePrefix("::1/128")

	t.Run("a request from outside the permitted networks is refused", func(t *testing.T) {
		srv := httptest.NewServer(handler(t, []netip.Prefix{elsewhere}))
		defer srv.Close()

		client := operatorv1connect.NewOperatorServiceClient(srv.Client(), srv.URL)
		_, err := client.BeginSignIn(t.Context(), connect.NewRequest(&operatorv1.BeginSignInRequest{}))
		if err == nil {
			t.Fatal("a request from outside the permitted networks was served")
		}
		if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
			t.Fatalf("want permission_denied, got %v: %v", got, err)
		}
	})

	// # Why loopback must be admitted over BOTH families
	//
	// This is the regression test for a real bug. The guard originally resolved
	// the caller through clientip.Scope, which returns a rate-limit BUCKET KEY
	// — and for IPv6 that key is a /64 PREFIX, not an address. Parsing it
	// worked over IPv4 and failed over IPv6, so every loopback request was
	// refused with "this request's origin could not be established" while the
	// configuration was correct.
	//
	// httptest binds 127.0.0.1, so the IPv4 half is what actually runs here;
	// the IPv6 prefix is in the permitted set because a deployment's is, and
	// because the resolver must return an address either way.
	t.Run("a request from a permitted network is served", func(t *testing.T) {
		srv := httptest.NewServer(handler(t, []netip.Prefix{loopback4, loopback6}))
		defer srv.Close()

		client := operatorv1connect.NewOperatorServiceClient(srv.Client(), srv.URL)
		_, err := client.BeginSignIn(t.Context(), connect.NewRequest(&operatorv1.BeginSignInRequest{}))

		// The call reaches the handler and fails there, because this test's
		// SignIn use case has no identity provider. What matters is the CODE:
		// anything other than permission_denied means the network check let it
		// through.
		if err != nil && connect.CodeOf(err) == connect.CodePermissionDenied {
			t.Fatalf("a request from a permitted network was refused by the network check: %v", err)
		}
	})
}

// --------------------------------------------------------------------------
// Stubs
//
// Real use cases built from stub ports, NOT zero-valued structs. A
// `&app.SignIn{}` compiles and panics on the first nil dependency, which would
// make these tests measure whether connect recovers a panic rather than whether
// the interceptors are wired.
// --------------------------------------------------------------------------

type stubIdP struct{}

func (stubIdP) Begin() (app.IdPCeremony, error) {
	return app.IdPCeremony{AuthorizationURL: "https://idp.example/authorize"}, nil
}

func (stubIdP) Finish(context.Context, app.IdPCeremony, app.IdPCallback) (app.IdPIdentity, error) {
	return app.IdPIdentity{}, app.ErrCeremonyRefused
}

type stubAuthenticator struct{ app.Authenticator }

type stubAccounts struct{}

func (stubAccounts) ByBinding(context.Context, string, string) (app.OperatorRecord, error) {
	return app.OperatorRecord{}, app.ErrNotAnOperator
}

func (stubAccounts) ByID(context.Context, string) (app.OperatorRecord, error) {
	return app.OperatorRecord{}, app.ErrNotAnOperator
}

type stubCredentials struct{ app.Credentials }

type stubCeremonies struct{}

func (stubCeremonies) Store(context.Context, string, app.CeremonyKind, string, []byte, time.Time) error {
	return nil
}

func (stubCeremonies) Consume(context.Context, string, app.CeremonyKind, time.Time) (string, []byte, error) {
	return "", nil, app.ErrCeremonyRefused
}

type stubEvents struct{}

func (stubEvents) AppendAudit(context.Context, string, any) error    { return nil }
func (stubEvents) AppendOperator(context.Context, string, any) error { return nil }

type stubDirectory struct{}

func (stubDirectory) List(context.Context, string, string, string, int32) (app.CustomerPage, error) {
	return app.CustomerPage{}, nil
}

func (stubDirectory) Get(context.Context, string) (app.Customer, error) {
	return app.Customer{}, app.ErrNoSuchCustomer
}

type stubVault struct{}

func (stubVault) Resolve(context.Context, string, []string) (map[string]string, error) {
	return map[string]string{}, nil
}

func stubSignIn(t *testing.T) *app.SignIn {
	t.Helper()
	s, err := app.NewSignIn(app.SignInDeps{
		IdP:           stubIdP{},
		Authenticator: stubAuthenticator{},
		Accounts:      stubAccounts{},
		Credentials:   stubCredentials{},
		Sessions:      stubSessions{},
		Ceremonies:    stubCeremonies{},
		Events:        stubEvents{},
		Auditor:       app.NewAuditor(stubEvents{}, fixedClock{}),
		Clock:         fixedClock{},
	})
	if err != nil {
		t.Fatalf("building the sign-in use case: %v", err)
	}
	return s
}

func stubCustomers(t *testing.T) *app.Customers {
	t.Helper()
	c, err := app.NewCustomers(stubDirectory{}, stubVault{}, app.NewAuditor(stubEvents{}, fixedClock{}), nil)
	if err != nil {
		t.Fatalf("building the customers use case: %v", err)
	}
	return c
}

func stubElevation(t *testing.T) *app.Elevation {
	t.Helper()
	e, err := app.NewElevation(stubSessions{}, app.NewAuditor(stubEvents{}, fixedClock{}),
		&recordingAlerter{}, fixedClock{}, nil)
	if err != nil {
		t.Fatalf("building the elevation use case: %v", err)
	}
	return e
}

// TestElevationRefusesToBuildWithoutAnAlerter is the composition-root assertion
// for operator.md §5's third control.
//
// The justification and the time box are enforced by the domain and by the
// database, so they cannot be omitted. The ALERT is the one control that lives
// outside both — and the way it gets lost is a constructor that treats a nil
// alerter as "alerting is optional here". It does not.
func TestElevationRefusesToBuildWithoutAnAlerter(t *testing.T) {
	_, err := app.NewElevation(stubSessions{}, app.NewAuditor(stubEvents{}, fixedClock{}),
		nil, fixedClock{}, nil)
	if err == nil {
		t.Fatal("a break-glass use case was built with no alerter, so it would grant " +
			"privileges silently — the dangerous half of the feature without the control " +
			"that makes it safe")
	}
	if !strings.Contains(err.Error(), "alerter") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
