package interceptor_test

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protodesc"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/descriptorpb"
)

// A real method descriptor, so Spec.Schema carries what Connect really carries.
func statusMethod(t *testing.T) protoreflect.MethodDescriptor {
	t.Helper()
	svc := systemv1.File_chronos_system_v1_system_proto.Services().Get(0)
	return svc.Methods().Get(0)
}

// mutatingService registers a synthetic WRITE method, because the only real RPC
// today is a public read — and a pipeline tested solely against a read never
// executes a single gate.
func mutatingService(t *testing.T, pkg string) (protoreflect.FullName, string) {
	t.Helper()
	opts := &descriptorpb.MethodOptions{}
	proto.SetExtension(opts, optionsv1.E_Authz, &optionsv1.Authz{
		Relation: "admin", ResourceType: "organization",
	})
	proto.SetExtension(opts, optionsv1.E_Operation,
		optionsv1.OperationClass_OPERATION_CLASS_WRITE)

	fd := &descriptorpb.FileDescriptorProto{
		Name:       new(pkg + "/svc.proto"),
		Package:    new(pkg),
		Syntax:     new("proto3"),
		Dependency: []string{"chronos/system/v1/system.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("SyntheticService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       new("Mutate"),
				InputType:  new(".chronos.system.v1.GetStatusRequest"),
				OutputType: new(".chronos.system.v1.GetStatusResponse"),
				Options:    opts,
			}},
		}},
	}
	f, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(f); err != nil {
		t.Fatalf("register: %v", err)
	}
	return protoreflect.FullName(pkg + ".SyntheticService"),
		"/" + pkg + ".SyntheticService/Mutate"
}

// publicMutatingService registers a synthetic method that is PUBLIC and WRITES.
//
// The real ones — Register, VerifyEmail, ResetPassword, Authenticate,
// CreateSession — live in the identity module, which this package does not
// import. Without this fixture the public branch of the pipeline is only ever
// exercised by `GetStatus`, a public READ, so the rule that a public MUTATION
// must carry an Idempotency-Key would have no test at all: deleting it would
// leave every test here green.
func publicMutatingService(t *testing.T, pkg string) (protoreflect.FullName, string) {
	t.Helper()
	opts := &descriptorpb.MethodOptions{}
	proto.SetExtension(opts, optionsv1.E_Public, true)
	proto.SetExtension(opts, optionsv1.E_Operation,
		optionsv1.OperationClass_OPERATION_CLASS_WRITE)

	fd := &descriptorpb.FileDescriptorProto{
		Name:       new(pkg + "/svc.proto"),
		Package:    new(pkg),
		Syntax:     new("proto3"),
		Dependency: []string{"chronos/system/v1/system.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("SyntheticPublicService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       new("Open"),
				InputType:  new(".chronos.system.v1.GetStatusRequest"),
				OutputType: new(".chronos.system.v1.GetStatusResponse"),
				Options:    opts,
			}},
		}},
	}
	f, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(f); err != nil {
		t.Fatalf("register: %v", err)
	}
	return protoreflect.FullName(pkg + ".SyntheticPublicService"),
		"/" + pkg + ".SyntheticPublicService/Open"
}

func policies(t *testing.T, names ...protoreflect.FullName) *policy.Set {
	t.Helper()
	set, err := policy.Load(names...)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	return set
}

func systemService() protoreflect.FullName {
	return systemv1.File_chronos_system_v1_system_proto.Services().Get(0).FullName()
}

// request builds an AnyRequest whose Spec matches a real method.
func request(t *testing.T, procedure string, md protoreflect.MethodDescriptor, hdr map[string]string) connect.AnyRequest {
	t.Helper()
	req := connect.NewRequest(&systemv1.GetStatusRequest{})
	for k, v := range hdr {
		req.Header().Set(k, v)
	}
	return &specRequest{AnyRequest: req, spec: connect.Spec{
		Procedure: procedure, Schema: md, StreamType: connect.StreamTypeUnary,
	}}
}

// specRequest overrides Spec, which connect.NewRequest leaves empty outside a
// real client or handler.
type specRequest struct {
	connect.AnyRequest
	spec connect.Spec
}

func (r *specRequest) Spec() connect.Spec { return r.spec }

func okHandler(calls *int) connect.UnaryFunc {
	return func(_ context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		*calls++
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}
}

// A public method passes straight through: readiness probes cannot authenticate.
func TestAPublicMethodNeedsNoGates(t *testing.T) {
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, systemService())})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, "/chronos.system.v1.SystemService/GetStatus", statusMethod(t), nil))
	if err != nil {
		t.Fatalf("a public method was refused: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times", calls)
	}
}

// A PUBLIC MUTATION requires an Idempotency-Key, and gate 5 is never reached to
// require it.
//
// This is the one requirement on a public method, and it is enforced in the
// public branch because the pipeline returns from there: authentication, and
// therefore idempotency, never run. The key is not claimed in any store — there
// is no principal to scope it to — it is required and used as the command's
// causation id, which is what the published document promises.
//
// Without this test the branch is dead code that no test distinguishes from its
// absence: every other public case here is `GetStatus`, a READ.
func TestAPublicMutationRequiresAnIdempotencyKey(t *testing.T) {
	svc, procedure := publicMutatingService(t, "chronos.publicmutation.v1")
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, svc)})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	tests := []struct {
		name    string
		header  map[string]string
		wantRun bool
	}{
		{name: "no key at all", header: nil},
		{name: "an empty key", header: map[string]string{interceptor.IdempotencyHeader: ""}},
		{
			name: "a key past the maximum",
			header: map[string]string{
				interceptor.IdempotencyHeader: strings.Repeat("A", cqrs.MaxKeyLen+1),
			},
		},
		{
			name: "a key carrying the reserved separator",
			header: map[string]string{
				interceptor.IdempotencyHeader: "01ARZ3NDEKTSV4RRFFQ69G5FAV|other",
			},
		},
		{
			name:    "a well-formed key",
			header:  map[string]string{interceptor.IdempotencyHeader: "01ARZ3NDEKTSV4RRFFQ69G5FAV"},
			wantRun: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			calls := 0
			_, err := g.WrapUnary(okHandler(&calls))(context.Background(),
				request(t, procedure, statusMethod(t), tt.header))

			if tt.wantRun {
				if err != nil {
					t.Fatalf("a public mutation with a valid key was refused: %v", err)
				}
				if calls != 1 {
					t.Fatalf("the handler ran %d times", calls)
				}
				return
			}
			if err == nil {
				t.Fatal("a public mutation was served without a usable Idempotency-Key")
			}
			if calls != 0 {
				t.Fatal("the handler ran before the key was checked")
			}
			if got := connect.CodeOf(err); got != connect.CodeInvalidArgument {
				t.Errorf("code = %v, want InvalidArgument — a missing key is a client bug", got)
			}
		})
	}
}

// The key a public mutation carries becomes the causation id of every event the
// command writes.
//
// That is the half of the requirement a "was it refused?" test cannot see. These
// commands are ROOTS — nothing above them in the log — so if the key does not
// reach the context, their events are appended with an empty causation and, when
// tracing is off, an empty correlation too. A log is append-only: an id not
// written at append time can never be added.
func TestAPublicMutationCarriesItsKeyAsCausation(t *testing.T) {
	svc, procedure := publicMutatingService(t, "chronos.publicmutationtrace.v1")
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, svc)})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	const key = "01ARZ3NDEKTSV4RRFFQ69G5FAV"
	var seen eventsourcing.Trace
	handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		seen = eventsourcing.TraceFrom(ctx)
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}

	if _, err := g.WrapUnary(handler)(context.Background(),
		request(t, procedure, statusMethod(t),
			map[string]string{interceptor.IdempotencyHeader: key})); err != nil {
		t.Fatalf("a public mutation with a valid key was refused: %v", err)
	}

	if seen.CausationID != key {
		t.Errorf("causation id = %q, want %q — the command has no stable identity across "+
			"retries, and its root events are appended with none", seen.CausationID, key)
	}
	if seen.CorrelationID == "" {
		t.Error("correlation id is empty; with no span it must fall back to the key")
	}
}

// A method the policy set does not know is NOT_FOUND, and the handler never runs.
//
// It reaching here means the router and the policy set disagree, and the only
// safe reading is "this method was never checked".
func TestAnUnknownMethodIsRefused(t *testing.T) {
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, systemService())})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, "/chronos.ghost.v1.GhostService/Vanish", statusMethod(t), nil))
	if err == nil {
		t.Fatal("a method with no policy was served")
	}
	if calls != 0 {
		t.Fatal("the handler ran for a method that has no declared policy")
	}
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("got %v, want NotFound: a caller who has passed no gate learns nothing",
			connect.CodeOf(err))
	}
}

// A gate a method DECLARES but that is not wired refuses the request.
//
// The whole package exists for this. Treating an unwired gate as satisfied means
// deleting an implementation silently opens every endpoint that relied on it.
func TestADeclaredButUnwiredGateRefuses(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.unwired.v1")
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, svc)})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil))
	if err == nil {
		t.Fatal("a method whose gates are unimplemented was served: the schema says it is " +
			"guarded and nothing contradicts that")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no gate applied")
	}
}

// A mutating method with no idempotency gate REFUSES rather than panics.
//
// A nil *Idempotency is not a skip: Do executes on the nil receiver, returns
// straight through for a read, and dereferences a nil field on a write. The gate
// would look correct right up until the first mutation, then crash.
func TestAMutatingMethodWithNoIdempotencyGateRefusesRatherThanPanics(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.noidem.v1")
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		// Every earlier gate wired, so the request reaches gate 5.
		Authn:         allowAuthn{},
		Org:           passOrg{},
		Authz:         allowGuard(t),
		Subscriptions: permitAll{},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	calls := 0
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("the pipeline PANICKED instead of refusing: %v", r)
		}
	}()
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000000",
		}))
	if err == nil {
		t.Fatal("a mutation ran with no idempotency gate")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no idempotency gate")
	}
}

// A typed nil in a gate field is refused at CONSTRUCTION.
//
// An interface holding a nil pointer is not == nil, so every `== nil` check
// passes, the pipeline calls through, and the request panics rather than being
// refused — a crash loop where the design promises a refusal.
func TestATypedNilGateIsRefusedAtConstruction(t *testing.T) {
	var nilAuthn *allowAuthnPtr // nil pointer, non-nil interface
	_, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, systemService()),
		Authn:    nilAuthn,
	})
	if err == nil {
		t.Fatal("a typed-nil authenticator was accepted: every request would panic instead " +
			"of being refused")
	}
	if !strings.Contains(err.Error(), "typed nil") {
		t.Errorf("the error does not explain the trap: %v", err)
	}
}

// Missing() names every unwired gate, so an operator sees it at startup instead
// of discovering it as a wall of denials.
func TestMissingNamesEveryUnwiredGate(t *testing.T) {
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, systemService())})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	missing := g.Missing()
	for _, want := range []interceptor.Gate{
		interceptor.GateAuthn, interceptor.GateOrgContext, interceptor.GateAuthz,
		interceptor.GateSubscription, interceptor.GateEntitlement, interceptor.GateIdempotency,
	} {
		var found bool
		for _, got := range missing {
			if got == want {
				found = true
			}
		}
		if !found {
			t.Errorf("%s is unwired but not reported; an operator would find out from denials", want)
		}
	}
}

// Streaming methods are refused rather than passed through.
//
// The gates are written for unary requests, and a streaming handler slipping past
// them would be ungated.
func TestStreamingMethodsAreRefused(t *testing.T) {
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, systemService())})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	called := false
	next := func(context.Context, connect.StreamingHandlerConn) error {
		called = true
		return nil
	}
	err = g.WrapStreamingHandler(next)(context.Background(),
		&fakeStream{procedure: "/chronos.test.v1.S/Stream"})
	if err == nil {
		t.Fatal("an ungated streaming method was served")
	}
	if called {
		t.Fatal("the streaming handler ran with no gate applied")
	}
}

// A gate is required to construct at all: no policy set, no pipeline.
func TestAPipelineWithoutPoliciesIsRefused(t *testing.T) {
	if _, err := interceptor.NewGates(interceptor.Deps{}); err == nil {
		t.Fatal("a pipeline was built with no policy set")
	}
}

// ---- doubles ----

type allowAuthn struct{}

func (allowAuthn) Authenticate(context.Context, interceptor.Header) (interceptor.Principal, error) {
	return interceptor.Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: "alice"},
		Context: authz.AuthContext{ActiveOrg: "org1"},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
	}, nil
}

// allowAuthnPtr exists only so a *nil pointer* can be assigned to the
// Authenticator interface in the typed-nil test.
type allowAuthnPtr struct{}

func (*allowAuthnPtr) Authenticate(context.Context, interceptor.Header) (interceptor.Principal, error) {
	return interceptor.Principal{}, errors.New("unused")
}

// passOrg resolves every request into one organization.
//
// It ATTACHES A TENANT SCOPE, which the first version of this fake did not — it
// returned the context untouched. That made it a resolver that resolves nothing,
// and it hid a real defect for as long as no method was org-scoped: gate 2 read
// the organization from `principal.Context.ActiveOrg`, which nothing ever set,
// so every org-scoped request failed. A fake that does not do the one thing the
// real implementation exists to do cannot catch that.
// resolvesNothing is a gate 1 that cannot place the caller in any organization.
//
// The real one returns NOT_FOUND in that case; this returns success with no
// scope attached, which is the harsher shape — it checks that gate 2 refuses on
// its own rather than relying on gate 1 having already failed.
type resolvesNothing struct{}

func (resolvesNothing) Resolve(ctx context.Context, _ interceptor.Principal, _ interceptor.Header) (context.Context, error) {
	return ctx, nil
}

type passOrg struct{}

func (passOrg) Resolve(ctx context.Context, p interceptor.Principal, _ interceptor.Header) (context.Context, error) {
	return db.WithTenant(ctx, db.Tenant{
		OrgID:  "org1",
		UserID: p.Subject.ID,
	}), nil
}

type permitAll struct{}

func (permitAll) Permit(context.Context, optionsv1.OperationClass) error { return nil }

type allowChecker struct{}

func (allowChecker) Check(context.Context, authz.Query) (authz.Decision, error) {
	return authz.Allow("test"), nil
}

func (allowChecker) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Allow("test")
	}
	return out, nil
}

func allowGuard(t *testing.T) *authz.Guard {
	t.Helper()
	g, err := authz.NewGuard(authz.GuardDeps{Checker: allowChecker{}})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	return g
}

type fakeStream struct{ procedure string }

func (f *fakeStream) Spec() connect.Spec {
	return connect.Spec{Procedure: f.procedure, StreamType: connect.StreamTypeBidi}
}
func (f *fakeStream) Peer() connect.Peer           { return connect.Peer{} }
func (f *fakeStream) Receive(any) error            { return nil }
func (f *fakeStream) RequestHeader() http.Header   { return http.Header{} }
func (f *fakeStream) Send(any) error               { return nil }
func (f *fakeStream) ResponseHeader() http.Header  { return http.Header{} }
func (f *fakeStream) ResponseTrailer() http.Header { return http.Header{} }
func (f *fakeStream) Conn() any                    { return nil }

// fullDeps wires every gate, so a request actually reaches each one.
//
// Without this, the only tests are "unwired refuses" — and four mutations
// survived precisely because nothing ever exercised a gate that was present.
func fullDeps(t *testing.T, svc protoreflect.FullName, checker authz.Checker) interceptor.Deps {
	t.Helper()
	guard, err := authz.NewGuard(authz.GuardDeps{Checker: checker})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newMemStore()})
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("idempotency: %v", err)
	}
	return interceptor.Deps{
		Policies:      policies(t, svc),
		Authn:         allowAuthn{},
		Org:           passOrg{},
		Authz:         guard,
		Subscriptions: permitAll{},
		Entitlements:  reserveAll{},
		Idempotency:   idem,
	}
}

// The happy path: every gate wired, every gate passed, handler runs once.
//
// This is the test that makes every "gate refuses" assertion meaningful — without
// it, a pipeline that refused EVERYTHING would pass the whole suite.
func TestAFullyWiredPipelineExecutesTheHandler(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.full.v1")
	g, err := interceptor.NewGates(fullDeps(t, svc, allowChecker{}))
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000001",
		}))
	if err != nil {
		t.Fatalf("a fully-gated request was refused: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times, want 1", calls)
	}
}

// An authz DENIAL stops the request, and the handler never runs.
//
// The gate being present is not the property — the gate's answer being obeyed is.
func TestAnAuthzDenialStopsTheRequest(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.denied.v1")
	g, err := interceptor.NewGates(fullDeps(t, svc, denyChecker{}))
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000002",
		}))
	if err == nil {
		t.Fatal("a denied request reached the handler")
	}
	if calls != 0 {
		t.Fatal("the handler ran despite an authorization denial")
	}
	// NOT_FOUND, not PERMISSION_DENIED: the parent-visibility check of ADR-036
	// is not implemented, so the rung that discloses LESS is the correct one.
	if connect.CodeOf(err) != connect.CodeNotFound {
		t.Errorf("got %v, want NotFound", connect.CodeOf(err))
	}
}

// Only the authn gate is missing. Every other gate is wired. The refusal must
// carry the identity of a SERVER FAULT, not of a client mistake.
//
// The earlier "nothing is wired" test cannot distinguish a skipped authn from a
// refusal at the next gate, which is exactly why a mutation that skipped authn
// survived it. Asserting merely that an error occurred is not enough either: if
// `enforce` returns nil for a missing authn gate the request still fails, but it
// fails downstream in the idempotency gate — which cannot find a principal in
// the context — and the client is told INVALID_ARGUMENT. In production that is a
// misconfigured server telling every caller their request was malformed: nobody
// is paged, the dashboards show a client-error spike, and the endpoint stays
// open to whatever the skipped gate was supposed to guard until someone reads
// the code. INTERNAL is what says "we are broken".
func TestAMissingAuthnGateIsReportedAsAServerFault(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.noauthn.v1")
	deps := fullDeps(t, svc, allowChecker{})
	deps.Authn = nil

	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000003",
		}))
	if err == nil {
		t.Fatal("a request ran with no authentication gate: every later gate was handed a " +
			"zero-value principal, and the authz check was made for nobody")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no authenticated caller")
	}
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("got %v, want Internal: an unwired gate is OUR misconfiguration, and the "+
			"refusal must be attributable to the missing gate rather than to whichever "+
			"later gate happened to trip over the consequences", got)
	}
}

// A mutating method with no Idempotency-Key is refused.
//
// Not defaulted: generating one server-side makes every retry look like a new
// request — the exact failure the header exists to prevent.
func TestAMutationWithoutAnIdempotencyKeyIsRefused(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.nokey.v1")
	g, err := interceptor.NewGates(fullDeps(t, svc, allowChecker{}))
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil)) // no header
	if err == nil {
		t.Fatal("a mutation ran with no idempotency key")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no idempotency key")
	}
	if connect.CodeOf(err) != connect.CodeInvalidArgument {
		t.Errorf("got %v, want InvalidArgument", connect.CodeOf(err))
	}
	// The message must name the header, and must not be the deeper layer's.
	//
	// cqrs.Scope.Validate and cqrs.Once.Do BOTH also refuse an empty key, so
	// deleting the gate's own check still refuses the request — which is why
	// asserting only on the code cannot tell the two apart. What changes is what
	// the client is told: the deeper layers answer "cqrs: invalid: no idempotency
	// key", which names an internal package and never names the header the client
	// has to set. A client cannot fix a request from that, so the retry storm the
	// gate exists to absorb turns into a support ticket.
	if !strings.Contains(err.Error(), interceptor.IdempotencyHeader) {
		t.Errorf("the refusal does not name the header the client must send: %v", err)
	}
	if strings.Contains(err.Error(), "cqrs:") {
		t.Errorf("an internal package name reached the client: %v", err)
	}
}

// The idempotency scope carries the AUTHENTICATED principal.
//
// This is what keeps one tenant's key from replaying another's response, and it
// depends entirely on the pipeline putting the principal into the context after
// authn. If it does not, the scope cannot be built and the request fails — so the
// assertion is on the recorded scope, not merely on success.
func TestTheIdempotencyScopeCarriesTheAuthenticatedPrincipal(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.scope.v1")
	store := newMemStore()
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store})
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("idempotency: %v", err)
	}
	deps := fullDeps(t, svc, allowChecker{})
	deps.Idempotency = idem

	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	if _, err := g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000004",
		})); err != nil {
		t.Fatalf("request: %v", err)
	}

	scopes := store.scopes()
	if len(scopes) != 1 {
		t.Fatalf("%d idempotency scopes were claimed, want 1", len(scopes))
	}
	if scopes[0].Principal != "user:alice" {
		t.Fatalf("the scope's principal is %q, want user:alice — without the authenticated "+
			"caller in it, one tenant's key replays another's response", scopes[0].Principal)
	}
	if scopes[0].Operation != procedure {
		t.Errorf("the scope's operation is %q, want %q", scopes[0].Operation, procedure)
	}
}

// A retry with the same key returns the stored response and does NOT re-execute.
//
// End to end through the real gate: this is the property a client relies on when
// its connection drops mid-mutation.
func TestARetryReplaysWithoutReExecuting(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.replay.v1")
	g, err := interceptor.NewGates(fullDeps(t, svc, allowChecker{}))
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	hdr := map[string]string{interceptor.IdempotencyHeader: "01J0000000000000000000005"}

	if _, err := g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), hdr)); err != nil {
		t.Fatalf("first: %v", err)
	}
	resp, err := g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), hdr))
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times; a retry executed the mutation again", calls)
	}
	if resp == nil || resp.Any() == nil {
		t.Fatal("the replay returned no response body")
	}
	// The replayed payload must be a real proto message. A *proto.Message — a
	// pointer to the interface — type-checks at the call site and only fails
	// when the codec tries to marshal it, on this path alone.
	if _, ok := resp.Any().(proto.Message); !ok {
		t.Fatalf("the replayed response is a %T, which the protobuf codec cannot marshal",
			resp.Any())
	}
}

// A handler whose response message is a TYPED NIL still replays.
//
// proto.Marshal is the trap. Marshalling any real message — generated, dynamicpb
// or a well-known type — returns a non-nil zero-length slice even when the
// message is empty, but marshalling a typed-nil pointer returns a NIL slice and
// a NIL error. Probed directly:
//
//	&systemv1.GetStatusResponse{}   b == nil: false, len 0
//	&emptypb.Empty{}                b == nil: false, len 0
//	dynamicpb.NewMessage(Empty)     b == nil: false, len 0
//	(*emptypb.Empty)(nil)           b == nil: TRUE,  len 0
//
// A nil slice is how the idempotency store spells "no response recorded". So
// without marshalResponse's normalization the store records a COMPLETED claim
// whose response is absent, and the first thing that notices is the client's
// retry: it takes the replay path, finds nil, and gets back "a completed
// idempotency record stored no response at all" — a raw error that never passed
// through errs, so it reaches the wire as an unmapped Unknown. The original
// mutation succeeded, so the client is told the operation failed while it in
// fact ran, and every subsequent retry says the same. A service layer returning
// (nil, nil) into connect.NewResponse is an ordinary Go mistake, which is what
// makes this reachable rather than theoretical.
func TestAHandlerReturningATypedNilMessageStillReplays(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.nilmsg.v1")
	g, err := interceptor.NewGates(fullDeps(t, svc, allowChecker{}))
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	nilHandler := func(context.Context, connect.AnyRequest) (connect.AnyResponse, error) {
		calls++
		return connect.NewResponse((*systemv1.GetStatusResponse)(nil)), nil
	}
	hdr := map[string]string{interceptor.IdempotencyHeader: "01J0000000000000000000006"}

	if _, err := g.WrapUnary(nilHandler)(context.Background(),
		request(t, procedure, statusMethod(t), hdr)); err != nil {
		t.Fatalf("first call: %v", err)
	}
	resp, err := g.WrapUnary(nilHandler)(context.Background(),
		request(t, procedure, statusMethod(t), hdr))
	if err != nil {
		t.Fatalf("the retry of a mutation that SUCCEEDED was refused: %v — the client now "+
			"believes an executed mutation failed, and every further retry says the same", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times, want 1", calls)
	}
	if resp == nil || resp.Any() == nil {
		t.Fatal("the replay returned no response body")
	}
}

// A read needs no key and is never stored.
func TestAReadNeedsNoIdempotencyKey(t *testing.T) {
	deps := fullDeps(t, systemService(), allowChecker{})
	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	if _, err := g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, "/chronos.system.v1.SystemService/GetStatus", statusMethod(t), nil)); err != nil {
		t.Fatalf("a read was refused for want of an idempotency key: %v", err)
	}
	if calls != 1 {
		t.Fatalf("the handler ran %d times", calls)
	}
}

type denyChecker struct{}

func (denyChecker) Check(context.Context, authz.Query) (authz.Decision, error) {
	return authz.Deny("no tuple"), nil
}

func (denyChecker) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Deny("no tuple")
	}
	return out, nil
}

type reserveAll struct{}

func (reserveAll) Reserve(ctx context.Context, _ string) (context.Context, func(), error) {
	return ctx, func() {}, nil
}

// memStore is an in-memory cqrs.Store that also RECORDS the scopes it was asked
// about, so a test can assert what the pipeline actually scoped by.
type memStore struct {
	mu      sync.Mutex
	records map[string]cqrs.Record
	seen    []cqrs.Scope
}

func newMemStore() *memStore {
	return &memStore{records: map[string]cqrs.Record{}}
}

func (m *memStore) Claim(_ context.Context, s cqrs.Scope, fp [32]byte, _ time.Duration) (cqrs.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.seen = append(m.seen, s)
	if rec, ok := m.records[s.String()]; ok {
		return rec, nil
	}
	m.records[s.String()] = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
	return cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}, nil
}

func (m *memStore) Complete(_ context.Context, s cqrs.Scope, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	rec := m.records[s.String()]
	rec.State, rec.Response = cqrs.StateDone, response
	m.records[s.String()] = rec
	return nil
}

func (m *memStore) Release(_ context.Context, s cqrs.Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, s.String())
	return nil
}

func (m *memStore) scopes() []cqrs.Scope {
	m.mu.Lock()
	defer m.mu.Unlock()
	return append([]cqrs.Scope(nil), m.seen...)
}

// Every event a mutation writes must be traceable to the request that caused it.
//
// The chain is attached at the edge because the log is append-only: an event
// appended without a correlation id can never acquire one, and a rule of the
// form "every handler remembers" is forgotten exactly once and then permanently.
// So the assertion is on what the HANDLER sees — the context the command runs
// under — not on the interceptor's internals.
func TestAMutationCarriesACausationChainIntoTheHandler(t *testing.T) {
	const key = "01J0000000000000000000009"

	svc, procedure := mutatingService(t, "chronos.test.gates.trace.v1")
	store := newMemStore()
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store})
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("idempotency: %v", err)
	}
	deps := fullDeps(t, svc, allowChecker{})
	deps.Idempotency = idem

	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	var seen eventsourcing.Trace
	handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		seen = eventsourcing.TraceFrom(ctx)
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}

	if _, err := g.WrapUnary(handler)(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: key,
		})); err != nil {
		t.Fatalf("request: %v", err)
	}

	if seen.IsZero() {
		t.Fatal("the handler ran with no causation chain; every event it wrote would be " +
			"untraceable to the request, permanently")
	}
	// The command's identity is the key, and it is stable across retries — so a
	// retried command reports the same cause instead of opening a second chain.
	if seen.CausationID != key {
		t.Errorf("causation %q, want the idempotency key %q", seen.CausationID, key)
	}
	// One request, one correlation id, even when it touches several aggregates.
	if seen.CorrelationID != key {
		t.Errorf("correlation %q, want the idempotency key %q", seen.CorrelationID, key)
	}
}

// A READ carries no chain, and must not: it writes no events, and requiring a
// key on reads would make every list endpoint carry one for nothing.
func TestAReadCarriesNoCausationChain(t *testing.T) {
	g, err := interceptor.NewGates(interceptor.Deps{Policies: policies(t, systemService())})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	var seen eventsourcing.Trace
	handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		seen = eventsourcing.TraceFrom(ctx)
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}
	if _, err := g.WrapUnary(handler)(context.Background(),
		request(t, "/chronos.system.v1.SystemService/GetStatus", statusMethod(t), nil)); err != nil {
		t.Fatalf("request: %v", err)
	}
	if !seen.IsZero() {
		t.Errorf("a read carried a causation chain: %+v", seen)
	}
}

// The correlation id is the TRACE id when the request carries one. That is the
// join between two systems that otherwise cannot be correlated: a span in Tempo
// and an event in the log, with no join table between them.
func TestACorrelationIDIsTheTraceIDWhenOneExists(t *testing.T) {
	const key = "01J000000000000000000000A"

	svc, procedure := mutatingService(t, "chronos.test.gates.otel.v1")
	store := newMemStore()
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: store})
	if err != nil {
		t.Fatalf("once: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("idempotency: %v", err)
	}
	deps := fullDeps(t, svc, allowChecker{})
	deps.Idempotency = idem

	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	// A span, as otelhttp would have opened from an incoming W3C header.
	traceID, err := trace.TraceIDFromHex("4bf92f3577b34da6a3ce929d0e0e4736")
	if err != nil {
		t.Fatalf("trace id: %v", err)
	}
	spanID, err := trace.SpanIDFromHex("00f067aa0ba902b7")
	if err != nil {
		t.Fatalf("span id: %v", err)
	}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))

	var seen eventsourcing.Trace
	handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		seen = eventsourcing.TraceFrom(ctx)
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}

	if _, err := g.WrapUnary(handler)(ctx,
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: key,
		})); err != nil {
		t.Fatalf("request: %v", err)
	}

	if seen.CorrelationID != traceID.String() {
		t.Errorf("correlation %q, want the trace id %q — without it an event cannot be "+
			"lined up with the span that produced it", seen.CorrelationID, traceID)
	}
	// Causation is still the COMMAND: a trace covers a request, and one request
	// can issue several commands.
	if seen.CausationID != key {
		t.Errorf("causation %q, want the idempotency key %q", seen.CausationID, key)
	}
}

// ---- self-scoped methods (identity acts on the caller's own account) ----

// selfScopedService registers a synthetic method carrying the self-scoped
// declaration the identity service uses: relation "self" on resource type
// "user", with no resource_id_field.
func selfScopedService(
	t *testing.T, pkg string, op optionsv1.OperationClass, aal optionsv1.AssuranceLevel,
) (protoreflect.FullName, string) {
	t.Helper()
	opts := &descriptorpb.MethodOptions{}
	proto.SetExtension(opts, optionsv1.E_Authz, &optionsv1.Authz{
		Relation: "self", ResourceType: "user",
	})
	proto.SetExtension(opts, optionsv1.E_Operation, op)
	if aal != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
		proto.SetExtension(opts, optionsv1.E_MinAal, aal)
	}

	fd := &descriptorpb.FileDescriptorProto{
		Name:       new(pkg + "/svc.proto"),
		Package:    new(pkg),
		Syntax:     new("proto3"),
		Dependency: []string{"chronos/system/v1/system.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("SelfService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       new("Act"),
				InputType:  new(".chronos.system.v1.GetStatusRequest"),
				OutputType: new(".chronos.system.v1.GetStatusResponse"),
				Options:    opts,
			}},
		}},
	}
	f, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(f); err != nil {
		t.Fatalf("register: %v", err)
	}
	return protoreflect.FullName(pkg + ".SelfService"), "/" + pkg + ".SelfService/Act"
}

// bootstrapSelfService registers a self-scoped method requiring AAL2 with a
// bootstrap floor of AAL1 — the shape EnrollTotp and ConfirmTotp declare.
func bootstrapSelfService(t *testing.T, pkg string) (protoreflect.FullName, string) {
	t.Helper()
	opts := &descriptorpb.MethodOptions{}
	proto.SetExtension(opts, optionsv1.E_Authz, &optionsv1.Authz{
		Relation: "self", ResourceType: "user",
	})
	proto.SetExtension(opts, optionsv1.E_Operation,
		optionsv1.OperationClass_OPERATION_CLASS_READ)
	proto.SetExtension(opts, optionsv1.E_MinAal,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)
	proto.SetExtension(opts, optionsv1.E_BootstrapMinAal,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)

	fd := &descriptorpb.FileDescriptorProto{
		Name:       new(pkg + "/svc.proto"),
		Package:    new(pkg),
		Syntax:     new("proto3"),
		Dependency: []string{"chronos/system/v1/system.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: new("SelfService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       new("Act"),
				InputType:  new(".chronos.system.v1.GetStatusRequest"),
				OutputType: new(".chronos.system.v1.GetStatusResponse"),
				Options:    opts,
			}},
		}},
	}
	f, err := protodesc.NewFile(fd, protoregistry.GlobalFiles)
	if err != nil {
		t.Fatalf("descriptor: %v", err)
	}
	if err := protoregistry.GlobalFiles.RegisterFile(f); err != nil {
		t.Fatalf("register: %v", err)
	}
	return protoreflect.FullName(pkg + ".SelfService"), "/" + pkg + ".SelfService/Act"
}

// runSelf drives one request through a pipeline wired with just an
// authenticator, and reports whether the handler ran.
func runSelf(
	t *testing.T, set *policy.Set, procedure string, p interceptor.Principal,
) (int, error) {
	t.Helper()
	g, err := interceptor.NewGates(interceptor.Deps{Policies: set, Authn: stubAuthn{principal: p}})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil))
	return calls, err
}

// THE HOLE. An AAL1 caller may enrol a first second factor and NOTHING else.
//
// This is the test the bootstrap floor exists to pass, and the second row is the
// one that matters: an attacker holding a stolen password, on an account that
// already has a second factor, is refused. Enrolling their own authenticator is
// precisely how they would make that access durable and survive the victim's
// password change, and the existing factor they cannot present is what stops
// them.
//
// The third and fourth rows close the routes around it. An authenticator that
// does not report an enrolment state gets the strict floor, so the relaxation
// cannot be reached by a Principal built carelessly or by an implementation that
// forgets the field. And on an account whose factor was REMOVED, the enrolment
// state is Established rather than Bootstrap — "has ever had", not "has" — so
// "remove the factor, then enrol my own" is refused at the same rung as adding
// one directly. That property is the authenticator's to preserve; what is proven
// here is that the gate honours it and has no second, looser path of its own.
func TestOnlyAFirstEnrolmentIsReachableBelowTheDeclaredAssuranceLevel(t *testing.T) {
	svc, procedure := bootstrapSelfService(t, "chronos.test.gates.bootstrap.v1")
	set := policies(t, svc)

	const subject = "subj_01J000000000000000000010"
	tests := []struct {
		name      string
		aal       optionsv1.AssuranceLevel
		enrolment policy.Enrolment
		admit     bool
		why       string
	}{
		{
			name:      "a first enrolment, single factor",
			aal:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
			enrolment: policy.EnrolmentBootstrap,
			admit:     true,
			why: "an account with no second factor cannot present one, so refusing here is " +
				"a requirement nothing can satisfy and the account never activates",
		},
		{
			name:      "an account that already has a second factor",
			aal:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
			enrolment: policy.EnrolmentEstablished,
			why: "this is the stolen-password attacker enrolling their own authenticator; " +
				"the existing factor is what they must present and cannot",
		},
		{
			name:      "an authenticator that did not report an enrolment state",
			aal:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
			enrolment: policy.EnrolmentUnknown,
			why:       "the zero value must deny, in the same sense authz.Decision's does",
		},
		{
			name:      "the ordinary case: a full session on an established account",
			aal:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2,
			enrolment: policy.EnrolmentEstablished,
			admit:     true,
			why:       "the strict floor is met, so nothing about it was relaxed away",
		},
		{
			name:      "a session with no assurance level at all",
			aal:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED,
			enrolment: policy.EnrolmentBootstrap,
			why: "UNSPECIFIED is below AAL1, and the bootstrap floor is a floor rather " +
				"than an exemption from having one",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			p := selfPrincipal(subject)
			p.AAL = tt.aal
			p.Context.AAL = int(tt.aal)
			p.Enrolment = tt.enrolment

			calls, err := runSelf(t, set, procedure, p)
			switch {
			case tt.admit && err != nil:
				t.Fatalf("refused: %v — %s", err, tt.why)
			case tt.admit && calls != 1:
				t.Fatalf("the handler ran %d times, want 1 — %s", calls, tt.why)
			case !tt.admit && err == nil:
				t.Fatalf("ADMITTED below the declared assurance level — %s", tt.why)
			case !tt.admit && calls != 0:
				t.Fatalf("the handler ran below the declared assurance level — %s", tt.why)
			}
			if !tt.admit {
				if got := connect.CodeOf(err); got != connect.CodePermissionDenied {
					t.Errorf("got %v, want PermissionDenied: a step-up refusal tells the "+
						"client to raise the session, not that the session is bad", got)
				}
			}
		})
	}
}

// The relaxation requires the DECLARATION, not merely the account state.
//
// Without this, a bootstrap account would be relaxed on every method it touches,
// and the exemption would be a property of the caller instead of a property of
// the two methods that need it. RevokeAllSessions and GenerateRecoveryCodes are
// AAL2 self-scoped methods that declare no exemption, and they must stay out of
// reach of a single-factor session whatever state its account is in.
func TestAFirstEnrolmentIsNotRelaxedOnMethodsThatDeclaredNoExemption(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.noexemption.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)

	p := selfPrincipal("subj_01J000000000000000000011")
	p.AAL = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
	p.Context.AAL = 1
	p.Enrolment = policy.EnrolmentBootstrap

	calls, err := runSelf(t, policies(t, svc), procedure, p)
	if err == nil {
		t.Fatal("a single-factor session reached an AAL2 method that declares no bootstrap " +
			"exemption: the relaxation has become a property of the caller rather than of " +
			"the method")
	}
	if calls != 0 {
		t.Fatal("the handler ran below the declared assurance level")
	}
}

// A bootstrap account is not exempt from AUTHENTICATION, nor from the
// credential-rotation confinement.
//
// The floor lowers one comparison. Everything that runs before and after it is
// untouched, and this is what says so — the alternative reading of "AAL1 is
// enough here" is "this method is nearly public", which it is not.
func TestABootstrapExemptionRelaxesNothingButTheAssuranceComparison(t *testing.T) {
	svc, procedure := bootstrapSelfService(t, "chronos.test.gates.bootstrapauthn.v1")
	set := policies(t, svc)

	t.Run("an unauthenticated caller is still refused", func(t *testing.T) {
		g, err := interceptor.NewGates(interceptor.Deps{
			Policies: set,
			Authn:    stubAuthn{err: errors.New("no session")},
		})
		if err != nil {
			t.Fatalf("NewGates: %v", err)
		}
		calls := 0
		_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
			request(t, procedure, statusMethod(t), nil))
		if err == nil || calls != 0 {
			t.Fatal("an unauthenticated caller reached a bootstrap-exempt method")
		}
		if got := connect.CodeOf(err); got != connect.CodeUnauthenticated {
			t.Fatalf("got %v, want Unauthenticated", got)
		}
	})

	t.Run("a principal carrying no subject is still refused", func(t *testing.T) {
		p := selfPrincipal("")
		p.AAL = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
		p.Enrolment = policy.EnrolmentBootstrap

		calls, err := runSelf(t, set, procedure, p)
		if err == nil || calls != 0 {
			t.Fatal("a principal with no subject reached a bootstrap-exempt method, so the " +
				"self check ran against an empty resource")
		}
	})
}

// stubAuthn is an authenticator whose answer the test chooses.
type stubAuthn struct {
	principal interceptor.Principal
	err       error
}

func (s stubAuthn) Authenticate(context.Context, interceptor.Header) (interceptor.Principal, error) {
	return s.principal, s.err
}

func selfPrincipal(subject string) interceptor.Principal {
	return interceptor.Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: subject},
		Context: authz.AuthContext{AAL: 2, SessionID: "sess_01J000000000000000000000"},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2,
	}
}

// A self-scoped method is served with NO organization anywhere in the request.
//
// This is the whole point of the third shape. Identity is not org-scoped — a
// person exists before any organization does — so the org-context, authz and
// subscription gates have nothing to resolve, consult or ask. Before this
// existed, every authenticated identity RPC was refused with an INTERNAL error.
func TestASelfScopedMethodIsServedWithNoOrganization(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.self.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)

	// Org, Authz, Subscriptions and Idempotency are deliberately ABSENT.
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		Authn:    stubAuthn{principal: selfPrincipal("subj_01J000000000000000000001")},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	var seen interceptor.Principal
	handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
		var ok bool
		seen, ok = interceptor.PrincipalFrom(ctx)
		if !ok {
			t.Error("the handler received no principal")
		}
		return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
	}
	if _, err := g.WrapUnary(handler)(context.Background(),
		request(t, procedure, statusMethod(t), nil)); err != nil {
		t.Fatalf("a self-scoped method was refused: %v", err)
	}
	if seen.Subject.ID != "subj_01J000000000000000000001" {
		t.Fatalf("the handler sees %q as the caller", seen.Subject.ID)
	}
}

// The self check is satisfied by the caller's OWN subject, and there is no input
// through which another subject could be named.
//
// Two different callers reach the same method and each is scoped to themselves;
// no header, field or context value the client controls changes which subject
// the check is about.
func TestASelfScopedCheckIsAlwaysAboutTheCaller(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfwho.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
	set := policies(t, svc)

	for _, subject := range []string{
		"subj_01J00000000000000000000A",
		"subj_01J00000000000000000000B",
	} {
		g, err := interceptor.NewGates(interceptor.Deps{
			Policies: set,
			Authn:    stubAuthn{principal: selfPrincipal(subject)},
		})
		if err != nil {
			t.Fatalf("NewGates: %v", err)
		}
		var seen string
		handler := func(ctx context.Context, _ connect.AnyRequest) (connect.AnyResponse, error) {
			p, _ := interceptor.PrincipalFrom(ctx)
			seen = p.Subject.ID
			return connect.NewResponse(&systemv1.GetStatusResponse{}), nil
		}
		if _, err := g.WrapUnary(handler)(context.Background(),
			request(t, procedure, statusMethod(t), map[string]string{
				// A caller attempting to name somebody else's account.
				"X-Subject-Id":  "subj_01J00000000000000000000Z",
				"Resource-Id":   "subj_01J00000000000000000000Z",
				"Authorization": "Bearer whatever",
			})); err != nil {
			t.Fatalf("request: %v", err)
		}
		if seen != subject {
			t.Fatalf("the request was scoped to %q, but the caller is %q", seen, subject)
		}
	}
}

// A self-scoped method whose principal has no subject is REFUSED.
//
// "Act on your own account" with an empty subject is "act on the account named
// by the empty string" — one row, shared by everyone who authenticated badly.
func TestASelfScopedMethodWithNoSubjectIsRefused(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfnosubj.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		Authn:    stubAuthn{principal: selfPrincipal("")},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil))
	if err == nil {
		t.Fatal("a self-scoped method ran for a principal with no subject")
	}
	if calls != 0 {
		t.Fatal("the handler ran for a principal with no subject")
	}
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("got %v, want Internal", got)
	}
}

// Self-scoped is not a way around authentication.
func TestASelfScopedMethodStillRequiresAuthentication(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfauthn.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
	set := policies(t, svc)

	tests := []struct {
		name string
		deps interceptor.Deps
		want connect.Code
	}{
		{
			name: "no authenticator wired",
			deps: interceptor.Deps{Policies: set},
			want: connect.CodeInternal,
		},
		{
			name: "the token resolved to nothing",
			deps: interceptor.Deps{Policies: set, Authn: stubAuthn{err: errors.New("no session")}},
			want: connect.CodeUnauthenticated,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			g, err := interceptor.NewGates(tt.deps)
			if err != nil {
				t.Fatalf("NewGates: %v", err)
			}
			calls := 0
			_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
				request(t, procedure, statusMethod(t), nil))
			if err == nil {
				t.Fatal("an unauthenticated caller reached a self-scoped method")
			}
			if calls != 0 {
				t.Fatal("the handler ran for an unauthenticated caller")
			}
			if got := connect.CodeOf(err); got != tt.want {
				t.Fatalf("got %v, want %v", got, tt.want)
			}
		})
	}
}

// Nor around step-up.
func TestASelfScopedMethodStillEnforcesItsAssuranceLevel(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfaal.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)

	weak := selfPrincipal("subj_01J000000000000000000002")
	weak.AAL = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1

	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		Authn:    stubAuthn{principal: weak},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil))
	if err == nil {
		t.Fatal("an AAL1 session reached a method requiring AAL2")
	}
	if calls != 0 {
		t.Fatal("the handler ran below the required assurance level")
	}
}

// Nor around idempotency: a self-scoped WRITE is still a mutation.
func TestASelfScopedMutationStillNeedsTheIdempotencyGate(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfwrite.v1",
		optionsv1.OperationClass_OPERATION_CLASS_WRITE,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		Authn:    stubAuthn{principal: selfPrincipal("subj_01J000000000000000000003")},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J0000000000000000000009",
		}))
	if err == nil {
		t.Fatal("a self-scoped mutation ran with no idempotency gate")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no idempotency gate")
	}
}

// The org-scoped shape did NOT become more permissive.
//
// An org-scoped method for which gate 1 resolved NO organization is still
// refused: the self branch answers a different question and must not have
// loosened this one.
//
// The mechanism changed with the gate. It used to mean "the principal carries no
// ActiveOrg", a field nothing ever populated; it now means "gate 1 attached no
// tenant scope", which is the state a resolver actually produces when it cannot
// place a caller. `resolvesNothing` below is that resolver.
func TestAnOrgScopedMethodWithNoOrganizationIsStillRefused(t *testing.T) {
	svc, procedure := mutatingService(t, "chronos.test.gates.noorg.v1")
	deps := fullDeps(t, svc, allowChecker{})
	orgless := selfPrincipal("subj_01J000000000000000000004")
	deps.Authn = stubAuthn{principal: orgless}
	deps.Org = resolvesNothing{}

	g, err := interceptor.NewGates(deps)
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), map[string]string{
			interceptor.IdempotencyHeader: "01J000000000000000000000A",
		}))
	if err == nil {
		t.Fatal("an org-scoped method ran with no organization resolved: the authz check " +
			"would have been made against an empty resource id")
	}
	if calls != 0 {
		t.Fatal("the handler ran with no organization")
	}
}

// An authentication OUTAGE is a server fault, not a credential failure.
//
// Reported as UNAUTHENTICATED, every client in the fleet signs its user out
// during a database blip and then re-authenticates against the database that is
// already struggling.
func TestAnAuthenticationOutageIsNotReportedAsABadCredential(t *testing.T) {
	svc, procedure := selfScopedService(t, "chronos.test.gates.selfoutage.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, svc),
		Authn: stubAuthn{err: fmt.Errorf("%w: connection refused",
			interceptor.ErrAuthenticationUnavailable)},
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}
	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
		request(t, procedure, statusMethod(t), nil))
	if err == nil {
		t.Fatal("a request was ADMITTED while authentication was unavailable")
	}
	if calls != 0 {
		t.Fatal("the handler ran while authentication was unavailable")
	}
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Fatalf("got %v, want Internal: an outage told to a client as UNAUTHENTICATED signs "+
			"every user out during a blip", got)
	}
}

// A session that must rotate its credential reaches its own account and nothing
// else (identity.md §3).
func TestASessionAwaitingCredentialRotationIsConfinedToItsOwnAccount(t *testing.T) {
	rotating := selfPrincipal("subj_01J000000000000000000005")
	rotating.RequiresCredentialRotation = true

	t.Run("its own account is reachable", func(t *testing.T) {
		svc, procedure := selfScopedService(t, "chronos.test.gates.rotself.v1",
			optionsv1.OperationClass_OPERATION_CLASS_READ,
			optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
		g, err := interceptor.NewGates(interceptor.Deps{
			Policies: policies(t, svc),
			Authn:    stubAuthn{principal: rotating},
		})
		if err != nil {
			t.Fatalf("NewGates: %v", err)
		}
		calls := 0
		if _, err := g.WrapUnary(okHandler(&calls))(context.Background(),
			request(t, procedure, statusMethod(t), nil)); err != nil {
			t.Fatalf("a rotation-flagged session could not reach its own account: %v", err)
		}
		if calls != 1 {
			t.Fatal("the handler did not run")
		}
	})

	t.Run("everything else is refused", func(t *testing.T) {
		svc, procedure := mutatingService(t, "chronos.test.gates.rotother.v1")
		deps := fullDeps(t, svc, allowChecker{})
		withOrg := rotating
		withOrg.Context.ActiveOrg = "org_01H8XG5N2QK7VB3C9WPYZR4TFM"
		deps.Authn = stubAuthn{principal: withOrg}

		g, err := interceptor.NewGates(deps)
		if err != nil {
			t.Fatalf("NewGates: %v", err)
		}
		calls := 0
		_, err = g.WrapUnary(okHandler(&calls))(context.Background(),
			request(t, procedure, statusMethod(t), map[string]string{
				interceptor.IdempotencyHeader: "01J000000000000000000000B",
			}))
		if err == nil {
			t.Fatal("a session established with a breached credential acted beyond its own " +
				"account")
		}
		if calls != 0 {
			t.Fatal("the handler ran for a session awaiting credential rotation")
		}
	})
}

// Blocking names only the gates a method actually REACHES.
//
// # The defect this exists to prevent, which shipped
//
// cmd/api logged Missing() at ERROR with "gates are declared by some methods and
// implemented by none; those methods will be refused for the lifetime of this
// process". On this build both halves were false. Every authorization
// declaration in the tree is `self` on `user`, and enforce returns at
// `if p.SelfScoped()` before the org-context gate — so org-context, authz and
// subscription are unreachable, and no method declares an entitlement at all.
// The server reported an ERROR on every boot and refused nothing.
//
// The cost is not cosmetic. A permanent ERROR that names no consequence is the
// line an operator learns to scroll past, and the same line will one day be
// real: the moment any method drops `self`, three unimplemented gates become an
// actual outage. Missing cannot distinguish the two states. Blocking can, and
// this pins the difference.
func TestBlockingNamesOnlyGatesAMethodReaches(t *testing.T) {
	selfSvc, _ := selfScopedService(t, "blocking.self.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)
	pubSvc, _ := publicMutatingService(t, "blocking.public.v1")

	// Nothing wired at all, so Missing() is the full set and any difference
	// Blocking() shows comes from reachability rather than from wiring.
	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, selfSvc, pubSvc, systemService()),
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	if got := len(g.Missing()); got != 6 {
		t.Fatalf("with no dependencies wired, Missing() named %d gates, want all 6; this "+
			"test's premise is that Blocking() is a strict subset of it", got)
	}

	blocking := map[interceptor.Gate]bool{}
	for _, gate := range g.Blocking() {
		blocking[gate] = true
	}

	// A self-scoped READ reaches authn and stops. The public mutation reaches
	// nothing at all — WrapUnary returns before authn for a public method — so
	// idempotency is not expected here either.
	if !blocking[interceptor.GateAuthn] {
		t.Errorf("a self-scoped method is authenticated, so an unwired authn gate DOES refuse "+
			"it; Blocking() does not name it: %v", g.Blocking())
	}
	for _, unreached := range []interceptor.Gate{
		interceptor.GateOrgContext, interceptor.GateAuthz,
		interceptor.GateSubscription, interceptor.GateEntitlement,
	} {
		if blocking[unreached] {
			t.Errorf("Blocking() names %s, but no method in this set reaches it — the "+
				"self-scoped one returns before it and the public one is not gated at all. "+
				"Reporting it as blocking is the false ERROR this test exists to prevent.",
				unreached)
		}
	}
}

// requiredGates agrees with the pipeline about what a self-scoped method needs.
//
// Blocking() derives its answer from requiredGates, which MIRRORS the early
// returns in enforce — and two descriptions of one control flow drift. A stale
// mirror here would under-report an outage, which is a worse failure than the
// over-reporting it replaced.
//
// So this asserts the claim directly against the real pipeline rather than
// against the mirror: with org-context, authz, subscription and entitlement ALL
// nil, a self-scoped method must still be served. If any of those gates were in
// fact reached, the request would come back INTERNAL naming the gate.
func TestASelfScopedMethodIsServedWithTheOrgGatesUnwired(t *testing.T) {
	selfSvc, procedure := selfScopedService(t, "blocking.drift.v1",
		optionsv1.OperationClass_OPERATION_CLASS_READ,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)

	g, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies(t, selfSvc),
		Authn:    allowAuthn{},
		// Org, Authz, Subscriptions and Entitlements deliberately nil.
	})
	if err != nil {
		t.Fatalf("NewGates: %v", err)
	}

	calls := 0
	_, err = g.WrapUnary(okHandler(&calls))(t.Context(),
		request(t, procedure, statusMethod(t), nil))
	if err != nil {
		t.Fatalf("a self-scoped method was refused with the organization gates unwired: %v.\n"+
			"Either enforce now reaches one of them for a self-scoped policy, or it never "+
			"did and requiredGates is wrong. Blocking() is derived from requiredGates, so "+
			"whichever it is, the startup report is now lying about what is down.", err)
	}
	if calls != 1 {
		t.Errorf("the handler ran %d times, want 1", calls)
	}
}
