package interceptor_test

import (
	"context"
	"errors"
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
		Name:       proto.String(pkg + "/svc.proto"),
		Package:    proto.String(pkg),
		Syntax:     proto.String("proto3"),
		Dependency: []string{"chronos/system/v1/system.proto"},
		Service: []*descriptorpb.ServiceDescriptorProto{{
			Name: proto.String("SyntheticService"),
			Method: []*descriptorpb.MethodDescriptorProto{{
				Name:       proto.String("Mutate"),
				InputType:  proto.String(".chronos.system.v1.GetStatusRequest"),
				OutputType: proto.String(".chronos.system.v1.GetStatusResponse"),
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

type passOrg struct{}

func (passOrg) Resolve(ctx context.Context, _ interceptor.Principal, _ interceptor.Header) (context.Context, error) {
	return ctx, nil
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

func (reserveAll) Reserve(context.Context, string) (func(), error) { return func() {}, nil }

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
