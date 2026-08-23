package policy_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"github.com/chronos/chronos-go/internal/server/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/types/descriptorpb"
)

// services is every service this server actually serves. It grows with the API,
// and TestEveryServedServiceIsListed is what makes forgetting to grow it fail.
var services = []protoreflect.FullName{
	systemv1.File_chronos_system_v1_system_proto.Services().Get(0).FullName(),
	identityv1.File_chronos_identity_v1_identity_proto.Services().Get(0).FullName(),
}

// Every RPC the server serves declares its gates.
//
// This is the conformance test ADR-021 promises. It is deliberately not a
// per-method assertion: a list of expected methods would have to be updated when
// an RPC is added, and the person who forgets the annotation is the same person
// who forgets the list entry.
func TestEveryServedRPCDeclaresItsPolicy(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("an RPC is missing its enforcement policy:\n%v", err)
	}
	if len(set.Methods()) == 0 {
		t.Fatal("no methods were loaded, so this test asserts nothing about anything")
	}
}

// A method with no options at all is refused, and the message names it.
//
// Built as a synthetic descriptor rather than by un-annotating a real proto,
// because the real ones must stay annotated — a test that requires breaking the
// schema to run is a test nobody runs twice.
func TestAnUnannotatedMethodStopsStartup(t *testing.T) {
	_, err := policy.Load(unannotatedService(t))
	if err == nil {
		t.Fatal("a method with no policy was accepted: it would be served with no authz, no " +
			"operation class and no idempotency requirement, and nothing would say so")
	}
	if !errors.Is(err, policy.ErrUnannotated) {
		t.Errorf("not reported as an annotation failure: %v", err)
	}
	if !strings.Contains(err.Error(), "Unguarded") {
		t.Errorf("the error does not name the offending method: %v", err)
	}
}

// Naming no services is refused. An empty set enforces nothing and would start
// silently.
func TestLoadingNoServicesIsRefused(t *testing.T) {
	if _, err := policy.Load(); err == nil {
		t.Fatal("a policy set was loaded with no services named")
	}
}

// An unknown method DENIES rather than skipping the gates.
//
// It reaching an interceptor means the policy set and the router disagree, and
// the only safe reading of that disagreement is "this method was never checked".
func TestAnUnknownMethodIsNotFound(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if _, ok := set.Lookup("/chronos.ghost.v1.GhostService/Vanish"); ok {
		t.Fatal("an unregistered method resolved to a policy")
	}
}

// The system service's status endpoint is public, and being public is coherent:
// no authz, no entitlement, no assurance level.
func TestThePublicStatusEndpointIsCoherent(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	p, ok := set.Lookup("/chronos.system.v1.SystemService/GetStatus")
	if !ok {
		t.Fatalf("GetStatus is not in the set; loaded: %v", set.Methods())
	}
	if !p.Public {
		t.Error("GetStatus is not public; readiness probes cannot authenticate")
	}
	if p.Relation != "" || p.ResourceType != "" {
		t.Error("a public method declares an authz policy that nothing will evaluate")
	}
	if p.Mutating() {
		t.Error("a read endpoint is classed as mutating and would demand an idempotency key")
	}
}

// Mutating is derived from the declared operation class, not the method name.
func TestMutatingFollowsTheOperationClass(t *testing.T) {
	for class, want := range map[optionsv1.OperationClass]bool{
		optionsv1.OperationClass_OPERATION_CLASS_READ:           false,
		optionsv1.OperationClass_OPERATION_CLASS_WRITE:          true,
		optionsv1.OperationClass_OPERATION_CLASS_GROW:           true,
		optionsv1.OperationClass_OPERATION_CLASS_BILLING_VIEW:   false,
		optionsv1.OperationClass_OPERATION_CLASS_BILLING_MANAGE: true,
		optionsv1.OperationClass_OPERATION_CLASS_EXPORT:         false,
	} {
		if got := (policy.Policy{Operation: class}).Mutating(); got != want {
			t.Errorf("%s: Mutating() = %v, want %v — a write not classed as mutating is a "+
				"mutation with no idempotency key", class, got, want)
		}
	}
}

// An unset assurance level resolves to AAL1, never to zero.
//
// Zero is UNSPECIFIED, and comparing a session's level against it would let a
// method requiring AAL2 be satisfied by anything at all.
func TestAnUnsetAssuranceLevelIsAAL1(t *testing.T) {
	if got := (policy.Policy{}).RequiredAAL(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		t.Fatalf("RequiredAAL() = %v, want AAL1", got)
	}
	if got := (policy.Policy{MinAAL: optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2}).RequiredAAL(); got !=
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		t.Fatalf("a declared AAL2 resolved to %v", got)
	}
}

// unannotatedService registers a throwaway service whose method declares
// nothing, and returns its name.
func unannotatedService(t *testing.T) protoreflect.FullName {
	t.Helper()
	return registerSynthetic(t, "chronos.test.unannotated.v1", "Unguarded",
		&descriptorpb.MethodOptions{})
}

// Incoherent combinations are refused rather than resolved.
//
// Each of these has two readings, and picking one silently is how an endpoint
// ends up open. Built one field at a time from a known-good policy, so a failure
// names the field that broke it.
func TestIncoherentPoliciesAreRefused(t *testing.T) {
	cases := map[string]struct {
		mutate func(*descriptorpb.MethodOptions)
		wants  string
	}{
		"public and authz together": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Public, true)
			},
			wants: "both public and authz",
		},
		"public with an entitlement": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_Authz)
				proto.SetExtension(o, optionsv1.E_Public, true)
				proto.SetExtension(o, optionsv1.E_Entitlement, "seats.member")
			},
			wants: "entitlement",
		},
		"public requiring an assurance level": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_Authz)
				proto.SetExtension(o, optionsv1.E_Public, true)
				proto.SetExtension(o, optionsv1.E_MinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)
			},
			wants: "assurance level",
		},
		"no authz and not public": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_Authz)
			},
			wants: "no authz policy",
		},
		"authz with no relation": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Authz,
					&optionsv1.Authz{ResourceType: "organization"})
			},
			wants: "no relation",
		},
		"authz with no resource type": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{Relation: "admin"})
			},
			wants: "no resource type",
		},
		"no operation class": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_Operation)
			},
			wants: "no operation class",
		},
		"relation carrying a reserved character": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{
					Relation: "admin#member", ResourceType: "organization",
				})
			},
			wants: "not usable",
		},
		"resource type carrying a reserved character": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{
					Relation: "admin", ResourceType: "org:anization",
				})
			},
			wants: "not usable",
		},
	}

	i := 0
	for name, tc := range cases {
		i++
		opts := annotated()
		tc.mutate(opts)
		svc := registerSynthetic(t, "chronos.test.incoherent"+itoa(i)+".v1", "Method", opts)

		_, err := policy.Load(svc)
		if err == nil {
			t.Errorf("%s: was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: error does not mention %q: %v", name, tc.wants, err)
		}
	}
}

// A fully-annotated method loads, so the refusals above are discriminating
// rather than blanket.
func TestAWellFormedPolicyLoads(t *testing.T) {
	svc := registerSynthetic(t, "chronos.test.wellformed.v1", "Method", annotated())
	set, err := policy.Load(svc)
	if err != nil {
		t.Fatalf("a well-formed policy was refused: %v", err)
	}
	// Built from the RETURNED name rather than restated: registerSynthetic makes
	// each descriptor unique within the process so the package survives
	// `-count=N`, and a hand-written path would not follow it.
	p, ok := set.Lookup("/" + string(svc) + "/Method")
	if !ok {
		t.Fatalf("the method is not in the set; loaded: %v", set.Methods())
	}
	if p.Relation != "admin" || p.ResourceType != "organization" {
		t.Errorf("policy read back as %+v", p)
	}
	if !p.Mutating() {
		t.Error("a WRITE method is not classed as mutating, so it would need no idempotency key")
	}
}

func itoa(i int) string { return strconv.Itoa(i) }

// ---- the self-scoped shape ----

// SelfScoped recognises exactly one declaration and nothing adjacent to it.
//
// Each false case below is a way the predicate could be made to fire for a
// question it does not answer, and each would turn three gates off for a method
// that needs them.
func TestSelfScopedRecognisesOnlyTheSelfDeclaration(t *testing.T) {
	cases := map[string]struct {
		policy policy.Policy
		want   bool
	}{
		"the identity shape": {
			policy: policy.Policy{Relation: "self", ResourceType: "user"},
			want:   true,
		},
		"an ordinary org-scoped method": {
			policy: policy.Policy{Relation: "admin", ResourceType: "organization"},
		},
		"another relation on the user type": {
			policy: policy.Policy{Relation: "owner", ResourceType: "user"},
		},
		"self on another resource type": {
			policy: policy.Policy{Relation: "self", ResourceType: "organization"},
		},
		"self whose resource the caller names": {
			policy: policy.Policy{
				Relation: "self", ResourceType: "user", ResourceIDField: "user_id",
			},
		},
		"a public method": {
			policy: policy.Policy{Public: true, Relation: "self", ResourceType: "user"},
		},
		"an empty policy": {},
	}
	for name, tc := range cases {
		if got := tc.policy.SelfScoped(); got != tc.want {
			t.Errorf("%s: SelfScoped() = %v, want %v", name, got, tc.want)
		}
	}
}

// Incoherent self declarations are refused at STARTUP, not resolved at request
// time.
func TestIncoherentSelfPoliciesAreRefused(t *testing.T) {
	cases := map[string]struct {
		authz *optionsv1.Authz
		ent   string
		wants string
	}{
		"self whose resource the caller names": {
			authz: &optionsv1.Authz{
				Relation: "self", ResourceType: "user", ResourceIdField: "user_id",
			},
			wants: "not a self check",
		},
		"self on another resource type": {
			authz: &optionsv1.Authz{Relation: "self", ResourceType: "organization"},
			wants: "the only coherent type",
		},
		"self with an entitlement": {
			authz: &optionsv1.Authz{Relation: "self", ResourceType: "user"},
			ent:   "seats.member",
			wants: "entitlements are purchased by an organization",
		},
	}
	i := 0
	for name, tc := range cases {
		i++
		o := annotated()
		proto.SetExtension(o, optionsv1.E_Authz, tc.authz)
		if tc.ent != "" {
			proto.SetExtension(o, optionsv1.E_Entitlement, tc.ent)
		}
		svc := registerSynthetic(t, "chronos.test.selfincoherent"+itoa(i)+".v1", "Method", o)

		_, err := policy.Load(svc)
		if err == nil {
			t.Errorf("%s: was accepted", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: error does not mention %q: %v", name, tc.wants, err)
		}
	}
}

// ---- the bootstrap assurance floor (a first enrolment has nothing to step up
// with) ----

// selfAnnotated builds a valid self-scoped AAL2 policy — the baseline the
// bootstrap cases mutate.
func selfAnnotated() *descriptorpb.MethodOptions {
	o := &descriptorpb.MethodOptions{}
	proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{
		Relation: "self", ResourceType: "user",
	})
	proto.SetExtension(o, optionsv1.E_Operation, optionsv1.OperationClass_OPERATION_CLASS_WRITE)
	proto.SetExtension(o, optionsv1.E_MinAal, optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)
	return o
}

// The floor is relaxed on ONE combination and on nothing adjacent to it.
//
// Every other row here is a way the exemption could leak into a state it was not
// granted for, and each of them is the hole the design exists to keep shut: an
// account that already has a second factor must present it before another can be
// added, or a stolen password is enough to enrol one.
func TestABootstrapFloorRelaxesOnlyAFirstEnrolment(t *testing.T) {
	const (
		aal1 = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
		aal2 = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2
	)
	exempt := policy.Policy{
		Relation: "self", ResourceType: "user",
		MinAAL: aal2, BootstrapMinAAL: aal1,
	}
	strict := policy.Policy{Relation: "self", ResourceType: "user", MinAAL: aal2}

	cases := map[string]struct {
		policy    policy.Policy
		enrolment policy.Enrolment
		want      optionsv1.AssuranceLevel
	}{
		"a first enrolment on a method that declared the exemption": {
			policy: exempt, enrolment: policy.EnrolmentBootstrap, want: aal1,
		},
		"an account that already has a second factor": {
			policy: exempt, enrolment: policy.EnrolmentEstablished, want: aal2,
		},
		"an authenticator that did not answer": {
			policy: exempt, enrolment: policy.EnrolmentUnknown, want: aal2,
		},
		"the zero enrolment value": {
			policy: exempt, want: aal2,
		},
		"a first enrolment on a method that declared no exemption": {
			policy: strict, enrolment: policy.EnrolmentBootstrap, want: aal2,
		},
		"an established account on a method that declared no exemption": {
			policy: strict, enrolment: policy.EnrolmentEstablished, want: aal2,
		},
	}
	for name, tc := range cases {
		if got := tc.policy.AALFloor(tc.enrolment); got != tc.want {
			t.Errorf("%s: AALFloor = %v, want %v", name, got, tc.want)
		}
	}

	// A method with no assurance declaration at all still floors at AAL1, in
	// every enrolment state. Without this the bootstrap branch could return
	// UNSPECIFIED, which a session carrying no level satisfies.
	for _, e := range []policy.Enrolment{
		policy.EnrolmentUnknown, policy.EnrolmentEstablished, policy.EnrolmentBootstrap,
	} {
		if got := (policy.Policy{}).AALFloor(e); got != aal1 {
			t.Errorf("an undeclared policy floors at %v for enrolment %v, want AAL1", got, e)
		}
	}
}

// Incoherent bootstrap declarations are refused at STARTUP.
//
// A gate that can be misdeclared silently is worse than the deadlock it removes:
// the deadlock is loud, because nobody activates, and a misdeclared exemption is
// a permanently lowered floor that nothing reports.
func TestIncoherentBootstrapPoliciesAreRefused(t *testing.T) {
	cases := map[string]struct {
		mutate func(*descriptorpb.MethodOptions)
		wants  string
	}{
		"declared as the unspecified zero value": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED)
			},
			wants: "which every session satisfies",
		},
		"equal to the required level": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)
			},
			wants: "not strictly below",
		},
		"above the required level": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_MinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2)
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_3)
			},
			wants: "not strictly below",
		},
		"with no required level to be an exemption from": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_MinAal)
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)
			},
			wants: "not strictly below",
		},
		"on an org-scoped method": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.SetExtension(o, optionsv1.E_Authz, &optionsv1.Authz{
					Relation: "admin", ResourceType: "organization",
				})
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)
			},
			wants: "not scoped to the caller's own account",
		},
		"on a public method": {
			mutate: func(o *descriptorpb.MethodOptions) {
				proto.ClearExtension(o, optionsv1.E_Authz)
				proto.ClearExtension(o, optionsv1.E_MinAal)
				proto.SetExtension(o, optionsv1.E_Public, true)
				proto.SetExtension(o, optionsv1.E_BootstrapMinAal,
					optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)
			},
			wants: "no enrolment state to relax for",
		},
	}

	i := 0
	for name, tc := range cases {
		i++
		opts := selfAnnotated()
		tc.mutate(opts)
		svc := registerSynthetic(t, "chronos.test.bootstrap"+itoa(i)+".v1", "Method", opts)

		_, err := policy.Load(svc)
		if err == nil {
			t.Errorf("%s: was accepted, so a method is served below its declared assurance "+
				"level with nothing saying so", name)
			continue
		}
		if !strings.Contains(err.Error(), tc.wants) {
			t.Errorf("%s: error does not mention %q: %v", name, tc.wants, err)
		}
	}
}

// A coherent bootstrap declaration loads, so the refusals above discriminate
// rather than reject everything with the option set.
func TestACoherentBootstrapFloorLoads(t *testing.T) {
	opts := selfAnnotated()
	proto.SetExtension(opts, optionsv1.E_BootstrapMinAal,
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1)
	svc := registerSynthetic(t, "chronos.test.bootstrapok.v1", "Method", opts)

	set, err := policy.Load(svc)
	if err != nil {
		t.Fatalf("a coherent bootstrap floor was refused: %v", err)
	}
	method := "/" + string(svc) + "/Method"
	p, ok := set.Lookup(method)
	if !ok {
		t.Fatalf("the method is not in the set; loaded: %v", set.Methods())
	}
	if !p.BootstrapExempt() {
		t.Fatal("the declared exemption did not survive Load")
	}
	if got := p.AALFloor(policy.EnrolmentBootstrap); got !=
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		t.Errorf("a first enrolment floors at %v, want AAL1 — the deadlock is not broken", got)
	}
	if got := p.AALFloor(policy.EnrolmentEstablished); got !=
		optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		t.Errorf("an established account floors at %v, want AAL2", got)
	}
	if want := []string{method}; len(set.BootstrapExempt()) != 1 ||
		set.BootstrapExempt()[0] != want[0] {
		t.Errorf("Set.BootstrapExempt() = %v, want %v; an operator reading the startup log "+
			"would not see which methods are relaxed", set.BootstrapExempt(), want)
	}
}

// EXACTLY the two halves of a first enrolment carry the exemption, across every
// service this server serves.
//
// A pinned list, unlike almost every other test here, and deliberately so. The
// argument against pinning — the person who forgets the annotation also forgets
// the list — does not apply in this direction: this list is what a method must
// be ADDED to, and the failure mode being guarded is a new RPC quietly acquiring
// a lowered assurance floor. A method that removes one factor to get back to the
// no-factor state, or that mints recovery codes, would be exactly such an RPC,
// and copying the annotation from EnrollTotp is how it would acquire it.
func TestOnlyAFirstEnrolmentCarriesTheBootstrapExemption(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	want := []string{
		"/chronos.identity.v1.IdentityService/ConfirmTotp",
		"/chronos.identity.v1.IdentityService/EnrollTotp",
	}
	got := set.BootstrapExempt()
	if len(got) != len(want) {
		t.Fatalf("methods carrying a bootstrap exemption = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("methods carrying a bootstrap exemption = %v, want %v", got, want)
		}
	}
}

// The deadlock is broken on the real schema, and only for a first enrolment.
//
// Read the three methods together and they are the whole decision: the two calls
// that produce a first factor are reachable without one, the call that mints a
// standing bypass of every factor is not, and none of them is reachable below
// AAL2 once the account has a factor to present.
func TestTheRealEnrolmentPathIsReachableExactlyOnceAndNoWider(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	const (
		aal1 = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
		aal2 = optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2
	)
	cases := []struct {
		method                 string
		bootstrap, established optionsv1.AssuranceLevel
		why                    string
	}{
		{"EnrollTotp", aal1, aal2,
			"an account with no second factor cannot present one, so AAL2 here means it can " +
				"never obtain the factor it must have to activate"},
		{"ConfirmTotp", aal1, aal2,
			"the confirmation is the other half of the same enrolment; exempting only the " +
				"first half moves the deadlock rather than removing it"},
		{"GenerateRecoveryCodes", aal2, aal2,
			"a recovery code is a standing bypass of every factor, and it activates nothing — " +
				"so there is no deadlock to break and nothing to gain by relaxing it"},
	}
	for _, tc := range cases {
		p, ok := set.Lookup("/chronos.identity.v1.IdentityService/" + tc.method)
		if !ok {
			t.Fatalf("%s is not in the policy set", tc.method)
		}
		if got := p.AALFloor(policy.EnrolmentBootstrap); got != tc.bootstrap {
			t.Errorf("%s floors a first enrolment at %v, want %v: %s",
				tc.method, got, tc.bootstrap, tc.why)
		}
		if got := p.AALFloor(policy.EnrolmentEstablished); got != tc.established {
			t.Errorf("%s floors an account that already has a second factor at %v, want %v — "+
				"a stolen password would be enough to enrol another",
				tc.method, got, tc.established)
		}
		if got := p.AALFloor(policy.EnrolmentUnknown); got != tc.established {
			t.Errorf("%s floors an unknown enrolment state at %v, want %v: an authenticator "+
				"that does not answer must get the strict floor", tc.method, got, tc.established)
		}
	}
}

// The real identity service is self-scoped on every method that is not public.
//
// This is the annotation the gate depends on. If a method ever declares an
// org-scoped policy instead, it becomes unreachable — identity has no
// organization to resolve — and the failure is an INTERNAL error at request
// time rather than anything visible at build time.
func TestEveryNonPublicIdentityMethodIsSelfScoped(t *testing.T) {
	set, err := policy.Load(services...)
	if err != nil {
		t.Fatalf("policy.Load: %v", err)
	}
	svc := identityv1.File_chronos_identity_v1_identity_proto.Services().Get(0)
	methods := svc.Methods()

	selfScoped := 0
	for i := range methods.Len() {
		name := "/" + string(svc.FullName()) + "/" + string(methods.Get(i).Name())
		p, ok := set.Lookup(name)
		if !ok {
			t.Fatalf("%s is not in the policy set", name)
		}
		if p.Public {
			continue
		}
		if !p.SelfScoped() {
			t.Errorf("%s is neither public nor self-scoped (relation %q, type %q, field %q), "+
				"so it is org-scoped — and identity has no organization to resolve, which "+
				"makes it unreachable", name, p.Relation, p.ResourceType, p.ResourceIDField)
			continue
		}
		selfScoped++
	}
	if selfScoped == 0 {
		t.Fatal("no identity method is self-scoped; this test would pass against an empty " +
			"service and is asserting nothing")
	}
	if got := len(set.SelfScoped()); got != selfScoped {
		t.Errorf("Set.SelfScoped() lists %d methods, but %d are self-scoped; an operator "+
			"reading the startup log would not see them all", got, selfScoped)
	}
}
