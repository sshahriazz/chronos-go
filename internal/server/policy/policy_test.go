package policy_test

import (
	"errors"
	"strconv"
	"strings"
	"testing"

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
	p, ok := set.Lookup("/chronos.test.wellformed.v1.SyntheticService/Method")
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
