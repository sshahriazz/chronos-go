// Package policy reads each RPC's declared enforcement policy and refuses to
// serve any method that has none.
//
// ADR-021's whole argument is that gates are declared, never hand-written: the
// failure mode of a per-handler design is that the one endpoint nobody
// remembered to guard is the one that leaks. Declaring the policy beside the
// method only removes that failure if a MISSING declaration is also impossible —
// otherwise "forgot to annotate" replaces "forgot to guard", and it is quieter,
// because an unannotated method looks exactly like a correctly-annotated one
// from the outside.
//
// So the check runs at STARTUP, over every method in the server's own file
// descriptors, and an unannotated method stops the process.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ErrUnannotated is a method with no declared policy.
var ErrUnannotated = errors.New("policy: method declares no enforcement policy")

// Policy is one RPC's declared enforcement, in the form the interceptors want.
//
// A value type with no pointers into the descriptor: the interceptors read it on
// every request, and a shared mutable view of protobuf options is a data race
// waiting for the first concurrent request.
type Policy struct {
	// Method is the full RPC name, "/chronos.workspace.v1.WorkspaceService/Create".
	Method string

	// Public marks an unauthenticated endpoint. Health and discovery only.
	Public bool

	// Relation and ResourceType are the authz check. Empty on a public method.
	Relation     authz.Relation
	ResourceType string

	// ResourceIDField names the request field holding the resource id. Empty
	// means the request is scoped to the org the org-context gate resolved.
	ResourceIDField string

	// Operation drives the subscription gate.
	Operation optionsv1.OperationClass

	// Entitlement is the key gate 4 checks. Empty means the method consumes none.
	Entitlement string

	// MinAAL is the authentication strength required. Unspecified means AAL1.
	MinAAL optionsv1.AssuranceLevel
}

// Mutating reports whether this method changes state, and therefore requires an
// idempotency key (CONVENTIONS §6).
//
// Derived from the declared operation class rather than from the method name.
// Naming conventions are a suggestion; the class is a declaration the
// subscription gate already depends on being right.
func (p Policy) Mutating() bool {
	switch p.Operation {
	case optionsv1.OperationClass_OPERATION_CLASS_WRITE,
		optionsv1.OperationClass_OPERATION_CLASS_GROW,
		optionsv1.OperationClass_OPERATION_CLASS_BILLING_MANAGE:
		return true
	default:
		return false
	}
}

// RequiredAAL resolves the assurance level, defaulting to AAL1.
func (p Policy) RequiredAAL() optionsv1.AssuranceLevel {
	if p.MinAAL == optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
	}
	return p.MinAAL
}

// Set is every method the server will serve, with its policy.
type Set struct {
	byMethod map[string]Policy
}

// Lookup returns the policy for a method.
//
// The second return is false for a method that is not in the set at all, and
// the caller must DENY on that — not skip the gates. An unknown method reaching
// an interceptor means the set and the router disagree, and the safe reading of
// that disagreement is "this method was never checked".
func (s *Set) Lookup(method string) (Policy, bool) {
	p, ok := s.byMethod[method]
	return p, ok
}

// Methods returns every method name, sorted. For logging what is being served.
func (s *Set) Methods() []string {
	out := make([]string, 0, len(s.byMethod))
	for m := range s.byMethod {
		out = append(out, m)
	}
	sort.Strings(out)
	return out
}

// Load reads the policies for the named services and refuses on any gap.
//
// Services are named explicitly rather than discovered from the global registry:
// the registry also holds every transitively-imported proto — Google's
// well-known types, gRPC health, OpenFGA's own API — and none of those are ours
// to annotate. Scanning everything would force the caller to maintain a
// skip-list, which is a list somebody eventually adds a real service to.
func Load(services ...protoreflect.FullName) (*Set, error) {
	if len(services) == 0 {
		return nil, fmt.Errorf("policy: no services named; a server that enforces nothing " +
			"would start silently")
	}
	set := &Set{byMethod: make(map[string]Policy)}
	var problems []string

	for _, name := range services {
		desc, err := protoregistry.GlobalFiles.FindDescriptorByName(name)
		if err != nil {
			return nil, fmt.Errorf("policy: service %s is not registered: %w", name, err)
		}
		svc, ok := desc.(protoreflect.ServiceDescriptor)
		if !ok {
			return nil, fmt.Errorf("policy: %s is a %T, not a service", name, desc)
		}
		methods := svc.Methods()
		for i := range methods.Len() {
			m := methods.Get(i)
			p, err := read(m)
			if err != nil {
				problems = append(problems, "  "+err.Error())
				continue
			}
			set.byMethod[p.Method] = p
		}
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%w:\n%s\n\nEvery RPC must declare its gates (ADR-021). "+
			"An unannotated method is indistinguishable from a correctly-annotated one at "+
			"runtime, which is why this stops startup instead of the request",
			ErrUnannotated, strings.Join(problems, "\n"))
	}
	return set, nil
}

// fullMethod renders the ConnectRPC / gRPC path form.
func fullMethod(m protoreflect.MethodDescriptor) string {
	return "/" + string(m.Parent().(protoreflect.ServiceDescriptor).FullName()) + "/" + string(m.Name())
}

// read extracts one method's policy, rejecting every incoherent combination.
func read(m protoreflect.MethodDescriptor) (Policy, error) {
	method := fullMethod(m)
	mo := m.Options()
	if mo == nil {
		return Policy{}, fmt.Errorf("%s: no options at all", method)
	}

	public, _ := proto.GetExtension(mo, optionsv1.E_Public).(bool)
	az, _ := proto.GetExtension(mo, optionsv1.E_Authz).(*optionsv1.Authz)
	op, _ := proto.GetExtension(mo, optionsv1.E_Operation).(optionsv1.OperationClass)
	ent, _ := proto.GetExtension(mo, optionsv1.E_Entitlement).(string)
	aal, _ := proto.GetExtension(mo, optionsv1.E_MinAal).(optionsv1.AssuranceLevel)

	p := Policy{
		Method:      method,
		Public:      public,
		Operation:   op,
		Entitlement: ent,
		MinAAL:      aal,
	}

	if public {
		// Mutually exclusive, and the combination is refused rather than
		// resolved: "public but also requires admin" has two readings, and
		// picking one silently is how an endpoint ends up open.
		if az != nil {
			return Policy{}, fmt.Errorf("%s: declares both public and authz", method)
		}
		if ent != "" {
			return Policy{}, fmt.Errorf("%s: is public but declares an entitlement", method)
		}
		if aal != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
			return Policy{}, fmt.Errorf("%s: is public but requires an assurance level, "+
				"which no unauthenticated caller can have", method)
		}
		if op == optionsv1.OperationClass_OPERATION_CLASS_UNSPECIFIED {
			return Policy{}, fmt.Errorf("%s: declares no operation class", method)
		}
		return p, nil
	}

	if az == nil {
		return Policy{}, fmt.Errorf("%s: declares no authz policy", method)
	}
	if az.GetRelation() == "" {
		return Policy{}, fmt.Errorf("%s: authz declares no relation", method)
	}
	if az.GetResourceType() == "" {
		return Policy{}, fmt.Errorf("%s: authz declares no resource type", method)
	}
	if op == optionsv1.OperationClass_OPERATION_CLASS_UNSPECIFIED {
		// Not defaulted to READ. A write silently classed as a read passes the
		// subscription gate in every org state, including Suspended and Closed —
		// so the safe default is no default.
		return Policy{}, fmt.Errorf("%s: declares no operation class; it cannot be defaulted, "+
			"because a write classed as a read is permitted in a suspended org", method)
	}
	p.Relation = authz.Relation(az.GetRelation())
	p.ResourceType = az.GetResourceType()
	p.ResourceIDField = az.GetResourceIdField()

	// The relation and resource type become an OpenFGA reference, so they carry
	// the same reserved-character rule as every other one — ':' separates type
	// from id and '#' introduces a userset, so either would address a different
	// object than the schema names. Checked HERE, at startup, against the same
	// validator the Guard uses: a relation that only fails at request time fails
	// closed, which means an endpoint that denies everybody and an ops
	// investigation instead of a build error.
	probe := authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: "probe"},
		Relation:  p.Relation,
		Resource:  authz.ResourceRef{Type: p.ResourceType, ID: "probe"},
	}
	if err := probe.Validate(); err != nil {
		return Policy{}, fmt.Errorf("%s: authz policy is not usable: %w", method, err)
	}
	return p, nil
}
