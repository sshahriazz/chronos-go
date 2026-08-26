// Package policy reads each operator RPC's declared enforcement and refuses to
// serve any method whose declaration is missing or incoherent.
//
// It is a sibling of internal/server/policy, not a reuse of it, for the reason
// chronos/operator/v1/options.proto sets out: the two planes authorize
// different things with different vocabularies, and a shared loader would have
// to accept both, which means accepting a tenant declaration on an operator
// method and vice versa.
//
// What it shares is the ARGUMENT. ADR-021: a per-handler design fails in
// exactly one way — the endpoint nobody remembered to guard — and declaring the
// policy beside the method only removes that failure if a missing declaration
// is also impossible. So this runs at STARTUP over every method in the server's
// own descriptors, and an unannotated method stops the process.
package policy

import (
	"errors"
	"fmt"
	"sort"
	"strings"

	operatorv1 "github.com/chronos/chronos-go/gen/proto/chronos/operator/v1"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ErrUnannotated is a method with no declared policy.
var ErrUnannotated = errors.New("operator policy: method declares no enforcement policy")

// Access is how a method is reached.
type Access int

const (
	// AccessCapability is the ordinary case: a live session whose operator's
	// role holds the declared capability. Zero value, so a Policy that failed
	// to load is the most restrictive kind rather than the least — a struct
	// that defaulted to "unauthenticated" would turn a loader bug into an open
	// endpoint.
	AccessCapability Access = iota

	// AccessUnauthenticated needs no session. The OIDC ceremony only.
	AccessUnauthenticated

	// AccessSSOOnly needs a session that has passed SSO and not yet WebAuthn.
	// The WebAuthn pair only.
	AccessSSOOnly
)

// Policy is one RPC's declared enforcement, in the form the interceptors want.
//
// A value type with no pointers into the descriptor, for the same reason the
// tenant plane's is: the interceptors read it on every request, and a shared
// mutable view of protobuf options is a data race waiting for the first
// concurrent request.
type Policy struct {
	// Method is the full RPC name, "/chronos.operator.v1.OperatorService/GetCustomer".
	Method string

	// Access is how the method is reached.
	Access Access

	// Capability is required when Access is AccessCapability, and empty
	// otherwise.
	Capability domain.Capability

	// Audit is what the method records. AUDIT_ACTION_UNSPECIFIED exactly when
	// Access is AccessUnauthenticated.
	Audit operatorv1.AuditAction
}

// Catalogue is every method's policy, by full method name.
type Catalogue map[string]Policy

// Load walks a service's descriptor and produces its catalogue, refusing the
// whole service if any method's declaration is missing or incoherent.
//
// # It refuses the SERVICE, not the method
//
// Returning a partial catalogue and letting the server run without the bad
// method would be the quieter failure and the wrong one: an operator endpoint
// that is absent looks, from the console, exactly like one that is broken, and
// the console's author would file a bug rather than notice a policy was
// rejected. Refusing to start puts the message in front of whoever deployed it.
func Load(sd protoreflect.ServiceDescriptor) (Catalogue, error) {
	out := make(Catalogue)
	var problems []string

	methods := sd.Methods()
	for i := range methods.Len() {
		md := methods.Get(i)
		name := fmt.Sprintf("/%s/%s", sd.FullName(), md.Name())

		p, err := policyFor(name, md)
		if err != nil {
			problems = append(problems, err.Error())
			continue
		}
		out[name] = p
	}

	if len(problems) > 0 {
		sort.Strings(problems)
		return nil, fmt.Errorf("%w:\n  %s", ErrUnannotated, strings.Join(problems, "\n  "))
	}
	return out, nil
}

// LoadByName resolves a service by its full protobuf name and loads it.
func LoadByName(full protoreflect.FullName) (Catalogue, error) {
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(full)
	if err != nil {
		return nil, fmt.Errorf("operator policy: resolving %s: %w", full, err)
	}
	sd, ok := d.(protoreflect.ServiceDescriptor)
	if !ok {
		return nil, fmt.Errorf("operator policy: %s is not a service", full)
	}
	return Load(sd)
}

func policyFor(name string, md protoreflect.MethodDescriptor) (Policy, error) {
	capability := domain.Capability(strings.TrimSpace(getString(md, operatorv1.E_Capability)))
	unauth := getBool(md, operatorv1.E_Unauthenticated)
	ssoOnly := getBool(md, operatorv1.E_SsoOnly)
	audit := getAudit(md)

	switch {
	case unauth && ssoOnly:
		return Policy{}, fmt.Errorf(
			"%s declares both unauthenticated and sso_only; there is no method both are true of, "+
				"and the permissive one would win at runtime", name)

	case unauth && capability != "":
		return Policy{}, fmt.Errorf(
			"%s declares a capability AND unauthenticated; a capability nobody is checked for "+
				"reads as a guard and is not one", name)

	case ssoOnly && capability != "":
		return Policy{}, fmt.Errorf(
			"%s declares a capability AND sso_only; an sso_only session has no role yet, so the "+
				"capability could never be evaluated", name)

	case unauth:
		if audit != operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED {
			return Policy{}, fmt.Errorf(
				"%s is unauthenticated and declares an audit action; an entry naming a caller "+
					"nobody has identified records only that somebody loaded a page", name)
		}
		return Policy{Method: name, Access: AccessUnauthenticated}, nil

	case ssoOnly:
		// An audit action is OPTIONAL here, and the exemption is narrow enough
		// to be safe: an sso_only method is a step of the sign-in ceremony, it
		// reads no tenant data, and operator.md §5's rule is about processing
		// somebody else's data. BeginWebAuthn issues a challenge and touches
		// nothing but the caller's own credential list; FinishWebAuthn declares
		// AUDIT_ACTION_SIGNED_IN because the ceremony has then actually
		// happened.
		//
		// It looks like an escape hatch — "mark it sso_only and record nothing"
		// — and it is closed from the other side rather than here:
		// TestOnlyTheWebAuthnPairIsReachableWithAPendingSession enumerates the
		// sso_only methods against a literal pair, so a third one fails the
		// suite whatever it declares.
		return Policy{Method: name, Access: AccessSSOOnly, Audit: audit}, nil

	case audit == operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED:
		return Policy{}, fmt.Errorf(
			"%s declares no audit action; under GDPR looking is processing, so every operator "+
				"method that reads a customer records one (operator.md §5)", name)

	case capability == "":
		return Policy{}, fmt.Errorf(
			"%s declares no capability and is not marked unauthenticated or sso_only", name)

	case !domain.KnownCapability(capability):
		// The one-list guarantee options.proto promises. The proto carries a
		// string so the role table can stay in Go where it is tested; this is
		// what stops that string being a name the table has never heard of.
		return Policy{}, fmt.Errorf(
			"%s declares capability %q, which no role in internal/operator/domain holds; "+
				"the capability set is the role table's vocabulary", name, capability)

	default:
		return Policy{
			Method:     name,
			Access:     AccessCapability,
			Capability: capability,
			Audit:      audit,
		}, nil
	}
}

func getString(md protoreflect.MethodDescriptor, xt protoreflect.ExtensionType) string {
	v, ok := proto.GetExtension(md.Options(), xt).(string)
	if !ok {
		return ""
	}
	return v
}

func getBool(md protoreflect.MethodDescriptor, xt protoreflect.ExtensionType) bool {
	v, ok := proto.GetExtension(md.Options(), xt).(bool)
	if !ok {
		return false
	}
	return v
}

func getAudit(md protoreflect.MethodDescriptor) operatorv1.AuditAction {
	v, ok := proto.GetExtension(md.Options(), operatorv1.E_Audit).(operatorv1.AuditAction)
	if !ok {
		return operatorv1.AuditAction_AUDIT_ACTION_UNSPECIFIED
	}
	return v
}
