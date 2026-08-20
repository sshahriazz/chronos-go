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

// RelationSelf and ResourceTypeUser are the SELF-SCOPED declaration: "the caller
// is acting on their own account".
//
// It exists because identity is not organization-scoped. A person exists before
// any organization does, so there is no org for gate 1 to resolve, no
// `workspace_id` for row-level security to scope by, and no OpenFGA object to
// check a relation against — the account IS the principal. The two org-scoped
// shapes both answer the wrong question here: an empty resource_id_field means
// "the org already resolved", and a named one means "read the id from this
// request field", which no identity message carries because the account is
// resolved from the session rather than named by the caller.
//
// Recognised by VALUE rather than by a dedicated option because the option does
// not exist yet; see Policy.SelfScoped for what the proto should gain and why
// the string is safe in the meantime.
const (
	RelationSelf     authz.Relation = "self"
	ResourceTypeUser string         = "user"
)

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

	// BootstrapMinAAL is the floor that applies while the caller's account has
	// never held a proven second factor. Unspecified means no exemption: MinAAL
	// applies in every state.
	//
	// Read AALFloor rather than this field. Comparing a session against the raw
	// value has the same defect as comparing it against the raw MinAAL — the
	// zero value is UNSPECIFIED, which anything satisfies.
	BootstrapMinAAL optionsv1.AssuranceLevel
}

// Enrolment is what the caller's account has, as the AUTHENTICATOR resolved it.
//
// It is a fact read server-side from the session's account, never a claim: no
// request field, header or context value any handler could write takes part in
// it. That is what stops the bootstrap floor from being something a caller can
// assert their way into.
//
// The zero value is EnrolmentUnknown and grants nothing, in the same sense as
// authz.Decision's: an authenticator that forgets to answer, a Principal built
// by a test double, and a struct literal that predates this field all produce
// the strict floor rather than the relaxed one.
type Enrolment int

const (
	// EnrolmentUnknown is "the authenticator did not say". No exemption.
	EnrolmentUnknown Enrolment = iota

	// EnrolmentEstablished is an account that has, or has ever had, a proven
	// second factor. No exemption — this is the state in which requiring the
	// existing factor is what stops an attacker adding their own.
	//
	// "Has ever had" and not "has" is the load-bearing half. An account that
	// loses its factor does NOT return to Bootstrap, so removing a factor is not
	// a route back to the exemption. Recovering from a lost factor is a recovery
	// flow, not a second first enrolment.
	EnrolmentEstablished

	// EnrolmentBootstrap is an account that has never held a proven second
	// factor. This is the only state the bootstrap floor applies in.
	EnrolmentBootstrap
)

func (e Enrolment) String() string {
	switch e {
	case EnrolmentBootstrap:
		return "bootstrap"
	case EnrolmentEstablished:
		return "established"
	default:
		return "unknown"
	}
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

// SelfScoped reports whether this method's authorization question is "is the
// caller acting on their own account".
//
// # What it means for the gates
//
// A self-scoped method resolves its resource from the PRINCIPAL — the subject id
// the authn gate read out of the session — and never from the request. The authz
// gate therefore answers it locally: the check is `self` on `user:<the caller's
// own subject>`, which is true by construction and which OpenFGA could only
// confirm after a round trip that could fail. That is not skipping the gate. The
// gate is answered, from strictly more information than the graph holds, and a
// self-scoped method is refused exactly as hard as any other if authn fails.
//
// The org-context and subscription gates are not run for one, either. Both are
// questions about an organization: which one is this request in, and does its
// lifecycle state permit this operation class. There is no organization, so
// there is nothing to resolve and no subscription to consult. An org whose
// payment lapsed must not stop a person signing out of a stolen device.
//
// # Why it cannot name somebody else's resource
//
// Three conditions have to hold together, and each closes a different route:
//
//   - The relation is exactly "self" and the resource type exactly "user", so a
//     method asking about any other relation or object takes the ordinary path
//     and is checked against OpenFGA.
//   - ResourceIDField is empty. A self-scoped method that also named a request
//     field would be asking "am I myself" about an id the CALLER supplied, which
//     is the confused deputy this predicate exists to make unrepresentable.
//     Load refuses that combination outright, at startup.
//   - The method is not public, so a principal exists at all.
//
// The gate then substitutes the principal's own subject id. Two callers can
// never resolve to the same resource, and no caller can influence which resource
// their own check is about.
//
// What it does NOT grant is authority over an object NAMED IN THE REQUEST BODY.
// RevokeSession carries a session id; this policy says the caller may act on
// their own account, not that the session they named is theirs. The handler
// scopes every read and write by the principal's subject, and that is a handler
// obligation this gate cannot discharge.
//
// # What the proto should gain
//
// A dedicated `self` marker on chronos.options.v1.Authz — a bool, or a resource
// scope enum — so the declaration is structural instead of a magic relation
// name. Until it exists, "self" is a value in a field the policy loader already
// validates, declared per method and reviewed like every other policy. Its blast
// radius is the same as `public: true`, which likewise turns the pipeline off by
// declaration; and unlike `public`, this one still requires a live session and
// still enforces the assurance level.
func (p Policy) SelfScoped() bool {
	return !p.Public &&
		p.Relation == RelationSelf &&
		p.ResourceType == ResourceTypeUser &&
		p.ResourceIDField == ""
}

// RequiredAAL resolves the assurance level, defaulting to AAL1.
//
// This is the floor for an account that has a second factor, which is every
// account the system considers finished. AALFloor is what the gate compares
// against, because a first enrolment is the one case where this floor is not
// merely strict but unsatisfiable.
func (p Policy) RequiredAAL() optionsv1.AssuranceLevel {
	if p.MinAAL == optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1
	}
	return p.MinAAL
}

// BootstrapExempt reports whether this method declares a bootstrap floor at all.
//
// Separate from AALFloor so the exemption can be LISTED — at startup, and in a
// test that pins exactly which methods carry it. A relaxation that is only
// visible by reading one method's options is a relaxation a new RPC can acquire
// without anyone noticing.
func (p Policy) BootstrapExempt() bool {
	return p.BootstrapMinAAL != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED
}

// AALFloor resolves the assurance level this method requires of an account in
// the given enrolment state.
//
// The relaxation happens on exactly one path: the method declared a bootstrap
// floor, AND the authenticator positively reported that the account has never
// held a proven second factor. Every other combination — no declaration, an
// established account, an authenticator that did not answer — resolves to
// RequiredAAL, so the strict floor is what a mistake produces.
//
// Load has already refused a bootstrap floor that is not strictly below MinAAL,
// so this can only ever LOWER the requirement, and only to a level that is
// itself at least AAL1. There is no declaration that makes this return
// UNSPECIFIED, which a session with no assurance level at all would satisfy.
func (p Policy) AALFloor(e Enrolment) optionsv1.AssuranceLevel {
	if e == EnrolmentBootstrap && p.BootstrapExempt() {
		return p.BootstrapMinAAL
	}
	return p.RequiredAAL()
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

// checkSelfScope refuses every incoherent use of the self relation, at STARTUP.
//
// Each of these combinations would otherwise be resolved silently at request
// time, and each resolves in the dangerous direction:
//
//   - "self" with a resource_id_field would ask "am I myself" about an id the
//     CALLER supplied. Whether the gate honoured the field or ignored it, the
//     declaration and the enforcement would disagree, and the reviewer reading
//     the proto would be reading the wrong one.
//   - "self" on a resource type other than "user" names an object the principal
//     is not. It would fall through to OpenFGA and be checked as an ordinary
//     relation, which is a different question than the one the author wrote.
//     Refused rather than reinterpreted.
//   - "self" with an entitlement asks gate 4 to reserve quota with no
//     organization to reserve it against. Entitlements are purchased by an org;
//     a person does not have one.
func checkSelfScope(p Policy) error {
	if p.Relation != RelationSelf {
		// Any other relation on resource type "user" is an ordinary graph
		// question — "owner", "viewer" — and belongs to OpenFGA. Only the self
		// relation gets the local answer.
		return nil
	}
	switch {
	case p.ResourceType != ResourceTypeUser:
		return fmt.Errorf("%s: declares the self relation on resource type %q; self means the "+
			"caller's own account, so the only coherent type is %q",
			p.Method, p.ResourceType, ResourceTypeUser)
	case p.ResourceIDField != "":
		return fmt.Errorf("%s: declares the self relation AND reads its resource id from field "+
			"%q; a self check whose subject the caller names is not a self check",
			p.Method, p.ResourceIDField)
	case p.Entitlement != "":
		return fmt.Errorf("%s: is self-scoped but declares the entitlement %q; entitlements are "+
			"purchased by an organization, and a self-scoped method has none",
			p.Method, p.Entitlement)
	}
	return nil
}

// checkBootstrap refuses every incoherent bootstrap declaration, at STARTUP.
//
// The floor is a deliberate hole in the assurance requirement, opened for one
// account state. A hole that can be declared wrongly and still start is worse
// than the deadlock it removes, because the deadlock is loud — nobody activates
// — and a misdeclared exemption is silent. So each shape below is refused rather
// than interpreted, and each of them resolves in the dangerous direction if it
// is not:
//
//   - Declared as UNSPECIFIED. The author wrote the option, so they meant
//     something, and the only reading available is the zero one — which every
//     session satisfies, including a session carrying no assurance level at all.
//     Refused rather than read as "no exemption", because the two readings are
//     indistinguishable in the descriptor and only one of them is safe.
//   - Not below min_aal. An exemption that does not relax anything is either a
//     mistake or a raise wearing the wrong name, and a reviewer scanning for
//     which methods are relaxed would be misled by both. Note that this also
//     forces min_aal to be declared: with it unset the effective floor is AAL1
//     and nothing is strictly below AAL1 except UNSPECIFIED, already refused.
//   - Not self-scoped. The condition is a fact about the CALLER'S OWN account,
//     and only a self-scoped method acts on that account. On an org-scoped
//     method the exemption would lower the floor for work done on somebody
//     else's resource, keyed off a property of the caller's account that has
//     nothing to do with it.
//   - Public. There is no session, so there is no account to be in a bootstrap
//     state and no assurance level to lower. read() has already refused a public
//     method that declares min_aal; this is the same refusal for the same
//     reason, and it is stated separately so the message names the right option.
func checkBootstrap(p Policy) error {
	if !p.BootstrapExempt() {
		return nil
	}
	switch {
	case p.Public:
		return fmt.Errorf("%s: is public but declares a bootstrap assurance floor; an "+
			"unauthenticated caller has no account, so there is no enrolment state to "+
			"relax for", p.Method)
	case p.BootstrapMinAAL >= p.RequiredAAL():
		return fmt.Errorf("%s: declares a bootstrap floor of %v that is not strictly below its "+
			"required %v; a bootstrap floor exempts a first enrolment from a level it could "+
			"not otherwise reach, and one that relaxes nothing reads as an exemption while "+
			"granting none", p.Method, p.BootstrapMinAAL, p.RequiredAAL())
	case !p.SelfScoped():
		return fmt.Errorf("%s: declares a bootstrap floor but is not scoped to the caller's own "+
			"account (relation %q, type %q, field %q); the bootstrap condition is a fact about "+
			"the CALLER'S account, and lowering the floor for work on any other resource keys "+
			"the relaxation off something unrelated to it",
			p.Method, p.Relation, p.ResourceType, p.ResourceIDField)
	}
	return nil
}

// BootstrapExempt returns every method declaring a bootstrap assurance floor,
// sorted.
//
// Exported for the same reason as SelfScoped: this is the list of methods
// reachable below their declared assurance level, and it belongs in the startup
// log where an operator sees it, not only in the proto where a reviewer might.
func (s *Set) BootstrapExempt() []string {
	var out []string
	for m, p := range s.byMethod {
		if p.BootstrapExempt() {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
}

// SelfScoped returns every self-scoped method, sorted.
//
// Exported for the same reason as Gates.Missing: a declaration that turns off
// three gates should be visible in the startup log, as a list an operator can
// read, rather than discoverable only by reading the proto.
func (s *Set) SelfScoped() []string {
	var out []string
	for m, p := range s.byMethod {
		if p.SelfScoped() {
			out = append(out, m)
		}
	}
	sort.Strings(out)
	return out
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

	// Read through HasExtension rather than by comparing the value against zero.
	// A declared ASSURANCE_LEVEL_UNSPECIFIED and an absent option produce the
	// same value, and they are not the same statement: the first is an author
	// saying something incoherent, which checkBootstrap refuses by name, and the
	// second is the ordinary case of a method that has no exemption. Collapsing
	// them would turn the incoherent declaration into the safe default and lose
	// the error that says so.
	if proto.HasExtension(mo, optionsv1.E_BootstrapMinAal) {
		boot, _ := proto.GetExtension(mo, optionsv1.E_BootstrapMinAal).(optionsv1.AssuranceLevel)
		if boot == optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED {
			return Policy{}, fmt.Errorf("%s: declares a bootstrap assurance floor of "+
				"ASSURANCE_LEVEL_UNSPECIFIED; that is the zero value, which every session "+
				"satisfies including one carrying no assurance level at all. Omit the option "+
				"to mean no exemption", method)
		}
		p.BootstrapMinAAL = boot
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
		if err := checkBootstrap(p); err != nil {
			return Policy{}, err
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

	if err := checkSelfScope(p); err != nil {
		return Policy{}, err
	}
	// After checkSelfScope, because it asks whether the method is self-scoped and
	// a method with an incoherent self declaration has no honest answer to that.
	if err := checkBootstrap(p); err != nil {
		return Policy{}, err
	}

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
