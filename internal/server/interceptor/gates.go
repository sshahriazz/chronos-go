// Package interceptor is ADR-021's enforcement pipeline.
//
// Four enforcement systems converge on every request, in one fixed order, and no
// gate may ever be implemented inside a handler:
//
//	recovery → telemetry → request-id → authn ──► Principal + AuthContext
//	   ├─ 1. org-context   resolve org (+ workspace)
//	   ├─ 2. authz         FAIL CLOSED
//	   ├─ 3. subscription  org lifecycle vs operation class
//	   ├─ 4. entitlement   purchased? quota available?
//	   ├─ 5. idempotency
//	   └──► handler ──► repository ──► 6. RLS (database backstop, always on)
//
// The property this package exists to guarantee is narrower than "the gates
// run": it is that a gate which is DECLARED but has no implementation refuses the
// request. A missing gate that silently passes is worse than no pipeline at all,
// because the schema says the endpoint is guarded and nothing contradicts it.
package interceptor

import (
	"context"
	"errors"
	"fmt"
	"reflect"

	"connectrpc.com/connect"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/policy"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// Principal is who is making the request, as the authn gate resolved them.
//
// Kept minimal on purpose: everything a later gate needs is here, and nothing
// else, so a gate cannot reach into a session object and grow a dependency on
// the identity module.
type Principal struct {
	Subject authz.Principal
	Context authz.AuthContext

	// AAL is the assurance level this session actually reached.
	AAL optionsv1.AssuranceLevel

	// Enrolment is what the caller's ACCOUNT has: whether it has ever held a
	// proven second factor. It is what a bootstrap assurance floor is relaxed
	// against (policy.Enrolment).
	//
	// It belongs on the principal rather than being looked up here for the same
	// reason AAL does: it is a property of who is calling, resolved once by the
	// authenticator from the session's own account, and a gate that went and read
	// it itself would be a second source of the answer that could disagree with
	// the first. The zero value is policy.EnrolmentUnknown, which relaxes
	// nothing — so an authenticator that does not set it produces the strict
	// floor, and every existing Principal literal keeps the behaviour it had.
	Enrolment policy.Enrolment

	// RequiresCredentialRotation marks a session established with a credential
	// the system has decided must be replaced — a password found in a breach
	// corpus. identity.md §3 restricts such a session to profile and credential
	// endpoints, and enforce applies that restriction: it is a property of the
	// session, so it is enforced where the session is read, not in nine handlers.
	RequiresCredentialRotation bool

	// BoundOrg is the organization a MACHINE CREDENTIAL is tied to, chosen when
	// it was minted and immutable afterwards (identity.md §10, review D2). Empty
	// for a session.
	//
	// The difference from `Context.ActiveOrg` on a session is who chose it. A
	// session is not scoped to an organization — a person belongs to several —
	// so gate 1 reads a header and VERIFIES membership. A key names exactly one
	// organization and the caller did not pick it, so gate 1 has nothing to
	// choose and everything to enforce: a header naming a different organization
	// is refused rather than resolved.
	//
	// Without this the binding would exist only in the database and nowhere in
	// the request pipeline, and a key leaked from one customer's CI would reach
	// another customer's data through an ordinary header — which is the
	// cross-tenant breach identity.md §10 exists to close.
	BoundOrg string

	// Scopes is the coarse capability list a machine credential carries. Empty
	// for a session, and empty for a key is a DENIAL rather than "no
	// restriction": scopeSatisfied answers false for an empty list.
	//
	// The asymmetry is deliberate. A session is a person acting as themselves,
	// so there is nothing to narrow and the graph is the whole answer. A key is
	// a credential somebody handed to a program, and access.md §4 defines its
	// permission as the INTERSECTION of its scopes and its owner's access — so
	// the scopes have to be enforced somewhere in the pipeline, and a rule of
	// the form "every handler remembers to check" is forgotten exactly once and
	// then permanently.
	Scopes []string
}

// Machine reports whether this request arrived on a non-human credential.
//
// Read off the principal's KIND rather than off a "is a key" boolean, which is
// the distinction ids.ServiceAccount's own comment makes: a boolean that grants
// something is exactly the field an injection bug sets, and its inverse — a
// boolean that RESTRICTS — is exactly the field an injection bug clears. A kind
// that must be one of an enumerated set, whose id must then parse under that
// kind's prefix, cannot be cleared into "human" by a single wrong byte.
//
// The zero Principal is a machine by this predicate, because its kind is the
// empty string rather than KindUser. That is the safe direction: a Principal a
// test double or a half-built authenticator produced faces the stricter rules,
// not the looser ones.
func (p Principal) Machine() bool { return p.Subject.Kind != authz.KindUser }

// Authenticator resolves the caller. Implemented by the identity module.
type Authenticator interface {
	// Authenticate reads whatever the transport carries and returns the caller.
	// An error denies; there is no anonymous fallback, because a public method
	// never reaches this gate at all.
	Authenticate(ctx context.Context, header Header) (Principal, error)
}

// Header is the subset of request metadata a gate may read. An interface rather
// than http.Header so a gate cannot start reading the body.
type Header interface {
	Get(key string) string
}

// OrgResolver is gate 1: which organization (and workspace) is this request in.
type OrgResolver interface {
	Resolve(ctx context.Context, p Principal, header Header) (context.Context, error)
}

// Subscriptions is gate 3: does the org's lifecycle state permit this operation
// class.
type Subscriptions interface {
	Permit(ctx context.Context, class optionsv1.OperationClass) error
}

// Entitlements is gate 4: is the feature purchased and is quota available.
//
// # The three return values are the reservation protocol
//
// entitlement.md §4 is check -> reserve -> commit/release, and a plain
// check-then-act is a race: two admins inviting the last seat both read
// `49 < 50` and both proceed.
//
// The CONTEXT carries the reservation forward, so the handler that consumes the
// quota can COMMIT it. Without that the handler cannot name what it was granted,
// and the only options left are counting usage from a projection — which lags
// the log, reopening the exact window a reservation exists to close — or never
// committing at all.
//
// The FUNC releases. WrapUnary defers it unconditionally, which is deliberate
// and is why an implementation must make it a no-op once committed: a
// reservation the handler used must survive, and one it did not must not leak
// until its TTL.
type Entitlements interface {
	Reserve(ctx context.Context, key string) (context.Context, func(), error)
}

// Gate names one rung of the pipeline, for errors that say which is missing.
type Gate string

const (
	GateAuthn        Gate = "authn"
	GateOrgContext   Gate = "org-context"
	GateAuthz        Gate = "authz"
	GateSubscription Gate = "subscription"
	GateEntitlement  Gate = "entitlement"
	GateIdempotency  Gate = "idempotency"
)

// ErrGateUnavailable is a gate a method needs, with no implementation wired.
//
// It is an ERROR rather than a skip. The alternative — treating an unwired gate
// as satisfied — means deleting an implementation silently opens every endpoint
// that relied on it, and the tests keep passing because nothing asserts on a
// gate that no longer exists.
var ErrGateUnavailable = errors.New("interceptor: gate not implemented")

// Deps is what the pipeline enforces with. Every field is optional to CONSTRUCT
// and required to USE: a method whose policy needs a gate that is nil is
// refused, so a partially-built server serves exactly the endpoints it can
// actually guard.
type Deps struct {
	Policies *policy.Set

	Authn         Authenticator
	Org           OrgResolver
	Authz         *authz.Guard
	Subscriptions Subscriptions
	Entitlements  Entitlements
	Idempotency   *Idempotency
}

// Gates is the interceptor.
type Gates struct{ deps Deps }

// NewGates builds the pipeline.
//
// Only the policy set is required. Everything else may legitimately be absent
// while a module is unbuilt — and the consequence of absence is that the methods
// needing it are refused, which is visible in the first request rather than in a
// breach.
func NewGates(d Deps) (*Gates, error) {
	if d.Policies == nil {
		return nil, fmt.Errorf("interceptor: a policy set is required; without one no method " +
			"has a declared policy and every request would have to be denied")
	}
	for name, gate := range map[Gate]any{
		GateAuthn: d.Authn, GateOrgContext: d.Org,
		GateSubscription: d.Subscriptions, GateEntitlement: d.Entitlements,
	} {
		if err := refuseTypedNil(name, gate); err != nil {
			return nil, err
		}
	}
	return &Gates{deps: d}, nil
}

// refuseTypedNil rejects an interface holding a nil pointer.
//
// `Deps.Authn` is an interface, so a nil *something assigned to it is NOT ==
// nil — the type descriptor is set. Every `if g.deps.Authn == nil` check would
// pass, the pipeline would call through, and the request would PANIC rather than
// be refused. That turns a half-wired server from "denies what it cannot guard"
// into a crash loop, which is the one outcome the fail-closed design is supposed
// to make impossible.
//
// Caught at construction because it is a wiring bug, and a wiring bug found at
// startup costs a failed deploy instead of an incident.
func refuseTypedNil(name Gate, gate any) error {
	if gate == nil {
		return nil // genuinely absent, which is allowed
	}
	v := reflect.ValueOf(gate)
	switch v.Kind() {
	case reflect.Pointer, reflect.Map, reflect.Slice, reflect.Func, reflect.Interface, reflect.Chan:
		if v.IsNil() {
			return fmt.Errorf("interceptor: the %s gate holds a typed nil (%T); it would not "+
				"compare equal to nil, so the pipeline would call it and panic instead of "+
				"refusing the request", name, gate)
		}
	}
	return nil
}

// Missing reports which declared gates have no implementation.
//
// Exported so the composition root can LOG the list at startup, rather than
// leaving an operator to discover it as a wall of denials. A server that refuses
// half its API should say so on the way up.
func (g *Gates) Missing() []Gate {
	var out []Gate
	if g.deps.Authn == nil {
		out = append(out, GateAuthn)
	}
	if g.deps.Org == nil {
		out = append(out, GateOrgContext)
	}
	if g.deps.Authz == nil {
		out = append(out, GateAuthz)
	}
	if g.deps.Subscriptions == nil {
		out = append(out, GateSubscription)
	}
	if g.deps.Entitlements == nil {
		out = append(out, GateEntitlement)
	}
	if g.deps.Idempotency == nil {
		out = append(out, GateIdempotency)
	}
	return out
}

// Blocking is the subset of Missing that actually refuses traffic.
//
// # Why this is not the same question as Missing
//
// Missing answers "which gates have no implementation", which is a fact about
// WIRING. Blocking answers "which of those does some method actually reach",
// which is a fact about this POLICY SET, and only the second one describes an
// outage.
//
// The distinction had teeth. cmd/api logged Missing() at ERROR with the text
// "gates are declared by some methods and implemented by none; those methods
// will be refused for the lifetime of this process" — and on this build that was
// false in both halves. Every authorization declaration in the tree is `self` on
// `user`, and enforce returns at `if p.SelfScoped()` BEFORE it reaches the
// org-context gate, so org-context, authz and subscription are unreachable. No
// method declares an entitlement at all, so gate 4 is unreachable twice over.
// Nothing was refused, and the server nonetheless reported an ERROR on every
// boot for the lifetime of the process.
//
// A permanent ERROR that names no real consequence is worse than silence: it is
// the line an operator learns to scroll past, and the next one will be real.
//
// Absent modules are still worth saying out loud — that is what Missing is for,
// at a level that matches "a module is unbuilt" rather than "the API is down".
func (g *Gates) Blocking() []Gate {
	unwired := map[Gate]bool{}
	for _, gate := range g.Missing() {
		unwired[gate] = true
	}
	if len(unwired) == 0 || g.deps.Policies == nil {
		return nil
	}

	reached := map[Gate]bool{}
	for _, method := range g.deps.Policies.Methods() {
		p, ok := g.deps.Policies.Lookup(method)
		if !ok {
			continue
		}
		for _, gate := range requiredGates(p) {
			if unwired[gate] {
				reached[gate] = true
			}
		}
	}

	// Returned in pipeline order rather than map order, so the first name in the
	// list is the first gate a request would hit.
	var out []Gate
	for _, gate := range []Gate{
		GateAuthn, GateOrgContext, GateAuthz,
		GateSubscription, GateEntitlement, GateIdempotency,
	} {
		if reached[gate] {
			out = append(out, gate)
		}
	}
	return out
}

// requiredGates is which gates a single method reaches.
//
// It MIRRORS the early returns in enforce and WrapUnary, and the mirroring is
// the risk: two descriptions of one control flow can drift, and a stale copy
// here would under-report an outage. TestRequiredGatesAgreesWithEnforce drives
// every shape through the real pipeline with exactly one gate nil and requires
// the two to agree, so the copy cannot rot silently.
func requiredGates(p policy.Policy) []Gate {
	// A public method returns at the top of WrapUnary: no authn, no gates.
	if p.Public {
		return nil
	}

	out := []Gate{GateAuthn}
	if p.Mutating() {
		out = append(out, GateIdempotency)
	}
	// Self-scoped stops at selfCheck, which is answered locally from the
	// principal. It never reaches the organization, the graph or the plan.
	if p.SelfScoped() {
		return out
	}
	out = append(out, GateOrgContext, GateAuthz, GateSubscription)
	if p.Entitlement != "" {
		out = append(out, GateEntitlement)
	}
	return out
}

// WrapUnary returns the ConnectRPC interceptor.
func (g *Gates) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		method := req.Spec().Procedure

		p, ok := g.deps.Policies.Lookup(method)
		if !ok {
			// The router and the policy set disagree. The safe reading is "this
			// method was never checked", and it is NOT_FOUND rather than
			// INTERNAL because the caller has passed no gate and is entitled to
			// learn nothing (ADR-036).
			return nil, srvconnect.Error(errs.NotFoundf("no such method"))
		}

		if p.Public {
			// No authn, no gates. The policy loader has already refused any
			// public method that also declares authz, an entitlement or an
			// assurance level, so "public" here means exactly one thing.
			//
			// A public MUTATION still requires an Idempotency-Key, and this is the
			// only place that can require it: gate 5 runs after authentication and
			// is never reached from here. Two reasons, and the second is the one
			// that made this a defect rather than a nicety.
			//
			// Register, VerifyEmail, ResetPassword, Authenticate and CreateSession
			// are the calls a person retries on a flaky connection, and without a
			// key a retry is a fresh command rather than a repeat of one.
			//
			// And the key is the CAUSATION id of every event the command writes
			// (see withCausation). These commands are roots — nothing above them
			// in the log — so without a key their events are appended with an
			// empty causation and, when tracing is off, an empty correlation too.
			// A log is append-only: an id not written at append time can never be
			// added, so "the public writes have no chain" would have been
			// permanent for every event already stored.
			//
			// What it does NOT do is claim the key in the store. There is no
			// principal, so there is no scope to claim under — and an anonymous
			// shared scope would hand one caller another's stored response, which
			// is the cross-caller read cqrs.Scope.Validate refuses an empty
			// principal to prevent. So: required, bounded, used as identity, never
			// stored. proto/openapi.base.yaml publishes exactly that.
			// identity/api/service.go's idempotencyKey() also refuses an empty
			// header, and it is left in place as a backstop for a caller that
			// reaches a handler another way. It is not sufficient on its own: it
			// lives in ONE module, so a public mutation added anywhere else would
			// be unguarded until somebody remembered; it refuses only the EMPTY
			// case, so a 4KB key reached the log; and it cannot attach causation,
			// because by then the context is already the handler's.
			//
			// The two messages below are the ones Idempotency.Do produces on the
			// authenticated path, deliberately word for word: a client that omits
			// the header should not be able to tell which branch refused it.
			if p.Mutating() {
				key := req.Header().Get(IdempotencyHeader)
				if key == "" {
					return nil, srvconnect.Error(errs.ValidationFailedf(
						"%s is required on every mutating request", IdempotencyHeader))
				}
				if err := cqrs.Key(key).Validate(); err != nil {
					return nil, srvconnect.Error(errs.ValidationFailedf("%s", err))
				}
				ctx = withCausation(ctx, key)
			}
			return next(ctx, req)
		}

		// Checked BEFORE enforce, and before the handler runs. A nil
		// *Idempotency is not a skip: Do would execute on a nil receiver, return
		// straight through for a read, and panic on `i.once` for a write — so
		// the gate would appear to work right up until the first mutation, then
		// crash instead of refusing. Refusing is this package's whole contract.
		if p.Mutating() && g.deps.Idempotency == nil {
			return nil, unavailable(GateIdempotency, p)
		}

		ctx, release, err := g.enforce(ctx, p, req.Header(), req.Any())
		if err != nil {
			return nil, err
		}
		if release != nil {
			defer release()
		}

		if g.deps.Idempotency == nil {
			// A read, with no gate wired. Nothing to claim and nothing to store.
			return next(ctx, req)
		}
		return g.deps.Idempotency.Do(ctx, p, req, func(ctx context.Context) (connect.AnyResponse, error) {
			return next(ctx, req)
		})
	}
}

// enforce runs gates 1 through 4 in ADR-021's order.
//
// The order is load-bearing and is not a style choice:
//
//   - authz BEFORE subscription, so a non-member learns nothing about an org —
//     not even that its payment is overdue. Existence and billing state are both
//     privileged.
//   - subscription BEFORE entitlement, because a suspended org's quota is
//     irrelevant, and checking it would leak plan details and waste a
//     reservation.
//   - entitlement LAST, immediately before the handler, so a reservation is
//     never taken for a request a later gate would reject.
func (g *Gates) enforce(
	ctx context.Context, p policy.Policy, header Header, msg any,
) (context.Context, func(), error) {
	if g.deps.Authn == nil {
		return ctx, nil, unavailable(GateAuthn, p)
	}
	principal, err := g.deps.Authn.Authenticate(ctx, header)
	if errors.Is(err, ErrAuthenticationUnavailable) {
		// "Could not tell" is not "bad credential". Reporting an outage as
		// UNAUTHENTICATED makes every client in the fleet sign its user out during
		// a database blip, and they then all re-authenticate against the database
		// that is already struggling. The request is refused either way — ADR-010's
		// resilience governs what the caller is told, never whether an
		// unauthenticated request proceeds.
		return ctx, nil, srvconnect.Error(errs.Internalf("authentication is unavailable").Wrap(err))
	}
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.Unauthenticatedf("authentication failed"))
	}

	// Step-up is checked here, not in the authz gate, because it is a property
	// of the SESSION rather than of the graph. Comparing against a resolved floor
	// and not against the raw option matters: the option's zero value is
	// UNSPECIFIED, and comparing a session against that is satisfied by
	// anything.
	//
	// AALFloor is that floor, and it differs from RequiredAAL for exactly one
	// combination: a method that declared a bootstrap exemption, called by an
	// account the AUTHENTICATOR reports has never held a proven second factor.
	// That combination is how an account gets its first factor at all — AAL2
	// means a second factor was presented, so demanding it of an account that has
	// none is a requirement nothing can satisfy, and the account can never
	// activate (identity.md §2).
	//
	// The enrolment state is read from the principal and from nowhere else. It is
	// not in the request, not in a header, and not in a context value a handler
	// could have written — the same argument that makes selfCheck's subject
	// safe. So a caller cannot claim to be bootstrapping, and an account that
	// HAS a factor faces the strict floor no matter what it sends.
	if principal.AAL < p.AALFloor(principal.Enrolment) {
		return ctx, nil, srvconnect.Error(errs.StepUpRequiredf(
			"this action requires a stronger authentication level"))
	}

	// A session flagged for credential rotation is restricted to the caller's own
	// account (identity.md §3): the password behind it is known to an attacker,
	// so what it may still do is exactly the work of replacing that password and
	// inspecting the damage. Enforced HERE because it is a property of the
	// SESSION — the same argument that puts the AAL comparison here rather than in
	// the authz gate — and because a rule of the form "every handler remembers to
	// check the flag" is forgotten exactly once and then permanently.
	//
	// Self-scoped is the closest available spelling of "profile and credential
	// endpoints". It is deliberately coarse in the SAFE direction: it admits only
	// the caller's own account, so a method wrongly refused is an inconvenience
	// and a method wrongly admitted is impossible.
	if principal.RequiresCredentialRotation && !p.SelfScoped() {
		return ctx, nil, srvconnect.Error(errs.AccessDeniedf(
			"this session must replace the credential it was established with before it can " +
				"be used for anything else"))
	}

	// A machine credential faces two rules a session does not, and both are here
	// for the reason the two above are: they are properties of the CREDENTIAL,
	// and a rule of the form "every handler remembers to check" is forgotten
	// exactly once and then permanently.
	if err := machineCredentialCheck(p, principal); err != nil {
		return ctx, nil, err
	}

	// Attached here, once, and never again. Every later gate and the handler read
	// the caller from the context rather than being passed it, so there is one
	// answer to "who is this" for the whole request — and the idempotency scope,
	// which depends on the principal to stay tenant-isolated, cannot be built
	// from anything a client sent.
	ctx = withPrincipal(ctx, principal)

	if p.SelfScoped() {
		return ctx, nil, selfCheck(p, principal)
	}

	if g.deps.Org == nil {
		return ctx, nil, unavailable(GateOrgContext, p)
	}
	ctx, err = g.deps.Org.Resolve(ctx, principal, header)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.NotFoundf("not found"))
	}

	if g.deps.Authz == nil {
		return ctx, nil, unavailable(GateAuthz, p)
	}
	// The organization gate 1 just resolved, read from the scope every later
	// query uses rather than from a second copy that could disagree with it.
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.Internalf(
			"gate 1 resolved no tenant scope, so gate 2 has no object to check").Wrap(err))
	}
	resourceID, err := resourceIDFor(p, tenant.OrgID, msg)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.NotFoundf("not found"))
	}
	decision := g.deps.Authz.Check(ctx, authz.Query{
		// Acting(), not Subject. For a session the two are the same value. For a
		// machine credential the subject is the KEY — which is what the audit
		// trail and every log line should see — and the object the graph holds a
		// tuple for is its OWNER, because a key's authority is defined as its
		// owner's narrowed by its scopes (access.md §4) rather than as a second
		// set of grants that could drift from the owner's.
		//
		// The narrowing has already happened: machineCredentialCheck refused the
		// request above unless the key carries the scope this method needs. So
		// what reaches OpenFGA is the second half of the intersection, and the
		// two halves are enforced by different code at different points, neither
		// of which can be satisfied by the other.
		Principal: principal.Subject.Acting(),
		Relation:  p.Relation,
		Resource:  authz.ResourceRef{Type: p.ResourceType, ID: resourceID},
		Context:   principal.Context,
	})
	if !decision.Allowed() {
		// NOT_FOUND, not ACCESS_DENIED. The disclosure ladder's parent-visibility
		// check (ADR-036 §5.1) decides between them, and it is not implemented
		// yet — so the rung that discloses LESS is the one to sit on. Upgrading
		// a NOT_FOUND to ACCESS_DENIED later is a feature; downgrading the other
		// way is a disclosure that already happened.
		return ctx, nil, srvconnect.Error(errs.NotFoundf("not found"))
	}

	if g.deps.Subscriptions == nil {
		return ctx, nil, unavailable(GateSubscription, p)
	}
	if err := g.deps.Subscriptions.Permit(ctx, p.Operation); err != nil {
		return ctx, nil, srvconnect.Error(errs.OrgSuspendedf("%s", err))
	}

	if p.Entitlement == "" {
		return ctx, nil, nil
	}
	if g.deps.Entitlements == nil {
		return ctx, nil, unavailable(GateEntitlement, p)
	}
	ctx, release, err := g.deps.Entitlements.Reserve(ctx, p.Entitlement)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.QuotaExceededf("%s", err))
	}
	return ctx, release, nil
}

// selfCheck answers the authz gate for a method scoped to the caller's own
// account.
//
// Identity is not organization-scoped: a person exists before any organization
// does. Gates 1 and 3 are both questions ABOUT an organization — which one is
// this request in, and does its lifecycle permit this operation class — so for a
// self-scoped method there is nothing for them to resolve and nothing to
// consult. An organization whose payment lapsed must not be able to stop
// somebody signing out of a stolen device.
//
// Gate 2 is answered here rather than skipped. The question is "may this
// principal act on user:<principal>", and the answer follows from the principal
// alone; asking OpenFGA would add a round trip that can fail, to confirm
// something the session already established. Note what that does NOT weaken: the
// caller still had to authenticate, and still had to reach the declared
// assurance level, before this line runs.
//
// The resource is taken from principal.Subject.ID and from nowhere else. It is
// not read from the request, not read from a header, and not read from a context
// value any package could have written — withPrincipal is unexported and called
// once, by the line above. So a caller cannot aim this check at another
// subject's account: the id substituted is the one their own session carries.
//
// The empty-subject guard is unreachable through SessionAuthenticator, which
// refuses a row whose subject does not parse. It is kept because the interface
// admits any implementation, and an empty subject would turn "act on your own
// account" into "act on the account named by the empty string" — one row, shared
// by everyone who authenticated badly.
func selfCheck(p policy.Policy, principal Principal) error {
	if principal.Subject.ID == "" {
		return srvconnect.Error(errs.Internalf(
			"%s is self-scoped but the authenticated principal carries no subject; refusing "+
				"rather than checking a relation against an empty resource", p.Method))
	}
	return nil
}

// machineCredentialCheck applies the two rules that exist only for a non-human
// caller.
//
// # 1. A machine may not touch a person's own account
//
// Every self-scoped method in this system is one of a person's account screens:
// their password, their sessions, their second factors, their deactivation. A
// machine credential acting on one would be acting on the account of whoever
// owns the key — so a personal access token minted for "read the workspace
// list" could change the password of the person who minted it, and an
// integration key could sign them out of every device.
//
// Refused HERE rather than in each handler. `identity/api.callerSubject` already
// refuses a non-user principal, and that is a real backstop, but it lives in ONE
// module: a self-scoped method added anywhere else would be unguarded until
// somebody remembered. This is the same argument the public-mutation idempotency
// check makes about its own backstop.
//
// ACCESS_DENIED and not NOT_FOUND, unlike the authz gate below. The caller
// learns nothing about any resource — the answer depends only on what kind of
// credential they presented, which they already know — and a NOT_FOUND here
// would send an integrator hunting for a missing endpoint that is in the
// document and works perfectly with a session.
//
// # 2. A machine may reach only what its scopes cover
//
// access.md §4 defines a key's permission as the INTERSECTION of its scopes and
// its owner's access. The owner's half is gate 2. This is the other half, and it
// runs FIRST — before the graph is consulted — so a key that could never reach
// the method costs no OpenFGA round trip and leaks nothing about the object.
//
// The required scope is DERIVED from the method's own declaration rather than
// annotated separately: `<resource_type>:<read|write>`, where write is anything
// the subscription gate treats as mutating. Deriving it means a new RPC cannot
// be added with a forgotten scope annotation — the failure of forgetting would
// be a method every key can reach — and it means the published authz policy and
// the scope requirement cannot disagree, because there is only one declaration.
//
// A method whose resource type is empty yields an empty required scope, and
// domain.APIKeyScopeSatisfied answers false for that. That is the safe reading:
// a method this function cannot characterise is one no machine credential
// reaches, and the alternative is admitting it.
func machineCredentialCheck(p policy.Policy, principal Principal) error {
	if !principal.Machine() {
		return nil
	}
	if p.SelfScoped() {
		return srvconnect.Error(errs.AccessDeniedf(
			"this endpoint acts on a person's own account, and a machine credential has none"))
	}
	if !domain.APIKeyScopeSatisfied(principal.Scopes, scopeFor(p)) {
		// The required scope IS named. It is not an oracle — it is a property of
		// the METHOD, published in the schema, identical for every caller — and
		// an integrator whose key is missing one has no other way to find out
		// which. Everything about the key itself stays unsaid.
		return srvconnect.Error(errs.AccessDeniedf(
			"this credential does not carry the %q scope", scopeFor(p)))
	}
	return nil
}

// scopeFor is the capability a method requires of a machine credential.
//
// Two levels and no more, because the vocabulary has to be derivable from what
// every RPC already declares. `Mutating()` is the same predicate gate 5 uses to
// decide whether an idempotency key is required and the same one the
// subscription gate's classes drive, so "write" here means exactly what "write"
// means everywhere else in the pipeline — there is no third definition to keep
// in step.
//
// A finer vocabulary is deliberately not available. Per-resource permission is
// OpenFGA's, and a scope grammar that grew an object id would be a second
// authorization model evaluated in Go, drifting from the first (CLAUDE.md:
// never evaluate permissions in Go).
func scopeFor(p policy.Policy) string {
	if p.ResourceType == "" {
		return ""
	}
	if p.Mutating() {
		return p.ResourceType + ":write"
	}
	return p.ResourceType + ":read"
}

// unavailable turns a missing gate into a refusal.
//
// INTERNAL, not NOT_FOUND: this is our misconfiguration, not the caller doing
// something wrong, and it must look like a fault an operator investigates rather
// than a resource that does not exist. The detail names the gate and the method
// so the log line is actionable; Disclose strips it from the response.
func unavailable(gate Gate, p policy.Policy) error {
	return srvconnect.Error(errs.Internalf(
		"%s gate is declared by %s but not implemented; refusing rather than skipping it",
		gate, p.Method))
}

// resourceIDFor resolves which resource the authz check is about.
//
// An empty ResourceIDField means the request is scoped to the org the
// org-context gate already resolved. Anything else must be read from the
// request, which is not implemented yet — and an unresolvable id is a REFUSAL,
// never a fallback to the org. Falling back would check a permission the schema
// did not ask for, and answer a different question than the one declared.
//
// A self-scoped method never reaches here: enforce takes the selfCheck branch
// above, where the resource is the principal's own subject. Both shapes below
// are org-scoped, which is why identity needed the third one.
// resourceIDFor decides WHICH object gate 2 asks about.
//
// # Why the organization comes from the resolved scope and not the principal
//
// It used to read `principal.Context.ActiveOrg`, and nothing ever set that
// field — so every org-scoped method failed with "no active organization", which
// the disclosure ladder turned into NOT_FOUND. That is indistinguishable from
// "you are not a member", and it stayed invisible for as long as no method was
// org-scoped.
//
// Gate 1 runs immediately before this and its entire job is to establish which
// organization the request is in. Reading its answer is both correct and the
// only version that cannot drift: a second copy on the principal would have to
// be kept in step with the scope every query already uses.
//
// # Reading it from the request
//
// A method that names a field is asking about an object the CALLER chose, and
// the whole point of the gate is that choosing it is not the same as being
// allowed to touch it. Reading the value is therefore all this does: it never
// falls back to the organization, because falling back would check a permission
// the schema did not ask for and answer a different question than the declared
// one — and it would answer it in the permissive direction, since org `admin`
// is inherited by every workspace through the `parent` edge.
//
// An absent, wrong-typed or empty field is a REFUSAL. The caller sees NOT_FOUND
// either way (ADR-036), so a missing id and a forbidden id are indistinguishable
// from outside, which is the property the ladder wants.
func resourceIDFor(p policy.Policy, orgID string, msg any) (string, error) {
	if p.ResourceIDField == "" {
		if orgID == "" {
			return "", fmt.Errorf("no organization in scope for an org-scoped method; gate 1 " +
				"resolved none")
		}
		return orgID, nil
	}

	message, ok := msg.(proto.Message)
	if !ok {
		return "", fmt.Errorf("%s reads its resource id from field %q, but its request is not "+
			"a protobuf message", p.Method, p.ResourceIDField)
	}

	reflected := message.ProtoReflect()
	field := reflected.Descriptor().Fields().ByName(protoreflect.Name(p.ResourceIDField))
	if field == nil {
		// A startup-time fault reaching request time. The policy loader cannot
		// catch it today — it reads method options, not message descriptors — so
		// this is where a renamed field surfaces.
		return "", fmt.Errorf("%s declares resource_id_field %q, which its request message "+
			"does not have", p.Method, p.ResourceIDField)
	}
	if field.Kind() != protoreflect.StringKind {
		return "", fmt.Errorf("%s declares resource_id_field %q, which is a %s and not a string",
			p.Method, p.ResourceIDField, field.Kind())
	}

	id := reflected.Get(field).String()
	if id == "" {
		// protovalidate runs AFTER the gates, so an empty id gets here. Refused
		// rather than passed on: an empty object id is a Check against
		// `workspace:`, which is a question about no object, and OpenFGA
		// answering it "no" would be right for the wrong reason.
		return "", fmt.Errorf("%s named no %s in field %q", p.Method, p.ResourceType,
			p.ResourceIDField)
	}
	return id, nil
}

// WrapStreamingClient is required by the interceptor interface. This server
// makes no outbound calls through it.
func (g *Gates) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler refuses every streaming method.
//
// Not a pass-through: the gates above are written for unary requests, and a
// streaming handler slipping past them would be ungated. When streaming methods
// arrive, this becomes a real implementation — until then the safe answer is no.
func (g *Gates) WrapStreamingHandler(next connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		p, ok := g.deps.Policies.Lookup(conn.Spec().Procedure)
		if ok && p.Public {
			return next(ctx, conn)
		}
		return srvconnect.Error(errs.Internalf(
			"streaming method %s is not gated; refusing rather than serving it ungated",
			conn.Spec().Procedure))
	}
}

var _ connect.Interceptor = (*Gates)(nil)
