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
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/policy"
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
}

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

// Entitlements is gate 4: is the feature purchased and is quota available. The
// returned func releases a reservation the handler did not end up using.
type Entitlements interface {
	Reserve(ctx context.Context, key string) (release func(), err error)
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

		ctx, release, err := g.enforce(ctx, p, req.Header())
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
	ctx context.Context, p policy.Policy, header Header,
) (context.Context, func(), error) {
	if g.deps.Authn == nil {
		return ctx, nil, unavailable(GateAuthn, p)
	}
	principal, err := g.deps.Authn.Authenticate(ctx, header)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.Unauthenticatedf("authentication failed"))
	}

	// Step-up is checked here, not in the authz gate, because it is a property
	// of the SESSION rather than of the graph. Comparing against RequiredAAL()
	// and not against the raw option matters: the option's zero value is
	// UNSPECIFIED, and comparing a session against that is satisfied by
	// anything.
	if principal.AAL < p.RequiredAAL() {
		return ctx, nil, srvconnect.Error(errs.StepUpRequiredf(
			"this action requires a stronger authentication level"))
	}

	// Attached here, once, and never again. Every later gate and the handler read
	// the caller from the context rather than being passed it, so there is one
	// answer to "who is this" for the whole request — and the idempotency scope,
	// which depends on the principal to stay tenant-isolated, cannot be built
	// from anything a client sent.
	ctx = withPrincipal(ctx, principal)

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
	resourceID, err := resourceIDFor(p, principal, header)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.NotFoundf("not found"))
	}
	decision := g.deps.Authz.Check(ctx, authz.Query{
		Principal: principal.Subject,
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
	release, err := g.deps.Entitlements.Reserve(ctx, p.Entitlement)
	if err != nil {
		return ctx, nil, srvconnect.Error(errs.QuotaExceededf("%s", err))
	}
	return ctx, release, nil
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
func resourceIDFor(p policy.Policy, principal Principal, _ Header) (string, error) {
	if p.ResourceIDField == "" {
		if principal.Context.ActiveOrg == "" {
			return "", fmt.Errorf("no active organization for an org-scoped method")
		}
		return principal.Context.ActiveOrg, nil
	}
	return "", fmt.Errorf("%w: %s reads its resource id from field %q, which is not "+
		"implemented", ErrGateUnavailable, p.Method, p.ResourceIDField)
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
