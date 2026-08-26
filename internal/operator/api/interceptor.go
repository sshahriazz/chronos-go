// Package api serves the operator plane over ConnectRPC.
//
// The handlers are thin: every enforcement decision is made in the interceptor
// below, from the policy the method declares, before a handler runs. That is
// ADR-021's argument applied to the plane where it matters most — a per-handler
// check fails when somebody forgets one, and these are the endpoints that read
// every customer we have.
package api

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/netip"
	"strings"

	"connectrpc.com/connect"

	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/operator/policy"
	"github.com/chronos/chronos-go/internal/platform/clientip"
)

type actorKey struct{}
type digestKey struct{}

// ActorFrom returns the resolved operator, if the method had one.
func ActorFrom(ctx context.Context) (app.Actor, bool) {
	a, ok := ctx.Value(actorKey{}).(app.Actor)
	return a, ok
}

// DigestFrom returns the digest of the bearer the caller presented.
//
// Carried so SignOut and FinishWebAuthn can END the session they were called
// with, without the handler re-reading a header — a handler that parsed the
// bearer itself could end a DIFFERENT session from the one the interceptor
// authenticated.
func DigestFrom(ctx context.Context) ([]byte, bool) {
	d, ok := ctx.Value(digestKey{}).([]byte)
	return d, ok
}

// Guard is the operator plane's enforcement interceptor.
type Guard struct {
	catalogue policy.Catalogue
	sessions  app.Sessions
	clock     app.Clock
	resolver  clientip.Resolver
	allowed   []netip.Prefix
	log       *slog.Logger
}

// GuardConfig is what the interceptor needs.
type GuardConfig struct {
	Catalogue policy.Catalogue
	Sessions  app.Sessions
	Clock     app.Clock
	Resolver  clientip.Resolver

	// Allowed is the set of networks operator access is restricted to
	// (operator.md §3: "access is IP-restricted to internal ranges").
	//
	// EMPTY MEANS ALLOW EVERYTHING, and that is a deliberate development
	// affordance rather than an oversight — but the binary refuses to start
	// with an empty list unless OPERATOR_ALLOW_ANY_IP is explicitly set, so the
	// permissive case cannot be reached by forgetting to configure it.
	Allowed []netip.Prefix

	Log *slog.Logger
}

// NewGuard builds the interceptor.
func NewGuard(cfg GuardConfig) (*Guard, error) {
	switch {
	case len(cfg.Catalogue) == 0:
		return nil, errors.New("operator api: the guard needs a policy catalogue")
	case cfg.Sessions == nil:
		return nil, errors.New("operator api: the guard needs a session store")
	case cfg.Clock == nil:
		return nil, errors.New("operator api: the guard needs a clock")
	}
	log := cfg.Log
	if log == nil {
		log = slog.Default()
	}
	return &Guard{
		catalogue: cfg.Catalogue, sessions: cfg.Sessions, clock: cfg.Clock,
		resolver: cfg.Resolver, allowed: cfg.Allowed, log: log,
	}, nil
}

// WrapUnary is the interceptor.
func (g *Guard) WrapUnary(next connect.UnaryFunc) connect.UnaryFunc {
	return func(ctx context.Context, req connect.AnyRequest) (connect.AnyResponse, error) {
		method := req.Spec().Procedure

		p, ok := g.catalogue[method]
		if !ok {
			// UNREACHABLE if the server started, because the loader walks the
			// same descriptors this server registers and refuses to start on a
			// gap. Kept because "unreachable" is a claim about today's wiring:
			// a method served by a handler the catalogue never saw must be
			// refused, not served without a policy.
			g.log.ErrorContext(ctx, "an operator method has no policy and was refused",
				"method", method)
			return nil, connect.NewError(connect.CodePermissionDenied,
				errors.New("this method declares no enforcement policy"))
		}

		// Address, NOT Scope. Scope returns a rate-limit BUCKET KEY, and for
		// IPv6 that key is a /64 prefix — so parsing it as an address works
		// over IPv4 and refuses every IPv6 connection, which is exactly the bug
		// this line shipped with and which denied every loopback request.
		addr, ok := g.resolver.Address(req.Peer().Addr, req.Header().Values("X-Forwarded-For"))
		if err := g.allow(addr, ok); err != nil {
			g.log.WarnContext(ctx, "an operator request came from outside the permitted networks",
				"method", method, "from_ip", addr.String(), "resolved", ok)
			return nil, connect.NewError(connect.CodePermissionDenied, err)
		}
		peer := ""
		if ok {
			peer = addr.String()
		}

		if p.Access == policy.AccessUnauthenticated {
			return next(ctx, req)
		}

		token := bearer(req.Header().Get("Authorization"))
		if token == "" {
			return nil, connect.NewError(connect.CodeUnauthenticated,
				errors.New("this method needs an operator session"))
		}

		// The digest DOMAIN is chosen from the declared access, not from the
		// token. A pending bearer and a live bearer are both 43 base64
		// characters and are indistinguishable by inspection; separating them by
		// domain means a pending token presented to an ordinary method hashes to
		// something no row holds, rather than being resolved and then rejected
		// by a stage comparison somebody could forget to write.
		var digest []byte
		if p.Access == policy.AccessSSOOnly {
			digest = app.PendingDigest(token)
		} else {
			digest = app.SessionDigest(token)
		}

		sess, err := g.sessions.Resolve(ctx, digest, g.clock.Now())
		if err != nil {
			// One answer for absent, expired, ended, and belonging to a
			// disabled operator. Distinguishing them would tell whoever holds a
			// dead token why it is dead.
			return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
		}

		wantStage := app.StageLive
		if p.Access == policy.AccessSSOOnly {
			wantStage = app.StageSSOOnly
		}
		if sess.Stage != wantStage {
			// Belt and braces with the domain separation above: this is
			// unreachable while the two domains differ, and it is the check
			// that still holds if somebody ever unifies them.
			g.log.ErrorContext(ctx, "an operator session was presented at the wrong stage",
				"method", method, "want", wantStage, "got", sess.Stage)
			return nil, connect.NewError(connect.CodeUnauthenticated, app.ErrSessionRefused)
		}

		actor := app.Actor{
			OperatorID: sess.OperatorID,
			SubjectID:  sess.SubjectID,
			Role:       sess.Role,
			SessionID:  sess.SessionID,
			FromIP:     peer,
		}

		if p.Access == policy.AccessCapability {
			if !domain.Permits(sess.Role, p.Capability) {
				g.log.InfoContext(ctx, "an operator was refused a capability their role does not hold",
					"method", method, "operator_id", sess.OperatorID,
					"role", sess.Role, "capability", p.Capability)
				return nil, connect.NewError(connect.CodePermissionDenied, app.ErrForbidden)
			}
		}

		ctx = context.WithValue(ctx, actorKey{}, actor)
		ctx = context.WithValue(ctx, digestKey{}, digest)
		return next(ctx, req)
	}
}

// WrapStreamingClient and WrapStreamingHandler complete the interceptor
// interface.
//
// The handler side REFUSES every stream rather than passing it through. The
// operator service declares no streaming method, so a stream reaching here means
// one was added without being considered against this guard — and the unary
// path above is the only one that resolves a session.
func (g *Guard) WrapStreamingClient(next connect.StreamingClientFunc) connect.StreamingClientFunc {
	return next
}

// WrapStreamingHandler refuses streams outright.
func (g *Guard) WrapStreamingHandler(_ connect.StreamingHandlerFunc) connect.StreamingHandlerFunc {
	return func(ctx context.Context, conn connect.StreamingHandlerConn) error {
		return connect.NewError(connect.CodeUnimplemented,
			errors.New("the operator plane serves no streaming methods"))
	}
}

var _ connect.Interceptor = (*Guard)(nil)

// allow enforces the internal-network restriction.
//
// An unresolvable origin is REFUSED, unlike in the audit path where it becomes
// NULL. The two treat it differently on purpose: there the address is evidence
// and losing it must not stop the record; here it is the input to an access
// decision, and a decision that cannot be made must fail closed.
//
// The refusal only applies when a restriction is CONFIGURED. With no permitted
// networks the plane is deliberately open — which the binary refuses to start
// in unless OPERATOR_ALLOW_ANY_IP says so — and refusing an in-process or
// unix-socket caller there would break a deployment that had asked for exactly
// this.
func (g *Guard) allow(addr netip.Addr, resolved bool) error {
	if len(g.allowed) == 0 {
		return nil
	}
	if !resolved {
		return fmt.Errorf("this request's origin could not be established")
	}
	for _, p := range g.allowed {
		if p.Contains(addr) {
			return nil
		}
	}
	return fmt.Errorf("the operator plane is not reachable from this network")
}

// bearer extracts the token from an Authorization header.
func bearer(header string) string {
	const prefix = "Bearer "
	if len(header) <= len(prefix) || !strings.EqualFold(header[:len(prefix)], prefix) {
		return ""
	}
	return strings.TrimSpace(header[len(prefix):])
}

// MethodName renders a policy's method for an audit entry.
//
// The audit's `method` column holds the full RPC name, which is what
// req.Spec().Procedure already is — this exists so a handler names the method
// once, from the same source the policy was looked up by, rather than repeating
// a string literal that can drift.
func MethodName(req connect.AnyRequest) string { return req.Spec().Procedure }
