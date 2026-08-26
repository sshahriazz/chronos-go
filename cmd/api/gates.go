package main

import (
	"log/slog"

	"github.com/chronos/chronos-go/gen/proto/chronos/billing/v1/billingv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1/compliancev1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/notification/v1/notificationv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/organization/v1/organizationv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/profile/v1/profilev1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1/workspacev1connect"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
	"google.golang.org/protobuf/reflect/protoreflect"
)

// gatedServices is every service whose methods this binary enforces policy for.
//
// It is the SAME list main registers on the mux, and the duplication is the
// point: policy.Load refuses a service with an unannotated method, so adding a
// service here and forgetting it there costs a 404, while adding it to the mux
// and forgetting it here costs an endpoint that is served with no declared
// policy at all. The composition-root test asserts the two lists agree.
func gatedServices() []protoreflect.FullName {
	return []protoreflect.FullName{
		systemv1connect.SystemServiceName,
		identityv1connect.IdentityServiceName,
		notificationv1connect.NotificationServiceName,
		profilev1connect.ProfileServiceName,
		organizationv1connect.OrganizationServiceName,
		workspacev1connect.WorkspaceServiceName,
		billingv1connect.BillingServiceName,
		compliancev1connect.ComplianceServiceName,
	}
}

// startGates builds ADR-021's enforcement pipeline.
//
// Every gate here is optional to CONSTRUCT and required to USE: a method whose
// declared policy needs a gate that is nil is REFUSED, not waved through. That
// property lives in the interceptor; what lives here is making sure each gate
// that could be built was, and that anything that could not be says so.
//
// The policy set is the one hard requirement, and it is loaded over both
// services at once. An unannotated method is a refusal to build the pipeline —
// which means the server serves nothing gated rather than serving one endpoint
// nobody checks (ADR-021).
func (d *dependencies) startGates(log *slog.Logger) {
	// The authenticator resolves the bearer token every non-public RPC carries.
	// SYSTEM transaction, not tenant: this runs before any organization is known
	// — that is the next gate's job — and identity's tables carry no RLS, so
	// there is no scope to set and nothing to scope it by.
	if d.pool == nil {
		log.Error("no session authenticator: postgres is unreachable, so no bearer token " +
			"can be resolved and EVERY authenticated RPC will be refused")
	} else {
		// Now comes from the SAME clock identity writes its deadlines with.
		//
		// Left unset, SessionAuthenticatorDeps defaults it to time.Now — and this
		// process then ran two clocks: every idle and absolute deadline written by
		// identity came from d.clock, while the check that enforces them read the
		// wall clock. In production the two agree, so expiry works; the costs were
		// that session expiry could not be TESTED at all through ADR-054's movable
		// clock, that the two halves of a session's lifetime were kept on different
		// clocks, and that a session could report lastSeenAt earlier than its own
		// createdAt. Found by internal/adapter/protocolit.
		authn, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
			TX:  pgadapter.New(d.pool),
			Log: log,
			Now: d.clock.Now,
		})
		if err != nil {
			// NewSessionAuthenticator refuses only relationships between durations
			// that we control, so this is a wiring bug rather than an outage.
			log.Error("session authenticator not constructed; every authenticated RPC "+
				"will be refused", "error", err)
		} else {
			d.authn = composeAuthenticator(d, authn, log)
		}
	}

	// Gate 5. Nil when Postgres is unreachable, and the pipeline must REFUSE
	// mutations rather than wave them through — a gate skipped during an outage
	// is skipped exactly when clients are retrying hardest.
	if d.once == nil {
		log.Error("no idempotency gate: every mutating RPC will be refused rather than " +
			"executed twice")
	} else if gate, err := interceptor.NewIdempotency(d.once); err != nil {
		log.Error("idempotency gate not constructed", "error", err)
	} else {
		d.idempotencyGate = gate
	}

	policies, err := policy.Load(gatedServices()...)
	if err != nil {
		// Unannotated methods, almost always — which is a build-time mistake that
		// only shows up here, because the annotations are read from the descriptor
		// rather than from Go. Not fatal, per ADR-010, but total: with no policy
		// set there is no pipeline, and main registers no RPC service at all.
		log.Error("NO ENFORCEMENT POLICY COULD BE LOADED; no Connect service will be "+
			"registered, because serving a method whose gates are unknown is worse than "+
			"not serving it", "error", err)
		return
	}
	d.policies = policies

	gates, err := interceptor.NewGates(interceptor.Deps{
		Policies: policies,
		// Already an interface, and already nil when nothing could be built —
		// composeAuthenticator returns an untyped nil rather than a typed one, so
		// NewGates. refuseTypedNil has nothing to catch here and the gate is
		// correctly reported as missing.
		Authn: d.authn,
		Authz: d.authz,

		// Gate 4. Nil until entitlement is constructed, and the pipeline
		// refuses any method declaring an entitlement while it is — an unwired
		// gate is an error, not a skip.
		Org:           d.orgContext,
		Subscriptions: d.subscriptions,
		Entitlements:  d.entitlements,
		// Entitlements may still be nil, and a method declaring one is then refused
		// with ErrGateUnavailable — an unwired gate is an error, not a skip.
		//
		// Identity.s methods are no longer all public or self-scoped: the six
		// service-account and API key RPCs are org-scoped, so gates 1, 2 and 3 are
		// now REACHED by this service and Blocking() would report them as an outage
		// if any of the three failed to build.
		Idempotency: d.idempotencyGate,
	})
	if err != nil {
		log.Error("THE ENFORCEMENT PIPELINE COULD NOT BE BUILT; no Connect service will be "+
			"registered", "error", err)
		return
	}
	d.gates = gates

	// Two different facts, at two different levels, because they have two
	// different consequences.
	//
	// Blocking is an OUTAGE: some method reaches a gate that has no
	// implementation, so it is refused for as long as this binary runs.
	//
	// Missing without Blocking is just an unbuilt module. It used to be reported
	// at ERROR, and on this build it was reported at ERROR on every boot while
	// refusing nothing at all — every authorization declaration in the tree is
	// `self` on `user`, and enforce returns before the org-context gate for
	// those. An ERROR that names no consequence is the line an operator learns to
	// scroll past, which is a bad habit to teach with the real ones coming later.
	if blocking := gates.Blocking(); len(blocking) > 0 {
		log.Error("gates are reached by some method and implemented by none; those methods "+
			"are refused for the lifetime of this process", "gates", blocking)
	} else if missing := gates.Missing(); len(missing) > 0 {
		log.Info("gates are unimplemented but unreachable: no method's policy reaches them, "+
			"so nothing is refused. They become an outage the moment a method declares one",
			"gates", missing)
	}
	log.Info("enforcement pipeline built",
		"services", gatedServices(), "methods", len(policies.Methods()))
}

// composeAuthenticator adds the API key resolver in front of the session one.
//
// # One authn step, two credential kinds
//
// The pipeline has exactly one authentication gate, and keeping it that way is
// the property this function exists to preserve. A second entry point for
// machine credentials would be a second place every later rule has to be
// repeated, and the rule that got missed would be the one that leaks. So both
// kinds resolve to the SAME Principal and face the same gates 1 to 5 — a key
// differs in what it carries (AAL1 permanently, an immutable organization, a
// scope list), never in which checks it passes.
//
// # A missing key resolver degrades to sessions only, and says so
//
// It is not fatal, per ADR-010: every human request still works, and machine
// requests are refused rather than admitted. But it is logged at ERROR, because
// an installation whose integrations have all stopped authenticating has one
// symptom and nothing else in the process would explain it.
func composeAuthenticator(
	d *dependencies, sessions *interceptor.SessionAuthenticator, log *slog.Logger,
) interceptor.Authenticator {
	if sessions == nil {
		return nil
	}
	// The SAME clock identity writes key deadlines with, for the reason the
	// session authenticator takes it: left to time.Now, expiry and rotation
	// retirement become untestable through ADR-054.s movable clock and the two
	// halves of a key.s lifetime sit on different clocks.
	keys, err := interceptor.NewAPIKeyAuthenticator(interceptor.APIKeyAuthenticatorDeps{
		TX:  pgadapter.New(d.pool),
		Log: log,
		Now: d.clock.Now,
	})
	if err != nil {
		log.Error("API key authenticator not constructed; every request presenting an "+
			"API key will be refused while session requests keep working", "error", err)
		return sessions
	}
	composite, err := interceptor.NewBearerAuthenticator(sessions, keys)
	if err != nil {
		log.Error("bearer authenticator not composed; API keys will not resolve",
			"error", err)
		return sessions
	}
	log.Info("bearer authenticator composed", "kinds", []string{"session", "api_key"})
	return composite
}
