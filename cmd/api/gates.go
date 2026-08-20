package main

import (
	"log/slog"

	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/system/v1/systemv1connect"
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
		authn, err := interceptor.NewSessionAuthenticator(interceptor.SessionAuthenticatorDeps{
			TX:  pgadapter.New(d.pool),
			Log: log,
		})
		if err != nil {
			// NewSessionAuthenticator refuses only relationships between durations
			// that we control, so this is a wiring bug rather than an outage.
			log.Error("session authenticator not constructed; every authenticated RPC "+
				"will be refused", "error", err)
		} else {
			d.authn = authn
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
		// Typed nil is a real hazard here: a nil *SessionAuthenticator inside a
		// non-nil Authenticator would pass NewGates' own refuseTypedNil check only
		// because it is not nil, and then deny with a panic instead of an error.
		// NewGates checks for exactly that, which is why the value is passed
		// through a helper rather than directly.
		Authn: authenticatorOrNil(d.authn),
		Authz: d.authz,
		// Org, Subscriptions and Entitlements belong to modules that do not exist
		// yet. Left nil DELIBERATELY: a method declaring one of those gates is
		// refused with ErrGateUnavailable, which is the correct answer for an
		// endpoint whose enforcement has not been built. Identity's own methods
		// are public or self-scoped and declare none of them.
		Idempotency: d.idempotencyGate,
	})
	if err != nil {
		log.Error("THE ENFORCEMENT PIPELINE COULD NOT BE BUILT; no Connect service will be "+
			"registered", "error", err)
		return
	}
	d.gates = gates

	if missing := gates.Missing(); len(missing) > 0 {
		// Not a warning about a possibility — a statement of fact about this
		// process. Every method whose policy names one of these is refused for as
		// long as this binary runs.
		log.Error("gates are declared by some methods and implemented by none; those "+
			"methods will be refused for the lifetime of this process", "gates", missing)
	}
	log.Info("enforcement pipeline built",
		"services", gatedServices(), "methods", len(policies.Methods()))
}

// authenticatorOrNil avoids the typed-nil trap: a nil *SessionAuthenticator
// placed directly into interceptor.Authenticator produces a value that is NOT
// == nil, so the authn gate would call through it and panic rather than refusing
// the request.
func authenticatorOrNil(a *interceptor.SessionAuthenticator) interceptor.Authenticator {
	if a == nil {
		return nil
	}
	return a
}
