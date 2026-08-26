// Package authz is the authorization kernel: who may do what to which resource.
//
// Permissions are never evaluated here, and never in PostgreSQL. There is no
// permissions table, no recursive CTE, no tree walking. The hierarchy and the
// ACLs live in OpenFGA; PostgreSQL stores what a resource IS, OpenFGA stores who
// may touch it. This package is the port and the policy around it.
//
// # Everything here fails closed
//
// This is the one deliberate exception to "the server stays resilient"
// (ADR-010). If the authorization service is unreachable, slow, or answers
// something this package does not understand, the answer is DENY. An outage
// must not become a privilege-escalation path, because an attacker who can
// degrade a dependency would otherwise gain access by doing so.
//
// The type system carries that rule rather than relying on discipline: the zero
// Decision is a denial, allowing requires an explicit constructor, and there is
// no way to build an allow from an error value.
package authz

import (
	"context"
	"errors"
	"fmt"
	"strings"
)

// Relation is a verb from the authorization model — "viewer", "editor",
// "owner". It is never a permission string assembled at a call site: the set is
// closed by the model, and a typo must fail loudly rather than silently deny.
type Relation string

func (r Relation) String() string { return string(r) }

// ResourceRef names one object: a type and an id, e.g. folder:01H8XG….
//
// The type is part of the identity. Two resources of different types may share
// an id, and a check that dropped the type would silently ask about the wrong
// object.
type ResourceRef struct {
	Type string
	ID   string
}

func (r ResourceRef) String() string { return r.Type + ":" + r.ID }

func (r ResourceRef) valid() error {
	if r.Type == "" || r.ID == "" {
		return fmt.Errorf("%w: resource %q is incomplete", ErrInvalid, r.String())
	}
	// ':' separates type from id and '#' introduces a userset. A value carrying
	// either would address a different object than the caller named — the
	// authorization equivalent of SQL injection.
	if strings.ContainsAny(r.Type, ":#") || strings.ContainsAny(r.ID, ":#") {
		return fmt.Errorf("%w: resource %q contains a reserved character", ErrInvalid, r.String())
	}
	return nil
}

// PrincipalKind distinguishes the sorts of actor that can hold access.
//
// API keys and service accounts are principals too. A key's effective permission
// is the INTERSECTION of its scopes and its owning principal's access, so a key
// can never exceed its creator and narrowing the creator narrows every key they
// issued (access.md §4).
type PrincipalKind string

const (
	KindUser           PrincipalKind = "user"
	KindServiceAccount PrincipalKind = "service_account"
	KindAPIKey         PrincipalKind = "api_key"
	KindLink           PrincipalKind = "link"
)

// Principal is the subject of a check.
type Principal struct {
	Kind PrincipalKind
	ID   string

	// OnBehalfOf is the principal an API key or service account acts for. It
	// bounds the key: the key can never exceed it.
	OnBehalfOf string

	// OnBehalfOfKind is what sort of principal OnBehalfOf names.
	//
	// It exists because OnBehalfOf on its own is an id with no type, and this
	// system has two owners a key can have — a person and a service account —
	// whose tuples name different object types. Rendering `user:svc_…` because
	// the kind was assumed rather than carried is not a denial: OpenFGA would be
	// asked a well-formed question about an object that does not exist, answer
	// no, and the key would fail closed for a reason nothing in the log
	// explains.
	//
	// Set together with OnBehalfOf or not at all. Acting refuses the half-set
	// combination rather than defaulting the kind, because the default that
	// would be reached for is `user`, and a service account silently checked as
	// a user is the one substitution that could pick up a real person's grants.
	OnBehalfOfKind PrincipalKind
}

func (p Principal) String() string { return string(p.Kind) + ":" + p.ID }

// Acting is the principal an authorization check must actually name.
//
// A machine credential is a PRINCIPAL in its own right — access.md §5 puts
// `api_key` in the kind list, and that is what the audit trail, the rate limiter
// and every log line should see. It is NOT what the graph holds a tuple for:
// nothing in the OpenFGA model grants a relation to `api_key:key_…`, and
// nothing should, because a key's authority is defined as its owner's narrowed
// by its scopes (access.md §4) rather than as a second set of grants that could
// drift from the owner's.
//
// So the identity a request is ATTRIBUTED to and the identity it is AUTHORIZED
// as are two different answers, and this function is the one place that turns
// the first into the second. The gate calls it; nothing else re-derives it.
//
// A principal with no OnBehalfOf is returned unchanged, so every existing caller
// — every session, which never sets the field — keeps exactly the behaviour it
// had.
//
// A principal whose OnBehalfOf is set with no kind returns a Principal with an
// empty kind, which valid() refuses and the Guard turns into a denial. That is
// the intended direction: the alternative is guessing, and the guess would be
// `user`.
func (p Principal) Acting() Principal {
	if p.OnBehalfOf == "" {
		return p
	}
	return Principal{Kind: p.OnBehalfOfKind, ID: p.OnBehalfOf}
}

func (p Principal) valid() error {
	switch p.Kind {
	case KindUser, KindServiceAccount, KindAPIKey, KindLink:
	default:
		return fmt.Errorf("%w: unknown principal kind %q", ErrInvalid, p.Kind)
	}
	if p.ID == "" {
		return fmt.Errorf("%w: principal has no id", ErrInvalid)
	}
	if strings.ContainsAny(p.ID, ":#") {
		return fmt.Errorf("%w: principal id %q contains a reserved character", ErrInvalid, p.ID)
	}
	// The delegation half is checked with the same rules as the principal
	// itself. It is rendered into a tuple by Acting, so a ':' or a '#' in it is
	// the same injection the id check above refuses — and an id with no kind
	// would produce a reference to an untyped object.
	if p.OnBehalfOf != "" {
		if strings.ContainsAny(p.OnBehalfOf, ":#") {
			return fmt.Errorf("%w: delegated principal id %q contains a reserved character",
				ErrInvalid, p.OnBehalfOf)
		}
		if p.OnBehalfOfKind == "" {
			return fmt.Errorf("%w: principal %s acts for %q with no kind; the object type "+
				"would have to be guessed, and the guess is the one that picks up a person's "+
				"grants", ErrInvalid, p.String(), p.OnBehalfOf)
		}
	}
	return nil
}

// Query is one authorization question.
type Query struct {
	Principal Principal
	Relation  Relation
	Resource  ResourceRef

	// Context carries the session facts conditions may reference — assurance
	// level, device trust, IP. They travel as contextual tuples so that
	// "destructive actions require AAL2" is an authorization rule rather than an
	// `if session.AAL < 2` scattered through handlers (access.md §4).
	Context AuthContext
}

func (q Query) Validate() error {
	if err := q.Principal.valid(); err != nil {
		return err
	}
	if q.Relation == "" {
		return fmt.Errorf("%w: no relation given", ErrInvalid)
	}
	if strings.ContainsAny(string(q.Relation), ":#") {
		return fmt.Errorf("%w: relation %q contains a reserved character", ErrInvalid, q.Relation)
	}
	return q.Resource.valid()
}

// AuthContext is what the session established, consumed here as contextual
// tuples. The session says who the principal is and how strongly; it says
// nothing about permissions.
type AuthContext struct {
	// AAL is the authenticator assurance level reached by this session.
	AAL int
	// DeviceTrusted reports whether the device is one the person has confirmed.
	DeviceTrusted bool
	IP            string
	SessionID     string
	// ActiveOrg scopes the request. A principal may belong to several
	// organizations and acts within exactly one at a time.
	ActiveOrg string
}

// Decision is the answer. Its ZERO VALUE IS A DENIAL.
//
// That is the single most important property in this package. Every path that
// fails — an error, a timeout, an unparseable response, a forgotten branch —
// yields the zero value, and the zero value denies. Allowing takes an explicit
// constructor, so no amount of forgetting can produce one.
type Decision struct {
	allowed bool
	reason  string
}

// Allow constructs a permit. The reason is for Expand and for audit, never for
// the caller's control flow.
func Allow(reason string) Decision { return Decision{allowed: true, reason: reason} }

// Deny constructs a refusal.
func Deny(reason string) Decision { return Decision{reason: reason} }

// Allowed reports whether the action may proceed.
func (d Decision) Allowed() bool { return d.allowed }

// Reason explains the decision. Never returned to an unauthorized caller — it
// describes the ACL graph, which is itself information (ADR-036).
func (d Decision) Reason() string { return d.reason }

func (d Decision) String() string {
	if d.allowed {
		return "allow(" + d.reason + ")"
	}
	return "deny(" + d.reason + ")"
}

// Checker answers authorization questions. Implemented by an adapter; the
// kernel never speaks to OpenFGA directly (ADR-001).
//
// An implementation MUST NOT return an allow it is not certain of. Returning an
// error is always safe: the Guard turns any error into a denial.
type Checker interface {
	// Check answers one question.
	Check(ctx context.Context, q Query) (Decision, error)

	// BatchCheck answers many in one round trip.
	//
	// It is a ROUND-TRIP optimisation, not a compute one — measured at 1.4x for
	// 50 checks on localhost, not 50x (access.md §1.5). It exists so a page of
	// resources costs one network hop, not so that unbounded fan-out becomes
	// cheap.
	//
	// The result slice is positionally aligned with the queries. An
	// implementation that cannot answer a position must place a DENIAL there,
	// never omit it — a short slice would otherwise shift every later answer
	// onto the wrong question.
	BatchCheck(ctx context.Context, qs []Query) ([]Decision, error)
}

// Lister answers the expensive questions, kept in a separate port so that
// reaching for one is a deliberate act.
//
// ListObjects is UNMEASURED at scale and ListUsers expands groups (access.md
// §7). The supported pattern for a page of resources is: page from the
// projection, then BatchCheck only that page.
type Lister interface {
	ListObjects(ctx context.Context, p Principal, r Relation, resourceType string) ([]ResourceRef, error)
	ListUsers(ctx context.Context, r Relation, res ResourceRef) ([]Principal, error)
}

// Explainer returns the decision tree behind an answer. Debugging and support
// only: it describes the ACL graph, which must never reach an end user.
type Explainer interface {
	Expand(ctx context.Context, r Relation, res ResourceRef) (string, error)
}

// MaxDepth is the deepest nesting a check may traverse.
//
// OpenFGA raises a hard error past 25, so a tree that grew beyond it would start
// failing checks — and failing closed means users losing access to resources
// they own. Capping at 15 leaves headroom and turns "too deep" into a rejected
// WRITE at the moment somebody nests too far, which is fixable, rather than a
// read outage later, which is not.
const MaxDepth = 15

var (
	// ErrInvalid marks a query that can never be answered as constructed. It is
	// a programming error, not a denial: the caller built something malformed.
	ErrInvalid = errors.New("authz: invalid query")

	// ErrUnavailable means the authorization service could not answer. Callers
	// see a denial; this exists so the CAUSE is distinguishable in logs and
	// metrics from a genuine refusal.
	ErrUnavailable = errors.New("authz: authorization service unavailable")

	// ErrTooDeep marks a hierarchy that exceeds MaxDepth.
	ErrTooDeep = errors.New("authz: hierarchy is too deep")
)
