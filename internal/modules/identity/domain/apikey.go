package domain

import (
	"regexp"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// The policy an API key is written under. Every one of these is a CEILING the
// aggregate enforces rather than a default the caller may exceed, because each
// of them fails in the same direction when it is absent: a credential that lives
// longer than anybody remembers it exists.
const (
	// MaxAPIKeyLifetime is the longest a key may be minted for.
	//
	// One year. identity.md §10 makes expiry mandatory with a policy-capped
	// maximum and does not name the number, so it is named here, once, with the
	// argument for it: a year is long enough that rotation is an annual chore
	// rather than a weekly interruption, and short enough that a key nobody
	// remembers minting stops working while the person who minted it is still
	// reachable. The failure this bounds is not the leak — that is what
	// revocation is for — it is the key that outlives its integration, its
	// owner and any memory of why it exists.
	MaxAPIKeyLifetime = 365 * 24 * time.Hour

	// DefaultAPIKeyLifetime is what a caller who names no deadline gets.
	//
	// Ninety days, and it is deliberately far below the ceiling. A default at
	// the maximum would mean every key ever minted through a client that does
	// not expose the field lives a year, which makes the ceiling the only
	// lifetime in practice.
	DefaultAPIKeyLifetime = 90 * 24 * time.Hour

	// MaxRotationOverlap bounds how long a superseded secret keeps working.
	//
	// Seven days. Long enough for a rotation to reach every consumer of a key
	// through whatever deployment pipeline they are behind — which is the whole
	// reason an overlap exists — and short enough that a rotation performed
	// BECAUSE a secret leaked has actually removed the leaked secret within a
	// week rather than at some unspecified future point.
	MaxRotationOverlap = 7 * 24 * time.Hour

	// DefaultRotationOverlap is what a caller who names no window gets.
	//
	// Twenty-four hours: one deploy cycle. Below the ceiling for the reason
	// DefaultAPIKeyLifetime is below its own — a default AT the maximum makes
	// the maximum the only value anybody ever uses.
	DefaultRotationOverlap = 24 * time.Hour

	// MaxAPIKeyScopes bounds the capability list.
	//
	// Thirty-two. The list is stored in an event, projected into a column and
	// compared on every request a key makes, so an unbounded one is a request
	// that can make every later request slower. It is far above any plausible
	// key: the scope vocabulary is `<resource type>:<read|write>` over a handful
	// of resource types.
	MaxAPIKeyScopes = 32

	// MaxAPIKeyScopeLen bounds one scope.
	MaxAPIKeyScopeLen = 64
)

// apiKeyScope is the capability grammar: `<resource type>:<read|write>`.
//
// Two levels and no more. A fine-grained permission belongs in OpenFGA, which is
// the one thing in this system permitted to answer "may this principal touch
// that object" (CLAUDE.md, access.md §7) — a scope vocabulary that grew a third
// axis would be a second authorization model, evaluated in Go, drifting from the
// first.
//
// What a scope is FOR is the other half of the intersection: it narrows a key
// below its owner, so an owner who is an org admin can mint a key that only
// reads. It can never widen, because the OpenFGA check on the owner still has to
// pass (access.md §4).
//
// The resource-type half is deliberately not an enumeration of known types. The
// gate derives the required scope from the RPC's own
// `(chronos.options.v1.authz).resource_type`, so a list here would be a second
// copy of the proto's vocabulary that has to be edited whenever a resource type
// is added — and the failure of forgetting is a key that can never reach a new
// endpoint, discovered by a customer.
var apiKeyScope = regexp.MustCompile(`^[a-z][a-z0-9_]*:(read|write)$`)

// APIKeyState is the lifecycle of one key.
type APIKeyState int

const (
	// APIKeyNone does not exist. Zero value, so an unloaded key is never
	// mistaken for a live one.
	APIKeyNone APIKeyState = iota
	APIKeyActive
	APIKeyRevoked
)

// APIKey is one machine credential.
//
// # Its own aggregate, not an entity on the owner
//
// Session's argument applies unchanged: rotation and revocation are per-key and
// frequent, and hanging them off the owner would serialise every key operation
// in an organization against one stream. It has a second argument of its own —
// an owner may be a SERVICE ACCOUNT or a USER, and an entity that had to live
// inside two different parents is not an entity, it is a join.
//
// # What is here and what is not
//
// The SECRET is not here, in any form. Not the plaintext, which is returned to
// the caller once and never stored anywhere; not the digest, which goes to
// `api_key_secret`. A digest recorded in an event outlives every mechanism that
// could remove it, because the log is append-only (ADR-013) — the same rule that
// keeps a session-token digest out of SessionCreated.
//
// `last_used_at` is not here either, and identity.md §13 explains why at length:
// an event per REQUEST makes the log grow with traffic rather than with state,
// and the cost lands at rebuild time. It is a coalesced projection write.
type APIKey struct {
	eventsourcing.Base

	id    ids.APIKeyID
	orgID string

	ownerKind contract.OwnerKind
	ownerID   string

	scopes    []string
	expiresAt time.Time
	state     APIKeyState
}

// NewAPIKey returns an empty aggregate for the repository to rebuild into.
func NewAPIKey() *APIKey { return &APIKey{} }

func (k *APIKey) ID() ids.APIKeyID              { return k.id }
func (k *APIKey) OrgID() string                 { return k.orgID }
func (k *APIKey) OwnerKind() contract.OwnerKind { return k.ownerKind }
func (k *APIKey) OwnerID() string               { return k.ownerID }
func (k *APIKey) ExpiresAt() time.Time          { return k.expiresAt }
func (k *APIKey) State() APIKeyState            { return k.state }

// Scopes returns a COPY of the capability list.
//
// A copy, because the slice is aggregate state and a caller that appended to the
// returned value would widen a key in memory — silently, and only for the
// lifetime of the process, which is the hardest possible version of that bug to
// reproduce.
func (k *APIKey) Scopes() []string { return slices.Clone(k.scopes) }

// Apply is the pure transition.
func (k *APIKey) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.ApiKeyCreated:
		k.id, _ = ids.Parse[ids.APIKey](ev.KeyID)
		k.orgID = ev.OrgID
		k.ownerKind = ev.OwnerKind
		k.ownerID = ev.OwnerID
		k.scopes = slices.Clone(ev.Scopes)
		k.expiresAt = ev.ExpiresAt
		k.state = APIKeyActive

	case *contract.ApiKeyRotated:
		// Only the deadline moves. The scopes, the owner and the org binding are
		// untouched by a rotation on purpose — a rotation that could change what
		// a key may do would be a way to escalate a key without minting one, and
		// the audit trail would read as routine maintenance.
		k.expiresAt = ev.ExpiresAt

	case *contract.ApiKeyRevoked:
		k.state = APIKeyRevoked
	}
}

// Usable reports whether the key may still act at this instant, as far as the
// LOG can tell.
//
// State and expiry, which are the two facts the log holds. It deliberately does
// NOT answer whether any particular SECRET resolves — a rotated key has two
// secrets with different deadlines, and only `api_key_secret` knows them. That
// is the same split Session.Live draws against the idle deadline, for the same
// reason: the value that moves outside the log cannot be answered from inside
// it, and a method that pretended to would answer from the state at creation.
func (k *APIKey) Usable(now time.Time) bool {
	return k.state == APIKeyActive && now.Before(k.expiresAt)
}

// Issue mints the key.
//
// Every bound is checked here rather than at the boundary alone, and the
// duplication is deliberate: protovalidate refuses a malformed request, but a
// reactor, a test and a future operator tool all reach the aggregate without
// passing through it, and the rule that decides how long a credential lives
// belongs where it cannot be bypassed.
func (k *APIKey) Issue(
	id ids.APIKeyID,
	orgID string,
	owner APIKeyOwner,
	scopes []string,
	expiresAt time.Time,
	createdBy string,
	at time.Time,
) error {
	if k.state != APIKeyNone {
		return errs.Conflictf("this API key already exists")
	}
	switch {
	case id.IsZero():
		return errs.ValidationFailedf("an API key id is required")
	case orgID == "":
		// The immutable binding, refused rather than defaulted. Without it a key
		// inherits every organization its owner belongs to, and a token leaked
		// from one customer's CI reaches another customer's data — a cross-tenant
		// breach originating in a feature nobody thought was tenant-scoped
		// (identity.md §10, review D2).
		return errs.ValidationFailedf("an API key is bound to exactly one organization")
	case createdBy == "":
		return errs.ValidationFailedf("an API key records who created it")
	}
	if err := owner.validate(); err != nil {
		return err
	}
	normalized, err := normalizeScopes(scopes)
	if err != nil {
		return err
	}
	if err := checkExpiry(expiresAt, at); err != nil {
		return err
	}

	eventsourcing.Record(k, &contract.ApiKeyCreated{
		KeyID:     id.String(),
		OrgID:     orgID,
		OwnerKind: owner.Kind,
		OwnerID:   owner.ID,
		Scopes:    normalized,
		ExpiresAt: expiresAt.UTC(),
		CreatedBy: createdBy,
		CreatedAt: at.UTC(),
	})
	return nil
}

// Rotate replaces the secret and records when the previous one dies.
//
// # The overlap is a DEADLINE, never a promise to clean up later
//
// `overlap` becomes `PreviousRetiresAt = at + overlap`, which is written into
// the event and stamped onto the superseded secret row. Nothing has to remember
// to remove the old secret afterwards: the lookup that resolves a presented
// token compares against that column, so the old secret stops working whether or
// not any sweep has run. The sweep only reclaims the row.
//
// That is the difference between this and the design where rotation "marks the
// old key for deletion". A mark is honoured by whoever remembers to read it, and
// the failure of forgetting is a leaked secret that stays live indefinitely —
// which is precisely the situation a rotation was performed to end.
//
// A zero overlap is legal and is the LEAK RESPONSE: the old secret retires at
// the instant of the rotation, so there is a window in which callers still
// holding it fail. That is the correct trade when the reason for rotating is
// that somebody else has the old secret, and it is refused as a DEFAULT — see
// DefaultRotationOverlap — precisely because it is the wrong answer for the
// routine case.
//
// # Why a revoked or expired key cannot be rotated
//
// Rotating a revoked key would resurrect it: the key id is unchanged, so every
// grant that names it applies again, and the audit trail reads as maintenance
// rather than as a restoration of access somebody deliberately removed. Rotating
// an EXPIRED key is refused for the narrower reason that it is indistinguishable
// from minting a new one while looking like a smaller decision — and minting is
// the operation that notifies and that an admin has to be entitled to perform.
func (k *APIKey) Rotate(
	overlap time.Duration, expiresAt time.Time, rotatedBy string, at time.Time,
) error {
	switch k.state {
	case APIKeyNone:
		return errs.NotFoundf("no such API key")
	case APIKeyRevoked:
		return errs.Conflictf("a revoked API key cannot be rotated; rotation keeps the key's " +
			"id and therefore every grant that names it, so it would restore access " +
			"somebody deliberately removed")
	}
	if !k.Usable(at) {
		return errs.Conflictf("an expired API key cannot be rotated; issue a new one, which is " +
			"the decision this would otherwise take while looking like a smaller one")
	}
	switch {
	case rotatedBy == "":
		return errs.ValidationFailedf("a rotation records who performed it")
	case overlap < 0:
		return errs.ValidationFailedf("a rotation overlap cannot be negative")
	case overlap > MaxRotationOverlap:
		return errs.ValidationFailedf(
			"a rotation overlap of %s exceeds the maximum of %s; a superseded secret that "+
				"outlives the rotation by longer than that is a secret nobody is going to "+
				"remove", overlap, MaxRotationOverlap)
	}
	if err := checkExpiry(expiresAt, at); err != nil {
		return err
	}

	eventsourcing.Record(k, &contract.ApiKeyRotated{
		KeyID: k.id.String(),
		OrgID: k.orgID,
		// Computed here rather than passed in, so the deadline and the instant it
		// is measured from come from one clock reading. Two readings would let a
		// retirement land before the rotation that caused it.
		PreviousRetiresAt: at.Add(overlap).UTC(),
		ExpiresAt:         expiresAt.UTC(),
		RotatedBy:         rotatedBy,
		RotatedAt:         at.UTC(),
	})
	return nil
}

// Revoke ends the key permanently.
//
// Idempotent, for Session.Revoke's reason: revoking an already-revoked key
// records nothing and succeeds, because making it an error turns a bulk
// revocation — which is what an incident response is — into a partial failure
// that leaves the caller unsure which keys actually died.
//
// An EXPIRED key is still revocable and DOES record the event, which is the one
// place this differs from Session.Revoke. A session that has expired can never
// be used again, so a tombstone for it is inert. A key's expiry is a date the
// key itself carries, and a rotation would move it — so "expired" is not a
// terminal state the way a revoked session is, and refusing to revoke here would
// mean a leaked secret on a key that happened to be a day past its deadline
// could be brought back with a single rotation.
func (k *APIKey) Revoke(actorID, reason string, at time.Time) error {
	switch k.state {
	case APIKeyNone:
		return errs.NotFoundf("no such API key")
	case APIKeyRevoked:
		return nil
	}
	if actorID == "" {
		return errs.ValidationFailedf("a revocation records who performed it")
	}
	eventsourcing.Record(k, &contract.ApiKeyRevoked{
		KeyID:     k.id.String(),
		OrgID:     k.orgID,
		ActorID:   actorID,
		Reason:    reason,
		RevokedAt: at.UTC(),
	})
	return nil
}

// APIKeyOwner is the principal a key acts as: a kind and an id, together.
//
// A value type rather than two parameters, so the pair travels as one thing and
// cannot be half-set by a caller that remembered the id and forgot the kind. Its
// zero value is invalid and validate says so, which is the property that makes
// "no owner" a refusal rather than a key that acts as the empty principal.
type APIKeyOwner struct {
	Kind contract.OwnerKind
	ID   string
}

// UserOwner is a personal access token's owner: the person, by pseudonym.
func UserOwner(subjectID string) APIKeyOwner {
	return APIKeyOwner{Kind: contract.OwnerUser, ID: subjectID}
}

// ServiceAccountOwner is an integration key's owner.
func ServiceAccountOwner(id ids.ServiceAccountID) APIKeyOwner {
	return APIKeyOwner{Kind: contract.OwnerServiceAccount, ID: id.String()}
}

// validate refuses every owner that is not exactly one known principal.
//
// The id is checked against the PREFIX its kind implies, and that is a second,
// independent control rather than tidiness. The kind is a string in a row and in
// an event; the id is a string beside it. A value that flipped the kind alone
// would name a service account that does not exist — but a value that flipped it
// on a system without this check would name whatever principal happened to share
// the id, and "the wrong kind of principal, with a real id" is the shape of the
// confused-deputy bug the whole tagged-pair design exists to prevent.
func (o APIKeyOwner) validate() error {
	switch o.Kind {
	case contract.OwnerUser:
		if _, err := ids.Parse[ids.Subject](o.ID); err != nil {
			return errs.ValidationFailedf(
				"a user-owned API key names its owner by SubjectID pseudonym; %s", err)
		}
	case contract.OwnerServiceAccount:
		if _, err := ids.Parse[ids.ServiceAccount](o.ID); err != nil {
			return errs.ValidationFailedf(
				"a service-account key names its owner by service account id; %s", err)
		}
	default:
		return errs.ValidationFailedf(
			"an API key is owned by a user or by a service account and by nothing else; " +
				"an unknown owner kind would be a principal with no grants and no way to " +
				"revoke it when its owner leaves")
	}
	return nil
}

// checkExpiry enforces the mandatory, capped deadline.
//
// Both ends are refused rather than clamped. A deadline in the past would mint a
// credential that is dead on arrival — the caller is handed a secret and told it
// works — and one beyond the ceiling is a request the server would have to
// answer with something other than what was asked for, which on a credential's
// lifetime is exactly the kind of silent substitution somebody later reads as a
// guarantee.
func checkExpiry(expiresAt, at time.Time) error {
	switch {
	case expiresAt.IsZero():
		// Named separately from "in the past", which it technically also is. A
		// zero time is an unset field rather than a bad value, and sending a
		// reader looking for a wrong date when the fault is a missing one costs
		// real time.
		return errs.ValidationFailedf(
			"an API key must expire; a credential with no deadline outlives the integration " +
				"it was minted for and any memory of why it exists (identity.md §10)")
	case !expiresAt.After(at):
		return errs.ValidationFailedf("an API key must expire in the future")
	case expiresAt.Sub(at) > MaxAPIKeyLifetime:
		return errs.ValidationFailedf(
			"an API key may live at most %s; %s was asked for",
			MaxAPIKeyLifetime, expiresAt.Sub(at).Round(time.Hour))
	}
	return nil
}

// normalizeScopes validates the capability list and returns it sorted and
// deduplicated.
//
// Sorted, because the list is compared and rendered in several places and an
// order that depended on how the caller typed it would make two identical keys
// look different in a diff, in a projection and in an audit record.
// Deduplicated, because a repeated scope is not an error the caller can act on
// and a list that grew by repetition would defeat MaxAPIKeyScopes.
//
// An EMPTY list is refused. A key with no scopes intersects to nothing and can
// do nothing, which is useless rather than dangerous — but it is also exactly
// what a list dropped somewhere between the client and here looks like, and the
// second reading is the one worth refusing at the write.
func normalizeScopes(scopes []string) ([]string, error) {
	if len(scopes) == 0 {
		return nil, errs.ValidationFailedf(
			"an API key must name at least one scope; a key with none can do nothing, and " +
				"is indistinguishable from one whose scopes were lost on the way here")
	}
	if len(scopes) > MaxAPIKeyScopes {
		return nil, errs.ValidationFailedf("an API key may carry at most %d scopes",
			MaxAPIKeyScopes)
	}
	out := make([]string, 0, len(scopes))
	for _, s := range scopes {
		if len(s) > MaxAPIKeyScopeLen {
			return nil, errs.ValidationFailedf("a scope is at most %d characters",
				MaxAPIKeyScopeLen)
		}
		if !apiKeyScope.MatchString(s) {
			// The offending value IS named here, unlike the service account name
			// above, and the difference is what the value can contain: a scope
			// that failed this pattern is not free text a person wrote about
			// themselves, and a caller debugging a typo in `workspace:reed` has
			// nothing else to go on.
			return nil, errs.ValidationFailedf(
				"%q is not a scope; a scope is <resource type>:read or <resource type>:write",
				s)
		}
		out = append(out, s)
	}
	slices.Sort(out)
	return slices.Compact(out), nil
}

// APIKeyScopeSatisfied reports whether a key holding these scopes may reach a
// method needing `required`.
//
// `:write` implies `:read` on the same resource type, and that implication is
// the only one. Without it every key that writes would have to carry both
// spellings, and the list that somebody forgot to keep in step is the one that
// makes a working integration fail on a read it has always been able to do.
//
// It lives in the domain rather than in the interceptor because it is a RULE
// about what a scope means, and the gate that consumes it must not be free to
// decide that meaning differently (CONVENTIONS §2). The gate derives the
// required scope from the RPC's declaration and asks this.
func APIKeyScopeSatisfied(held []string, required string) bool {
	if required == "" {
		// Refused rather than treated as "no requirement". A method whose
		// required scope could not be derived is one this function has no honest
		// answer for, and "yes" is the answer that opens it.
		return false
	}
	if slices.Contains(held, required) {
		return true
	}
	if after, ok := cutSuffix(required, ":read"); ok {
		return slices.Contains(held, after+":write")
	}
	return false
}

// cutSuffix is strings.CutSuffix, spelled locally so this file imports no more
// than it needs. It returns the head and whether the suffix was present.
func cutSuffix(s, suffix string) (string, bool) {
	if len(s) < len(suffix) || s[len(s)-len(suffix):] != suffix {
		return s, false
	}
	return s[:len(s)-len(suffix)], true
}
