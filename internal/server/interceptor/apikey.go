package interceptor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/server/policy"
	"github.com/jackc/pgx/v5"
)

// APIKeyAuthenticator turns an API key bearer token into a Principal.
//
// # Where this type belongs
//
// Beside SessionAuthenticator, and that type's own note applies unchanged: its
// natural home is the identity module's postgres adapter, and it is here so the
// two resolvers that answer the same question sit next to each other while the
// Authenticator interface is declared here.
//
// # What it does NOT do
//
// It does not re-check anything `GetApiKeySecret` already checked. That
// statement applies BOTH deadlines — the key's mandatory expiry and the rotation
// retirement — inside the query, so a key past either does not exist to it. A
// Go-side re-check would be a second implementation of the same rule and
// therefore a second chance to disagree with it, and the looser of the two would
// win silently.
//
// It performs no comparison of token bytes. The lookup is a primary-key probe on
// a 32-byte digest, so what an attacker can measure is an index probe that hit or
// missed, not how many leading bytes of their guess were right.
//
// # Why it touches no projection, unlike SessionAuthenticator
//
// `GetSessionByToken` INNER JOINs `session_view`, so a session stops resolving
// while that projection is rebuilt and every human is signed out for its
// duration. They sign in again. A machine does not: a rebuild that broke every
// integration a customer has built would be an outage with no human in the loop
// to recover from it, triggered by routine maintenance on an unrelated
// projection.
//
// So the owner, the organization and the scopes are stored on the secret row and
// resolved from it, and revocation is structural rather than a flag checked here
// — revoking DELETES the secret rows, so a revoked key has nothing to resolve.
// Migration 00051's header carries the full argument.
type APIKeyAuthenticator struct {
	tx  db.SystemTX
	now func() time.Time
	log *slog.Logger
}

// APIKeyAuthenticatorDeps is what the authenticator needs to exist.
type APIKeyAuthenticatorDeps struct {
	// TX is the system transaction helper. SYSTEM and not tenant: this runs
	// before any organization is known — establishing which one is the next
	// gate's job, and for a machine credential the ANSWER comes out of this very
	// lookup — so there is no scope to set and nothing to scope it by.
	// `api_key_secret` carries no row-level security for exactly that reason.
	TX db.SystemTX

	// Now is the clock, injectable for tests. Defaults to time.Now.
	//
	// It must be the same clock identity writes key deadlines with. Left to
	// time.Now while the rest of the process runs on a movable clock, expiry and
	// rotation retirement become untestable and the two halves of a key's
	// lifetime sit on different clocks — the defect ADR-054's session work
	// already found once.
	Now func() time.Time

	// Log records WHY an authentication failed. Defaults to slog.Default().
	Log *slog.Logger
}

// NewAPIKeyAuthenticator builds the authenticator.
func NewAPIKeyAuthenticator(d APIKeyAuthenticatorDeps) (*APIKeyAuthenticator, error) {
	if d.TX == nil {
		return nil, errors.New("interceptor: the API key authenticator needs a system " +
			"transaction; without one it cannot resolve a key and every machine request " +
			"would be refused")
	}
	a := &APIKeyAuthenticator{tx: d.TX, now: d.Now, log: d.Log}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	return a, nil
}

var _ Authenticator = (*APIKeyAuthenticator)(nil)

// Authenticate resolves the API key the request carries.
//
// The reduction from token to digest is `app.APIKeyTokenDigest`, the same
// exported function that reduced the token when it was issued. That is not a
// convenience: a second implementation is a second chance to differ over the
// domain separator or the length prefix, and the failure mode of differing is
// that every key in the system resolves to nothing, at deploy time, for everyone
// at once.
func (a *APIKeyAuthenticator) Authenticate(ctx context.Context, header Header) (Principal, error) {
	if header == nil {
		return Principal{}, fmt.Errorf("%w: the request carried no headers", errNoSession)
	}
	token, ok := bearerToken(header.Get(AuthorizationHeader))
	if !ok {
		a.log.DebugContext(ctx, "authentication refused",
			"reason", "no bearer token in the Authorization header")
		return Principal{}, fmt.Errorf("%w: no bearer token", errNoSession)
	}

	// Parsed for ATTRIBUTION, never for authentication. Nothing it returns is
	// trusted — the digest below covers the whole string, so a token pairing one
	// key's id with another's secret resolves to nothing regardless of what this
	// says. What it buys is a key id in the log line when a malformed credential
	// shows up, which is the difference between "somebody presented garbage" and
	// "key_01ARZ… is being presented with a wrong secret".
	parsed, parseErr := app.ParseAPIKeyToken(token)
	if parseErr != nil {
		a.log.DebugContext(ctx, "authentication refused",
			"reason", "the bearer token is not a well-formed API key")
		return Principal{}, fmt.Errorf("%w: malformed API key", errNoSession)
	}

	now := a.now().UTC()
	row, err := a.resolve(ctx, app.APIKeyTokenDigest(token), now, parsed.KeyID)
	if err != nil {
		return Principal{}, err
	}

	principal, err := a.principalFrom(ctx, row)
	if err != nil {
		return Principal{}, err
	}
	a.touch(ctx, row, now)
	return principal, nil
}

// resolve runs the one query, and translates its two failures differently.
//
// The distinction is SessionAuthenticator's and matters at least as much here: a
// database blip reported as a bad credential makes every integration in the
// fleet start reporting authentication failures to its own operators, who then
// go looking for a revoked key that was never revoked.
func (a *APIKeyAuthenticator) resolve(
	ctx context.Context, digest []byte, now time.Time, claimed ids.APIKeyID,
) (identitydb.GetApiKeySecretRow, error) {
	var row identitydb.GetApiKeySecretRow
	err := a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// Scanned into the GENERATED row struct, field by field in the generated
		// order. If the statement's column list changes, this stops compiling —
		// which is the point: a scan that silently shifted by one column would
		// put the organization where the owner belongs and authenticate a key
		// into the wrong tenant.
		return q.QueryRow(ctx, identitydb.GetApiKeySecret, digest, now).Scan(
			&row.KeyID,
			&row.OrgID,
			&row.OwnerKind,
			&row.OwnerID,
			&row.Scopes,
			&row.ExpiresAt,
			&row.RetiresAt,
		)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The undifferentiated outcome. There is no row because the key was
		// never minted, or because it was revoked (its secrets are deleted), or
		// because it expired, or because the secret was retired by a rotation —
		// the statement refuses all four identically and so does this, because
		// telling them apart is exactly the oracle ADR-036 closes.
		//
		// The claimed key id IS logged, and only here. It is not a secret: it
		// travels in the token's own public segment precisely so a leaked
		// credential can be attributed without anybody presenting the secret,
		// and a leak-response investigation with no key id in the log has
		// nothing to start from. The token itself is never logged in any form.
		a.log.DebugContext(ctx, "authentication refused",
			"reason", "no live API key for the presented token",
			"claimed_key_id", claimed.String())
		return row, fmt.Errorf("%w: %w", errNoSession, err)
	case err != nil:
		a.log.ErrorContext(ctx, "API key authentication could not be decided", "error", err)
		return row, fmt.Errorf("%w: resolving an API key: %w", ErrAuthenticationUnavailable, err)
	}
	return row, nil
}

// principalFrom builds the caller from the resolved row.
//
// A row this build cannot interpret is ErrAuthenticationUnavailable and not
// "unauthenticated", for SessionAuthenticator's reason: it was written by
// something that is not this application, or by a version of it that stores
// values this one does not understand, and answering "your credential is bad"
// to that hides the tampering.
//
// # What the principal says, and what it deliberately does not
//
// The SUBJECT is the key — `api_key:key_…` — which is what access.md §5 puts in
// the kind list and what the audit trail should see. OnBehalfOf is the owner,
// and `authz.Principal.Acting` is what turns the second into the object gate 2
// asks OpenFGA about, because nothing in the graph holds a tuple for a key and
// nothing should: a key's authority is defined as its owner's narrowed by its
// scopes, not as a second set of grants that could drift from the owner's.
//
// The ASSURANCE LEVEL is AAL1, permanently, and it can never be raised. A
// machine cannot present a second factor — there is no ceremony a program can
// perform — so every RPC declaring `min_aal = ASSURANCE_LEVEL_2` is unreachable
// with a key. That is not a limitation to work around; it is the control that
// stops a stolen key minting a second, quieter key or revoking the first to
// cover a track, because all four key-management mutations declare AAL2.
//
// ENROLMENT is EnrolmentUnknown, which relaxes nothing. The bootstrap exemption
// exists so an account with no second factor can enrol its first; a key has no
// account and no factor to enrol, and reporting it as bootstrapping would lower
// the floor on exactly the methods the paragraph above depends on being
// unreachable.
func (a *APIKeyAuthenticator) principalFrom(
	ctx context.Context, row identitydb.GetApiKeySecretRow,
) (Principal, error) {
	if _, err := ids.Parse[ids.APIKey](row.KeyID); err != nil {
		a.log.ErrorContext(ctx, "an API key row carries an unreadable id", "error", err)
		return Principal{}, fmt.Errorf("%w: an API key row carries an unreadable id: %w",
			ErrAuthenticationUnavailable, err)
	}
	if row.OrgID == "" {
		// Refused rather than resolved into no tenant. A key with no organization
		// would reach gate 1 with nothing to verify, and the safe reading of "we
		// cannot tell which tenant this credential belongs to" is that the
		// request does not happen.
		a.log.ErrorContext(ctx, "an API key row carries no organization", "key_id", row.KeyID)
		return Principal{}, fmt.Errorf(
			"%w: API key %s is bound to no organization", ErrAuthenticationUnavailable, row.KeyID)
	}
	ownerKind, err := ownerPrincipalKind(row.OwnerKind, row.OwnerID)
	if err != nil {
		a.log.ErrorContext(ctx, "an API key row carries an unusable owner",
			"error", err, "key_id", row.KeyID)
		return Principal{}, fmt.Errorf("%w: %w", ErrAuthenticationUnavailable, err)
	}
	if len(row.Scopes) == 0 {
		// A key with no scopes can reach nothing, because scopeSatisfied denies
		// on an empty list. Refused HERE anyway, and refused loudly, because the
		// two readings — "somebody minted a key with no scopes", which the
		// aggregate and two CHECK constraints all refuse, and "the column came
		// back empty" — are both faults, and a request that is denied at every
		// gate looks exactly like a permission problem to whoever reports it.
		a.log.ErrorContext(ctx, "an API key row carries no scopes", "key_id", row.KeyID)
		return Principal{}, fmt.Errorf(
			"%w: API key %s carries no scopes", ErrAuthenticationUnavailable, row.KeyID)
	}

	return Principal{
		Subject: authz.Principal{
			Kind:           authz.KindAPIKey,
			ID:             row.KeyID,
			OnBehalfOf:     row.OwnerID,
			OnBehalfOfKind: ownerKind,
		},
		Context: authz.AuthContext{
			AAL: 1,
			// The organization the key is BOUND to. Unlike a session's — which is
			// deliberately empty, because a session is not scoped to an org and
			// taking one from a header would let any member of any org name any
			// other — a key names exactly one, immutably, chosen when it was
			// minted. It is not a claim the caller makes.
			//
			// DeviceTrusted, IP and SessionID stay zero: there is no device, the
			// only source of an IP is a forgeable header, and there is no session.
			ActiveOrg: row.OrgID,
		},
		AAL:       optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
		Enrolment: policy.EnrolmentUnknown,
		BoundOrg:  row.OrgID,
		Scopes:    row.Scopes,
	}, nil
}

// ownerPrincipalKind maps the stored owner kind onto the authz kind, checking
// the id against the prefix that kind implies.
//
// The prefix check is a SECOND, independent control and not tidiness. The kind
// is a string in a row and the id is a string beside it; a value that flipped
// the kind alone would render `user:svc_…` into an OpenFGA tuple, which asks a
// well-formed question about an object that does not exist. That fails closed —
// but the dangerous direction is the other one, where a service account id that
// happened to collide with a subject pseudonym picked up a real person's grants.
// Two constraints already refuse the pairing at write time; this refuses it at
// read time, so a row written by anything else cannot get past here either.
//
// An unrecognised kind is an ERROR rather than a default. The default that would
// be reached for is `user`, which is the permissive one.
func ownerPrincipalKind(kind, ownerID string) (authz.PrincipalKind, error) {
	switch contract.OwnerKind(kind) {
	case contract.OwnerUser:
		if _, err := ids.Parse[ids.Subject](ownerID); err != nil {
			return "", fmt.Errorf("an API key claims a user owner whose id is not a subject "+
				"pseudonym: %w", err)
		}
		return authz.KindUser, nil
	case contract.OwnerServiceAccount:
		if _, err := ids.Parse[ids.ServiceAccount](ownerID); err != nil {
			return "", fmt.Errorf("an API key claims a service account owner whose id is not a "+
				"service account: %w", err)
		}
		return authz.KindServiceAccount, nil
	default:
		return "", fmt.Errorf("owner kind %q is not one this build can interpret", kind)
	}
}

// touch advances `last_used_at`, at most once per key per minute.
//
// Failure is DELIBERATELY not returned, for the reason SessionAuthenticator's
// touch gives: the key already resolved, the request is authentic whether or not
// the bookkeeping write landed, and the only consequence of a lost touch is a
// stale hint on a management screen. Failing the request instead would convert a
// transient write error into a broken integration.
//
// The threshold is in the STATEMENT rather than here, so the write is skipped by
// the database instead of by a read-modify-write — one round trip rather than
// two, and no race between two concurrent requests that both read a stale value.
//
// It runs under the key's OWN tenant scope, because `api_key_view` carries
// row-level security and the organization is the one the secret row named. That
// is the only write in this file that touches a policy-protected table, and it
// is why this method opens its own transaction rather than reusing the resolve
// one: the resolve is unscoped by necessity, and a scope cannot be added to a
// transaction after a statement has run under none.
func (a *APIKeyAuthenticator) touch(
	ctx context.Context, row identitydb.GetApiKeySecretRow, now time.Time,
) {
	scoped := db.WithTenant(ctx, db.Tenant{OrgID: row.OrgID, UserID: row.OwnerID})
	tenantTX, ok := a.tx.(db.TX)
	if !ok {
		// The helper cannot open a scoped transaction. Logged once per request
		// rather than silently skipped, because the column would then never move
		// and "last used" would read as "never used" for every key in the system
		// — which is precisely the signal somebody uses to decide a key is safe
		// to revoke.
		a.log.WarnContext(ctx, "an API key's last-used stamp cannot be advanced; the "+
			"transaction helper offers no tenant scope and api_key_view carries row "+
			"security", "key_id", row.KeyID)
		return
	}
	err := tenantTX.InTenantTx(scoped, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, identitydb.TouchApiKey, row.KeyID, now.UTC())
		return err
	})
	if err != nil {
		a.log.WarnContext(ctx, "could not advance an API key's last-used stamp",
			"error", err, "key_id", row.KeyID)
	}
}

// BearerAuthenticator routes a presented bearer to the resolver that owns its
// shape.
//
// # Why one authenticator and not two gates
//
// The gate pipeline has exactly one authn step, and that is the property worth
// preserving: a second entry point for machine credentials would be a second
// place every later rule has to be repeated, and the one that got missed would
// be the one that leaks. So both credential kinds resolve to the SAME Principal
// type and flow through the same gates 1 to 5 — the key differs in what it
// carries (AAL1 permanently, a bound organization, a scope list), not in which
// checks it faces.
//
// # The routing is on the token's own shape and never on a header
//
// An API key starts `chr_`, which is a prefix no session token can have: a
// session token is unpadded base64url over 32 random bytes and contains no
// underscore. A separate header — `X-Api-Key` — would let a caller choose which
// resolver runs, and a caller who can choose the resolver can choose which
// deadline and revocation rules apply to them.
//
// A value that looks like a key and is not one is refused HERE rather than
// falling through to the session lookup. Falling through would produce a second,
// differently-worded refusal that a caller could tell apart from the first,
// which is a shape oracle for whether a given key id exists.
type BearerAuthenticator struct {
	sessions Authenticator
	keys     Authenticator
}

// NewBearerAuthenticator composes the two resolvers.
//
// Both are required. A nil session resolver would refuse every human request and
// a nil key resolver every machine one — and the interesting half is that
// neither failure is visible from the other's tests, which is why this refuses
// at construction rather than at the first request.
func NewBearerAuthenticator(sessions, keys Authenticator) (*BearerAuthenticator, error) {
	switch {
	case sessions == nil:
		return nil, errors.New("interceptor: the bearer authenticator needs a session " +
			"resolver; without one every human request is refused")
	case keys == nil:
		return nil, errors.New("interceptor: the bearer authenticator needs an API key " +
			"resolver; without one every machine request is refused")
	}
	return &BearerAuthenticator{sessions: sessions, keys: keys}, nil
}

var _ Authenticator = (*BearerAuthenticator)(nil)

// Authenticate dispatches on the token's prefix.
func (b *BearerAuthenticator) Authenticate(ctx context.Context, header Header) (Principal, error) {
	if header == nil {
		return Principal{}, fmt.Errorf("%w: the request carried no headers", errNoSession)
	}
	if token, ok := bearerToken(header.Get(AuthorizationHeader)); ok && app.LooksLikeAPIKey(token) {
		return b.keys.Authenticate(ctx, header)
	}
	return b.sessions.Authenticate(ctx, header)
}
