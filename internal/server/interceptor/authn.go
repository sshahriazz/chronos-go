package interceptor

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/server/policy"
	"github.com/jackc/pgx/v5"
)

// AuthorizationHeader carries the bearer token. RFC 6750 §2.1.
const AuthorizationHeader = "Authorization"

// bearerScheme is compared case-INSENSITIVELY: RFC 7235 §2.1 makes the auth
// scheme a case-insensitive token, and clients really do send "bearer". A
// case-sensitive prefix check turns a spec-compliant client into a permanent
// 401 that looks like a credential problem on their side.
const bearerScheme = "bearer"

// ErrAuthenticationUnavailable is "could not tell", as distinct from "no such
// session".
//
// The distinction is the whole reason this sentinel exists. A database blip
// reported as a bad credential makes every client in the fleet sign its user
// out simultaneously, and the users then re-authenticate against the database
// that is already struggling. So an outage is an INTERNAL fault the client
// retries, and only a genuinely unresolvable token is UNAUTHENTICATED.
//
// This is not fail-open: neither outcome admits the request. ADR-010's "the
// server stays resilient" governs what the caller is TOLD, never whether an
// unauthenticated request proceeds.
var ErrAuthenticationUnavailable = errors.New("interceptor: authentication is unavailable")

// errNoSession is the undifferentiated failure. Missing header, wrong scheme,
// unknown token, revoked session, either deadline passed: one outcome to the
// caller, because every distinction is an oracle (ADR-036). The distinction is
// made in the log instead, where it costs nothing.
var errNoSession = errors.New("interceptor: no live session for this token")

// DefaultTouchAfter is how stale the idle deadline is allowed to become before
// a request pushes it forward.
//
// The alternative — touching on EVERY authenticated request — is one row update
// per authenticated read, on a single row per session, which is a write
// amplification of the entire read traffic of the API and a contention point on
// exactly the row every one of that session's concurrent requests wants. It buys
// nothing: the idle window is 14 days (app.DefaultIdleWindow), so an hour of
// staleness moves the deadline by 0.3% of its length.
//
// Not touching at all is the other failure, and it is worse than it looks: the
// idle deadline is written once at login and never moves, so it becomes a second
// absolute deadline and a session in constant daily use dies mid-use at 14 days.
// The idle window would still exist in the schema and no longer mean anything.
const DefaultTouchAfter = time.Hour

// SessionAuthenticator turns a bearer token into a Principal.
//
// # Where this type belongs
//
// Its natural home is the identity module's postgres adapter — the Authenticator
// interface is declared here precisely so the implementation can live there. It
// is in this package only because the task that wrote it could not create files
// under internal/modules. Nothing in it reaches into this package beyond
// Principal and Header, so moving it is a file move plus an import.
//
// # What it does not do
//
// It does not re-check anything GetSessionByToken already checked. That query
// INNER JOINs the secret (session_token) with the facts (session_view) and
// applies revocation and BOTH deadlines inside the statement, so a revoked or
// expired session does not exist to it. A Go-side re-check would be a second
// implementation of the same rule and therefore a second chance to disagree with
// it — and the disagreement would be silent, because the looser of the two wins.
//
// It performs no comparison of token bytes, in constant time or otherwise. The
// lookup is a primary-key probe on the digest, so what an attacker can measure is
// an index probe that hit or missed, not how many leading bytes of their guess
// were right. There is nothing here for crypto/subtle to protect; if a comparison
// of secrets is ever added, it is subtle.ConstantTimeCompare and nothing else.
type SessionAuthenticator struct {
	tx         db.SystemTX
	idleWindow time.Duration
	touchAfter time.Duration
	now        func() time.Time
	log        *slog.Logger
}

// SessionAuthenticatorDeps is what the authenticator needs to exist.
type SessionAuthenticatorDeps struct {
	// TX is the system transaction helper. SYSTEM and not tenant: this runs
	// before any org is known — that is the next gate's job — and identity's
	// tables carry no RLS, so there is no tenant scope to set and nothing to
	// scope it by.
	TX db.SystemTX

	// IdleWindow is how far ahead of now a touch pushes the idle deadline. It
	// defaults to app.DefaultIdleWindow, which is the same constant CreateSession
	// used to set the deadline in the first place — a different value here would
	// mean the deadline changes length the first time the session is used.
	IdleWindow time.Duration

	// TouchAfter is the staleness threshold. Defaults to DefaultTouchAfter.
	TouchAfter time.Duration

	// Now is the clock, injectable for tests. Defaults to time.Now.
	Now func() time.Time

	// Log records WHY an authentication failed. Defaults to slog.Default().
	Log *slog.Logger
}

// NewSessionAuthenticator builds the authenticator.
//
// Every relationship between the durations is checked here rather than at
// request time, because each of them fails by making the idle deadline
// meaningless rather than by producing an error anyone would see.
func NewSessionAuthenticator(d SessionAuthenticatorDeps) (*SessionAuthenticator, error) {
	if d.TX == nil {
		return nil, errors.New("interceptor: the authenticator needs a system transaction; " +
			"without one it cannot resolve a token and every request would be refused")
	}
	a := &SessionAuthenticator{
		tx:         d.TX,
		idleWindow: d.IdleWindow,
		touchAfter: d.TouchAfter,
		now:        d.Now,
		log:        d.Log,
	}
	if a.idleWindow == 0 {
		a.idleWindow = app.DefaultIdleWindow
	}
	if a.touchAfter == 0 {
		a.touchAfter = DefaultTouchAfter
	}
	if a.now == nil {
		a.now = time.Now
	}
	if a.log == nil {
		a.log = slog.Default()
	}
	switch {
	case a.idleWindow < 0:
		return nil, fmt.Errorf("interceptor: an idle window of %s is in the past, so every "+
			"touch would expire the session it refreshed", a.idleWindow)
	case a.touchAfter < 0:
		return nil, fmt.Errorf("interceptor: a touch threshold of %s is negative", a.touchAfter)
	case a.touchAfter >= a.idleWindow:
		// A threshold at or beyond the window means the session reaches its idle
		// deadline before it is ever eligible for a refresh: the touch code stays
		// present, stays tested, and never runs in production.
		return nil, fmt.Errorf("interceptor: a touch threshold of %s is not shorter than the "+
			"idle window of %s, so a session would expire before it was ever refreshed",
			a.touchAfter, a.idleWindow)
	}
	return a, nil
}

var _ Authenticator = (*SessionAuthenticator)(nil)

// Authenticate resolves the bearer token the request carries.
//
// The reduction from token to digest is app.SessionTokenDigest, the same
// exported function CreateSession used to reduce the token it issued. That is
// not a convenience: a second implementation of the reduction is a second chance
// to differ over the domain separator or the length prefix, and the failure mode
// of differing is that every session in the system resolves to nothing, at
// deploy time, for everyone at once.
func (a *SessionAuthenticator) Authenticate(ctx context.Context, header Header) (Principal, error) {
	if header == nil {
		return Principal{}, fmt.Errorf("%w: the request carried no headers", errNoSession)
	}
	token, ok := bearerToken(header.Get(AuthorizationHeader))
	if !ok {
		// Logged at DEBUG: an unauthenticated request is ordinary traffic — a
		// browser with an expired session, a probe — and logging it at INFO makes
		// the log useless on the day it matters. The token is NEVER logged, in any
		// form: it is a live credential until it expires.
		a.log.DebugContext(ctx, "authentication refused",
			"reason", "no bearer token in the Authorization header")
		return Principal{}, fmt.Errorf("%w: no bearer token", errNoSession)
	}

	now := a.now().UTC()
	row, err := a.resolve(ctx, app.SessionTokenDigest(token), now)
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
func (a *SessionAuthenticator) resolve(
	ctx context.Context, digest []byte, now time.Time,
) (identitydb.GetSessionByTokenRow, error) {
	var row identitydb.GetSessionByTokenRow
	err := a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// Scanned into the GENERATED row struct, field by field in the generated
		// order. If the query's column list changes, this stops compiling — which
		// is the point: a scan that silently shifted by one column would put the
		// subject id where the session id belongs and authenticate everyone as
		// somebody else.
		return q.QueryRow(ctx, identitydb.GetSessionByToken, digest, now).Scan(
			&row.SessionID,
			&row.SubjectID,
			&row.DeviceID,
			&row.Aal,
			&row.IdleExpiresAt,
			&row.AbsoluteExpiresAt,
			&row.RequiresCredentialRotation,
			&row.ElevatedScope,
			&row.ElevatedUntil,
			&row.CreatedAt,
			&row.LastSeenAt,
			&row.Enrolment,
		)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// The undifferentiated outcome. There is no row because the token is
		// unknown, or because the session is revoked, or because either deadline
		// has passed — the statement refuses all four identically and so does
		// this, because telling them apart is exactly the oracle ADR-036 closes.
		a.log.DebugContext(ctx, "authentication refused",
			"reason", "no live session for the presented token")
		return row, fmt.Errorf("%w: %w", errNoSession, err)
	case err != nil:
		// "Could not tell." Never reported as a credential failure.
		a.log.ErrorContext(ctx, "authentication could not be decided", "error", err)
		return row, fmt.Errorf("%w: resolving a session token: %w", ErrAuthenticationUnavailable, err)
	}
	return row, nil
}

// principalFrom builds the caller from the resolved row.
//
// A row this build cannot interpret is ErrAuthenticationUnavailable, not
// "unauthenticated". It was written by something that is not this application,
// or by a version of it that stores values this one does not understand, and
// answering "your credential is bad" to that hides the tampering — the same
// reasoning the identity adapter applies to an unparseable user id.
func (a *SessionAuthenticator) principalFrom(
	ctx context.Context, row identitydb.GetSessionByTokenRow,
) (Principal, error) {
	if _, err := ids.Parse[ids.Subject](row.SubjectID); err != nil {
		a.log.ErrorContext(ctx, "a session row carries an unreadable subject", "error", err)
		return Principal{}, fmt.Errorf("%w: session %s carries an unreadable subject: %w",
			ErrAuthenticationUnavailable, row.SessionID, err)
	}
	if _, err := ids.Parse[ids.Session](row.SessionID); err != nil {
		a.log.ErrorContext(ctx, "a session row carries an unreadable id", "error", err)
		return Principal{}, fmt.Errorf("%w: a session row carries an unreadable id: %w",
			ErrAuthenticationUnavailable, err)
	}
	aal, err := assuranceLevel(row.Aal)
	if err != nil {
		a.log.ErrorContext(ctx, "a session row carries an unusable assurance level",
			"error", err, "session_id", row.SessionID)
		return Principal{}, fmt.Errorf("%w: %w", ErrAuthenticationUnavailable, err)
	}

	return Principal{
		// The pseudonym, never the user id and never the address. It is what
		// every projection stores and what OpenFGA tuples name, so the authz gate
		// asks about the same string the access module wrote (ADR-002).
		Subject: authz.Principal{Kind: authz.KindUser, ID: row.SubjectID},
		Context: authz.AuthContext{
			AAL:       int(row.Aal),
			SessionID: row.SessionID,
			// DeviceTrusted and IP are deliberately left at their zero values.
			// The row records which device opened the session, not that the
			// person confirmed it, and the only source of an IP here is a client
			// header — which is forgeable, so consuming one would let the caller
			// choose the value that an "allow from the office network" condition
			// evaluates. Both default to the LESS trusted answer.
			//
			// ActiveOrg is likewise empty: a session is not scoped to an
			// organization, and taking one from a header would let any member of
			// any org name any other. Resolving it — with a membership check — is
			// gate 1's job.
		},
		AAL:                        aal,
		Enrolment:                  a.enrolment(ctx, row),
		RequiresCredentialRotation: row.RequiresCredentialRotation,
	}, nil
}

// Enrolment states, as GetSessionByToken spells them.
//
// Compared as strings against the statement's own literals rather than being
// converted from an integer, for the reason assuranceLevel gives: a numeric
// mapping makes an unrecognised value land on whichever constant happens to
// share its number, and here the constant that grants the exemption is one away
// from the one that denies it.
const (
	enrolmentEstablished = "established"
	enrolmentBootstrap   = "bootstrap"
	enrolmentUnknown     = "unknown"
)

// enrolment reads the account's enrolment state out of the resolved row.
//
// The whole point of this value is that it is a FACT about the caller's account,
// read server-side in the same statement that resolved their session. Nothing a
// caller sends takes part in it, which is what stops "I am still bootstrapping"
// from being a claim (policy.Enrolment).
//
// Anything this build does not recognise — a value written by a newer schema, a
// row a test double left empty, a column that has drifted — is EnrolmentUnknown,
// which relaxes nothing. That is a refusal of the exemption and not a refusal of
// the request: the session is real and the caller keeps whatever their assurance
// level already entitles them to, they simply face the strict floor on the two
// methods that declare a bootstrap one. Denying the session outright would sign
// out the entire fleet over a column nobody has read before, which is a far
// worse answer to "the value looks odd".
//
// It is logged at WARN and not at ERROR for the same reason: the outcome is
// safe, but a build that cannot read its own enrolment column has an unusable
// bootstrap flow, and nobody would otherwise find out.
func (a *SessionAuthenticator) enrolment(
	ctx context.Context, row identitydb.GetSessionByTokenRow,
) policy.Enrolment {
	switch row.Enrolment {
	case enrolmentEstablished:
		return policy.EnrolmentEstablished
	case enrolmentBootstrap:
		return policy.EnrolmentBootstrap
	case enrolmentUnknown:
		// The account row was absent — mid-rebuild, or erased. Expected, and
		// already the safe answer, so it is not worth a log line on every request.
		return policy.EnrolmentUnknown
	default:
		a.log.WarnContext(ctx, "a session row carries an enrolment state this build does not "+
			"recognise; the account is treated as having a second factor, so a first "+
			"enrolment cannot proceed for it",
			"session_id", row.SessionID, "enrolment", row.Enrolment)
		return policy.EnrolmentUnknown
	}
}

// touch pushes the idle deadline forward, at most once per touchAfter.
//
// Failure is DELIBERATELY not returned. The session already resolved; the
// request is authentic whether or not the bookkeeping write landed, and the only
// consequence of a lost touch is that the deadline stays where it was — the
// session expires EARLIER than it might have, which is the safe direction. Failing
// the request instead would convert a transient write error into a sign-out, which
// is the outcome the "could not tell" distinction above exists to prevent.
//
// It is logged rather than swallowed: if every touch is failing, the fleet is
// walking towards a synchronized mass expiry and nobody would otherwise know.
func (a *SessionAuthenticator) touch(
	ctx context.Context, row identitydb.GetSessionByTokenRow, now time.Time,
) {
	// An invalid (NULL) last_seen_at means the session has never been touched, so
	// it is due by definition.
	if row.LastSeenAt.Valid && now.Sub(row.LastSeenAt.Time) < a.touchAfter {
		return
	}
	err := a.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// The new deadline is clamped to the absolute one BY THE STATEMENT, across
		// the join. Computing the clamp here instead would need the absolute
		// deadline read on this request to still be current, and would put a
		// second copy of the rule where the first one cannot see it.
		// Both timestamps come from `now`, which is this server's injected clock.
		// The statement used to stamp last_seen_at with the DATABASE's now(), so
		// one row carried two clocks and a session could report a lastSeenAt
		// before its own createdAt.
		_, err := q.Exec(ctx, identitydb.TouchSession,
			row.SessionID, now.Add(a.idleWindow).UTC(), now.UTC())
		return err
	})
	if err != nil {
		a.log.WarnContext(ctx, "could not refresh a session's idle deadline",
			"error", err, "session_id", row.SessionID)
	}
}

// bearerToken extracts the credential from an Authorization header value.
func bearerToken(value string) (string, bool) {
	scheme, token, found := strings.Cut(value, " ")
	if !found || !strings.EqualFold(scheme, bearerScheme) {
		return "", false
	}
	token = strings.TrimSpace(token)
	if token == "" {
		return "", false
	}
	return token, true
}

// assuranceLevel maps the stored column onto the enum the policy compares
// against.
//
// An explicit switch over literals rather than a conversion: optionsv1's zero
// value is UNSPECIFIED, and a conversion would turn a 0 in the column — the
// value a projector writes for a level it could not record — into an enum that
// compares as "less than every requirement" only by accident. It also mirrors
// projection.aalColumn, which writes only 1 and 2 today; 3 is accepted on READ so
// that a build which starts establishing AAL3 does not make every session
// unreadable to a server that has not been redeployed yet.
func assuranceLevel(stored int32) (optionsv1.AssuranceLevel, error) {
	switch stored {
	case 1:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1, nil
	case 2:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2, nil
	case 3:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_3, nil
	default:
		return optionsv1.AssuranceLevel_ASSURANCE_LEVEL_UNSPECIFIED,
			fmt.Errorf("assurance level %d is not one this build can interpret", stored)
	}
}
