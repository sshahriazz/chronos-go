package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Stream categories written by authentication.
//
// KurrentDB derives a category from everything before the FIRST dash, so neither
// value may contain one.
const (
	// SessionCategory names one session's stream: session-<session id>.
	SessionCategory eventsourcing.Category = "session"

	// AttemptCategory names the authentication journal: auth_attempt-<UTC date>.
	//
	// It exists as its own category because an attempt against an address nobody
	// registered has no account and therefore no user stream (identity.md §1), and
	// inventing a subject to hold it would create a permanent record keyed to a
	// person who does not exist here. It also keeps login volume off the account
	// stream, where every sign-in would otherwise contend with every password
	// change for one stream's revision.
	//
	// # Why the key is a DATE and not the blind index
	//
	// The obvious key is the identifier being attempted, and it is unsafe. The
	// stream name is chosen by whoever posts the login form, so keying on it lets
	// an UNAUTHENTICATED caller create one permanent stream per guessed address.
	// KurrentDB deletion is a soft delete, every name lands in `$streams` and in
	// the category stream, and every projector's `$all` scan grows with them. Rate
	// limiting bounds the rate and not the total, and it fails open by design — so
	// the ceiling is not the control that stops this.
	//
	// Bucketing by UTC day makes the stream COUNT a function of the calendar
	// instead of a function of input: one stream per day, forever, whatever an
	// attacker sends. What is lost is per-identifier ordering, and nothing wants
	// it — the journal already appends with AnyRevision because it carries no
	// invariant, and stuffing detection reads `login_history_view` by
	// `email_index`, which is a projected column rather than a stream name.
	//
	// The date is not personal data and not attacker-chosen, so the reasoning in
	// ADR-048 about keyed stream names does not apply here: there is nothing in the
	// name to protect.
	AttemptCategory eventsourcing.Category = "auth_attempt"
)

// attemptStreamKey buckets the authentication journal by UTC day.
//
// UTC because storage is always UTC (APP_TIMEZONE is presentation only), and
// because a local-time bucket would produce two streams for one day in half the
// world and rename the boundary twice a year.
//
// The layout has no dashes: KurrentDB derives a category from everything before
// the FIRST dash, so `2026-08-13` would file every attempt under the category
// `auth_attempt-2026` — which is not an error, just a silently wrong category
// that breaks the prefix-filtered subscription. NewStreamID refuses a dash in the
// key, so this is caught at the append rather than discovered later.
func attemptStreamKey(at time.Time) string { return at.UTC().Format("20060102") }

// Session lifetimes (identity.md §3).
const (
	// DefaultIdleWindow ends a session nobody is using. It MOVES: every
	// authenticated request pushes it forward, clamped to the absolute deadline.
	DefaultIdleWindow = 14 * 24 * time.Hour

	// DefaultAbsoluteWindow ends a session somebody may well be using, and never
	// moves. It is what bounds a stolen token held by an attacker who keeps it
	// warm — an idle deadline alone can be refreshed indefinitely by the thief.
	DefaultAbsoluteWindow = 30 * 24 * time.Hour

	// DefaultProofWindow is how long a completed authentication may be exchanged
	// for a session.
	//
	// Short, because a Proof is a bearer of the whole ceremony: it exists only
	// between Authenticate returning and CreateSession being called, which in the
	// server is the next few microseconds. The window is generous by three orders
	// of magnitude and still refuses a Proof that has been stored somewhere and
	// replayed later, which is the only way one can be misused.
	DefaultProofWindow = 2 * time.Minute
)

const (
	// sessionTokenBytes is the entropy in a bearer token. 256 bits.
	//
	// The token IS the session to anyone holding it, so it gets the same budget as
	// an emailed single-use secret and for the same reason: it is machine
	// generated, machine checked, and never typed by a human.
	sessionTokenBytes = 32

	// sessionTokenDomain separates session-token digests from every other SHA-256
	// this system computes.
	//
	// A session token and an emailed verification token are both random 256-bit
	// values reduced to a 32-byte digest, and they are stored in different tables
	// with different lifetimes and different consequences. Without a domain
	// separator, a digest lifted from one table is presentable to the other's
	// lookup — the tables cannot collide today because their columns differ, but
	// that is a property of the current schema rather than of the construction.
	// Length-prefixed, so no future separator can be made to overlap this one by
	// shifting the boundary.
	sessionTokenDomain = "chronos/identity/session_token/v1"

	// dummyPasswordBytes is the entropy behind the verifier an unknown identifier
	// is checked against. It is never presentable and never stored.
	dummyPasswordBytes = 32

	// lockoutKeySuffix and rehashKeySuffix separate the two appends one login can
	// make to the ACCOUNT stream from the append it makes to the attempt journal.
	//
	// eventsourcing.DeriveEventID hashes (idempotency key, index), so two appends
	// under one key both start at index 0 and produce the SAME event id on two
	// different streams. That is not a collision the store rejects — it is worse
	// than that: the id is what the second idempotency layer deduplicates on
	// (EVENT-SOURCING §3), so a retried command could see one of the two already
	// present and skip the other. Suffixing the key gives each stream its own
	// derivation while keeping both deterministic, so a retry still collapses onto
	// the original append rather than writing a second one.
	lockoutKeySuffix = ":authenticator-lockout"
	rehashKeySuffix  = ":password-rehash"
)

// Authentication is the four commands that turn credentials into a session and
// take one away: Authenticate, CreateSession, RevokeSession, RevokeAllSessions.
//
// # Every refusal is the same refusal
//
// An unknown identifier, a wrong password, a wrong code, a replayed code, an
// unverified address, a deactivated account, a suspended account and a
// rate-limited attempt all produce ONE undifferentiated error, byte for byte
// (ADR-036, identity.md §11). The distinction is recorded in the event's
// contract.FailureReason and in the log, where an operator can investigate it and
// an attacker cannot read it. Anything that puts the difference back on the wire
// — a distinct message, a distinct errs.Reason, an early return that skips work
// the other paths do — is an oracle, and the useful ones are all account-existence
// oracles.
//
// # Timing is part of the response
//
// The refusal for an identifier that matches no account must COST the same as the
// refusal for a wrong password. Argon2id is ~51 ms and dominates everything else
// here, so skipping it when there is no account turns the response time itself
// into the answer — and no wording on the wire hides a two-order-of-magnitude
// difference. So an unknown identifier is verified against a fixed dummy
// verifier, produced once per process, and then fails. That code reads like waste
// and is not; see verifyUnknown.
//
// # Why the second factor is presented in the same command
//
// Authenticate takes an optional code, and an authentication that arrives without
// one is answered with a challenge rather than with a session. The alternative —
// a first call that returns a ticket the second call redeems — needs somewhere to
// put the ticket, and every option is worse at this point in the build: a row in
// identity_token gives a partially-authenticated secret the same storage as a
// password reset, and an in-process map is a per-pod control that an attacker
// defeats by reaching a different pod. Restating the password costs a second
// Argon2id evaluation, which is a cost paid by legitimate users only and is
// visible in the code rather than hidden in a table. When S1-23 introduces the
// PendingSecondFactor ticket identity.md §3 describes, it belongs HERE, as a port.
//
// # A session is minted only against a Proof
//
// CreateSession does not take a subject id. It takes a Proof, whose fields are
// unexported and which no code outside this package can construct — the same
// discipline authz.Decision and ratelimit.Decision use, for the same reason: the
// zero value must not be usable. A handler that has not authenticated anybody
// therefore cannot ask for a session, and the compiler is what enforces it rather
// than a review comment.
type Authentication struct {
	clock       clock.Clock
	entropy     io.Reader
	index       EmailIndexer
	limiter     AttemptLimiter
	hasher      PasswordHasher
	credentials PasswordCredentials
	accounts    AccountDirectory
	users       AggregateLoader[*domain.User]
	sessions    AggregateLoader[*domain.Session]
	live        LiveSessions
	tokens      SessionTokens
	sealer      TotpSealer
	secrets     TotpSecrets
	verifier    TotpVerifier
	breach      BreachChecker
	appender    eventsourcing.MultiAppender
	epochs      RevocationEpochs

	idle     time.Duration
	absolute time.Duration
	proofTTL time.Duration
	log      *slog.Logger
	observer AuthObserver

	// tokenEntropy is the source bearer tokens are drawn from, and it is NOT a
	// dependency: it is crypto/rand, always, and is a field only so an in-package
	// test can drive the short-read branch. Making it wireable would turn "which
	// entropy source mints session tokens" into a configuration decision whose one
	// wrong answer is unrecoverable — every live session guessable, with nothing
	// in the system able to notice.
	tokenEntropy io.Reader

	// dummy holds the verifier an unknown identifier is checked against, built
	// once and reused. See verifyUnknown.
	dummyOnce sync.Once
	dummy     dummyVerifier
	schemas   eventsourcing.SchemaVersions
}

// dummyVerifier is a real verifier over a password nobody knows.
//
// The ids are real and non-zero because the hasher authenticates them into the
// sealed digest: verifying under the same pair is what makes the check do the
// full Argon2id evaluation instead of failing early on the AAD.
type dummyVerifier struct {
	verifier string
	user     ids.UserID
	cred     ids.CredentialID
	err      error
}

// AuthenticationDeps is everything the four handlers need.
//
// A struct rather than a positional constructor because sixteen dependencies in
// one call are sixteen chances to transpose two of the same shape, and several of
// these are interfaces over the same aggregate machinery.
type AuthenticationDeps struct {
	Clock       clock.Clock
	Entropy     io.Reader
	Index       EmailIndexer
	Limiter     AttemptLimiter
	Hasher      PasswordHasher
	Credentials PasswordCredentials
	Accounts    AccountDirectory
	Users       AggregateLoader[*domain.User]
	Sessions    AggregateLoader[*domain.Session]
	Live        LiveSessions
	Tokens      SessionTokens
	Sealer      TotpSealer
	Secrets     TotpSecrets
	Verifier    TotpVerifier
	Breach      BreachChecker
	Appender    eventsourcing.MultiAppender

	// Epochs invalidates the authorization decisions cached for the subject whose
	// sessions are being revoked (ADR-045).
	//
	// Optional, and its absence is a REAL weakening, exactly as authz.GuardDeps
	// says of its own Tombstones: without it a permit cached for this principal
	// keeps authorizing until it expires on its own, up to authz.MaxDecisionTTL
	// after the user pressed "sign out everywhere". NewAuthentication logs that
	// plainly and InvalidatesAuthorization reports it, so the composition root can
	// be ASSERTED rather than assumed — an absent port here is invisible at
	// runtime, which is precisely how this repository once shipped three adapters
	// that no binary constructed.
	Epochs RevocationEpochs

	// IdleWindow and AbsoluteWindow override the defaults. Zero means the default.
	IdleWindow     time.Duration
	AbsoluteWindow time.Duration

	// ProofWindow overrides DefaultProofWindow. Zero means the default.
	ProofWindow time.Duration

	// Log is optional and defaults to slog.Default(). Nothing here logs a
	// password, a code, a token or a digest: the only identifiers that reach it
	// are pseudonyms, credential ids and the keyed email index.
	Log *slog.Logger

	// Observer is optional and defaults to a nop. See AuthObserver for why the
	// two outcomes it reports cannot be recovered from the event log.
	Observer AuthObserver
	// Schemas stamps each appended event with its current schema version.
	//
	// Repository.Save does this for single-stream appends; these handlers use
	// MultiAppender and therefore must do it themselves. Without it every event is
	// stored at version 0 while the registry declares 1, so loading the aggregate
	// back demands a 0->1 upcaster that should never exist — the account is
	// writable exactly once and unreadable thereafter, while every projection and
	// dashboard stays green because the read path does not upcast.
	Schemas eventsourcing.SchemaVersions
}

// AuthObserver counts the authentication outcomes that leave NO event behind.
//
// Everything else on this path is answerable from the log: successes, failures
// and their reasons are events, projected into `login_history_view`, and
// `CountRecentFailures` reads them for the credential-stuffing signal. These two
// are not, and both are invisible for a reason that is worth stating.
//
// An attempt refused ABOVE the ceiling appends nothing, deliberately: refusals
// are unbounded, and one event each would let an unauthenticated caller drive
// unbounded writes into the log. The consequence is that the attempts most
// indicative of an attack in progress are exactly the ones the stuffing signal
// cannot see, so they have to be counted somewhere — here.
//
// A DEGRADED ceiling is worse. The limiter fails open (ratelimit.Limiter.Allow),
// so an unreachable counter means every attempt proceeds unthrottled, and the
// only trace is a log line. A counter makes it alertable, which is what the
// fail-open trade assumes exists.
//
// Declared here and satisfied structurally by the metrics adapter, so this
// package imports no metrics library (ADR-001, CONVENTIONS §2). Labels must come
// from a closed set: the rule name is one, the email index is NOT — it is
// unbounded and attacker-chosen, and putting it in a label is how a metrics
// backend falls over.
type AuthObserver interface {
	// Throttled records an attempt refused by the ceiling, labelled by the rule
	// that tripped.
	Throttled(rule string)

	// CeilingUnavailable records that the ceiling could not be evaluated and the
	// attempt was allowed anyway.
	CeilingUnavailable()
}

// nopAuthObserver is the default, so a caller that wires no metrics still gets a
// working login rather than a nil dereference on the first attempt.
type nopAuthObserver struct{}

func (nopAuthObserver) Throttled(string)    {}
func (nopAuthObserver) CeilingUnavailable() {}

// NewAuthentication validates the wiring and returns the handlers.
//
// Every dependency is checked. A nil port here would surface as a panic during
// somebody's login rather than as a refusal to start, and this repository has
// already shipped three adapters that were built, tested and constructed by no
// binary.
func NewAuthentication(deps AuthenticationDeps) (*Authentication, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: authentication needs %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Entropy == nil:
		return nil, missing("an entropy source")
	case deps.Index == nil:
		return nil, missing("an email indexer; without one no identifier resolves to an account")
	case deps.Limiter == nil:
		return nil, missing("an attempt limiter; without one password guessing is unthrottled " +
			"and nothing counts it")
	case deps.Hasher == nil:
		return nil, missing("a password hasher")
	case deps.Credentials == nil:
		return nil, missing("a credential store")
	case deps.Accounts == nil:
		return nil, missing("an account directory")
	case deps.Users == nil:
		return nil, missing("a user loader")
	case deps.Sessions == nil:
		return nil, missing("a session loader")
	case deps.Live == nil:
		return nil, missing("a live-session list; without one \"sign out everywhere\" finds " +
			"nothing to sign out and reports success")
	case deps.Tokens == nil:
		return nil, missing("a session-token store; without one a session is appended to the " +
			"log and nothing can ever present it")
	case deps.Sealer == nil:
		return nil, missing("a sealer for stored TOTP secrets")
	case deps.Secrets == nil:
		return nil, missing("a TOTP secret store")
	case deps.Verifier == nil:
		return nil, missing("a TOTP verifier")
	case deps.Breach == nil:
		return nil, missing("a breach checker; login-time screening is the only moment an " +
			"existing password can be re-screened (identity.md §4.1)")
	case deps.Appender == nil:
		return nil, missing("a multi-stream appender")
	case deps.IdleWindow < 0 || deps.AbsoluteWindow < 0 || deps.ProofWindow < 0:
		return nil, fmt.Errorf("identity/app: a session window may not be negative")
	}

	idle := deps.IdleWindow
	if idle == 0 {
		idle = DefaultIdleWindow
	}
	absolute := deps.AbsoluteWindow
	if absolute == 0 {
		absolute = DefaultAbsoluteWindow
	}
	if idle > absolute {
		// The domain refuses this per session, which would make every login fail
		// with a validation error naming two deadlines the user never chose.
		// Refused at wiring time so the misconfiguration is a refusal to start.
		return nil, fmt.Errorf("identity/app: an idle window of %s exceeds the absolute window "+
			"of %s, so the idle deadline would never fire", idle, absolute)
	}
	proof := deps.ProofWindow
	if proof == 0 {
		proof = DefaultProofWindow
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	// A nop rather than a required dependency: metrics are an optimisation of
	// visibility, and a login path that refused to build without them would make
	// an observability gap into an outage (ADR-010). The composition root is
	// expected to pass one, and its test asserts that.
	observer := deps.Observer
	if observer == nil {
		observer = nopAuthObserver{}
	}
	if deps.Epochs == nil {
		// A warning rather than a refusal, for the same reason authz.NewGuard warns
		// about absent tombstones: revocation still WORKS without it — the session
		// stops resolving — and refusing to start would take the login path down for
		// a cache. What is lost is the bound on how long a permit already cached for
		// this principal keeps authorizing, so the loss is stated in the words an
		// operator would need to recognise it.
		log.Warn("identity: no revocation epochs are wired; a permit already cached for a " +
			"principal keeps authorizing for up to the decision TTL after their sessions " +
			"are revoked")
	}
	return &Authentication{
		clock: deps.Clock, entropy: deps.Entropy, index: deps.Index,
		limiter: deps.Limiter, hasher: deps.Hasher, credentials: deps.Credentials,
		accounts: deps.Accounts, users: deps.Users, sessions: deps.Sessions,
		live: deps.Live, tokens: deps.Tokens, sealer: deps.Sealer,
		secrets: deps.Secrets, verifier: deps.Verifier, breach: deps.Breach,
		appender: deps.Appender, epochs: deps.Epochs,
		idle: idle, absolute: absolute, proofTTL: proof, log: log,
		observer:     observer,
		tokenEntropy: rand.Reader,
		schemas:      deps.Schemas,
	}, nil
}

// InvalidatesAuthorization reports whether a revocation also invalidates the
// authorization decisions cached for the subject.
//
// Exposed for the composition root's test, mirroring authz.Guard.HasTombstones.
// The port is optional and its absence changes nothing observable at runtime —
// revocations still append, sessions still stop resolving, every test still
// passes — so an assertion is the only thing that can notice it was never wired.
func (a *Authentication) InvalidatesAuthorization() bool { return a.epochs != nil }

// ---------------------------------------------------------------------------
// Authenticate
// ---------------------------------------------------------------------------

// AuthenticateCommand is one login attempt.
type AuthenticateCommand struct {
	// Identifier is the address as typed. It is normalized and reduced to a blind
	// index here, and neither the raw nor the normalized form reaches an event, a
	// log line or an error message (ADR-002).
	Identifier string

	// Password is the raw secret as typed. Normalized under RFC 8265's
	// OpaqueString profile by the hasher, at both set and verify.
	Password string

	// Code is the second factor, empty on the first leg of a login. When it is
	// empty and the password is correct, the answer is a challenge rather than a
	// session.
	Code string

	// DeviceID is a pseudonym for the client. The device name, platform, user
	// agent and address are personal data and belong in the vault under it —
	// never here, because this value goes into events.
	DeviceID string

	// IdempotencyKey derives the event ids, so a retried attempt collapses into
	// the original append instead of writing the outcome twice.
	IdempotencyKey string
}

// AuthenticateResult reports what an attempt established.
//
// A refusal never arrives here: it is an error, and it is the same error for
// every cause. What this distinguishes is only the two SUCCESSFUL shapes — the
// first factor passed and a second is owed, or every factor passed.
type AuthenticateResult struct {
	// SecondFactorRequired reports that the password was correct and the
	// authentication is not finished. Proof is zero in that case, and a zero Proof
	// mints nothing.
	SecondFactorRequired bool

	// Offered lists the second-factor kinds this account can complete with. Method
	// KINDS only — never credential ids, which would let a caller enumerate the
	// account's authenticators.
	Offered []contract.MethodKind

	// Proof is the evidence CreateSession requires. Non-zero only when every
	// factor was satisfied.
	Proof Proof

	// Position is the log position of the append, for read-your-writes.
	Position eventsourcing.Position
}

// Proof is evidence that THIS process completed an authentication.
//
// Every field is unexported and there is no exported constructor, so a Proof can
// only come from Authenticate returning one. That is the whole design: CreateSession
// takes a Proof instead of a subject id, so a handler that has authenticated
// nobody has nothing to hand it, and its zero value creates nothing.
//
// It is deliberately NOT serializable and must not be made so. A Proof that could
// be written down is a bearer token for an authentication, with none of a session
// token's storage, revocation or deadline.
type Proof struct {
	userID    ids.UserID
	subjectID string
	methods   []contract.MethodKind
	aal       contract.AssuranceLevel
	rotate    bool
	at        time.Time

	// bootstrap marks the one authentication that legitimately stops below AAL2:
	// an account that has never held a second factor, presenting the only factor
	// it has, in order to enrol the one it is required to have.
	//
	// Unexported like every other field, and set on exactly one path in this
	// file. It is the carve-out CreateSession consults, so making it settable from
	// outside would turn "a session below AAL2" from a state the domain reaches
	// into a value a caller can ask for.
	bootstrap bool
}

// SubjectID reports whose authentication this proves. Exposed because a caller
// has to correlate the login with the session it is about to mint; nothing else
// about a Proof is readable, and nothing about it is settable.
func (p Proof) SubjectID() string { return p.subjectID }

// AAL reports the assurance level the ceremony reached.
func (p Proof) AAL() contract.AssuranceLevel { return p.aal }

// Authenticate verifies an identifier and a password, and either demands a second
// factor or completes the ceremony.
//
// # Order of operations, and why each step is where it is
//
//  1. normalize the identifier and derive its blind index — pure computation, no
//     account state, so it cannot leak by timing
//  2. consult the attempt ceiling, BEFORE any hashing. Every attempt is counted
//     whether or not it is allowed; a limiter that only counted permitted attempts
//     would freeze at exactly the threshold and let an attacker over the line
//     continue for free
//  3. resolve the identifier to an account; a miss verifies the dummy verifier
//     and fails, at the same cost as a wrong password
//  4. verify the password — ALWAYS, before the account's state is consulted, so
//     that a suspended, deactivated or unverified account costs exactly what a
//     wrong password costs
//  5. ask the aggregate whether it may authenticate at all
//  6. re-derive the verifier if it has fallen below current policy — the same
//     single moment the plaintext exists (identity.md §4)
//  7. screen the plaintext against the breach corpus, likewise. It never blocks
//     the login
//  8. with no code: append SecondFactorChallenged and stop. With one: verify it,
//     append AuthenticationSucceeded and return the Proof
//
// # The three layers that throttle guessing, and what each is for
//
// The attempt ceiling in step 2 is the first, it is scoped to the identifier, and
// it FAILS OPEN — an unreachable counter lets every attempt through. The mandatory
// second factor is the second, and it is what makes the fail-open trade defensible:
// guessing a password alone produces no session. The per-authenticator lockout is
// the third, and its job is the case the other two miss — an attacker who already
// holds the password and grinds the second factor slowly enough to stay under the
// ceiling, or with the ceiling degraded and refusing nothing.
//
// The lockout is per AUTHENTICATOR and never per account, and the domain refuses
// to apply it to a primary factor at all (domain.User.RecordAuthenticatorFailure).
// A password lockout would be a denial of service against any address an attacker
// can name; a second-factor lockout can only be aimed at an account whose password
// the attacker already has. Nothing about it reaches the caller: a locked-out
// credential is absent from the credential store's usable lookup and unusable to
// the aggregate, so it produces the same refusal, at the same cost, as a wrong
// password.
//
// # What is deliberately not here
//
// A rate-limited attempt appends NO event. That is a departure from "every attempt
// is an event" and it is the one place the rule cannot hold: an attempt refused by
// the ceiling is refused by definition without limit, so appending one event per
// refusal hands an unauthenticated caller an unbounded write to the log against a
// single address. It is counted by the limiter and logged here instead.
func (a *Authentication) Authenticate(
	ctx context.Context, cmd AuthenticateCommand,
) (AuthenticateResult, error) {
	if cmd.IdempotencyKey == "" {
		return AuthenticateResult{}, errs.ValidationFailedf("an idempotency key is required")
	}

	email, err := domain.NormalizeEmail(cmd.Identifier)
	if err != nil {
		// An address this system will not accept names no account. Refused with the
		// ordinary refusal rather than a validation message, because "that is not a
		// valid address" and "that address has no account" are two answers a
		// probing caller can tell apart.
		return AuthenticateResult{}, errRefused()
	}
	index, err := a.index.Of(email)
	if err != nil {
		return AuthenticateResult{}, errRefused()
	}
	if cmd.Password == "" {
		// Refused before the ceiling and before any hashing. It discloses nothing
		// about the account — no account state is consulted to produce it — and the
		// answer is the same one every other refusal gives.
		return AuthenticateResult{}, errRefused()
	}

	now := a.clock.Now().UTC()
	if refused, err := a.throttle(ctx, index); err != nil {
		return AuthenticateResult{}, err
	} else if refused {
		return AuthenticateResult{}, errRefused()
	}

	account, err := a.accounts.AccountByEmailIndex(ctx, index)
	if err != nil {
		if !errors.Is(err, ErrNoSuchAccount) {
			// The lookup could not be PERFORMED. Not a login answer: reporting a
			// database outage as "wrong password" turns an incident into a global
			// wave of failures that look like user error and get investigated as
			// such. It discloses nothing — every identifier gets it.
			return AuthenticateResult{}, fmt.Errorf("resolving an identifier: %w", err)
		}
		a.verifyUnknown(ctx, cmd.Password)
		return a.refuse(ctx, cmd, index, "", contract.ReasonNoSuchIdentifier, now)
	}

	user, err := a.users.Load(ctx, account.UserID.String())
	if err != nil {
		return AuthenticateResult{}, fmt.Errorf("loading the account for an authentication: %w", err)
	}
	subjectID := user.SubjectID()
	if subjectID == "" {
		// The projection named an account whose stream holds nothing. Treated as an
		// unknown identifier, dummy hash included, because the alternative answers
		// faster for an address that is mid-registration than for one that is not.
		a.verifyUnknown(ctx, cmd.Password)
		return a.refuse(ctx, cmd, index, "", contract.ReasonNoSuchIdentifier, now)
	}

	cred, err := a.credentials.Find(ctx, subjectID)
	if err != nil {
		if !errors.Is(err, ErrNoPasswordCredential) {
			return AuthenticateResult{}, fmt.Errorf("reading a password credential: %w", err)
		}
		// A passwordless account, or one whose password is locked out. Both cost a
		// hash, for the same reason an unknown identifier does.
		a.verifyUnknown(ctx, cmd.Password)
		return a.refuse(ctx, cmd, index, subjectID, contract.ReasonIncomplete, now)
	}

	ok, err := a.hasher.Verify(ctx, cmd.Password, cred.Verifier, account.UserID, cred.ID)
	switch {
	case errors.Is(err, ErrVerifierUnreadable):
		// The verifier will not open under its own row: a pepper key destroyed too
		// early, or a row copied from another account. NOT a wrong password, and
		// recorded loudly — but answered identically, because an internal error here
		// would confirm that this address has an account with a password.
		a.log.ErrorContext(ctx, "a stored password verifier could not be read",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "pepper_version", cred.PepperVersion,
			"error", err)
		return a.refuse(ctx, cmd, index, subjectID, contract.ReasonWrongPassword, now)
	case err != nil:
		// The check could not be performed — the hasher is over capacity, or the
		// pepper key is unreachable. Surfaced rather than counted against the user.
		return AuthenticateResult{}, fmt.Errorf("verifying a password: %w", err)
	case !ok:
		a.countFailure(ctx, user, subjectID, cred.ID, cmd.IdempotencyKey, now)
		return a.refuse(ctx, cmd, index, subjectID, contract.ReasonWrongPassword, now)
	}

	// The password credential was used successfully, so its consecutive-failure
	// count is cleared HERE rather than at the end of the ceremony. The count is
	// per authenticator, and this authenticator succeeded; deferring it until the
	// second factor also passed would let an abandoned login leave a correct
	// password looking like a failing one.
	a.recordSuccess(ctx, subjectID, cred.ID)

	if reason, allowed := user.CanAuthenticate(); !allowed {
		// Unverified, incomplete, deactivated, suspended. The reason goes in the
		// event; the caller gets what a wrong password gets, and by now it has cost
		// the same as one.
		return a.refuse(ctx, cmd, index, subjectID, reason, now)
	}

	// After the state gate rather than before it, so a refused account never writes
	// to its own stream — and so the extra Argon2id evaluation a rehash costs is
	// never paid on a path that ends in a refusal, where an unequal cost would be
	// measurable. Every refusal above still pays exactly one verification.
	a.rehashIfNeeded(ctx, user, subjectID, account.UserID, cred, cmd.Password,
		cmd.IdempotencyKey, now)

	// The one moment the plaintext exists. Screening never blocks the login: the
	// credential is correct and the user is legitimate, so a corpus hit restricts
	// the SESSION to credential endpoints instead (identity.md §4.1).
	rotate := a.screen(ctx, subjectID, cmd.Password)

	if cmd.Code == "" && user.NeedsFirstSecondFactor() {
		return a.bootstrapProof(ctx, cmd, index, user, account.UserID, subjectID, rotate, now)
	}

	offered := secondFactorKinds(user)
	if cmd.Code == "" {
		if len(offered) == 0 {
			// Activation requires a real second factor, so an account arrives here
			// with at least one — but a lockout can take the last one away, and it
			// deliberately does not check whether it is the last (a second factor
			// being ground is exactly the one that must go). So this is reachable
			// for a locked-out account with no recovery codes, as well as for an
			// account activated by something other than this codebase. Both need an
			// operator, and both give the caller the ordinary refusal.
			a.log.ErrorContext(ctx, "an authenticable account offers no second factor",
				"module", "identity", "subject_id", subjectID)
			return a.refuse(ctx, cmd, index, subjectID, contract.ReasonIncomplete, now)
		}
		position, err := a.appendAttempt(ctx, cmd.IdempotencyKey, index, subjectID,
			&contract.SecondFactorChallenged{
				SubjectID:    subjectID,
				Offered:      offered,
				DeviceID:     cmd.DeviceID,
				ChallengedAt: now,
			})
		if err != nil {
			return AuthenticateResult{}, err
		}
		return AuthenticateResult{
			SecondFactorRequired: true,
			Offered:              offered,
			Position:             position,
		}, nil
	}

	reason, ok := a.verifySecondFactor(ctx, user, subjectID, cmd.Code, cmd.IdempotencyKey, now)
	if !ok {
		return a.refuse(ctx, cmd, index, subjectID, reason, now)
	}

	// domain.AALFor, never a literal. Password plus a second factor is AAL2 because
	// the set spans two independent things, and hardcoding the number here would be
	// a policy decision taken in a place nobody looks when the policy changes.
	methods := []contract.MethodKind{contract.MethodPassword, contract.MethodTOTP}
	aal := domain.AALFor(methods)
	if !aal.Valid() {
		return AuthenticateResult{}, errs.Internalf(
			"an authentication reached assurance level %d, which no session may record", int(aal))
	}
	if user.IsDowngrade(methods) {
		// Compared against StrongestUsablePrimary inside the aggregate, so an
		// ordinary password login does not read as a downgrade against the account's
		// own TOTP. Recorded as a risk signal, never a refusal: a user who has lost
		// their passkey is entitled to the fallback.
		a.log.WarnContext(ctx, "an authentication used a weaker primary factor than the "+
			"account has available",
			"module", "identity", "subject_id", subjectID)
	}

	position, err := a.appendAttempt(ctx, cmd.IdempotencyKey, index, subjectID,
		&contract.AuthenticationSucceeded{
			SubjectID:   subjectID,
			Methods:     methods,
			AAL:         aal,
			DeviceID:    cmd.DeviceID,
			SucceededAt: now,
		})
	if err != nil {
		return AuthenticateResult{}, err
	}
	return AuthenticateResult{
		Proof: Proof{
			userID:    account.UserID,
			subjectID: subjectID,
			methods:   methods,
			aal:       aal,
			rotate:    rotate,
			at:        now,
		},
		Position: position,
	}, nil
}

// bootstrapProof completes the one authentication that stops at AAL1: an
// account that has never held a second factor, presenting the only factor it
// has.
//
// # Why this is not a half-authentication
//
// identity.md §3 describes a `PendingSecondFactor` ticket — a partially
// completed ceremony, held for five minutes, that may call exactly one RPC — and
// ADR-050 refuses to build one. This is NOT that, and the distinction is worth
// stating because the two look alike from a distance and are opposite in the
// part that matters. The ceremony here is COMPLETE: every factor the account
// possesses was presented and verified, nothing is owed, and what it earns is an
// ordinary session — stored, revocable, subject to both deadlines, recorded in
// the log. What is different is only its assurance level, and AAL1 is the honest
// description of a password-only authentication rather than a fiction the
// session carries around.
//
// The two also fail differently, which is the practical test. A
// half-authentication is dangerous when a gate FORGETS to look at it: an
// interceptor that does not know about the ticket accepts it as a full session.
// An AAL1 session is compared against every declared floor by the same code that
// compares an AAL2 one, so a gate that forgets nothing still refuses it wherever
// AAL2 is required. Its authority is bounded by a comparison that already runs
// on every request, not by a special case somebody has to remember.
//
// # What bounds it
//
// The bounding is the policy annotations and nothing here. Only EnrollTotp and
// ConfirmTotp declare a bootstrap assurance floor, and the gate applies that
// floor only while the AUTHENTICATOR reports the account has never held a proven
// second factor (policy.Policy.AALFloor). Adding a second check in this layer —
// "and the handler must also verify the account is pending" — would be a
// duplicate of a rule that is already declared beside the RPC, and duplicates of
// authorization rules disagree eventually.
//
// # Where an account is refused instead
//
// This is reached only after CanAuthenticate admitted the account, so the
// address is proven and no factor has ever been held. An account that HAS a
// factor takes the ordinary path: a challenge, then a code. That is the property
// the stolen-password attack turns on, and it is enforced by the aggregate
// (NeedsFirstSecondFactor) rather than by the shape of this function.
//
// A caller that sends a code while in this state does not arrive here at all —
// Authenticate only takes this branch for an empty code — and is refused by the
// ordinary second-factor path, because there is no enrolment for the code to
// verify against. Refusing is the right answer: a code presented by an account
// with no authenticator is either a mistake or somebody else's code.
func (a *Authentication) bootstrapProof(
	ctx context.Context,
	cmd AuthenticateCommand,
	index contract.EmailIndex,
	user *domain.User,
	userID ids.UserID,
	subjectID string,
	rotate bool,
	now time.Time,
) (AuthenticateResult, error) {
	// AALFor over the methods actually used, never a literal: a password alone is
	// AAL1 because the set spans one thing, and writing the number here would put
	// a policy decision where nobody looks when the policy changes.
	methods := []contract.MethodKind{contract.MethodPassword}
	aal := domain.AALFor(methods)
	if aal != contract.AAL1 || !aal.Valid() {
		// Unreachable while AALFor maps a lone password to AAL1, and refused rather
		// than passed on if that ever changes: this path exists to mint the WEAKEST
		// session the system has, and one that silently claimed more would be handed
		// the authority of a completed two-factor login.
		return AuthenticateResult{}, errs.Internalf(
			"a first-enrolment authentication reached assurance level %d, which is not the "+
				"level a single primary factor establishes", int(aal))
	}

	// Recorded in the journal like every other completed authentication, with the
	// level it actually reached. An enrolment session that left no trace would be
	// the one login shape invisible to `login_history_view` and therefore to the
	// stuffing signal that reads it.
	position, err := a.appendAttempt(ctx, cmd.IdempotencyKey, index, subjectID,
		&contract.AuthenticationSucceeded{
			SubjectID:   subjectID,
			Methods:     methods,
			AAL:         aal,
			DeviceID:    cmd.DeviceID,
			SucceededAt: now,
		})
	if err != nil {
		return AuthenticateResult{}, err
	}

	a.log.InfoContext(ctx, "an account with no second factor authenticated at AAL1 to enrol "+
		"its first one",
		"module", "identity", "subject_id", subjectID,
		"state", user.State().String())

	return AuthenticateResult{
		Proof: Proof{
			userID:    userID,
			subjectID: subjectID,
			methods:   methods,
			aal:       aal,
			rotate:    rotate,
			at:        now,
			bootstrap: true,
		},
		Position: position,
	}, nil
}

// throttle consults the attempt ceiling and reports whether to refuse.
//
// The limiter FAILS OPEN, and the degraded decision is surfaced here rather than
// swallowed. A ceiling that has silently stopped counting is indistinguishable
// from one that is never reached, and the fail-open trade is only defensible while
// somebody can see it has been taken (ratelimit.Limiter.Allow).
func (a *Authentication) throttle(ctx context.Context, index contract.EmailIndex) (bool, error) {
	// The scope is the keyed index, not the address: it is an HMAC, so it is safe
	// in a cache key and in the log line below, and it is stable under the
	// normalization the address has already been through.
	decision, err := a.limiter.Allow(ctx, string(index))
	if err != nil {
		// Counted as well as logged. Fail-open means an unreachable counter lets
		// every attempt through unthrottled, and a log line is not something an
		// alert rule can fire on.
		a.observer.CeilingUnavailable()
		a.log.ErrorContext(ctx, "the authentication attempt ceiling could not be evaluated; "+
			"the attempt was allowed unthrottled",
			"module", "identity", "email_index", string(index),
			"degraded", decision.Degraded, "error", err)
		return false, nil
	}
	if !decision.Allowed() {
		// The only trace of this attempt. No event is appended above the ceiling —
		// refusals are unbounded, so one event each would be an unbounded log write
		// driven by an unauthenticated caller — which means these attempts are
		// invisible to `login_history_view` and therefore to the stuffing signal
		// that reads it. The counter is what keeps them observable.
		a.observer.Throttled(decision.Rule)
		a.log.WarnContext(ctx, "an authentication attempt was refused by the attempt ceiling",
			"module", "identity", "email_index", string(index),
			"rule", decision.Rule, "retry_after", decision.RetryAfter,
			"reason", string(contract.ReasonRateLimited))
		return true, nil
	}
	return false, nil
}

// verifySecondFactor checks a TOTP code and claims its time step.
//
// Slice 1 ships TOTP as the only second factor a login can complete with. A
// recovery code is redeemed through SecondFactor.ConsumeRecoveryCode, which is a
// different ceremony with a different risk profile — one is a device the user
// still holds, the other is a sheet of paper they may have lost.
//
// Every branch returns the reason for the EVENT. The caller answers all of them
// identically.
func (a *Authentication) verifySecondFactor(
	ctx context.Context, user *domain.User, subjectID, code, idempotencyKey string, now time.Time,
) (contract.FailureReason, bool) {
	stored, err := a.secrets.Find(ctx, subjectID)
	if err != nil {
		if !errors.Is(err, ErrNoTotpCredential) {
			a.log.ErrorContext(ctx, "a TOTP enrolment could not be read",
				"module", "identity", "subject_id", subjectID, "error", err)
		}
		return contract.ReasonWrongSecondFactor, false
	}
	if !stored.Enabled {
		// Provisioned and never proven. Accepting it would let a secret that exists
		// only on this side of the exchange complete a login.
		return contract.ReasonWrongSecondFactor, false
	}
	// The aggregate is the authority on whether the method may take part, not the
	// row: a credential the account's own log does not record as usable must not
	// authenticate, whatever the table says.
	if m, ok := user.Method(stored.ID); !ok || m.Kind != contract.MethodTOTP || !m.Usable() {
		a.log.ErrorContext(ctx, "a stored TOTP credential is not one the account's own log "+
			"records as usable",
			"module", "identity", "subject_id", subjectID, "credential_id", stored.ID.String())
		return contract.ReasonWrongSecondFactor, false
	}

	secret, err := a.sealer.Open(stored.Sealed, subjectID, stored.ID)
	if err != nil {
		// An outage or tampering, not user error — and still the ordinary refusal,
		// because an internal error would answer "this account has an authenticator"
		// to anyone who asked.
		a.log.ErrorContext(ctx, "a stored TOTP secret could not be opened",
			"module", "identity", "subject_id", subjectID,
			"credential_id", stored.ID.String(), "key_version", stored.KeyVersion,
			"error", err)
		return contract.ReasonWrongSecondFactor, false
	}

	valid, err := a.verifier.Verify(ctx, secret, code, stored.ID, now)
	switch {
	case errors.Is(err, ErrCodeReplayed):
		// A VALID code presented twice. Not a typo: somebody has observed a real
		// code, which is the strongest signal this flow produces.
		a.log.WarnContext(ctx, "a TOTP code was replayed during an authentication",
			"module", "identity", "subject_id", subjectID,
			"credential_id", stored.ID.String())
		a.countFailure(ctx, user, subjectID, stored.ID, idempotencyKey, now)
		return contract.ReasonReplayedCode, false
	case err != nil:
		// The replay guard could not be consulted. It fails closed by construction,
		// so the attempt is refused — and logged, because an outage that looks like
		// a wave of wrong codes is an outage nobody investigates.
		a.log.ErrorContext(ctx, "a TOTP code could not be verified",
			"module", "identity", "subject_id", subjectID,
			"credential_id", stored.ID.String(), "error", err)
		return contract.ReasonWrongSecondFactor, false
	case !valid:
		a.countFailure(ctx, user, subjectID, stored.ID, idempotencyKey, now)
		return contract.ReasonWrongSecondFactor, false
	}

	a.recordSuccess(ctx, subjectID, stored.ID)
	return "", true
}

// verifyUnknown spends an Argon2id evaluation on an identifier that matched no
// usable credential.
//
// This function looks like waste and is a security control. Argon2id is ~51 ms and
// dominates everything else a login does, so an implementation that skips it when
// there is no account answers "no such address" in microseconds and "wrong
// password" in milliseconds — an account-existence oracle that reads the same on
// the wire, passes every functional test, and is measurable from any network.
//
// Do not "optimise" this away. If the dummy verifier cannot be built the cost is
// no longer paid, which is why that failure is logged as the security regression
// it is rather than ignored.
//
// The result is discarded on purpose: the verifier is over a password drawn from
// crypto/rand that nothing has ever been told, so the only outcomes are false and
// an error, and both mean the same thing to the caller.
func (a *Authentication) verifyUnknown(ctx context.Context, password string) {
	a.dummyOnce.Do(func() { a.dummy = a.buildDummy(ctx) })

	if a.dummy.err != nil {
		a.log.ErrorContext(ctx, "no dummy verifier is available, so an unknown identifier "+
			"is refused faster than a wrong password; account existence is measurable "+
			"from response time until this is fixed",
			"module", "identity", "error", a.dummy.err)
		return
	}
	if _, err := a.hasher.Verify(
		ctx, password, a.dummy.verifier, a.dummy.user, a.dummy.cred,
	); err != nil {
		a.log.ErrorContext(ctx, "the dummy verifier could not be checked",
			"module", "identity", "error", err)
	}
}

// buildDummy produces the verifier verifyUnknown checks against, once per process.
//
// The password is 256 bits from crypto/rand and is discarded on return, so there
// is no value anywhere in the system that verifies against this row — it is not a
// credential, it is a unit of work shaped exactly like one.
//
// Built lazily rather than in the constructor because it needs the pepper key,
// which means a round trip: a constructor that did I/O would make wiring depend on
// a reachable OpenBao, and the failure would arrive at startup for a mechanism
// only the login path uses.
func (a *Authentication) buildDummy(ctx context.Context) dummyVerifier {
	raw := make([]byte, dummyPasswordBytes)
	if _, err := io.ReadFull(a.tokenEntropy, raw); err != nil {
		return dummyVerifier{err: fmt.Errorf("generating a dummy password: %w", err)}
	}
	now := a.clock.Now().UTC()
	out := dummyVerifier{
		user: ids.New[ids.User](now, a.entropy),
		cred: ids.New[ids.Credential](now, a.entropy),
	}
	// Non-zero ids, and the SAME pair verifyUnknown verifies under: the hasher
	// authenticates them into the sealed digest, so a mismatched pair would fail to
	// open and return before doing any Argon2id work at all — which is precisely
	// the shortcut this exists to prevent.
	verifier, err := a.hasher.Hash(ctx, base64.RawURLEncoding.EncodeToString(raw), out.user, out.cred)
	if err != nil {
		return dummyVerifier{err: fmt.Errorf("building a dummy verifier: %w", err)}
	}
	out.verifier = verifier
	return out
}

// screen checks the plaintext against the breach corpus and reports whether the
// session must be restricted.
//
// Fail OPEN and say so. An unreachable corpus is an outage at a third party;
// blocking on it would lock out every user in the system, which is the opposite
// of what a control protecting users from their own weak passwords should do
// (identity.md §4.1, ADR-010's deliberate counterexample).
func (a *Authentication) screen(ctx context.Context, subjectID, password string) bool {
	breached, corpus, err := a.breach.Breached(ctx, password)
	switch {
	case err != nil:
		a.log.WarnContext(ctx, "breach screening did not run; the password was accepted unscreened",
			"module", "identity", "subject_id", subjectID,
			"reason", "breach_corpus_unavailable", "error", err)
		return false
	case breached:
		// The login is ACCEPTED. The session it produces is restricted to profile
		// and credential endpoints until the password is changed — the corpus name
		// is logged and never returned, because "your password is in a breach" said
		// to whoever is typing confirms they have the right password.
		a.log.WarnContext(ctx, "an authentication used a password found in a breach corpus; "+
			"the session requires credential rotation",
			"module", "identity", "subject_id", subjectID, "corpus", corpus)
		return true
	default:
		return false
	}
}

// refuse records why an attempt failed and returns the one refusal.
//
// The reason reaches the EVENT and the log. It never reaches the returned error,
// and the two must not be brought together by a caller that maps one to the
// other — that mapping is the oracle this whole file is shaped to deny.
//
// A failure to append is reported instead of the refusal, because it means the
// attempt was not recorded: silently downgrading it to "wrong password" would make
// a broken audit trail look like ordinary user error, which is the state an
// attacker wants the system in.
func (a *Authentication) refuse(
	ctx context.Context,
	cmd AuthenticateCommand,
	index contract.EmailIndex,
	subjectID string,
	reason contract.FailureReason,
	now time.Time,
) (AuthenticateResult, error) {
	a.log.InfoContext(ctx, "an authentication attempt was refused",
		"module", "identity", "email_index", string(index),
		"subject_id", subjectID, "reason", string(reason))

	// SubjectID is EMPTY when the identifier matched no account, and the projection
	// writes NULL for it. Inventing one would create a permanent record keyed to a
	// person who does not exist here, while the attempt still has to be counted for
	// stuffing detection — which is what the index carries.
	if _, err := a.appendAttempt(ctx, cmd.IdempotencyKey, index, subjectID,
		&contract.AuthenticationFailed{
			SubjectID: subjectID,
			Index:     index,
			Reason:    reason,
			DeviceID:  cmd.DeviceID,
			FailedAt:  now,
		}); err != nil {
		return AuthenticateResult{}, err
	}
	return AuthenticateResult{}, errRefused()
}

// countFailure records one failed attempt against an authenticator and applies
// the account's lockout rule to the new total.
//
// Best-effort bookkeeping: the login has already been decided, so nothing here
// may change the answer. A store that cannot count, an aggregate that refuses,
// and an append that fails are all logged and then dropped — the caller gets the
// same refusal either way, and a lockout that did not land is re-attempted by the
// next failure, because the threshold is a floor rather than an equality.
//
// Every failure goes through here, including a password's, and the decision about
// which of them can lock out is the AGGREGATE'S alone
// (domain.User.RecordAuthenticatorFailure). The alternative — the app checking
// the method's role before calling — would put the rule that stops the lockout
// being a denial-of-service vector in the layer that orchestrates rather than the
// layer that decides, where the next caller would have to remember it.
func (a *Authentication) countFailure(
	ctx context.Context,
	user *domain.User,
	subjectID string,
	cred ids.CredentialID,
	idempotencyKey string,
	now time.Time,
) {
	failures, err := a.credentials.RecordFailure(ctx, cred)
	if err != nil {
		// Logged rather than dropped, because a counter that has stopped counting
		// is what the lockout below reads: the throttle would be silently absent
		// while every ordinary login kept working.
		a.log.ErrorContext(ctx, "a failed authentication could not be counted against its "+
			"credential; the lockout ceiling cannot be evaluated for it",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "error", err)
		return
	}

	locked, err := user.RecordAuthenticatorFailure(cred, int(failures), now)
	if err != nil {
		// The credential store named a method the account's own log does not have.
		// Loud, because that is a disagreement between the row and the stream.
		a.log.ErrorContext(ctx, "a failed authentication could not be attributed to a method "+
			"the account's own log records",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "error", err)
		return
	}
	if !locked {
		if failures >= domain.LockoutThreshold {
			// A primary factor, which is never locked out — see
			// RecordAuthenticatorFailure for why that is a refusal rather than a
			// tuning choice. The count is still the only in-system evidence of a
			// slow grind against one account's password that stays under the
			// attempt ceiling, so it is surfaced here where an alert can reach it.
			a.log.WarnContext(ctx, "an authenticator has passed the lockout threshold in "+
				"consecutive failures and is not one this account's rules lock out",
				"module", "identity", "subject_id", subjectID,
				"credential_id", cred.String(), "failures", failures,
				"threshold", domain.LockoutThreshold)
		}
		return
	}
	a.lockOut(ctx, user, subjectID, cred, failures, idempotencyKey, now)
}

// lockOut records the disabling of one authenticator and then makes the row
// unusable.
//
// # The append comes FIRST, the row second
//
// Both orders lose something if the process dies between them, and this is the
// recoverable one. Log-first leaves an authenticator the aggregate considers
// disabled and the table still returns: the login path consults the aggregate as
// well as the row (verifySecondFactor checks user.Method), so the lockout is
// already in force, and the next failed attempt re-runs this and retries the
// write. Row-first leaves a credential disabled with nothing in the log saying
// why — invisible to the account's own history, invisible to a projection rebuild,
// and indistinguishable from a credential that was never enrolled.
//
// Nothing here can fail the login. It has already been refused; this is what
// happens to the authenticator afterwards.
func (a *Authentication) lockOut(
	ctx context.Context,
	user *domain.User,
	subjectID string,
	cred ids.CredentialID,
	failures int32,
	idempotencyKey string,
	now time.Time,
) {
	stream, err := eventsourcing.NewStreamID(UserCategory, user.ID().String())
	if err != nil {
		a.log.ErrorContext(ctx, "an authenticator lockout could not be addressed to a stream",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "error", err)
		user.ClearUncommitted()
		return
	}
	if _, err := a.append(ctx, idempotencyKey+lockoutKeySuffix, subjectID, stream,
		eventsourcing.ExpectedFor(user), user); err != nil {
		// Dropped, not retried. The aggregate was loaded at the start of this
		// login, so a revision conflict means the account changed underneath it and
		// this decision saw a state that is no longer current. The count is still in
		// the table and still above the threshold, so the next failure locks out
		// against a freshly loaded aggregate.
		a.log.ErrorContext(ctx, "an authenticator reached the lockout ceiling and the lockout "+
			"could not be recorded; the authenticator is still usable",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "failures", failures, "error", err)
		user.ClearUncommitted()
		return
	}

	if err := a.credentials.Disable(ctx, cred); err != nil {
		// The log says disabled and the row does not. Not fatal — the aggregate
		// check refuses the credential on every subsequent attempt — but loud,
		// because the row is what the credential-store lookups filter on and the
		// two must not stay apart.
		a.log.ErrorContext(ctx, "an authenticator was recorded as disabled and its stored "+
			"credential was not; the log is in force and the row disagrees",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "error", err)
	}
	a.log.WarnContext(ctx, "an authenticator was disabled after consecutive failed "+
		"presentations; it must be re-enrolled rather than waited out",
		"module", "identity", "subject_id", subjectID,
		"credential_id", cred.String(), "failures", failures,
		"threshold", domain.LockoutThreshold)
}

// rehashIfNeeded re-derives a stored verifier that has fallen below current
// policy, at the one moment the plaintext exists.
//
// A verifier can only be upgraded from the plaintext, and the plaintext exists in
// this process for the length of one successful verification. Everything else — a
// parameter bump, an algorithm change, a pepper rotation — can find the rows that
// need upgrading and cannot upgrade them, because the value they were derived from
// is gone. So this is not an optimisation: for passwords it is the ONLY mechanism
// that completes a rotation, and without it `pepper_version < n` never reaches
// zero and the old transit key can never be destroyed (identity.md §4).
//
// # Nothing here may fail the login
//
// The user authenticated. Every branch below logs and returns, including the ones
// that mean the database refused the write. A rehash that did not happen leaves a
// verifier that still verifies — it is merely still old — and the next login tries
// again. Turning any of this into a refusal would take a policy upgrade and
// convert it into an outage for the people whose credentials are furthest behind.
//
// # ErrCredentialMoved is dropped, never retried
//
// PasswordCredentials.Rehash is a compare-and-set against the verifier this login
// read. ErrCredentialMoved means the row no longer holds it: the password was
// changed, or the credential was disabled, while this login was in flight.
// Retrying would mean re-reading and writing a re-encoding of the OLD password
// over the new one — quietly restoring a password the user may have replaced
// precisely because it was compromised. The value in hand is stale by definition
// and the correct action is to discard it.
//
// # Cost
//
// One extra Argon2id evaluation, on top of the one this login already paid. ADR-050
// accounts for a completed login as TWO evaluations (one per leg of the ceremony);
// a rehash makes it three on the leg where it fires. It fires once per credential
// per policy change — the next login reads the upgraded verifier and NeedsRehash
// returns false — so the cost is a one-off per user rather than a new steady-state
// rate. The burst it does produce is the whole population passing through once
// after a parameter bump or a pepper rotation, which lands on the hasher's
// concurrency bound rather than on memory.
func (a *Authentication) rehashIfNeeded(
	ctx context.Context,
	user *domain.User,
	subjectID string,
	userID ids.UserID,
	cred PasswordCredential,
	password, idempotencyKey string,
	now time.Time,
) {
	if !a.hasher.NeedsRehash(cred.Verifier) {
		return
	}

	replacement, err := a.hasher.Hash(ctx, password, userID, cred.ID)
	if err != nil {
		a.log.ErrorContext(ctx, "a password verifier is below current policy and could not be "+
			"re-derived; the login was unaffected",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "error", err)
		return
	}

	// The version comes from the hasher rather than from the verifier, because the
	// hasher is the only component that parses that format. It is duplicated into
	// its own column so the rotation job can find stale rows without parsing every
	// one of them.
	switch err := a.credentials.Rehash(
		ctx, cred.ID, cred.Verifier, replacement, a.hasher.PepperVersion(),
	); {
	case errors.Is(err, ErrCredentialMoved):
		// A concurrent password change won the race. Expected, not an incident, and
		// recorded at info: the winning write is the current one and this rehash is
		// discarded rather than layered on top of it.
		a.log.InfoContext(ctx, "a rehash was discarded because the credential changed while "+
			"the login was in flight",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String())
		return
	case err != nil:
		a.log.ErrorContext(ctx, "a re-derived password verifier could not be stored; the "+
			"credential remains below current policy",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "error", err)
		return
	}

	if err := user.RecordPasswordRehash(cred.ID, now); err != nil {
		a.log.ErrorContext(ctx, "a password verifier was upgraded and the account's own log "+
			"does not record the credential",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "error", err)
		user.ClearUncommitted()
		return
	}
	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		a.log.ErrorContext(ctx, "a password rehash could not be addressed to a stream",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "error", err)
		user.ClearUncommitted()
		return
	}
	if _, err := a.append(ctx, idempotencyKey+rehashKeySuffix, subjectID, stream,
		eventsourcing.ExpectedFor(user), user); err != nil {
		// The verifier is upgraded and the evidence is missing. Not retried and not
		// reversed: the row is what verifies a password, and it is now correct. What
		// is lost is the only signal that a rotation is progressing, which is why
		// this is an error rather than a note.
		a.log.ErrorContext(ctx, "a password verifier was upgraded and the event recording it "+
			"could not be appended; the rehash job's progress is unobservable for this row",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.ID.String(), "error", err)
		user.ClearUncommitted()
	}
}

// recordSuccess stamps a credential as used and clears its consecutive-failure
// count. Best-effort, for the same reason countFailure is.
func (a *Authentication) recordSuccess(ctx context.Context, subjectID string, cred ids.CredentialID) {
	if err := a.credentials.RecordSuccess(ctx, cred); err != nil {
		a.log.ErrorContext(ctx, "a successful authentication could not be recorded against "+
			"its credential; the failure count was not cleared",
			"module", "identity", "subject_id", subjectID,
			"credential_id", cred.String(), "error", err)
	}
}

// secondFactorKinds lists the kinds this account can complete an authentication
// with, deduplicated and in a stable order.
//
// Kinds, never credential ids: the list is returned to an unfinished login, and a
// caller holding ids could enumerate an account's authenticators from the outside.
func secondFactorKinds(user *domain.User) []contract.MethodKind {
	var out []contract.MethodKind
	for _, kind := range []contract.MethodKind{
		contract.MethodTOTP, contract.MethodRecoveryCode,
	} {
		for _, m := range user.UsableMethods() {
			if m.Kind == kind {
				out = append(out, kind)
				break
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// CreateSession
// ---------------------------------------------------------------------------

// CreateSessionCommand exchanges a completed authentication for a session.
type CreateSessionCommand struct {
	// Proof comes from Authenticate and cannot be constructed anywhere else.
	Proof Proof

	// DeviceID is a pseudonym for the client, as in AuthenticateCommand.
	DeviceID string

	IdempotencyKey string
}

// CreateSessionResult carries the bearer token back to the caller ONCE.
type CreateSessionResult struct {
	SessionID ids.SessionID
	SubjectID string

	// Token is the plaintext bearer token. Only its digest is stored, so this is
	// the only moment it exists anywhere this system can reach. Never log it,
	// never place it in an event, never return it from any other call.
	Token string

	AAL contract.AssuranceLevel

	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time

	// RequiresCredentialRotation restricts the session to profile and credential
	// endpoints, set when the password that established it was found in a breach
	// corpus.
	RequiresCredentialRotation bool

	Position eventsourcing.Position
}

// CreateSession mints the session a completed authentication earned.
//
// # The append comes FIRST, the token row second
//
// SessionCreated is appended, and only then is the digest written to
// session_token. Both orders lose something if the process dies between them, and
// this is the recoverable one: the log holds a session nothing can present, the
// user signs in again, and the sweep eventually retires the projected row.
//
// The reverse order is not recoverable. It leaves a token row whose session was
// never projected — and SweepSessionTokens finds dead secrets by JOINING
// session_view, so a digest with no session row matches nothing, is never swept,
// and stays in the table for the lifetime of the deployment. A secret that outlives
// every mechanism that could remove it is worse than a session the user has to
// re-establish.
//
// # AAL1 mints nothing, with one carve-out
//
// A second factor is mandatory before an account activates (identity.md §2), so a
// proof below AAL2 normally means a factor was skipped somewhere between Authenticate
// and here. It is refused rather than downgraded: a session that records AAL1 would be
// compared against every min_aal requirement downstream and would honestly pass the
// ones that ask for AAL1, which is precisely the half-authenticated session
// identity.md §3 names as a complete authentication bypass.
//
// The carve-out is the account that has never held a second factor and is
// presenting the only factor it has, in order to enrol the one it is required to
// have (bootstrapProof). Without it that account is deadlocked: enrolment needs a
// session, a session needs AAL2, and AAL2 needs the factor being enrolled.
//
// # The carve-out is NOT the PendingSecondFactor ticket, and the next reader will
// conflate them
//
// identity.md §3 describes a partially-authenticated ticket that may call one
// RPC, and ADR-050 refuses to build it. This is a different object. Nothing is
// owed here: every factor the account has was presented and verified, so the
// ceremony is COMPLETE and what it produces is an ordinary session — a row, a
// digest, both deadlines, revocable, in the log — whose assurance level is AAL1
// because AAL1 is what a password alone establishes.
//
// The difference that matters is how each one fails. A ticket is dangerous when a
// gate does not know about it, because an interceptor that has never heard of the
// ticket treats it as a finished session. An AAL1 session is compared against
// every declared floor by the same line of code that compares an AAL2 one, so a
// gate that knows nothing special still refuses it everywhere AAL2 is required.
// Its authority is bounded by an existing comparison rather than by a special
// case somebody has to remember to write.
//
// # How narrow the carve-out is
//
// It admits exactly AAL1, and only on a Proof this package marked as a first
// enrolment. `bootstrap` is unexported and set on one path, and that path is
// reached only after the aggregate reported the account has never held a proven
// second factor. A Proof that claims bootstrap at any other level is refused
// below rather than clamped, because the two readings of "bootstrap at AAL2" —
// an ordinary login mislabelled, or a level inflated — are both bugs and neither
// should mint a session.
func (a *Authentication) CreateSession(
	ctx context.Context, cmd CreateSessionCommand,
) (CreateSessionResult, error) {
	if cmd.IdempotencyKey == "" {
		return CreateSessionResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	p := cmd.Proof
	switch {
	case p.subjectID == "" || p.userID.IsZero() || p.at.IsZero():
		// The zero Proof, or one whose fields were never set. It mints nothing, and
		// that is the property the unexported fields exist to guarantee.
		return CreateSessionResult{}, errs.Unauthenticatedf("this request has not authenticated")
	case !p.aal.Valid():
		// AAL0 and AAL3 alike: nothing authenticated, and a level this system
		// cannot establish. The domain refuses both again on Create; refusing here
		// keeps the answer identical to every other authentication failure.
		return CreateSessionResult{}, errs.Unauthenticatedf(
			"this authentication has not reached the assurance level a session requires")
	case p.aal < contract.AAL2 && !p.bootstrap:
		return CreateSessionResult{}, errs.Unauthenticatedf(
			"this authentication has not reached the assurance level a session requires")
	case p.bootstrap && p.aal != contract.AAL1:
		// A first-enrolment proof that is not AAL1 is a bug in this package rather
		// than a caller's doing, and it is refused rather than clamped: the two
		// ways it could happen — an ordinary login mislabelled as a bootstrap, or a
		// bootstrap whose level was inflated — both produce a session with more
		// authority than the ceremony earned.
		return CreateSessionResult{}, errs.Internalf(
			"a first-enrolment authentication carries assurance level %d; only AAL1 is a level "+
				"that ceremony can reach", int(p.aal))
	}

	now := a.clock.Now().UTC()
	if now.Sub(p.at) > a.proofTTL || p.at.After(now.Add(a.proofTTL)) {
		// Stale, or from a clock far ahead of this one. A Proof lives for the few
		// microseconds between two calls in one handler; anything older has been
		// stored somewhere, and a stored authentication is a bearer credential with
		// no deadline and no way to revoke it.
		return CreateSessionResult{}, errs.Unauthenticatedf(
			"this authentication is too old to exchange for a session")
	}

	sessionID := ids.New[ids.Session](now, a.entropy)
	session := eventsourcing.NewAggregate(domain.NewSession)
	if err := session.Create(
		sessionID, p.subjectID, cmd.DeviceID, p.aal,
		now.Add(a.idle), now.Add(a.absolute), now, p.rotate,
	); err != nil {
		return CreateSessionResult{}, err
	}

	// Minted before the append so a failure to produce entropy costs nothing but
	// the request. A token generated after the event would leave a session in the
	// log that no caller was ever given a way to use.
	token, digest, err := a.mintSessionToken()
	if err != nil {
		return CreateSessionResult{}, err
	}

	stream, err := eventsourcing.NewStreamID(SessionCategory, sessionID.String())
	if err != nil {
		return CreateSessionResult{}, err
	}
	position, err := a.append(ctx, cmd.IdempotencyKey, p.subjectID, stream,
		eventsourcing.ExpectedFor(session), session)
	if err != nil {
		return CreateSessionResult{}, err
	}

	idleExpiresAt := now.Add(a.idle)
	if err := a.tokens.Issue(ctx, NewSessionToken{
		Digest:        digest,
		SessionID:     sessionID,
		IdleExpiresAt: idleExpiresAt,
	}); err != nil {
		// The session exists in the log and has no secret. Reported as a failure so
		// the caller signs in again rather than being handed a token that resolves
		// to nothing on its next request.
		return CreateSessionResult{}, fmt.Errorf("storing a session token: %w", err)
	}

	return CreateSessionResult{
		SessionID:                  sessionID,
		SubjectID:                  p.subjectID,
		Token:                      token,
		AAL:                        p.aal,
		IdleExpiresAt:              idleExpiresAt,
		AbsoluteExpiresAt:          now.Add(a.absolute),
		RequiresCredentialRotation: p.rotate,
		Position:                   position,
	}, nil
}

// mintSessionToken draws a bearer token and reduces it to what is stored.
//
// The plaintext is returned to exactly one caller and the digest to the store, so
// there is no moment at which a token exists that nothing can resolve, and none at
// which a digest is stored for a token nobody was given.
func (a *Authentication) mintSessionToken() (string, []byte, error) {
	raw := make([]byte, sessionTokenBytes)
	if _, err := io.ReadFull(a.tokenEntropy, raw); err != nil {
		// Refused, never degraded. A short read leaves trailing zero bytes, and a
		// session token whose tail is predictable is one an attacker can search
		// while the user believes they hold 256 bits.
		return "", nil, fmt.Errorf("generating a session token: %w", err)
	}
	// base64url without padding: the token travels in an Authorization header and
	// in a cookie, and '+' and '/' need escaping in neither if they never appear.
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	return plaintext, SessionTokenDigest(plaintext), nil
}

// SessionTokenDigest is what session_token holds and what a presented bearer token
// is hashed to.
//
// SHA-256, not Argon2id, and the rule is where the entropy came from: the token is
// 256 bits from crypto/rand, so there is no candidate list to search and a slow
// hash would add ~51 ms to EVERY authenticated request while buying nothing — and
// would make the authenticator a memory-amplification vector for anyone posting
// garbage tokens (adapter/token makes the same argument for emailed secrets).
//
// The domain separator is length-prefixed with a fixed-width count, so no future
// separator can be chosen to shift the boundary and make two different (domain,
// token) pairs hash alike. It is deliberately NOT one of the app.TokenPurpose
// values: those scope the single-use emailed secrets, which have their own table,
// their own TTLs and their own consume-once semantics, and reusing one here would
// make a session digest and a reset digest interchangeable to any lookup that
// forgot to filter.
//
// Exported because the authenticator (S1-25) must reduce an incoming token exactly
// as this reduced the issued one. Two implementations of that reduction is two
// chances for them to differ, and the failure mode is every session resolving to
// nothing.
func SessionTokenDigest(plaintext string) []byte {
	return digestUnder(sessionTokenDomain, plaintext)
}

// digestUnder is the separator-parameterised form, and it exists to make the
// length prefix TESTABLE.
//
// With the domain hardcoded, removing the prefix cannot be observed from outside:
// one constant means no second (domain, token) pair to collide with, so the
// mutation survives and the property is carried by a comment asking to be trusted.
// Taking the domain as a parameter lets a test present the classic collision pair
// — ("ab", "cd") against ("a", "bcd"), which hash alike under plain concatenation
// and differ under a fixed-width length prefix — so the guarantee is enforced by a
// failing test rather than by an argument.
//
// Unexported and called with one constant in production, so nothing here widens
// the surface: the parameter exists for the test, and the test exists because the
// property has to keep holding when somebody adds a second separator and does not
// think to re-derive it.
func digestUnder(domain, plaintext string) []byte {
	h := sha256.New()
	// Fixed-width count, so the boundary between the domain and the token cannot
	// be moved by choosing a clever separator.
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(domain)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(domain))
	_, _ = h.Write([]byte(plaintext))
	return h.Sum(nil)
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// RevokeSessionCommand ends one session.
type RevokeSessionCommand struct {
	SessionID ids.SessionID

	// SubjectID is who the session must belong to. Required, and checked: without
	// it a caller holding any session id could end anybody's session, because a
	// session id is not a secret — it appears in the device list of every screen
	// that renders one.
	SubjectID string

	// ActorID is who is doing it, and defaults to SubjectID. It differs when an
	// operator or a password reset revokes on the holder's behalf, and that
	// difference is what decides who gets notified.
	ActorID string

	// Reason is a short machine-readable label for the log and the event. It
	// carries no personal data.
	Reason string

	IdempotencyKey string
}

// RevokeSessionResult reports what a revocation did.
type RevokeSessionResult struct {
	// Changed is false when the session was already revoked or already expired.
	// Nothing was appended, and it is not an error: the caller wanted the session
	// unusable and it is.
	Changed  bool
	Position eventsourcing.Position
}

// RevokeSession ends one session.
//
// # Ownership is checked here, and a mismatch is a NotFound
//
// The session's own stream says whose it is, and a request naming somebody else's
// gets the same answer as one naming a session that does not exist. Telling the
// two apart would turn the device list into a probe for which session ids exist.
//
// # The authorization cache is invalidated BEFORE the append
//
// ADR-045 requires a revocation to be visible on the authorization path without
// waiting for a projector. A revoked session stops resolving when the session
// projection applies SessionRevoked; a permit already cached for the SUBJECT does
// not, because the decision cache is keyed by principal and resource and knows
// nothing about which session earned the permit. So the epoch is bumped here, and
// it is bumped first: if it fails, nothing is appended, the caller is told the
// revocation did not happen, and the retry redoes both. Bumping afterwards would
// leave the one state that cannot be repaired — a revocation durably in the log
// whose retry finds the session already revoked, appends nothing, and therefore
// never reaches the invalidation that failed.
//
// No tombstone is written. A tombstone names a relation and a resource and is
// cleared by the access projector confirming it removed the matching tuple; this
// revocation removes no tuple, so nothing would ever confirm one and it would sit
// until the TTL that ADR-045 defines as an alert. See RevocationEpochs.
func (a *Authentication) RevokeSession(
	ctx context.Context, cmd RevokeSessionCommand,
) (RevokeSessionResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return RevokeSessionResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.SessionID.IsZero():
		return RevokeSessionResult{}, errs.ValidationFailedf("a session id is required")
	case cmd.SubjectID == "":
		return RevokeSessionResult{}, errs.ValidationFailedf("a subject id is required")
	}

	session, err := a.sessions.Load(ctx, cmd.SessionID.String())
	if err != nil {
		return RevokeSessionResult{}, fmt.Errorf("loading a session for revocation: %w", err)
	}
	if session.State() == domain.SessionNone || session.SubjectID() != cmd.SubjectID {
		// Unknown and somebody else's are ONE answer. The first is a session id that
		// was never issued; the second is one that was, to a different person.
		return RevokeSessionResult{}, errs.NotFoundf("no such session")
	}

	actor := cmd.ActorID
	if actor == "" {
		actor = cmd.SubjectID
	}
	now := a.clock.Now().UTC()
	if err := session.Revoke(actor, cmd.Reason, now); err != nil {
		return RevokeSessionResult{}, err
	}
	if len(session.Uncommitted()) == 0 {
		// Already revoked, or already expired. The aggregate records nothing for
		// either, deliberately: a revocation tombstone for a session nothing can use
		// would give the access projector a confirmation to wait for that nobody
		// will ever send.
		return RevokeSessionResult{}, nil
	}

	// The SESSION's owner, never cmd.ActorID. An operator or a password reset
	// revokes on somebody else's behalf, and bumping the actor's epoch would flush
	// the wrong person's cache and leave the revoked subject's permits live — an
	// invalidation that reports success and invalidates nobody.
	if err := a.invalidateAuthorization(ctx, session.SubjectID()); err != nil {
		return RevokeSessionResult{}, err
	}

	stream, err := eventsourcing.NewStreamID(SessionCategory, cmd.SessionID.String())
	if err != nil {
		return RevokeSessionResult{}, err
	}
	// conflictOnRace, because the race is REACHABLE here and the caller can act
	// on it: two devices signing the same session out at once is ordinary, the
	// stream already exists, and telling the loser to retry with backoff has it
	// retry a command decided against a revision that is gone.
	//
	// CreateSession does not do this, and the reason is reachability rather than
	// disclosure — it appends to a stream named by a freshly minted session id,
	// so ExpectedFor is "must not exist" and only an id collision could fail it.
	// Both calls sit behind a validated Proof, so neither would be leaking
	// anything by answering CONFLICT.
	position, err := a.append(ctx, cmd.IdempotencyKey, cmd.SubjectID, stream,
		eventsourcing.ExpectedFor(session), session)
	if err != nil {
		return RevokeSessionResult{}, conflictOnRace(err)
	}
	return RevokeSessionResult{Changed: true, Position: position}, nil
}

// RevokeReasonEmailVerified is the reason a verification voids sessions.
//
// It lands in SessionRevoked, which is permanent, so it is a fixed string rather
// than prose assembled at the call site. It exists as a named constant because
// the rule it records — identity.md §7 rule 7, void everything on verification
// and on any reset or recovery — will acquire more callers than the one it has
// today: password reset, email change and federated linking are all required to
// pass a reason of this shape, and a reader grepping for this constant should
// find every one of them.
const RevokeReasonEmailVerified = "email_verified"

// RevokeReasonPasswordReset is the reason a completed password reset voids
// sessions.
//
// It lands in SessionRevoked, which is permanent, so it is a fixed string rather
// than prose assembled at the call site — and it is a DIFFERENT string from
// RevokeReasonEmailVerified because the two mean different things to the person
// receiving the notification. "Your address was verified, so we signed you out"
// is routine; "your password was reset, so we signed you out everywhere" is the
// line that tells somebody their account was taken, and collapsing the two would
// bury it.
//
// Unlike the verification's, this one is NOT a no-op: a reset is performed by an
// account that has a password and therefore can have sessions, and every one of
// them dies (identity.md §4.5). See app.PasswordReset.Complete.
const RevokeReasonPasswordReset = "password_reset"

// RevokeAllSessionsCommand ends every live session for a subject.
type RevokeAllSessionsCommand struct {
	SubjectID string

	// Except is the session to SPARE — "sign out everywhere else", which must not
	// sign the caller out of the device they are asking from.
	//
	// Zero spares nothing, and that is what a password reset and a compromise
	// response need: identity.md §7 rule 7 requires a reset to void every session,
	// including the one that asked for it, because the acting party may be the
	// attacker.
	Except ids.SessionID

	// ActorID is who is doing it, defaulting to SubjectID.
	ActorID string

	Reason string

	IdempotencyKey string
}

// RevokeAllSessionsResult reports what the fan-out did.
type RevokeAllSessionsResult struct {
	// Revoked is how many sessions this call ended. Sessions already revoked or
	// expired are not counted: nothing was appended for them.
	Revoked int

	// Scanned is how many live sessions the work list returned, spared one
	// included. Reported so a caller can see the difference between "nothing to do"
	// and "the list came back empty because it is broken".
	Scanned int

	Position eventsourcing.Position
}

// RevokeAllSessions ends every live session for a subject in ONE atomic append.
//
// # Why one append rather than a loop of appends
//
// "Sign out everywhere" that half-happened is worse than one that failed: the user
// is told every device is signed out and one is not, and nothing in the system
// disagrees with them. The multi-stream append commits every stream or none, so
// the partial outcome does not exist. The cost is that one session whose stream is
// unreadable fails the whole call, which is the correct direction for this
// particular failure to fall.
//
// # The projection is read, never written
//
// The work list comes from session_view and the revocation is an event per
// session; the projector clears revoked_at from those events. A handler that wrote
// the column directly would end sessions with nothing in the log saying so, and a
// rebuild from position zero would bring every one of them back to life.
//
// # One epoch bump covers the whole fan-out
//
// The authorization cache is keyed by principal, not by session, so invalidating
// it is one operation however many sessions were ended — and it happens even when
// Except spares one, because the spared session shares that principal's cached
// permits. A password reset calls this with a zero Except, which is the case the
// invalidation exists for: identity.md §7 rule 7 voids every session including the
// one that asked, and a permit cached before the reset must not survive it.
func (a *Authentication) RevokeAllSessions(
	ctx context.Context, cmd RevokeAllSessionsCommand,
) (RevokeAllSessionsResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return RevokeAllSessionsResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.SubjectID == "":
		return RevokeAllSessionsResult{}, errs.ValidationFailedf("a subject id is required")
	}

	now := a.clock.Now().UTC()
	live, err := a.live.List(ctx, cmd.SubjectID, now)
	if err != nil {
		return RevokeAllSessionsResult{}, fmt.Errorf("listing live sessions: %w", err)
	}

	actor := cmd.ActorID
	if actor == "" {
		actor = cmd.SubjectID
	}
	result := RevokeAllSessionsResult{Scanned: len(live)}

	var (
		appends []eventsourcing.StreamAppend
		revoked []*domain.Session
		seq     int
	)
	meta := a.metadata(ctx, cmd.SubjectID, cmd.IdempotencyKey)
	for _, id := range live {
		if !cmd.Except.IsZero() && id == cmd.Except {
			continue
		}
		session, err := a.sessions.Load(ctx, id.String())
		if err != nil {
			return RevokeAllSessionsResult{}, fmt.Errorf("loading session %s for revocation: %w", id, err)
		}
		if session.SubjectID() != cmd.SubjectID {
			// The row said this session belongs to the subject and its own stream
			// disagrees. The stream wins, and the disagreement is loud: it means the
			// projection was written by something other than the projector.
			a.log.ErrorContext(ctx, "a session listed for a subject belongs to another on its "+
				"own stream; it was not revoked",
				"module", "identity", "subject_id", cmd.SubjectID, "session_id", id.String())
			continue
		}
		if err := session.Revoke(actor, cmd.Reason, now); err != nil {
			return RevokeAllSessionsResult{}, err
		}
		pending := session.Uncommitted()
		if len(pending) == 0 {
			// Revoked or expired between the list and the load. Not an error and not
			// rare — the view lags the log by design.
			continue
		}

		stream, err := eventsourcing.NewStreamID(SessionCategory, id.String())
		if err != nil {
			return RevokeAllSessionsResult{}, err
		}
		events := make([]eventsourcing.PendingEvent, 0, len(pending))
		for _, e := range pending {
			events = append(events, eventsourcing.PendingEvent{
				ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey, seq),
				Event: e,
				// Stamped per EVENT TYPE, not once for the command: two events of
				// one command can sit at different schema versions.
				Meta: eventsourcing.StampSchemaVersion(meta, a.schemas, e.EventType()),
			})
			seq++
		}
		appends = append(appends, eventsourcing.StreamAppend{
			Stream: stream,
			// The exact loaded revision. A session elevated or revoked between the
			// load and the append is refused rather than layered on top of a state
			// this decision never saw.
			Expected: eventsourcing.ExpectedFor(session),
			Events:   events,
		})
		revoked = append(revoked, session)
	}
	if len(appends) == 0 {
		return result, nil
	}

	// Once, for the subject, before the append — see RevokeSession for why the
	// order is not the other one. It covers the SPARED session too, and must: the
	// decision cache is keyed by principal, so there is no per-session entry to
	// keep. The spared session simply recomputes its next check against OpenFGA,
	// which costs one round trip and can only return what that principal is still
	// entitled to.
	if err := a.invalidateAuthorization(ctx, cmd.SubjectID); err != nil {
		return RevokeAllSessionsResult{}, err
	}

	results, err := a.appender.AppendToMany(ctx, appends)
	if err != nil {
		return RevokeAllSessionsResult{}, err
	}
	if len(results) == 0 {
		return RevokeAllSessionsResult{}, errs.Internalf("the append reported no result")
	}
	// Cleared only now. Clearing before the append is durable would lose the events
	// if the caller retried after a transient failure.
	for _, session := range revoked {
		session.ClearUncommitted()
	}
	result.Revoked = len(appends)
	result.Position = results[0].Position
	return result, nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// invalidateAuthorization discards every authorization decision cached for a
// subject, and FAILS the revocation if it cannot (ADR-045).
//
// # Why the error is not swallowed
//
// The alternative is a log line, and a log line here means the user is told
// "signed out everywhere" while a permit cached for their principal keeps
// authorizing for up to authz.MaxDecisionTTL. That is the shape of failure
// ADR-045 was written about: a control that is built, tested, and reports success
// while doing nothing. RevokeAllSessions is what a password reset and a compromise
// response call, so the person on the other side of this decision is somebody who
// already believes they have been attacked.
//
// The cost of failing is a retry, and the retry is safe in both halves: nothing
// has been appended yet, so the caller repeats the command under the same
// idempotency key, and the epoch is a counter whose only observable effect is a
// cache miss — bumping it twice is indistinguishable from bumping it once.
//
// A total Valkey outage does not need this protection, and that is why paying for
// it is cheap: authz.Guard reads the epoch before consulting the cache, and an
// unreadable epoch makes it BYPASS the cache entirely rather than trust it. The
// dangerous failure is the partial one — reads answering, this one INCR refused —
// where stale permits are still being served and nothing else notices. The two are
// indistinguishable from here, so this takes the safe reading of both.
//
// The principal is (user, subject pseudonym), which is what the authenticator puts
// in authz.Principal.ID and therefore what every cached permit is keyed under. A
// UserID here would bump a counter nothing reads and invalidate nothing.
func (a *Authentication) invalidateAuthorization(ctx context.Context, subjectID string) error {
	if a.epochs == nil {
		return nil
	}
	if subjectID == "" {
		// Never reachable from the two callers, both of which validate. Refused
		// rather than passed on, because an empty id would bump one shared counter
		// for "the principal with no id" and report success for every subject.
		return errs.Internalf("a revocation cannot be completed")
	}
	err := a.epochs.BumpEpoch(ctx, authz.Principal{Kind: authz.KindUser, ID: subjectID})
	if err == nil {
		return nil
	}
	// Pseudonym only, and the cause stays server-side: errs.Error keeps a wrapped
	// error out of anything a client sees.
	a.log.ErrorContext(ctx, "the authorization decision cache could not be invalidated; the "+
		"revocation was refused rather than reported as done",
		"module", "identity", "subject_id", subjectID, "error", err)
	return errs.Internalf("this revocation could not be completed").Wrap(err)
}

// errRefused is the ONE answer every failed authentication gives.
//
// A function rather than a package-level value so no caller can compare against it
// by identity and re-derive the distinction it exists to remove. The message names
// neither the identifier nor which factor failed, and the errs.Reason is the same
// for all of them — ADR-036 puts the disclosure boundary at the authz gate, and an
// unauthenticated caller is below it.
func errRefused() error {
	return errs.Unauthenticatedf("those credentials are not valid")
}

// appendAttempt writes one authentication outcome to the day's journal.
//
// The stream is keyed by UTC date, NOT by the identifier being attempted — see
// AttemptCategory for why, and it is a security property rather than a filing
// convention. Which identifier an attempt concerns travels in the event's
// EmailIndex field, where it is projected into `login_history_view` and can be
// counted; it is deliberately not in the stream name, which an unauthenticated
// caller would then get to choose.
//
// AnyRevision, because the journal carries no invariant: simultaneous attempts
// must all be recorded, and an expected-revision precondition would fail one of
// them for a reason that has nothing to do with the credentials presented. That
// matters more now than it did per-identifier — every attempt in the system
// shares one stream per day, so any precondition here would serialise the entire
// login path.
func (a *Authentication) appendAttempt(
	ctx context.Context,
	idempotencyKey string,
	_ contract.EmailIndex,
	subjectID string,
	events ...eventsourcing.Event,
) (eventsourcing.Position, error) {
	stream, err := eventsourcing.NewStreamID(AttemptCategory, attemptStreamKey(a.clock.Now()))
	if err != nil {
		return eventsourcing.Position{}, err
	}

	meta := a.metadata(ctx, subjectID, idempotencyKey)
	pending := make([]eventsourcing.PendingEvent, 0, len(events))
	for i, e := range events {
		pending = append(pending, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			// Stamped per EVENT TYPE, not once for the command: two events of
			// one command can sit at different schema versions.
			Meta: eventsourcing.StampSchemaVersion(meta, a.schemas, e.EventType()),
		})
	}

	results, err := a.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream:   stream,
		Expected: eventsourcing.AnyRevision(),
		Events:   pending,
	}})
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	return results[0].Position, nil
}

// append writes one aggregate's uncommitted events to one stream.
//
// Through the multi-stream appender even for a single stream, so the derived event
// ids and the precondition are the same machinery registration and second factors
// use. A second append path would be a second place for the id derivation to drift.
func (a *Authentication) append(
	ctx context.Context,
	idempotencyKey, subjectID string,
	stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision,
	agg eventsourcing.Root,
) (eventsourcing.Position, error) {
	pending := agg.Uncommitted()
	if len(pending) == 0 {
		return eventsourcing.Position{}, nil
	}

	meta := a.metadata(ctx, subjectID, idempotencyKey)
	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			// Stamped per EVENT TYPE, not once for the command: two events of
			// one command can sit at different schema versions.
			Meta: eventsourcing.StampSchemaVersion(meta, a.schemas, e.EventType()),
		})
	}

	results, err := a.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream:   stream,
		Expected: expected,
		Events:   events,
	}})
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	agg.ClearUncommitted()
	return results[0].Position, nil
}

// metadata builds the envelope shared by every event of one command.
//
// Pseudonyms and nothing else: no address, no device name, no user agent, and no
// OrgID — an authentication happens on an account, not in an organization. The
// subject is empty for an attempt against an identifier nobody registered, which is
// correct: there is no person to name.
func (a *Authentication) metadata(
	ctx context.Context, subjectID, idempotencyKey string,
) eventsourcing.Metadata {
	meta := eventsourcing.Metadata{OccurredAt: a.clock.Now().UTC()}
	if subjectID != "" {
		meta.SubjectIDs = []string{subjectID}
		meta.ActorID = subjectID
	}
	trace := eventsourcing.TraceFrom(ctx)
	meta.CorrelationID = trace.CorrelationID
	meta.CausationID = trace.CausationID
	if meta.CorrelationID == "" {
		meta.CorrelationID = eventsourcing.DeriveEventID(idempotencyKey, 0).String()
	}
	if meta.CausationID == "" {
		meta.CausationID = idempotencyKey
	}
	return meta
}
