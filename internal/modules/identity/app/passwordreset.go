package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// PasswordReset is the pair of use cases that let somebody who has lost their
// password get a new one: asking for a link, and redeeming it.
//
// identity.md §4.5 specified this flow years before it was written, and the
// specification is a list of things it MUST do rather than a description of a
// feature. All five are enforced here, and each one is a named variant from
// Sudhodanan & Paverd, "Pre-hijacked accounts" (USENIX Security 2022), or from
// ASVS 5.0 §6.4:
//
//  1. void every session for the subject, including one held by whoever is
//     performing the reset;
//  2. void every outstanding token of EVERY purpose, not only reset tokens;
//  3. void any pending identifier change;
//  4. never bypass the second factor;
//  5. send the link to the STORED verified address, never one the request
//     supplied.
//
// # (4) is the one that is carried by SHAPE rather than by a check
//
// A reset here mints no session, returns no bearer token, and is not an
// authentication event of any kind. `Complete` replaces one credential and
// appends one event; the caller is then in exactly the position of somebody who
// has just been told a password — they must call Authenticate/CreateSession,
// and that path demands the account's second factor unchanged.
//
// This is deliberate and it is the reason there is no "skip the second factor
// after a reset" branch anywhere to get wrong. The usual way ASVS 5.0 V6.4.3 is
// broken is a reset that helpfully signs the user in, which converts "the
// attacker can read the mailbox" into full account takeover in one step: the
// mailbox proves control of an ADDRESS, and the second factor exists precisely
// because control of an address is not control of a person.
//
// Two things this therefore refuses to do, both of which would be convenient:
//
//   - It does not disable, remove or weaken TOTP, and it does not consume a
//     recovery code. An account that had a second factor before a reset has the
//     same one after it. Somebody who has lost BOTH their password and their
//     authenticator is a support case (identity.md §7.5, last-resort recovery),
//     not a reset.
//   - It does not activate a Pending account or touch `everSecondFactor`, so it
//     cannot widen the one carve-out that admits a password alone
//     (domain.User.NeedsFirstSecondFactor: a verified account that has NEVER
//     held a second factor, which is the state every new account passes
//     through). An account in that state has no second factor to bypass, and a
//     reset leaves it exactly as reachable — and as unreachable — as it was.
//
// # Why the request and the redemption are one type
//
// They share the rule set rather than the dependencies, and the rule set is what
// goes wrong when they are separated: the request decides which accounts may be
// mailed a link, and the redemption decides what a link may do. Written apart,
// the two answers drift — a request that mails a deactivated account, or a
// redemption that admits one — and the drift is invisible because each half
// passes its own tests. Registration is written the same way and for the same
// reason.
type PasswordReset struct {
	clock       clock.Clock
	index       EmailIndexer
	accounts    AccountDirectory
	subjects    UserDirectory
	users       AggregateLoader[*domain.User]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	byAddr      AttemptLimiter
	byCaller    AttemptLimiter
	tokenTTL    time.Duration
	breach      BreachChecker
	hasher      PasswordHasher
	credentials PasswordCredentials
	tokens      TokenStore
	digest      TokenDigest
	revocations SessionRevoker
	log         *slog.Logger
}

// PasswordResetDeps is everything the two handlers need.
//
// A struct rather than a positional constructor because sixteen dependencies in
// a call are sixteen chances to transpose two of the same type, and four of
// these are interfaces over the same storage machinery.
type PasswordResetDeps struct {
	Clock clock.Clock

	// Index derives the blind index. It is BOTH the account lookup key and the
	// rate-limit scope, so the raw address never reaches Valkey — a cache is a
	// projection with a shorter life, and ADR-002 applies to it unchanged.
	Index EmailIndexer

	// Directory resolves the blind index to the account claiming it, for the
	// REQUEST half. The same reader authentication uses, so "which account claims
	// this address" has one answer.
	Directory AccountDirectory

	// Subjects resolves the pseudonym a redeemed token names back to the account
	// id, for the REDEMPTION half. A separate port from Directory because the two
	// are asked in opposite directions, and keeping them apart is what stops the
	// redemption path acquiring the ability to turn an address into an account.
	Subjects UserDirectory

	// Users loads the account aggregate. Every decision either handler takes is
	// taken from the aggregate, never from the projection row that named it.
	Users AggregateLoader[*domain.User]

	// Appender writes the account stream.
	Appender eventsourcing.MultiAppender

	// Schemas stamps each appended event with its current schema version. Without
	// it the event is stored at version 0 while the registry declares 1, and the
	// aggregate cannot be loaded back — invisibly, because projections do not
	// upcast.
	Schemas eventsourcing.SchemaVersions

	// AddressLimiter bounds how much triggered mail one address can be made to
	// receive, and it MUST be the same counter the verification resend spends.
	// See NOTIFICATIONS.md §4 and cmd/api's mailAddressLimitPrefix: "an hourly
	// ceiling per address across ALL classes" is only true if reset mail and
	// verification mail increment one key. A separate budget here would let an
	// attacker alternate between the two endpoints and double the mail one victim
	// receives.
	AddressLimiter AttemptLimiter

	// CallerLimiter bounds how many DISTINCT addresses one caller can touch.
	CallerLimiter AttemptLimiter

	// TokenTTL is how long the link the issuer will mint lives. Passed in rather
	// than imported because the adapter that owns the constant imports this
	// package, and the dependency cannot point both ways.
	TokenTTL time.Duration

	// Breach screens the NEW password against a public corpus. A reset is the one
	// moment a person is most likely to reach for a password they have used
	// elsewhere, which is exactly the population a breach corpus covers.
	Breach BreachChecker

	// Hasher produces the replacement verifier, bound by AAD to the user and the
	// credential it replaces.
	Hasher PasswordHasher

	// Credentials holds the verifier. The reset's compare-and-set through this
	// port is the flow's only serialization point; see Complete.
	Credentials PasswordCredentials

	// Tokens redeems the emailed proof and sweeps every other outstanding token.
	Tokens TokenStore

	// Digest reduces the presented plaintext to the value the store holds. The
	// purpose is mixed INTO it, so a verification token cannot be redeemed here.
	Digest TokenDigest

	// Revocations voids every live session for the subject. REQUIRED, and unlike
	// registration's it is not a no-op: a reset exists because control of the
	// account may have been lost, and a session that survives it is the attacker's
	// session.
	Revocations SessionRevoker

	// Log is optional and defaults to slog.Default(). Nothing here logs an
	// address, a token or a password: the only identifiers that reach it are
	// pseudonyms and blind indexes.
	Log *slog.Logger
}

// NewPasswordReset validates the wiring and returns the handlers.
//
// Every dependency is required and none has a safe default. This repository has
// shipped adapters that were built, tested, and constructed by no binary six
// times; the two ceilings in particular are anti-abuse controls whose absence is
// invisible in every test that does not count mail.
func NewPasswordReset(deps PasswordResetDeps) (*PasswordReset, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: a password reset needs %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Index == nil:
		return nil, missing("an email indexer")
	case deps.Directory == nil:
		return nil, missing("an account directory")
	case deps.Subjects == nil:
		return nil, missing("a user directory")
	case deps.Users == nil:
		return nil, missing("a user loader")
	case deps.Appender == nil:
		return nil, missing("an appender")
	case deps.AddressLimiter == nil:
		return nil, missing("a per-address ceiling; without one this endpoint is an " +
			"unauthenticated mail bomb aimed at any address a caller can type")
	case deps.CallerLimiter == nil:
		return nil, missing("a per-caller ceiling; without one this endpoint is an " +
			"unauthenticated account-existence sweep")
	case deps.TokenTTL <= 0:
		return nil, fmt.Errorf("identity/app: a password reset needs a positive token "+
			"lifetime, got %s", deps.TokenTTL)
	case deps.Breach == nil:
		return nil, missing("a breach checker")
	case deps.Hasher == nil:
		return nil, missing("a password hasher")
	case deps.Credentials == nil:
		return nil, missing("a credential store")
	case deps.Tokens == nil:
		return nil, missing("a token store")
	case deps.Digest == nil:
		return nil, missing("a token digest function")
	case deps.Revocations == nil:
		return nil, missing("a session revoker; a reset that cannot void the sessions " +
			"established before it hands the account back to whoever held one, which is " +
			"the entire situation a reset exists for (identity.md §4.5)")
	case deps.Hasher.PepperVersion() < 1:
		// Checked at wiring time because the consequence is invisible until it is
		// unrecoverable: a verifier written at version 0 is skipped by the
		// `pepper_version < n` rotation query, and the account holding it is locked
		// out for good when the old transit key is destroyed.
		return nil, fmt.Errorf("identity/app: the password hasher reports pepper version %d; "+
			"a verifier stored below version 1 is invisible to key rotation",
			deps.Hasher.PepperVersion())
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &PasswordReset{
		clock: deps.Clock, index: deps.Index, accounts: deps.Directory,
		subjects: deps.Subjects, users: deps.Users, appender: deps.Appender,
		schemas: deps.Schemas, byAddr: deps.AddressLimiter, byCaller: deps.CallerLimiter,
		tokenTTL: deps.TokenTTL, breach: deps.Breach, hasher: deps.Hasher,
		credentials: deps.Credentials, tokens: deps.Tokens, digest: deps.Digest,
		revocations: deps.Revocations, log: log,
	}, nil
}

// ---------------------------------------------------------------------------
// Asking for a link
// ---------------------------------------------------------------------------

// RequestPasswordResetCommand asks for a reset link to be sent.
type RequestPasswordResetCommand struct {
	// Email is the raw address as typed. It is normalized here, reduced to a
	// blind index, and used to FIND an account — it is never used to address the
	// mail. identity.md §4.5: the link goes to the stored verified address, and
	// this handler could not send it anywhere else if it wanted to, because it
	// holds no address at all after this line and the event it appends carries a
	// pseudonym.
	Email string

	// CallerScope identifies whoever is calling, for the per-caller ceiling. The
	// transport supplies it — today the peer address — and it is REQUIRED: an
	// empty value would put every caller in one bucket, so the first few requests
	// anywhere would exhaust the budget for everybody.
	CallerScope string

	// IdempotencyKey makes a retried request derive the same event id, which the
	// store collapses instead of appending a second request.
	IdempotencyKey string
}

// ResetOutcome is what actually happened, for tests and metrics. It never
// reaches the wire.
type ResetOutcome int

const (
	// ResetNoAccount means no account claims the address.
	ResetNoAccount ResetOutcome = iota

	// ResetRequested means the event was appended and the issuer will mail.
	ResetRequested

	// ResetNoPassword means an account claims the address and has no password to
	// reset — it has never been verified, or it is passwordless by design. The
	// route into such an account is the verification link, never this one.
	ResetNoPassword

	// ResetNotEligible means an account claims the address but is deactivated or
	// suspended.
	ResetNotEligible

	// ResetRaced means a concurrent write to the account's stream won, so the
	// request this call would have appended is already there or superseded.
	ResetRaced
)

// RequestPasswordResetResult reports the outcome INSIDE the process.
//
// It is deliberately not mappable onto anything the wire carries. See
// api.RequestPasswordReset.
type RequestPasswordResetResult struct {
	Outcome ResetOutcome

	// Position is the log position of the append, set only for ResetRequested.
	Position eventsourcing.Position
}

// Request records that a reset was asked for, if there is an account a reset
// could help.
//
// # Order of operations
//
//  1. normalize the address and derive its blind index
//  2. spend the CALLER's budget
//  3. spend the ADDRESS's budget
//  4. look the account up, load it, decide, append
//
// Both ceilings are spent before step 4, and that ordering is the whole reason
// this endpoint can be public: an unknown address costs a caller exactly as much
// budget as a known one, so the request at which a caller is refused says
// nothing about which addresses have accounts. Spending them after the lookup
// would turn the rate limiter itself into the enumeration oracle the rest of
// this flow is shaped to deny — three requests then means "registered" and
// unlimited means "nobody".
//
// The caller's budget is spent BEFORE the address's, for ResendVerification's
// reason: a sweep across a thousand addresses that spent each victim's budget
// first would leave a thousand real people unable to ask for their own reset,
// having sent no mail at all. Caller-first bounds the damage to the attacker's
// own scope.
//
// # Five outcomes, one response
//
// No account, an account that can be reset, an account with no password, a
// deactivated account and a suspended account are five different facts and one
// answer. RequestPasswordResetResult carries which one happened for tests and
// metrics; the handler drops it, and the wire message has no field to put it in.
//
// The residual leak is TIMING: the appending path performs one store round trip
// the others do not. It is not closed by padding, and the reason is the ceiling
// rather than optimism — separating a few milliseconds of I/O from network
// jitter needs many samples of the SAME address, and the per-address rule
// permits three an hour. Stated here rather than hidden, because a control this
// argument depends on must not be quietly loosened later.
func (p *PasswordReset) Request(
	ctx context.Context, cmd RequestPasswordResetCommand,
) (RequestPasswordResetResult, error) {
	if cmd.IdempotencyKey == "" {
		return RequestPasswordResetResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.CallerScope == "" {
		return RequestPasswordResetResult{}, errs.Internalf(
			"the per-caller ceiling has no scope to count against")
	}

	email, err := domain.NormalizeEmail(cmd.Email)
	if err != nil {
		return RequestPasswordResetResult{}, err
	}
	index, err := p.index.Of(email)
	if err != nil {
		return RequestPasswordResetResult{}, err
	}

	if err := p.spend(ctx, p.byCaller, "caller", cmd.CallerScope); err != nil {
		return RequestPasswordResetResult{}, err
	}
	if err := p.spend(ctx, p.byAddr, "address", string(index)); err != nil {
		return RequestPasswordResetResult{}, err
	}

	account, err := p.accounts.AccountByEmailIndex(ctx, index)
	if err != nil {
		if errors.Is(err, ErrNoSuchAccount) {
			// The whole point of the empty response. Nothing is appended, nothing
			// is mailed, and the caller cannot tell this branch from any other.
			return RequestPasswordResetResult{Outcome: ResetNoAccount}, nil
		}
		return RequestPasswordResetResult{}, fmt.Errorf(
			"resolving the account for a reset request: %w", err)
	}

	user, err := p.users.Load(ctx, account.UserID.String())
	if err != nil {
		return RequestPasswordResetResult{}, fmt.Errorf(
			"loading the account for a reset request: %w", err)
	}

	// Decided from the AGGREGATE, never from the projection that named it. The
	// projection is behind the log by construction, so a decision taken from it
	// could be taken twice with two different answers — and one of those answers
	// mails a live reset link for an account that has since been suspended.
	switch {
	case user.State() != domain.StateActive && user.State() != domain.StatePending:
		// Deactivated or suspended. A reset link for an account that cannot
		// authenticate leads nowhere, and mailing one to a suspended account is
		// how a suspension is discovered by the person it was applied to.
		return RequestPasswordResetResult{Outcome: ResetNotEligible}, nil
	case !user.EmailVerified():
		// The address was never proven, so nothing here has established that the
		// person reading that mailbox is the person who typed the address at
		// registration. This is the pre-hijacking premise (identity.md §4.3), and
		// a reset link is a far better prize than a verification link: treat an
		// unproven address as no account at all.
		return RequestPasswordResetResult{Outcome: ResetNoPassword}, nil
	case !user.HasUsablePassword():
		// Passwordless — a first-class state here, not a broken one. There is
		// nothing to reset, and the way into such an account is a verification
		// link or the account's other methods, never this.
		return RequestPasswordResetResult{Outcome: ResetNoPassword}, nil
	case user.EmailIndex() != index:
		// The account's current claim is some OTHER address; this call reached it
		// through a projection row that has not caught up. Appending would ask for
		// a link to be mailed to the address the vault holds, which is not the one
		// that was typed here.
		return RequestPasswordResetResult{Outcome: ResetNotEligible}, nil
	}

	now := p.clock.Now().UTC()

	// Recorded from the application layer, exactly as EmailVerificationRequested
	// is and for the same reason: it changes no state the aggregate holds,
	// User.Apply has no case for it, and the deadline it carries is one only this
	// layer knows.
	// The index comes from the ACCOUNT'S OWN EVENTS, never from the request —
	// the same rule VerifyEmail takes it under. The switch above has already
	// established that the two are equal, so this is not a different value; it is
	// a different SOURCE, and the source is what survives somebody deleting the
	// check. Taking it from anywhere a caller can influence would let a request
	// name which claim a reset link is issued against.
	eventsourcing.Record(user, &contract.PasswordResetRequested{
		SubjectID:   user.SubjectID(),
		Index:       user.EmailIndex(),
		ExpiresAt:   now.Add(p.tokenTTL),
		RequestedAt: now,
	})

	pos, err := p.append(ctx, cmd.IdempotencyKey, user)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Somebody else wrote to this account between the load and the append —
			// a concurrent request, or a login recording a rehash. NOTHING was
			// written, and reporting success is correct: either a request is
			// already on the stream or the account changed in a way this call
			// should re-read. Retrying here would race again and could mail twice.
			return RequestPasswordResetResult{Outcome: ResetRaced}, nil
		}
		return RequestPasswordResetResult{}, err
	}
	return RequestPasswordResetResult{Outcome: ResetRequested, Position: pos}, nil
}

// ---------------------------------------------------------------------------
// Redeeming one
// ---------------------------------------------------------------------------

// ResetPasswordCommand presents an emailed reset token and the new password.
type ResetPasswordCommand struct {
	// Token is the plaintext from the link. It is hashed here and never stored,
	// logged or placed in an event: a token in a log line is a live credential in
	// a system whose logs outlive it by months, and this one grants account
	// access rather than merely confirming an address.
	Token string

	// Password is the raw secret as typed, normalized here under RFC 8265's
	// OpaqueString profile before it is screened or hashed.
	Password string

	// IdempotencyKey makes a retried reset derive the same event ids.
	IdempotencyKey string
}

// ResetPasswordResult reports the outcome INSIDE the process.
//
// None of it reaches the wire. See api.ResetPassword: a reset returns no
// identifiers and no session, because the caller's next act must be an ordinary
// authentication that presents the account's second factor.
type ResetPasswordResult struct {
	SubjectID string
	UserID    ids.UserID

	// SessionsRevoked is how many live sessions this reset ended, and
	// TokensRevoked how many outstanding tokens of every purpose it swept.
	// Recorded so a test can assert the rule ran rather than assert that a
	// function was called.
	SessionsRevoked int
	TokensRevoked   int

	Position eventsourcing.Position
}

// Complete redeems a reset link and replaces the account's password.
//
// # The order, and why each step is where it is
//
//  1. screen the new password           — before the token is spent
//  2. consume the token                 — atomic, single-use
//  3. resolve the subject to an account, load the aggregate
//  4. find the credential the LOG says is the account's usable password
//  5. decide on the aggregate           — ChangePassword(viaReset: true)
//  6. hash the new password             — bound by AAD to (user, credential)
//  7. void every outstanding token of every purpose
//  8. void any pending identifier change
//  9. void every session, sparing none
//  10. replace the verifier              — compare-and-set; the ONLY serialization point
//  11. append PasswordChanged
//
// # Steps 1 and 2: a rejected password does not burn the link
//
// Length and the breach corpus are checked on the submitted password BEFORE
// Consume, exactly as VerifyEmail does it, and for the same reason: neither
// refusal is a function of anything the caller does not already know, so
// repeating the call with a different password buys an attacker one bit they
// already had. A wrong token still fails at Consume, atomically and identically,
// however good the password beside it was. The alternative tells a person who
// picked a weak password that their link is now dead in the same breath, and the
// only route back is a request they have to know to ask for.
//
// # Steps 7-9 before step 10: the reset fails towards LESS access
//
// Both orderings can fail and they fail in opposite directions.
//
// Revocations first: a failure leaves the sessions and tokens dead and the
// password unchanged. The caller sees an error, asks for another link, and
// nothing was granted to anybody.
//
// Verifier first: a failure leaves a NEW password live while the attacker's
// session is still live and their outstanding verification token still
// redeemable — which is the exact state §4.5 exists to forbid, reached through
// an error path where nothing will ever notice it.
//
// # Step 10 before step 11, and what a crash between them costs
//
// This is the one place the flow can leave a fact the log does not explain: a
// verifier written with no PasswordChanged behind it. It is accepted
// deliberately, because the other order is worse in a way that matters more.
//
// Appending first and writing the verifier second means a failure leaves the log
// saying the password was reset, the sessions gone, the user told to sign in —
// and the OLD password still the one that works. A reset exists because control
// may have been lost; leaving the old credential live after announcing it dead
// is the failure direction a reset must never take.
//
// Writing the verifier first means a failure leaves the person's new password
// working with no event to explain it. That is visible and it is caught: the
// credential-tamper reconciliation replays the account's stream and reports a
// verifier the log does not account for (identity.md §4.2). The person's
// recovery is to request another link; the system's recovery is an alert that
// fires on a real anomaly.
//
// # Step 10 is the whole concurrency story
//
// Two reset links for one account can be redeemed simultaneously — an attacker
// triggered one, a victim triggered another — and both consume their own token
// successfully, because they are different digests in different rows. Both then
// hold a verifier computed against the same expected value, and the
// compare-and-set is what makes exactly one of them land. The loser writes
// nothing, appends nothing, and is told the credential moved. There is no
// interleaving that leaves the account holding a password nobody chose.
//
// A reset racing a LOGIN is a different race and is handled at step 11: a login
// can append to the account's stream (an authenticator lockout, a rehash), so
// the append's expected revision can be stale. Because the verifier is already
// written by then, the event is not optional — see appendChanged.
//
// # What it does NOT do (ASVS 5.0 V6.4.3)
//
// It mints no session and returns no token. It does not disable the second
// factor, consume a recovery code, or activate a Pending account. The caller's
// next act is an ordinary authentication that presents whatever factors the
// account has, unchanged by this call. See the type's doc.
func (p *PasswordReset) Complete(
	ctx context.Context, cmd ResetPasswordCommand,
) (ResetPasswordResult, error) {
	if cmd.IdempotencyKey == "" {
		return ResetPasswordResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.Token == "" {
		return ResetPasswordResult{}, errs.ValidationFailedf("a reset token is required")
	}
	if cmd.Password == "" {
		// Refused explicitly rather than left to NormalizePassword's length rule,
		// so "you sent no password" and "your password is six characters" are not
		// the same message. Neither discloses anything: both are properties of the
		// request, evaluated before the token is looked at.
		return ResetPasswordResult{}, errs.ValidationFailedf("a new password is required")
	}

	// Screened on the RAW password, before normalization and before hashing, for
	// the reason VerifyEmail screens there: a rejected password must not cost an
	// Argon2id evaluation, which is a free amplification vector for anyone posting
	// known-breached passwords at an unauthenticated endpoint.
	breached, corpus, err := p.breach.Breached(ctx, cmd.Password)
	switch {
	case err != nil:
		// FAIL OPEN, and say so. An unreachable corpus is an outage at a third
		// party, and blocking on it would stop every password reset in the system.
		// The signal is recorded rather than swallowed: a screening step nobody can
		// tell has stopped running is the same as not having one (identity.md §4.1).
		p.log.WarnContext(ctx, "breach screening did not run; the reset password was accepted unscreened",
			"module", "identity", "reason", "breach_corpus_unavailable", "error", err)
	case breached:
		return ResetPasswordResult{}, errs.ValidationFailedf(
			"this password appears in a known data breach (%s); choose a different one", corpus)
	}

	password, err := domain.NormalizePassword(cmd.Password)
	if err != nil {
		return ResetPasswordResult{}, err
	}

	now := p.clock.Now().UTC()
	subjectID, err := p.tokens.Consume(
		ctx, PurposePasswordReset, p.digest(PurposePasswordReset, cmd.Token), now)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// Unknown, already spent and expired are ONE outcome by design. "That
			// link has expired" tells whoever holds it that the address it was sent
			// to has an account with a password.
			return ResetPasswordResult{}, errRejectedResetLink()
		}
		return ResetPasswordResult{}, err
	}

	userID, err := p.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			return ResetPasswordResult{}, errRejectedResetLink()
		}
		return ResetPasswordResult{}, fmt.Errorf("resolving the account for a reset: %w", err)
	}

	user, err := p.users.Load(ctx, userID.String())
	if err != nil {
		return ResetPasswordResult{}, fmt.Errorf("loading the account for a reset: %w", err)
	}

	// The credential comes from the ACCOUNT'S OWN EVENTS, never from the
	// credential table. The log is the authority on which credentials an account
	// has (identity.md §4.2): a row the log cannot account for was written outside
	// the application, and a reset driven from the table would rewrite it as if it
	// were legitimate — which is exactly the "injected credential" case the
	// reconciliation job exists to catch.
	credentialID, ok := user.UsablePasswordCredential()
	if !ok {
		// A live token for an account with no usable password. Reachable if the
		// credential was disabled or removed between the request and the click.
		// The same undifferentiated refusal, because the alternative distinguishes
		// account states for whoever holds a link.
		return ResetPasswordResult{}, errRejectedResetLink()
	}

	// Decided on the aggregate FIRST, so a suspended account is refused before
	// anything is destroyed. domain.User.mutable refuses Suspended and StateNone.
	if err := user.ChangePassword(credentialID, true, now); err != nil {
		return ResetPasswordResult{}, err
	}

	// The stored verifier this reset was decided against. Read here rather than
	// earlier because it is the compare-and-set's expected value and must be as
	// fresh as possible — a value read before the aggregate was loaded would widen
	// the window in which a concurrent reset can slip between the read and the
	// write, without changing whether the guard holds.
	current, err := p.credentials.Find(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoPasswordCredential) {
			// The log says there is a usable password and the table disagrees. That
			// is a divergence, not a user error (identity.md §4.2), and it is
			// reported as an internal failure rather than as a bad link so it lands
			// somewhere an operator will see it.
			return ResetPasswordResult{}, errs.Internalf(
				"the account's log records a usable password that the credential store does not hold")
		}
		return ResetPasswordResult{}, fmt.Errorf("reading the credential for a reset: %w", err)
	}
	if current.ID != credentialID {
		return ResetPasswordResult{}, errs.Internalf(
			"the credential store holds a different password credential than the account's log names")
	}

	verifier, err := p.hasher.Hash(ctx, password, userID, credentialID)
	if err != nil {
		// Propagated unchanged and NOT retried: the hasher is bounded at the core
		// count, so over capacity it returns RATE_LIMITED after queueing and a retry
		// here would add load to the condition the bound exists to relieve. The
		// token is already spent; the recovery is a fresh link, and NOTHING has been
		// revoked at this point — the account is exactly as it was.
		return ResetPasswordResult{}, err
	}

	// ---- from here on the account is being taken back ----

	// (2) Every outstanding token of EVERY purpose. Not only reset tokens: an
	// attacker who triggered a verification mail — by registering, or through
	// ResendEmailVerification — otherwise holds a live link that survives the
	// recovery, which is Sudhodanan & Paverd's "trojan identifier" variant.
	tokensRevoked, err := p.tokens.RevokeAllPurposes(ctx, subjectID)
	if err != nil {
		return ResetPasswordResult{}, fmt.Errorf(
			"voiding the outstanding tokens for a reset: %w", err)
	}

	// (3) Any pending identifier change. Today this records nothing, because no
	// flow in this module can create one — see
	// domain.User.VoidPendingIdentifierChange, which carries the whole argument
	// for writing a call that provably does nothing. It is here rather than
	// remembered by whoever writes the email-change flow, exactly as
	// VerifyEmail's RevokeAllSessions was written before any session could exist.
	//
	// It runs on the aggregate this command is already going to append, so if it
	// ever does record an event that event rides the same atomic append as
	// PasswordChanged rather than being a second write that can fail alone.
	if err := user.VoidPendingIdentifierChange(now); err != nil {
		return ResetPasswordResult{}, fmt.Errorf(
			"voiding a pending identifier change for a reset: %w", err)
	}

	// (1) Every session, sparing NONE. Except is zero and must stay zero: a reset
	// exists because control may have been lost, so sparing the session that asked
	// assumes the opposite. It is also not performed from a session at all — this
	// is a public endpoint reached from a mailbox.
	revoked, err := p.revocations.RevokeAllSessions(ctx, RevokeAllSessionsCommand{
		SubjectID: subjectID,
		Reason:    RevokeReasonPasswordReset,
		// Derived from this command's key so a retried reset collapses into the
		// same session events instead of appending a second set, and suffixed so it
		// cannot collide with the event ids appendChanged derives from the bare key.
		IdempotencyKey: cmd.IdempotencyKey + ":" + RevokeReasonPasswordReset,
	})
	if err != nil {
		return ResetPasswordResult{}, fmt.Errorf(
			"voiding the sessions established before this reset: %w", err)
	}

	// (10) The compare-and-set. Everything above this line can be repeated
	// harmlessly; nothing below it can be undone.
	if err := p.credentials.Replace(
		ctx, credentialID, current.Verifier, verifier, p.hasher.PepperVersion(),
	); err != nil {
		if errors.Is(err, ErrCredentialMoved) {
			// A concurrent reset won, or the credential was disabled underneath
			// this one. Nothing was written and nothing is appended. Reported as a
			// conflict rather than as a bad link, because the caller held a real
			// token and is entitled to know the request did not take effect.
			return ResetPasswordResult{}, errs.Conflictf(
				"this account's password was changed by another request; ask for a new link")
		}
		return ResetPasswordResult{}, fmt.Errorf("replacing the password verifier: %w", err)
	}

	pos, err := p.appendChanged(ctx, cmd.IdempotencyKey, userID, subjectID, credentialID, now, user)
	if err != nil {
		return ResetPasswordResult{}, err
	}

	return ResetPasswordResult{
		SubjectID:       subjectID,
		UserID:          userID,
		SessionsRevoked: revoked.Revoked,
		TokensRevoked:   tokensRevoked,
		Position:        pos,
	}, nil
}

// errRejectedResetLink is the ONE refusal every unusable link gets.
//
// Unknown, spent, expired, pointing at a subject with no account, and pointing
// at an account with no usable password are five different facts and one
// message. Any distinction among them is an oracle for whoever holds the link,
// and the population holding a link they cannot use includes everyone who
// guessed one.
//
// A function rather than a package-level error value because errs errors carry
// per-instance metadata, and a shared value would let one call site's metadata
// leak into another's.
func errRejectedResetLink() error {
	return errs.ValidationFailedf("this password-reset link is no longer valid; request a new one")
}

// ---------------------------------------------------------------------------
// Shared machinery
// ---------------------------------------------------------------------------

// spend consumes one unit of a ceiling and reports whether the call may proceed.
//
// # Fail OPEN, deliberately
//
// The same trade ResendVerification takes, for the same reason. OpenFGA fails
// closed because what it protects is access to other people's data. This limiter
// protects a mail queue: failing closed would mean a Valkey blip — a rolling
// restart, a failover — stops every locked-out person from asking for the link
// that is their only way back into their own account.
//
// Failing open costs, at worst, unbounded reset mail for the duration of the
// outage. That is bounded downstream by the mail provider's own limits, it is
// reversible, and it is LOUD: every degraded evaluation is logged here, which is
// the difference between a control that is known to be off and one that is
// silently doing nothing.
func (p *PasswordReset) spend(
	ctx context.Context, limiter AttemptLimiter, axis, scope string,
) error {
	decision, err := limiter.Allow(ctx, scope)
	if err != nil {
		// Degraded. Allowed, and never silently: the scope is a blind index or a
		// peer address, so this line carries no personal data.
		p.log.WarnContext(ctx, "the reset-mail ceiling could not be evaluated; "+
			"the request was allowed unmetered",
			"module", "identity", "reason", "ceiling_unavailable", "axis", axis, "error", err)
		return nil
	}
	if !decision.Allowed() {
		// The SAME refusal for a known and an unknown address, because the budget
		// was spent before either was looked up. The wording deliberately says
		// nothing about accounts, and it is deliberately the same shape the resend
		// uses — a caller must not be able to tell the two endpoints' ceilings
		// apart either, since they share one counter.
		return errs.RateLimitedf(
			"too many password-reset links have been requested; try again later").
			WithMeta(map[string]string{
				"rule":        decision.Rule,
				"retry_after": decision.RetryAfter.String(),
			})
	}
	return nil
}

// append writes the account stream for a reset REQUEST.
//
// eventsourcing.MultiAppender with one entry rather than a Repository.Save, so a
// reset request, a resend and a registration reach the log through the same call,
// with the same precondition semantics and the same event-id derivation. A second
// write path for one event type is a second place for the schema stamp to be
// forgotten.
func (p *PasswordReset) append(
	ctx context.Context, idempotencyKey string, user *domain.User,
) (eventsourcing.Position, error) {
	pending := user.Uncommitted()
	if len(pending) == 0 {
		// Unreachable today — Record ran immediately above — and refused rather
		// than assumed: an empty entry is rejected by the adapter, and an entry
		// carrying only a precondition would turn a replay into a conflict.
		return eventsourcing.Position{}, errs.Internalf("a reset request produced no event to append")
	}
	stream, err := eventsourcing.NewStreamID(UserCategory, user.ID().String())
	if err != nil {
		return eventsourcing.Position{}, err
	}
	events := p.pending(ctx, idempotencyKey, user.SubjectID(), pending)
	results, err := p.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream,
		// The exact revision the aggregate was loaded at. A concurrent write is
		// therefore a refusal rather than a second request appended blind — which
		// matters, because two requests on one stream is two reset links.
		Expected: eventsourcing.ExpectedFor(user),
		Events:   events,
	}})
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	user.ClearUncommitted()
	return results[0].Position, nil
}

// appendChangedAttempts bounds the retry in appendChanged.
//
// Three, because the contention it absorbs is a login writing to the same
// account stream — a lockout or a rehash — and those are single writes, not a
// stream of them. A larger number would turn a genuinely hot stream into a long
// synchronous stall on a public endpoint; a smaller one would fail on the first
// ordinary collision.
const appendChangedAttempts = 3

// appendChanged records PasswordChanged, retrying a lost expected-revision race.
//
// # Why this one append is allowed to retry, when the request's is not
//
// Request.append treats ErrWrongExpectedRevision as "somebody else got there,
// report success, send nothing" — the safe answer, because nothing had happened
// yet and retrying could mail twice.
//
// Here the verifier has ALREADY been replaced. The account's password is the new
// one from the moment Replace returns, so an append that gives up leaves a
// credential the log does not explain, which the tamper reconciliation reports as
// an injected credential (identity.md §4.2). The event is not optional, and the
// race is real rather than theoretical: an authentication appends to this same
// stream when it locks out an authenticator or rehashes a verifier, so a reset
// racing a login can lose the precondition through no fault of its own.
//
// The aggregate is RELOADED on each attempt rather than re-appended at a bumped
// revision, because the precondition exists to make the decision current: the
// event this records is a fact about a credential that was just replaced, and it
// must be recorded against whatever the stream says now.
//
// Re-deciding is safe and is not a second reset. ChangePassword records one event
// from state the reload re-establishes, and a failed append wrote nothing — so
// the derived event ids are still unused and a retry reproduces them exactly,
// which is what makes a retry that partially succeeded collapse rather than
// duplicate.
func (p *PasswordReset) appendChanged(
	ctx context.Context,
	idempotencyKey string,
	userID ids.UserID,
	subjectID string,
	credentialID ids.CredentialID,
	now time.Time,
	loaded *domain.User,
) (eventsourcing.Position, error) {
	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return eventsourcing.Position{}, err
	}

	user := loaded
	var lastErr error
	for attempt := range appendChangedAttempts {
		if attempt > 0 {
			reloaded, loadErr := p.users.Load(ctx, userID.String())
			if loadErr != nil {
				return eventsourcing.Position{}, fmt.Errorf(
					"reloading the account to record a completed reset: %w", loadErr)
			}
			// Cleared before re-deciding, so a loader that hands back the SAME
			// aggregate instance cannot accumulate one PasswordChanged per attempt.
			// eventsourcing.Repository builds a fresh aggregate every time and this
			// is a no-op against it; the guard is here because the alternative
			// failure — a retry appending two identical events — is silent, and the
			// port's contract says nothing about instance identity.
			user.ClearUncommitted()
			user = reloaded
			user.ClearUncommitted()
			if err := user.ChangePassword(credentialID, true, now); err != nil {
				return eventsourcing.Position{}, err
			}
		}
		pending := user.Uncommitted()
		if len(pending) == 0 {
			return eventsourcing.Position{}, errs.Internalf(
				"a completed reset produced no event to append")
		}
		events := p.pending(ctx, idempotencyKey, subjectID, pending)
		results, appendErr := p.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
			Stream:   stream,
			Expected: eventsourcing.ExpectedFor(user),
			Events:   events,
		}})
		if appendErr == nil {
			if len(results) == 0 {
				return eventsourcing.Position{}, errs.Internalf("the append reported no result")
			}
			user.ClearUncommitted()
			return results[0].Position, nil
		}
		if !errors.Is(appendErr, eventsourcing.ErrWrongExpectedRevision) {
			return eventsourcing.Position{}, appendErr
		}
		lastErr = appendErr
	}

	// Every attempt lost the race. The verifier is the new one and the log does
	// not say so, which is exactly the divergence the reconciliation job reports —
	// so this is returned rather than swallowed, with the fact stated in the
	// message so the operator reading it does not have to derive it.
	return eventsourcing.Position{}, errs.Internalf(
		"the password was replaced but the change could not be recorded after %d attempts; "+
			"the credential store and the event log now disagree for this account",
		appendChangedAttempts).Wrap(lastErr)
}

// pending turns an aggregate's uncommitted events into stamped, id-derived
// pending events.
//
// One helper for both appends so the metadata, the schema stamp and the id
// derivation cannot differ between the request and the completion. Two copies of
// this loop is two places for StampSchemaVersion to be forgotten — which stores
// the event at version 0 while the registry declares 1 and makes the aggregate
// unloadable, invisibly, because projections do not upcast.
func (p *PasswordReset) pending(
	ctx context.Context, idempotencyKey, subjectID string, events []eventsourcing.Event,
) []eventsourcing.PendingEvent {
	meta := eventsourcing.Metadata{
		OccurredAt: p.clock.Now().UTC(),
		SubjectIDs: []string{subjectID},
		ActorID:    subjectID,
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

	out := make([]eventsourcing.PendingEvent, 0, len(events))
	for i, e := range events {
		out = append(out, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			// Stamped per EVENT TYPE, not once for the command: two events of one
			// command can sit at different schema versions.
			Meta: eventsourcing.StampSchemaVersion(meta, p.schemas, e.EventType()),
		})
	}
	return out
}
