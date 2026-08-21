package app

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// Stream categories written by registration.
//
// KurrentDB derives a category from everything before the FIRST dash, so neither
// value may contain one. A public identifier uses '_' as its prefix separator
// precisely so it is safe as a stream key (ADR-030), and a blind index is hex.
const (
	// UserCategory names the account stream: user-<user id>.
	UserCategory eventsourcing.Category = "user"

	// ReservationCategory names the uniqueness stream:
	// reservation_email-<blind index>.
	//
	// The value is duplicated in the blindindex adapter, which cannot be imported
	// here — app/ may not depend on adapter/ (CONVENTIONS §1.1). The two must stay
	// equal: a divergence would put the claim enforced by this use case and the
	// claim projected for the lapse sweep on two different streams, which looks
	// exactly like a projection that has fallen behind and never catches up.
	ReservationCategory eventsourcing.Category = "reservation_email"
)

// DefaultReservationLease is how long an UNVERIFIED claim on an address holds.
//
// The constraint that decides the number is not a product preference: it must be
// strictly LONGER than the lifetime of the verification link, which is 24 hours.
// EmailReservation.Confirm refuses a lapsed claim, so a link that outlives its
// own reservation produces a verification that fails for a user who did
// everything right, at a moment nothing in the system distinguishes from an
// attacker presenting a stale token.
//
// It cannot be expressed as a compile-time relation to the token adapter's
// constant, because that adapter imports this package for TokenPurpose and the
// dependency cannot point both ways. So it is stated here, with the slack — one
// extra day — carrying mail-queue delay and clock skew between the two services.
const DefaultReservationLease = 48 * time.Hour

// Registration is the pair of use cases that bring an account into existence:
// claiming an address, and proving it.
//
// # Why both handlers write two streams in ONE append
//
// An account and its claim on an address are two aggregates — deliberately, since
// a reservation outlives no account and an account may change address — and they
// live on two streams. Written as two sequential appends, the process can die
// between them, and the two orderings fail differently: reserve-then-register
// strands a lease with no account (self-healing, it lapses), register-then-reserve
// strands an account holding an address it has no claim to (nothing repairs it,
// and a second registration then wins the reservation while both accounts point
// at one identifier).
//
// eventsourcing.MultiAppender removes the choice rather than making it. The server
// evaluates every precondition and commits all of them or none — verified against
// the running server — so the window in which one exists without the other does
// not exist. What it does NOT do is relax the aggregate boundary: each stream
// still carries its own precondition, and each aggregate still decides alone.
//
// # Why the reservation stream is what enforces uniqueness
//
// The stream is named from the address's blind index, so two concurrent
// registrations for one address contend on the SAME stream with NoStream, and
// the server rejects one of them (ADR-044). The alternative — read a projection,
// then write — cannot work and fails invisibly: the projection is behind the log
// by construction, so under concurrency both callers read "free", both succeed,
// and two accounts own one address.
type Registration struct {
	clock        clock.Clock
	entropy      io.Reader
	index        EmailIndexer
	breach       BreachChecker
	hasher       PasswordHasher
	vault        SubjectVault
	credentials  PasswordCredentials
	reservations AggregateLoader[*domain.EmailReservation]
	usernames    AggregateLoader[*domain.UsernameReservation]
	users        AggregateLoader[*domain.User]
	appender     eventsourcing.MultiAppender
	tokens       TokenStore
	minter       TokenMinter
	digest       TokenDigest
	directory    UserDirectory
	revocations  SessionRevoker
	lease        time.Duration
	byAddr       AttemptLimiter
	byCaller     AttemptLimiter
	log          *slog.Logger
	schemas      eventsourcing.SchemaVersions
}

// RegistrationDeps is everything the two handlers need.
//
// A struct rather than a positional constructor because fourteen dependencies in
// a call are fourteen chances to transpose two of the same type, and two of these
// are interfaces over the same aggregate machinery.
type RegistrationDeps struct {
	Clock        clock.Clock
	Entropy      io.Reader
	Index        EmailIndexer
	Breach       BreachChecker
	Hasher       PasswordHasher
	Vault        SubjectVault
	Credentials  PasswordCredentials
	Reservations AggregateLoader[*domain.EmailReservation]

	// Usernames loads the public handle's reservation aggregate (ADR-051).
	//
	// REQUIRED. A nil here would make VerifyEmail panic on the first real
	// verification in production — the one call every account in the system must
	// pass through — and it is the load half only: the claim is written by the
	// same atomic append that verifies the address, through Appender.
	Usernames AggregateLoader[*domain.UsernameReservation]

	Users     AggregateLoader[*domain.User]
	Appender  eventsourcing.MultiAppender
	Tokens    TokenStore
	Minter    TokenMinter
	Digest    TokenDigest
	Directory UserDirectory

	// Revocations voids every live session for a subject when their address
	// becomes verified. See SessionRevoker, and VerifyEmail for why it is called
	// where it is.
	//
	// REQUIRED, and required precisely because it does nothing today. A
	// pre-verification account has no credential, therefore no session, therefore
	// nothing to revoke — so a nil here would have no runtime symptom at all, on
	// any request, until the day a flow exists that can leave a session behind.
	// That is the exact shape of the failure this repository has already shipped
	// three times: a control built, tested, and constructed by no binary.
	Revocations SessionRevoker

	// Lease overrides DefaultReservationLease. Zero means the default.
	Lease time.Duration

	// AddressLimiter and CallerLimiter are the SHARED triggered-mail ceilings —
	// the same counter, the same keys and the same numbers ResendVerification and
	// PasswordReset spend from (cmd/api's mailAddressRules and mailCallerRules).
	//
	// Sharing is the point, and it is why they are ports rather than something
	// built here. NOTIFICATIONS.md §4 asks for "an hourly ceiling per address
	// across ALL classes"; a budget of this message's own would let an attacker
	// alternate between Register and RequestPasswordReset and double the mail one
	// victim receives, which is the exact failure mailAddressLimitPrefix is
	// deliberately not class-specific to prevent.
	//
	// They are consulted on BOTH registration paths, not only the refused one,
	// and the symmetry is a security property rather than tidiness. Spending only
	// when the address turns out to be taken makes the ceiling itself an oracle:
	// a prober would exhaust the budget on an address, then read the answer off a
	// later ResendEmailVerification for the same address being refused. Both
	// paths mail the address — the free one sends a verification link — so both
	// paying is also simply correct.
	//
	// What a refusal does is suppress the duplicate-registration NOTICE. It never
	// refuses the registration and never reaches the wire, because a
	// RATE_LIMITED that only the taken path could produce would be the same
	// oracle wearing a different hat, and one that could also block a legitimate
	// person from registering an address somebody else had probed.
	//
	// OPTIONAL, and the absence is not silent: NewRegistration warns, and
	// MetersMail reports it so a composition-root test can assert what a binary
	// wired. When they are absent the notice is still bounded — by the address's
	// own reservation stream (domain.MaxDuplicateNoticesPerHour), which is the
	// floor that holds when this ceiling is unwired, degraded or flushed. What is
	// lost is only the sharing with the other classes of triggered mail.
	AddressLimiter AttemptLimiter
	CallerLimiter  AttemptLimiter

	// Log is optional and defaults to slog.Default(). Nothing here logs an
	// address: the only identifiers that reach it are pseudonyms.
	Log *slog.Logger
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

// NewRegistration validates the wiring and returns the handlers.
//
// Every dependency is checked, and the check is not ceremony. This repository has
// already shipped three adapters that were built, tested and constructed by no
// binary; a nil port here would surface as a panic on the first registration in
// production rather than as a refusal to start.
func NewRegistration(deps RegistrationDeps) (*Registration, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: registration needs %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Entropy == nil:
		return nil, missing("an entropy source")
	case deps.Index == nil:
		return nil, missing("an email indexer; without one no stream can be named " +
			"and uniqueness is not enforced at all")
	case deps.Breach == nil:
		return nil, missing("a breach checker")
	case deps.Hasher == nil:
		return nil, missing("a password hasher")
	case deps.Vault == nil:
		return nil, missing("a vault; the address has nowhere else to go")
	case deps.Credentials == nil:
		return nil, missing("a credential store")
	case deps.Reservations == nil:
		return nil, missing("a reservation loader")
	case deps.Usernames == nil:
		return nil, missing("a username reservation loader; without one no handle can " +
			"be claimed and VerifyEmail — the only route into a usable account — panics " +
			"on the first real verification")
	case deps.Users == nil:
		return nil, missing("a user loader")
	case deps.Appender == nil:
		return nil, missing("a multi-stream appender")
	case deps.Tokens == nil:
		return nil, missing("a token store")
	case deps.Minter == nil:
		// Checked here rather than tolerated as "verification mail is optional",
		// because the failure mode of a nil minter is a registration that succeeds
		// and an account that can never be verified. The address is claimed by then,
		// so the person cannot even register again — and nothing in the read model
		// distinguishes that account from one whose owner simply has not clicked yet.
		return nil, missing("a token minter; without one a registration issues no " +
			"verification token and the account can never be proven")
	case deps.Digest == nil:
		return nil, missing("a token digest function")
	case deps.Directory == nil:
		return nil, missing("a user directory")
	case deps.Revocations == nil:
		return nil, missing("a session revoker; a verification that cannot void the " +
			"sessions established before it re-opens the pre-hijacking variants " +
			"IDENTITY-REVIEW C8 closes, and it would do so silently — there are no " +
			"sessions to void today, so nothing at runtime can tell this is missing")
	case deps.Lease < 0:
		return nil, fmt.Errorf("identity/app: a reservation lease may not be negative")
	case deps.Hasher.PepperVersion() < 1:
		// Checked at wiring time because the consequence is invisible until it is
		// unrecoverable: every verifier written at version 0 is skipped by the
		// `pepper_version < n` rotation query, and every account holding one is
		// locked out for good when the old transit key is destroyed.
		return nil, fmt.Errorf("identity/app: the password hasher reports pepper version %d; "+
			"a verifier stored below version 1 is invisible to key rotation",
			deps.Hasher.PepperVersion())
	}

	lease := deps.Lease
	if lease == 0 {
		lease = DefaultReservationLease
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	if deps.AddressLimiter == nil || deps.CallerLimiter == nil {
		// Loud rather than refused. Refusing would leave the binary with no
		// registration at all, which is a far worse outcome than a notice bounded
		// by one ceiling instead of two — and the remaining ceiling is the durable
		// one. Loud because the alternative is a control that is off with nothing
		// anywhere saying so, which is the shape of failure this repository keeps
		// finding.
		log.Warn("registration is not sharing the triggered-mail ceilings: the "+
			"duplicate-registration notice is bounded by the address's own reservation "+
			"stream only, so an attacker can alternate between Register and "+
			"RequestPasswordReset to double the mail one address receives. Wire "+
			"AddressLimiter and CallerLimiter from the same limiters "+
			"ResendVerification and PasswordReset already hold",
			"module", "identity", "reason", "mail_ceiling_unshared",
			"address_ceiling", deps.AddressLimiter != nil,
			"caller_ceiling", deps.CallerLimiter != nil)
	}
	return &Registration{
		clock: deps.Clock, entropy: deps.Entropy, index: deps.Index,
		breach: deps.Breach, hasher: deps.Hasher, vault: deps.Vault,
		credentials: deps.Credentials, reservations: deps.Reservations,
		usernames: deps.Usernames,
		users:     deps.Users, appender: deps.Appender, tokens: deps.Tokens,
		minter: deps.Minter, digest: deps.Digest, directory: deps.Directory,
		revocations: deps.Revocations,
		lease:       lease, log: log,
		byAddr: deps.AddressLimiter, byCaller: deps.CallerLimiter,
		schemas: deps.Schemas,
	}, nil
}

// MetersMail reports whether the SHARED triggered-mail ceilings are wired.
//
// Exposed for the same reason reactor.VerificationMail exposes Durable: the two
// states are indistinguishable from outside until the day they differ, and this
// repository has shipped six components that were built, tested and constructed
// by no binary. A composition-root test can assert this; a reader of a healthy
// log cannot.
//
// False does not mean unbounded. It means the duplicate-registration notice is
// bounded only by the address's own reservation stream and does not share a
// budget with password-reset or resend mail — see RegistrationDeps.AddressLimiter.
func (r *Registration) MetersMail() bool { return r.byAddr != nil && r.byCaller != nil }

// RegisterCommand is a registration request.
//
// It carries NO PASSWORD, and the absence is the fix for IDENTITY-REVIEW C8.
// See Register.
type RegisterCommand struct {
	// Email is the raw address as typed. It is normalized here, and the
	// normalized form is the only one that reaches the vault or the indexer.
	Email string

	// IdempotencyKey makes a retried request produce byte-identical event ids,
	// which the store collapses instead of duplicating (EVENT-SOURCING §3).
	//
	// Required, not optional. An empty key derives the SAME id for every
	// registration in the system, and two different accounts appending events
	// with one id is a corruption no later check can undo.
	IdempotencyKey string

	// CallerScope is what the per-caller mail ceiling counts against: the
	// connection's peer address, plus as much of X-Forwarded-For as
	// API_TRUSTED_PROXY_HOPS declares trustworthy. internal/platform/clientip
	// owns every rule about it and identity.md §12.1 owns the deployment
	// contract.
	//
	// Required whenever CallerLimiter is wired, and refused rather than defaulted
	// when it is missing — exactly as ResendVerification and PasswordReset refuse
	// it. An empty scope would put every caller in one bucket, which turns a
	// per-caller ceiling into a global one with no runtime symptom at all.
	CallerScope string
}

// RegisterResult reports what a registration produced.
//
// # Created is not a status code
//
// It is false when the address was already claimed, and the caller must render
// the SAME response either way — "if that address can be registered, we have sent
// it a link". Registration is one of the four flows identity.md §11 names as
// leaking account existence when written naively, and the leak is not fixed at
// the API by choosing a vague message: it is fixed by the handler having produced
// indistinguishable work.
//
// # What the removal of the password hash did, and did not, do to the timing
//
// This handler used to compute an Argon2id verifier before examining the
// reservation, and the comment here used to claim that paying ~51 ms on both
// paths is what made the two responses take the same time. That claim was
// always half wrong, and the arithmetic is worth stating because the hash has
// now gone and somebody will otherwise read its absence as a regression.
//
// The hash was a CONSTANT ADDED TO BOTH paths. It never equalised them: the
// free path additionally writes the vault, issues a token digest and appends to
// KurrentDB, and the claimed path returns before all three. The difference
// between the two — some milliseconds of I/O — was exactly the same with the
// hash as without it; the hash only raised the floor under both. Removing it
// therefore leaves the residual delta unchanged and stops charging every
// registration in the system 51 ms of CPU for a verifier nobody will ever use.
//
// The residual delta is real and is NOT closed here. It is the same shape and
// the same size as the one ResendVerification documents openly, and it is
// bounded by the same argument: separating a few milliseconds of I/O from
// network jitter needs many samples of the SAME address. Padding it would mean
// writing a vault row and a token digest for every probe, which converts a
// timing oracle into an unbounded storage-amplification vector aimed at an
// unauthenticated endpoint. Stated rather than hidden, because a control this
// argument depends on must not be silently loosened later.
//
// # Nothing here is a secret, and the verification token in particular is not
//
// Every field is an identifier the caller already supplied or may freely learn.
// The verification token is deliberately absent: it travels to the address being
// claimed and nowhere else, so that clicking the link proves control of the
// mailbox. Returning it — here, or through the empty RegisterResponse this maps
// to — would let anyone who can call Register verify an address they do not own,
// which is the entire property the mail exists to establish.
type RegisterResult struct {
	// Created is false when the address was already claimed by somebody else.
	Created bool

	UserID     ids.UserID
	SubjectID  string
	EmailIndex contract.EmailIndex

	// Position is the log position of the append, for read-your-writes.
	Position eventsourcing.Position
}

// Register claims an address and creates the account that claims it — and
// creates NO CREDENTIAL.
//
// # Why no credential (IDENTITY-REVIEW C8)
//
// A password accepted here would be set by whoever typed the address, which is
// not necessarily whoever can read mail sent to it. The verification click that
// follows proves control of the MAILBOX; it does not prove that the party who
// chose the password controls that mailbox. When those are different people, the
// victim's own proof is what switches the attacker's credential on — this is the
// pre-hijacking attack of Sudhodanan & Paverd (USENIX Security 2022), and it was
// executed end to end against this system before this handler was changed.
//
// Two fixes were on the table. Voiding the credential on verification is the
// paper's own rule and cannot be applied here: there is no password-reset flow,
// so voiding the password locks out every legitimate registrant. The other is
// this one — do not create the credential at all, and take the password in the
// same request as the proof (VerifyEmail). It removes the premise rather than
// mitigating the consequence: there is no attacker-set credential for the
// mailbox owner's proof to activate, because none exists until the proof
// arrives.
//
// The account is still created here, and deliberately. See the doc on
// VerifyEmail for what that costs and why an EmailReservation alone would cost
// more.
//
// # Order of operations, and why the append is last
//
// Everything that can fail independently happens BEFORE the atomic append, so
// the append is the commit point and nothing follows it that could leave the log
// describing a state the rest of the system does not have:
//
//  1. normalize the address, derive its blind index
//  2. mint the subject and user ids
//  3. decide the reservation; a claim held by somebody else stops here, writing
//     at most ONE event — the notice on the address's own reservation stream —
//     and no vault row, no token and no account for a probe
//  4. write the address to the vault
//  5. mint the verification token and store its digest
//  6. append the reservation claim, the account creation and the verification
//     request, atomically
//
// Steps 4-5 before 6 is a deliberate trade, and step 5 follows the argument
// already written at step 4. A crash before the append leaves an unreferenced
// vault row and an unreferenced token digest — garbage, both of it holding a
// pseudonym and no account — and the retry succeeds completely. Neither is
// reachable: the token is redeemable only through VerifyEmail, which resolves
// the pseudonym through UserDirectory and refuses a subject with no account, and
// both expire on their own.
//
// The reverse order trades that for an account that exists with no address to
// mail and no token to redeem — and no retry repairs it, because the address is
// claimed by the very append that succeeded.
func (r *Registration) Register(ctx context.Context, cmd RegisterCommand) (RegisterResult, error) {
	if cmd.IdempotencyKey == "" {
		return RegisterResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if r.byCaller != nil && cmd.CallerScope == "" {
		return RegisterResult{}, errs.Internalf(
			"the per-caller mail ceiling has no scope to count against")
	}

	email, err := domain.NormalizeEmail(cmd.Email)
	if err != nil {
		return RegisterResult{}, err
	}
	index, err := r.index.Of(email)
	if err != nil {
		return RegisterResult{}, err
	}

	// Spent HERE, before the reservation is even loaded, so both outcomes of this
	// command cost the same budget. See RegistrationDeps.AddressLimiter for why
	// spending only on the refused path would make the ceiling an oracle for the
	// question this whole handler is shaped to refuse.
	//
	// The answer is carried, not acted on: it gates the notice far below and
	// nothing else. A registration is never refused for want of mail budget.
	mayNotify := r.spendMailBudget(ctx, cmd.CallerScope, index)

	now := r.clock.Now().UTC()
	userID := ids.New[ids.User](now, r.entropy)
	subjectID := ids.New[ids.Subject](now, r.entropy).String()

	reservation, err := r.reservations.Load(ctx, string(index))
	if err != nil {
		return RegisterResult{}, fmt.Errorf("loading the reservation for a registration: %w", err)
	}
	// Reserve records a release first when a previous UNVERIFIED claim has lapsed,
	// so the log explains what happened to the earlier registrant instead of
	// overwriting them silently.
	if err := reservation.Reserve(index, subjectID, now.Add(r.lease), now); err != nil {
		if errs.ReasonOf(err) == errs.Conflict {
			// Already claimed. Deliberately NOT an error: a CONFLICT on the wire
			// answers "does an account exist for this address?" precisely, which
			// is the oracle this whole flow is shaped to deny. The work done so
			// far — including the hash — is what makes the two paths cost the
			// same.
			//
			// It is no longer a dead end, though, and that is the point of the
			// call below. The wire still says nothing; the MAILBOX is told. This
			// branch is the one a returning user hits most often, and until the
			// notice existed they were shown "check your email" and then sent
			// nothing at all, with no route back to the account they already had.
			// The address is the one channel that proves ownership before
			// disclosing anything, so it is the only one the answer may travel on.
			r.notifyClaimHolder(ctx, cmd.IdempotencyKey, reservation, mayNotify, now)
			return RegisterResult{}, nil
		}
		return RegisterResult{}, err
	}

	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, subjectID, index, now); err != nil {
		return RegisterResult{}, err
	}
	// No SetPassword here, and domain.User refuses one anyway while the address
	// is unproven. An account with no credential is now a FIRST-CLASS state
	// rather than the hole the old comment on this line worried about: it is not
	// reachable by any authentication (CanAuthenticate refuses an unverified
	// Pending account before it looks at a credential), and the way out of it is
	// the verification link, not a reset flow.

	// The address goes to the vault and NOWHERE else. Every event below carries
	// the pseudonym and the keyed index; neither can be read back into an address
	// without a key that no projector, log or event holds (ADR-002).
	if err := r.vault.PutAll(ctx, pii.SubjectID(subjectID), map[pii.Field]string{
		pii.FieldEmail: email,
	}); err != nil {
		return RegisterResult{}, fmt.Errorf("storing the address for a registration: %w", err)
	}

	if err := r.issueVerification(ctx, subjectID, index, user, now); err != nil {
		return RegisterResult{}, err
	}

	res, err := r.appendStreams(ctx, cmd.IdempotencyKey, subjectID, userID,
		streamPart{ReservationCategory, string(index), reservation},
		streamPart{UserCategory, userID.String(), user},
	)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Lost the race for the reservation stream. The append is atomic, so
			// NOTHING was written — not the claim, not the account. Reported as
			// the same non-answer as the sequential case, for the same reason.
			return RegisterResult{}, nil
		}
		return RegisterResult{}, err
	}

	return RegisterResult{
		Created:    true,
		UserID:     userID,
		SubjectID:  subjectID,
		EmailIndex: index,
		Position:   res,
	}, nil
}

// spendMailBudget consumes this registration's share of the SHARED triggered-mail
// ceilings and reports whether the duplicate-registration notice may be sent.
//
// # It never refuses the registration
//
// The return value is a permission to MAIL, not a permission to proceed. A
// ceiling that could refuse a registration would hand an attacker a way to stop
// somebody claiming an address by probing it three times an hour, and it would
// do so through a wire response that only one of the two branches can produce —
// reopening the account-existence oracle from the other side.
//
// # Caller first, and the address only if the caller had budget
//
// The same order and the same argument as ResendVerification.spend. A sweep that
// is already over its own ceiling must not still be able to spend a thousand
// victims' address budgets on its way to being ignored: that would convert the
// attacker's own refusal into a denial of service against everyone on their list,
// silencing the legitimate reset and resend mail those people might need.
//
// Note what does NOT leak from the short circuit: whether the address budget was
// spent depends on the CALLER's state, which the caller already knows, and never
// on anything about the address.
//
// # Fail OPEN, and loudly
//
// The same direction, and for the same reason, as every other ceiling over this
// counter (ResendVerification.spend carries the full argument). Failing closed
// here would mean a Valkey blip silently stops telling people that somebody is
// trying to register their address — a security signal switched off by a cache
// restart. What is not lost when it fails open is the floor: the address's own
// reservation stream still refuses more than domain.MaxDuplicateNoticesPerHour,
// and that one is derived from the log rather than from a cache.
func (r *Registration) spendMailBudget(
	ctx context.Context, callerScope string, index contract.EmailIndex,
) bool {
	if !r.spend(ctx, r.byCaller, "caller", callerScope) {
		return false
	}
	return r.spend(ctx, r.byAddr, "address", string(index))
}

// spend consumes one unit of one ceiling. A nil limiter allows: see
// RegistrationDeps.AddressLimiter for what is and is not lost when it is absent.
func (r *Registration) spend(
	ctx context.Context, limiter AttemptLimiter, axis, scope string,
) bool {
	if limiter == nil {
		return true
	}
	decision, err := limiter.Allow(ctx, scope)
	if err != nil {
		// Degraded, allowed, and never silently. The scope is a blind index or a
		// peer address, so this line carries no personal data.
		r.log.WarnContext(ctx, "the triggered-mail ceiling could not be evaluated; "+
			"the registration was allowed unmetered",
			"module", "identity", "reason", "ceiling_unavailable", "axis", axis, "error", err)
		return true
	}
	return decision.Allowed()
}

// notifyClaimHolder records that somebody tried to register with an address that
// is already claimed, so the holder's mailbox can be told.
//
// # It returns nothing, and swallows everything
//
// Every failure below is logged and dropped, and that is forced rather than lax.
// Register must answer the same empty response on this branch as on the one that
// creates an account; an error escaping here would be an error that ONLY the
// taken branch can produce, which is the account-existence oracle restated as a
// status code. There is nothing this call can discover that the caller is
// entitled to learn.
//
// # What decides whether anything is recorded
//
// Three things, and all three must hold. The shared mail ceiling must have had
// budget (mayNotify, spent symmetrically above). The claim must be VERIFIED and
// within its own per-address ceiling — both decided by the aggregate, which is
// the only thing that knows how often this address has already said so, and
// which refuses outright for an unverified claim because mailing an address
// nobody has proven is unsolicited mail (NOTIFICATIONS §5).
//
// # Why the event goes on the RESERVATION stream
//
// Because the fact is about the ADDRESS, not about the account. The reservation
// stream is named from the address's blind index, so the per-address ceiling is
// enforced by the same stream that enforces uniqueness, with the revision the
// aggregate was loaded at as its precondition — two simultaneous probes contend
// and one of them writes nothing, which is one fewer message rather than a
// failure.
//
// The account's own stream was the alternative and is worse in a way that is not
// obvious: appending there lets an unauthenticated stranger move the revision of
// a stream the holder's own commands depend on, turning a probe into a way to
// make somebody else's legitimate request fail its expected-revision check.
func (r *Registration) notifyClaimHolder(
	ctx context.Context,
	idempotencyKey string,
	reservation *domain.EmailReservation,
	mayNotify bool,
	now time.Time,
) {
	if !mayNotify {
		// Over the shared ceiling. Counted, not mailed, and not an error: the
		// budget exists precisely so that repeating this request stops producing
		// messages.
		return
	}
	if !reservation.NoticeDuplicateRegistration(now) {
		// Unverified claim, or the address's own ceiling. The aggregate owns both
		// decisions and has recorded nothing.
		return
	}
	pending := reservation.Uncommitted()
	if len(pending) == 0 {
		r.log.ErrorContext(ctx, "the reservation reported a notice it did not record",
			"module", "identity", "reason", "notice_not_recorded")
		return
	}
	stream, err := eventsourcing.NewStreamID(ReservationCategory, string(reservation.Index()))
	if err != nil {
		r.log.ErrorContext(ctx, "the duplicate-registration notice has no stream to land on",
			"module", "identity", "reason", "notice_stream", "error", err)
		return
	}

	meta := r.metadata(ctx, reservation.SubjectID(), idempotencyKey)
	// The holder is the SUBJECT and emphatically not the actor. Whoever typed the
	// address is unauthenticated and unnamed, and metadata's default — actor
	// equals subject — would write into a permanent audit trail that the account
	// holder tried to register their own address, which is the one reading of this
	// event that is certainly false.
	meta.ActorID = ""

	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			// Derived from the idempotency key, so a retried request produces the
			// same id and the store collapses it. A retry that mailed a second time
			// would make the ceiling's arithmetic wrong by exactly the number of
			// times the network hiccuped.
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, r.schemas, e.EventType()),
		})
	}

	if _, err := r.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream:   stream,
		Expected: eventsourcing.ExpectedFor(reservation),
		Events:   events,
	}}); err != nil {
		// Including ErrWrongExpectedRevision, which here means a concurrent probe
		// or a legitimate command wrote first. Nothing was appended, nothing is
		// mailed, and the caller learns nothing either way.
		r.log.WarnContext(ctx, "the duplicate-registration notice was not appended; "+
			"the address holder will not be told about this attempt",
			"module", "identity", "reason", "notice_append", "error", err)
		reservation.ClearUncommitted()
		return
	}
	reservation.ClearUncommitted()
}

// issueVerification mints the verification token, stores its digest, and records
// the request on the account.
//
// # Why the token is stored BEFORE the append, and why a failure here fails the
// whole registration
//
// The digest row is a separate write from the atomic two-stream append, so one of
// the two happens first and a crash between them has to leave something
// recoverable. Stored first, the loss is a digest row belonging to a subject that
// never got an account: unusable — VerifyEmail resolves the pseudonym through
// UserDirectory and refuses when there is none — invisible to everything else,
// and self-clearing at its own expiry. The retry then registers cleanly.
//
// Stored second, the loss is an account that exists, holds the address, and has
// no token. There is no retry: the address is claimed by the append that
// succeeded, so the same person registering again is answered with the
// indistinguishable "already claimed" non-answer, and the account sits Pending
// forever with no way in. That is the same argument the credential row is written
// under, one step above, and it points the same way.
//
// A failure to store therefore fails the registration outright rather than
// proceeding without a token. Argued from what the person experiences: on failure
// they see an error, retry, and get a working account, because the append never
// ran and the address is still free. Proceeding would show them success and then
// silence — no mail, no way to ask for another one, and an address they can never
// register again. A visible failure that is recoverable beats an invisible one
// that is not.
//
// # One live token per purpose
//
// RevokeAll runs before Issue. For a brand-new subject there is nothing to
// revoke, and that is exactly why it is cheap to state here: the invariant
// identity.md §7 rule 7 asks for — at most one outstanding token of a purpose per
// subject — becomes a property of this call site rather than a coincidence of
// subject ids being freshly minted on every attempt. The day registration derives
// its subject id from the idempotency key, which is the obvious way to make a
// retry return the original result, a retry would otherwise leave two live
// verification links for one address and using one would leave the other usable.
//
// Under today's fresh-subject ids a retry cannot produce two live tokens for one
// ADDRESS either, for a stronger reason than revocation: only one subject ever
// wins the reservation stream, and a token belonging to any of the losers cannot
// be redeemed at all, because no account resolves from its pseudonym.
//
// # The plaintext stops here
//
// It is deliberately not returned, not stored, and not logged. RegisterResult
// carries it nowhere, because a caller that can read the token can verify an
// address it does not control — which would make the emailed link decorative and
// registration itself an account-takeover primitive for any address not yet
// claimed. The event carries no token, no digest and no address either (ADR-002):
// only the pseudonym, the keyed index and the deadline.
//
// It is also, today, delivered NOWHERE — no reactor consumes
// EmailVerificationRequested yet, so the minted secret is dropped on this line and
// the mail that would carry it is not sent. That is a missing component, not a
// missing decision here: whatever sends the mail must be handed the plaintext at
// the moment it is minted, since the digest is one-way and no later reader can
// recover it.
func (r *Registration) issueVerification(
	ctx context.Context,
	subjectID string,
	index contract.EmailIndex,
	user *domain.User,
	now time.Time,
) error {
	token, err := r.minter(PurposeEmailVerification, now)
	if err != nil {
		return fmt.Errorf("minting a verification token for a registration: %w", err)
	}
	if err := r.tokens.RevokeAll(ctx, PurposeEmailVerification, subjectID); err != nil {
		return fmt.Errorf("voiding outstanding verification tokens for a registration: %w", err)
	}
	if err := r.tokens.Issue(
		ctx, PurposeEmailVerification, subjectID, token.Digest, token.ExpiresAt,
	); err != nil {
		return fmt.Errorf("storing the verification token for a registration: %w", err)
	}

	// Recorded on the ACCOUNT aggregate so it rides the same atomic append as
	// UserRegistered and PasswordSet. It belongs on the user stream and not the
	// reservation stream: the reservation records who holds a claim, while this
	// records that a particular ACCOUNT was asked to prove one — the same stream
	// EmailVerified lands on when the proof arrives, so the request and its
	// outcome can be read in order without joining two streams.
	//
	// Recorded from here rather than through a decide method on domain.User
	// because it changes no state the aggregate holds: no invariant reads it, and
	// User.Apply has no case for it. It is a fact the APPLICATION produced — this
	// is the layer that minted the token and knows its deadline — and putting it
	// behind a domain method would mean handing the domain an expiry it cannot
	// compute and cannot check.
	//
	// LAST in the aggregate's uncommitted list, after PasswordSet. The order is
	// the order a reader sees: the account exists, then it has a password, then it
	// is asked to prove its address. A request recorded before the account was
	// created would be a fact about something that does not yet exist.
	eventsourcing.Record(user, &contract.EmailVerificationRequested{
		SubjectID:   subjectID,
		Index:       index,
		ExpiresAt:   token.ExpiresAt,
		RequestedAt: now,
	})
	return nil
}

// VerifyEmailCommand presents an emailed verification token and the password
// the account is to be given.
type VerifyEmailCommand struct {
	// Token is the plaintext from the link. It is hashed here and never stored,
	// logged or placed in an event: a token in a log line is a live credential in
	// a system whose logs outlive it by months.
	Token string

	// Password is the raw secret as typed, normalized here under RFC 8265's
	// OpaqueString profile before it is screened or hashed.
	//
	// It arrives HERE rather than at registration because the party presenting
	// this token has just demonstrated control of the mailbox, and that is the
	// only party entitled to choose the credential for it (IDENTITY-REVIEW C8).
	Password string

	// Username is the public handle the account will be known by (ADR-051). It
	// is MANDATORY, and it arrives here for the same reason the password does.
	//
	// # Why not at Register
	//
	// Two reasons, and the second is decisive.
	//
	// A handle claimed at registration is claimed by whoever typed an address
	// they may not control. The address squat that leaves is bounded — an
	// unverified claim lapses after DefaultReservationLease — but a handle squat
	// is NOT: a handle is claimed permanently, and the tombstone rule means it
	// cannot be reclaimed even in principle. So the cheapest form of the attack
	// would be a script sweeping every desirable handle with throwaway addresses
	// it never proves, and every one it took would be gone forever. Claiming here
	// prices each squatted handle at one mailbox the attacker must actually
	// control.
	//
	// The decisive reason is that a handle at Register DESTROYS registration's
	// indistinguishability. RegisterResponse is empty precisely so that "the
	// address was free" and "the address was taken" are the same answer. Pair the
	// address with a fresh random handle and the two stop being the same answer:
	// register, then ask the public availability RPC about the handle. Taken means
	// the registration went through, which means the address was free; free means
	// it did not, which means the address has an account. One extra unauthenticated
	// call, and the oracle identity.md §11 exists to close is open again — through
	// a field, not through a message.
	//
	// # What it costs, and how that is paid
	//
	// A handle cannot be confirmed available until the link is clicked. That is
	// answered by CheckUsernameAvailability being public: a person picks and
	// checks at the FORM, and the check is advisory because any check-then-claim
	// is racy. If they lose the race, the refusal is explicit — see VerifyEmail —
	// and it is refused BEFORE the token is consumed, so the link survives.
	Username string

	// IdempotencyKey makes a retried verification derive the same event ids.
	IdempotencyKey string
}

// VerifyEmailResult reports the outcome of a verification.
type VerifyEmailResult struct {
	SubjectID string
	UserID    ids.UserID

	// Changed is false when the token was valid but everything it asserts was
	// already recorded — a link clicked twice, or prefetched by a mail client.
	// Nothing was appended in that case, and it is not an error.
	Changed bool

	Position eventsourcing.Position
}

// VerifyEmail proves control of the address, sets the account's first password,
// and makes the claim permanent.
//
// # Why the password is set here (IDENTITY-REVIEW C8)
//
// Because this is the one moment in the flow at which the system knows who it is
// talking to. Presenting a live token IS proof of control of the mailbox, and
// the credential is created for, and by, that party in the same request. See
// Register for the attack this removes.
//
// # What is screened, and in what order, and what that does to the token
//
// The password is screened — length by domain.NormalizePassword, breach by the
// corpus — BEFORE the token is consumed, and the ordering answers the question
// "does a rejected password burn the link?". It does not.
//
// The argument for burning it is that a token surviving repeated attempts is a
// guessing surface. That argument does not apply to these two refusals, because
// neither is a function of anything the caller does not already know: a password
// is too short, or it is in a public breach corpus, for reasons entirely
// contained in the bytes the caller just sent. Nothing about the token, the
// account or the address changes the answer, so repeating the call with a
// different password buys an attacker exactly one bit they already had. The
// token's own guessing surface is unchanged: a wrong digest fails at Consume,
// atomically and identically, however good the password beside it was.
//
// The argument against burning it is concrete and one-directional. A person who
// follows their link and picks a weak password would otherwise be told "that
// password is no good" and "that link is now dead" in the same breath, and the
// only route back is a resend they have to know to ask for. That is a real
// lockout, produced by the system, for a user who did nothing wrong.
//
// Everything AFTER Consume does spend the token — the hash, the credential
// write, the append. Those failures are recoverable through
// ResendEmailVerification, which still admits the account because it is still
// Pending and still unverified, and the retry then re-screens and re-hashes from
// scratch.
//
// # The token is spent BEFORE the append
//
// Consume is atomic and single-use, and it runs before anything is decided about
// the account. If the append then fails, the user must request a new link — an
// inconvenience. The other order is not an inconvenience: appending first and
// consuming after leaves a live token in a mailbox for every verification that
// crashed at the wrong moment, and a single-use secret that is sometimes
// multi-use is exactly what an attacker who has intercepted one mail needs.
//
// # Every session established before the proof is voided
//
// The paper's rule applied to the half of it that is enforceable here: when an
// identifier becomes verified, nothing that was established while it was
// unproven may survive. Today that voids nothing, because a pre-verification
// account has no credential and therefore no session — see the call site for why
// it is written anyway, and for the flows it is waiting for.
//
// # The public handle is claimed here too, and the refusal is NOT undifferentiated
//
// A taken handle is answered with a plain CONFLICT saying so. Every other
// refusal in this module is deliberately indistinguishable (ADR-036), and this
// one deliberately is not: a handle is PUBLISHED by design, its availability is
// served by a public RPC whose whole purpose is to answer this question, and a
// vague refusal here would tell the person nothing while telling an attacker
// nothing they could not already read. The asymmetry is the point — the address
// is secret and the handle is not, and pretending otherwise about the handle
// would only break the signup form.
//
// It is refused BEFORE Consume, which is the same placement the password
// screening gets and it is placed there for the user rather than for the
// attacker: a person who picks a taken handle keeps their link. The argument
// §4.3 makes for the password — the refusal is a function of the caller's own
// bytes, so repeating the call buys nothing — does not literally apply, because
// handle availability is system state. What replaces it is stronger: that state
// is public and free to query, so burning the link would cost a legitimate user
// their only way in and cost an attacker nothing at all.
//
// # Three streams now, and the same reason there were two
//
// EmailVerified belongs to the account and EmailReservationConfirmed belongs to
// the claim, and a confirmation that landed without the other half would leave a
// permanent claim on an address the account does not consider verified — or an
// account that believes it is verified while its claim is still a lease that will
// lapse and hand the address to somebody else. One atomic append, two
// preconditions.
//
// UsernameReserved is the third, on the handle's own stream, and it carries the
// same argument one step further. Written separately, a crash between the two
// leaves either a handle claimed by an account that does not know it holds one —
// unusable, unreclaimable, and permanently burned — or an account that believes
// it has a handle no reservation records, so the next person to want that handle
// takes it and two accounts answer to one name. Both halves go in with the
// verification or neither does.
//
// The precondition on the handle's stream is what makes uniqueness real. Under
// contention the pre-check above is advisory; the append is authoritative, and a
// loser's ENTIRE verification is rolled back — no password, no verification, no
// claim.
func (r *Registration) VerifyEmail(ctx context.Context, cmd VerifyEmailCommand) (VerifyEmailResult, error) {
	if cmd.IdempotencyKey == "" {
		return VerifyEmailResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.Token == "" {
		return VerifyEmailResult{}, errs.ValidationFailedf("a verification token is required")
	}
	if cmd.Password == "" {
		// Refused explicitly rather than left to NormalizePassword's length rule,
		// so that "you sent no password" and "your password is six characters"
		// are not the same message. Neither discloses anything: both are
		// properties of the request, evaluated before the token is looked at.
		return VerifyEmailResult{}, errs.ValidationFailedf(
			"a password is required; the account has none until this call sets one")
	}

	// Normalized FIRST, before the breach corpus is consulted and long before the
	// token is spent. Every refusal it can produce — too short, a bad character, a
	// reserved name — is a function of the caller's own bytes and a public rule,
	// so none of them costs anything and none of them may cost the link.
	username, err := domain.NormalizeUsername(cmd.Username)
	if err != nil {
		return VerifyEmailResult{}, err
	}

	// Screening happens on the RAW password, before normalization and before
	// hashing — moved from Register unchanged, and for the reason it was written
	// there: a rejected password must not cost an Argon2id evaluation, which is
	// a free amplification vector for anyone posting known-breached passwords.
	breached, corpus, err := r.breach.Breached(ctx, cmd.Password)
	switch {
	case err != nil:
		// FAIL OPEN, and say so. An unreachable corpus is an outage at a third
		// party, and blocking on it would stop every verification in the system —
		// which is now the ONLY route into a new account. The signal is recorded
		// rather than swallowed: a screening step nobody can tell has stopped
		// running is the same as not having one.
		r.log.WarnContext(ctx, "breach screening did not run; the password was accepted unscreened",
			"module", "identity", "reason", "breach_corpus_unavailable", "error", err)
	case breached:
		return VerifyEmailResult{}, errs.ValidationFailedf(
			"this password appears in a known data breach (%s); choose a different one", corpus)
	}

	password, err := domain.NormalizePassword(cmd.Password)
	if err != nil {
		return VerifyEmailResult{}, err
	}

	now := r.clock.Now().UTC()

	// The handle's availability is decided against its STREAM, before the token
	// is spent. A taken handle stops the call here, having written nothing and
	// having consumed nothing — the link is still live and the person picks
	// again.
	//
	// This aggregate is carried all the way to the append: the revision it was
	// loaded at becomes the append's precondition, so a handle taken between this
	// read and the commit loses the whole verification rather than silently
	// overwriting somebody's claim.
	usernameClaim, err := r.usernames.Load(ctx, username)
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"loading the username reservation for a verification: %w", err)
	}
	if !usernameClaim.Available() {
		// Said plainly. See the doc comment for why this one refusal is allowed to
		// be specific when every other refusal in this module is not — and see
		// UsernameReservation.Reserve for the one distinction it still refuses to
		// draw, which is between "taken" and "tombstoned".
		return VerifyEmailResult{}, errs.Conflictf("that username is not available; choose another")
	}

	subjectID, err := r.tokens.Consume(
		ctx, PurposeEmailVerification, r.digest(PurposeEmailVerification, cmd.Token), now)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// Unknown, already spent and expired are one outcome by design. "That
			// link has expired" tells whoever holds it that the address it was
			// sent to has an account.
			return VerifyEmailResult{}, errs.ValidationFailedf(
				"this verification link is no longer valid; request a new one")
		}
		return VerifyEmailResult{}, err
	}

	userID, err := r.directory.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			return VerifyEmailResult{}, errs.ValidationFailedf(
				"this verification link is no longer valid; request a new one")
		}
		return VerifyEmailResult{}, fmt.Errorf("resolving the account for a verification: %w", err)
	}

	user, err := r.users.Load(ctx, userID.String())
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf("loading the account for a verification: %w", err)
	}
	// The index comes from the ACCOUNT's own events, never from the request. It
	// is what names the reservation stream, so taking it from anywhere a caller
	// can influence would let a token for one address confirm a claim on another.
	index := user.EmailIndex()
	if index == "" {
		return VerifyEmailResult{}, errs.Internalf(
			"the account for this verification claims no address")
	}
	// Captured BEFORE the transition, because it decides whether this call is a
	// first verification (which sets the password) or a repeat (which must not).
	// A live token for an already-verified account is not reachable through
	// Register or ResendEmailVerification — neither issues one for a verified
	// account — but the branch is written rather than assumed, because the
	// alternative is SetPassword refusing with a conflict and turning a harmless
	// double click into an error page.
	alreadyVerified := user.EmailVerified()

	// VerifyEmail also records the activation when the account has by then
	// enrolled a second factor, which is why this is one call and not two.
	if err := user.VerifyEmail(index, now); err != nil {
		return VerifyEmailResult{}, err
	}

	// FIRST, so that domain.User.SetPassword sees a verified account. The
	// aggregate refuses a password on an unproven address, which is the whole
	// pre-hijacking defence — and it means the two calls are ordered by a rule
	// rather than by habit.
	var credentialID ids.CredentialID
	if !alreadyVerified {
		credentialID = ids.New[ids.Credential](now, r.entropy)
		verifier, hashErr := r.hasher.Hash(ctx, password, userID, credentialID)
		if hashErr != nil {
			// Propagated unchanged, and NOT retried here. The hasher is bounded at
			// the core count because throughput declines past it, so over capacity
			// it returns RATE_LIMITED after queueing — a retry in this handler
			// would add load to the exact condition the bound exists to relieve.
			// The token is already spent by this point; the recovery is a resend,
			// which the account still qualifies for because nothing was appended.
			return VerifyEmailResult{}, hashErr
		}
		if err := user.SetPassword(credentialID, now); err != nil {
			return VerifyEmailResult{}, err
		}
		// Written BEFORE the append, for the reason the token digest is: a crash
		// between the two must leave something recoverable, and a verifier with no
		// PasswordSet event is inert — the aggregate is the authority on whether
		// the account has a password, and it says no. StoreFirst is what makes
		// that inert row recoverable rather than fatal; see its doc.
		//
		// EnabledAt is set, not left zero: the usable-credential lookup filters on
		// `enabled_at IS NOT NULL`, so a zero value produces an account that is
		// passwordless with a password row sitting in the table.
		if err := r.credentials.StoreFirst(ctx, NewPasswordCredential{
			ID:            credentialID,
			SubjectID:     subjectID,
			Verifier:      verifier,
			PepperVersion: r.hasher.PepperVersion(),
			EnabledAt:     now,
		}); err != nil {
			return VerifyEmailResult{}, fmt.Errorf(
				"storing the password verifier for a verification: %w", err)
		}
	}

	// LAST on the account's stream, after the proof and after the credential. The
	// order is the order a reader sees: the address is proven, the account gets
	// something to sign in with, and then it gets the name other people will know
	// it by. It sits AFTER SetPassword rather than between it and EmailVerified so
	// that the pair the pre-hijacking defence depends on — verified, then password
	// — stays adjacent in the log and in this function.
	//
	// domain.User refuses a handle on an unproven address, so this call is ordered
	// by a rule rather than by habit, exactly as SetPassword is. Idempotent for the
	// SAME handle, and a CONFLICT for a different one: there is no username-change
	// flow, and a second assignment would strand the first handle claimed on its
	// own stream by an account that no longer answers to it.
	if err := user.AssignUsername(username, now); err != nil {
		return VerifyEmailResult{}, err
	}

	reservation, err := r.reservations.Load(ctx, string(index))
	if err != nil {
		return VerifyEmailResult{}, fmt.Errorf("loading the reservation for a verification: %w", err)
	}
	// Confirm refuses a subject that does not hold the claim, and refuses a claim
	// that has already lapsed. Both refusals are the point: without the first, a
	// token could confirm an address out from under its holder; without the
	// second, a late link would take an address back from whoever legitimately
	// claimed it after the lease ran out.
	if err := reservation.Confirm(subjectID, now); err != nil {
		return VerifyEmailResult{}, err
	}

	// The handle's claim, on the aggregate loaded BEFORE the token was spent — so
	// the revision this reserves against is the one the append will assert, and a
	// handle taken in between loses this whole verification rather than
	// overwriting the winner.
	//
	// Reserve is idempotent for the same subject and refuses every other, which
	// is what makes the one case the pre-check above answers differently harmless:
	// a caller holding a LIVE token for an account that ALREADY holds this handle
	// is refused early with "not available" instead of succeeding as a no-op. No
	// flow in this module can produce that — nothing issues a verification token
	// for a verified account — and the refusal costs the caller nothing, because
	// it happens before Consume and leaves the link live.
	if err := usernameClaim.Reserve(username, subjectID, now); err != nil {
		return VerifyEmailResult{}, err
	}

	// Every session for this subject dies here (IDENTITY-REVIEW C8).
	//
	// # What it does today, stated plainly: nothing
	//
	// A pre-verification account has no credential, so no authentication can
	// succeed for it, so no session exists to void. RevokeAllSessions reads an
	// empty work list, appends nothing and does not even reach the epoch bump.
	// That is not an argument against making the call — it is the argument FOR
	// making it now. The rule is free while it is a no-op and expensive to
	// retrofit once it is not, and the moment a flow exists that can leave a
	// session standing across a verification, the enforcement is already here
	// rather than being remembered by whoever writes that flow.
	//
	// The precedent is one file up: issueVerification calls TokenStore.RevokeAll
	// on a subject id minted seconds earlier, where there is provably nothing to
	// revoke, so that the invariant is a property of the call site instead of a
	// coincidence of how ids happen to be generated today.
	//
	// # Which flows this is waiting for
	//
	// Password reset, email change and federated linking — none of which exist
	// (no RPC, no use case, no event). Each is a variant in Sudhodanan & Paverd:
	// re-verification after an email change runs through this same handler, and
	// the attacker's "unexpired session" variant is defeated at that point
	// without the future author of that flow having to know the paper. The
	// requirement is written into identity.md §4, §7 and §12 so it arrives with
	// them.
	//
	// # Why here, and not in a reactor on EmailVerified
	//
	// A reactor would catch every future producer of the event, which is
	// genuinely attractive — but it is asynchronous. The window between the
	// append and the reactor's revocation is exactly the window the attack uses,
	// and it is unbounded when the reactor is behind or stopped. The rule has to
	// hold at the instant the identifier becomes verified, and only the handler
	// can promise that.
	//
	// # Why BEFORE the append, and why the error is not swallowed
	//
	// Both orderings can fail; they fail in opposite directions. Revoked first,
	// a failure leaves an account that is NOT verified and has NO password: the
	// caller sees an error and recovers through ResendEmailVerification, and
	// nothing was granted. Appended first, a failure leaves an account that IS
	// verified with the attacker's session still live and no retry — the exact
	// state the rule exists to forbid, arriving through an error path.
	//
	// The one cost of this order is that the token is already spent, so the
	// recovery is a fresh link rather than a retry of this call. That is the same
	// price everything after Consume already pays, and it buys the failure
	// falling towards less access rather than more.
	//
	// Except is zero: a verification is not performed from a session, so there is
	// no caller's session to spare. It also runs on the idempotent no-change path
	// below, deliberately — the token was consumed either way, and a spent token
	// is a real proof event whatever the aggregates already recorded.
	if _, err := r.revocations.RevokeAllSessions(ctx, RevokeAllSessionsCommand{
		SubjectID: subjectID,
		Reason:    RevokeReasonEmailVerified,
		// Derived from this command's key so a retried verification collapses
		// into the same session events instead of appending a second set, and
		// suffixed so it cannot collide with the event ids appendBoth derives
		// from the bare key.
		IdempotencyKey: cmd.IdempotencyKey + ":" + RevokeReasonEmailVerified,
	}); err != nil {
		return VerifyEmailResult{}, fmt.Errorf(
			"voiding the sessions established before this verification: %w", err)
	}

	result := VerifyEmailResult{SubjectID: subjectID, UserID: userID}
	if len(user.Uncommitted()) == 0 && len(reservation.Uncommitted()) == 0 &&
		len(usernameClaim.Uncommitted()) == 0 {
		// Both aggregates were already in the state the token asserts. Appending
		// nothing is correct, and reporting success is correct: the user clicked
		// a link twice and has no failure to be told about.
		return result, nil
	}

	pos, err := r.appendStreams(ctx, cmd.IdempotencyKey, subjectID, userID,
		streamPart{ReservationCategory, string(index), reservation},
		streamPart{UsernameCategory, username, usernameClaim},
		streamPart{UserCategory, userID.String(), user},
	)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Lost a race. The append is atomic, so NOTHING was written — not the
			// verification, not the password event, not either claim — and the
			// credential row written above is inert without its PasswordSet
			// (StoreFirst's own contract). The handle is the only stream here that
			// two live callers can contend on, so this is said plainly for the same
			// reason the pre-check is.
			return VerifyEmailResult{}, errs.Conflictf(
				"that username is not available; choose another").Wrap(err)
		}
		return VerifyEmailResult{}, err
	}
	result.Changed = true
	result.Position = pos
	return result, nil
}

// streamPart is one aggregate and the stream it belongs on.
//
// A named type rather than three positional arguments because two of the three
// fields are strings and the compiler cannot tell a transposed pair apart — and
// a category swapped with a key produces a stream name that is syntactically
// valid, appends successfully, and is wrong forever.
type streamPart struct {
	category eventsourcing.Category
	key      string
	agg      eventsourcing.Root
}

// appendStreams writes every part in ONE atomic append.
//
// Registration passes two parts — the address claim and the account.
// Verification passes three, adding the public handle's claim. The server
// evaluates every precondition and commits all of them or none, so there is no
// ordering to choose between and no window in which one exists without another.
//
// Streams carrying no uncommitted events are omitted rather than appended empty:
// a multi-append entry with no events is refused by the adapter, and an entry
// whose only content is a precondition would turn an idempotent replay into a
// concurrency failure.
//
// The event ids are derived from ONE sequence spanning every stream, so no two
// events of a command share an id and a retry reproduces every id exactly. That
// makes the ORDER of the parts load-bearing even though atomicity does not
// depend on it: the parts must be passed in the same order on every retry, which
// is why they are written out at each call site rather than collected from a map.
//
// The CLAIMS lead and the account follows, at both call sites. Ordering does not
// affect atomicity — the server commits all or none — but it fixes which ids
// belong to which stream, and it means a reader of the log sees the entries that
// decide whether the append may happen at all before the ones that describe what
// it did.
func (r *Registration) appendStreams(
	ctx context.Context,
	idempotencyKey, subjectID string,
	userID ids.UserID,
	parts ...streamPart,
) (eventsourcing.Position, error) {
	meta := r.metadata(ctx, subjectID, idempotencyKey)

	var (
		appends []eventsourcing.StreamAppend
		seq     int
	)
	for _, part := range parts {
		pending := part.agg.Uncommitted()
		if len(pending) == 0 {
			continue
		}
		stream, err := eventsourcing.NewStreamID(part.category, part.key)
		if err != nil {
			return eventsourcing.Position{}, err
		}
		events := make([]eventsourcing.PendingEvent, 0, len(pending))
		for _, e := range pending {
			events = append(events, eventsourcing.PendingEvent{
				ID:    eventsourcing.DeriveEventID(idempotencyKey, seq),
				Event: e,
				// Stamped per EVENT TYPE, not once for the command: two events of
				// one command can sit at different schema versions.
				Meta: eventsourcing.StampSchemaVersion(meta, r.schemas, e.EventType()),
			})
			seq++
		}
		appends = append(appends, eventsourcing.StreamAppend{
			Stream: stream,
			// NoStream for a brand-new aggregate, the exact loaded revision
			// otherwise. The first is what makes an address and a handle unique; the
			// second is what makes taking over a lapsed address claim safe under
			// concurrency.
			Expected: eventsourcing.ExpectedFor(part.agg),
			Events:   events,
		})
	}
	if len(appends) == 0 {
		return eventsourcing.Position{}, nil
	}

	results, err := r.appender.AppendToMany(ctx, appends)
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	// Every result carries the same log position — one append, one commit — so
	// the first is the consistency token for the whole command.
	position := results[0].Position

	// Cleared only now. Clearing before the append is durable would lose the
	// events if the caller retried after a transient failure.
	for _, part := range parts {
		part.agg.ClearUncommitted()
	}
	return position, nil
}

// metadata builds the envelope shared by every event of one command.
//
// It carries pseudonyms and nothing else: no address, no name, and no OrgID,
// because a registration happens before any organization exists.
//
// The causation chain is resolved ONCE here, mirroring what Repository.Save does
// for a single-stream append — an explicit value from the context wins, and a
// write with no ambient trace becomes the root of its own chain using
// deterministic values, so a retried command produces one chain rather than two.
func (r *Registration) metadata(
	ctx context.Context, subjectID, idempotencyKey string,
) eventsourcing.Metadata {
	meta := eventsourcing.Metadata{
		OccurredAt: r.clock.Now().UTC(),
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
	return meta
}
