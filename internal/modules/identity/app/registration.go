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
	users        AggregateLoader[*domain.User]
	appender     eventsourcing.MultiAppender
	tokens       TokenStore
	minter       TokenMinter
	digest       TokenDigest
	directory    UserDirectory
	revocations  SessionRevoker
	lease        time.Duration
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
	Users        AggregateLoader[*domain.User]
	Appender     eventsourcing.MultiAppender
	Tokens       TokenStore
	Minter       TokenMinter
	Digest       TokenDigest
	Directory    UserDirectory

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
	return &Registration{
		clock: deps.Clock, entropy: deps.Entropy, index: deps.Index,
		breach: deps.Breach, hasher: deps.Hasher, vault: deps.Vault,
		credentials: deps.Credentials, reservations: deps.Reservations,
		users: deps.Users, appender: deps.Appender, tokens: deps.Tokens,
		minter: deps.Minter, digest: deps.Digest, directory: deps.Directory,
		revocations: deps.Revocations,
		lease:       lease, log: log,
		schemas: deps.Schemas,
	}, nil
}

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
//  3. decide the reservation; a claim held by somebody else stops here, having
//     written nothing at all — no vault row for a probe
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

	email, err := domain.NormalizeEmail(cmd.Email)
	if err != nil {
		return RegisterResult{}, err
	}
	index, err := r.index.Of(email)
	if err != nil {
		return RegisterResult{}, err
	}

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

	res, err := r.appendBoth(ctx, cmd.IdempotencyKey, subjectID, index, userID, reservation, user)
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
// # Two streams again, and the same reason
//
// EmailVerified belongs to the account and EmailReservationConfirmed belongs to
// the claim, and a confirmation that landed without the other half would leave a
// permanent claim on an address the account does not consider verified — or an
// account that believes it is verified while its claim is still a lease that will
// lapse and hand the address to somebody else. One atomic append, two
// preconditions.
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
	if len(user.Uncommitted()) == 0 && len(reservation.Uncommitted()) == 0 {
		// Both aggregates were already in the state the token asserts. Appending
		// nothing is correct, and reporting success is correct: the user clicked
		// a link twice and has no failure to be told about.
		return result, nil
	}

	pos, err := r.appendBoth(ctx, cmd.IdempotencyKey, subjectID, index, userID, reservation, user)
	if err != nil {
		return VerifyEmailResult{}, err
	}
	result.Changed = true
	result.Position = pos
	return result, nil
}

// appendBoth writes the reservation stream and the user stream in ONE atomic
// append.
//
// Streams carrying no uncommitted events are omitted rather than appended empty:
// a multi-append entry with no events is refused by the adapter, and an entry
// whose only content is a precondition would turn an idempotent replay into a
// concurrency failure.
//
// The event ids are derived from ONE sequence spanning both streams, so no two
// events of a command share an id and a retry reproduces every id exactly.
func (r *Registration) appendBoth(
	ctx context.Context,
	idempotencyKey, subjectID string,
	index contract.EmailIndex,
	userID ids.UserID,
	reservation *domain.EmailReservation,
	user *domain.User,
) (eventsourcing.Position, error) {
	reservationStream, err := eventsourcing.NewStreamID(ReservationCategory, string(index))
	if err != nil {
		return eventsourcing.Position{}, err
	}
	userStream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return eventsourcing.Position{}, err
	}

	meta := r.metadata(ctx, subjectID, idempotencyKey)

	var (
		appends []eventsourcing.StreamAppend
		seq     int
	)
	// The reservation goes FIRST in the slice. Ordering does not affect atomicity
	// — the server commits all or none — but it fixes which event ids belong to
	// which stream, and those ids must be stable across a retry.
	for _, part := range []struct {
		stream eventsourcing.StreamID
		agg    eventsourcing.Root
	}{
		{reservationStream, reservation},
		{userStream, user},
	} {
		pending := part.agg.Uncommitted()
		if len(pending) == 0 {
			continue
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
			Stream: part.stream,
			// NoStream for a brand-new aggregate, the exact loaded revision
			// otherwise. The first is what makes an address unique; the second is
			// what makes taking over a lapsed claim safe under concurrency.
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
	reservation.ClearUncommitted()
	user.ClearUncommitted()
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
