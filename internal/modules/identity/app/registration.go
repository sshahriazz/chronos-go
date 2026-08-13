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
	digest       TokenDigest
	directory    UserDirectory
	lease        time.Duration
	log          *slog.Logger
}

// RegistrationDeps is everything the two handlers need.
//
// A struct rather than a positional constructor because thirteen dependencies in
// a call are thirteen chances to transpose two of the same type, and two of these
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
	Digest       TokenDigest
	Directory    UserDirectory

	// Lease overrides DefaultReservationLease. Zero means the default.
	Lease time.Duration

	// Log is optional and defaults to slog.Default(). Nothing here logs an
	// address: the only identifiers that reach it are pseudonyms.
	Log *slog.Logger
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
	case deps.Digest == nil:
		return nil, missing("a token digest function")
	case deps.Directory == nil:
		return nil, missing("a user directory")
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
		digest: deps.Digest, directory: deps.Directory,
		lease: lease, log: log,
	}, nil
}

// RegisterCommand is a registration request.
type RegisterCommand struct {
	// Email is the raw address as typed. It is normalized here, and the
	// normalized form is the only one that reaches the vault or the indexer.
	Email string

	// Password is the raw secret as typed, normalized here under RFC 8265's
	// OpaqueString profile before it is screened or hashed.
	Password string

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
// That property is why the Argon2id hash is computed BEFORE the reservation is
// examined. It costs ~51 ms, it dominates everything else the handler does, and
// paying it on both paths is what makes the two responses take the same time. A
// handler that checked availability first would answer a taken address in
// microseconds and a free one in milliseconds — a timing oracle that no wording
// on the wire can hide.
type RegisterResult struct {
	// Created is false when the address was already claimed by somebody else.
	Created bool

	UserID       ids.UserID
	SubjectID    string
	CredentialID ids.CredentialID
	EmailIndex   contract.EmailIndex

	// Position is the log position of the append, for read-your-writes.
	Position eventsourcing.Position
}

// Register claims an address and creates the account that claims it.
//
// # Order of operations, and why the append is last
//
// Everything that can fail independently happens BEFORE the atomic append, so
// the append is the commit point and nothing follows it that could leave the log
// describing a state the rest of the system does not have:
//
//  1. normalize the address, derive its blind index
//  2. screen the password against the breach corpus — before hashing, so a
//     rejected password does not cost a 51 ms hash
//  3. normalize and hash the password
//  4. mint the subject, user and credential ids
//  5. decide the reservation; a claim held by somebody else stops here, having
//     written nothing at all — no vault row for a probe, no credential row
//  6. write the address to the vault and the verifier to the credential table
//  7. append the reservation claim and the account creation, atomically
//
// Steps 6 and 7 in that order are a deliberate trade. A crash between them leaves
// an unreferenced vault row and an unreferenced verifier — garbage, holding a
// pseudonym and no account — and the retry succeeds completely. The reverse order
// trades that for an account that exists with no address to mail and no password
// to sign in with, which no retry repairs because the address is now claimed.
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

	// Screening happens on the RAW password, before normalization and before
	// hashing. Before hashing because a rejected password must not cost an
	// Argon2id evaluation — that is a free amplification vector for anyone
	// posting known-breached passwords.
	breached, corpus, err := r.breach.Breached(ctx, cmd.Password)
	switch {
	case err != nil:
		// FAIL OPEN, and say so. An unreachable corpus is an outage at a third
		// party, and blocking on it would stop every registration in the system.
		// The signal is recorded rather than swallowed: a screening step nobody
		// can tell has stopped running is the same as not having one.
		r.log.WarnContext(ctx, "breach screening did not run; the password was accepted unscreened",
			"module", "identity", "reason", "breach_corpus_unavailable", "error", err)
	case breached:
		return RegisterResult{}, errs.ValidationFailedf(
			"this password appears in a known data breach (%s); choose a different one", corpus)
	}

	password, err := domain.NormalizePassword(cmd.Password)
	if err != nil {
		return RegisterResult{}, err
	}

	now := r.clock.Now().UTC()
	userID := ids.New[ids.User](now, r.entropy)
	credentialID := ids.New[ids.Credential](now, r.entropy)
	subjectID := ids.New[ids.Subject](now, r.entropy).String()

	verifier, err := r.hasher.Hash(ctx, password, userID, credentialID)
	if err != nil {
		// Propagated unchanged, and NOT retried here. The hasher is bounded at
		// the core count because throughput declines past it, so over capacity it
		// returns RATE_LIMITED after queueing — a retry in this handler would add
		// load to the exact condition the bound exists to relieve, and would hold
		// a request open for a multiple of the queue timeout.
		return RegisterResult{}, err
	}

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
	// The password is enrolled in the SAME append as the account. Two appends
	// would allow an account with no credential to exist, and the only way out of
	// that state is a reset flow that an unverified account cannot use.
	if err := user.SetPassword(credentialID, now); err != nil {
		return RegisterResult{}, err
	}

	// The address goes to the vault and NOWHERE else. Every event below carries
	// the pseudonym and the keyed index; neither can be read back into an address
	// without a key that no projector, log or event holds (ADR-002).
	if err := r.vault.PutAll(ctx, pii.SubjectID(subjectID), map[pii.Field]string{
		pii.FieldEmail: email,
	}); err != nil {
		return RegisterResult{}, fmt.Errorf("storing the address for a registration: %w", err)
	}
	// The SAME credential id that PasswordSet carries. The hasher authenticated it
	// into the verifier, so a row stored under any other id can never be opened —
	// and the failure would surface at the user's first login rather than here.
	//
	// EnabledAt is set, not left zero: the usable-credential lookup filters on
	// `enabled_at IS NOT NULL`, so a zero value produces an account that is
	// passwordless with a password row sitting in the table.
	if err := r.credentials.Store(ctx, NewPasswordCredential{
		ID:            credentialID,
		SubjectID:     subjectID,
		Verifier:      verifier,
		PepperVersion: r.hasher.PepperVersion(),
		EnabledAt:     now,
	}); err != nil {
		return RegisterResult{}, fmt.Errorf("storing the password verifier for a registration: %w", err)
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
		Created:      true,
		UserID:       userID,
		SubjectID:    subjectID,
		CredentialID: credentialID,
		EmailIndex:   index,
		Position:     res,
	}, nil
}

// VerifyEmailCommand presents an emailed verification token.
type VerifyEmailCommand struct {
	// Token is the plaintext from the link. It is hashed here and never stored,
	// logged or placed in an event: a token in a log line is a live credential in
	// a system whose logs outlive it by months.
	Token string

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

// VerifyEmail proves control of the address and makes the claim permanent.
//
// # The token is spent FIRST
//
// Consume is atomic and single-use, and it runs before anything is decided. If
// the append then fails, the user must request a new link — an inconvenience.
// The other order is not an inconvenience: appending first and consuming after
// leaves a live token in a mailbox for every verification that crashed at the
// wrong moment, and a single-use secret that is sometimes multi-use is exactly
// what an attacker who has intercepted one mail needs.
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
	// VerifyEmail also records the activation when the account has by then
	// enrolled a second factor, which is why this is one call and not two.
	if err := user.VerifyEmail(index, now); err != nil {
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
				Meta:  meta,
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
