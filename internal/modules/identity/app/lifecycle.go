package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// DefaultDeletionGracePeriod is how long an account has to change its mind.
//
// Thirty days, matching the statutory clock the compliance domain works to
// (FEATURES.md, "Orchestrated by Temporal with a 30-day statutory clock"). It is
// stated here as a default and injected as a value, because the number is a
// policy the deployment owns and a constant compiled into a use case is a policy
// nobody can change without a release.
const DefaultDeletionGracePeriod = 30 * 24 * time.Hour

// RevokeReasonDeactivated is the reason a deactivation voids sessions.
//
// Its own label rather than a shared "revoked": the reason travels into
// SessionRevoked and is what a person reading their own security history sees.
// "You signed out everywhere", "your password was reset" and "you switched your
// account off" are three different sentences, and collapsing them loses the only
// evidence of which one happened.
const RevokeReasonDeactivated = "account_deactivated"

// SessionRevocationPlanner plans a revocation, invalidates the authorization
// cache, and destroys the secrets of sessions that were revoked.
//
// Declared by the consumer and narrowed to three methods (ADR-001, CONVENTIONS
// §2). It is satisfied by *Authentication, which owns every rule about what
// revoking a subject's sessions means — this package must not acquire a second
// answer to that question.
type SessionRevocationPlanner interface {
	PlanRevokeAllSessions(
		ctx context.Context, cmd RevokeAllSessionsCommand,
	) (SessionRevocationPlan, error)
	InvalidateAuthorization(ctx context.Context, subjectID string) error

	// DestroySessionSecrets makes the revocation immediate. Without it a
	// deactivated account's sessions keep authenticating until the projector
	// clears `revoked_at` — see the implementation for what that costs.
	DestroySessionSecrets(ctx context.Context, sessions []ids.SessionID) (int64, error)
}

// Lifecycle is the account's own on/off switch and its request to be erased.
//
// # What is here, and what deliberately is not
//
// Deactivate and RequestDeletion. There is no Reactivate and no Suspend, and
// both absences are decisions rather than gaps:
//
//   - REACTIVATION is not a command. A deactivated account cannot authenticate,
//     so it cannot hold a session, so it could never reach a command that needs
//     one — a `Reactivate` use case here would be reachable only by accounts that
//     do not need it. The reversal identity.md §1 promises the holder happens
//     inside the authentication instead, atomically with it
//     (Authentication.succeed, domain.User.NeedsReactivation).
//
//   - SUSPENSION is not the holder's to perform. identity.md §1 makes it
//     administrative and explicitly not reversible by the holder, and every
//     command in this module is reached by the account holder acting on their own
//     account — api.callerSubject refuses every other kind of principal. A
//     `Suspend` here would therefore be a SELF-suspension: one call, and the
//     account is unreachable by every route this module has (Reactivate refuses
//     Suspended, RequestPasswordReset refuses it, ResendEmailVerification refuses
//     it), with no operator surface anywhere in the repository to undo it.
//     domain.User.Suspend stays built, tested and unreachable until the operator
//     module exists to call it.
type Lifecycle struct {
	clock       clock.Clock
	subjects    UserDirectory
	users       AggregateLoader[*domain.User]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	revocations SessionRevocationPlanner
	grace       time.Duration
	log         *slog.Logger
}

// LifecycleDeps is everything the two use cases need.
type LifecycleDeps struct {
	Clock clock.Clock

	// Subjects turns the caller's pseudonym into the account id the stream is
	// named by. The pseudonym is what the session carries (ADR-002); the stream
	// is named by the user id.
	Subjects UserDirectory

	// Users loads the aggregate. Every decision below is taken from the LOG and
	// never from user_view: a projection is behind by construction, so a decision
	// taken from it can be taken twice with two different answers.
	Users AggregateLoader[*domain.User]

	// Appender writes. MultiAppender rather than a repository because a
	// deactivation is one atomic append across the account stream and every one
	// of its session streams.
	Appender eventsourcing.MultiAppender

	// Schemas stamps each appended event with its current schema version. Without
	// it the event is stored at version 0 while the registry declares 1, and the
	// aggregate cannot be loaded back — invisibly, because projections do not
	// upcast.
	Schemas eventsourcing.SchemaVersions

	// Revocations plans the session revocation a deactivation folds into its own
	// append. REQUIRED, and the requirement is not bookkeeping: nothing in the
	// request pipeline reads an account's state — the authenticator's query joins
	// user_view only to read the enrolment column — so an account switched off
	// with a live session is an account that is off in the log and fully usable
	// over HTTP.
	Revocations SessionRevocationPlanner

	// GracePeriod is how long a deletion request waits before it falls due.
	// Defaults to DefaultDeletionGracePeriod when zero; a NEGATIVE value is
	// refused rather than clamped, because it would put every deadline in the
	// past and the aggregate would reject every request with a validation error
	// nobody could explain.
	GracePeriod time.Duration

	// Log is optional and defaults to slog.Default(). Nothing here logs an
	// address or a token: the only identifiers that reach it are pseudonyms.
	Log *slog.Logger
}

// NewLifecycle validates the wiring and returns the handlers.
//
// Every dependency is required and none has a safe default. This repository has
// shipped adapters that were built, tested, and constructed by no binary; a nil
// here would serve the first deactivation with a panic, after the composition
// root had reported a healthy start.
func NewLifecycle(deps LifecycleDeps) (*Lifecycle, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: an account lifecycle needs %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Subjects == nil:
		return nil, missing("a user directory")
	case deps.Users == nil:
		return nil, missing("a user loader")
	case deps.Appender == nil:
		return nil, missing("an appender")
	case deps.Schemas == nil:
		return nil, missing("a schema registry; without one every event it writes is " +
			"stored at version 0 and the account can never be loaded back")
	case deps.Revocations == nil:
		return nil, missing("a session revocation planner; a deactivation that cannot void " +
			"the account's sessions switches the account off in the log and leaves it " +
			"fully usable over HTTP, because nothing in the request pipeline reads an " +
			"account's state")
	case deps.GracePeriod < 0:
		return nil, fmt.Errorf("identity/app: a deletion grace period of %s is in the past",
			deps.GracePeriod)
	}
	grace := deps.GracePeriod
	if grace == 0 {
		grace = DefaultDeletionGracePeriod
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &Lifecycle{
		clock: deps.Clock, subjects: deps.Subjects, users: deps.Users,
		appender: deps.Appender, schemas: deps.Schemas, revocations: deps.Revocations,
		grace: grace, log: log,
	}, nil
}

// ---------------------------------------------------------------------------
// Deactivate
// ---------------------------------------------------------------------------

// DeactivateAccountCommand switches the caller's own account off.
type DeactivateAccountCommand struct {
	// SubjectID is the CALLER'S pseudonym, read from the session by the transport
	// and never from the request. There is no field naming another account and
	// there must not be one: identity has no delegation convention, so a subject
	// taken from the wire would let any authenticated caller switch off any
	// account whose pseudonym they could obtain.
	SubjectID string

	// IdempotencyKey makes a retried request derive the same event ids, which the
	// store collapses instead of appending a second deactivation.
	IdempotencyKey string
}

// DeactivateAccountResult reports what happened INSIDE the process.
type DeactivateAccountResult struct {
	// Changed is false when the account was already deactivated. The sessions are
	// still swept in that case — see Deactivate.
	Changed bool

	// SessionsRevoked is how many live sessions this call ended, and
	// SessionsScanned how many the work list returned. Both are recorded so a
	// test can assert the rule RAN rather than assert that a function was called.
	SessionsRevoked int
	SessionsScanned int

	Position eventsourcing.Position
}

// Deactivate switches the account off and ends every session it has, in ONE
// atomic append.
//
// # Why one append and not two
//
// RevokeAllSessions' own contract says it: "sign out everywhere that half
// happened is worse than one that failed". A deactivation is that statement with
// a second half. The two orderings both fail, and neither fails safe:
//
//   - Revoke, then deactivate. A failure leaves every session dead and the
//     account on. Recoverable, but it is a full sign-out the person did not ask
//     for and nothing in the log explains.
//   - Deactivate, then revoke. A failure leaves the account off in the log and a
//     live session in the hands of whoever held it. Nothing in the request
//     pipeline reads an account's state — GetSessionByToken joins user_view only
//     to read the enrolment column — so that session keeps full API access, and
//     the person who switched their account off has been told it is off.
//
// The password reset can choose an order because its two writes have a safe
// direction: revoking first fails towards LESS access. A deactivation has no
// granting half, so there is no safe direction and the write has to be
// indivisible instead. AppendToMany evaluates every precondition and commits all
// of them or none.
//
// # Every session, sparing none — including the caller's own
//
// `Except` is zero and must stay zero. Sparing the session that asked would
// leave the account switched off everywhere except on the device that switched
// it off, which is not what the person asked for and is not what they were told.
// This follows VerifyEmail and ResetPassword, which both revoke with a zero
// Except; the difference is that neither of those is a no-op here, because an
// account that can reach this command necessarily has the session it reached it
// with.
//
// # Concurrency
//
// The account stream carries the exact revision the aggregate was loaded at, so
// two simultaneous deactivations produce exactly one UserDeactivated: the loser's
// entire append — its session revocations included — is rolled back, and it is
// told to retry. The retry is the idempotent path below.
//
// # Already deactivated: not a no-op
//
// A second call records nothing on the account and still sweeps the sessions. It
// is not defensive tidying: a login whose ceremony began before the deactivation
// committed can mint a session the first sweep's work list never saw, and this is
// the only command that will ever look for it. `Changed` is false so the caller
// can tell the two apart.
//
// # Tokens are NOT swept, and that is the difference from a reset
//
// A password reset voids every outstanding token of every purpose, because it
// exists for an account whose control may have been lost. A deactivation is
// reversible by its own holder and asserts nothing about compromise. Voiding the
// verification token of an account that deactivated mid-signup would destroy the
// only route back into it, to defend against nothing.
func (l *Lifecycle) Deactivate(
	ctx context.Context, cmd DeactivateAccountCommand,
) (DeactivateAccountResult, error) {
	user, userID, err := l.load(ctx, cmd.SubjectID, cmd.IdempotencyKey, "a deactivation")
	if err != nil {
		return DeactivateAccountResult{}, err
	}

	now := l.clock.Now().UTC()
	// The actor is the holder. It is taken from the same pseudonym the account was
	// resolved by, never from anything the request carried: an ActorID a caller
	// could choose would let a request claim to be somebody else's action in a
	// permanent log, and it is what decides who the security mail names
	// (NOTIFICATIONS §4).
	if err := user.Deactivate(cmd.SubjectID, now); err != nil {
		return DeactivateAccountResult{}, err
	}

	// Planned under a namespaced key so the session events cannot collide with the
	// account event's derived ids, both of which come from the caller's one key.
	plan, err := l.revocations.PlanRevokeAllSessions(ctx, RevokeAllSessionsCommand{
		SubjectID: cmd.SubjectID,
		Reason:    RevokeReasonDeactivated,
		// Except stays zero. See the doc comment.
		IdempotencyKey: cmd.IdempotencyKey + ":" + RevokeReasonDeactivated,
	})
	if err != nil {
		return DeactivateAccountResult{}, fmt.Errorf(
			"planning the session revocations for a deactivation: %w", err)
	}

	result := DeactivateAccountResult{SessionsScanned: plan.Scanned}
	appends := plan.Appends

	pending := user.Uncommitted()
	if len(pending) > 0 {
		stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
		if err != nil {
			return DeactivateAccountResult{}, err
		}
		// The account stream FIRST, matching the order registration writes its two
		// streams in: the entry that decides whether the append may happen at all
		// leads, so a reader of the log sees the decision before its consequences.
		appends = append([]eventsourcing.StreamAppend{{
			Stream: stream,
			// The exact loaded revision. A concurrent deactivation, login or
			// credential change is refused rather than layered on top of a state this
			// decision never saw.
			Expected: eventsourcing.ExpectedFor(user),
			Events:   l.pending(ctx, cmd.IdempotencyKey, cmd.SubjectID, pending),
		}}, appends...)
		result.Changed = true
	}
	if len(appends) == 0 {
		// Already deactivated and holding no live session. Nothing to write.
		return result, nil
	}

	// Before the append, as RevokeAllSessions does it: a decision cached for this
	// principal must not survive the sessions it was cached for.
	if err := l.revocations.InvalidateAuthorization(ctx, cmd.SubjectID); err != nil {
		return DeactivateAccountResult{}, err
	}

	results, err := l.appender.AppendToMany(ctx, appends)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Somebody else wrote to this account between the load and the append.
			// NOTHING was written — not the deactivation, not one revocation — so the
			// caller retries and the retry re-decides against the current stream.
			return DeactivateAccountResult{}, errs.Conflictf(
				"this account is being changed by another request; try again").Wrap(err)
		}
		return DeactivateAccountResult{}, err
	}
	if len(results) == 0 {
		return DeactivateAccountResult{}, errs.Internalf("the append reported no result")
	}

	// Cleared only now. Clearing before the append is durable would lose the events
	// if the caller retried after a transient failure.
	user.ClearUncommitted()
	plan.Commit()

	// The secrets, destroyed now that the append is durable. A deactivation whose
	// sessions outlive it by the projector's lag is the one outcome this command
	// must not have: the holder pressed the switch, was told it worked, and their
	// bearer still opens their account.
	if _, err := l.revocations.DestroySessionSecrets(ctx, plan.Revoked()); err != nil {
		return DeactivateAccountResult{}, err
	}

	result.SessionsRevoked = len(plan.Appends)
	result.Position = results[0].Position
	return result, nil
}

// ---------------------------------------------------------------------------
// RequestDeletion
// ---------------------------------------------------------------------------

// RequestAccountDeletionCommand asks for the caller's own account to be erased.
type RequestAccountDeletionCommand struct {
	// SubjectID is the CALLER'S pseudonym, from the session. As in
	// DeactivateAccountCommand, there is no field naming another account.
	SubjectID string

	IdempotencyKey string
}

// RequestAccountDeletionResult reports what happened INSIDE the process.
type RequestAccountDeletionResult struct {
	// Changed is false when a request was already outstanding. The deadline
	// returned is then the FIRST one, which is the date already mailed.
	Changed bool

	// ScheduledFor is when erasure falls due.
	ScheduledFor time.Time

	Position eventsourcing.Position
}

// RequestDeletion records that the holder wants the account erased.
//
// # It appends one event and stops, on purpose
//
// Erasure is `compliance`'s work — destroy the key, and the personal data
// becomes unreadable everywhere at once (ADR-002) — and the handoff is now
// wired: `compliance-erasure` consumes this event and starts a Temporal
// workflow that waits out the grace period, re-reading as it goes so a
// cancellation stops it. At the deadline it confirms to the person, destroys the
// subject key, and appends UserErased.
//
// TWO CAVEATS, because neither is visible from here. The workflow needs Temporal:
// with TEMPORAL_ENABLED=false the reactor refuses to be built and says so at
// startup, because a thirty-day grace period has no inline fallback the way mail
// does. And there is still no command to CANCEL a request — the aggregate has
// `CancelDeletion` and nothing calls it, so the cancel link NOTIFICATIONS §4
// specifies has no endpoint behind it yet.
//
// # No sessions are revoked, and that is deliberate
//
// A request is not a deletion. The grace period exists precisely so the person
// can change their mind, and signing them out of an account that still works
// teaches them the request took effect immediately, which it did not. This is
// the one place in this module where the revocation rule of identity.md §4.4 is
// NOT followed, and the reason is that nothing here changes what any credential
// can do.
//
// # Idempotent, and the first deadline wins
//
// A second request records nothing and returns the original deadline. Otherwise
// anyone holding the session could push the deadline out indefinitely, and every
// mail naming a date would be contradicted by the next one.
func (l *Lifecycle) RequestDeletion(
	ctx context.Context, cmd RequestAccountDeletionCommand,
) (RequestAccountDeletionResult, error) {
	user, userID, err := l.load(ctx, cmd.SubjectID, cmd.IdempotencyKey, "a deletion request")
	if err != nil {
		return RequestAccountDeletionResult{}, err
	}

	now := l.clock.Now().UTC()
	scheduled := now.Add(l.grace)
	if err := user.RequestDeletion(cmd.SubjectID, scheduled, now); err != nil {
		return RequestAccountDeletionResult{}, err
	}

	pending := user.Uncommitted()
	if len(pending) == 0 {
		// Already requested. The deadline comes from the AGGREGATE, so the answer is
		// the date the log holds and the person was mailed, not the one this call
		// would have computed.
		at, _ := user.DeletionRequested()
		return RequestAccountDeletionResult{ScheduledFor: at}, nil
	}

	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return RequestAccountDeletionResult{}, err
	}
	results, err := l.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream,
		// The exact loaded revision, so two simultaneous requests put exactly one
		// deadline in the log rather than two the mail would have to choose between.
		Expected: eventsourcing.ExpectedFor(user),
		Events:   l.pending(ctx, cmd.IdempotencyKey, cmd.SubjectID, pending),
	}})
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return RequestAccountDeletionResult{}, errs.Conflictf(
				"this account is being changed by another request; try again").Wrap(err)
		}
		return RequestAccountDeletionResult{}, err
	}
	if len(results) == 0 {
		return RequestAccountDeletionResult{}, errs.Internalf("the append reported no result")
	}
	user.ClearUncommitted()

	l.log.InfoContext(ctx, "an account deletion was requested",
		"module", "identity", "subject_id", cmd.SubjectID,
		"scheduled_for", scheduled.Format(time.RFC3339))

	return RequestAccountDeletionResult{
		Changed:      true,
		ScheduledFor: scheduled,
		Position:     results[0].Position,
	}, nil
}

// ---------------------------------------------------------------------------
// Shared machinery
// ---------------------------------------------------------------------------

// load resolves the caller's pseudonym and rehydrates the account.
//
// One helper for both commands so neither can acquire a different answer to "who
// is this and where is their stream". An unknown subject is NotFound with no
// detail, the same answer api.callerUser gives: a caller able to tell "no such
// account" from "not your account" can test pseudonyms for existence.
func (l *Lifecycle) load(
	ctx context.Context, subjectID, idempotencyKey, what string,
) (*domain.User, ids.UserID, error) {
	switch {
	case idempotencyKey == "":
		return nil, ids.UserID{}, errs.ValidationFailedf("an idempotency key is required")
	case subjectID == "":
		return nil, ids.UserID{}, errs.ValidationFailedf("a subject id is required")
	}

	userID, err := l.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			return nil, ids.UserID{}, errs.NotFoundf("no such account")
		}
		return nil, ids.UserID{}, fmt.Errorf("resolving the account for %s: %w", what, err)
	}
	user, err := l.users.Load(ctx, userID.String())
	if err != nil {
		return nil, ids.UserID{}, fmt.Errorf("loading the account for %s: %w", what, err)
	}
	if user.State() == domain.StateNone {
		// The directory named an account whose stream holds nothing. Answered as a
		// missing account rather than as an internal error, because from the
		// caller's side it is one.
		return nil, ids.UserID{}, errs.NotFoundf("no such account")
	}
	return user, userID, nil
}

// pending turns an aggregate's uncommitted events into stamped, id-derived
// pending events.
//
// One helper for both commands so the metadata, the schema stamp and the id
// derivation cannot differ between them. Two copies of this loop is two places
// for StampSchemaVersion to be forgotten — which stores the event at version 0
// while the registry declares 1 and makes the aggregate unloadable, invisibly,
// because projections do not upcast.
func (l *Lifecycle) pending(
	ctx context.Context, idempotencyKey, subjectID string, events []eventsourcing.Event,
) []eventsourcing.PendingEvent {
	meta := eventsourcing.Metadata{
		OccurredAt: l.clock.Now().UTC(),
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
			Meta: eventsourcing.StampSchemaVersion(meta, l.schemas, e.EventType()),
		})
	}
	return out
}

// The planner port must be satisfied by the type that owns the rules. A
// consumer-declared interface no producer implements is a mock the tests pass
// against and the composition root cannot wire.
var _ SessionRevocationPlanner = (*Authentication)(nil)

// CancelAccountDeletionCommand withdraws an outstanding erasure request.
type CancelAccountDeletionCommand struct {
	SubjectID      string
	IdempotencyKey string
}

// CancelAccountDeletionResult reports what happened inside the process.
type CancelAccountDeletionResult struct {
	// Changed is false when nothing was outstanding. A SUCCESS, not a refusal —
	// see CancelDeletion.
	Changed bool

	Position eventsourcing.Position
}

// CancelDeletion withdraws the caller's outstanding erasure request.
//
// # This is what makes the grace period a safeguard rather than a delay
//
// The window exists so somebody who clicked in anger, or whose session was
// taken, can stop what was started. The erasure workflow re-reads the request on
// every wake precisely so that this call stops it: cancel, and the run ends
// without erasing.
//
// # Cancelling nothing succeeds
//
// The cancel link in the "deletion scheduled" mail is clicked twice, or after an
// operator already withdrew the request on the holder's behalf. Neither person
// did anything wrong, and an error would tell both of them they had.
//
// An ERASED account is refused by the aggregate, and that is the direction that
// matters: once the key is destroyed there is nothing to come back to, and a
// cancel that appeared to succeed would tell somebody their account was saved
// when it is unreadable.
func (l *Lifecycle) CancelDeletion(
	ctx context.Context, cmd CancelAccountDeletionCommand,
) (CancelAccountDeletionResult, error) {
	user, userID, err := l.load(ctx, cmd.SubjectID, cmd.IdempotencyKey, "a deletion cancellation")
	if err != nil {
		return CancelAccountDeletionResult{}, err
	}

	now := l.clock.Now().UTC()
	if err := user.CancelDeletion(cmd.SubjectID, now); err != nil {
		return CancelAccountDeletionResult{}, err
	}

	pending := user.Uncommitted()
	if len(pending) == 0 {
		// Nothing was outstanding. Reported as an unchanged success.
		return CancelAccountDeletionResult{}, nil
	}

	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return CancelAccountDeletionResult{}, err
	}
	results, err := l.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream,
		// The exact loaded revision. A cancellation racing the erasure workflow's
		// own append is the one race that matters here, and losing it means
		// re-reading rather than overwriting a decision taken in between.
		Expected: eventsourcing.ExpectedFor(user),
		Events:   l.pending(ctx, cmd.IdempotencyKey, cmd.SubjectID, pending),
	}})
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return CancelAccountDeletionResult{}, errs.Conflictf(
				"this account is being changed by another request; try again").Wrap(err)
		}
		return CancelAccountDeletionResult{}, err
	}
	if len(results) == 0 {
		return CancelAccountDeletionResult{}, errs.Internalf("the append reported no result")
	}
	user.ClearUncommitted()

	l.log.InfoContext(ctx, "an account deletion request was withdrawn",
		"module", "identity", "subject_id", cmd.SubjectID)

	return CancelAccountDeletionResult{Changed: true, Position: results[0].Position}, nil
}
