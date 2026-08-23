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
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// Revocation reasons recorded on the sessions an email change voids.
const (
	// RevokeReasonEmailChanged is identity.md §4.4 at the moment the identifier
	// moves. The "unexpired session" variant is an attacker keeping a live
	// session across the change; re-verification is what defeats it, and this is
	// the re-verification.
	RevokeReasonEmailChanged = "email_changed"

	// RevokeReasonEmailChangeReverted is the same rule on the way back. Whoever
	// performed the change may still hold a session, and the revert exists
	// because that party may be an attacker.
	RevokeReasonEmailChangeReverted = "email_change_reverted"
)

// Default windows. Both are overridable at construction; these are the numbers
// the deployment runs unless it says otherwise.
const (
	// DefaultEmailChangeTTL bounds how long an unproven change may hold a claim
	// on the address it named. It is the same order as a verification link,
	// because it is the same act — proving control of an address by reading mail
	// sent to it.
	DefaultEmailChangeTTL = 24 * time.Hour

	// DefaultEmailRevertWindow is how long the OLD address may undo a completed
	// change (identity.md §12).
	//
	// Longer than the change itself, deliberately: the person who needs it is
	// the one who did NOT ask for the change and is reading an unexpected mail,
	// possibly after a weekend. It also bounds how long the old address stays
	// unavailable to everybody else, which is the cost of making it longer.
	DefaultEmailRevertWindow = 72 * time.Hour
)

// RequestEmailChangeCommand starts a move to a new address.
type RequestEmailChangeCommand struct {
	// SubjectID is the CALLER'S pseudonym, from their session. There is
	// deliberately no field naming another account: an email change is
	// self-service, and a command that could name a subject would be a command an
	// administrator could use to take an account over.
	SubjectID string

	// NewEmail is the address being claimed, as the caller typed it. The only
	// address in this package's surface, and it goes straight to the indexer and
	// the vault — no handler holds it beyond this call (ADR-002).
	NewEmail string

	IdempotencyKey string
}

// ConfirmEmailChangeCommand completes a change with the token mailed to the new
// address.
type ConfirmEmailChangeCommand struct {
	Token          string
	IdempotencyKey string
}

// RevertEmailChangeCommand undoes a completed change with the token mailed to
// the old address.
type RevertEmailChangeCommand struct {
	Token          string
	IdempotencyKey string
}

// CancelEmailChangeCommand calls off a pending change from a session.
type CancelEmailChangeCommand struct {
	SubjectID      string
	IdempotencyKey string
}

// EmailChange is the identifier-change flow of identity.md §12.
//
// # Three properties the flow exists to hold
//
//   - The NEW address is proven before anything switches. An attacker holding a
//     session can name an address; naming one changes nothing until somebody
//     reads mail sent to it.
//   - The OLD address is told, and can undo it. That is the remedy for the case
//     where the attacker DID prove an address — they cannot stop the real owner
//     being notified at the address the account had.
//   - Completing voids every session (§4.4). Re-verification is the trigger, so
//     an attacker's session does not survive the change they performed, and the
//     victim's revert is not racing a live attacker session either.
//
// # No address ever reaches this type twice
//
// RequestEmailChangeCommand carries one, because somebody has to type it. It is
// turned into a blind index and handed to the vault, and from that point the
// flow works in indexes and pseudonyms — the confirm and revert handlers never
// see an address at all, and the moves between the vault's slots happen inside
// the vault adapter (SubjectAddresses).
type EmailChange struct {
	clock       clock.Clock
	index       EmailIndexer
	subjects    UserDirectory
	users       AggregateLoader[*domain.User]
	claims      AggregateLoader[*domain.EmailReservation]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	addresses   SubjectAddresses
	tokens      TokenStore
	digest      TokenDigest
	revocations SessionRevoker
	ttl         time.Duration
	revert      time.Duration
	log         *slog.Logger
}

// EmailChangeDeps is what the flow needs.
type EmailChangeDeps struct {
	Clock clock.Clock

	// Index derives the blind index from the address the caller typed. The same
	// indexer registration and authentication use, so "which account claims this
	// address" has one answer everywhere.
	Index EmailIndexer

	// There is deliberately NO account directory here, and its absence is a
	// decision rather than an omission.
	//
	// Asking "is this address already taken" from the projection before claiming
	// it would be a second answer to a question the reservation STREAM already
	// answers authoritatively — and a lagging one, so under concurrency both
	// callers read "free" and the append is what actually separates them. It
	// would also be an enumeration oracle: an authenticated caller could learn
	// which addresses have accounts by watching which pre-checks refused.
	//
	// The claim below contends on the address's own stream, and the loser loses
	// the whole change. That is the only check that holds.

	// Subjects resolves the pseudonym a redeemed token names back to an account
	// id, for the confirm and revert halves.
	Subjects UserDirectory

	Users  AggregateLoader[*domain.User]
	Claims AggregateLoader[*domain.EmailReservation]

	// Appender writes the account and BOTH address claims in one atomic append.
	// Three sequential single-stream writes would leave an account pointing at an
	// address whose claim was never confirmed, or an address confirmed for an
	// account that never moved.
	Appender eventsourcing.MultiAppender
	Schemas  eventsourcing.SchemaVersions

	// Addresses moves the values between the vault's slots. See the port: every
	// method is a MOVE and none is a read, so no address crosses back into this
	// module.
	Addresses SubjectAddresses

	Tokens TokenStore
	Digest TokenDigest

	// Revocations voids every session on completion and on revert (§4.4).
	Revocations SessionRevoker

	// TTL bounds an unproven change; Revert is the window the old address has to
	// undo a completed one. Zero takes the defaults above.
	TTL    time.Duration
	Revert time.Duration

	Log *slog.Logger
}

// NewEmailChange builds the flow.
func NewEmailChange(d EmailChangeDeps) (*EmailChange, error) {
	switch {
	case d.Clock == nil:
		return nil, errors.New("identity: an email change needs a clock")
	case d.Index == nil:
		return nil, errors.New("identity: an email change needs an email indexer; without " +
			"one the address would have to be stored or compared in the clear")
	case d.Subjects == nil:
		return nil, errors.New("identity: an email change needs a user directory")
	case d.Users == nil, d.Claims == nil:
		return nil, errors.New("identity: an email change needs the user and reservation " +
			"aggregates; every decision it takes is taken from a stream")
	case d.Appender == nil:
		return nil, errors.New("identity: an email change needs a multi-stream appender; " +
			"the account and both address claims must move in ONE append or an account " +
			"ends up pointing at an address whose claim was never confirmed")
	case d.Schemas == nil:
		return nil, errors.New("identity: an email change needs schema versions")
	case d.Addresses == nil:
		return nil, errors.New("identity: an email change needs the vault's address book; " +
			"without it the new address is never stored, the verification link has " +
			"nowhere to go, and the revert has nothing to restore")
	case d.Tokens == nil, d.Digest == nil:
		return nil, errors.New("identity: an email change needs the token store; the " +
			"change is proven by a token mailed to the new address and by nothing else")
	case d.Revocations == nil:
		return nil, errors.New("identity: an email change needs a session revoker; " +
			"identity.md §4.4 voids every session when an identifier is re-verified, and " +
			"an attacker's session surviving the change they performed is the whole of " +
			"the unexpired-session variant")
	}

	ec := &EmailChange{
		clock: d.Clock, index: d.Index, subjects: d.Subjects,
		users: d.Users, claims: d.Claims, appender: d.Appender, schemas: d.Schemas,
		addresses: d.Addresses, tokens: d.Tokens, digest: d.Digest,
		revocations: d.Revocations,
		ttl:         d.TTL, revert: d.Revert, log: d.Log,
	}
	if ec.ttl <= 0 {
		ec.ttl = DefaultEmailChangeTTL
	}
	if ec.revert <= 0 {
		ec.revert = DefaultEmailRevertWindow
	}
	if ec.log == nil {
		ec.log = slog.Default()
	}
	return ec, nil
}

// Request claims a new address and records the intent. Nothing switches.
//
// # The order, and why each step is where it is
//
//  1. Index the address. A refusal here is a property of the caller's own bytes
//     and costs nothing.
//  2. Load the account and take the decision on the AGGREGATE. A pending change,
//     a suspended account and an unverified current address are all refused
//     against the stream, not against a projection.
//  3. Claim the new address on ITS OWN STREAM. That is what makes the claim
//     unique under concurrency: two accounts requesting one address contend on
//     the same stream and one of them loses the append.
//  4. Stage the address in the vault BEFORE the append. The reactor mails the
//     link off the back of the event, and an event whose address is not yet
//     staged is an event the reactor cannot serve — it would retry, which is
//     survivable, but the ordering makes the retry unnecessary.
//  5. Append account and claim(s) together.
func (e *EmailChange) Request(ctx context.Context, cmd RequestEmailChangeCommand) error {
	switch {
	case cmd.SubjectID == "":
		return errs.Internalf("no authenticated subject reached the email-change handler")
	case cmd.IdempotencyKey == "":
		return errs.ValidationFailedf("an idempotency key is required")
	case cmd.NewEmail == "":
		return errs.ValidationFailedf("a new email address is required")
	}

	index, err := e.index.Of(cmd.NewEmail)
	if err != nil {
		return err
	}

	now := e.clock.Now().UTC()
	userID, user, err := e.load(ctx, cmd.SubjectID)
	if err != nil {
		return err
	}
	if user.EmailIndex() == index {
		// Said plainly, and it discloses nothing: the caller is authenticated and
		// is being told about their own address.
		return errs.ValidationFailedf("that is already this account's address")
	}

	// The address the account is LEAVING behind, if this supersedes an earlier
	// request. Captured before the aggregate transition clears it, because the
	// superseded claim has to be released and nothing else remembers which one
	// it was.
	superseded, hadPending := user.PendingEmailIndex()

	if err := user.RequestEmailChange(index, now.Add(e.ttl), now); err != nil {
		return err
	}
	if len(user.Uncommitted()) == 0 {
		// The same request again. Nothing to append, nothing to mail — the link
		// from the first request is still live, and issuing a second would revoke
		// it, which turns a double-click into a broken link.
		return nil
	}

	parts := []streamPart{{UserCategory, userID.String(), user}}

	claim, err := e.claims.Load(ctx, string(index))
	if err != nil {
		return fmt.Errorf("loading the claim on the new address: %w", err)
	}
	if err := claim.Reserve(index, cmd.SubjectID, now.Add(e.ttl), now); err != nil {
		// Deliberately whatever the aggregate said, which for a taken address is
		// the SAME refusal whether it is verified-and-owned or merely claimed.
		// The distinction tells an authenticated caller whether a stranger's
		// address has an account, which is the enumeration oracle identity.md §7
		// closes everywhere else.
		return err
	}
	parts = append(parts, streamPart{ReservationCategory, string(index), claim})

	if hadPending && superseded != index {
		// The superseded claim, released on its own stream. Without this a person
		// who mistyped an address once holds it away from its real owner until
		// the lease runs out.
		old, loadErr := e.claims.Load(ctx, string(superseded))
		if loadErr != nil {
			return fmt.Errorf("loading the superseded claim: %w", loadErr)
		}
		if err := old.Release(cmd.SubjectID, domain.ReleaseChanged, now); err != nil {
			return err
		}
		parts = append(parts, streamPart{ReservationCategory, string(superseded), old})
	}

	// Staged BEFORE the append. See the doc comment: the reactor mails the link
	// off the back of the event and needs somewhere to send it.
	if err := e.addresses.StagePending(ctx, pii.SubjectID(cmd.SubjectID), cmd.NewEmail); err != nil {
		return fmt.Errorf("staging the new address: %w", err)
	}

	if _, err := e.append(ctx, cmd.IdempotencyKey, cmd.SubjectID, parts...); err != nil {
		return err
	}
	return nil
}

// Confirm completes a change with the token mailed to the NEW address.
//
// Public: it is reached from a mailbox, by somebody who may not hold a session —
// and after §4.4 does its work, certainly does not.
func (e *EmailChange) Confirm(ctx context.Context, cmd ConfirmEmailChangeCommand) error {
	if cmd.IdempotencyKey == "" {
		return errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.Token == "" {
		return errs.ValidationFailedf("a confirmation token is required")
	}

	now := e.clock.Now().UTC()
	subjectID, err := e.tokens.Consume(
		ctx, PurposeEmailChange, e.digest(PurposeEmailChange, cmd.Token), now)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			// Unknown, spent and expired are ONE outcome. "That link has expired"
			// tells whoever holds it that the address it was sent to is real.
			return errs.ValidationFailedf(
				"this link is no longer valid; request the change again")
		}
		return err
	}

	userID, user, err := e.load(ctx, subjectID)
	if err != nil {
		return err
	}
	pending, ok := user.PendingEmailIndex()
	if !ok {
		return errs.ValidationFailedf(
			"this link is no longer valid; request the change again")
	}
	from := user.EmailIndex()

	revertUntil := now.Add(e.revert)
	if err := user.CompleteEmailChange(pending, revertUntil, now); err != nil {
		return err
	}
	if len(user.Uncommitted()) == 0 {
		// Already completed. A second click of one link is not a failure — and the
		// token was spent either way, so there is nothing to hand back.
		return nil
	}

	parts := []streamPart{{UserCategory, userID.String(), user}}

	claim, err := e.claims.Load(ctx, string(pending))
	if err != nil {
		return fmt.Errorf("loading the claim on the new address: %w", err)
	}
	if err := claim.Confirm(subjectID, now); err != nil {
		return err
	}
	parts = append(parts, streamPart{ReservationCategory, string(pending), claim})

	if from != "" {
		// DEMOTED, not released. Releasing would let whoever performed the change
		// re-register the old address immediately and leave the revert with
		// nowhere to go — which is the attack the window exists to defeat. The
		// demotion expires at exactly the revert deadline, so the address stops
		// being reclaimable at the moment the revert stops being possible, and
		// nothing has to sweep it.
		old, loadErr := e.claims.Load(ctx, string(from))
		if loadErr != nil {
			return fmt.Errorf("loading the claim on the old address: %w", loadErr)
		}
		if err := old.Demote(subjectID, domain.DemoteRevertWindow, revertUntil, now); err != nil {
			return err
		}
		parts = append(parts, streamPart{ReservationCategory, string(from), old})
	}

	// The vault moves BEFORE the append, and the ordering is the same argument
	// Registration.VerifyEmail makes about revoking before appending: both orders
	// can fail, and they fail in opposite directions. Moved first, a failed append
	// leaves the vault holding the new address for an account whose log says it
	// never moved — recoverable, because the aggregate is the authority and it
	// says the change is still pending, so the next attempt re-runs the move
	// idempotently. Appended first, a failed move leaves an account whose log says
	// it moved and whose mail still goes to the old address.
	if err := e.addresses.PromotePending(ctx, pii.SubjectID(subjectID)); err != nil {
		return fmt.Errorf("promoting the new address: %w", err)
	}

	// §4.4, at the instant the identifier is re-verified. Except is zero: the
	// party who requested the change may be an attacker, so sparing the session
	// that asked assumes exactly what is in question. This call is also not
	// performed from a session at all.
	if _, err := e.revocations.RevokeAllSessions(ctx, RevokeAllSessionsCommand{
		SubjectID:      subjectID,
		Reason:         RevokeReasonEmailChanged,
		IdempotencyKey: cmd.IdempotencyKey + ":" + RevokeReasonEmailChanged,
	}); err != nil {
		return fmt.Errorf("voiding the sessions established before this change: %w", err)
	}

	if _, err := e.append(ctx, cmd.IdempotencyKey, subjectID, parts...); err != nil {
		return err
	}
	return nil
}

// Revert undoes a completed change with the token mailed to the OLD address.
//
// Whoever redeems this has proven control of the address the account had BEFORE
// the change, which is the whole remedy: an attacker holding a session can move
// the address and cannot stop the real owner undoing it.
func (e *EmailChange) Revert(ctx context.Context, cmd RevertEmailChangeCommand) error {
	if cmd.IdempotencyKey == "" {
		return errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.Token == "" {
		return errs.ValidationFailedf("a token is required")
	}

	now := e.clock.Now().UTC()
	subjectID, err := e.tokens.Consume(
		ctx, PurposeEmailChangeRevert, e.digest(PurposeEmailChangeRevert, cmd.Token), now)
	if err != nil {
		if errors.Is(err, ErrTokenNotFound) {
			return errs.ValidationFailedf("this link is no longer valid")
		}
		return err
	}

	userID, user, err := e.load(ctx, subjectID)
	if err != nil {
		return err
	}
	abandoned := user.EmailIndex()
	restored, open := user.RevertibleEmailIndex(now)
	if !open {
		// Either there is nothing to undo or the window has closed. One message
		// for both: distinguishing them tells the holder of a stale link whether
		// the account still exists in the state they remember.
		return errs.ValidationFailedf("this link is no longer valid")
	}

	if err := user.RevertEmailChange(now); err != nil {
		return err
	}
	if len(user.Uncommitted()) == 0 {
		return nil
	}

	parts := []streamPart{{UserCategory, userID.String(), user}}

	back, err := e.claims.Load(ctx, string(restored))
	if err != nil {
		return fmt.Errorf("loading the claim on the restored address: %w", err)
	}
	if err := back.Restore(subjectID, now); err != nil {
		return err
	}
	parts = append(parts, streamPart{ReservationCategory, string(restored), back})

	if abandoned != "" {
		// RELEASED outright, unlike the old address on the way out. There is no
		// window to preserve here: the address being abandoned is the one the
		// change moved to, nobody is being protected from losing it, and holding
		// it would keep an address the account has repudiated away from whoever
		// else might want it.
		gone, loadErr := e.claims.Load(ctx, string(abandoned))
		if loadErr != nil {
			return fmt.Errorf("loading the claim on the abandoned address: %w", loadErr)
		}
		if err := gone.Release(subjectID, domain.ReleaseChanged, now); err != nil {
			return err
		}
		parts = append(parts, streamPart{ReservationCategory, string(abandoned), gone})
	}

	if err := e.addresses.RestorePrevious(ctx, pii.SubjectID(subjectID)); err != nil {
		return fmt.Errorf("restoring the previous address: %w", err)
	}

	// §4.4 again, and for a sharper reason than on the way out: the party who
	// performed the change is who this is being undone against, and they may
	// still be holding the session they did it from.
	if _, err := e.revocations.RevokeAllSessions(ctx, RevokeAllSessionsCommand{
		SubjectID:      subjectID,
		Reason:         RevokeReasonEmailChangeReverted,
		IdempotencyKey: cmd.IdempotencyKey + ":" + RevokeReasonEmailChangeReverted,
	}); err != nil {
		return fmt.Errorf("voiding the sessions held across this revert: %w", err)
	}

	if _, err := e.append(ctx, cmd.IdempotencyKey, subjectID, parts...); err != nil {
		return err
	}
	return nil
}

// Cancel calls off a pending change from the holder's own session.
func (e *EmailChange) Cancel(ctx context.Context, cmd CancelEmailChangeCommand) error {
	switch {
	case cmd.SubjectID == "":
		return errs.Internalf("no authenticated subject reached the email-change handler")
	case cmd.IdempotencyKey == "":
		return errs.ValidationFailedf("an idempotency key is required")
	}

	now := e.clock.Now().UTC()
	userID, user, err := e.load(ctx, cmd.SubjectID)
	if err != nil {
		return err
	}
	pending, ok := user.PendingEmailIndex()
	if !ok {
		// Nothing to cancel. Success: the caller asked for a state that holds.
		return nil
	}
	if err := user.CancelEmailChange(now); err != nil {
		return err
	}

	parts := []streamPart{{UserCategory, userID.String(), user}}

	claim, loadErr := e.claims.Load(ctx, string(pending))
	if loadErr != nil {
		return fmt.Errorf("loading the cancelled claim: %w", loadErr)
	}
	if err := claim.Release(cmd.SubjectID, domain.ReleaseChanged, now); err != nil {
		return err
	}
	parts = append(parts, streamPart{ReservationCategory, string(pending), claim})

	// The live link dies with the claim. Without this the mail already sitting in
	// the new mailbox still completes a change the account holder called off.
	if err := e.tokens.RevokeAll(ctx, PurposeEmailChange, cmd.SubjectID); err != nil {
		return fmt.Errorf("voiding the outstanding change link: %w", err)
	}
	if err := e.addresses.DiscardPending(ctx, pii.SubjectID(cmd.SubjectID)); err != nil {
		return fmt.Errorf("discarding the staged address: %w", err)
	}

	if _, err := e.append(ctx, cmd.IdempotencyKey, cmd.SubjectID, parts...); err != nil {
		return err
	}
	return nil
}

// load resolves a pseudonym to its account aggregate.
func (e *EmailChange) load(
	ctx context.Context, subjectID string,
) (ids.UserID, *domain.User, error) {
	userID, err := e.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			// Same wording a bad token gets. Anything more specific tells a caller
			// whether a pseudonym names a real account.
			return ids.UserID{}, nil, errs.ValidationFailedf("this link is no longer valid")
		}
		return ids.UserID{}, nil, fmt.Errorf("resolving the account: %w", err)
	}
	user, err := e.users.Load(ctx, userID.String())
	if err != nil {
		return ids.UserID{}, nil, fmt.Errorf("loading the account: %w", err)
	}
	return userID, user, nil
}

// append writes every part in ONE atomic append.
//
// The same shape Registration.appendStreams uses, and for the same reason: the
// account and the claims on both addresses cannot be allowed to disagree, and
// two sequential single-stream appends are exactly how they come to.
func (e *EmailChange) append(
	ctx context.Context, idempotencyKey, subjectID string, parts ...streamPart,
) (eventsourcing.Position, error) {
	meta := eventsourcing.Metadata{
		OccurredAt: e.clock.Now().UTC(),
		SubjectIDs: []string{subjectID},
		ActorID:    subjectID,
	}
	trace := eventsourcing.TraceFrom(ctx)
	meta.CorrelationID, meta.CausationID = trace.CorrelationID, trace.CausationID
	if meta.CorrelationID == "" {
		meta.CorrelationID = eventsourcing.DeriveEventID(idempotencyKey, 0).String()
	}
	if meta.CausationID == "" {
		meta.CausationID = idempotencyKey
	}

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
		for _, ev := range pending {
			events = append(events, eventsourcing.PendingEvent{
				ID:    eventsourcing.DeriveEventID(idempotencyKey, seq),
				Event: ev,
				Meta:  eventsourcing.StampSchemaVersion(meta, e.schemas, ev.EventType()),
			})
			seq++
		}
		appends = append(appends, eventsourcing.StreamAppend{
			Stream: stream,
			// The exact loaded revision on every part. An address claimed between
			// the load and the commit loses this WHOLE change rather than
			// overwriting somebody's claim.
			Expected: eventsourcing.ExpectedFor(part.agg),
			Events:   events,
		})
	}
	if len(appends) == 0 {
		return eventsourcing.Position{}, nil
	}

	results, err := e.appender.AppendToMany(ctx, appends)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return eventsourcing.Position{}, errs.Conflictf(
				"this address was claimed by another account; try a different one").Wrap(err)
		}
		return eventsourcing.Position{}, fmt.Errorf("recording the email change: %w", err)
	}
	for _, part := range parts {
		part.agg.ClearUncommitted()
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	return results[0].Position, nil
}
