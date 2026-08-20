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
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// ResendVerification issues a replacement verification link for an address whose
// account has not proven it yet.
//
// # Why this exists
//
// A verification link expires in 24 hours and is single-use, and every issuance
// revokes every earlier one (VerificationIssuer). So a person who lost the mail,
// waited a day, or clicked a link that a later issuance had already voided has no
// route into their own account — and none is recoverable by registering again,
// because the address is claimed by the account they cannot reach. VerifyEmail's
// own refusal already tells them to "request a new one", so until this existed
// the product's error message was a promise nothing kept.
//
// # Why it appends an EVENT instead of calling the issuer directly
//
// Both work. Calling VerificationIssuer from the handler is fewer moving parts,
// and it is the wrong choice for three reasons.
//
// The first is that it would make the mail system's availability part of whether
// a resend can be requested. The reactor path is durable: the event is appended,
// the persistent subscription redelivers until the mail is accepted, and an SMTP
// outage costs a delay rather than a failure. The direct path has no retry that
// outlives the request, so the one person who most needs a link — they have
// already lost one — is the one told to try again later.
//
// The second is that it would make "a verification link was sent" two code paths.
// Registration appends this event and the reactor mints, revokes and mails; a
// resend that bypassed it would duplicate the ordering rule (revoke first, always)
// at a second site, and mint a plaintext token inside a request handler that has
// no business holding one. NOTIFICATIONS.md §5 names the trigger for a resend as
// `EmailVerificationRequested` for exactly this reason.
//
// The third is that the log would not record it. A resend is a security-relevant
// act — it is how a link that somebody else may hold gets voided — and appending
// nothing would leave the account's own stream saying a link was requested once,
// at registration, while five were issued.
//
// # What the caller learns: nothing
//
// Four outcomes are possible and all four return the same zero value with a nil
// error: no account claims the address, the account is Pending (the one case that
// appends), the account already verified, and the account is deactivated or
// suspended. ResendVerificationResult carries which one happened for tests and
// metrics; the handler drops it, and the wire message has no field to put it in.
//
// The residual leak is TIMING: the appending path performs one store round trip
// the other three do not. It is not closed by padding, and the reason is the
// ceiling below rather than optimism. A timing distinction of a few milliseconds
// over a network needs many samples of the SAME address to separate from jitter,
// and the per-address rule permits a handful per hour. An attacker who wants the
// answer for one address has to spend days on it; one who wants a list is stopped
// by the per-caller rule long before that. Stated here rather than hidden, because
// a control this argument depends on must not be silently loosened later.
type ResendVerification struct {
	clock    clock.Clock
	index    EmailIndexer
	accounts AccountDirectory
	users    AggregateLoader[*domain.User]
	appender eventsourcing.MultiAppender
	schemas  eventsourcing.SchemaVersions
	byAddr   AttemptLimiter
	byCaller AttemptLimiter
	tokenTTL time.Duration
	log      *slog.Logger
}

// ResendVerificationDeps is everything the use case needs.
type ResendVerificationDeps struct {
	Clock clock.Clock

	// Index derives the blind index. It is BOTH the lookup key and the
	// rate-limit scope, so the raw address never reaches Valkey — a cache is a
	// projection with a shorter life, and ADR-002 applies to it unchanged.
	Index EmailIndexer

	// Users loads the account aggregate the directory named. Every decision this
	// use case takes is taken from the aggregate, never from the row.
	Users AggregateLoader[*domain.User]

	// Directory resolves the blind index to the account claiming it. A projection,
	// so eventually consistent: a row that has not arrived yet costs one resend the
	// person can repeat, never a wrong decision.
	Directory AccountDirectory

	// Appender writes the account stream. The multi-stream appender is reused for
	// a single-stream append rather than a second write path being introduced.
	Appender eventsourcing.MultiAppender

	// Schemas stamps the appended event with its current schema version. Without
	// it the event is stored at version 0 while the registry declares 1, and the
	// aggregate cannot be loaded back — invisibly, because projections do not
	// upcast.
	Schemas eventsourcing.SchemaVersions

	// AddressLimiter bounds how much mail one address can be made to receive.
	// Scoped by the blind index.
	AddressLimiter AttemptLimiter

	// CallerLimiter bounds how many DISTINCT addresses one caller can touch.
	// Scoped by whatever the transport can say about who is calling.
	CallerLimiter AttemptLimiter

	// TokenTTL is how long the link the reactor mints will live. It is passed in
	// rather than imported because the adapter that owns the constant imports this
	// package, and the dependency cannot point both ways.
	TokenTTL time.Duration

	// Log is optional and defaults to slog.Default(). Nothing here logs an
	// address.
	Log *slog.Logger
}

// NewResendVerification validates the wiring and returns the use case.
//
// The two limiters are REQUIRED and neither has a permissive default. A nil one
// would be an anti-abuse control that is present in the design, absent at
// runtime, and invisible in every test that does not count mail — which is the
// exact shape of failure this repository has already shipped.
func NewResendVerification(deps ResendVerificationDeps) (*ResendVerification, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: resending a verification needs %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Index == nil:
		return nil, missing("an email indexer")
	case deps.Directory == nil:
		return nil, missing("an account directory")
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
		return nil, fmt.Errorf("identity/app: resending a verification needs a positive "+
			"token lifetime, got %s", deps.TokenTTL)
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &ResendVerification{
		clock: deps.Clock, index: deps.Index, accounts: deps.Directory,
		users: deps.Users, appender: deps.Appender, schemas: deps.Schemas,
		byAddr: deps.AddressLimiter, byCaller: deps.CallerLimiter,
		tokenTTL: deps.TokenTTL, log: log,
	}, nil
}

// ResendVerificationCommand asks for a replacement link.
type ResendVerificationCommand struct {
	// Email is the raw address as typed. Normalized here; only the blind index
	// derived from it leaves this call.
	Email string

	// CallerScope identifies whoever is calling, for the per-caller ceiling. The
	// transport supplies it — today the peer address — and it is REQUIRED: an
	// empty value would put every caller in one bucket, so the first few requests
	// anywhere would exhaust the budget for everybody. Refused rather than
	// defaulted, because the alternative is a wiring mistake that disables one of
	// the two anti-abuse axes with nothing to show for it.
	CallerScope string

	// IdempotencyKey makes a retried resend derive the same event id, which the
	// store collapses instead of appending a second request.
	IdempotencyKey string
}

// ResendOutcome is what actually happened, for tests and metrics. It never
// reaches the wire.
type ResendOutcome int

const (
	// ResendNoAccount means no account claims the address.
	ResendNoAccount ResendOutcome = iota

	// ResendRequested means the event was appended and the reactor will mail.
	ResendRequested

	// ResendAlreadyVerified means the account has already proven the address.
	ResendAlreadyVerified

	// ResendNotPending means an account claims the address but is not in a state
	// that can be verified — deactivated, or suspended.
	ResendNotPending

	// ResendRaced means a concurrent write to the account's stream won, so the
	// event this call would have appended is already there or superseded.
	ResendRaced
)

// ResendVerificationResult reports the outcome to the caller INSIDE the process.
type ResendVerificationResult struct {
	Outcome ResendOutcome

	// Position is the log position of the append, set only for ResendRequested.
	Position eventsourcing.Position
}

// Resend records a fresh verification request for the address, if there is an
// account waiting to prove it.
//
// # Order of operations
//
// 1. normalize the address and derive its blind index
// 2. spend the CALLER's budget
// 3. spend the ADDRESS's budget
// 4. look the account up, load it, decide, append
//
// Both ceilings are spent before step 4, which is what keeps them from becoming
// the oracle they exist to protect: an unknown address costs a caller exactly as
// much budget as a known one.
//
// The caller's budget is spent BEFORE the address's, and the order matters. A
// sweep across a thousand addresses that spent each victim's budget first would
// leave a thousand real people unable to ask for their own link, having sent no
// mail — the attacker would have converted their own refusal into a denial of
// service against everyone on the list. Caller-first bounds the damage to the
// attacker's own scope.
func (v *ResendVerification) Resend(
	ctx context.Context, cmd ResendVerificationCommand,
) (ResendVerificationResult, error) {
	if cmd.IdempotencyKey == "" {
		return ResendVerificationResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.CallerScope == "" {
		return ResendVerificationResult{}, errs.Internalf(
			"the per-caller ceiling has no scope to count against")
	}

	email, err := domain.NormalizeEmail(cmd.Email)
	if err != nil {
		return ResendVerificationResult{}, err
	}
	index, err := v.index.Of(email)
	if err != nil {
		return ResendVerificationResult{}, err
	}

	if err := v.spend(ctx, v.byCaller, "caller", cmd.CallerScope); err != nil {
		return ResendVerificationResult{}, err
	}
	if err := v.spend(ctx, v.byAddr, "address", string(index)); err != nil {
		return ResendVerificationResult{}, err
	}

	account, err := v.accounts.AccountByEmailIndex(ctx, index)
	if err != nil {
		if errors.Is(err, ErrNoSuchAccount) {
			// The whole point of the empty response. Nothing is appended, nothing
			// is mailed, and the caller cannot tell this branch from the next one.
			return ResendVerificationResult{Outcome: ResendNoAccount}, nil
		}
		return ResendVerificationResult{}, fmt.Errorf("resolving the account for a resend: %w", err)
	}

	user, err := v.users.Load(ctx, account.UserID.String())
	if err != nil {
		return ResendVerificationResult{}, fmt.Errorf("loading the account for a resend: %w", err)
	}

	// Decided from the AGGREGATE, never from the projection that named it. The
	// projection is behind the log by construction, so a resend decided from it
	// could be decided twice with two different answers — and one of those answers
	// mails a live verification link to an address whose account has already been
	// deactivated.
	switch {
	case user.EmailVerified():
		// Already proven. Mailing here would be unsolicited mail to a verified
		// mailbox on an unauthenticated caller's say-so, and it would void nothing,
		// since a verified account has no outstanding token worth revoking.
		return ResendVerificationResult{Outcome: ResendAlreadyVerified}, nil
	case user.State() != domain.StatePending:
		// Deactivated or suspended. A link that cannot lead anywhere is mail the
		// recipient did not ask for and cannot act on.
		return ResendVerificationResult{Outcome: ResendNotPending}, nil
	case user.EmailIndex() != index:
		// The account's current claim is some OTHER address — it reached this call
		// through a projection row that has not caught up with an address change.
		// Appending would ask the reactor to prove a claim the account no longer
		// makes, and the reactor mails the address the vault holds, which is not
		// the one that was typed here.
		return ResendVerificationResult{Outcome: ResendNotPending}, nil
	}

	now := v.clock.Now().UTC()

	// Recorded from the application layer, exactly as registration records it and
	// for the same reason: it changes no state the aggregate holds, User.Apply has
	// no case for it, and the deadline it carries is one only this layer knows.
	//
	// ExpiresAt is the deadline the link WILL have, derived from the same TTL the
	// minter uses. It is advisory in both paths — the reactor mints the real token
	// and its own expiry is what the store enforces — and it is recorded so the
	// projection can show "a link is outstanding until roughly then" without
	// holding a digest.
	eventsourcing.Record(user, &contract.EmailVerificationRequested{
		SubjectID:   user.SubjectID(),
		Index:       index,
		ExpiresAt:   now.Add(v.tokenTTL),
		RequestedAt: now,
	})

	pos, err := v.append(ctx, cmd.IdempotencyKey, user)
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Somebody else wrote to this account between the load and the append —
			// a concurrent resend, or the verification itself landing. NOTHING was
			// written, and reporting success is correct: either a request is already
			// on the stream or the address is already proven. Retrying here would
			// race again and could mail twice.
			return ResendVerificationResult{Outcome: ResendRaced}, nil
		}
		return ResendVerificationResult{}, err
	}
	return ResendVerificationResult{Outcome: ResendRequested, Position: pos}, nil
}

// spend consumes one unit of a ceiling and reports whether the call may proceed.
//
// # Fail OPEN, deliberately, and not by copying anything
//
// OpenFGA fails closed because the thing it protects is access to other people's
// data: allowing on error is a breach that no later log line undoes. This
// limiter protects a mail queue. Failing closed would mean that a Valkey blip —
// a rolling restart, a failover — stops every legitimate person from asking for
// the link that is the ONLY way into their own account, and a Pending account has
// no second route: it cannot sign in, and it cannot re-register, because the
// address is already claimed by the account it cannot reach. That converts a
// cache outage into permanent account loss for everyone who registered during it.
//
// Failing open costs, at worst, unbounded verification mail for the duration of
// the outage. That is bounded downstream by the mail provider's own limits, it is
// reversible, and it is LOUD: every degraded evaluation is logged here, which is
// the difference between a control that is known to be off and one that is
// silently doing nothing.
//
// It is also the same direction the authentication ceiling already took, and that
// consistency is worth something on its own: two limiters in one process with
// opposite failure modes is a trap for whoever next reads either one.
func (v *ResendVerification) spend(
	ctx context.Context, limiter AttemptLimiter, axis, scope string,
) error {
	decision, err := limiter.Allow(ctx, scope)
	if err != nil {
		// Degraded. Allowed, and never silently: the scope is a blind index or a
		// peer address, so this line carries no personal data.
		v.log.WarnContext(ctx, "the verification-mail ceiling could not be evaluated; "+
			"the request was allowed unmetered",
			"module", "identity", "reason", "ceiling_unavailable", "axis", axis, "error", err)
		return nil
	}
	if !decision.Allowed() {
		// The SAME refusal for a known and an unknown address, because the budget
		// was spent before either was looked up. Wording deliberately says nothing
		// about accounts.
		return errs.RateLimitedf(
			"too many verification links have been requested; try again later").
			WithMeta(map[string]string{
				"rule":        decision.Rule,
				"retry_after": decision.RetryAfter.String(),
			})
	}
	return nil
}

// append writes the single account stream.
//
// eventsourcing.MultiAppender with one entry rather than a Repository.Save, so a
// resend and a registration reach the log through the same call, with the same
// precondition semantics and the same event-id derivation. A second write path
// for one event type is a second place for the schema stamp to be forgotten.
func (v *ResendVerification) append(
	ctx context.Context, idempotencyKey string, user *domain.User,
) (eventsourcing.Position, error) {
	pending := user.Uncommitted()
	if len(pending) == 0 {
		// Unreachable today — Record ran immediately above — and refused rather
		// than assumed: an empty entry is rejected by the adapter, and an entry
		// carrying only a precondition would turn a replay into a conflict.
		return eventsourcing.Position{}, errs.Internalf("a resend produced no event to append")
	}
	stream, err := eventsourcing.NewStreamID(UserCategory, user.ID().String())
	if err != nil {
		return eventsourcing.Position{}, err
	}

	meta := eventsourcing.Metadata{
		OccurredAt: v.clock.Now().UTC(),
		SubjectIDs: []string{user.SubjectID()},
		ActorID:    user.SubjectID(),
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

	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, v.schemas, e.EventType()),
		})
	}

	results, err := v.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream,
		// The exact revision the aggregate was loaded at. A concurrent write is
		// therefore a refusal rather than a second request appended blind — which
		// matters, because two requests on one stream is two mails.
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

// Compile-time proof that *ratelimit.Limiter satisfies the port this use case
// declares. Without it the only thing binding the two together is a line in
// cmd/api, and a change to either signature would surface there rather than here.
var _ AttemptLimiter = (*ratelimit.Limiter)(nil)
