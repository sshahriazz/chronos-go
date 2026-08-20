// Package reactor holds identity's side effects on the outside world.
//
// There is one today, and it is the one the module cannot work without: the
// verification mail. Registration appends EmailVerificationRequested and drops
// the token's plaintext on the floor, because an event may not carry a live
// credential (ADR-002). Without something on the other end of that event, an
// account is created, an address is claimed, and the person who registered is
// never told how to prove it — the account sits Pending forever and the address
// can never be registered again.
//
// # Why the token is minted HERE and not on the registration path
//
// The alternative is a delivery port called from the handler at the moment of
// minting. Both work; this one is chosen for two reasons.
//
// The first is that it keeps a slow, failure-prone step off the request. A
// registration already pays ~51 ms of Argon2id; adding a workflow start — or, in
// the deployment without durable work, an SMTP conversation — makes the mail
// system's availability part of whether an account can be created at all. Here a
// mail server that is down costs a redelivery, not a failed registration.
//
// The second is that the plaintext then has ONE holder for its whole life. On
// the handler route the token has to be threaded from the mint site, through the
// use case's return path or a port, to whatever delivers it, while the same
// function is also performing an atomic two-stream append that must not carry
// it. Here it is minted, used and discarded inside one call.
//
// What the choice costs is stated plainly rather than hidden: Register returns
// BEFORE any token exists. Someone who asks to resend one second later is asking
// about a token that may not have been issued yet — and because issuing revokes
// what came before, the ordering matters. Both paths converge on the same
// invariant, which is why the ordering is safe either way: every issuance voids
// every outstanding token first, so whichever of the two lands second is the one
// that survives, and there is never more than one live link for an address.
//
// # Why the delivery is keyed by the TOKEN, not only by the event
//
// A reactor's delivery is at-least-once. The platform runner's dedup filters the
// common redeliveries, but it cannot cover a crash between performing the effect
// and recording it, so React must tolerate running twice.
//
// Running twice here mints a second token and revokes the first. That is
// deliberate — one live token, always — but it means the two runs are not the
// same delivery: the first run's mail now contains a DEAD link. So the workflow
// id and the Message-ID are derived from the event id AND the token's
// fingerprint. Keying on the event id alone would make the second run a
// duplicate of the first, refused by Temporal, and the only mail ever sent would
// be the one carrying the revoked token — a verification link that is dead on
// arrival with nothing anywhere to say so. Keyed by the token, a rerun sends a
// second mail whose link works, which is precisely what a resend is.
package reactor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// VerificationReactorName is the persistent subscription group, and it is
// PERMANENT. Renaming it creates a fresh group positioned at the END of the log,
// silently abandoning every verification mail the old group had not yet sent
// (ADR-019).
const VerificationReactorName = "identity-verification-mail"

// VerificationTemplate names the wording. It is permanent too: it appears in
// metrics, in operator template overrides and in the X-Chronos-Template header.
const VerificationTemplate = "identity.verify_email"

// Verification is one freshly issued link's ingredients, as this package needs
// them.
//
// A local type rather than the use case's, so that this package depends on
// identity's contract (the event) and on the notification kernel, and NOT on
// identity's application layer. The composition root converts, in three fields,
// the same way cmd/worker already adapts the reservation sweep onto the durable
// work port — an adapter that reaches into a use case is an adapter that will
// eventually make a decision for it.
type Verification struct {
	// Plaintext is the secret the emailed link carries.
	Plaintext string

	// ExpiresAt is when it stops working, UTC.
	ExpiresAt time.Time

	// TTL is how long it lives, for the wording.
	TTL time.Duration

	// Fingerprint identifies this issuance without being redeemable.
	Fingerprint string
}

// Issuer voids every outstanding verification token for a subject and issues one
// new one, returning the plaintext.
//
// A port declared by its consumer (CONVENTIONS §2). The implementation is
// identity's VerificationIssuer; the reactor knows only that calling this yields
// a link that works and invalidates every earlier one.
type Issuer interface {
	IssueVerification(ctx context.Context, subjectID string) (Verification, error)
}

// Dispatcher applies notification policy and fans out to channels.
//
// An interface rather than *notify.Dispatcher so a test can observe exactly what
// was dispatched without a vault, a template set or an SMTP server.
type Dispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification) error
}

// VerificationMail sends the address-verification link.
type VerificationMail struct {
	issuer   Issuer
	codec    eventsourcing.Codec
	dispatch Dispatcher
	starter  workflow.Starter
}

// Option configures the reactor.
type Option func(*VerificationMail)

// WithWorkflows makes delivery DURABLE: the reactor starts the notification
// workflow instead of sending inline (ADR-017).
//
// The difference is who owns the retry. Inline, an SMTP server that is out for
// twenty minutes turns into a parked backlog a human has to replay, and every
// parked event is a person who registered and was never told how to finish. As a
// workflow, the retry policy is the workflow's own: it survives this process
// restarting and keeps trying for an hour.
//
// The cost is stated where it can be weighed: the workflow's input is written to
// HISTORY, so the plaintext token lives there for the history's retention. That
// is a real weakening of "the plaintext exists only in the mail", and it is
// accepted here because the alternative — minting inside the delivery activity —
// needs a port on the mail transport, and because what history holds is the token
// beside a SubjectID PSEUDONYM and no address (ADR-002). Reading it therefore
// yields a 24-hour, single-use secret that confirms an address claim for an
// account whose password the reader does not have, and which the next issuance
// revokes. Without this option the token never leaves this process.
func WithWorkflows(s workflow.Starter) Option {
	return func(r *VerificationMail) { r.starter = s }
}

// NewVerificationMail builds the reactor.
//
// Every dependency is required. A nil issuer or dispatcher would produce a
// reactor that consumes the event, does nothing, and acks — which is
// indistinguishable at runtime from the gap this whole package exists to close.
func NewVerificationMail(
	issuer Issuer, codec eventsourcing.Codec, dispatch Dispatcher, opts ...Option,
) (*VerificationMail, error) {
	switch {
	case issuer == nil:
		return nil, errors.New("identity/reactor: the verification mail needs a token issuer")
	case codec == nil:
		return nil, errors.New("identity/reactor: the verification mail needs a codec; " +
			"without one the event cannot be decoded and every verification parks")
	case dispatch == nil:
		return nil, errors.New("identity/reactor: the verification mail needs a dispatcher; " +
			"without one it would issue tokens nobody is ever told about")
	}
	r := &VerificationMail{issuer: issuer, codec: codec, dispatch: dispatch}
	for _, apply := range opts {
		apply(r)
	}
	return r, nil
}

// Name is the persistent subscription group.
func (r *VerificationMail) Name() string { return VerificationReactorName }

// Durable reports whether delivery goes through a workflow. Exposed so a
// composition-root test can assert which path a binary actually wired — the two
// are indistinguishable from the outside until a transport fails.
func (r *VerificationMail) Durable() bool { return r.starter != nil }

// Filter narrows the subscription to the one event this reacts to, server-side.
//
// Named exactly rather than by module prefix: identity writes an event on nearly
// every authentication, and a group that woke for all of them would spend its
// whole life deciding it has nothing to do.
func (r *VerificationMail) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{verificationRequestedType},
	}
}

// verificationRequestedType is taken from the contract type rather than written
// out, so it cannot drift from what the codec registers and the domain appends.
var verificationRequestedType = (&contract.EmailVerificationRequested{}).EventType()

// React issues a fresh token and has the link delivered.
//
// The order is issue-then-deliver, and it is the only order that fails safely.
// Delivering first is impossible — there is nothing to deliver until the token
// exists. Issuing and then failing to deliver leaves a live token nobody was
// told about, which this handles by returning the error: the event is
// redelivered, the next attempt revokes that orphan as its first act, and issues
// one that IS delivered. An orphan therefore lives until the next attempt, and
// at worst until its own expiry, and it is unguessable in the meantime.
func (r *VerificationMail) React(ctx context.Context, env eventsourcing.Envelope) error {
	if env.Type != verificationRequestedType {
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a mint: reacting to whatever arrives would
		// make a filter change into an email.
		return nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		// An event we cannot decode will never become decodable. Park it, so it
		// is visible as a verification that never went out.
		return fmt.Errorf("%w: identity/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}
	requested, ok := event.(*contract.EmailVerificationRequested)
	if !ok {
		return fmt.Errorf("%w: identity/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}
	if requested.SubjectID == "" {
		// A token issued against no subject is redeemable by nobody, and mailing
		// it would need an address the vault cannot resolve. Retrying re-reads the
		// same bytes, so this is poison rather than a failure.
		return fmt.Errorf("%w: identity/reactor: %s records no subject",
			eventsourcing.ErrPoison, env.Type)
	}

	verification, err := r.issuer.IssueVerification(ctx, requested.SubjectID)
	if err != nil {
		return fmt.Errorf("identity/reactor: issuing a verification token: %w", err)
	}

	// Derived from the event AND the token, never random: two runs of one event
	// carry two different credentials and are two different deliveries, while a
	// rerun that somehow reached the same token would still deduplicate.
	key := env.ID.String() + ":" + verification.Fingerprint

	n := notify.Notification{
		Template: VerificationTemplate,
		// Transactional: the person asked for this by registering, so it is
		// always delivered and carries no unsubscribe. Nobody can switch off the
		// mail that is the only way into their own account (NOTIFICATIONS §4).
		Class: notify.Transactional,
		// The pseudonym only. The address is resolved from the vault inside the
		// dispatcher, immediately before sending, so it never travels through this
		// reactor, this event or a workflow's history (ADR-002).
		Recipient: notify.Recipient{SubjectID: requested.SubjectID, OrgID: env.Meta.OrgID},
		// EMAIL ONLY, and that restriction is a security control rather than a
		// preference. The link is a live credential: in-app delivery would append
		// it to the notification feed's event stream and project it into a
		// Postgres row, and web push would hand it to a browser endpoint — both of
		// them durable places a token may not go. It is also the only channel that
		// can possibly work here, since the recipient has no session yet.
		Channels: []notify.Channel{notify.ChannelEmail},
		OrgID:    env.Meta.OrgID,
		// Data carries no personal data: a token, and how long it lasts. The
		// address, the name and the locale come from the vault.
		Data: map[string]any{
			"Token":     verification.Plaintext,
			"ExpiresIn": humanize(verification.TTL),
		},
		OccurredAt:     env.Meta.OccurredAt,
		IdempotencyKey: key,
	}

	if r.starter != nil {
		return r.start(ctx, n, key)
	}
	if err := r.dispatch.Dispatch(ctx, n); err != nil {
		return fmt.Errorf("identity/reactor: delivering %s: %w", VerificationTemplate, err)
	}
	return nil
}

// start hands the delivery to a workflow.
//
// ErrAlreadyStarted is success: a run under this id already exists, and because
// the id contains the token's fingerprint that run carries THIS token — the work
// this call wanted is already running or already done. Treating it as an error
// would park an event whose mail was sent perfectly.
//
// Anything else means the run did NOT start, and is returned so the event is
// redelivered rather than acked with a token nobody was told about.
func (r *VerificationMail) start(ctx context.Context, n notify.Notification, id string) error {
	_, err := r.starter.Start(ctx, workflow.Start{
		ID:    id,
		Name:  notify.SendNotificationWorkflow,
		Input: notify.InputFor(n),
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("identity/reactor: starting delivery for %s: %w", VerificationTemplate, err)
	}
	return nil
}

// humanize renders a token lifetime the way a person would say it.
//
// Deliberately coarse. The exact deadline is enforced by the store, and a
// message that promises "23 hours and 59 minutes" is both less readable and
// wrong the moment the mail sits in a queue for a minute.
func humanize(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	case d >= 2*time.Minute:
		return fmt.Sprintf("%d minutes", int(d.Minutes()))
	default:
		return "a few minutes"
	}
}
