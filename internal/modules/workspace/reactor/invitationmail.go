// Package reactor holds workspace's side effects on the outside world.
//
// There is one, and it is the one invitations cannot work without: the mail
// carrying the link. Issuing appends InvitationIssued and mints nothing, because
// an event may not carry a live credential (ADR-002) — so without something on
// the other end of that event, a seat is spent, an invitation sits Pending for
// seven days, and the person it was for is never told it exists.
//
// # Why this mints the link rather than reading one
//
// There is nothing to read. Only the digest reaches storage, and a digest is
// one-way by construction, so whoever sends the mail must hold the plaintext at
// the moment it is minted. That is identity's reasoning for its verification
// mail and it applies here unchanged; app.InvitationIssuer records the rest.
//
// # Why the delivery is keyed by the LINK, not only by the event
//
// A reactor's delivery is at-least-once. The platform runner's dedup filters the
// common redeliveries, but it cannot cover a crash between performing the effect
// and recording it, so React must tolerate running twice.
//
// Running twice here mints a second link and voids the first. That is deliberate
// — one live link, always — but it means the two runs are not the same delivery:
// the first run's mail now contains a DEAD link. So the delivery key is derived
// from the event id AND the link's fingerprint. Keying on the event id alone
// would make the second run a duplicate, refused as already done, and the only
// mail ever sent would be the one carrying the voided link — an invitation that
// is dead on arrival with nothing anywhere to say so.
package reactor

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// InvitationReactorName is the persistent subscription group, and it is
// PERMANENT. Renaming it creates a fresh group positioned at the END of the log,
// silently abandoning every invitation mail the old group had not yet sent
// (ADR-019).
const InvitationReactorName = "workspace-invitation-mail"

// InvitationTemplate names the wording. Permanent too: it appears in metrics, in
// operator template overrides and in the X-Chronos-Template header.
const InvitationTemplate = "workspace.invitation"

// Link is one freshly issued invitation link, as this package needs it.
//
// A local type rather than the use case's, so this package depends on
// workspace's contract and the notification kernel and NOT on workspace's
// application layer. The composition root converts, in three fields — an adapter
// that reaches into a use case is an adapter that will eventually make a
// decision for it.
type Link struct {
	// Plaintext is the secret the emailed link carries.
	Plaintext string

	// TTL is how long it lives, for the wording.
	TTL time.Duration

	// Fingerprint identifies this issuance without being redeemable.
	Fingerprint string
}

// Issuer voids every outstanding link for an invitation and mints one.
//
// A port declared by its consumer (CONVENTIONS §2). The implementation is
// workspace's InvitationIssuer; this reactor knows only that calling it yields a
// link that works and invalidates every earlier one.
type Issuer interface {
	IssueLink(ctx context.Context, invitationID, orgID string) (Link, error)
}

// Dispatcher applies notification policy and fans out to channels.
type Dispatcher interface {
	Dispatch(ctx context.Context, n notify.Notification) error
}

// InvitationMail sends the invitation link.
type InvitationMail struct {
	issuer   Issuer
	codec    eventsourcing.Codec
	dispatch Dispatcher
	starter  workflow.Starter

	// lifecycleStarter and lifecycle are the per-invitation timer. SEPARATE from
	// starter above, so that enabling the timer does not silently also move mail
	// delivery onto a workflow — two independent decisions with two independent
	// failure modes, and one option that quietly did both would be found out by
	// somebody debugging why an SMTP outage stopped parking events.
	lifecycleStarter workflow.Starter
	lifecycle        string
}

// Option configures the reactor.
type Option func(*InvitationMail)

// WithWorkflows makes delivery DURABLE: the reactor starts the notification
// workflow instead of sending inline (ADR-017).
//
// The difference is who owns the retry. Inline, an SMTP server out for twenty
// minutes becomes a parked backlog a human has to replay, and every parked event
// is a seat spent on somebody who was never told. As a workflow the retry is the
// workflow's own, surviving this process restarting.
//
// The cost is stated where it can be weighed, exactly as identity states it: the
// workflow's input is written to HISTORY, so the plaintext lives there for the
// history's retention. That weakens "the plaintext exists only in the mail", and
// it is accepted for the same reasons — the alternative needs a port on the mail
// transport, and what history holds is a token beside a SubjectID PSEUDONYM with
// no address (ADR-002). Reading it yields a seven-day, single-use secret that
// joins one workspace as one role, which the next issuance voids. Without this
// option the link never leaves this process.
func WithWorkflows(s workflow.Starter) Option {
	return func(r *InvitationMail) { r.starter = s }
}

// WithLifecycle makes the reactor START the per-invitation timer.
//
// The timer is what reminds and expires on time; the reconciliation sweep is
// what makes expiry certain when a timer was never started. Both are needed and
// neither replaces the other.
//
// The workflow NAME is passed in rather than declared here, and that is not
// ceremony: the name is registered by the worker and persisted in history, so
// two constants that must match would be one more place to drift. This package
// cannot import the Temporal adapter, so the composition root — which imports
// both — hands over the one constant.
//
// Started only on an ISSUE. A resend needs no second timer: the run already
// waiting re-reads the deadline every time it wakes, so an extended window is
// simply a longer sleep.
func WithLifecycle(s workflow.Starter, workflowName string) Option {
	return func(r *InvitationMail) {
		r.lifecycleStarter = s
		r.lifecycle = workflowName
	}
}

// NewInvitationMail builds the reactor.
//
// Every dependency is required. A nil issuer or dispatcher produces a reactor
// that consumes the event, does nothing, and acks — indistinguishable at runtime
// from the gap this package exists to close.
func NewInvitationMail(
	issuer Issuer, codec eventsourcing.Codec, dispatch Dispatcher, opts ...Option,
) (*InvitationMail, error) {
	switch {
	case issuer == nil:
		return nil, errors.New("workspace/reactor: the invitation mail needs a link issuer")
	case codec == nil:
		return nil, errors.New("workspace/reactor: the invitation mail needs a codec; " +
			"without one the event cannot be decoded and every invitation parks")
	case dispatch == nil:
		return nil, errors.New("workspace/reactor: the invitation mail needs a dispatcher; " +
			"without one it would mint links nobody is ever told about")
	}
	r := &InvitationMail{issuer: issuer, codec: codec, dispatch: dispatch}
	for _, apply := range opts {
		apply(r)
	}
	return r, nil
}

// Name is the persistent subscription group.
func (r *InvitationMail) Name() string { return InvitationReactorName }

// Timed reports whether the per-invitation timer is wired. Exposed for the same
// reason Durable is: a reactor that mails but starts no timer looks identical
// from the outside until an invitation should have expired and did not.
func (r *InvitationMail) Timed() bool { return r.lifecycleStarter != nil && r.lifecycle != "" }

// Durable reports whether delivery goes through a workflow. Exposed so a
// composition-root test can assert which path a binary actually wired — the two
// are indistinguishable from the outside until a transport fails.
func (r *InvitationMail) Durable() bool { return r.starter != nil }

// Filter narrows the subscription to the two events that mean "send a link".
//
// Named exactly rather than by category prefix: an invitation's stream also
// carries five settlements, and a group that woke for all of them would spend
// most of its life deciding it has nothing to do — and would be one missing
// branch away from mailing a link for a revocation.
func (r *InvitationMail) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{invitationIssuedType, invitationRotatedType},
	}
}

// Taken from the contract types rather than written out, so they cannot drift
// from what the codec registers and the domain appends.
var (
	invitationIssuedType  = (&contract.InvitationIssued{}).EventType()
	invitationRotatedType = (&contract.InvitationTokenRotated{}).EventType()
)

// React mints a fresh link and has it delivered.
//
// The order is mint-then-deliver, and it is the only order that fails safely.
// Delivering first is impossible — there is nothing to deliver until the link
// exists. Minting and then failing to deliver leaves a live link nobody was told
// about, which this handles by returning the error: the event is redelivered,
// the next attempt voids that orphan as its first act, and mints one that IS
// delivered. An orphan therefore lives until the next attempt, and at worst
// until its own expiry, and it is unguessable in the meantime.
func (r *InvitationMail) React(ctx context.Context, env eventsourcing.Envelope) error {
	invitationID, orgID, subjectID, ok, err := r.subject(env)
	if err != nil || !ok {
		return err
	}

	link, err := r.issuer.IssueLink(ctx, invitationID, orgID)
	if err != nil {
		return fmt.Errorf("workspace/reactor: issuing an invitation link: %w", err)
	}

	// Derived from the event AND the link, never random: two runs of one event
	// carry two different credentials and are two different deliveries, while a
	// rerun that somehow reached the same link would still deduplicate.
	key := env.ID.String() + ":" + link.Fingerprint

	n := notify.Notification{
		Template: InvitationTemplate,
		// Transactional: somebody deliberately invited this person, and the mail
		// is the only way they can act on it. It carries no unsubscribe, because
		// there is nothing to unsubscribe FROM — declining is a link in the same
		// message (NOTIFICATIONS §4).
		Class: notify.Transactional,
		// The pseudonym only. The address is resolved from the vault inside the
		// dispatcher, immediately before sending, so it never travels through
		// this reactor, this event or a workflow's history (ADR-002).
		Recipient: notify.Recipient{SubjectID: subjectID, OrgID: orgID},
		// EMAIL ONLY, and that is a security control rather than a preference.
		// The link is a live credential: in-app delivery would append it to the
		// notification feed's event stream and project it into a Postgres row,
		// and web push would hand it to a browser endpoint — both durable places
		// a token may not go. It is also the only channel that can work, since
		// the recipient may have no account at all.
		Channels: []notify.Channel{notify.ChannelEmail},
		OrgID:    orgID,
		// No personal data: a token, how long it lasts, and which workspace. The
		// address, the name and the locale come from the vault.
		Data: map[string]any{
			"Token":       link.Plaintext,
			"ExpiresIn":   humanize(link.TTL),
			"WorkspaceID": env.Meta.WorkspaceID,
		},
		OccurredAt:     env.Meta.OccurredAt,
		IdempotencyKey: key,
	}

	if r.starter != nil {
		if err := r.start(ctx, n, key); err != nil {
			return err
		}
	} else if err := r.dispatch.Dispatch(ctx, n); err != nil {
		return fmt.Errorf("workspace/reactor: delivering %s: %w", InvitationTemplate, err)
	}

	// The timer, AFTER the mail. Both orders leave a window, and this is the
	// harmless one: a failure here means the invitation exists with a link in
	// somebody's inbox and no timer, which the reconciliation sweep closes. The
	// reverse would start a timer for an invitation nobody was told about.
	//
	// Only on an issue. A resend needs no second timer — the run already waiting
	// re-reads the deadline every time it wakes.
	if env.Type == invitationIssuedType {
		return r.startLifecycle(ctx, invitationID, orgID)
	}
	return nil
}

// startLifecycle begins the per-invitation timer.
//
// Keyed on the INVITATION and not on the event, unlike the mail: there is
// exactly one timer per invitation for its whole life, and a redelivered issue
// must find the existing run rather than start a second one that would expire
// the same invitation twice.
//
// ErrAlreadyStarted is therefore the NORMAL outcome on every redelivery, and it
// is success. Anything else means no timer is running, and it is returned so the
// event comes back.
func (r *InvitationMail) startLifecycle(ctx context.Context, invitationID, orgID string) error {
	if r.lifecycleStarter == nil || r.lifecycle == "" {
		// No durable work in this deployment. The invitation still expires —
		// through the reconciliation sweep — but nothing reminds, and that is a
		// property of the deployment rather than a failure here.
		return nil
	}
	_, err := r.lifecycleStarter.Start(ctx, workflow.Start{
		ID:    "invitation-lifecycle:" + invitationID,
		Name:  r.lifecycle,
		Input: InvitationLifecycleArgs{InvitationID: invitationID, OrgID: orgID},
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workspace/reactor: starting the timer for %s: %w", invitationID, err)
	}
	return nil
}

// InvitationLifecycleArgs is what the timer is started with.
//
// Ids and nothing else. Workflow input is written to history, which is durable
// and replicated, so ADR-002 applies to it exactly as it does to the event log —
// and it deliberately carries NO DEADLINE, because a resend moves it and a timer
// that trusted its input would expire an invitation whose link is still live.
//
// It mirrors the adapter's input type rather than importing it, for the reason
// Link does: a reactor that could reach into the Temporal adapter is one that
// will eventually make a decision for it.
type InvitationLifecycleArgs struct {
	InvitationID string
	OrgID        string
}

// subject decodes the event and pulls out the three things a link needs.
//
// Both events carry them, and neither carries anything else this reactor uses —
// which is why a rotation and an issue take the same path: from here on the two
// are the same job, "mail a fresh link for this invitation".
func (r *InvitationMail) subject(
	env eventsourcing.Envelope,
) (invitationID, orgID, subjectID string, ok bool, err error) {
	switch env.Type {
	case invitationIssuedType, invitationRotatedType:
	default:
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a mint: reacting to whatever arrives would
		// turn a filter change into an email — and on this stream the other five
		// event types are settlements, so it would mail a link for a revocation.
		return "", "", "", false, nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		// An event we cannot decode will never become decodable. Park it, so it
		// is visible as an invitation that never went out.
		return "", "", "", false, fmt.Errorf("%w: workspace/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}

	switch e := event.(type) {
	case *contract.InvitationIssued:
		invitationID, orgID, subjectID = e.InvitationID, e.OrgID, e.SubjectID
	case *contract.InvitationTokenRotated:
		invitationID, orgID, subjectID = e.InvitationID, e.OrgID, e.SubjectID
	default:
		return "", "", "", false, fmt.Errorf("%w: workspace/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}

	// A link with no invitation is redeemable by nobody; one with no subject
	// cannot be addressed, because the vault entry hangs off that pseudonym; one
	// with no organization cannot be stored against a tenant. Retrying re-reads
	// the same bytes, so each is poison rather than a failure.
	switch {
	case invitationID == "":
		return "", "", "", false, fmt.Errorf("%w: workspace/reactor: %s names no invitation",
			eventsourcing.ErrPoison, env.Type)
	case orgID == "":
		return "", "", "", false, fmt.Errorf("%w: workspace/reactor: %s names no organization",
			eventsourcing.ErrPoison, env.Type)
	case subjectID == "":
		return "", "", "", false, fmt.Errorf("%w: workspace/reactor: %s names no subject, so "+
			"the vault has no address to resolve", eventsourcing.ErrPoison, env.Type)
	}
	return invitationID, orgID, subjectID, true, nil
}

// start hands the delivery to a workflow.
//
// ErrAlreadyStarted is success: a run under this id already exists, and because
// the id contains the link's fingerprint that run carries THIS link — the work
// this call wanted is already running or already done. Treating it as an error
// would park an event whose mail was sent perfectly.
func (r *InvitationMail) start(ctx context.Context, n notify.Notification, id string) error {
	_, err := r.starter.Start(ctx, workflow.Start{
		ID:    id,
		Name:  notify.SendNotificationWorkflow,
		Input: notify.InputFor(n),
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("workspace/reactor: starting delivery for %s: %w",
			InvitationTemplate, err)
	}
	return nil
}

// humanize renders a lifetime the way a person would say it.
//
// Deliberately coarse. The exact deadline is enforced by the store, and a message
// promising "6 days and 23 hours" is both less readable and wrong the moment the
// mail sits in a queue.
func humanize(d time.Duration) string {
	switch {
	case d >= 48*time.Hour:
		return fmt.Sprintf("%d days", int(d.Hours()/24))
	case d >= 2*time.Hour:
		return fmt.Sprintf("%d hours", int(d.Hours()))
	default:
		return "a few minutes"
	}
}
