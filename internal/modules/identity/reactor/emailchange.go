package reactor

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// EmailChangeReactorName is the persistent subscription group. Permanent: it
// keys the group, so renaming it makes the server create a new one starting from
// the beginning of the log and re-mail every change ever requested.
const EmailChangeReactorName = "identity-email-change-mail"

// The three messages this flow sends. Permanent — they appear in metrics, in
// preferences and in operator overrides.
const (
	// ChangeConfirmTemplate carries the link that PROVES the new address. It goes
	// to the new address and nowhere else.
	ChangeConfirmTemplate = "identity.email_change_confirm"

	// ChangeNoticeTemplate warns the CURRENT address that a change was asked
	// for. It carries no link and grants nothing; its whole job is to reach
	// somebody who did not ask for this while it can still be cancelled.
	ChangeNoticeTemplate = "identity.email_change_requested"

	// ChangeRevertTemplate carries the link that UNDOES a completed change. It
	// goes to the address the account moved AWAY from.
	ChangeRevertTemplate = "identity.email_change_revert"
)

// PurposeIssuer voids every outstanding token of a purpose for a subject and
// issues exactly one new one.
//
// A port declared by its consumer (CONVENTIONS §2), and a WIDER one than Issuer
// above by exactly the purpose argument. The reactor knows only that calling
// this yields a link that works and invalidates every earlier one of that kind.
type PurposeIssuer interface {
	IssueFor(ctx context.Context, purpose app.TokenPurpose, subjectID string) (Verification, error)
}

// EmailChangeMail sends the three messages identity.md §12's flow needs.
//
// # Why it is a separate reactor from the verification mail
//
// Not tidiness — the two are on different subscription GROUPS, so a change mail
// that parks does not stop registrations from being verified, and an SMTP outage
// during a change campaign does not park the one message that is the only way
// into a new account. It is the same argument the provisioning reactor makes for
// its own group.
//
// # Two messages from one event, which the notification catalogue cannot express
//
// A request produces a LINK to the new address and a WARNING to the old one, and
// the catalogue maps one event to one notification. It also cannot mint a token.
// So both live here, and the catalogue records the event as silent with a
// pointer to this file.
type EmailChangeMail struct {
	issuer   PurposeIssuer
	codec    eventsourcing.Codec
	dispatch Dispatcher
	starter  workflow.Starter
}

// ChangeOption configures the reactor.
type ChangeOption func(*EmailChangeMail)

// WithChangeWorkflows makes delivery durable, exactly as WithWorkflows does for
// the verification mail, and with the same trade-off: the token reaches workflow
// history in exchange for an hour of durable retries instead of a parked event.
func WithChangeWorkflows(s workflow.Starter) ChangeOption {
	return func(r *EmailChangeMail) { r.starter = s }
}

// NewEmailChangeMail builds the reactor.
func NewEmailChangeMail(
	issuer PurposeIssuer, codec eventsourcing.Codec, dispatch Dispatcher, opts ...ChangeOption,
) (*EmailChangeMail, error) {
	switch {
	case issuer == nil:
		return nil, errors.New("identity/reactor: the email-change mail needs a token issuer; " +
			"without one a requested change can never be proven and the account is stuck " +
			"holding a claim on an address it cannot move to")
	case codec == nil:
		return nil, errors.New("identity/reactor: the email-change mail needs a codec")
	case dispatch == nil:
		return nil, errors.New("identity/reactor: the email-change mail needs a dispatcher; " +
			"without one it would issue tokens nobody is told about — and, worse, would " +
			"complete changes without ever warning the address being moved away from")
	}
	r := &EmailChangeMail{issuer: issuer, codec: codec, dispatch: dispatch}
	for _, apply := range opts {
		apply(r)
	}
	return r, nil
}

func (r *EmailChangeMail) Name() string { return EmailChangeReactorName }

// Durable reports whether delivery goes through a workflow.
func (r *EmailChangeMail) Durable() bool { return r.starter != nil }

var (
	changeRequestedType = (&contract.EmailChangeRequested{}).EventType()
	changedType         = (&contract.EmailChanged{}).EventType()
)

// Filter names both events exactly.
func (r *EmailChangeMail) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{changeRequestedType, changedType},
	}
}

// React sends what the event calls for.
func (r *EmailChangeMail) React(ctx context.Context, env eventsourcing.Envelope) error {
	switch env.Type {
	case changeRequestedType, changedType:
	default:
		// The filter over-delivered, or the group predates the filter. Not an
		// error, and deliberately not a mint.
		return nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("%w: identity/reactor: decoding %s: %w",
			eventsourcing.ErrPoison, env.Type, err)
	}

	switch e := event.(type) {
	case *contract.EmailChangeRequested:
		return r.onRequested(ctx, env, e)
	case *contract.EmailChanged:
		return r.onChanged(ctx, env, e)
	default:
		return fmt.Errorf("%w: identity/reactor: %s decoded as %T",
			eventsourcing.ErrPoison, env.Type, event)
	}
}

// onRequested mails the proof link to the NEW address and a warning to the old.
//
// # The warning is the one that matters, and it is sent SECOND
//
// The link is what the account holder is waiting for, so it goes first. The
// warning is what reaches somebody whose session was hijacked, and it is sent on
// the same event so that the two cannot come apart — a build that sent only the
// link would leave an attacker's change completely silent to the victim until it
// completed, which is the failure identity.md §12 names in one sentence.
//
// A failure of EITHER returns an error and the event is redelivered. That means
// the link can be sent twice, which is harmless because the second issuance
// revokes the first; the warning can also be sent twice, which is noise. Both
// are better than the alternative, where a failed warning is acked away.
func (r *EmailChangeMail) onRequested(
	ctx context.Context, env eventsourcing.Envelope, e *contract.EmailChangeRequested,
) error {
	if e.SubjectID == "" {
		return fmt.Errorf("%w: identity/reactor: %s records no subject",
			eventsourcing.ErrPoison, env.Type)
	}

	token, err := r.issuer.IssueFor(ctx, app.PurposeEmailChange, e.SubjectID)
	if err != nil {
		return fmt.Errorf("identity/reactor: issuing an email-change token: %w", err)
	}

	key := env.ID.String() + ":" + token.Fingerprint
	if err := r.deliver(ctx, key, notify.Notification{
		Template: ChangeConfirmTemplate,
		// Transactional: the person asked for this, so it is always delivered and
		// carries no unsubscribe. Nobody can switch off the mail that is the only
		// way to finish a change they started.
		Class:     notify.Transactional,
		Recipient: notify.Recipient{SubjectID: e.SubjectID, OrgID: env.Meta.OrgID},
		// THE PENDING ADDRESS. Sending this to the primary would mail the proof of
		// a new address to the old one, which proves nothing — and would hand a
		// live change token to whoever already reads the current mailbox.
		Address: notify.AddressPending,
		// EMAIL ONLY, and it is a security control rather than a preference: the
		// link is a live credential, and in-app delivery would project it into a
		// Postgres row while web push would hand it to a browser endpoint.
		Channels:       []notify.Channel{notify.ChannelEmail},
		OrgID:          env.Meta.OrgID,
		Data:           map[string]any{"Token": token.Plaintext, "ExpiresIn": humanize(token.TTL)},
		OccurredAt:     env.Meta.OccurredAt,
		IdempotencyKey: key,
	}); err != nil {
		return err
	}

	// The warning, to the address still in force. No token, no link: it exists to
	// tell somebody a change was asked for while it can still be refused, and a
	// credential in it would make the warning itself the attack.
	return r.deliver(ctx, env.ID.String()+":notice", notify.Notification{
		Template: ChangeNoticeTemplate,
		// SECURITY, so no preference can switch it off. A person who has muted
		// account mail has not consented to being kept unaware that somebody is
		// moving their address (NOTIFICATIONS §4).
		Class:          notify.Security,
		Recipient:      notify.Recipient{SubjectID: e.SubjectID, OrgID: env.Meta.OrgID},
		Address:        notify.AddressPrimary,
		OrgID:          env.Meta.OrgID,
		Data:           map[string]any{"ExpiresIn": humanize(token.TTL)},
		OccurredAt:     env.Meta.OccurredAt,
		IdempotencyKey: env.ID.String() + ":notice",
	})
}

// onChanged mails the revert link to the address the account moved AWAY from.
//
// This is the remedy identity.md §12 asks for, and the address it goes to is the
// whole of it: an attacker who proved a new address still cannot stop the person
// who reads the OLD mailbox from being told and undoing it.
//
// It is the only notification in the system that resolves a non-primary address,
// and the vault adapter REFUSES to fall back to the primary when no previous
// address is recorded — because that fallback would deliver "your address was
// changed, click here to undo it" to the attacker.
func (r *EmailChangeMail) onChanged(
	ctx context.Context, env eventsourcing.Envelope, e *contract.EmailChanged,
) error {
	if e.SubjectID == "" {
		return fmt.Errorf("%w: identity/reactor: %s records no subject",
			eventsourcing.ErrPoison, env.Type)
	}
	if e.FromIndex == "" {
		// A change from nothing. No previous address exists, so there is nobody to
		// warn and no revert to offer. Not an error: it is a state the aggregate
		// forbids today, and reacting to it by parking would be a reactor that
		// stops on a shape of history rather than on a fault.
		return nil
	}

	token, err := r.issuer.IssueFor(ctx, app.PurposeEmailChangeRevert, e.SubjectID)
	if err != nil {
		return fmt.Errorf("identity/reactor: issuing an email-change revert token: %w", err)
	}

	key := env.ID.String() + ":" + token.Fingerprint
	return r.deliver(ctx, key, notify.Notification{
		Template: ChangeRevertTemplate,
		// SECURITY. This is the message that tells somebody their account was
		// taken, and no preference may suppress it.
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: e.SubjectID, OrgID: env.Meta.OrgID},
		// THE PREVIOUS ADDRESS. See the doc comment.
		Address:        notify.AddressPrevious,
		Channels:       []notify.Channel{notify.ChannelEmail},
		OrgID:          env.Meta.OrgID,
		Data:           map[string]any{"Token": token.Plaintext, "ExpiresIn": humanize(token.TTL)},
		OccurredAt:     env.Meta.OccurredAt,
		IdempotencyKey: key,
	})
}

// deliver sends inline or starts a workflow, as the verification mail does.
func (r *EmailChangeMail) deliver(ctx context.Context, id string, n notify.Notification) error {
	if r.starter != nil {
		_, err := r.starter.Start(ctx, workflow.Start{
			ID: id, Name: notify.SendNotificationWorkflow, Input: notify.InputFor(n),
		})
		if errors.Is(err, workflow.ErrAlreadyStarted) {
			// Success: a run under this id already exists, and the id contains the
			// token's fingerprint, so that run carries THIS token.
			return nil
		}
		if err != nil {
			return fmt.Errorf("identity/reactor: starting delivery for %s: %w", n.Template, err)
		}
		return nil
	}
	if err := r.dispatch.Dispatch(ctx, n); err != nil {
		return fmt.Errorf("identity/reactor: delivering %s: %w", n.Template, err)
	}
	return nil
}
