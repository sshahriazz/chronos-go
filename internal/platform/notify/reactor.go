package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// Audiences turns a role into the people who hold it, for one event.
//
// A port because the answer differs by role and by module: the subject comes
// from event metadata, but the org's owner and admins are read-model questions.
type Audiences interface {
	Resolve(ctx context.Context, a Audience, env eventsourcing.Envelope) ([]Recipient, error)
}

// ErrAudienceUnsupported means a role cannot be resolved yet. It is deliberately
// an error rather than an empty list: silently notifying nobody is the failure
// this whole mechanism exists to prevent.
var ErrAudienceUnsupported = errors.New("notify: audience cannot be resolved")

// SubjectAudiences resolves the roles derivable from the event alone.
//
// Subject and Actor come from metadata. Operator comes from configuration. The
// org roles need a read model and are refused here rather than guessed —
// wiring a module's resolver replaces this one.
type SubjectAudiences struct {
	// Operator receives Operator-class notifications. Empty means operator
	// alerts cannot be delivered, which Resolve reports rather than hides.
	Operator []Recipient
}

var _ Audiences = SubjectAudiences{}

func (s SubjectAudiences) Resolve(
	_ context.Context, a Audience, env eventsourcing.Envelope,
) ([]Recipient, error) {
	switch a {
	case AudienceSubject:
		out := make([]Recipient, 0, len(env.Meta.SubjectIDs))
		for _, id := range env.Meta.SubjectIDs {
			out = append(out, Recipient{SubjectID: id, OrgID: env.Meta.OrgID})
		}
		return out, nil

	case AudienceActor:
		// From ActorID, never guessed from SubjectIDs. An admin who revokes
		// someone else's access is the actor while the other person is the
		// subject, so "the first subject" would send the notification to the
		// wrong person — worse than sending none.
		if env.Meta.ActorID == "" {
			return nil, fmt.Errorf("%w: the event records no actor", ErrAudienceUnsupported)
		}
		return []Recipient{{SubjectID: env.Meta.ActorID, OrgID: env.Meta.OrgID}}, nil

	case AudienceOperator:
		if len(s.Operator) == 0 {
			return nil, fmt.Errorf("%w: no operator recipients configured", ErrAudienceUnsupported)
		}
		return s.Operator, nil

	default:
		return nil, fmt.Errorf("%w: %s needs a read model", ErrAudienceUnsupported, a)
	}
}

// EventReactor turns domain events into notifications, driven entirely by the
// catalogue.
//
// There is ONE of these, not one per notification. Per-notification reactor code
// is where the mapping drifts: two handlers disagree about a class, a third
// forgets an audience, and nothing compares them. Here the mapping is data, it
// is verified against the codec, and this code is the same for every event.
type EventReactor struct {
	name      string
	catalogue *Catalogue
	codec     eventsourcing.Codec
	audiences Audiences
	dispatch  *Dispatcher
	starter   workflow.Starter
}

// NewEventReactor builds the reactor. The name is the persistent subscription
// group and is permanent.
func NewEventReactor(
	name string, c *Catalogue, codec eventsourcing.Codec, aud Audiences, d *Dispatcher,
	opts ...ReactorOption,
) *EventReactor {
	r := &EventReactor{name: name, catalogue: c, codec: codec, audiences: aud, dispatch: d}
	for _, apply := range opts {
		apply(r)
	}
	return r
}

// ReactorOption configures the reactor.
type ReactorOption func(*EventReactor)

// WithWorkflows makes delivery DURABLE: the reactor starts one workflow per
// recipient instead of sending inline (ADR-017).
//
// The difference is what happens when the transport is down. Inline, the send
// fails, the event is redelivered by the subscription, and after the group's
// retries it parks — an SMTP server that is out for twenty minutes turns into a
// parked backlog a human has to replay. As a workflow, the retry policy is the
// workflow's own: it survives this process restarting, keeps trying for an hour,
// and the reactor has already acked.
//
// Without it the reactor delivers inline, which is correct and is what a
// deployment with TEMPORAL_ENABLED=false does. The two paths dispatch the same
// notification through the same dispatcher; only who owns the retry differs.
func WithWorkflows(s workflow.Starter) ReactorOption {
	return func(r *EventReactor) { r.starter = s }
}

// Durable reports whether delivery goes through workflows. Exposed so a
// composition-root test can assert which path a binary actually wired — the two
// are indistinguishable from the outside until a transport fails.
func (r *EventReactor) Durable() bool { return r.starter != nil }

func (r *EventReactor) Name() string { return r.name }

// Filter narrows the subscription to exactly the event types the catalogue
// notifies on, so the worker is not handed traffic it would only discard.
//
// An EMPTY catalogue yields a filter matching nothing, not everything. Left to
// the default, an empty prefix list means "no filter", and a notification
// reactor with nothing registered would subscribe to the entire log — waking on
// every event in the system to decide, each time, that it has nothing to do.
func (r *EventReactor) Filter() eventsourcing.SubscriptionFilter {
	events := r.catalogue.EventTypePrefixes()
	if len(events) == 0 {
		return eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{matchNothing}}
	}
	return eventsourcing.SubscriptionFilter{EventTypePrefixes: events}
}

// matchNothing is a prefix no event type can have: types are
// "<module>.<Name>.v<N>" and none begins with a NUL-ish sentinel.
const matchNothing = "\x00-notify-matches-nothing"

// React looks the event up and dispatches to everyone the catalogue says should
// hear about it.
func (r *EventReactor) React(ctx context.Context, env eventsourcing.Envelope) error {
	spec, ok := r.catalogue.For(env.Type)
	if !ok {
		// Either declared silent, or the filter over-delivered. Both are fine:
		// Verify is what guarantees the type was decided about at all.
		return nil
	}

	event, err := r.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		// An event we cannot decode will never become decodable.
		return fmt.Errorf("%w: notify: decoding %s: %w", eventsourcing.ErrPoison, env.Type, err)
	}

	recipients, err := r.audiences.Resolve(ctx, spec.Audience, env)
	if err != nil {
		if errors.Is(err, ErrAudienceUnsupported) {
			// Not retryable, and NOT silently dropped: park it so the gap is
			// visible instead of becoming a notification nobody ever received.
			return fmt.Errorf("%w: notify: %s audience for %s: %w",
				eventsourcing.ErrPoison, spec.Audience, env.Type, err)
		}
		return fmt.Errorf("notify: resolving %s audience: %w", spec.Audience, err)
	}
	// Validate BEFORE anything is delivered. A resolver is the one place where
	// a bug becomes a cross-tenant leak rather than a missing message, so what
	// it returns is checked rather than trusted.
	if err := validateRecipients(spec, env, recipients); err != nil {
		// Not retryable: the same resolver will return the same people. Park it
		// so the fault is visible instead of becoming silence.
		// Both %w: the caller must be able to distinguish a containment
		// failure (ErrCrossTenant) from a gap (ErrAudienceUnsupported), and
		// both must still read as poison to the transport.
		return fmt.Errorf("%w: notify: %w", eventsourcing.ErrPoison, err)
	}
	if len(recipients) == 0 {
		return nil
	}

	var data map[string]any
	if spec.Data != nil {
		data = spec.Data(event)
	}

	var firstErr error
	for i, rcpt := range recipients {
		// Per recipient, so two people notified by one event do not deduplicate
		// against each other — and so the workflow id below is unique per
		// delivery while still being DERIVED rather than random.
		key := fmt.Sprintf("%s:%d", env.ID.String(), i)

		n := Notification{
			Template:       spec.Template,
			Class:          spec.Class,
			Recipient:      rcpt,
			Channels:       spec.Channels,
			Address:        spec.Address,
			OrgID:          env.Meta.OrgID,
			WorkspaceID:    env.Meta.WorkspaceID,
			Data:           data,
			OccurredAt:     env.Meta.OccurredAt,
			IdempotencyKey: key,
		}

		var err error
		if r.starter != nil {
			err = r.start(ctx, n, key)
		} else {
			err = r.dispatch.Dispatch(ctx, n)
		}
		if err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}

// start hands one delivery to a workflow.
//
// The workflow id is the delivery's idempotency key, so it is derived from the
// event and stable across redeliveries. A second start with that id is REFUSED
// by the service, and that refusal is success here: the work is already running
// or has already run, which is exactly what this call wanted. Treating it as an
// error would park an event whose notification was delivered perfectly.
//
// Anything else means the run did NOT start. It is returned, so the subscription
// redelivers rather than acking a notification nobody will ever send.
func (r *EventReactor) start(ctx context.Context, n Notification, id string) error {
	_, err := r.starter.Start(ctx, workflow.Start{
		ID:   id,
		Name: SendNotificationWorkflow,
		// Pseudonyms only: workflow input is written to durable history, so the
		// same rule the event log follows applies unchanged (ADR-002). The
		// address is resolved from the vault inside the activity.
		Input: InputFor(n),
	})
	if errors.Is(err, workflow.ErrAlreadyStarted) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("notify: starting delivery for %s: %w", n.Template, err)
	}
	return nil
}
