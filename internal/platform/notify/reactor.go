package notify

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
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
}

// NewEventReactor builds the reactor. The name is the persistent subscription
// group and is permanent.
func NewEventReactor(
	name string, c *Catalogue, codec eventsourcing.Codec, aud Audiences, d *Dispatcher,
) *EventReactor {
	return &EventReactor{name: name, catalogue: c, codec: codec, audiences: aud, dispatch: d}
}

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
		n := Notification{
			Template:    spec.Template,
			Class:       spec.Class,
			Recipient:   rcpt,
			Channels:    spec.Channels,
			OrgID:       env.Meta.OrgID,
			WorkspaceID: env.Meta.WorkspaceID,
			Data:        data,
			OccurredAt:  env.Meta.OccurredAt,
			// Per recipient, so two people notified by one event do not
			// deduplicate against each other.
			IdempotencyKey: fmt.Sprintf("%s:%d", env.ID.String(), i),
		}
		if err := r.dispatch.Dispatch(ctx, n); err != nil && firstErr == nil {
			firstErr = err
		}
	}
	return firstErr
}
