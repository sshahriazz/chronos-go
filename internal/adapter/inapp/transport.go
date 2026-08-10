// Package inapp is the in-app feed channel of the notification system.
//
// "Delivering" in-app means APPENDING AN EVENT, not writing a row. The feed is a
// projection (notification.md §11), so writing the table here would break the
// rule that every projected row is reconstructable by replaying the log, and
// would leave the feed unrebuildable — precisely the property that makes a read
// model safe to change.
//
// The browser learns about it through the feed projection's realtime publish,
// not from here: a transport that also published would double-notify.
package inapp

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// Transport records notifications as feed items.
type Transport struct {
	store eventsourcing.EventStore
	clock clock.Clock
	obs   Observer
}

// Observer records outcomes for metrics. Optional.
type Observer interface {
	Created(template, class string)
	Failed(template, class string)
}

type noObserver struct{}

func (noObserver) Created(string, string) {}
func (noObserver) Failed(string, string)  {}

func New(store eventsourcing.EventStore, clk clock.Clock, obs Observer) *Transport {
	if clk == nil {
		clk = clock.System{}
	}
	if obs == nil {
		obs = noObserver{}
	}
	return &Transport{store: store, clock: clk, obs: obs}
}

var _ notify.Transport = (*Transport)(nil)

func (t *Transport) Channel() notify.Channel { return notify.ChannelInApp }

// Deliver appends the feed item.
//
// One stream per notification rather than one per user: a user's feed is
// unbounded, and an unbounded aggregate stream is one that eventually cannot be
// loaded. Per-notification streams stay tiny, and the FEED is assembled by the
// projection — which is what projections are for.
func (t *Transport) Deliver(ctx context.Context, n notify.Notification) error {
	if n.Recipient.SubjectID == "" {
		// Operator alerts have no tenant subject and therefore no feed. That is
		// correct, not a failure: operators are not users of the product.
		return fmt.Errorf("%w: in-app delivery needs a subject", notify.ErrNoAddress)
	}
	if n.OrgID == "" {
		// The feed is an org-scoped read model like every other one (ADR-020),
		// so a row with no org has nowhere to live under RLS.
		//
		// In practice this covers notifications raised before someone belongs
		// to an organization — registration, a password reset from the sign-in
		// screen. Those are Security or Transactional class and reach the
		// person by email, which is the durable record anyway
		// (NOTIFICATIONS §4). Worth revisiting if identity ever needs a
		// pre-organization feed.
		return fmt.Errorf("%w: in-app delivery needs an organization scope", notify.ErrNoAddress)
	}

	notificationID := ids.New[ids.Notification](t.clock.Now(), ids.Entropy())
	stream, err := eventsourcing.NewStreamID("notification", notificationID.String())
	if err != nil {
		return fmt.Errorf("inapp: stream id: %w", err)
	}

	occurred := n.OccurredAt
	if occurred.IsZero() {
		occurred = t.clock.Now()
	}

	event := &contract.NotificationCreated{
		NotificationID: notificationID.String(),
		SubjectID:      n.Recipient.SubjectID,
		Template:       n.Template,
		Class:          n.Class.String(),
		OrgID:          n.OrgID,
		WorkspaceID:    n.WorkspaceID,
		Data:           n.Data,
		OccurredAt:     occurred.UTC(),
	}

	// The idempotency key derives the event id, so a redelivered source event
	// produces a byte-identical id and the store collapses the duplicate itself
	// rather than creating a second feed item (EVENT-SOURCING §3).
	key := n.IdempotencyKey
	if key == "" {
		key = notificationID.String()
	}

	_, err = t.store.Append(ctx, stream, eventsourcing.NoStream(),
		[]eventsourcing.PendingEvent{{
			ID:    eventsourcing.DeriveEventID(key, 0),
			Event: event,
			Meta: eventsourcing.Metadata{
				SchemaVersion: 1,
				OccurredAt:    occurred.UTC(),
				OrgID:         n.OrgID,
				WorkspaceID:   n.WorkspaceID,
				SubjectIDs:    []string{n.Recipient.SubjectID},
				// Personal data never enters an event: the name and address
				// stay in the vault and are resolved by whoever renders
				// (ADR-002).
			},
		}})
	if err != nil {
		t.obs.Failed(n.Template, n.Class.String())
		return fmt.Errorf("inapp: appending feed item: %w", err)
	}

	t.obs.Created(n.Template, n.Class.String())
	return nil
}
