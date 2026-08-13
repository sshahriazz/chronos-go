package inapp_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/inapp"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// The feed is a PROJECTION (notification.md §11). Delivering in-app therefore
// appends an event; writing the table here would make the feed unrebuildable,
// which is the property that makes a read model safe to change.
func TestDeliveryAppendsAnEventRatherThanWritingARow(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.NewFixed(time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC)), nil)

	err := tr.Deliver(context.Background(), notification())
	if err != nil {
		t.Fatalf("deliver: %v", err)
	}
	if len(store.appended) != 1 {
		t.Fatalf("appended %d events, want 1", len(store.appended))
	}
	got := store.appended[0]
	if got.Event.EventType() != "notification.Created.v1" {
		t.Errorf("event type %q", got.Event.EventType())
	}
	// One stream per notification: a user's feed is unbounded, and an unbounded
	// aggregate stream eventually cannot be loaded.
	if !strings.HasPrefix(string(got.Stream), "notification-notif_") {
		t.Errorf("stream %q should be one per notification", got.Stream)
	}
	if !got.Expected.IsNoStream() {
		t.Error("a new feed item must be appended with a NoStream precondition")
	}
}

// Personal data never enters an event (ADR-002). The name and address are
// resolved by whoever renders, from the vault.
func TestFeedItemCarriesNoPersonalData(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.System{}, nil)

	n := notification()
	n.Recipient.Address = "sam.larsson@example.test"
	n.Recipient.Name = "Sam Larsson"
	if err := tr.Deliver(context.Background(), n); err != nil {
		t.Fatal(err)
	}

	encoded, err := codec.Marshal(store.appended[0].Event)
	if err != nil {
		t.Fatal(err)
	}
	for _, forbidden := range []string{"sam.larsson@example.test", "Sam Larsson"} {
		if strings.Contains(string(encoded), forbidden) {
			t.Errorf("the feed event contains %q; the log is immutable and erasure "+
				"works by destroying a key, not by rewriting history:\n%s", forbidden, encoded)
		}
	}
	if !strings.Contains(string(encoded), "sub_1") {
		t.Error("the subject pseudonym should be present — it is what the vault resolves")
	}
}

// A redelivered source event must not create a second feed item.
func TestRedeliveryProducesTheSameEventID(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.System{}, nil)

	if err := tr.Deliver(context.Background(), notification()); err != nil {
		t.Fatal(err)
	}
	if err := tr.Deliver(context.Background(), notification()); err != nil {
		t.Fatal(err)
	}
	if len(store.appended) != 2 {
		t.Fatalf("expected two append attempts, got %d", len(store.appended))
	}
	if store.appended[0].ID != store.appended[1].ID {
		t.Fatal("a redelivered event produced a different event id, so the store " +
			"cannot collapse the duplicate and the user sees the notification twice")
	}
}

// The feed is an org-scoped read model like every other one (ADR-020), so a
// notification with no organization has nowhere to live under RLS. In practice
// that is a notification raised before someone belongs to an org — registration,
// a reset from the sign-in screen — which reaches them by email, the durable
// record anyway (NOTIFICATIONS §4).
func TestNotificationWithoutAnOrgHasNoFeedItem(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.System{}, nil)

	n := notification()
	n.OrgID = ""
	err := tr.Deliver(context.Background(), n)
	if !errors.Is(err, notify.ErrNoAddress) {
		t.Fatalf("expected the in-app channel to report nowhere to deliver, got %v", err)
	}
	if len(store.appended) != 0 {
		t.Fatal("wrote a feed row with no organization; RLS has nothing to scope it by")
	}
}

// The org and workspace must reach the event, or the projected row cannot
// satisfy the RLS policy on notification_feed.
func TestFeedItemCarriesTheTenantScope(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.System{}, nil)

	if err := tr.Deliver(context.Background(), notification()); err != nil {
		t.Fatal(err)
	}
	encoded, _ := codec.Marshal(store.appended[0].Event)
	if !strings.Contains(string(encoded), "org_1") {
		t.Errorf("the feed event lost its org, so the projected row cannot pass RLS:\n%s", encoded)
	}
}

// Operators are not users of the product and have no feed.
func TestOperatorNotificationHasNoFeed(t *testing.T) {
	store := &fakeStore{}
	tr := inapp.New(store, clock.System{}, nil)

	err := tr.Deliver(context.Background(), notify.Notification{
		Template:  "operator.alert",
		Class:     notify.Operator,
		Recipient: notify.Recipient{Address: "ops@chronos.test"},
	})
	if err == nil {
		t.Fatal("an operator alert has no tenant subject and therefore no feed item")
	}
	if len(store.appended) != 0 {
		t.Fatal("wrote a feed item for an operator alert")
	}
}

func notification() notify.Notification {
	return notify.Notification{
		Template:       "identity.password_changed",
		Class:          notify.Security,
		Recipient:      notify.Recipient{SubjectID: "sub_1"},
		OrgID:          "org_1",
		WorkspaceID:    "ws_1",
		Data:           map[string]any{"Device": "Firefox"},
		OccurredAt:     time.Date(2026, 3, 14, 9, 26, 0, 0, time.UTC),
		IdempotencyKey: "evt_1:0",
	}
}

type appended struct {
	Stream   eventsourcing.StreamID
	Expected eventsourcing.ExpectedRevision
	ID       string
	Event    eventsourcing.Event
}

type fakeStore struct{ appended []appended }

func (f *fakeStore) Append(
	_ context.Context, stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision, events []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	for _, e := range events {
		f.appended = append(f.appended, appended{
			Stream: stream, Expected: expected, ID: e.ID.String(), Event: e.Event,
		})
	}
	return eventsourcing.AppendResult{}, nil
}

func (f *fakeStore) ReadStream(
	context.Context, eventsourcing.StreamID, eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	return nil, eventsourcing.ErrStreamNotFound
}
