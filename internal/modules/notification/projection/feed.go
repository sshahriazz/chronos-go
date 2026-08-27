// Package projection builds the notification module's read models.
//
// Both projections here are rebuildable from position zero, which is the whole
// reason the in-app channel appends an event rather than writing a row: the feed
// and the subscription list are DERIVED, and anything derived can be recomputed
// when its shape changes (ADR-019).
package projection

import (
	"context"
	"fmt"
	"time"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"

	// Aliased: every projection constructor in this module takes a parameter
	// named `codec` for the event codec, which would shadow the package inside
	// the handler bodies below.
	jsoncodec "github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/chronos/chronos-go/internal/platform/realtime"
)

// FeedName is the projection's permanent identity: it keys the checkpoint row
// and the single-writer lease, so renaming it silently restarts from zero.
const FeedName = "notification_feed"

// Feed builds the in-app list and the unread count.
type Feed struct{ dispatch *projection.Dispatch }

var (
	_ projection.Projection = (*Feed)(nil)
	_ projection.Emitter    = (*Feed)(nil)
)

func NewFeed(codec eventsourcing.Codec) *Feed {
	d := projection.NewDispatch(codec)

	d.On[contract.NotificationCreated](func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.NotificationCreated,
	) error {
		// No NullEmpty, deliberately. A notification with no template data has
		// e.Data nil, which v1 wrote as JSON `null` — into a column declared
		// `jsonb NOT NULL DEFAULT '{}'`. The v2 shape, `{}`, is the one the
		// schema already calls "no data", so a row inserted here and a row that
		// took the default finally agree, and `data->>'x'` behaves the same on
		// both. The table is rebuildable from position zero, so old `null` rows
		// converge on the next rebuild rather than needing a migration.
		data, err := jsoncodec.Marshal(e.Data)
		if err != nil {
			// Template input that will not serialise is a bug in whatever
			// raised the notification, and it can never become serialisable.
			return fmt.Errorf("notification feed: encoding data for %s: %w", e.NotificationID, err)
		}

		// Upsert, not insert. A projector is replayed on restart and on
		// rebuild, so the same event WILL arrive twice; an insert would fail
		// the second time and stall the projection permanently.
		//
		// read_at is deliberately NOT touched on conflict: a replay must not
		// mark a read notification unread again.
		// Queued, not executed: the projector sends one pipelined round trip
		// per event. The SQL is authored in db/query/notification/feed.sql and
		// checked against the real schema by sqlc (CONVENTIONS §8).
		w.Exec(notificationdb.UpsertFeedItem,
			e.NotificationID, e.SubjectID, e.OrgID, e.WorkspaceID,
			e.Template, e.Class, data, e.OccurredAt)
		return nil
	})

	d.On[contract.NotificationRead](func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.NotificationRead,
	) error {
		// COALESCE keeps the FIRST read time. Reading something twice does not
		// move when you first saw it, and alert arbitration asks exactly that
		// question — whether it was read within the window (ADR-026).
		//
		// The SUBJECT is passed as well as the id, and the statement matches on
		// both. A notification id is a stream name, and a stream name is not a
		// capability: an event carrying somebody else's notification id would
		// otherwise dismiss the alert on their screen from here, with no error
		// and no log line. The API refuses such an id before it appends; this is
		// the half that still holds for an event that was forged, replayed, or
		// written before that check existed.
		w.Exec(notificationdb.MarkFeedItemRead,
			e.NotificationID, e.ReadAt, e.SubjectID)
		return nil
	})

	// AN ERASED ACCOUNT LOSES ITS FEED, and this is where it happens.
	//
	// `notification_feed` holds `template` and an unvalidated `data` jsonb, and
	// that jsonb carries free text the person typed — `identity.new_device` puts
	// the device name they chose into it (cmd/worker/events.go). None of it is a
	// vault reference, so destroying the subject's key leaves every word of it
	// readable (ADR-002 reaches what the vault holds, and nothing else).
	//
	// See onUserErased for why this belongs in the projection rather than in an
	// erasure use case, and why the scope statement it queues first is needed at
	// all.
	onUserErased(d, notificationdb.DeleteFeedOfSubject)

	return &Feed{dispatch: d}
}

func (f *Feed) Name() string { return FeedName }

// Filter is this module's shared subscription: its own events, plus the erasure
// that empties this table. See subscription() for what selecting on event types
// costs a rebuild, and why no filter can avoid it.
func (f *Feed) Filter() eventsourcing.SubscriptionFilter { return subscription() }

// Handles reports whether this projection has a handler for an event type. It
// exists so a test can assert that the filter above actually delivers everything
// registered below it — a handler for an event the subscription never carries is
// indistinguishable from no handler at all.
func (f *Feed) Handles(eventType string) bool { return f.dispatch.Handles(eventType) }

func (f *Feed) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return f.dispatch.Apply(ctx, w, env)
}

func (f *Feed) Reset(ctx context.Context, q db.Querier) error {
	// TRUNCATE, because a rebuild runs in an unscoped system transaction where
	// RLS hides every row and DELETE would remove none (ADR-019).
	_, err := q.Exec(ctx, notificationdb.TruncateFeed)
	return err
}

// Emit announces a new feed item to the recipient's browser.
//
// A POINTER, not the notification: the id, its template and its class, and
// nothing else. Two reasons. A realtime payload passes through infrastructure we
// do not control and may sit in channel history, so it must carry no personal
// data (ADR-002). And a browser that missed the message must be able to recover
// by reading the feed — which it can only do if the feed, not the message, is
// the record.
//
// Only NotificationCreated announces. A read event is the browser telling US
// something; echoing it back would make a second tab mark itself read from a
// message it caused.
func (f *Feed) Emit(env projection.Envelope) []realtime.Message {
	if env.Type != (&contract.NotificationCreated{}).EventType() {
		return nil
	}
	e, err := f.dispatch.Decode(env)
	if err != nil {
		return nil
	}
	created, ok := e.(*contract.NotificationCreated)
	if !ok || created.SubjectID == "" {
		return nil
	}

	// Every field is a string, so the v2 nil-slice change cannot alter what
	// Centrifugo forwards to a browser; no NullEmpty is needed to keep this
	// third-party wire shape stable.
	payload, err := jsoncodec.Marshal(feedAnnouncement{
		Type:           "notification.created",
		NotificationID: created.NotificationID,
		Template:       created.Template,
		Class:          created.Class,
		OccurredAt:     created.OccurredAt.UTC().Format(time.RFC3339),
	})
	if err != nil {
		return nil
	}

	return []realtime.Message{{
		Channel: realtime.UserChannel(created.SubjectID),
		Type:    "notification.created",
		Data:    payload,
		// The notification id, so a redelivered event does not produce a second
		// toast for the same notification.
		IdempotencyKey: created.NotificationID,
	}}
}

// feedAnnouncement is the wire shape. A closed struct, not a map: a map would
// let someone add the recipient's name, and this payload leaves our control.
type feedAnnouncement struct {
	Type           string `json:"type"`
	NotificationID string `json:"notificationId"`
	Template       string `json:"template"`
	Class          string `json:"class"`
	OccurredAt     string `json:"occurredAt"`
}
