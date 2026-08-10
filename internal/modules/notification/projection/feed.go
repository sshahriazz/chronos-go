// Package projection builds the notification module's read models.
//
// Both projections here are rebuildable from position zero, which is the whole
// reason the in-app channel appends an event rather than writing a row: the feed
// and the subscription list are DERIVED, and anything derived can be recomputed
// when its shape changes (ADR-019).
package projection

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
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

	projection.On[contract.NotificationCreated](d, func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.NotificationCreated,
	) error {
		data, err := json.Marshal(e.Data)
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

	projection.On[contract.NotificationRead](d, func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.NotificationRead,
	) error {
		// COALESCE keeps the FIRST read time. Reading something twice does not
		// move when you first saw it, and alert arbitration asks exactly that
		// question — whether it was read within the window (ADR-026).
		w.Exec(notificationdb.MarkFeedItemRead,
			e.NotificationID, e.ReadAt)
		return nil
	})

	return &Feed{dispatch: d}
}

func (f *Feed) Name() string { return FeedName }

// Filter narrows to this module's own streams. One category, so a rebuild reads
// the category stream instead of scanning the whole log (measured 14.8x).
func (f *Feed) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"notification-"}}
}

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

	payload, err := json.Marshal(feedAnnouncement{
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
