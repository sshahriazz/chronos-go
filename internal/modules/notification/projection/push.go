package projection

import (
	"context"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// PushName is permanent: it keys the checkpoint and the single-writer lease.
const PushName = "notification_push_subscriptions"

// PushSubscriptions tracks which browser endpoints are live.
//
// Separate from the feed rather than folded into it, because the two are read on
// entirely different paths — the feed on every page load, this only when a push
// is being sent — and one projection per table keeps rebuild order defined
// (CONVENTIONS §8).
type PushSubscriptions struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*PushSubscriptions)(nil)

func NewPushSubscriptions(codec eventsourcing.Codec) *PushSubscriptions {
	d := projection.NewDispatch(codec)

	projection.On[contract.PushSubscribed](d, func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.PushSubscribed,
	) error {
		// Conflict on (org_id, endpoint), not the id: the same browser
		// re-subscribing produces the same endpoint with a fresh id, and
		// inserting both would push to that device twice for every notification.
		//
		// Scoped to the organization, because one person belongs to several and
		// their browser has ONE endpoint across all of them. A global conflict
		// target made this upsert read a row RLS hides, so the second
		// organization's subscribe failed outright and that person received no
		// push there at all (migration 00006).
		//
		// Re-subscribing also revives an expired row: the person granted
		// permission again, and their earlier 410 is history.
		w.Exec(notificationdb.UpsertPushSubscription,
			e.SubscriptionID, e.SubjectID, env.Meta.OrgID, e.Endpoint,
			e.P256dh, e.Auth, e.UserAgent, e.SubscribedAt)
		return nil
	})

	projection.On[contract.PushSubscriptionExpired](d, func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.PushSubscriptionExpired,
	) error {
		// Marked expired, not deleted. "Why did I stop getting push?" is a real
		// support question, and a deleted row cannot answer it.
		//
		// COALESCE keeps the first expiry: a replay must not overwrite when a
		// device actually went away.
		w.Exec(notificationdb.ExpirePushSubscription,
			e.SubscriptionID, e.ExpiredAt, e.Reason)
		return nil
	})

	return &PushSubscriptions{dispatch: d}
}

func (p *PushSubscriptions) Name() string { return PushName }

func (p *PushSubscriptions) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"notification-"}}
}

func (p *PushSubscriptions) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return p.dispatch.Apply(ctx, w, env)
}

func (p *PushSubscriptions) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, notificationdb.TruncatePushSubscriptions)
	return err
}
