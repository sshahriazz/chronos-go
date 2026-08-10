// Package postgres reads the notification module's projections.
//
// Read-only, by design. Nothing here writes: the feed and the subscription list
// are projections, filled by their projectors from the log (ADR-019). The one
// apparent exception, Retire, appends an EVENT — it does not touch the table.
package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/adapter/webpush"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/notify"
	pgxv5 "github.com/jackc/pgx/v5"
)

// Reader answers the questions the notification channels ask.
type Reader struct {
	tx    db.SystemTX
	scope Scoper
	store eventsourcing.EventStore
	clock clock.Clock
}

// Scoper applies a tenant scope inside an open transaction.
//
// Injected rather than implemented here: SET LOCAL is kernel plumbing that the
// postgres adapter already owns, and a second copy in every module is exactly
// the duplication that lets one of them drift.
type Scoper func(ctx context.Context, q db.Querier, orgID string) error

func NewReader(tx db.SystemTX, scope Scoper, store eventsourcing.EventStore, clk clock.Clock) *Reader {
	if clk == nil {
		clk = clock.System{}
	}
	return &Reader{tx: tx, scope: scope, store: store, clock: clk}
}

var (
	_ webpush.Subscriptions = (*Reader)(nil)
	_ notify.ReadState      = (*Reader)(nil)
	_ notify.Preferences    = (*Reader)(nil)
)

// scoped runs a read under the tenant scope of an org.
//
// A reactor has no ambient request scope — it is reacting to an event, not
// serving a user — so the scope comes from the event and is applied explicitly.
func (r *Reader) scoped(ctx context.Context, orgID string, fn func(context.Context, db.Querier) error) error {
	return r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if orgID != "" && r.scope != nil {
			if err := r.scope(ctx, q, orgID); err != nil {
				return err
			}
		}
		return fn(ctx, q)
	})
}

// Active lists a subject's live push endpoints.
//
// Expired rows are excluded rather than deleted: "why did I stop getting push?"
// is a real support question, and a deleted row cannot answer it.
func (r *Reader) Active(ctx context.Context, orgID, subjectID string) ([]webpush.Subscription, error) {
	var out []webpush.Subscription

	err := r.scoped(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, notificationdb.ListActivePushSubscriptions, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var s webpush.Subscription
			if err := rows.Scan(&s.ID, &s.SubjectID, &s.Endpoint, &s.P256dh, &s.Auth); err != nil {
				return err
			}
			out = append(out, s)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("notification: reading push subscriptions: %w", err)
	}
	return out, nil
}

// Retire records that a push service rejected an endpoint.
//
// It appends an EVENT rather than updating the table: the subscription's life is
// history, and the projection follows. Writing the row here would put a second
// writer on a projected table and make it unrebuildable.
func (r *Reader) Retire(ctx context.Context, orgID string, sub webpush.Subscription, reason string) error {
	stream, err := eventsourcing.NewStreamID("notification", sub.ID)
	if err != nil {
		return fmt.Errorf("notification: stream id: %w", err)
	}
	now := r.clock.Now().UTC()

	// Any revision: a subscription may already have events, and retiring is not
	// a decision that depends on what came before.
	_, err = r.store.Append(ctx, stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			// Deterministic in the subscription and the reason, so a redelivery
			// collapses into the existing event rather than expiring twice.
			ID: eventsourcing.DeriveEventID("expire:"+sub.ID+":"+reason, 0),
			Event: &contract.PushSubscriptionExpired{
				SubscriptionID: sub.ID,
				SubjectID:      sub.SubjectID,
				Reason:         reason,
				ExpiredAt:      now,
			},
			Meta: eventsourcing.Metadata{
				SchemaVersion: 1,
				OccurredAt:    now,
				OrgID:         orgID,
				SubjectIDs:    []string{sub.SubjectID},
			},
		}})
	if err != nil {
		return fmt.Errorf("notification: recording expired subscription: %w", err)
	}
	return nil
}

// ReadWithin answers the arbitration question: was this seen in-app already?
//
// Only Activity notifications ask it. A missing row means unread, which is the
// safe answer — it sends the email rather than suppressing it (ADR-026).
func (r *Reader) ReadWithin(
	ctx context.Context, orgID, subjectID, key string, window time.Duration,
) (bool, error) {
	var read bool

	err := r.scoped(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, notificationdb.WasReadWithin,
			subjectID, key, window.String()).Scan(&read)
		if errors.Is(scanErr, pgxv5.ErrNoRows) {
			read = false
			return nil
		}
		return scanErr
	})
	if err != nil {
		return false, fmt.Errorf("notification: reading read-state: %w", err)
	}
	return read, nil
}

// Enabled reports whether a subject wants a channel.
//
// ABSENCE MEANS ENABLED. Someone who has never opened the settings screen still
// receives their notifications, and a row exists only where they switched
// something off — so a failure to write a default cannot silence anyone.
//
// This is consulted only for Activity and Product notifications; the dispatcher
// checks class first, so no preference can reach a security alert
// (notification.md §6).
func (r *Reader) Enabled(
	ctx context.Context, orgID, subjectID, _ string, ch notify.Channel,
) (bool, error) {
	enabled := true

	err := r.scoped(ctx, orgID, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, notificationdb.IsChannelEnabled,
			subjectID, string(ch)).Scan(&enabled)
		if errors.Is(scanErr, pgxv5.ErrNoRows) {
			enabled = true
			return nil
		}
		return scanErr
	})
	if err != nil {
		return false, fmt.Errorf("notification: reading preference: %w", err)
	}
	return enabled, nil
}
