// Package postgres holds billing's idempotency boundary.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"

	billingdb "github.com/chronos/chronos-go/gen/sqlc/billing"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// EventLog records incoming Stripe webhooks, keyed by Stripe's own event id.
type EventLog struct{ tx db.SystemTX }

func NewEventLog(tx db.SystemTX) (*EventLog, error) {
	if tx == nil {
		return nil, fmt.Errorf("billing: a transaction source is required")
	}
	return &EventLog{tx: tx}, nil
}

// Claim records an event and reports whether this delivery should APPLY it.
//
// # Why the insert is the check
//
// `ON CONFLICT DO NOTHING ... RETURNING` is the whole mechanism: the first
// delivery inserts and gets a row back, every later one gets nothing. Reading
// first and inserting after would leave a window in which two concurrent
// deliveries both see "not seen" and both apply the change — and Stripe
// redelivers precisely when things are slow, which is when that window is
// widest.
//
// A row that exists but was never PROCESSED is claimable again. That is an
// earlier attempt which failed partway, and re-applying is safe because applying
// a subscription's current state is convergent.
func (l *EventLog) Claim(
	ctx context.Context, eventID, eventType string, payload []byte,
) (bool, error) {
	var claimed bool
	err := l.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var id string
		scanErr := q.QueryRow(ctx, billingdb.RecordWebhookEvent,
			eventID, eventType, payload).Scan(&id)
		switch {
		case scanErr == nil:
			claimed = true
			return nil
		case errors.Is(scanErr, pgx.ErrNoRows):
			var processed bool
			if err := q.QueryRow(ctx, billingdb.WebhookEventProcessed, eventID).
				Scan(&processed); err != nil {
				return err
			}
			claimed = !processed
			return nil
		default:
			return scanErr
		}
	})
	return claimed, err
}

// MarkProcessed records that the event has been applied.
func (l *EventLog) MarkProcessed(ctx context.Context, eventID string) error {
	return l.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, billingdb.MarkWebhookEventProcessed, eventID)
		return err
	})
}

// MarkFailed records why an event could not be applied, WITHOUT marking it
// processed, so a retry still applies it.
func (l *EventLog) MarkFailed(ctx context.Context, eventID string, cause error) error {
	return l.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, billingdb.MarkWebhookEventFailed, eventID, cause.Error())
		return err
	})
}
