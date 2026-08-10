package postgres

import (
	"context"
	"errors"
	"fmt"

	platformdb "github.com/chronos/chronos-go/gen/sqlc/platform"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/reactor"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
)

// Dedup filters at-least-once redelivery for reactors.
//
// It holds the pool rather than taking a Querier, unlike Checkpoints: a
// reactor's effect is a network call to the outside world, so there is no
// transaction to enlist in and nothing to make atomic with it.
type Dedup struct{ db *DB }

var _ reactor.Dedup = (*Dedup)(nil)

func NewDedup(d *DB) *Dedup { return &Dedup{db: d} }

func (d *Dedup) Seen(ctx context.Context, name string, id ids.EventID) (bool, error) {
	var seen bool
	err := d.db.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		scanErr := q.QueryRow(ctx, platformdb.HasReactorProcessed,
			name, uuid.UUID(id.Bytes())).Scan(&seen)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			seen = false
			return nil
		}
		return scanErr
	})
	if err != nil {
		return false, fmt.Errorf("postgres: reading dedup for %s: %w", name, err)
	}
	return seen, nil
}

// MarkSeen records the event as handled.
//
// ON CONFLICT DO NOTHING because two consumers racing on the same redelivered
// event is normal for a competing-consumer group, and neither should fail.
func (d *Dedup) MarkSeen(ctx context.Context, name string, id ids.EventID) error {
	err := d.db.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, execErr := q.Exec(ctx, platformdb.MarkReactorProcessed,
			name, uuid.UUID(id.Bytes()))
		return execErr
	})
	if err != nil {
		return fmt.Errorf("postgres: recording dedup for %s: %w", name, err)
	}
	return nil
}

// Forget drops dedup rows older than the retention window.
//
// The table would otherwise grow forever. The window must comfortably exceed
// the longest possible redelivery gap — a parked event replayed weeks later
// must still be recognised — so it is measured in days, not hours.
func (d *Dedup) Forget(ctx context.Context, olderThanDays int) (int64, error) {
	var removed int64
	err := d.db.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, execErr := q.Exec(ctx, platformdb.ForgetProcessedBefore, olderThanDays)
		removed = n
		return execErr
	})
	if err != nil {
		return 0, fmt.Errorf("postgres: pruning dedup: %w", err)
	}
	return removed, nil
}
