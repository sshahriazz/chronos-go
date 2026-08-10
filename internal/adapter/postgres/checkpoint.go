package postgres

import (
	"context"
	"errors"
	"fmt"
	"math"

	platformdb "github.com/chronos/chronos-go/gen/sqlc/platform"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/jackc/pgx/v5"
)

// Checkpoints stores projector positions in projection_checkpoint.
//
// It is stateless: every method takes the caller's Querier, because the
// checkpoint must commit in the same transaction as the rows it describes. A
// store that held its own pool could not promise that, so it does not hold one.
type Checkpoints struct{}

var _ projection.Checkpoints = Checkpoints{}

func (Checkpoints) Load(ctx context.Context, q db.Querier, name string) (projection.Checkpoint, error) {
	var commit, prepare, processed int64
	err := q.QueryRow(ctx, platformdb.LoadCheckpoint, name).Scan(&commit, &prepare, &processed)
	if errors.Is(err, pgx.ErrNoRows) {
		return projection.Checkpoint{}, projection.ErrNoCheckpoint
	}
	if err != nil {
		return projection.Checkpoint{}, fmt.Errorf("postgres: loading checkpoint %q: %w", name, err)
	}
	return projection.Checkpoint{
		Position: eventsourcing.Position{
			Commit:  uint64(commit),  //nolint:gosec // written by toBigint, never negative
			Prepare: uint64(prepare), //nolint:gosec // written by toBigint, never negative
		},
		EventsProcessed: processed,
	}, nil
}

// Save queues the position into the caller's batch, so it commits with the rows
// it describes and costs no extra round trip.
//
// It cannot fail: queueing is not executing. A malformed statement or a
// constraint violation surfaces when the batch is sent, which is also the point
// at which the projected rows would be rolled back with it.
func (Checkpoints) Save(
	_ context.Context, w db.Writer, name string, c projection.Checkpoint, holder string,
) {
	w.Exec(platformdb.SaveCheckpoint,
		name, toBigint(c.Position.Commit), toBigint(c.Position.Prepare), c.EventsProcessed, holder)
}

// Clear removes the checkpoint so the projector restarts from the beginning of
// the log. Called only from a rebuild, in the same transaction that empties the
// projection's tables.
func (Checkpoints) Clear(ctx context.Context, q db.Querier, name string) error {
	if _, err := q.Exec(ctx, platformdb.ClearCheckpoint, name); err != nil {
		return fmt.Errorf("postgres: clearing checkpoint %q: %w", name, err)
	}
	return nil
}

// toBigint narrows KurrentDB's uint64 position to Postgres' signed bigint.
// Saturating beats a silent wrap to a negative position, which would make a
// projector restart from the beginning of the log without saying why. A commit
// position past 2^63 is not physically reachable.
func toBigint(n uint64) int64 {
	if n > uint64(math.MaxInt64) {
		return math.MaxInt64
	}
	return int64(n)
}
