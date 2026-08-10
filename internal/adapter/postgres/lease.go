package postgres

import (
	"context"
	"fmt"
	"hash/fnv"
	"sync"

	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Lease is single-writer mutual exclusion built on Postgres session-level
// advisory locks.
//
// Advisory locks rather than a row with an expiry, because the lock is bound to
// the CONNECTION: if the holder crashes, is paused, or is partitioned away, the
// server drops the connection and the lock goes with it. A lease table needs a
// heartbeat, a clock both sides agree on, and a fencing token to be correct, and
// gets all three wrong under GC pause. This gets failover for free and cannot
// hand the lock to two holders at once.
//
// The cost is one pooled connection held for as long as the lease is: session
// scope is the point, so it cannot be borrowed back mid-lease.
type Lease struct {
	pool *pgxpool.Pool
}

var _ projection.Lease = (*Lease)(nil)

func NewLease(pool *pgxpool.Pool) *Lease { return &Lease{pool: pool} }

// Acquire takes the lock for name, or reports held=false immediately.
//
// pg_try_advisory_lock never waits. A projector that cannot get the lease is
// not queuing behind the current holder — it is a standby, and it retries.
func (l *Lease) Acquire(ctx context.Context, name string) (projection.Release, bool, error) {
	key := leaseKey(name)

	conn, err := l.pool.Acquire(ctx)
	if err != nil {
		return nil, false, fmt.Errorf("postgres: acquiring connection for lease %q: %w", name, err)
	}

	var got bool
	if err := conn.QueryRow(ctx, `SELECT pg_try_advisory_lock($1)`, key).Scan(&got); err != nil {
		conn.Release()
		return nil, false, fmt.Errorf("postgres: lease %q: %w", name, err)
	}
	if !got {
		conn.Release()
		return nil, false, nil
	}

	// sync.Once, not a bool: Run releases inline while Rebuild releases from a
	// defer, and advisory locks are COUNTED per session — a second unlock would
	// surrender a lock this process may have legitimately re-acquired, letting
	// two writers into the same projection.
	var once sync.Once
	return func(ctx context.Context) {
		once.Do(func() { release(ctx, conn, key) })
	}, true, nil
}

func release(ctx context.Context, conn *pgxpool.Conn, key int64) {
	defer conn.Release()
	// Best effort. If this fails the connection is going back to the pool
	// holding a lock nobody will release, so it is destroyed instead: closing
	// it makes the server drop the lock for us.
	if _, err := conn.Exec(ctx, `SELECT pg_advisory_unlock($1)`, key); err != nil {
		_ = conn.Conn().Close(ctx)
	}
}

// leaseKey maps a projection name to the bigint advisory locks take.
//
// FNV-1a, not a random hash: the value must be identical in every process and
// across restarts, or two instances take different locks and both believe they
// are the single writer. Go's map hash is seeded per process and would do
// exactly that.
func leaseKey(name string) int64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte("chronos.projection."))
	_, _ = h.Write([]byte(name))
	return int64(h.Sum64()) //nolint:gosec // advisory lock keys are opaque; wrap is fine
}
