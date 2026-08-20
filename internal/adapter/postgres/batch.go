package postgres

import (
	"context"
	"fmt"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/jackc/pgx/v5"
)

var _ db.BatchTX = (*DB)(nil)

// InTenantBatch sends one unit of work as a single pipelined round trip.
//
// Every statement — the tenant scope, the caller's writes, whatever else is
// queued — travels in one packet with a single trailing Sync, which PostgreSQL
// executes as one implicit transaction. There is no BEGIN and no COMMIT to pay
// for, and no window in which some statements have run and others have not.
//
// Measured against the running server: 5 round trips → 1, and 299 µs → 139 µs
// per projected event with Replayable durability (ADR-019).
func (d *DB) InTenantBatch(
	ctx context.Context, t db.Tenant, durability db.Durability, fn func(db.Writer) error,
) error {
	w := &batchWriter{}

	// Transaction-local settings go first, so everything queued after them is
	// evaluated under the right tenant. set_config(..., true) is SET LOCAL in
	// function form, which lets the values be bound as parameters instead of
	// interpolated into SQL.
	settings, args := scopeStatement(t, durability)
	w.Exec(settings, args...)

	if err := fn(w); err != nil {
		return err
	}
	if w.batch.Len() == 0 {
		return nil
	}

	conn, err := d.pool.Acquire(ctx)
	if err != nil {
		return fmt.Errorf("postgres: acquiring connection for batch: %w", err)
	}
	defer conn.Release()

	res := conn.SendBatch(ctx, &w.batch)

	// Every queued statement must be drained, even after one fails: closing
	// early leaves results on the wire and poisons the connection for whoever
	// borrows it next.
	var first error
	var failed int
	for i := range w.sql {
		if _, err := res.Exec(); err != nil && first == nil {
			first, failed = err, i
		}
	}
	if err := res.Close(); err != nil && first == nil {
		first = err
	}
	if first != nil {
		// Typed, so a caller that queued several statements per unit of work can
		// map the index back to the unit that queued it. See
		// db.BatchStatementError: a projector that cannot do that names the
		// batch's last event, which is almost never the one that failed.
		return fmt.Errorf("postgres: %w", &db.BatchStatementError{
			Index: failed,
			Count: len(w.sql),
			SQL:   summarise(w.sql[failed]),
			Err:   first,
		})
	}
	return nil
}

// scopeStatement builds the single statement that establishes tenant scope and
// durability for the batch. One statement, because each one is a queue entry
// and there is no reason to spend two.
func scopeStatement(t db.Tenant, d db.Durability) (string, []any) {
	commit := "on"
	if d == db.Replayable {
		commit = "off"
	}
	if t.OrgID == "" {
		return `SELECT set_config('synchronous_commit', $1, true)`, []any{commit}
	}
	return `SELECT set_config('app.org_id',         $1, true),
	               set_config('app.workspace_id',   $2, true),
	               set_config('app.user_id',        $3, true),
	               set_config('app.residency',      $4, true),
	               set_config('synchronous_commit', $5, true)`,
		[]any{t.OrgID, t.WorkspaceID, t.UserID, t.Residency, commit}
}

// batchWriter queues statements. It keeps the SQL alongside pgx's batch purely
// so a failure can name which statement broke — without it, a batch error says
// only that something in the packet failed.
type batchWriter struct {
	batch pgx.Batch
	sql   []string
}

func (w *batchWriter) Exec(sql string, args ...any) {
	w.batch.Queue(sql, args...)
	w.sql = append(w.sql, sql)
}

// Queued reports the position the next statement will take, which is what a
// caller needs in order to record the range of statements one unit of work
// queued. It counts the scope statement this batch queued before the caller was
// handed the Writer, so the number is on the same scale as the index a
// db.BatchStatementError reports.
func (w *batchWriter) Queued() int { return len(w.sql) }

var _ db.StatementCounter = (*batchWriter)(nil)

// summarise reduces a statement to something readable in an error message.
func summarise(sql string) string {
	s := strings.Join(strings.Fields(sql), " ")
	const max = 80
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
