package postgres_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// A truncated read of the sign-out-everywhere work list must be an ERROR.
//
// This is the failure `rows.Err()` exists for, and it was reported as untestable:
// provoking it against a real database needs the connection to die between rows.
// It does not need a real database. `db.Rows` is a four-method interface, so a
// fake that yields one row and then reports a failure drives exactly the state a
// dropped connection produces.
//
// It matters because the caller is `RevokeAllSessions`. A short list there is a
// PARTIAL sign-out reported as a complete one: the sessions that were not listed
// keep working, and the person who just changed their password after a compromise
// is told every device was signed out. That is the one answer this query may not
// give, and it is why the revocation itself is a single atomic append.
type truncatingRows struct {
	ids       []string
	i         int
	failAfter int
	err       error
}

func (r *truncatingRows) Next() bool {
	if r.i >= len(r.ids) || r.i >= r.failAfter {
		return false
	}
	r.i++
	return true
}

func (r *truncatingRows) Scan(dest ...any) error {
	if len(dest) != 1 {
		return errors.New("unexpected column count")
	}
	p, ok := dest[0].(*string)
	if !ok {
		return errors.New("unexpected destination type")
	}
	*p = r.ids[r.i-1]
	return nil
}

func (r *truncatingRows) Close()     {}
func (r *truncatingRows) Err() error { return r.err }

// queryingTX serves one prepared Rows to whatever asks.
type queryingTX struct{ rows db.Rows }

func (t *queryingTX) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return fn(ctx, t)
}
func (t *queryingTX) Exec(context.Context, string, ...any) (int64, error) { return 0, nil }
func (t *queryingTX) Query(context.Context, string, ...any) (db.Rows, error) {
	return t.rows, nil
}
func (t *queryingTX) QueryRow(context.Context, string, ...any) db.Row { return nil }

func TestATruncatedWorkListIsRefusedRatherThanSignedOutPartially(t *testing.T) {
	t.Parallel()

	live := []string{"sess_01KZY093ACBHWRJF7RKR1BTHET", "sess_01KZY093ACPV6XTPK2EKWBTPMN"}
	sessions, buildErr := identitypg.NewSessions(&queryingTX{rows: &truncatingRows{
		ids:       live,
		failAfter: 1, // one row arrives, then the connection dies
		err:       errors.New("unexpected EOF"),
	}})
	if buildErr != nil {
		t.Fatalf("building the adapter: %v", buildErr)
	}

	got, err := sessions.List(context.Background(), "sub_1", time.Now())
	if err == nil {
		t.Fatalf("a truncated read returned %d sessions and no error; the caller would "+
			"revoke those and report a complete sign-out", len(got))
	}
	if !strings.Contains(err.Error(), "unexpected EOF") {
		t.Errorf("the failure was reported as %q, losing the underlying cause", err)
	}
	if got != nil {
		t.Errorf("a failed read returned %d ids; a partial list must not reach the caller "+
			"at all, since nothing downstream can tell it apart from a complete one", len(got))
	}
}
