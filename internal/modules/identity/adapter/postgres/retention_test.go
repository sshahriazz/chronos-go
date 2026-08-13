package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// fakeTX records what SQL was executed with which arguments, without a database.
//
// Untagged and infra-free deliberately: what is asserted here is that each method
// issues the GENERATED statement rather than something hand-written, and that the
// cutoff reaches the database at all. Neither needs Postgres, and both are the
// kind of thing that breaks silently — a statement swapped for its neighbour
// still compiles, still returns a row count, and still reports success.
type fakeTX struct {
	sql  []string
	args [][]any
	rows int64
	err  error
}

func (f *fakeTX) InSystemTx(ctx context.Context, fn func(context.Context, db.Querier) error) error {
	return fn(ctx, f)
}

func (f *fakeTX) Exec(_ context.Context, sql string, args ...any) (int64, error) {
	f.sql = append(f.sql, sql)
	f.args = append(f.args, args)
	if f.err != nil {
		return 0, f.err
	}
	return f.rows, nil
}

func (f *fakeTX) Query(context.Context, string, ...any) (db.Rows, error) {
	return nil, errors.New("not used")
}

func (f *fakeTX) QueryRow(context.Context, string, ...any) db.Row {
	return nil
}

var cutoff = time.Date(2026, 5, 15, 12, 0, 0, 0, time.UTC)

func newRetention(t *testing.T, tx db.SystemTX) *identitypg.Retention {
	t.Helper()
	r, err := identitypg.NewRetention(tx)
	if err != nil {
		t.Fatalf("building retention: %v", err)
	}
	return r
}

// Each method must issue its OWN generated statement. Two of these delete secret
// material and two delete projections; a statement wired to the wrong method is a
// silent mis-deletion that still reports a row count.
func TestEachRetentionMethodIssuesItsOwnStatement(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*identitypg.Retention) (int64, error)
		want string
	}{
		{"totp replay", func(r *identitypg.Retention) (int64, error) {
			return r.SweepTOTPReplay(context.Background())
		}, identitydb.SweepTOTPReplay},
		{"tokens", func(r *identitypg.Retention) (int64, error) {
			return r.SweepTokens(context.Background())
		}, identitydb.SweepTokens},
		{"session tokens", func(r *identitypg.Retention) (int64, error) {
			return r.SweepSessionTokens(context.Background())
		}, identitydb.SweepSessionTokens},
		{"session views", func(r *identitypg.Retention) (int64, error) {
			return r.SweepExpiredSessionViews(context.Background(), cutoff)
		}, identitydb.SweepExpiredSessionViews},
		{"released reservations", func(r *identitypg.Retention) (int64, error) {
			return r.DeleteReleasedReservations(context.Background(), cutoff)
		}, identitydb.DeleteReleasedReservations},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeTX{rows: 7}
			got, err := tc.run(newRetention(t, tx))
			if err != nil {
				t.Fatalf("running: %v", err)
			}
			if got != 7 {
				t.Errorf("reported %d rows, want the affected-row count 7", got)
			}
			if len(tx.sql) != 1 {
				t.Fatalf("issued %d statements, want exactly 1", len(tx.sql))
			}
			if tx.sql[0] != tc.want {
				t.Errorf("issued the wrong statement:\n got %q\nwant %q", tx.sql[0], tc.want)
			}
		})
	}
}

// The cutoff must reach the database, in UTC. A statement that dropped it would
// delete against whatever the SQL's own default is — or nothing at all — while
// still reporting a perfectly healthy row count.
func TestTheCutoffReachesTheStatement(t *testing.T) {
	local := cutoff.In(time.FixedZone("well-east", 11*3600))

	for _, tc := range []struct {
		name string
		run  func(*identitypg.Retention, time.Time) (int64, error)
	}{
		{"session views", func(r *identitypg.Retention, c time.Time) (int64, error) {
			return r.SweepExpiredSessionViews(context.Background(), c)
		}},
		{"released reservations", func(r *identitypg.Retention, c time.Time) (int64, error) {
			return r.DeleteReleasedReservations(context.Background(), c)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeTX{}
			if _, err := tc.run(newRetention(t, tx), local); err != nil {
				t.Fatalf("running: %v", err)
			}
			if len(tx.args) != 1 || len(tx.args[0]) != 1 {
				t.Fatalf("the statement was issued with %v, want exactly one argument", tx.args)
			}
			got, ok := tx.args[0][0].(time.Time)
			if !ok {
				t.Fatalf("the cutoff reached the database as %T, not a time", tx.args[0][0])
			}
			if !got.Equal(cutoff) {
				t.Errorf("cutoff = %s, want %s", got, cutoff)
			}
			if got.Location() != time.UTC {
				t.Errorf("the cutoff was sent in %s; all times are UTC in storage", got.Location())
			}
		})
	}
}

// A zero cutoff must be refused BEFORE the statement runs. Passed through, it
// compares against year 1: nothing matches, the DELETE succeeds, zero rows are
// reported — retention that has silently stopped, wearing the exact signature of
// retention with nothing to do.
func TestAZeroCutoffIsRefusedWithoutRunningAnything(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(*identitypg.Retention) (int64, error)
	}{
		{"session views", func(r *identitypg.Retention) (int64, error) {
			return r.SweepExpiredSessionViews(context.Background(), time.Time{})
		}},
		{"released reservations", func(r *identitypg.Retention) (int64, error) {
			return r.DeleteReleasedReservations(context.Background(), time.Time{})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			tx := &fakeTX{}
			if _, err := tc.run(newRetention(t, tx)); err == nil {
				t.Error("a zero cutoff was accepted, so this deletes nothing and reports success")
			}
			if len(tx.sql) != 0 {
				t.Errorf("a statement ran with a zero cutoff: %v", tx.sql)
			}
		})
	}
}

// A failing statement must surface as an error rather than as a zero count. Zero
// is the normal steady state for most of these, so an error swallowed into one is
// invisible.
func TestAFailingStatementIsReportedRatherThanCountedAsZero(t *testing.T) {
	tx := &fakeTX{err: errors.New("permission denied for table totp_replay")}
	if _, err := newRetention(t, tx).SweepTOTPReplay(context.Background()); err == nil {
		t.Fatal("a failing statement reported success")
	}
}

// Retention with no transaction cannot run a single statement, so it must refuse
// to be built rather than fail one run at a time.
func TestRetentionRefusesToBeBuiltWithoutASystemTransaction(t *testing.T) {
	if _, err := identitypg.NewRetention(nil); err == nil {
		t.Fatal("retention was built with no system transaction")
	}
}
