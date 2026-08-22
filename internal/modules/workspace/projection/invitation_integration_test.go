//go:build integration

package projection_test

import (
	"context"
	"os"
	"testing"
	"time"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The invitation projection's statements, run against the real schema.
//
// Asserted at this level rather than end to end because the property is a
// property of the STATEMENTS: it is about what a redelivered event does to a row
// a later event already moved, and reproducing that end to end would need a
// subscription to deliver out of order — which it does not, which is exactly why
// the bug was invisible.
func TestInvitationProjectionStatements(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)

	// invitation_view carries row security, so every statement below runs under
	// a scope. Connecting as chronos_app and forgetting the scope would make
	// every read return nothing and every assertion pass vacuously.
	orgID := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]

	scoped := func(t *testing.T, fn func(q *workspacedb.Queries)) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", orgID); err != nil {
			t.Fatalf("scope: %v", err)
		}
		fn(workspacedb.New(tx))
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	// A SETTLED INVITATION IS NOT RESURRECTED BY A REDELIVERED ISSUE.
	//
	// The upsert's conflict clause used to write `status = 'pending'` and
	// `settled_at = NULL`, because a replayed issue is byte-identical to the
	// first and overwriting looked free. It is not: status, settled_at and
	// expires_at are written by LATER events, so an issue that arrives again
	// after a settlement puts an accepted invitation back on the admin screen
	// and hands the expiry sweep a settled row to expire — releasing a seat the
	// new member is sitting in.
	//
	// It was safe only because a catch-up subscription happens to deliver in
	// order. That is a property of the subscription, not of this statement, and
	// nothing about at-least-once delivery promises it.
	t.Run("a redelivered issue does not resurrect a settled invitation", func(t *testing.T) {
		invitationID := "inv_" + ids.New[ids.Invitation](time.Now(), ids.Entropy()).String()[4:]
		workspaceID := "ws_" + ids.New[ids.Workspace](time.Now(), ids.Entropy()).String()[3:]
		issued := time.Now().UTC().Truncate(time.Microsecond)
		expiry := issued.Add(7 * 24 * time.Hour)

		insert := workspacedb.UpsertInvitationParams{
			InvitationID: invitationID, WorkspaceID: workspaceID, OrgID: orgID,
			SubjectID: "subj_x", EmailIndex: "idx_x", InvitedBy: "subj_y",
			Role: "member", ExpiresAt: ts(expiry), IssuedAt: ts(issued),
		}

		scoped(t, func(q *workspacedb.Queries) {
			mustExec(t, q.UpsertInvitation(ctx, insert))
		})

		accepted := issued.Add(time.Hour)
		scoped(t, func(q *workspacedb.Queries) {
			mustExec(t, q.SettleInvitation(ctx, workspacedb.SettleInvitationParams{
				InvitationID: invitationID, Status: "accepted", SettledAt: ts(accepted),
			}))
		})

		// THE REDELIVERY. Byte-identical to the first issue.
		scoped(t, func(q *workspacedb.Queries) {
			mustExec(t, q.UpsertInvitation(ctx, insert))
		})

		var status string
		var settledAt pgtype.Timestamptz
		row := scopedRow(t, pool, orgID,
			`SELECT status, settled_at FROM invitation_view WHERE invitation_id = $1`,
			invitationID)
		if err := row.Scan(&status, &settledAt); err != nil {
			t.Fatalf("reading the row back: %v", err)
		}

		if status != "accepted" {
			t.Fatalf("a redelivered issue moved the invitation back to %q. It returns to "+
				"the admin screen as outstanding, and the expiry sweep is handed a settled "+
				"row to expire — releasing the seat the new member is sitting in", status)
		}
		if !settledAt.Valid {
			t.Error("settled_at was cleared by the redelivery, so 'how long did this sit' " +
				"becomes unanswerable for every invitation that was ever redelivered")
		}
	})

	// A RESEND'S WINDOW SURVIVES A REDELIVERED ISSUE.
	//
	// The same defect in its other half. expires_at is the SWEEP'S key, so an
	// issue that overwrote it would sweep a resent invitation at its original
	// deadline — returning the seat while a live link is still in somebody's
	// inbox.
	t.Run("a redelivered issue does not undo a resend", func(t *testing.T) {
		invitationID := "inv_" + ids.New[ids.Invitation](time.Now(), ids.Entropy()).String()[4:]
		workspaceID := "ws_" + ids.New[ids.Workspace](time.Now(), ids.Entropy()).String()[3:]
		issued := time.Now().UTC().Truncate(time.Microsecond)
		expiry := issued.Add(7 * 24 * time.Hour)
		extended := issued.Add(14 * 24 * time.Hour)

		insert := workspacedb.UpsertInvitationParams{
			InvitationID: invitationID, WorkspaceID: workspaceID, OrgID: orgID,
			SubjectID: "subj_x", EmailIndex: "idx_x", InvitedBy: "subj_y",
			Role: "member", ExpiresAt: ts(expiry), IssuedAt: ts(issued),
		}

		scoped(t, func(q *workspacedb.Queries) {
			mustExec(t, q.UpsertInvitation(ctx, insert))
			mustExec(t, q.ExtendInvitation(ctx, workspacedb.ExtendInvitationParams{
				InvitationID: invitationID, ExpiresAt: ts(extended),
			}))
			mustExec(t, q.UpsertInvitation(ctx, insert))
		})

		var got time.Time
		if err := scopedRow(t, pool, orgID,
			`SELECT expires_at FROM invitation_view WHERE invitation_id = $1`,
			invitationID).Scan(&got); err != nil {
			t.Fatalf("reading the row back: %v", err)
		}
		if !got.UTC().Equal(extended) {
			t.Fatalf("the window is %s after a redelivered issue, want the RESENT %s. The "+
				"sweep keys on this column, so the invitation is expired at its original "+
				"deadline and its seat returned while a live link is in somebody's inbox",
				got.UTC(), extended)
		}
	})

	// A SETTLEMENT IS IDEMPOTENT, and never overwrites another settlement.
	//
	// The `status = 'pending'` guard is what makes that true: without it, a
	// redelivered revocation would move an accepted invitation to revoked
	// because the log happened to be re-read in a different order.
	t.Run("a settlement does not overwrite another settlement", func(t *testing.T) {
		invitationID := "inv_" + ids.New[ids.Invitation](time.Now(), ids.Entropy()).String()[4:]
		workspaceID := "ws_" + ids.New[ids.Workspace](time.Now(), ids.Entropy()).String()[3:]
		issued := time.Now().UTC().Truncate(time.Microsecond)

		scoped(t, func(q *workspacedb.Queries) {
			mustExec(t, q.UpsertInvitation(ctx, workspacedb.UpsertInvitationParams{
				InvitationID: invitationID, WorkspaceID: workspaceID, OrgID: orgID,
				SubjectID: "subj_x", EmailIndex: "idx_x", InvitedBy: "subj_y",
				Role: "member", ExpiresAt: ts(issued.Add(time.Hour)), IssuedAt: ts(issued),
			}))
			mustExec(t, q.SettleInvitation(ctx, workspacedb.SettleInvitationParams{
				InvitationID: invitationID, Status: "accepted", SettledAt: ts(issued),
			}))
			// A revocation arriving afterwards, which the log can produce if two
			// settlements race and both are appended before either is projected.
			mustExec(t, q.SettleInvitation(ctx, workspacedb.SettleInvitationParams{
				InvitationID: invitationID, Status: "revoked", SettledAt: ts(issued),
			}))
		})

		var status string
		if err := scopedRow(t, pool, orgID,
			`SELECT status FROM invitation_view WHERE invitation_id = $1`,
			invitationID).Scan(&status); err != nil {
			t.Fatal(err)
		}
		if status != "accepted" {
			t.Fatalf("a second settlement moved an accepted invitation to %q; whichever "+
				"event is projected last wins, and the screen then disagrees with the log",
				status)
		}
	})
}

// scopedRow runs one read under a tenant scope.
//
// invitation_view carries row security, so an UNSCOPED read returns nothing —
// and a test that read nothing would pass every assertion above vacuously.
func scopedRow(t *testing.T, pool *pgxpool.Pool, orgID, sql string, args ...any) pgx.Row {
	t.Helper()
	ctx := context.Background()
	conn, err := pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire: %v", err)
	}
	t.Cleanup(conn.Release)
	if _, err := conn.Exec(ctx, "SELECT set_config('app.org_id', $1, false)", orgID); err != nil {
		t.Fatalf("scope: %v", err)
	}
	return conn.QueryRow(ctx, sql, args...)
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// appDSN connects as chronos_app, never the owner: the owner bypasses RLS, and a
// test that runs as one proves nothing about what the application can see.
func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}

func mustExec(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("statement failed: %v", err)
	}
}
