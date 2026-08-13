//go:build integration

package projection_test

import (
	"context"
	"encoding/hex"
	"io"
	"os"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The reservation projection's statements, run against the real schema.
//
// They are tested here rather than against a fake because every property that
// matters is a property of the SQL: which columns an upsert overwrites, whether a
// confirmation clears the deadline, and which rows the sweep's partial index
// actually selects. A stub that accepted the statements would prove nothing about
// any of it.
//
// What is NOT tested here is uniqueness. Two subjects cannot hold one address
// because they contend on the same KurrentDB stream (ADR-044); this table has no
// opinion on it, and asserting one here would document a guarantee the schema
// does not make.

func TestReservationProjectionStatements(t *testing.T) {
	ctx := context.Background()
	q := identitydb.New(openPool(t))

	t.Run("a takeover replaces the holder and clears the release", func(t *testing.T) {
		index := testIndex(t)
		first, second := "sub_first", "sub_second"
		reserved := time.Now().UTC().Truncate(time.Microsecond)
		lapses := reserved.Add(time.Hour)

		mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
			EmailIndex: index, SubjectID: first,
			ExpiresAt: ts(lapses), ReservedAt: ts(reserved),
		}))
		mustExec(t, q.ReleaseEmailReservation(ctx, identitydb.ReleaseEmailReservationParams{
			EmailIndex: index, SubjectID: first, ReleasedAt: ts(reserved.Add(time.Minute)),
		}))

		// The takeover: a second subject reserves the address the first released.
		// This is the ordinary path after a lapse, and it is why the upsert says
		// DO UPDATE rather than DO NOTHING.
		mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
			EmailIndex: index, SubjectID: second,
			ExpiresAt: ts(lapses), ReservedAt: ts(reserved.Add(2 * time.Minute)),
		}))

		row, err := q.GetEmailReservation(ctx, index)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if row.SubjectID != second {
			t.Errorf("holder is %q, want %q: a takeover left the row naming the previous holder",
				row.SubjectID, second)
		}
		if row.ReleasedAt.Valid {
			t.Error("released_at survived the takeover, so the sweep skips a live claim forever")
		}
		if row.Verified {
			t.Error("the row is verified after a bare reservation")
		}
	})

	t.Run("confirming clears the deadline", func(t *testing.T) {
		index := testIndex(t)
		subject := "sub_confirm"
		now := time.Now().UTC().Truncate(time.Microsecond)

		mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
			EmailIndex: index, SubjectID: subject,
			ExpiresAt: ts(now.Add(time.Hour)), ReservedAt: ts(now),
		}))
		mustExec(t, q.ConfirmEmailReservation(ctx, identitydb.ConfirmEmailReservationParams{
			EmailIndex: index, SubjectID: subject,
		}))

		row, err := q.GetEmailReservation(ctx, index)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if !row.Verified {
			t.Fatal("confirmation did not mark the row verified")
		}
		// The deadline is cleared rather than left in the future: a confirmed claim
		// has no deadline at all, so no widening of the sweep's WHERE clause can
		// ever select it.
		if row.ExpiresAt.Valid {
			t.Error("expires_at survived confirmation; a confirmed claim still carries a deadline")
		}
	})

	t.Run("confirming under the wrong subject changes nothing", func(t *testing.T) {
		index := testIndex(t)
		now := time.Now().UTC().Truncate(time.Microsecond)

		mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
			EmailIndex: index, SubjectID: "sub_holder",
			ExpiresAt: ts(now.Add(time.Hour)), ReservedAt: ts(now),
		}))
		mustExec(t, q.ConfirmEmailReservation(ctx, identitydb.ConfirmEmailReservationParams{
			EmailIndex: index, SubjectID: "sub_impostor",
		}))

		row, err := q.GetEmailReservation(ctx, index)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if row.Verified {
			t.Error("a confirmation naming a different subject verified somebody else's claim")
		}
	})

	t.Run("the sweep selects lapsed claims only", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		past, future := now.Add(-time.Hour), now.Add(time.Hour)

		lapsed := testIndex(t)
		live := testIndex(t)
		confirmed := testIndex(t)
		released := testIndex(t)

		for _, r := range []struct {
			index   string
			expires time.Time
		}{
			{lapsed, past}, {live, future}, {confirmed, past}, {released, past},
		} {
			mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
				EmailIndex: r.index, SubjectID: "sub_sweep",
				ExpiresAt: ts(r.expires), ReservedAt: ts(now.Add(-2 * time.Hour)),
			}))
		}
		mustExec(t, q.ConfirmEmailReservation(ctx, identitydb.ConfirmEmailReservationParams{
			EmailIndex: confirmed, SubjectID: "sub_sweep",
		}))
		mustExec(t, q.ReleaseEmailReservation(ctx, identitydb.ReleaseEmailReservationParams{
			EmailIndex: released, SubjectID: "sub_sweep", ReleasedAt: ts(now),
		}))

		rows, err := q.ListLapsedReservations(ctx, identitydb.ListLapsedReservationsParams{
			ExpiresAt: ts(now), Limit: 1000,
		})
		if err != nil {
			t.Fatalf("sweep: %v", err)
		}
		got := make(map[string]bool, len(rows))
		for _, r := range rows {
			got[r.EmailIndex] = true
		}

		if !got[lapsed] {
			t.Error("the sweep missed a lapsed unverified claim, so the address is held forever")
		}
		// Each of these is a way to free an address that is not free to take.
		if got[live] {
			t.Error("the sweep selected a claim whose lease has not run out")
		}
		if got[confirmed] {
			t.Error("the sweep selected a CONFIRMED claim: a proven address would be released")
		}
		if got[released] {
			t.Error("the sweep selected an already-released claim, so it releases it again forever")
		}
	})

	t.Run("retention deletes only released rows", func(t *testing.T) {
		now := time.Now().UTC().Truncate(time.Microsecond)
		held, gone := testIndex(t), testIndex(t)

		for _, index := range []string{held, gone} {
			mustExec(t, q.UpsertEmailReservation(ctx, identitydb.UpsertEmailReservationParams{
				EmailIndex: index, SubjectID: "sub_retention",
				ExpiresAt: ts(now.Add(time.Hour)), ReservedAt: ts(now),
			}))
		}
		mustExec(t, q.ReleaseEmailReservation(ctx, identitydb.ReleaseEmailReservationParams{
			EmailIndex: gone, SubjectID: "sub_retention", ReleasedAt: ts(now.Add(-48 * time.Hour)),
		}))

		if _, err := q.DeleteReleasedReservations(ctx, ts(now.Add(-24*time.Hour))); err != nil {
			t.Fatalf("retention: %v", err)
		}

		if _, err := q.GetEmailReservation(ctx, held); err != nil {
			t.Errorf("retention deleted a live claim: %v", err)
		}
		if _, err := q.GetEmailReservation(ctx, gone); err == nil {
			t.Error("retention kept a row released two days ago")
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// testIndex returns an index no other test or run uses.
//
// Shaped like a real one — 64 hex characters — because the column is the primary
// key and a short value would exercise a narrower index entry than production
// ever sees.
func testIndex(t *testing.T) string {
	t.Helper()
	var b [32]byte
	if _, err := io.ReadFull(ids.Entropy(), b[:]); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	return hex.EncodeToString(b[:])
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
