//go:build integration

package projection_test

import (
	"context"
	"errors"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5"
)

// The account projection's statements, run against the real schema.
//
// The property under test is the one migration 00014 exists for, and it is a
// property of the SCHEMA rather than of any Go code: user_view must be able to
// hold two accounts that carried one email index at different times.
//
// It is asserted at this level because that is where it broke and where it
// cannot be hidden. The end-to-end version of the same sequence lives in
// TestALapsedReservationIsReleasedAndTheAddressIsRegisterableAgain, and it took
// 30 seconds of polling and a live sweep to reach the statement that failed.
// Here the sequence is three statements in the order $all delivers them.
func TestUserProjectionStatements(t *testing.T) {
	ctx := context.Background()
	q := identitydb.New(openPool(t))

	t.Run("a lapsed address is re-registered by a second account", func(t *testing.T) {
		index := testIndex(t)
		squatter, owner := freshSubject(t), freshSubject(t)
		registered := time.Now().UTC().Truncate(time.Microsecond)

		// 1. The squat. Somebody registers an address they do not own.
		mustExec(t, q.UpsertUser(ctx, identitydb.UpsertUserParams{
			SubjectID: squatter.subject, UserID: squatter.user, EmailIndex: index,
			State: "pending", RegisteredAt: ts(registered),
		}))

		// 2. The lapse. EmailReleased arrives — from the sweep, or from the
		//    takeover's own multi-append — and it names the SQUATTER, because a
		//    release names the holder whose claim ended.
		mustExec(t, q.ReleaseUserEmailIndex(ctx, identitydb.ReleaseUserEmailIndexParams{
			SubjectID: squatter.subject, EmailIndex: index,
			EmailReleasedAt: ts(registered.Add(48 * time.Hour)),
		}))

		// 3. The real owner registers. Under the bare UNIQUE constraint 00008
		//    put on email_index this statement failed with SQLSTATE 23505, the
		//    identity projector stopped on it, and `projector -rebuild
		//    identity_user` failed at the same event — so user_view was no
		//    longer reconstructable by replaying from position zero.
		if err := q.UpsertUser(ctx, identitydb.UpsertUserParams{
			SubjectID: owner.subject, UserID: owner.user, EmailIndex: index,
			State: "pending", RegisteredAt: ts(registered.Add(49 * time.Hour)),
		}); err != nil {
			t.Fatalf("the second registration for a released address was refused: %v\n"+
				"The domain permits this — an unverified claim lapses after "+
				"app.DefaultReservationLease and EmailReservation.Reserve takes it "+
				"over, while the squatter's Pending account is deliberately not "+
				"deleted — so a projection that cannot represent it stops on the "+
				"next registration and never rebuilds.", err)
		}

		// Both accounts survive, and they are distinguishable.
		both := map[string]bool{}
		rows, err := openPool(t).Query(ctx,
			`SELECT subject_id, email_released_at IS NOT NULL FROM user_view WHERE email_index = $1`,
			index)
		if err != nil {
			t.Fatalf("reading back: %v", err)
		}
		defer rows.Close()
		for rows.Next() {
			var subject string
			var released bool
			if err := rows.Scan(&subject, &released); err != nil {
				t.Fatalf("scanning: %v", err)
			}
			both[subject] = released
		}
		if err := rows.Err(); err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if len(both) != 2 {
			t.Fatalf("%d accounts carry the index, want 2: %v", len(both), both)
		}
		if !both[squatter.subject] {
			t.Error("the squatter's row is not marked as having released the address, so the " +
				"login lookup can still resolve the address to it")
		}
		if both[owner.subject] {
			t.Error("the new holder's row is marked released, so the login lookup resolves " +
				"the address to nobody")
		}

		// The login lookup must reach the CURRENT holder. This is the half that
		// fails silently rather than loudly: two matching rows and a :one query
		// return whichever the planner reached first.
		got, err := q.GetUserByEmailIndex(ctx, index)
		if err != nil {
			t.Fatalf("the login lookup found no account for a held address: %v", err)
		}
		if got.SubjectID != owner.subject {
			t.Errorf("the login lookup resolved the address to %s, want the current holder %s: "+
				"an authentication attempt reaches the abandoned account",
				got.SubjectID, owner.subject)
		}
	})

	t.Run("a release is idempotent and keeps the first timestamp", func(t *testing.T) {
		index := testIndex(t)
		holder := freshSubject(t)
		now := time.Now().UTC().Truncate(time.Microsecond)

		mustExec(t, q.UpsertUser(ctx, identitydb.UpsertUserParams{
			SubjectID: holder.subject, UserID: holder.user, EmailIndex: index,
			State: "pending", RegisteredAt: ts(now),
		}))
		first := now.Add(time.Hour)
		mustExec(t, q.ReleaseUserEmailIndex(ctx, identitydb.ReleaseUserEmailIndexParams{
			SubjectID: holder.subject, EmailIndex: index, EmailReleasedAt: ts(first),
		}))
		// A projector replays. The second application must not move the column:
		// it answers "when did this account lose the address", not "when was
		// this event last replayed".
		mustExec(t, q.ReleaseUserEmailIndex(ctx, identitydb.ReleaseUserEmailIndexParams{
			SubjectID: holder.subject, EmailIndex: index, EmailReleasedAt: ts(now.Add(2 * time.Hour)),
		}))

		var released time.Time
		if err := openPool(t).QueryRow(ctx,
			`SELECT email_released_at FROM user_view WHERE subject_id = $1`,
			holder.subject).Scan(&released); err != nil {
			t.Fatalf("reading back: %v", err)
		}
		if !released.UTC().Equal(first) {
			t.Errorf("a replayed release moved the timestamp to %v, want %v", released.UTC(), first)
		}

		// And the address is now unresolvable, which is what makes it claimable.
		if _, err := q.GetUserByEmailIndex(ctx, index); !errors.Is(err, pgx.ErrNoRows) {
			t.Errorf("the login lookup still resolves a released address (err=%v)", err)
		}
	})

	t.Run("a release naming a different holder changes nothing", func(t *testing.T) {
		index := testIndex(t)
		holder, stranger := freshSubject(t), freshSubject(t)
		now := time.Now().UTC().Truncate(time.Microsecond)

		mustExec(t, q.UpsertUser(ctx, identitydb.UpsertUserParams{
			SubjectID: holder.subject, UserID: holder.user, EmailIndex: index,
			State: "pending", RegisteredAt: ts(now),
		}))
		// A release for a subject that does not hold this index must not retire
		// the live row. Without the subject_id guard the address would be handed
		// to nobody, and the account holding it would become unreachable.
		mustExec(t, q.ReleaseUserEmailIndex(ctx, identitydb.ReleaseUserEmailIndexParams{
			SubjectID: stranger.subject, EmailIndex: index, EmailReleasedAt: ts(now.Add(time.Hour)),
		}))

		got, err := q.GetUserByEmailIndex(ctx, index)
		if err != nil {
			t.Fatalf("the holder became unreachable after somebody else's release: %v", err)
		}
		if got.SubjectID != holder.subject {
			t.Errorf("the address resolves to %s, want %s", got.SubjectID, holder.subject)
		}
	})
}

type subjectAndUser struct{ subject, user string }

func freshSubject(t *testing.T) subjectAndUser {
	t.Helper()
	now := time.Now()
	return subjectAndUser{
		subject: ids.New[ids.Subject](now, ids.Entropy()).String(),
		user:    ids.New[ids.User](now, ids.Entropy()).String(),
	}
}
