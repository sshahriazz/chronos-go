package postgres

// White-box, because the two things worth testing without a database are
// unexported and cannot be provoked through one.
//
// accountState's failure branch is unreachable from an integration test: the
// CHECK on user_view.state refuses every value it would reject, which is asserted
// in queries_integration_test.go. The branch still exists, because the constraint
// and the binary are deployed separately — a migration that adds a state to the
// constraint reaches the database before every binary is replaced, and the old
// binary must refuse the row rather than render it as a missing account.

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/page"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestAccountState(t *testing.T) {
	for _, tc := range []struct {
		projected string
		want      domain.State
		wantErr   bool
	}{
		{"pending", domain.StatePending, false},
		{"active", domain.StateActive, false},
		{"deactivated", domain.StateDeactivated, false},
		{"suspended", domain.StateSuspended, false},
		// Each of these must be an ERROR rather than StateNone. StateNone means
		// "this account does not exist", so mapping an unknown string to it would
		// make a row that is plainly there render as a missing account — and the
		// caller's answer for a missing account is deliberately detail-free, so
		// nothing downstream would ever say what happened.
		{"quarantined", domain.StateNone, true},
		{"none", domain.StateNone, true},
		{"", domain.StateNone, true},
		{"ACTIVE", domain.StateNone, true},
	} {
		t.Run(tc.projected, func(t *testing.T) {
			got, err := accountState(tc.projected)
			if (err != nil) != tc.wantErr {
				t.Fatalf("accountState(%q) error = %v, wantErr %v", tc.projected, err, tc.wantErr)
			}
			if got != tc.want {
				t.Errorf("accountState(%q) = %v, want %v", tc.projected, got, tc.want)
			}
		})
	}
}

// The first page's sentinel must be PostgreSQL's `infinity`, not a finite value.
//
// A finite "far future" would work until it did not: a row written by a clock
// ahead of this one, or a fixture dated past the sentinel, would sort above it and
// silently vanish from the first page.
func TestBeforeEverythingIsInfinite(t *testing.T) {
	if !beforeEverything.Valid {
		t.Fatal("the first-page cursor is NULL; comparing against NULL yields NULL, so " +
			"the first page would come back empty")
	}
	if beforeEverything.InfinityModifier != pgtype.Infinity {
		t.Fatalf("the first-page cursor is %v, want infinity: a finite sentinel hides "+
			"every row dated after it", beforeEverything.InfinityModifier)
	}
}

func TestSessionCursorArgs(t *testing.T) {
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.FixedZone("east", 3600))

	t.Run("the start position binds infinity", func(t *testing.T) {
		ts, id, err := sessionCursorArgs(page.Start())
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		if ts.InfinityModifier != pgtype.Infinity || id != "" {
			t.Errorf("start bound (%v, %q), want (infinity, \"\")", ts, id)
		}
	})

	t.Run("a cursor is normalized to UTC", func(t *testing.T) {
		k, err := page.NewKeyset(
			page.Key{Column: "created_at", Value: at},
			page.Key{Column: "session_id", Value: "ses_1", Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		ts, id, err := sessionCursorArgs(k)
		if err != nil {
			t.Fatalf("cursor: %v", err)
		}
		if ts.Time.Location() != time.UTC {
			t.Errorf("bound a timestamp in %v; storage is UTC", ts.Time.Location())
		}
		if !ts.Time.Equal(at) || id != "ses_1" {
			t.Errorf("bound (%v, %q), want (%v, ses_1)", ts.Time, id, at.UTC())
		}
	})

	t.Run("the wrong arity is refused", func(t *testing.T) {
		k, err := page.NewKeyset(page.Key{Column: "created_at", Value: "solo", Unique: true})
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		if _, _, err := sessionCursorArgs(k); err == nil {
			t.Error("a one-column cursor was bound to a two-column comparison")
		}
	})

	// Each column is checked SEPARATELY. A keyset with both columns wrong is
	// refused by whichever check runs first, so it proves nothing about the
	// other — a mutation that dropped the timestamp check survived a
	// both-wrong fixture because the tiebreaker check caught it instead.
	t.Run("only the timestamp is wrong", func(t *testing.T) {
		k, err := page.NewKeyset(
			page.Key{Column: "created_at", Value: "not-a-timestamp"},
			page.Key{Column: "session_id", Value: "ses_1", Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		if _, _, err := sessionCursorArgs(k); err == nil {
			t.Error("a string bound where a timestamp belongs; unchecked it becomes the " +
				"zero time, and `created_at < '0001-01-01'` returns an empty page that " +
				"reads as the end of the list")
		}
	})

	t.Run("only the tiebreaker is wrong", func(t *testing.T) {
		k, err := page.NewKeyset(
			page.Key{Column: "created_at", Value: at},
			page.Key{Column: "session_id", Value: int64(7), Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		if _, _, err := sessionCursorArgs(k); err == nil {
			t.Error("an integer bound where a session id belongs; unchecked it becomes the " +
				"empty string, which sorts below every id and drops the whole tied group")
		}
	})
}

func TestLoginCursorArgs(t *testing.T) {
	at := time.Date(2026, 5, 1, 12, 0, 0, 0, time.UTC)

	t.Run("the start position binds infinity", func(t *testing.T) {
		ts, id, err := loginCursorArgs(page.Start())
		if err != nil {
			t.Fatalf("start: %v", err)
		}
		if ts.InfinityModifier != pgtype.Infinity || id != 0 {
			t.Errorf("start bound (%v, %d), want (infinity, 0)", ts, id)
		}
	})

	t.Run("a cursor binds its bigint tiebreaker", func(t *testing.T) {
		k, err := page.NewKeyset(
			page.Key{Column: "occurred_at", Value: at},
			page.Key{Column: "id", Value: int64(42), Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		ts, id, err := loginCursorArgs(k)
		if err != nil {
			t.Fatalf("cursor: %v", err)
		}
		if !ts.Time.Equal(at) || id != 42 {
			t.Errorf("bound (%v, %d), want (%v, 42)", ts.Time, id, at)
		}
	})

	t.Run("only the timestamp is wrong", func(t *testing.T) {
		k, err := page.NewKeyset(
			page.Key{Column: "occurred_at", Value: "not-a-timestamp"},
			page.Key{Column: "id", Value: int64(1), Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		if _, _, err := loginCursorArgs(k); err == nil {
			t.Error("a string bound where a timestamp belongs")
		}
	})

	t.Run("a string tiebreaker is refused", func(t *testing.T) {
		// The failure this catches is a session cursor reaching the login history:
		// its tail is a text session id, and binding it to a bigint column is
		// either an error from the driver or a comparison against whatever the
		// driver made of it.
		k, err := page.NewKeyset(
			page.Key{Column: "occurred_at", Value: at},
			page.Key{Column: "id", Value: "ses_01J", Unique: true},
		)
		if err != nil {
			t.Fatalf("keyset: %v", err)
		}
		if _, _, err := loginCursorArgs(k); err == nil {
			t.Error("a text tiebreaker was bound to a bigint comparison")
		}
	})
}

// utc turns a NULL into the zero time and everything else into UTC. Both halves
// matter: callers document a zero time as "never happened", and a timestamp left
// in the connection's zone would compare equal but format differently everywhere
// it is rendered.
func TestUTC(t *testing.T) {
	if got := utc(pgtype.Timestamptz{}); !got.IsZero() {
		t.Errorf("a NULL timestamp became %v, want the zero time", got)
	}
	east := time.Date(2026, 5, 1, 12, 0, 0, 0, time.FixedZone("east", 3600))
	got := utc(pgtype.Timestamptz{Time: east, Valid: true})
	if got.Location() != time.UTC {
		t.Errorf("a timestamp came back in %v, want UTC", got.Location())
	}
	if !got.Equal(east) {
		t.Errorf("the instant moved: %v, want %v", got, east)
	}
}
