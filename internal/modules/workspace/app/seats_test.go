package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
)

// fakeReserver records what was reserved and released, per pool.
type fakeReserver struct {
	reserved  []string // pool keys, in order
	committed int
	released  []string // pool keys released by subject
	full      map[string]bool
	nextID    int
}

func newFakeReserver() *fakeReserver {
	return &fakeReserver{full: map[string]bool{}}
}

func (f *fakeReserver) ReserveFor(_ context.Context, _, limitKey, _ string) (string, error) {
	if f.full[limitKey] {
		return "", errors.New("quota exhausted: " + limitKey)
	}
	f.reserved = append(f.reserved, limitKey)
	f.nextID++
	return "res_" + limitKey, nil
}

func (f *fakeReserver) Commit(context.Context, string) error  { f.committed++; return nil }
func (f *fakeReserver) Release(context.Context, string) error { return nil }

func (f *fakeReserver) ReleaseFor(_ context.Context, _, limitKey, _ string) error {
	f.released = append(f.released, limitKey)
	return nil
}

// fakeMembers answers how many workspaces of an org somebody is already in.
type fakeMembers struct{ count int }

func (f fakeMembers) WorkspaceCount(context.Context, string, string) (int, error) {
	return f.count, nil
}

func seats(t *testing.T, r *fakeReserver, existing int) *app.Seats {
	t.Helper()
	s, err := app.NewSeats(app.SeatsDeps{Reserver: r, Members: fakeMembers{count: existing}})
	if err != nil {
		t.Fatalf("NewSeats: %v", err)
	}
	return s
}

// ONE PERSON IN FIVE WORKSPACES OF ONE ORGANIZATION CONSUMES ONE SEAT.
//
// workspace.md §12 names this the highest-value test in the domain, and §2 says
// why: getting it wrong "either overcharges customers or leaks revenue". This is
// the overcharging direction — a seat taken for every workspace somebody joins,
// which a customer discovers on an invoice rather than in a test.
func TestOnePersonInFiveWorkspacesConsumesOneSeat(t *testing.T) {
	t.Parallel()

	r := newFakeReserver()

	// The FIRST workspace: nobody is in the organization yet.
	first := seats(t, r, 0)
	_, consumed, err := first.ReserveForJoin(t.Context(), "org_1", "sub_alice", contract.RoleMember)
	if err != nil {
		t.Fatalf("the first join: %v", err)
	}
	if !consumed {
		t.Fatal("joining a first workspace consumed no seat; nobody is ever charged")
	}

	// Workspaces two through five: already in the organization.
	for i := 2; i <= 5; i++ {
		later := seats(t, r, i-1)
		_, consumed, err := later.ReserveForJoin(
			t.Context(), "org_1", "sub_alice", contract.RoleMember)
		if err != nil {
			t.Fatalf("join %d: %v", i, err)
		}
		if consumed {
			t.Fatalf("joining workspace %d consumed ANOTHER seat. Five workspaces would "+
				"cost five seats for one person, and the customer is overcharged fourfold", i)
		}
	}

	if len(r.reserved) != 1 {
		t.Errorf("%d seats were reserved across five workspaces, want 1: %v",
			len(r.reserved), r.reserved)
	}
}

// REMOVING SOMEBODY FROM ONE WORKSPACE OF SEVERAL RELEASES NOTHING.
//
// The revenue-leaking direction. If every removal returned a seat, somebody in
// five workspaces could be removed from one and keep working in four while the
// organization was charged for none of them.
func TestRemovingFromOneWorkspaceOfSeveralReleasesNoSeat(t *testing.T) {
	t.Parallel()

	r := newFakeReserver()
	s := seats(t, r, 0)

	// Four memberships remain after this removal.
	released, err := s.ReleaseOnRemoval(
		t.Context(), "org_1", "sub_alice", contract.RoleMember, 4)
	if err != nil {
		t.Fatalf("ReleaseOnRemoval: %v", err)
	}
	if released {
		t.Fatal("removing somebody from one workspace of five returned their seat. They are " +
			"still in the organization and still working, and the seat is now free for " +
			"somebody else — the organization is under-charged for an active person")
	}
	if len(r.released) != 0 {
		t.Errorf("a seat was released: %v", r.released)
	}
}

// LEAVING THE ORGANIZATION ENTIRELY RELEASES ONE SEAT.
func TestLeavingTheOrganizationReleasesTheSeat(t *testing.T) {
	t.Parallel()

	r := newFakeReserver()
	s := seats(t, r, 0)

	released, err := s.ReleaseOnRemoval(
		t.Context(), "org_1", "sub_alice", contract.RoleMember, 0)
	if err != nil {
		t.Fatalf("ReleaseOnRemoval: %v", err)
	}
	if !released {
		t.Fatal("the last membership was removed and no seat came back; the organization " +
			"keeps paying for somebody who has left")
	}
	if len(r.released) != 1 || r.released[0] != "seats.member" {
		t.Errorf("released %v, want one seats.member", r.released)
	}
}

// GUEST AND MEMBER SEATS ARE INDEPENDENT POOLS (ADR-027).
//
// Exhausting guest seats must never block hiring.
func TestGuestAndMemberSeatsAreSeparatePools(t *testing.T) {
	t.Parallel()

	r := newFakeReserver()
	r.full["seats.guest"] = true // no guest seats left at all

	s := seats(t, r, 0)
	if _, _, err := s.ReserveForJoin(
		t.Context(), "org_1", "sub_alice", contract.RoleMember); err != nil {
		t.Fatalf("hiring a MEMBER was blocked because GUEST seats are exhausted: %v", err)
	}
	if _, _, err := s.ReserveForJoin(
		t.Context(), "org_1", "sub_guest", contract.RoleGuest); err == nil {
		t.Fatal("a guest was admitted with no guest seats left")
	}
}

// PROMOTING A GUEST TO MEMBER MOVES POOLS, and takes the new seat FIRST.
//
// The ordering is the point. Releasing first would mean a promotion into a full
// member pool leaves the person holding NEITHER seat — a member of the
// organization consuming nothing, which is a leak in the customer's favour and
// invisible until an audit.
func TestPromotingAGuestTakesTheNewSeatBeforeReturningTheOld(t *testing.T) {
	t.Parallel()

	t.Run("the member pool is full", func(t *testing.T) {
		t.Parallel()
		r := newFakeReserver()
		r.full["seats.member"] = true

		s := seats(t, r, 1)
		err := s.MovePools(t.Context(), "org_1", "sub_guest",
			contract.RoleGuest, contract.RoleMember)
		if err == nil {
			t.Fatal("a promotion into a full member pool succeeded")
		}
		if len(r.released) != 0 {
			t.Fatal("the GUEST seat was released even though the member seat could not be " +
				"taken. The person now holds neither, and the organization is charged for " +
				"nobody while they keep working")
		}
	})

	t.Run("both pools have room", func(t *testing.T) {
		t.Parallel()
		r := newFakeReserver()

		s := seats(t, r, 1)
		if err := s.MovePools(t.Context(), "org_1", "sub_guest",
			contract.RoleGuest, contract.RoleMember); err != nil {
			t.Fatalf("MovePools: %v", err)
		}
		if len(r.reserved) != 1 || r.reserved[0] != "seats.member" {
			t.Errorf("reserved %v, want one seats.member", r.reserved)
		}
		if len(r.released) != 1 || r.released[0] != "seats.guest" {
			t.Errorf("released %v, want one seats.guest", r.released)
		}
	})

	t.Run("a change within one pool moves nothing", func(t *testing.T) {
		t.Parallel()
		r := newFakeReserver()

		s := seats(t, r, 1)
		// member -> admin: both draw on seats.member.
		if err := s.MovePools(t.Context(), "org_1", "sub_alice",
			contract.RoleMember, contract.RoleAdmin); err != nil {
			t.Fatalf("MovePools: %v", err)
		}
		if len(r.reserved) != 0 || len(r.released) != 0 {
			t.Errorf("promoting a member to admin touched the pools: reserved=%v released=%v",
				r.reserved, r.released)
		}
	})
}

// A failed commit returns the held reservation rather than leaving it to expire.
func TestAFailedJoinDoesNotStrandASeat(t *testing.T) {
	t.Parallel()

	r := &failingCommit{fakeReserver: newFakeReserver()}
	s, err := app.NewSeats(app.SeatsDeps{Reserver: r, Members: fakeMembers{count: 0}})
	if err != nil {
		t.Fatalf("NewSeats: %v", err)
	}

	if _, _, err := s.ReserveForJoin(
		t.Context(), "org_1", "sub_alice", contract.RoleMember); err == nil {
		t.Fatal("a failed commit reported success")
	}
	if !r.releasedHeld {
		t.Error("the held reservation was left to expire. A seat nobody holds is unavailable " +
			"to everybody else until its TTL")
	}
}

type failingCommit struct {
	*fakeReserver
	releasedHeld bool
}

func (f *failingCommit) Commit(context.Context, string) error {
	return errors.New("commit failed")
}

func (f *failingCommit) Release(context.Context, string) error {
	f.releasedHeld = true
	return nil
}

// Neither dependency is optional.
func TestSeatsRefusesToBeBuiltHalfWired(t *testing.T) {
	t.Parallel()

	if _, err := app.NewSeats(app.SeatsDeps{Reserver: newFakeReserver()}); err == nil {
		t.Error("seats was built with no organization membership source; whether a join " +
			"consumes a seat is a question about the organization")
	}
	if _, err := app.NewSeats(app.SeatsDeps{Members: fakeMembers{}}); err == nil {
		t.Error("seats was built with no reserver")
	}
}

// The refusal names the pool, so an operator knows which limit to raise.
func TestAnExhaustedPoolIsNamed(t *testing.T) {
	t.Parallel()

	r := newFakeReserver()
	r.full["seats.member"] = true
	s := seats(t, r, 0)

	_, _, err := s.ReserveForJoin(t.Context(), "org_1", "sub_alice", contract.RoleMember)
	if err == nil {
		t.Fatal("a join succeeded with no member seats")
	}
	if !strings.Contains(err.Error(), "seats.member") {
		t.Errorf("the refusal does not name the exhausted pool: %v", err)
	}
}
