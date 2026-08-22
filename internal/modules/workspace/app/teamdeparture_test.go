package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// fakeTeamRoster is the projection the cascade reads.
type fakeTeamRoster struct {
	// Keyed by workspace, so a test can prove the cascade is scoped to ONE
	// workspace rather than sweeping every team the person is in anywhere.
	teams map[string][]string
	err   error
	calls int
}

func (f *fakeTeamRoster) TeamsOf(_ context.Context, workspaceID, _ string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	return f.teams[workspaceID], nil
}

// departureHarness drives the cascade over a real membership repository.
type departureHarness struct {
	*teamMemberHarness

	departures *app.TeamDepartures
	teamRoster *fakeTeamRoster
}

func newDepartureHarness(t *testing.T) *departureHarness {
	t.Helper()
	base := newTeamMemberHarness(t)
	roster := &fakeTeamRoster{teams: map[string][]string{}}

	departures, err := app.NewTeamDepartures(app.TeamDeparturesDeps{
		Memberships: base.memberships, Roster: roster,
		Now: func() time.Time { return time.Unix(1_700_000_100, 0).UTC() },
	})
	if err != nil {
		t.Fatalf("NewTeamDepartures: %v", err)
	}
	return &departureHarness{teamMemberHarness: base, departures: departures, teamRoster: roster}
}

// joins puts somebody in a team through the real use case and records the team
// on the roster, the way the projection would.
func (h *departureHarness) joins(t *testing.T, name, subjectID string) string {
	t.Helper()
	team := h.create(t, name)
	h.roster.members[subjectID] = true
	if err := h.add(team.TeamID, subjectID, founder); err != nil {
		t.Fatalf("seeding %s into %s: %v", subjectID, name, err)
	}
	h.teamRoster.teams[inviteWS] = append(h.teamRoster.teams[inviteWS], team.TeamID)
	return team.TeamID
}

// LEAVING A WORKSPACE LEAVES ITS TEAMS.
//
// workspace.md §6 in the other direction, and the half that had no code. A
// removed person who keeps `team:x member user:y` gets whatever that team is
// ever granted — access that outlives the fact that granted it, which is exactly
// the shape ADR-045 exists for.
//
// EVERY team, not the first: a loop that stops early leaves the rest attached
// and looks identical from the caller's side.
func TestLeavingAWorkspaceLeavesEveryTeamInIt(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"

	engineering := h.joins(t, "engineering", leaver)
	design := h.joins(t, "design", leaver)
	oncall := h.joins(t, "oncall", leaver)

	if err := h.departures.Depart(context.Background(), inviteWS, leaver); err != nil {
		t.Fatalf("the cascade failed: %v", err)
	}

	for name, teamID := range map[string]string{
		"engineering": engineering, "design": design, "oncall": oncall,
	} {
		if h.isInTeam(t, teamID, leaver) {
			t.Errorf("still in %s after leaving the workspace; that team's grants now reach "+
				"somebody who was removed", name)
		}
	}
}

// AND ONLY THAT WORKSPACE'S TEAMS.
//
// A person can be in several workspaces of one organization, and being removed
// from one has nothing to do with the others. A cascade scoped to the SUBJECT
// rather than the (workspace, subject) pair would quietly empty every team they
// are in anywhere — a much larger revocation than the removal authorised.
func TestLeavingOneWorkspaceLeavesAnothersTeamsAlone(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"

	here := h.joins(t, "engineering", leaver)

	// A team the roster reports under a DIFFERENT workspace. It is reachable by
	// id, so a cascade that ignored the workspace would strip it.
	elsewhere := h.create(t, "elsewhere")
	if err := h.add(elsewhere.TeamID, leaver, founder); err != nil {
		t.Fatal(err)
	}
	h.teamRoster.teams["ws_01ARZ3NDEKTSV4RRFFQ69G5FBB"] = []string{elsewhere.TeamID}

	if err := h.departures.Depart(context.Background(), inviteWS, leaver); err != nil {
		t.Fatal(err)
	}

	if h.isInTeam(t, here, leaver) {
		t.Error("still in this workspace's team")
	}
	if !h.isInTeam(t, elsewhere.TeamID, leaver) {
		t.Error("a team of ANOTHER workspace was stripped; one removal revoked membership " +
			"of a workspace the person is still in")
	}
}

// THE CASCADE IS IDEMPOTENT.
//
// A reactor's delivery is at-least-once, and this one has no fingerprint to key
// on. A second run has to find the memberships already inactive and append
// nothing rather than failing — a failure would park the event and retry
// forever.
func TestRunningTheCascadeTwiceIsRunningItOnce(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"
	teamID := h.joins(t, "engineering", leaver)

	ctx := context.Background()
	if err := h.departures.Depart(ctx, inviteWS, leaver); err != nil {
		t.Fatal(err)
	}
	key := eventsourcing.StreamID(domain.TeamMembershipCategory) + "-" +
		eventsourcing.StreamID(domain.TeamMembershipStreamKey(teamID, leaver))
	before := len(h.store.streams[key])
	// Without this the whole test is vacuous: a wrong stream key makes both
	// lookups zero, and "appended nothing twice" passes for a cascade that
	// appended nothing at all.
	if before != 2 {
		t.Fatalf("the stream holds %d events, want 2 (added, removed) — the key %q does not "+
			"address the membership this test is measuring", before, key)
	}

	if err := h.departures.Depart(ctx, inviteWS, leaver); err != nil {
		t.Fatalf("a redelivery failed: %v; the reactor parks and retries forever", err)
	}
	after := len(h.store.streams[key])

	if after != before {
		t.Errorf("a second run appended %d events, want none", after-before)
	}
}

// AN UNREADABLE ROSTER IS A FAILURE, NOT AN EMPTY LIST.
//
// The distinction is the whole cascade. Returning nil on error would ack the
// event having stripped nothing — the reactor would report success and every
// membership would survive the removal, with no parked event and no log line.
func TestAnUnreadableRosterFailsTheCascade(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"
	teamID := h.joins(t, "engineering", leaver)

	h.teamRoster.err = errors.New("postgres: connection refused")

	if err := h.departures.Depart(context.Background(), inviteWS, leaver); err == nil {
		t.Fatal("an unreadable roster reported SUCCESS; the reactor acks, every membership " +
			"survives the removal, and nothing anywhere records that it happened")
	}
	if !h.isInTeam(t, teamID, leaver) {
		t.Error("the roster was unreadable and a membership was removed anyway")
	}
}

// A DEPARTURE NEEDS BOTH IDS.
//
// An empty subject would list every team membership in the workspace whose
// subject column happens to be empty; an empty workspace would scope the query
// to nothing at all. Both are refused before the roster is read.
func TestADepartureNeedsBothIds(t *testing.T) {
	h := newDepartureHarness(t)
	ctx := context.Background()

	for name, call := range map[string]func() error{
		"no workspace": func() error { return h.departures.Depart(ctx, "", "subj_x") },
		"no subject":   func() error { return h.departures.Depart(ctx, inviteWS, "") },
	} {
		t.Run(name, func(t *testing.T) {
			before := h.teamRoster.calls
			if err := call(); err == nil {
				t.Error("accepted")
			}
			if h.teamRoster.calls != before {
				t.Error("the roster was queried with an incomplete key")
			}
		})
	}
}

// AN INCOMPLETE WIRING IS REFUSED AT CONSTRUCTION.
//
// The nil roster is the one that matters: it does not crash, it makes the
// enumeration unreachable, and every removal then reports success having
// stripped nothing.
func TestTeamDeparturesRefusesAnIncompleteWiring(t *testing.T) {
	store := newMemStore()
	memberships := eventsourcing.NewRepository[*domain.TeamMembership](
		store, jsonCodec{}, nil, domain.TeamMembershipCategory, domain.NewTeamMembership)
	now := func() time.Time { return time.Unix(1_700_000_000, 0).UTC() }

	full := app.TeamDeparturesDeps{
		Memberships: memberships, Roster: &fakeTeamRoster{}, Now: now,
	}
	if _, err := app.NewTeamDepartures(full); err != nil {
		t.Fatalf("a complete wiring was refused: %v", err)
	}

	for name, drop := range map[string]func(*app.TeamDeparturesDeps){
		"memberships": func(d *app.TeamDeparturesDeps) { d.Memberships = nil },
		"roster":      func(d *app.TeamDeparturesDeps) { d.Roster = nil },
		"now":         func(d *app.TeamDeparturesDeps) { d.Now = nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := full
			drop(&deps)
			if _, err := app.NewTeamDepartures(deps); err == nil {
				t.Errorf("a wiring with no %s was accepted", name)
			}
		})
	}
}

// A STALE ROSTER ROW IS SKIPPED, NOT PARKED.
//
// The roster is a projection, so it can name a membership whose stream is empty
// — a rebuild in flight, a truncated table refilling. The aggregate rejects a
// removal from a team somebody was never in, and letting that through would park
// the WHOLE departure on a row that is not coming back, leaving every other team
// attached behind it.
func TestAStaleRosterRowDoesNotParkTheDeparture(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"

	real := h.joins(t, "engineering", leaver)
	// A team that exists with a membership stream that does not. Listed FIRST,
	// so a departure that failed on it would never reach the real one.
	ghost := h.create(t, "ghost")
	h.teamRoster.teams[inviteWS] = append([]string{ghost.TeamID}, h.teamRoster.teams[inviteWS]...)

	if err := h.departures.Depart(context.Background(), inviteWS, leaver); err != nil {
		t.Fatalf("a stale roster row parked the departure: %v; every team after it in the "+
			"list keeps its membership", err)
	}
	if h.isInTeam(t, real, leaver) {
		t.Error("the real membership survived a departure that a ghost row interrupted")
	}
}

// EACH REMOVAL GETS ITS OWN IDEMPOTENCY KEY.
//
// Asserted on the derived EVENT IDS, because that is what the key becomes:
// Repository.Save runs it through DeriveEventID, and the store deduplicates on
// the id. One key shared across a person's teams therefore does not merely look
// untidy — the first removal lands and every subsequent one is discarded as a
// duplicate, silently, leaving somebody in every team but the first.
//
// The fake store does not model that dedup, so nothing else in this file can see
// it. This checks the property the real store would enforce.
func TestEachRemovalGetsItsOwnEventID(t *testing.T) {
	h := newDepartureHarness(t)
	const leaver = "subj_leaver0000000000000000"

	engineering := h.joins(t, "engineering", leaver)
	design := h.joins(t, "design", leaver)

	if err := h.departures.Depart(context.Background(), inviteWS, leaver); err != nil {
		t.Fatal(err)
	}

	ids := map[ids.EventID]string{}
	for _, teamID := range []string{engineering, design} {
		key := eventsourcing.StreamID(domain.TeamMembershipCategory) + "-" +
			eventsourcing.StreamID(domain.TeamMembershipStreamKey(teamID, leaver))
		events := h.store.streams[key]
		if len(events) != 2 {
			t.Fatalf("%s holds %d events, want 2 (added, removed)", teamID, len(events))
		}
		removal := events[1]
		if other, clash := ids[removal.ID]; clash {
			t.Fatalf("the removals from %s and %s derive the SAME event id %s; against the "+
				"real store the second is discarded as a duplicate and that person stays "+
				"in every team but the first", other, teamID, removal.ID)
		}
		ids[removal.ID] = teamID
	}
}
