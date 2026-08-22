package reactor

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

type recordedDeparture struct{ workspaceID, subjectID string }

type fakeDepartures struct {
	seen []recordedDeparture
	err  error
}

func (f *fakeDepartures) Depart(_ context.Context, workspaceID, subjectID string) error {
	f.seen = append(f.seen, recordedDeparture{workspaceID, subjectID})
	return f.err
}

func removal(t *testing.T, seatReleased bool) eventsourcing.Envelope {
	t.Helper()
	codec := testCodec(t)
	event := &contract.MemberRemoved{
		WorkspaceID: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		OrgID:       "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		SubjectID:   "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		RemovedAt:   time.Unix(1_700_000_000, 0).UTC(),

		SeatReleased: seatReleased,
	}
	payload, err := codec.Marshal(event)
	if err != nil {
		t.Fatal(err)
	}
	return eventsourcing.Envelope{Type: event.EventType(), Payload: payload}
}

// A REMOVAL STRIPS THE WORKSPACE'S TEAMS.
func TestARemovalDrivesTheCascade(t *testing.T) {
	departures := &fakeDepartures{}
	r, err := NewTeamDeparture(departures, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := r.React(context.Background(), removal(t, true)); err != nil {
		t.Fatal(err)
	}
	if len(departures.seen) != 1 {
		t.Fatalf("drove the cascade %d times, want once", len(departures.seen))
	}
	got := departures.seen[0]
	if got.workspaceID != "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV" ||
		got.subjectID != "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV" {
		t.Errorf("cascaded for %+v, want the workspace and subject the event names", got)
	}
}

// EVERY REMOVAL, NOT ONLY THE ONES THAT RELEASE A SEAT.
//
// The discriminator against InviterDeparture, which subscribes to the same event
// and DOES ignore a removal with SeatReleased=false because its rule is per
// ORGANIZATION. This rule is per WORKSPACE: somebody removed from one workspace
// while remaining in another has left that workspace's teams, and their seat is
// irrelevant to it.
//
// Asserted separately because copying the sibling reactor's filter is the
// obvious mistake, and it fails silently — the majority of removals in a
// multi-workspace organization release no seat, so most of the cascade would
// simply never run.
func TestARemovalThatReleasesNoSeatStillStripsTeams(t *testing.T) {
	departures := &fakeDepartures{}
	r, err := NewTeamDeparture(departures, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := r.React(context.Background(), removal(t, false)); err != nil {
		t.Fatal(err)
	}
	if len(departures.seen) != 1 {
		t.Fatalf("a removal that released no seat drove the cascade %d times, want once; "+
			"somebody who moved between workspaces keeps the teams of the one they left",
			len(departures.seen))
	}
}

// A FAILING CASCADE PARKS THE EVENT.
//
// Swallowing the error would ack a removal whose teams are still attached, and
// nothing would ever come back to it.
func TestAFailingCascadeIsReported(t *testing.T) {
	departures := &fakeDepartures{err: errors.New("postgres: connection refused")}
	r, err := NewTeamDeparture(departures, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := r.React(context.Background(), removal(t, true)); err == nil {
		t.Fatal("a failed cascade was acked; the removal's teams stay attached and nothing " +
			"retries")
	}
}

// AN EVENT WITH NO SUBJECT IS POISON, NOT A FAILURE.
//
// Retrying re-reads the same bytes, so it would park forever. Worse, an empty
// subject reaching the query would list every membership in the workspace whose
// subject column happens to be empty.
func TestAnIncompleteRemovalIsPoison(t *testing.T) {
	codec := testCodec(t)

	for name, event := range map[string]*contract.MemberRemoved{
		"no workspace": {SubjectID: "subj_x", OrgID: "org_x"},
		"no subject":   {WorkspaceID: "ws_x", OrgID: "org_x"},
	} {
		t.Run(name, func(t *testing.T) {
			payload, err := codec.Marshal(event)
			if err != nil {
				t.Fatal(err)
			}
			departures := &fakeDepartures{}
			r, err := NewTeamDeparture(departures, codec)
			if err != nil {
				t.Fatal(err)
			}

			err = r.React(context.Background(), eventsourcing.Envelope{
				Type: event.EventType(), Payload: payload,
			})
			if !errors.Is(err, eventsourcing.ErrPoison) {
				t.Errorf("returned %v, want ErrPoison — a retry re-reads the same bytes and "+
					"this parks forever", err)
			}
			if len(departures.seen) != 0 {
				t.Error("an incomplete event reached the cascade")
			}
		})
	}
}

// AN UNEXPECTED TYPE IS IGNORED, NOT ACTED ON.
//
// The filter can over-deliver, and a group can predate a filter change. Acting
// on whatever arrives would let a filter change strip live memberships.
func TestAnUnexpectedEventStripsNothing(t *testing.T) {
	departures := &fakeDepartures{}
	r, err := NewTeamDeparture(departures, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}

	if err := r.React(context.Background(), eventsourcing.Envelope{
		Type: "workspace.TeamCreated.v1", Payload: []byte(`{}`),
	}); err != nil {
		t.Fatalf("an over-delivered event errored: %v; the group stalls on something that "+
			"is not its business", err)
	}
	if len(departures.seen) != 0 {
		t.Error("an unrelated event drove the cascade")
	}
}

// THE FILTER NAMES THE ONE EVENT.
//
// It fails INDEPENDENTLY of React: every branch above can be correct and never
// run, and a reactor that matches nothing looks exactly like a quiet system.
func TestTheTeamDepartureFilterNamesTheRemoval(t *testing.T) {
	r, err := NewTeamDeparture(&fakeDepartures{}, testCodec(t))
	if err != nil {
		t.Fatal(err)
	}
	got := r.Filter().EventTypePrefixes
	want := (&contract.MemberRemoved{}).EventType()

	if len(got) != 1 || got[0] != want {
		t.Fatalf("the filter is %v, want exactly [%s]; anything else either misses removals "+
			"or subscribes this group to work that is not its own", got, want)
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
//
// A nil port produces a reactor that consumes the event, does nothing and acks —
// indistinguishable at runtime from the gap it exists to close.
func TestTeamDepartureRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := NewTeamDeparture(nil, testCodec(t)); err == nil {
		t.Error("a reactor with no departures port was accepted; it would ack every removal " +
			"having stripped nothing")
	}
	if _, err := NewTeamDeparture(&fakeDepartures{}, nil); err == nil {
		t.Error("a reactor with no codec was accepted; every removal parks")
	}
}
