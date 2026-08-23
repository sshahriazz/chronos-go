package main

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	workspacereactor "github.com/chronos/chronos-go/internal/modules/workspace/reactor"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// A reactor no binary registers delivers nothing, silently.
//
// It is the failure this repository has already shipped several times, and here
// it is worse than usual: issuing an invitation SPENDS A SEAT. With no consumer
// for InvitationIssued the organization is charged, the invitation sits pending
// for seven days, and the person it was for never learns it exists — with no
// error, no parked event and no metric anywhere.
//
// Only a test of the COMPOSITION ROOT can see it.
func TestInvitationMailIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.invitations == nil {
		t.Fatal("no invitation issuer was constructed; nothing can mint the emailed link, " +
			"so every invitation spends a seat and mails nobody")
	}

	found := find(reactors(newCodec(), d), workspacereactor.InvitationReactorName)
	if found == nil {
		t.Fatalf("the worker registers no %q reactor: InvitationIssued is consumed by "+
			"nothing and no invitation link is ever sent",
			workspacereactor.InvitationReactorName)
	}

	// The filter is what the subscription is created with. A wrong one is not a
	// crash: the group simply never receives the events it exists for — and here
	// there are TWO, because a resend has to mail as well as an issue.
	prefixes := found.Filter().EventTypePrefixes
	want := map[string]bool{
		(&contract.InvitationIssued{}).EventType():       false,
		(&contract.InvitationTokenRotated{}).EventType(): false,
	}
	for _, p := range prefixes {
		if _, ok := want[p]; !ok {
			t.Errorf("the registered reactor also subscribes to %q, which is not a sending "+
				"event; on this stream everything else is a settlement", p)
			continue
		}
		want[p] = true
	}
	for eventType, seen := range want {
		if !seen {
			t.Errorf("the registered reactor does not subscribe to %s, so that half of the "+
				"flow mails nobody", eventType)
		}
	}
}

// The reactor can DECODE its own event with the codec this binary hands it.
//
// What that catches is a codec carrying none of workspace's types — which is a
// live possibility, because the notification codec's type set comes from
// registerEvents and a module dropped from that list is a reactor whose every
// event parks, after its seats have already been spent.
//
// What it does NOT catch is stated rather than implied, and the mutation
// SURVIVES: handing the reactor newCodec() instead of workspaceCodec() passes
// this test. Both register workspace's whole type set, and they differ only in
// the upcaster registry — newCodec is built over a bare one, workspaceCodec over
// RegisterSchemas. At schema version 1 nothing needs upcasting, so no decode can
// tell them apart. Identity records exactly the same limitation about its own
// verification codec.
//
// Reaching that difference needs a stored event at an older version and an
// upcaster to lift it, which is a test to write when the first v2 event exists.
// Until then the registry is chosen correctly and asserted by reading, not by
// this test.
func TestInvitationMailCanDecodeItsOwnEvent(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	r, err := newInvitationMail(d)
	if err != nil {
		t.Fatalf("building the invitation mail: %v", err)
	}

	// A REAL event through the REAL codec this binary hands the reactor. React
	// returns a decode failure as poison, so an undecodable event is
	// distinguishable here from every other kind of failure.
	codec := workspaceCodec()
	issued := &contract.InvitationIssued{
		InvitationID: "inv_01H8XG5N2QK7VB3C9WPYZR4TFN",
		WorkspaceID:  "ws_01H8XG5N2QK7VB3C9WPYZR4TFK",
		OrgID:        "org_01H8XG5N2QK7VB3C9WPYZR4TFM",
		SubjectID:    "subj_01H8XG5N2QK7VB3C9WPYZR4TFP",
		EmailIndex:   "idx", InvitedBy: "subj_inviter",
		Role: contract.RoleMember, SeatConsumed: true,
		ExpiresAt: time.Now().Add(time.Hour), IssuedAt: time.Now(),
	}
	payload, err := codec.Marshal(issued)
	if err != nil {
		t.Fatal(err)
	}

	err = r.React(context.Background(), eventsourcing.Envelope{
		ID:      ids.New[ids.Event](time.Now(), ids.Entropy()),
		Type:    issued.EventType(),
		Payload: payload,
	})
	if err != nil && errors.Is(err, eventsourcing.ErrPoison) {
		t.Fatalf("the reactor could not DECODE its own event: %v\nEvery invitation would "+
			"park after its seat was already spent", err)
	}
	// Any other error is expected here: this test has no Postgres to mint a link
	// against. What it asserts is that the failure is not a decode failure.
}

// THE TEAM-DEPARTURE REACTOR IS REGISTERED.
//
// A reactor no binary registers delivers nothing, silently — and this one's
// silence is a permission that outlives its grant: everybody removed from a
// workspace keeps `team:x member user:y`, so the first thing ever shared with
// one of those teams reaches somebody who was removed. There is no error, no
// parked event and no metric; the graph simply answers a question with a
// membership nothing explains.
//
// Only a test of the COMPOSITION ROOT can see it. Every unit above it passes
// whether or not this line exists.
func TestTeamDepartureIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	found := find(reactors(newCodec(), d), workspacereactor.TeamDepartureReactorName)
	if found == nil {
		t.Fatalf("the worker registers no %q reactor: everybody removed from a workspace "+
			"stays in its teams, and the access graph keeps granting through them",
			workspacereactor.TeamDepartureReactorName)
	}

	// Its OWN group, not the inviter-departure one. They subscribe to the same
	// event and react to different subsets of it — that one ignores a removal
	// with SeatReleased=false, this one must not — so sharing a group would make
	// a failure in either park the other's work.
	if found.Name() == workspacereactor.DepartureReactorName {
		t.Error("the team cascade shares the inviter-departure group; a failure in either " +
			"now parks the other's work, and the two react to different subsets of the " +
			"same event")
	}

	want := (&contract.MemberRemoved{}).EventType()
	prefixes := found.Filter().EventTypePrefixes
	if len(prefixes) != 1 || prefixes[0] != want {
		t.Errorf("the registered reactor subscribes to %v, want exactly [%s]", prefixes, want)
	}
}

// THE ORGANIZATION-MEMBER AUDIENCE MUST BE WIRED IN THE BINARY.
//
// Suspension is the only thing that sends to it, and its failure is quiet in a
// way the others are not: with no resolver the notification PARKS — which is at
// least visible — but with the wiring absent nobody notices until a tenant is
// suspended and asks why nothing was said. Every member loses access; telling
// only the owner tells the one person who can fix it and nobody affected.
//
// Only a test of the COMPOSITION ROOT can see it. The resolver, the catalogue
// entry and the templates all pass their own tests while reaching nobody.
func TestTheOrgMemberAudienceIsWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	members := orgMembers(d, slog.New(slog.DiscardHandler))
	if members == nil {
		t.Fatal("the worker builds no organization-member audience; every suspension parks " +
			"instead of telling the members their access has ended")
	}

	reg := audiences(d.operator, members)
	if _, err := reg.Resolve(context.Background(), notify.AudienceOrgMembers,
		eventsourcing.Envelope{Meta: eventsourcing.Metadata{OrgID: "org_probe"}},
	); errors.Is(err, notify.ErrAudienceUnsupported) {
		t.Fatalf("the registry cannot resolve %s even with a resolver built: %v",
			notify.AudienceOrgMembers, err)
	}
}
