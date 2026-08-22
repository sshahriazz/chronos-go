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
