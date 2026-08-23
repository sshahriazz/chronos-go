package main

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	identityreactor "github.com/chronos/chronos-go/internal/modules/identity/reactor"
)

// THE EMAIL-CHANGE MAIL REACTOR IS REGISTERED, AND SUBSCRIBES TO BOTH EVENTS.
//
// # Why this test exists at all
//
// Three adapters in this repository were built, fully tested, and constructed by
// no binary; every component test passed while three notification channels
// delivered nothing. A reactor is the same shape of failure and a worse one,
// because there is no error, no parked event and no metric — the events are
// simply consumed by the projections and nobody is ever mailed.
//
// # What the absence costs, precisely
//
// A missing verification reactor strands people at signup, which they notice
// within a minute. A missing email-change reactor is silent to the person it
// harms: an attacker holding a session requests a change, the CURRENT address is
// never warned, and the account holder first learns when they can no longer sign
// in. identity.md §12 names that warning as the reason the flow is safe at all.
func TestTheEmailChangeMailReactorIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.verification == nil {
		t.Fatal("no token issuer was constructed; nothing can mint the change or revert " +
			"links, so a requested change can never be proven and a completed one can " +
			"never be undone")
	}

	found := find(reactors(context.Background(), newCodec(), d),
		identityreactor.EmailChangeReactorName)
	if found == nil {
		t.Fatalf("the worker registers no %q reactor: a requested address change mails "+
			"nobody, and the address being moved AWAY from is never warned",
			identityreactor.EmailChangeReactorName)
	}

	// The filter is what the subscription is created with. A wrong one is not a
	// crash: the group simply never receives the events it exists for.
	//
	// BOTH are required and they fail differently. Without the request type,
	// nobody is warned and no change can ever complete. Without the changed type,
	// a completed change sends NO revert link — which is the one message that
	// makes an account takeover recoverable.
	got := found.Filter().EventTypePrefixes
	for _, want := range []string{
		"identity.EmailChangeRequested.v1",
		"identity.EmailChanged.v1",
	} {
		if !slices.Contains(got, want) {
			t.Errorf("the registered reactor subscribes to %v and not to %q, so that "+
				"event is delivered to nothing", got, want)
		}
	}
	if len(got) != 2 {
		t.Errorf("the reactor subscribes to %v; a wider filter wakes the group for "+
			"events it has nothing to do with, and identity writes one on nearly "+
			"every authentication", got)
	}
}

// IT IS ITS OWN GROUP, NOT THE VERIFICATION MAIL'S.
//
// Sharing a group would mean a change mail that keeps failing parks the queue
// that carries verification links — and a verification link is the only way into
// a new account, so a stuck email-change campaign would stop every signup in the
// system.
func TestTheEmailChangeReactorHasItsOwnGroup(t *testing.T) {
	if identityreactor.EmailChangeReactorName == identityreactor.VerificationReactorName {
		t.Fatal("the email-change mail shares the verification mail's subscription " +
			"group; a change mail that keeps failing would park the queue that " +
			"carries every registration's verification link")
	}
}
