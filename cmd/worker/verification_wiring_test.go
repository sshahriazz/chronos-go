package main

import (
	"context"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	identityreactor "github.com/chronos/chronos-go/internal/modules/identity/reactor"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// A reactor that no binary registers delivers nothing, silently — the failure
// this repository has already shipped three times, and the one that left
// EmailVerificationRequested with no consumer at all: registration minted a
// token, stored its digest, appended the event, and the plaintext reached
// nobody. Every unit test below passed throughout.
//
// Only a test of the COMPOSITION ROOT can see it, which is what this is.
func TestVerificationMailIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.verification == nil {
		t.Fatal("no verification issuer was constructed; nothing can mint the emailed " +
			"link, so every registration claims an address and mails nobody")
	}

	found := find(reactors(newCodec(), d), identityreactor.VerificationReactorName)
	if found == nil {
		t.Fatalf("the worker registers no %q reactor: EmailVerificationRequested is "+
			"consumed by nothing and no verification link is ever sent",
			identityreactor.VerificationReactorName)
	}

	// The filter is what the subscription is created with. A wrong one is not a
	// crash: the group simply never receives the event it exists for.
	prefixes := found.Filter().EventTypePrefixes
	if len(prefixes) != 1 || prefixes[0] != "identity.EmailVerificationRequested.v1" {
		t.Errorf("the registered reactor subscribes to %v, not to the verification "+
			"request", prefixes)
	}
}

// The reactor decodes with identity's codec, not the notification one. If it
// were handed newCodec, every verification event would fail to decode and park —
// visibly, but only after the fact, and only for events that already happened.
func TestVerificationMailCanDecodeItsOwnEvent(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	r, err := newVerificationMail(d)
	if err != nil {
		t.Fatalf("building the verification mail: %v", err)
	}

	// A well-formed event whose subject is empty. The reactor decodes it and
	// refuses it for the missing subject — and refusing it for THAT reason is the
	// proof: a reactor holding the wrong codec cannot get far enough to look at
	// the subject, and fails while decoding instead. Nothing is minted or sent on
	// this path, so the assertion costs no side effects.
	event := &contract.EmailVerificationRequested{RequestedAt: time.Now().UTC()}
	codec, _ := newIdentityCodec()
	payload, err := codec.Marshal(event)
	if err != nil {
		t.Fatalf("encoding the probe event: %v", err)
	}

	err = r.React(context.Background(), eventsourcing.Envelope{
		ID:      ids.MustParse[ids.Event]("evt_01H8XG5N2QK7VB3C9WPYZR4TFP"),
		Type:    event.EventType(),
		Payload: payload,
	})
	if err == nil || !strings.Contains(err.Error(), "records no subject") {
		t.Fatalf("the registered reactor could not decode its own event: %v", err)
	}
}

// Durable work is off by default. The verification mail must still be delivered
// then — inline, through the same dispatcher — because a deployment without
// Temporal that silently sends nothing is the worst outcome available here.
func TestVerificationMailDeliversWithoutDurableWork(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.temporal != nil {
		t.Fatal("a Temporal client was built with TEMPORAL_ENABLED=false")
	}
	r, err := newVerificationMail(d)
	if err != nil {
		t.Fatalf("building the verification mail: %v", err)
	}
	if r.Durable() {
		t.Error("the reactor claims durable delivery with no Temporal client wired")
	}
}

func find(rs []reactor.Reactor, name string) reactor.Reactor {
	for _, r := range rs {
		if r.Name() == name {
			return r
		}
	}
	return nil
}
