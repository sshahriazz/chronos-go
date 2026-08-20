package main

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// THE test. Every event this binary can decode must have a notification
// decision recorded against it — either it notifies someone, or it is declared
// silent with a reason.
//
// Without this, adding an event type is enough to create a notification nobody
// ever receives and nothing ever reports. That failure is invisible in
// production: no error, no metric, no log line — just a user asking why they
// were never told their password changed.
func TestEveryEventHasANotificationDecision(t *testing.T) {
	codec := newCodec()
	cat := notifications()

	if err := cat.Verify(codec.Types()); err != nil {
		t.Fatalf(`%v

Fix by adding ONE of these to cmd/worker/events.go:

    cat.On[modulepkg.TheEvent](notify.Spec{
        Template: "module.the_event",
        Class:    notify.Security,        // or Transactional / Activity / Product / Operator
        Audience: notify.AudienceSubject, // who receives it
    }, func(e *modulepkg.TheEvent) map[string]any { ... })

    cat.Silent[modulepkg.TheEvent]("why nobody needs to hear about this")`, err)
	}
}

// A renamed or retired event leaves its notification behind, pointing at
// something that can no longer arrive. The entry then looks like coverage while
// covering nothing.
func TestNoOrphanedCatalogueEntries(t *testing.T) {
	codec := newCodec()
	cat := notifications()

	if orphans := cat.Orphans(codec.Types()); len(orphans) > 0 {
		t.Fatalf("the catalogue notifies on %v, which the codec cannot decode. "+
			"Either the event was renamed and the entry was not, or it was retired "+
			"and the entry outlived it", orphans)
	}
}

// Every template the catalogue names must exist. A missing one fails at
// DELIVERY time — the moment somebody needs the message — and by then the event
// is long past.
func TestEveryCatalogueTemplateExists(t *testing.T) {
	cat := notifications()
	templates := cat.Templates()
	if len(templates) == 0 {
		t.Skip("no notifications declared yet")
	}

	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Email: "no-reply@chronos.local"},
		BaseURL: "http://localhost:3000",
	})
	if err := renderer.Load(context.Background()); err != nil {
		t.Fatalf("loading templates: %v", err)
	}

	available := map[string]struct{}{}
	for _, name := range renderer.Templates() {
		available[name] = struct{}{}
	}
	for _, want := range templates {
		if _, ok := available[want]; !ok {
			t.Errorf("the catalogue names template %q, which does not exist in "+
				"internal/adapter/mailrender/templates", want)
		}
	}
}

// The guard above is only worth having if it actually fires. This proves the
// mechanism on a fixture, so a trivially-empty catalogue cannot make the real
// test pass vacuously.
func TestVerificationActuallyFires(t *testing.T) {
	codec := eventcodec.NewJSON(nil)
	eventcodec.Register[undecidedEvent](codec)

	err := notifications().Verify(codec.Types())
	if err == nil {
		t.Fatal("an event with no decision passed verification; the guard does not work")
	}
	if !strings.Contains(err.Error(), "test.Undecided.v1") {
		t.Errorf("the failure must name the offending type, got: %v", err)
	}
}

type undecidedEvent struct{}

func (*undecidedEvent) EventType() string { return "test.Undecided.v1" }

// Operator alerts have nowhere to go unless an address is configured. The
// reactor parks them rather than dropping them, but an empty configuration
// makes that certain — better to know here.
func TestOperatorRecipients(t *testing.T) {
	if got := operatorRecipients(""); len(got) != 0 {
		t.Errorf("an unset operator address must yield no recipients, got %v", got)
	}
	got := operatorRecipients("ops@chronos.local")
	if len(got) != 1 || got[0].Address != "ops@chronos.local" {
		t.Fatalf("got %v", got)
	}
	// Operator mail must never be addressed to a tenant subject.
	if got[0].SubjectID != "" {
		t.Error("an operator recipient must carry no tenant subject id")
	}
}

// The subscription filter must never be empty-meaning-everything: a
// notification reactor with nothing registered would otherwise wake on every
// event in the system.
func TestEmptyCatalogueDoesNotSubscribeToEverything(t *testing.T) {
	r := notify.NewEventReactor("notifications", notify.NewCatalogue(), newCodec(),
		notify.SubjectAudiences{}, nil)

	f := r.Filter()
	if len(f.EventTypePrefixes) == 0 && len(f.StreamPrefixes) == 0 {
		t.Fatal("an empty catalogue produced a filter with no prefixes, which means " +
			"'no filter' — the reactor would be handed every event in the system")
	}
}

// An audience a catalogue entry uses but nothing can answer parks every
// notification that needs it. Better caught here than by a user asking why they
// were never told.
func TestEveryAudienceInUseHasAResolver(t *testing.T) {
	cat := notifications()
	reg := audiences("ops@chronos.local")

	for _, event := range cat.Events() {
		spec, _ := cat.For(event)
		_, err := reg.Resolve(context.Background(), spec.Audience, eventsourcing.Envelope{
			Meta: eventsourcing.Metadata{OrgID: "org_probe", SubjectIDs: []string{"sub_probe"}, ActorID: "sub_probe"},
		})
		if errors.Is(err, notify.ErrAudienceUnsupported) {
			t.Errorf("%s notifies the %s audience, but nothing can resolve it — "+
				"every one of those notifications will park. Either wire a resolver "+
				"in audiences(), or change the audience", event, spec.Audience)
		}
	}
}
