//go:build integration

package reactor

import (
	"context"
	"crypto/rand"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	smtpadapter "github.com/chronos/chronos-go/internal/adapter/smtp"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// The other half of ADR-055, proven against running infrastructure: a refused
// registration → DuplicateRegistrationAttempted → the notification catalogue →
// the template → SMTP → a real message in the address holder's mailbox.
//
// # Why this test lives in identity/reactor with no source file beside it
//
// Because there is no reactor to write. This message is delivered by the
// platform's ONE catalogue-driven reactor (notify.EventReactor), so the only
// things identity contributes are the event, the catalogue entry and the
// wording — and all three can be wrong in ways every unit test tolerates: an
// entry naming a template that does not exist fails at delivery time, and a
// template that renders is not the same as a template that says the right thing.
// The verification mail is proven the same way, one file over.
//
// # What it does NOT prove
//
// That cmd/worker carries this entry. That binary is not ours to edit and its
// own completeness guard (TestEveryEventHasANotificationDecision) fails until
// somebody adds it — deliberately, because a missing entry means nobody is told
// and nothing says so. This test proves the entry BELOW is the right one.
func TestDuplicateRegistrationNoticeReachesTheHoldersMailbox(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const baseURL = "http://localhost:3000"
	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Name: "Chronos", Email: "no-reply@chronos.local"},
		BaseURL: baseURL,
	})
	if err := renderer.Load(ctx); err != nil {
		t.Fatalf("templates: %v", err)
	}
	transport := mail.NewTransport(renderer,
		smtpadapter.New(smtpadapter.Config{Host: "localhost", Port: 1025, Domain: "chronos.local"}),
		clock.System{}, nil)

	// A unique address and a unique pseudonym per run, so the assertion cannot
	// pass on a message an earlier run left behind.
	to := fmt.Sprintf("holder+%d@example.test", time.Now().UnixNano())
	subject := fmt.Sprintf("subj_%d", time.Now().UnixNano())

	dispatcher := notify.NewDispatcher(notify.Deps{
		// The ONLY source of the address, consulted at delivery time. Nothing
		// upstream of this line — not the event, not the reactor, not the
		// catalogue — has ever seen it (ADR-002).
		Vault:      fixedVault{address: to, name: "Robin Ash", locale: "en", tz: "UTC"},
		Transports: []notify.Transport{transport},
	})

	reactor := notify.NewEventReactor(
		"identity-duplicate-registration-test",
		duplicateRegistrationCatalogue(),
		identityCodec(),
		notify.SubjectAudiences{},
		dispatcher,
	)
	if err := reactor.React(ctx, duplicateNoticeEnvelope(t, subject)); err != nil {
		t.Fatalf("React: %v", err)
	}

	msg := waitForMessage(ctx, t, to)

	if !strings.Contains(msg.Subject, "tried to sign up with your email address") {
		t.Errorf("subject: %q", msg.Subject)
	}
	if msg.Text == "" || msg.HTML == "" {
		t.Error("a part is missing; HTML-only mail is a deliverability problem")
	}
	// Security class carries no opt-out. An attacker who reached an account must
	// not be able to switch off the message that reveals them (NOTIFICATIONS §3).
	if strings.Contains(strings.ToLower(msg.HTML), "unsubscribe") {
		t.Error("the notice carried an unsubscribe link")
	}

	// The disclosure line, asserted in both directions.
	//
	// TOLD, because the message is delivered to the mailbox and reading it
	// already proves control of the address: an account exists here, and here is
	// how to get into it.
	for _, want := range []string{"already has one", "/sign-in", "/forgot-password"} {
		if !strings.Contains(msg.Text, want) {
			t.Errorf("the notice never says %q, so the person who owns this mailbox still "+
				"has no route to the account they already have:\n%s", want, msg.Text)
		}
	}
	// NOT TOLD. None of this is needed to get back into the account, and every
	// item is a fresh disclosure to whoever can read the mailbox — which includes
	// anyone who has already compromised it. The pseudonym in particular is an
	// internal identifier that appears in no other product surface.
	for _, forbidden := range []string{subject, "username", "handle", "created on", "two-factor"} {
		if strings.Contains(strings.ToLower(msg.Text), strings.ToLower(forbidden)) {
			t.Errorf("the notice discloses %q; the intended disclosure is the single fact "+
				"that an account exists here, and nothing beyond it", forbidden)
		}
	}
	// Nothing about the party who made the attempt, who is unauthenticated: their
	// address, their client and anything else they control would be
	// attacker-chosen text in somebody else's inbox.
	for _, forbidden := range []string{"198.51.100", "IP address", "user agent"} {
		if strings.Contains(msg.Text, forbidden) {
			t.Errorf("the notice describes the caller (%q); nothing about an unauthenticated "+
				"stranger may be repeated into a victim's mailbox", forbidden)
		}
	}
}

// duplicateRegistrationCatalogue is the ENTRY cmd/worker must carry, reproduced
// here so this test proves the exact spec being handed over rather than one
// invented for the occasion.
//
// Class Security, not Transactional: nobody asked for this message, and it is an
// account-safety signal — somebody is trying to create an account on an address
// that already has one. Security is unsuppressible, which is the property that
// matters: an attacker who reached the account must not be able to switch off
// the mail that reveals them.
//
// Audience Subject: the account that HOLDS the address, resolved from
// Metadata.SubjectIDs. Never Actor — the actor is unauthenticated and the event
// deliberately records nobody there.
//
// No Data function. The wording needs the recipient's name and the time, and the
// renderer supplies both from the vault and the envelope; the event carries
// nothing else that may be shown, which is the point of it carrying so little.
func duplicateRegistrationCatalogue() *notify.Catalogue {
	cat := notify.NewCatalogue()
	cat.On[contract.DuplicateRegistrationAttempted](notify.Spec{
		Template: "identity.duplicate_registration_attempted",
		Class:    notify.Security,
		Audience: notify.AudienceSubject,
	}, nil)
	return cat
}

// duplicateNoticeEnvelope is a real notice, encoded by the real codec, on the
// stream the use case appends it to.
func duplicateNoticeEnvelope(t *testing.T, subjectID string) eventsourcing.Envelope {
	t.Helper()
	now := time.Now().UTC()
	event := &contract.DuplicateRegistrationAttempted{
		Index:       contract.EmailIndex("idx_duplicate"),
		SubjectID:   subjectID,
		AttemptedAt: now,
	}
	payload, err := identityCodec().Marshal(event)
	if err != nil {
		t.Fatalf("encoding the event: %v", err)
	}
	return eventsourcing.Envelope{
		ID:      ids.New[ids.Event](now, rand.Reader),
		Type:    event.EventType(),
		Stream:  "reservation_email-idx_duplicate",
		Payload: payload,
		Meta: eventsourcing.Metadata{
			SubjectIDs: []string{subjectID},
			OccurredAt: now,
		},
	}
}
