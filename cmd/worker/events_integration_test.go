//go:build integration

package main

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	smtpadapter "github.com/chronos/chronos-go/internal/adapter/smtp"
	identityevents "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// The gap this file closes, proven end to end against running infrastructure.
//
// Identity emitted twenty-nine event types and the catalogue contained no entry
// for any of them, so the nine Sec-class alerts NOTIFICATIONS §5 specifies —
// among them the one that tells a victim their second factor was just turned
// off — reached nobody. Every unit test passed throughout, because the guard
// that was supposed to catch it verified the catalogue against the five types
// the worker happened to register.
//
// So the claim under test here is not "the catalogue has entries". It is: an
// identity event goes in at one end and a real message comes out of a real SMTP
// server at the other, through the same catalogue, codec, audience resolver,
// dispatcher, renderer and transport the worker binary runs.
func TestIdentitySecurityAlertsReachMailpit(t *testing.T) {
	tests := []struct {
		name string

		// event is exactly the type identity appends, decoded by the real codec.
		event eventsourcing.Event

		// wantSubject is a fragment of the rendered Subject header, so a
		// catalogue entry pointed at the wrong template fails here rather than
		// passing on "some mail arrived".
		wantSubject string

		// wantBody is a fragment that can only come from the event's own data,
		// so a Data function that stopped extracting is caught too.
		wantBody string
	}{
		{
			name: "the second factor was turned off",
			event: &identityevents.TotpDisabled{
				SubjectID: "", CredentialID: "cred_1",
				ActorID: "", DisabledAt: time.Now().UTC(),
			},
			wantSubject: "Two-factor authentication was turned off",
			wantBody:    "protected by your password alone",
		},
		{
			name: "the password changed",
			event: &identityevents.PasswordChanged{
				CredentialID: "cred_1", ViaReset: true, ChangedAt: time.Now().UTC(),
			},
			wantSubject: "password was changed",
			// ViaReset must reach the template: the wording for a reset and for
			// a change made with the old password is not the same message.
			wantBody: "reset link rather than by someone who knew the old",
		},
		{
			name: "a recovery code was used and few remain",
			event: &identityevents.RecoveryCodeConsumed{
				CredentialID: "cred_1", Remaining: 1, ConsumedAt: time.Now().UTC(),
			},
			wantSubject: "recovery code was used",
			wantBody:    "You are running low",
		},
		{
			name: "an unrecognised device signed in",
			event: &identityevents.DeviceRegistered{
				DeviceID: "dev_1", RegisteredAt: time.Now().UTC(),
			},
			wantSubject: "device we haven't seen before",
			wantBody:    "only the first time a device is used",
		},
		{
			name: "the account was suspended",
			event: &identityevents.UserSuspended{
				ActorID: "sub_operator", Reason: "abuse", SuspendedAt: time.Now().UTC(),
			},
			wantSubject: "has been suspended",
			wantBody:    "cannot lift this yourself",
		},
		{
			name: "the address was proven, so the welcome goes out",
			event: &identityevents.EmailVerified{
				Index: "idx_x", VerifiedAt: time.Now().UTC(),
			},
			wantSubject: "Welcome to Chronos",
			wantBody:    "Turn on two-factor authentication",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 40*time.Second)
			defer cancel()

			// A unique address per case, so an assertion cannot pass on a
			// message an earlier run left in the mailbox.
			to := uniqueAddress(t)
			subjectID := uniqueSubject(t)

			transport, err := mailpitTransport(ctx, to)
			if err != nil {
				t.Fatalf("mail transport: %v", err)
			}
			r := notify.NewEventReactor(
				notificationReactorName, notifications(), newCodec(),
				// nil members: these cases are identity events, which resolve
				// AudienceSubject from the envelope. Passing a resolver would
				// suggest this test exercises one.
				audiences("", nil), transport.dispatcher)

			env, _ := identityEnvelope(t, tt.event, subjectID, "evt-"+to)
			if err := r.React(ctx, env); err != nil {
				t.Fatalf("React: %v", err)
			}

			msg := waitForMailpitMessage(ctx, t, to)

			if !strings.Contains(msg.Subject, tt.wantSubject) {
				t.Errorf("subject %q does not contain %q — the catalogue entry names "+
					"the wrong template", msg.Subject, tt.wantSubject)
			}
			if msg.Text == "" || msg.HTML == "" {
				t.Error("a part is missing; HTML-only mail is a deliverability problem")
			}
			if !strings.Contains(msg.Text, tt.wantBody) {
				t.Errorf("the plaintext body does not contain %q:\n%s", tt.wantBody, msg.Text)
			}
			// Security and Transactional mail carries no opt-out. A user who
			// could unsubscribe from "your second factor was disabled" could be
			// unsubscribed by the attacker who disabled it (NOTIFICATIONS §3).
			if strings.Contains(strings.ToLower(msg.HTML), "unsubscribe") {
				t.Error("an account-safety message carried an unsubscribe link")
			}
		})
	}
}

// Redelivery, through the real machinery that is supposed to stop it.
//
// The reactor is a persistent subscription with at-least-once delivery, so the
// same event WILL arrive twice — after a rebalance, after a process restart,
// after an ack that did not land. Sending a second "your password was changed"
// is not a cosmetic fault: it is indistinguishable, to the reader, from a second
// password change.
//
// This drives the real reactor.Runner with the real Postgres dedup table under
// the real reactor name, delivering one identical event twice, and asserts that
// exactly ONE message exists in Mailpit afterwards. Nothing about the catalogue
// entries participates in the guarantee, which is the point: every entry
// inherits it.
func TestARedeliveredIdentityEventIsNotMailedTwice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	cfg := integrationConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()
	if d.pool == nil {
		t.Fatal("no PostgreSQL pool: the reactor dedup table is what suppresses a redelivery")
	}

	to := uniqueAddress(t)
	transport, err := mailpitTransport(ctx, to)
	if err != nil {
		t.Fatalf("mail transport: %v", err)
	}

	codecJSON := newCodec()
	r := notify.NewEventReactor(
		notificationReactorName, notifications(), codecJSON,
		audiences("", nil), transport.dispatcher)

	_, recorded := identityEnvelope(t, &identityevents.TotpDisabled{
		CredentialID: "cred_redelivery", DisabledAt: time.Now().UTC(),
	}, uniqueSubject(t), "evt-redelivery-"+to)

	// A group name of its own. `notificationReactorName` is shared with the
	// running worker, and a dedup row it had already written for this id would
	// make the test pass without proving anything — while a row THIS test wrote
	// under the real name would make the worker skip a real event later.
	group := "notifications-redelivery-" + to

	// The subscriber hands the runner the SAME recorded event twice, which is
	// exactly what a redelivering persistent subscription does.
	sub := &replayingSubscriber{
		events:  []eventsourcing.RecordedEvent{recorded, recorded},
		drained: make(chan struct{}),
	}
	runner := reactor.NewRunner(namedReactor{EventReactor: r, name: group}, reactor.Deps{
		Subscriber: sub,
		Codec:      codecJSON,
		Dedup:      pgadapter.NewDedup(pgadapter.New(d.pool)),
		Log:        slog.New(slog.DiscardHandler),
		Clock:      clock.System{},
		Retry:      time.Hour, // one pass; the test ends it
	})

	runCtx, stopRunner := context.WithCancel(ctx)
	done := make(chan error, 1)
	go func() { done <- runner.Run(runCtx) }()

	select {
	case <-sub.drained:
	case <-ctx.Done():
		t.Fatal("the subscriber never finished delivering both copies")
	}
	for i, err := range sub.errs {
		if err != nil {
			t.Fatalf("delivery %d failed: %v", i+1, err)
		}
	}

	// The first delivery must actually produce mail, or "exactly one" would be
	// satisfied by a reactor that sent nothing at all.
	waitForMailpitMessage(ctx, t, to)
	stopRunner()
	<-done

	// Mailpit is already holding the first message, so any second one has had
	// its full delivery path completed by now. A short settle makes that
	// argument robust rather than merely likely.
	if !sleepCtx(ctx, 2*time.Second) {
		t.Fatal("context ended before the settle window")
	}

	if got := countMailpitMessages(ctx, t, to); got != 1 {
		t.Fatalf("%d messages reached the mailbox for one event delivered twice; the "+
			"reactor dedup did not suppress the redelivery, so every catalogue entry "+
			"can double-send after a rebalance", got)
	}
}

// ---------------------------------------------------------------------------
// harness
// ---------------------------------------------------------------------------

// integrationConfig loads the AMBIENT configuration, unlike testConfig, which
// substitutes placeholder credentials.
//
// This test issues real queries, so the placeholders would fail SASL auth as
// `chronos_app` — a failure that surfaces as "no message arrived in Mailpit"
// and reads exactly like a broken catalogue. `make test-integration` sources
// .env for this reason.
func integrationConfig(t *testing.T) *config.Config {
	t.Helper()
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v (run through `make test-integration`, which sources .env)", err)
	}
	return cfg
}

// namedReactor renames a reactor without touching the catalogue.
//
// The name is the dedup key's namespace and the subscription group, and the
// real one is PERMANENT (ADR-019) — writing test rows under it would make the
// running worker skip a genuine event.
type namedReactor struct {
	*notify.EventReactor
	name string
}

func (n namedReactor) Name() string { return n.name }

// replayingSubscriber delivers a fixed list of events once, then holds the
// subscription open until the test ends — the shape a real persistent
// subscription has, and the shape reactor.Runner is written against.
type replayingSubscriber struct {
	events  []eventsourcing.RecordedEvent
	drained chan struct{}

	// errs is what the runner returned for each delivery. Recorded rather than
	// discarded: a test that swallows the handler's error reports "no message
	// arrived" for a delivery that failed for a reason it was holding all along.
	errs []error
}

func (s *replayingSubscriber) Consume(
	ctx context.Context, _ string, _ eventsourcing.SubscriptionFilter, h eventsourcing.Handler,
) error {
	for _, e := range s.events {
		// A handler error is the server's to retry, not ours to stop on — the
		// runner treats it the same way. It is kept so the test can report it.
		s.errs = append(s.errs, h(ctx, e))
	}
	close(s.drained)
	<-ctx.Done()
	return ctx.Err()
}

// mailpitHarness is a dispatcher wired the way the worker wires one, with the
// vault replaced.
//
// The vault is the ONE substitution, and it has to be: contact details are
// resolved from the PII vault at delivery time (ADR-002), and a synthetic
// subject has no vault record. Everything downstream of it — the class policy,
// the renderer, the embedded templates, SMTP — is the real thing.
type mailpitHarness struct {
	dispatcher *notify.Dispatcher
}

func mailpitTransport(ctx context.Context, address string) (mailpitHarness, error) {
	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Name: "Chronos", Email: "no-reply@chronos.local"},
		BaseURL: "http://localhost:3000",
	})
	if err := renderer.Load(ctx); err != nil {
		return mailpitHarness{}, err
	}
	transport := mail.NewTransport(renderer,
		smtpadapter.New(smtpadapter.Config{Host: "localhost", Port: 1025, Domain: "chronos.local"}),
		clock.System{}, nil)

	return mailpitHarness{dispatcher: notify.NewDispatcher(notify.Deps{
		Vault:      fixedVault{address: address, name: "Robin Ash", locale: "en", tz: "UTC"},
		Transports: []notify.Transport{transport},
		Log:        slog.New(slog.DiscardHandler),
	})}, nil
}

type fixedVault struct{ address, name, locale, tz string }

func (v fixedVault) Resolve(context.Context, string) (notify.Recipient, error) {
	return notify.Recipient{
		Address: v.address, Name: v.name, Locale: v.locale, Timezone: v.tz,
	}, nil
}

// identityEnvelope encodes an event with the REAL codec and wraps it the way
// the runner does, so a type the worker cannot decode fails here.
func identityEnvelope(
	t *testing.T, event eventsourcing.Event, subjectID, idempotencyKey string,
) (eventsourcing.Envelope, eventsourcing.RecordedEvent) {
	t.Helper()

	c := newCodec()
	payload, err := c.Marshal(event)
	if err != nil {
		t.Fatalf("the worker's codec cannot encode %s: %v", event.EventType(), err)
	}
	meta := eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    time.Now().UTC(),
		SubjectIDs:    []string{subjectID},
		ActorID:       subjectID,
	}
	rawMeta, err := c.MarshalMetadata(meta)
	if err != nil {
		t.Fatalf("metadata: %v", err)
	}

	id := eventsourcing.DeriveEventID(idempotencyKey, 0)
	stream, err := eventsourcing.NewStreamID(eventsourcing.Category("identity"), subjectID)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}

	return eventsourcing.Envelope{
		ID: id, Type: event.EventType(), Stream: stream, Meta: meta, Payload: payload,
	}, eventsourcing.RecordedEvent{
		ID: id, Type: event.EventType(), Stream: stream,
		Payload: payload, Metadata: rawMeta, CreatedAt: time.Now().UTC(),
	}
}

func uniqueAddress(t *testing.T) string {
	t.Helper()
	return fmt.Sprintf("notify+%d@example.test", time.Now().UnixNano())
}

func uniqueSubject(t *testing.T) string {
	t.Helper()
	// A pseudonym, not a real subject: the vault is stubbed, and ADR-002 means
	// nothing downstream may derive anything from its shape.
	return fmt.Sprintf("sub_test_%d", time.Now().UnixNano())
}

func sleepCtx(ctx context.Context, d time.Duration) bool {
	select {
	case <-ctx.Done():
		return false
	case <-time.After(d):
		return true
	}
}

// ---------------------------------------------------------------------------
// Mailpit
// ---------------------------------------------------------------------------

type mailpitMessage struct {
	Subject string
	Text    string
	HTML    string
}

func mailpitGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8025"+path, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

func waitForMailpitMessage(ctx context.Context, t *testing.T, to string) mailpitMessage {
	t.Helper()
	deadline := time.Now().Add(25 * time.Second)
	for time.Now().Before(deadline) {
		if ids := mailpitIDs(ctx, to); len(ids) > 0 {
			return fetchMailpitMessage(ctx, t, ids[0])
		}
		if !sleepCtx(ctx, 300*time.Millisecond) {
			t.Fatal("context ended while waiting for the message")
		}
	}
	t.Fatalf("no message for %s arrived in Mailpit; the event was accepted and "+
		"nobody was told", to)
	return mailpitMessage{}
}

func countMailpitMessages(ctx context.Context, t *testing.T, to string) int {
	t.Helper()
	return len(mailpitIDs(ctx, to))
}

func mailpitIDs(ctx context.Context, to string) []string {
	resp, err := mailpitGet(ctx, "/api/v1/search?query="+url.QueryEscape("to:"+to))
	if err != nil {
		return nil
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil
	}
	// Tolerant, and it has to be: Mailpit returns a dozen fields this test does
	// not model, and a strict decode would report "nothing arrived" for mail
	// that arrived fine.
	out, err := codec.Tolerant[struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}](body)
	if err != nil {
		return nil
	}
	ids := make([]string, 0, len(out.Messages))
	for _, m := range out.Messages {
		ids = append(ids, m.ID)
	}
	return ids
}

func fetchMailpitMessage(ctx context.Context, t *testing.T, id string) mailpitMessage {
	t.Helper()
	resp, err := mailpitGet(ctx, "/api/v1/message/"+id)
	if err != nil {
		t.Fatalf("fetching message: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading message: %v", err)
	}
	out, err := codec.Tolerant[struct {
		Subject string `json:"Subject"`
		Text    string `json:"Text"`
		HTML    string `json:"HTML"`
	}](body)
	if err != nil {
		t.Fatalf("decoding message: %v", err)
	}
	return mailpitMessage{Subject: out.Subject, Text: out.Text, HTML: out.HTML}
}
