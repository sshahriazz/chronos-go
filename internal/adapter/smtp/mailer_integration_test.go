//go:build integration

package smtp_test

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	smtpadapter "github.com/chronos/chronos-go/internal/adapter/smtp"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// The whole outbound path against a real SMTP server: dispatcher policy →
// template → MIME → SMTP → Mailpit. Everything below this test is unit-tested
// in isolation; this is the one that proves the pieces fit.
func TestNotificationReachesMailpit(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Name: "Chronos", Email: "no-reply@chronos.local"},
		BaseURL: "http://localhost:3000",
	})
	if err := renderer.Load(ctx); err != nil {
		t.Fatalf("templates: %v", err)
	}

	mailer := smtpadapter.New(smtpadapter.Config{Host: "localhost", Port: 1025, Domain: "chronos.local"})
	transport := mail.NewTransport(renderer, mailer, clock.System{}, nil)

	// A unique address per run, so the assertion cannot pass on a message left
	// behind by an earlier run.
	to := fmt.Sprintf("sam+%d@example.test", time.Now().UnixNano())

	d := notify.NewDispatcher(notify.Deps{
		Vault:      fixedVault{address: to, name: "Sam Larsson", locale: "en", tz: "Asia/Tokyo"},
		Transports: []notify.Transport{transport},
	})

	err := d.Dispatch(ctx, notify.Notification{
		Template:  "identity.password_changed",
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: "sub_test"},
		Data: map[string]any{
			"RevokeURL": "http://localhost:3000/revoke?t=abc",
			"Location":  "Berlin, Germany",
			"Device":    "Firefox on macOS",
		},
		OccurredAt:     time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC),
		IdempotencyKey: "evt_test_1",
	})
	if err != nil {
		t.Fatalf("dispatch: %v", err)
	}

	msg := waitForMessage(t, ctx, to)

	if !strings.Contains(msg.Subject, "password was changed") {
		t.Errorf("subject: %q", msg.Subject)
	}
	// 09:26 UTC is 18:26 in Tokyo. The vault supplied the timezone, and the
	// conversion happens at render time only (ADR-008).
	if !strings.Contains(msg.Text, "18:26") {
		t.Errorf("timestamp was not rendered in the recipient's timezone:\n%s", msg.Text)
	}
	if msg.HTML == "" {
		t.Error("no HTML part")
	}
	if msg.Text == "" {
		t.Error("no plaintext part — HTML-only mail is a deliverability problem")
	}
	// Security mail must offer no opt-out.
	if strings.Contains(strings.ToLower(msg.HTML), "unsubscribe") {
		t.Error("a security message carried an unsubscribe link")
	}
}

type mailpitMessage struct {
	Subject string
	Text    string
	HTML    string
}

func waitForMessage(t *testing.T, ctx context.Context, to string) mailpitMessage {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		id := findMessageID(t, to)
		if id != "" {
			return fetchMessage(t, id)
		}
		select {
		case <-ctx.Done():
			t.Fatal("context ended while waiting for the message")
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatalf("no message for %s arrived in Mailpit", to)
	return mailpitMessage{}
}

func findMessageID(t *testing.T, to string) string {
	t.Helper()
	resp, err := http.Get("http://localhost:8025/api/v1/search?query=" + to)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	// TOLERANT, and it has to be: this is Mailpit's response, and it carries a
	// dozen fields this test does not model. A strict decode would reject every
	// one of them and report "no message arrived" for mail that arrived fine.
	//
	// The tags spell the keys exactly as Mailpit writes them — v2 matches
	// case-sensitively, so `messages` and `ID` are no longer interchangeable
	// with any other casing.
	out, err := codec.Tolerant[struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}](body)
	if err != nil {
		return ""
	}
	if len(out.Messages) == 0 {
		return ""
	}
	return out.Messages[0].ID
}

func fetchMessage(t *testing.T, id string) mailpitMessage {
	t.Helper()
	resp, err := http.Get("http://localhost:8025/api/v1/message/" + id)
	if err != nil {
		t.Fatalf("fetching message: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading message: %v", err)
	}
	// TOLERANT for the same reason as above: Mailpit returns the whole message
	// record, and only three of its fields are asserted here.
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

type fixedVault struct {
	address, name, locale, tz string
}

func (v fixedVault) Resolve(context.Context, string) (notify.Recipient, error) {
	return notify.Recipient{Address: v.address, Name: v.name, Locale: v.locale, Timezone: v.tz}, nil
}
