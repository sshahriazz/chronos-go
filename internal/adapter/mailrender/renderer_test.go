package mailrender_test

import (
	"context"
	"maps"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

func newRenderer(t *testing.T) *mailrender.Renderer {
	t.Helper()
	r := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Name: "Chronos", Email: "no-reply@chronos.test"},
		BaseURL: "https://app.chronos.test",
	})
	if err := r.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	return r
}

// Every shipped template must render. A template that only breaks when someone
// resets their password is found by that person, not by us.
func TestEveryTemplateRenders(t *testing.T) {
	r := newRenderer(t)
	names := r.Templates()
	if len(names) == 0 {
		t.Fatal("no templates were loaded")
	}

	for _, name := range names {
		t.Run(name, func(t *testing.T) {
			msg, err := r.Render(context.Background(), mail.Request{
				Template: name,
				Class:    notify.Security,
				Recipient: notify.Recipient{
					SubjectID: "sub_1", Address: "user@example.test",
					Name: "Sam", Locale: "en", Timezone: "Europe/Berlin",
				},
				OccurredAt: time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC),
				Data: map[string]any{
					"VerifyURL": "https://app.chronos.test/verify?t=abc",
					"RevokeURL": "https://app.chronos.test/revoke?t=abc",
					"ExpiresIn": "1 hour",
					"Component": "projector", "Severity": "critical",
					"Summary": "identity_users stopped", "Detail": "column does not exist",

					// A time.Time, not a string. The `date` and `datetime`
					// helpers take one, so a template that formats a deadline
					// fails here on any other type — which is the point: this
					// fixture is the only place a template's data contract is
					// checked before a customer sees the result.
					"TrialEndsAt": time.Date(2026, 3, 28, 9, 26, 53, 0, time.UTC),

					// A slice, so a template that ranges over it renders. The
					// erasure confirmation must list what was retained, and a
					// string here would range over its bytes.
					"Retained": []string{"invoices, where a statutory period applies"},
				},
			})
			if err != nil {
				t.Fatalf("render: %v", err)
			}
			if msg.Subject == "" {
				t.Error("empty subject")
			}
			if strings.TrimSpace(msg.HTML) == "" {
				t.Error("empty HTML body")
			}
			// A plaintext alternative is deliverability, not courtesy:
			// HTML-only mail scores badly with spam filters.
			if strings.TrimSpace(msg.Text) == "" {
				t.Error("empty plaintext body")
			}
			if !strings.Contains(msg.HTML, "<html") {
				t.Error("HTML body was not wrapped in the layout")
			}
		})
	}
}

// The reason for html/template. A workspace or person's name is attacker-
// influenced, and it lands in an email body.
func TestHTMLInjectionIsEscaped(t *testing.T) {
	r := newRenderer(t)
	const attack = `"><script>alert(1)</script>`

	msg, err := r.Render(context.Background(), mail.Request{
		Template: "identity.welcome",
		Class:    notify.Transactional,
		Recipient: notify.Recipient{
			SubjectID: "sub_1", Address: "user@example.test", Name: attack, Locale: "en",
		},
		Data: map[string]any{"VerifyURL": "https://app.chronos.test/v?t=1", "ExpiresIn": "1 hour"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(msg.HTML, "<script>") {
		t.Fatalf("a name containing markup reached the HTML body unescaped:\n%s", msg.HTML)
	}
	if !strings.Contains(msg.HTML, "&lt;script&gt;") {
		t.Errorf("expected the name to appear escaped; body was:\n%s", msg.HTML)
	}
}

// A URL lands in an href, which is a different escaping context from text.
// javascript: must not survive there.
func TestDangerousURLIsNeutralised(t *testing.T) {
	r := newRenderer(t)
	msg, err := r.Render(context.Background(), mail.Request{
		Template:  "identity.welcome",
		Class:     notify.Transactional,
		Recipient: notify.Recipient{SubjectID: "s", Address: "u@example.test", Locale: "en"},
		Data:      map[string]any{"VerifyURL": "javascript:alert(1)", "ExpiresIn": "1 hour"},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.Contains(msg.HTML, "href=\"javascript:") {
		t.Fatalf("a javascript: URL survived into an href:\n%s", msg.HTML)
	}
}

// A newline in a subject lets an attacker append headers. The renderer collapses
// whitespace so nothing downstream has to.
func TestSubjectCannotCarryANewline(t *testing.T) {
	r := newRenderer(t)
	msg, err := r.Render(context.Background(), mail.Request{
		Template: "operator.alert",
		Class:    notify.Operator,
		Recipient: notify.Recipient{
			Address: "ops@chronos.test", Locale: "en",
		},
		Data: map[string]any{
			"Component": "projector",
			"Severity":  "critical",
			"Summary":   "line one\r\nBcc: attacker@evil.test",
		},
	})
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	if strings.ContainsAny(msg.Subject, "\r\n") {
		t.Fatalf("subject contains a line break: %q", msg.Subject)
	}
}

// Timestamps are stored UTC and converted at render time only (ADR-008).
func TestTimestampRendersInTheRecipientTimezone(t *testing.T) {
	r := newRenderer(t)
	at := time.Date(2026, 3, 14, 9, 26, 53, 0, time.UTC)

	berlin, err := r.Render(context.Background(), mail.Request{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Recipient: notify.Recipient{
			SubjectID: "s", Address: "u@example.test", Locale: "en", Timezone: "Europe/Berlin",
		},
		OccurredAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	tokyo, err := r.Render(context.Background(), mail.Request{
		Template: "identity.password_changed",
		Class:    notify.Security,
		Recipient: notify.Recipient{
			SubjectID: "s", Address: "u@example.test", Locale: "en", Timezone: "Asia/Tokyo",
		},
		OccurredAt: at,
	})
	if err != nil {
		t.Fatal(err)
	}
	if berlin.Text == tokyo.Text {
		t.Fatal("the same instant rendered identically in Berlin and Tokyo; " +
			"the timestamp was not converted to the reader's zone")
	}
	if !strings.Contains(tokyo.Text, "18:26") {
		t.Errorf("expected 09:26 UTC to render as 18:26 in Tokyo, got:\n%s", tokyo.Text)
	}
}

// A missing regional variant must fall back, not fail.
func TestLocaleFallback(t *testing.T) {
	r := newRenderer(t)
	msg, err := r.Render(context.Background(), mail.Request{
		Template: "identity.welcome",
		Class:    notify.Transactional,
		Recipient: notify.Recipient{
			SubjectID: "s", Address: "u@example.test", Locale: "de-AT",
		},
		Data: map[string]any{"ExpiresIn": "1 hour"},
	})
	if err != nil {
		t.Fatalf("an unknown locale must fall back, not fail: %v", err)
	}
	if msg.Subject == "" {
		t.Error("fallback produced no subject")
	}
}

func TestUnknownTemplateIsAnError(t *testing.T) {
	r := newRenderer(t)
	_, err := r.Render(context.Background(), mail.Request{
		Template:  "identity.does_not_exist",
		Class:     notify.Security,
		Recipient: notify.Recipient{SubjectID: "s", Address: "u@example.test"},
	})
	if err == nil {
		t.Fatal("rendering an unregistered template must fail loudly")
	}
	if !strings.Contains(err.Error(), "no such template") {
		t.Errorf("unhelpful error: %v", err)
	}
}

// Security and transactional mail must not offer an opt-out: you cannot
// unsubscribe from being told your password changed.
func TestUnsubscribeOnlyOnOptionalClasses(t *testing.T) {
	r := newRenderer(t)
	cases := []struct {
		class notify.Class
		want  bool
	}{
		{notify.Security, false},
		{notify.Transactional, false},
		{notify.Activity, true},
		{notify.Product, true},
	}
	for _, tc := range cases {
		t.Run(tc.class.String(), func(t *testing.T) {
			msg, err := r.Render(context.Background(), mail.Request{
				Template:  "identity.welcome",
				Class:     tc.class,
				Recipient: notify.Recipient{SubjectID: "s", Address: "u@example.test", Locale: "en"},
				Data: map[string]any{
					"UnsubscribeURL": "https://app.chronos.test/unsub?t=1",
					"ExpiresIn":      "1 hour",
				},
			})
			if err != nil {
				t.Fatal(err)
			}
			_, has := msg.Headers["List-Unsubscribe"]
			if has != tc.want {
				t.Errorf("List-Unsubscribe present=%v, want %v for class %s", has, tc.want, tc.class)
			}
		})
	}
}

// Caller data must not be able to overwrite the recipient fields the renderer
// controls — otherwise an event payload could set the displayed name.
func TestCallerDataCannotShadowRecipientFields(t *testing.T) {
	r := newRenderer(t)
	msg, err := r.Render(context.Background(), mail.Request{
		Template: "identity.welcome",
		Class:    notify.Transactional,
		Recipient: notify.Recipient{
			SubjectID: "s", Address: "real@example.test", Name: "Real Name", Locale: "en",
		},
		Data: map[string]any{"Name": "Injected Name", "Email": "attacker@evil.test", "ExpiresIn": "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(msg.Text, "Injected Name") {
		t.Fatal("template data overwrote the recipient's name")
	}
	if !strings.Contains(msg.Text, "Real Name") {
		t.Errorf("the real name did not render:\n%s", msg.Text)
	}
}

// An override replaces wording without a deploy, and a broken override store
// must not take outbound mail down with it.
func TestOverlayOverridesAndSurvivesABrokenStore(t *testing.T) {
	over := mapSource{
		"en/identity.welcome.subject.tmpl": []byte("Custom welcome subject"),
	}
	r := mailrender.New(
		mailrender.Overlay{Base: mailrender.Embedded{}, Override: over},
		mailrender.Config{From: mail.Address{Email: "a@b.test"}, BaseURL: "https://x.test"},
	)
	if err := r.Load(context.Background()); err != nil {
		t.Fatalf("load: %v", err)
	}
	msg, err := r.Render(context.Background(), mail.Request{
		Template:  "identity.welcome",
		Class:     notify.Transactional,
		Recipient: notify.Recipient{SubjectID: "s", Address: "u@example.test", Locale: "en"},
		Data:      map[string]any{"ExpiresIn": "1h"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if msg.Subject != "Custom welcome subject" {
		t.Errorf("override did not apply, got %q", msg.Subject)
	}

	broken := mailrender.New(
		mailrender.Overlay{Base: mailrender.Embedded{}, Override: failingSource{}},
		mailrender.Config{From: mail.Address{Email: "a@b.test"}, BaseURL: "https://x.test"},
	)
	if err := broken.Load(context.Background()); err != nil {
		t.Fatalf("an unreachable override store must fall back to the embedded set: %v", err)
	}
}

type mapSource map[string][]byte

func (m mapSource) Templates(context.Context) (map[string][]byte, error) {
	out := map[string][]byte{}
	maps.Copy(out, m)
	return out, nil
}

type failingSource struct{}

func (failingSource) Templates(context.Context) (map[string][]byte, error) {
	return nil, context.DeadlineExceeded
}
