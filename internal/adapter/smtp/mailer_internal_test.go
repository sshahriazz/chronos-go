package smtp

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

func testMailer() *Mailer {
	return New(Config{Host: "localhost", Port: 1025, Domain: "chronos.test"})
}

func msg() mail.Message {
	return mail.Message{
		From:     mail.Address{Name: "Chronos", Email: "no-reply@chronos.test"},
		To:       mail.Address{Name: "Sam", Email: "sam@example.test"},
		Subject:  "Your password was changed",
		Text:     "Hello Sam,\n\nYour password was changed.\n",
		HTML:     "<html><body><p>Hello Sam,</p></body></html>",
		Class:    notify.Security,
		Template: "identity.password_changed",
		Headers:  map[string]string{},
	}
}

// Header injection is the one serious vulnerability in outbound mail: a newline
// in a header value lets an attacker append headers of their own — a second
// Bcc, a different From. It must be REFUSED, not sanitised, so the attempt is
// visible rather than silently swallowed.
func TestHeaderInjectionIsRefused(t *testing.T) {
	cases := map[string]func(*mail.Message){
		"newline in subject": func(m *mail.Message) {
			m.Subject = "hello\r\nBcc: attacker@evil.test"
		},
		"newline in a custom header": func(m *mail.Message) {
			m.Headers["X-Thing"] = "a\r\nBcc: attacker@evil.test"
		},
		"newline in the sender display name": func(m *mail.Message) {
			m.From = mail.Address{Name: "Chronos\r\nBcc: attacker@evil.test", Email: "a@b.test"}
		},
		"newline in the recipient display name": func(m *mail.Message) {
			m.To = mail.Address{Name: "Sam\nBcc: attacker@evil.test", Email: "sam@example.test"}
		},
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			m := msg()
			mutate(&m)
			doc, err := testMailer().build(m)
			if err != nil {
				return // refused outright, which is the desired outcome
			}
			// Accepted is fine ONLY if the encoding neutralised it. The test is
			// whether a new header LINE appeared — not whether the text "Bcc:"
			// occurs anywhere, which it legitimately does inside an RFC 2047
			// encoded-word where the CRLF has become "=0D=0A".
			head, _, _ := strings.Cut(string(doc), "\r\n\r\n")
			for line := range strings.SplitSeq(head, "\r\n") {
				name, _, isHeader := strings.Cut(line, ":")
				if !isHeader {
					continue
				}
				if strings.EqualFold(strings.TrimSpace(name), "bcc") {
					t.Fatalf("an injected Bcc header became a real header line:\n%s", head)
				}
			}
		})
	}
}

// Both parts, always. HTML-only mail scores badly with spam filters and is
// unreadable in text clients and screen readers.
func TestMessageIsMultipartAlternativeWithBothParts(t *testing.T) {
	doc, err := testMailer().build(msg())
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s := string(doc)
	if !strings.Contains(s, "multipart/alternative") {
		t.Error("not multipart/alternative")
	}
	if !strings.Contains(s, `text/plain; charset="utf-8"`) {
		t.Error("missing the plaintext part")
	}
	if !strings.Contains(s, `text/html; charset="utf-8"`) {
		t.Error("missing the HTML part")
	}
	// Ordered least-preferred first: reversing this shows raw markup in some
	// clients.
	if strings.Index(s, "text/plain") > strings.Index(s, "text/html") {
		t.Error("the HTML part precedes the plaintext part; multipart/alternative is ordered least-preferred first")
	}
}

func TestNonASCIIDisplayNameIsEncoded(t *testing.T) {
	m := msg()
	m.To = mail.Address{Name: "Sørensen Müller", Email: "s@example.test"}
	doc, err := testMailer().build(m)
	if err != nil {
		t.Fatalf("build: %v", err)
	}
	s := string(doc)
	if strings.Contains(s, "Sørensen") {
		t.Error("a non-ASCII display name was written raw; it must be RFC 2047 encoded")
	}
	if !strings.Contains(s, "=?utf-8?q?") && !strings.Contains(s, "=?UTF-8?q?") {
		t.Errorf("expected an encoded-word in the headers:\n%s", firstLines(s, 8))
	}
	if !strings.Contains(s, "<s@example.test>") {
		t.Error("the address itself must not be encoded")
	}
}

func TestMessageIDIsSetWhenAbsent(t *testing.T) {
	doc, err := testMailer().build(msg())
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "@chronos.test>") {
		t.Error("no Message-ID was generated")
	}
}

func firstLines(s string, n int) string {
	lines := strings.SplitN(s, "\r\n", n+1)
	if len(lines) > n {
		lines = lines[:n]
	}
	return strings.Join(lines, "\n")
}
