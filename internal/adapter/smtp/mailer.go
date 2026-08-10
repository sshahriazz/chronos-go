// Package smtp delivers rendered messages over SMTP.
//
// It builds the MIME document by hand rather than pulling in a mail library.
// The reason is auditable safety: header injection is the one serious
// vulnerability in outbound mail, and it is prevented by rejecting control
// characters in every header value — a rule that has to be visible here to be
// trusted.
package smtp

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"mime"
	"mime/multipart"
	"mime/quotedprintable"
	"net"
	"net/smtp"
	"net/textproto"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/platform/mail"
)

// Config describes the mail server.
type Config struct {
	Host string
	Port int

	// Username and Password are empty in development: Mailpit accepts
	// unauthenticated mail, and requiring credentials there would mean the dev
	// path differs from production in the code rather than in configuration.
	Username string
	Password string

	// StartTLS upgrades the connection. Off for Mailpit; on everywhere real.
	StartTLS bool

	// InsecureSkipVerify disables certificate verification. Only ever true for
	// a local server with a self-signed certificate.
	InsecureSkipVerify bool

	// Timeout bounds the whole conversation. A hung mail server must not hold a
	// reactor's in-flight slot open indefinitely.
	Timeout time.Duration

	// Domain is used for the Message-ID. Defaults to the host.
	Domain string
}

// Mailer sends messages over SMTP.
type Mailer struct {
	cfg Config
}

var _ mail.Mailer = (*Mailer)(nil)

func New(cfg Config) *Mailer {
	if cfg.Timeout <= 0 {
		cfg.Timeout = 30 * time.Second
	}
	if cfg.Domain == "" {
		cfg.Domain = cfg.Host
	}
	return &Mailer{cfg: cfg}
}

// Send delivers one message.
func (m *Mailer) Send(ctx context.Context, msg mail.Message) error {
	if msg.To.Email == "" {
		return fmt.Errorf("smtp: message has no recipient")
	}
	doc, err := m.build(msg)
	if err != nil {
		return err
	}

	addr := net.JoinHostPort(m.cfg.Host, fmt.Sprint(m.cfg.Port))
	d := net.Dialer{Timeout: m.cfg.Timeout}
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return fmt.Errorf("smtp: dialling %s: %w", addr, err)
	}
	// The deadline covers the entire conversation, not just the dial: a server
	// that accepts the connection and then stalls is the common failure.
	if deadline, ok := ctx.Deadline(); ok {
		_ = conn.SetDeadline(deadline)
	} else {
		_ = conn.SetDeadline(time.Now().Add(m.cfg.Timeout))
	}

	c, err := smtp.NewClient(conn, m.cfg.Host)
	if err != nil {
		_ = conn.Close()
		return fmt.Errorf("smtp: handshake with %s: %w", addr, err)
	}
	defer func() { _ = c.Close() }()

	if m.cfg.StartTLS {
		if ok, _ := c.Extension("STARTTLS"); !ok {
			return errors.New("smtp: server does not offer STARTTLS but it is required")
		}
		//nolint:gosec // InsecureSkipVerify is opt-in and only for local servers
		if err := c.StartTLS(&tls.Config{
			ServerName:         m.cfg.Host,
			InsecureSkipVerify: m.cfg.InsecureSkipVerify,
			MinVersion:         tls.VersionTLS12,
		}); err != nil {
			return fmt.Errorf("smtp: starttls: %w", err)
		}
	}

	if m.cfg.Username != "" {
		auth := smtp.PlainAuth("", m.cfg.Username, m.cfg.Password, m.cfg.Host)
		if err := c.Auth(auth); err != nil {
			return fmt.Errorf("smtp: authenticating: %w", err)
		}
	}

	if err := c.Mail(msg.From.Email); err != nil {
		return fmt.Errorf("smtp: MAIL FROM %s: %w", msg.From.Email, err)
	}
	if err := c.Rcpt(msg.To.Email); err != nil {
		return fmt.Errorf("smtp: RCPT TO: %w", err)
	}

	w, err := c.Data()
	if err != nil {
		return fmt.Errorf("smtp: DATA: %w", err)
	}
	if _, err := w.Write(doc); err != nil {
		_ = w.Close()
		return fmt.Errorf("smtp: writing message: %w", err)
	}
	if err := w.Close(); err != nil {
		return fmt.Errorf("smtp: completing message: %w", err)
	}
	return c.Quit()
}

// build assembles a multipart/alternative document.
//
// Both parts are always present. HTML-only mail scores badly with spam filters
// and is unreadable in text clients and screen readers; the plaintext part is
// not a courtesy, it is deliverability.
func (m *Mailer) build(msg mail.Message) ([]byte, error) {
	var b strings.Builder
	var body strings.Builder

	mw := multipart.NewWriter(&body)

	// Text first. multipart/alternative is ordered least-preferred first, so a
	// client that understands both picks the HTML — reversing this shows raw
	// markup to some clients.
	textPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {`text/plain; charset="utf-8"`},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeQuotedPrintable(textPart, msg.Text); err != nil {
		return nil, err
	}

	htmlPart, err := mw.CreatePart(textproto.MIMEHeader{
		"Content-Type":              {`text/html; charset="utf-8"`},
		"Content-Transfer-Encoding": {"quoted-printable"},
	})
	if err != nil {
		return nil, err
	}
	if err := writeQuotedPrintable(htmlPart, msg.HTML); err != nil {
		return nil, err
	}
	if err := mw.Close(); err != nil {
		return nil, err
	}

	messageID := msg.MessageID
	if messageID == "" {
		messageID = m.messageID()
	}

	headers := []struct{ k, v string }{
		{"From", encodeAddress(msg.From)},
		{"To", encodeAddress(msg.To)},
		{"Subject", mime.QEncoding.Encode("utf-8", msg.Subject)},
		{"Message-ID", messageID},
		{"Date", time.Now().UTC().Format(time.RFC1123Z)},
		{"MIME-Version", "1.0"},
		{"Content-Type", "multipart/alternative; boundary=" + mw.Boundary()},
	}
	if msg.ReplyTo.Email != "" {
		headers = append(headers, struct{ k, v string }{"Reply-To", encodeAddress(msg.ReplyTo)})
	}
	for k, v := range msg.Headers {
		headers = append(headers, struct{ k, v string }{k, v})
	}

	for _, h := range headers {
		// THE security check. A newline in a header value lets an attacker
		// append headers of their own — a second Bcc, a different From. Every
		// value that reaches here is rejected rather than sanitised, because
		// silently stripping would hide the attempt.
		if strings.ContainsAny(h.v, "\r\n") {
			return nil, fmt.Errorf("smtp: header %q contains a line break; refusing to send", h.k)
		}
		b.WriteString(h.k)
		b.WriteString(": ")
		b.WriteString(h.v)
		b.WriteString("\r\n")
	}
	b.WriteString("\r\n")
	b.WriteString(body.String())
	return []byte(b.String()), nil
}

func (m *Mailer) messageID() string {
	var buf [16]byte
	_, _ = rand.Read(buf[:])
	return "<" + base64.RawURLEncoding.EncodeToString(buf[:]) + "@" + m.cfg.Domain + ">"
}

// encodeAddress RFC 2047-encodes the display name so non-ASCII names survive,
// and leaves the address itself alone.
func encodeAddress(a mail.Address) string {
	if a.Name == "" {
		return a.Email
	}
	return mime.QEncoding.Encode("utf-8", a.Name) + " <" + a.Email + ">"
}

// writeQuotedPrintable encodes a part body.
//
// Quoted-printable rather than raw 8-bit: SMTP servers may refuse or mangle
// long lines and non-ASCII bytes, and a mangled password-reset link is a
// support ticket.
func writeQuotedPrintable(w io.Writer, s string) error {
	qp := quotedprintable.NewWriter(w)
	if _, err := io.WriteString(qp, s); err != nil {
		return err
	}
	return qp.Close()
}
