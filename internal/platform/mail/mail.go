// Package mail is the kernel's outbound email surface: what a message is, who
// may be told what, and the ports that render and deliver it.
//
// Nothing here knows about SMTP, HTML, or any template engine. The domain
// decides WHAT to say and to WHICH subject; adapters decide how it is rendered
// and carried (ADR-001).
//
// Two rules from NOTIFICATIONS §4 are enforced by these types rather than left
// to reviewers:
//
//   - A message is addressed to a SubjectID, never to an email address. Events
//     carry pseudonyms only (ADR-002), and the address is resolved from the
//     vault at send time.
//   - An erased subject is SKIPPED, not failed. A user who exercised erasure has
//     no address, and that is a correct outcome.
package mail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/notify"
)

// Request is what the mail channel is asked to send, before rendering.
//
// Class, Recipient and Vault deliberately live in platform/notify rather than
// here: they are notification policy, shared by push and the in-app feed, and a
// second definition in this package would drift from it. Mail is one channel
// under that policy, not a system of its own.
type Request struct {
	// Template names the message, e.g. "identity.password_changed".
	Template string

	Class     notify.Class
	Recipient notify.Recipient

	// Data is template input. It must contain NO personal data — the recipient
	// travels separately, resolved from the vault.
	Data map[string]any

	// OccurredAt is the UTC instant of the underlying event, rendered in the
	// recipient's timezone. Zero means now.
	OccurredAt time.Time

	// IdempotencyKey deduplicates at the transport, normally the event ID.
	IdempotencyKey string
}

// Validate rejects requests that could only produce a broken message.
func (r Request) Validate() error {
	switch {
	case r.Template == "":
		return errors.New("mail: template is required")
	case r.Class == 0:
		return errors.New("mail: class is required")
	case r.Recipient.Address == "":
		return notify.ErrNoAddress
	}
	return nil
}

// Message is a fully rendered message, ready for a transport.
type Message struct {
	From      Address
	To        Address
	ReplyTo   Address
	Subject   string
	HTML      string
	Text      string
	Headers   map[string]string
	Class     notify.Class
	Template  string
	MessageID string
}

// Address is an RFC 5322 address.
type Address struct {
	Name  string
	Email string
}

func (a Address) String() string {
	if a.Name == "" {
		return a.Email
	}
	return fmt.Sprintf("%s <%s>", a.Name, a.Email)
}

// Renderer turns a Request into a Message.
//
// Locale and timezone are inputs, not globals: the same request rendered for two
// recipients produces two different messages, and neither depends on the
// server's own locale or clock (notification.md §12).
type Renderer interface {
	Render(ctx context.Context, req Request) (Message, error)
}

// Mailer delivers a rendered message.
type Mailer interface {
	Send(ctx context.Context, m Message) error
}

var (
	// ErrUnknownTemplate means no template is registered under that name — a
	// wiring bug, not a data problem.
	ErrUnknownTemplate = errors.New("mail: no such template")
)
