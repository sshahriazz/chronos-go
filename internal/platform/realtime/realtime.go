// Package realtime is the live-delivery kernel: publishing to connected
// browsers, and knowing who is connected.
//
// Two rules from the architecture shape everything here.
//
// NO WEBSOCKET LOOPS IN GO SERVICES. Chronos never holds a socket open to a
// browser. The API mints a short-lived subscription token, the browser connects
// to Centrifugo, and Centrifugo owns the connections. A Go process that held
// them would have to be sticky, would lose them all on deploy, and would make
// horizontal scaling a session-affinity problem.
//
// PAYLOADS ARE NOTIFICATIONS, NOT THE DATA OF RECORD. A realtime message says
// "something changed, and here is enough to show it" — never the authoritative
// copy. A browser that missed a message must be able to recover by reading the
// projection, because delivery over a socket is best-effort by nature.
package realtime

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"
)

// Channel is a subscription target, namespaced.
//
// The namespace is not decoration: Centrifugo applies presence, history and
// recovery per namespace, and a channel outside a configured namespace has none
// of them. It is also the authorisation boundary — no namespace grants clients
// the right to subscribe, so every channel needs a token minted by us.
type Channel string

func (c Channel) String() string { return string(c) }

// UserChannel is one person's private stream: their notification feed, their
// unread count.
//
// Keyed by SubjectID, the same pseudonym everything else uses (ADR-002). A
// channel named after an email address would leak it to anyone who can see a
// connection.
func UserChannel(subjectID string) Channel { return Channel("user:" + subjectID) }

// Namespace reports the part Centrifugo matches its configuration against.
func (c Channel) Namespace() string {
	if i := strings.IndexByte(string(c), ':'); i > 0 {
		return string(c)[:i]
	}
	return ""
}

// Valid reports whether a channel is well formed. A channel with no namespace
// silently loses presence and history, which is the kind of failure nobody
// notices until they need recovery.
func (c Channel) Valid() bool {
	ns := c.Namespace()
	return ns != "" && len(string(c)) > len(ns)+1
}

// Message is what a browser receives.
//
// Data is deliberately small and deliberately not authoritative: an id and
// enough to render a badge or a toast. The browser reads the projection for the
// rest, which is what makes a missed message recoverable.
type Message struct {
	Channel Channel

	// Type lets a client route without parsing the payload.
	Type string

	// Data is the payload, already encoded. It carries NO personal data: a
	// realtime payload passes through infrastructure we do not control and may
	// be retained in channel history (ADR-002).
	Data []byte

	// IdempotencyKey deduplicates when a publisher retries.
	IdempotencyKey string
}

// Publisher sends messages to connected clients.
type Publisher interface {
	// Publish delivers to everyone subscribed to a channel.
	//
	// Best effort by design: a browser that is offline misses it and recovers
	// by reading the projection. A publish failure must therefore NOT fail the
	// operation that triggered it.
	Publish(ctx context.Context, msg Message) error

	// PublishMany sends several messages in one round trip. Used by projectors,
	// which frequently touch several channels for one event.
	PublishMany(ctx context.Context, msgs []Message) error
}

// Presence answers "is this person actually looking right now?".
//
// This is what makes ADR-026 implementable: an Activity notification that
// reaches somebody with the app open does not also need an email. Without
// presence, alert arbitration can only guess, and guessing wrong either spams
// or loses.
type Presence interface {
	// Online reports whether a subject has at least one live connection.
	Online(ctx context.Context, subjectID string) (bool, error)

	// Connections counts a subject's live connections — several tabs, several
	// devices.
	Connections(ctx context.Context, subjectID string) (int, error)
}

// TokenMinter issues subscription credentials.
//
// The authorisation seam. No namespace grants clients the right to subscribe,
// so a browser can only join a channel we have minted a token for — and we mint
// one only after an OpenFGA check. Centrifugo never decides who may see what.
type TokenMinter interface {
	// Connection issues a token identifying a user to Centrifugo.
	Connection(ctx context.Context, subjectID string, ttl time.Duration) (string, error)

	// Subscription issues a token for ONE channel, after authorisation.
	Subscription(ctx context.Context, subjectID string, ch Channel, ttl time.Duration) (string, error)
}

// DefaultTokenTTL is how long a minted token stays valid.
//
// Short: a token is a capability, and a leaked one is a subscription to somebody
// else's notifications. Clients refresh, which Centrifugo supports natively.
const DefaultTokenTTL = 10 * time.Minute

var (
	// ErrInvalidChannel means the channel is malformed or outside a configured
	// namespace.
	ErrInvalidChannel = errors.New("realtime: invalid channel")

	// ErrUnavailable means the realtime service could not be reached. Callers
	// must treat a publish failure as non-fatal: the projection is the record,
	// and the browser recovers from it.
	ErrUnavailable = errors.New("realtime: service unavailable")
)

// Validate checks a message before it is published.
func (m Message) Validate() error {
	switch {
	case !m.Channel.Valid():
		return fmt.Errorf("%w: %q needs a namespace, or it loses presence and history",
			ErrInvalidChannel, m.Channel)
	case m.Type == "":
		return errors.New("realtime: a message type is required so clients can route without parsing")
	case len(m.Data) > MaxPayloadBytes:
		return fmt.Errorf("realtime: payload is %d bytes, over the %d-byte limit; "+
			"a realtime message carries a pointer, not the data", len(m.Data), MaxPayloadBytes)
	}
	return nil
}

// MaxPayloadBytes bounds a realtime message.
//
// Small on purpose. A large payload is a sign the message has become the data of
// record — at which point a client that missed it has lost something, instead of
// simply re-reading a projection.
const MaxPayloadBytes = 8 << 10
