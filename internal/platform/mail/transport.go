package mail

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// Transport is the email channel of the notification system.
//
// It renders and delivers; it decides NOTHING about whether a notification
// should be sent. Class policy, preferences and read arbitration all live in
// notify.Dispatcher, so email, push and the in-app feed cannot drift into
// disagreeing about whether a security alert may be suppressed.
type Transport struct {
	renderer Renderer
	mailer   Mailer
	clock    clock.Clock
	obs      Observer
}

// Observer records delivery outcomes for metrics. Optional.
type Observer interface {
	Sent(template, class string)
	Failed(template, class string)
	Skipped(template, reason string)
	Rendered(template string, seconds float64)
}

type noObserver struct{}

func (noObserver) Sent(string, string)      {}
func (noObserver) Failed(string, string)    {}
func (noObserver) Skipped(string, string)   {}
func (noObserver) Rendered(string, float64) {}

func NewTransport(r Renderer, m Mailer, clk clock.Clock, obs Observer) *Transport {
	if clk == nil {
		clk = clock.System{}
	}
	if obs == nil {
		obs = noObserver{}
	}
	return &Transport{renderer: r, mailer: m, clock: clk, obs: obs}
}

var _ notify.Transport = (*Transport)(nil)

func (t *Transport) Channel() notify.Channel { return notify.ChannelEmail }

// Deliver renders and sends.
//
// A recipient with no address is SKIPPED rather than failed. By the time a
// notification reaches a transport the dispatcher has already resolved the
// subject, so an empty address means there is genuinely nowhere to send — an
// operator address that was never configured, or a subject whose record exists
// without one. Retrying cannot conjure an address.
func (t *Transport) Deliver(ctx context.Context, n notify.Notification) error {
	if n.Recipient.Address == "" {
		t.obs.Skipped(n.Template, "no_address")
		return fmt.Errorf("%w: %s", notify.ErrNoAddress, n.Template)
	}

	started := t.clock.Now()
	msg, err := t.renderer.Render(ctx, Request{
		Template:       n.Template,
		Class:          n.Class,
		Recipient:      n.Recipient,
		Data:           n.Data,
		OccurredAt:     n.OccurredAt,
		IdempotencyKey: n.IdempotencyKey,
	})
	if err != nil {
		if errors.Is(err, ErrUnknownTemplate) {
			// A missing template is a wiring bug. Retrying re-renders the same
			// absence forever, so it is poison rather than a transient failure.
			t.obs.Skipped(n.Template, "unknown_template")
			return fmt.Errorf("%w: %w", errPoison, err)
		}
		t.obs.Failed(n.Template, n.Class.String())
		return fmt.Errorf("mail: rendering %s: %w", n.Template, err)
	}
	t.obs.Rendered(n.Template, t.clock.Now().Sub(started).Seconds())

	// The idempotency key becomes the Message-ID, so a redelivered event
	// produces a message the receiving server can recognise as the same one it
	// already accepted.
	if n.IdempotencyKey != "" {
		msg.MessageID = "<" + n.IdempotencyKey + "@chronos>"
	}

	if err := t.mailer.Send(ctx, msg); err != nil {
		t.obs.Failed(n.Template, n.Class.String())
		return fmt.Errorf("mail: sending %s: %w", n.Template, err)
	}
	t.obs.Sent(n.Template, n.Class.String())
	return nil
}

// errPoison mirrors eventsourcing.ErrPoison without importing it: the mail
// package must not depend on the event-sourcing kernel to describe an
// unrecoverable message. Reactors match on the string-free sentinel below.
var errPoison = errors.New("mail: unrecoverable")

// Unrecoverable reports whether an error from Deliver can never succeed on
// retry, so a reactor can park it immediately instead of exhausting its retries.
func Unrecoverable(err error) bool { return errors.Is(err, errPoison) }

// EnsureTimeout bounds a send. A mail server that accepts a connection and then
// stalls would otherwise hold a reactor's in-flight slot for as long as it likes.
func EnsureTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
