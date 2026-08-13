// Package webpush is the browser push channel.
//
// Two properties shape everything here, both from notification.md §4:
//
//   - The payload transits a THIRD-PARTY push service and may render on a lock
//     screen. It therefore carries no personal data — a title, a short body, and
//     the notification id. Nothing else (ADR-002).
//   - A 404 or 410 means the browser dropped the subscription. Those endpoints
//     accumulate fast and silently degrade delivery, so they are pruned on the
//     first rejection rather than retried.
package webpush

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	webpushgo "github.com/SherClockHolmes/webpush-go"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// Subscription is one browser profile on one device.
type Subscription struct {
	ID        string
	SubjectID string
	Endpoint  string
	P256dh    string
	Auth      string
}

// Subscriptions reads a subject's active endpoints and retires dead ones.
//
// Retire is a port rather than a direct write because a subscription's life is
// recorded in the log: pruning appends PushSubscriptionExpired, and the read
// model follows.
type Subscriptions interface {
	// orgID scopes both: subscriptions are an RLS-protected read model.
	Active(ctx context.Context, orgID, subjectID string) ([]Subscription, error)
	Retire(ctx context.Context, orgID string, sub Subscription, reason string) error
}

// Payload is exactly what crosses the wire.
//
// A closed struct, not a map: a map would let a caller add a field, and the
// field they would add is the recipient's name. The type is the enforcement.
type Payload struct {
	Title          string `json:"title"`
	Body           string `json:"body"`
	NotificationID string `json:"notification_id"`
	URL            string `json:"url,omitempty"`
}

// Titles renders the short push text for a template.
//
// Separate from the email renderer because the constraint is different: push
// text must be generic enough to sit on a lock screen a stranger can read.
// "Your password was changed" is fine; "Sam Larsson changed your password" is
// not.
type Titles interface {
	Push(template string, data map[string]any) (title, body string, ok bool)
}

// Transport delivers web push notifications.
type Transport struct {
	subs    Subscriptions
	titles  Titles
	vapid   VAPID
	client  *http.Client
	ttl     int
	baseURL string
	obs     Observer
	urgency webpushgo.Urgency
}

// VAPID identifies this application server to the push services.
type VAPID struct {
	PublicKey  string
	PrivateKey string

	// Subject is a mailto: or https: URL push services use to contact the
	// operator about abuse. Required by the spec.
	Subject string
}

// Observer records outcomes. Optional.
type Observer interface {
	Sent(template string)
	Failed(template string)
	Pruned(reason string)
	Skipped(template, reason string)
}

type noObserver struct{}

func (noObserver) Sent(string)            {}
func (noObserver) Failed(string)          {}
func (noObserver) Pruned(string)          {}
func (noObserver) Skipped(string, string) {}

type Config struct {
	VAPID   VAPID
	BaseURL string

	// TTL is how long a push service should hold an undelivered message.
	// Zero takes a day, which suits notifications that stay meaningful.
	TTL time.Duration

	Client   *http.Client
	Observer Observer
}

func New(subs Subscriptions, titles Titles, cfg Config) *Transport {
	if cfg.Client == nil {
		// A bounded client: a push service that accepts the connection and
		// stalls would otherwise hold a reactor's in-flight slot indefinitely.
		cfg.Client = &http.Client{Timeout: 15 * time.Second}
	}
	if cfg.TTL <= 0 {
		cfg.TTL = 24 * time.Hour
	}
	if cfg.Observer == nil {
		cfg.Observer = noObserver{}
	}
	return &Transport{
		subs: subs, titles: titles, vapid: cfg.VAPID,
		client: cfg.Client, ttl: int(cfg.TTL.Seconds()),
		baseURL: cfg.BaseURL, obs: cfg.Observer,
		// Normal urgency: high would ask the device to wake for every
		// notification, which drains batteries and gets the origin throttled.
		urgency: webpushgo.UrgencyNormal,
	}
}

var _ notify.Transport = (*Transport)(nil)

func (t *Transport) Channel() notify.Channel { return notify.ChannelWebPush }

// Deliver pushes to every active subscription the subject has.
//
// A subject with no subscriptions is not a failure: most people have not granted
// push permission, and treating that as an error would retry forever and park a
// notification that was delivered perfectly well by email.
func (t *Transport) Deliver(ctx context.Context, n notify.Notification) error {
	if n.Recipient.SubjectID == "" {
		return fmt.Errorf("%w: web push needs a subject", notify.ErrNoAddress)
	}

	title, body, ok := t.titles.Push(n.Template, n.Data)
	if !ok {
		// No push wording for this template. Deliberate: not every notification
		// is worth interrupting someone for, and userVisibleOnly means a push
		// that shows nothing risks the browser revoking permission for the
		// origin entirely (notification.md §4).
		t.obs.Skipped(n.Template, "no_push_wording")
		return nil
	}

	subs, err := t.subs.Active(ctx, n.OrgID, n.Recipient.SubjectID)
	if err != nil {
		return fmt.Errorf("webpush: reading subscriptions: %w", err)
	}
	if len(subs) == 0 {
		t.obs.Skipped(n.Template, "no_subscriptions")
		return nil
	}

	// These bytes are decrypted and parsed by a service worker we do not own, so
	// the wire shape is not ours to change casually — but Payload is four
	// strings with no slice or map in it, so v2's `[]`-instead-of-`null`
	// difference cannot reach the browser and NullEmpty would be a no-op.
	payload, err := codec.Marshal(buildPayload(n, title, body, t.baseURL))
	if err != nil {
		return fmt.Errorf("webpush: encoding payload: %w", err)
	}

	var firstErr error
	for _, sub := range subs {
		if err := t.send(ctx, n.OrgID, sub, payload); err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		t.obs.Sent(n.Template)
	}
	return firstErr
}

// buildPayload assembles exactly what crosses the wire.
//
// Extracted so it can be asserted directly: the wire body is encrypted, so a
// test that inspects the HTTP request proves nothing about what is inside it.
// This is the only place the payload is constructed, and the only place a
// privacy check is meaningful.
//
// Note what it does NOT take from the notification: the recipient. Name and
// address are resolved before a transport is called, and both are deliberately
// unreachable from here.
func buildPayload(n notify.Notification, title, body, baseURL string) Payload {
	return Payload{
		Title:          title,
		Body:           body,
		NotificationID: n.IdempotencyKey,
		URL:            baseURL,
	}
}

// send delivers to one endpoint, pruning it if the browser has dropped it.
func (t *Transport) send(ctx context.Context, orgID string, sub Subscription, payload []byte) error {
	resp, err := webpushgo.SendNotificationWithContext(ctx, payload, &webpushgo.Subscription{
		Endpoint: sub.Endpoint,
		Keys:     webpushgo.Keys{P256dh: sub.P256dh, Auth: sub.Auth},
	}, &webpushgo.Options{
		HTTPClient:      t.client,
		Subscriber:      t.vapid.Subject,
		VAPIDPublicKey:  t.vapid.PublicKey,
		VAPIDPrivateKey: t.vapid.PrivateKey,
		TTL:             t.ttl,
		Urgency:         t.urgency,
	})
	if err != nil {
		t.obs.Failed("")
		return fmt.Errorf("webpush: sending to %s: %w", redactEndpoint(sub.Endpoint), err)
	}
	defer func() { _ = resp.Body.Close() }()

	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusGone:
		// The browser dropped it. Retrying can never succeed, and leaving it
		// makes every future send slower for no benefit.
		reason := fmt.Sprintf("push service returned %d", resp.StatusCode)
		if err := t.subs.Retire(ctx, orgID, sub, reason); err != nil {
			return fmt.Errorf("webpush: retiring dead subscription: %w", err)
		}
		t.obs.Pruned(reason)
		return nil

	case resp.StatusCode == http.StatusRequestEntityTooLarge:
		// Our payload is too big for the service. That is our bug, not a
		// transient failure, and every retry will be the same size.
		t.obs.Failed("")
		return fmt.Errorf("%w: webpush: payload rejected as too large", ErrUnrecoverable)

	case resp.StatusCode >= 500:
		t.obs.Failed("")
		return fmt.Errorf("webpush: push service returned %d", resp.StatusCode)

	case resp.StatusCode >= 400:
		// 401/403 mean our VAPID keys are wrong — configuration, not weather.
		t.obs.Failed("")
		return fmt.Errorf("%w: webpush: push service returned %d", ErrUnrecoverable, resp.StatusCode)
	}
	return nil
}

// ErrUnrecoverable marks a failure no retry can fix, so a reactor parks it
// instead of exhausting its attempts.
var ErrUnrecoverable = errors.New("webpush: unrecoverable")

// redactEndpoint keeps the push service host for diagnosis and drops the token
// that identifies the device.
func redactEndpoint(endpoint string) string {
	for i := len("https://"); i < len(endpoint); i++ {
		if endpoint[i] == '/' {
			return endpoint[:i] + "/…"
		}
	}
	return endpoint
}
