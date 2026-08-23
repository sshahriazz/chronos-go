// Package api serves the billing endpoints that are not RPCs.
//
// The Stripe webhook is plain HTTP rather than a Connect procedure, and it has
// to be: Stripe posts a signed body to a URL of our choosing, with no knowledge
// of Connect's envelope, its headers or its error shape.
package api

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	"github.com/chronos/chronos-go/internal/modules/billing/app"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// maxBody bounds what will be read from the connection.
//
// Stripe events are small; the largest documented ones are a few hundred
// kilobytes. Without a bound, an endpoint that anybody on the internet can POST
// to will read whatever it is sent into memory.
const maxBody = 1 << 20 // 1 MiB

// Verifier checks a signature and re-fetches what the event names.
type Verifier interface {
	Verify(payload []byte, signatureHeader string) (stripeadapter.Event, error)
	SubscriptionFor(ctx context.Context, payload []byte) (orgapp.SubscriptionState, error)
	InvoiceFor(ctx context.Context, payload []byte) (app.InvoiceState, error)
}

// EventLog is the idempotency boundary: it records what arrived and reports
// whether this delivery is the one that should apply it.
//
// A port rather than a database handle, so this layer never learns which driver
// is underneath — the previous shape checked pgx.ErrNoRows from here, which put
// the driver in a module's API layer.
type EventLog interface {
	Claim(ctx context.Context, eventID, eventType string, payload []byte) (bool, error)
	MarkProcessed(ctx context.Context, eventID string) error
	MarkFailed(ctx context.Context, eventID string, cause error) error
}

// Sync applies a subscription's current state to its organization.
type Sync interface {
	Apply(ctx context.Context, state orgapp.SubscriptionState, eventID string) error
}

// Trials records the warning that a trial is about to end.
//
// Separate from Sync because the two answer different questions about the same
// webhook. `trial_will_end` names a subscription whose status is still
// `trialing`, so the sync correctly does nothing; the warning is about a
// DEADLINE, not a status.
type Trials interface {
	Warn(ctx context.Context, orgID string, trialEndsAt time.Time, eventID string) error
}

// InvoiceRecorder records what Stripe reports about an invoice.
type InvoiceRecorder interface {
	Record(ctx context.Context, state app.InvoiceState, eventID string) error
}

// invoiceEventPrefix is what an invoice event's type starts with.
//
// A PREFIX rather than a list, and that is the deliberate choice. billing.md §4
// names eight invoice events — created, finalized, paid, payment_failed,
// payment_action_required, upcoming, marked_uncollectible, voided — and the
// handler treats every one of them identically, because it RE-FETCHES the
// invoice and records its current state rather than interpreting which event
// arrived. A list would have to be kept in step with Stripe's for no gain: a
// new invoice event this build had not heard of would be skipped, and skipping
// it means an invoice whose state moved and whose row did not.
//
// `invoice.upcoming` is the one that does not name a real invoice — it is a
// preview with no id — and it is not special-cased here: the re-fetch reports
// that the payload names no invoice, which is already the "not ours" path.
const invoiceEventPrefix = "invoice."

// TrialWillEndEvent is Stripe's warning, three days before a trial ends.
//
// For a CARDLESS trial it is the only warning anybody gets: the subscription
// then pauses, the organization is Suspended, and the first signal a customer
// would otherwise have is being locked out of their own tenant.
const TrialWillEndEvent = "customer.subscription.trial_will_end"

// Webhook is the endpoint Stripe posts to.
type Webhook struct {
	verifier Verifier
	sync     Sync
	trials   Trials
	invoices InvoiceRecorder
	events   EventLog
	log      *slog.Logger
}

// WebhookDeps is what the endpoint needs.
type WebhookDeps struct {
	Verifier Verifier
	Sync     Sync
	Trials   Trials
	Invoices InvoiceRecorder
	Events   EventLog
	Log      *slog.Logger
}

func NewWebhook(d WebhookDeps) (*Webhook, error) {
	switch {
	case d.Verifier == nil:
		return nil, fmt.Errorf("billing: a verifier is required; an endpoint that accepted " +
			"unverified events would be an unauthenticated way to suspend a tenant")
	case d.Sync == nil:
		return nil, fmt.Errorf("billing: a subscription sync is required")
	case d.Invoices == nil:
		return nil, fmt.Errorf("billing: an invoice recorder is required; without one every " +
			"invoice event is consumed and dropped, and the billing history is empty for " +
			"customers who are being charged")
	case d.Trials == nil:
		return nil, fmt.Errorf("billing: a trial warning use case is required; without one " +
			"trial_will_end is consumed and dropped, and a cardless trial's only warning " +
			"is never sent — the customer's first signal is being locked out")
	case d.Events == nil:
		return nil, fmt.Errorf("billing: an event log is required; without the idempotency " +
			"boundary Stripe's redeliveries would each apply the change again")
	case d.Log == nil:
		return nil, fmt.Errorf("billing: a logger is required")
	}
	return &Webhook{
		verifier: d.Verifier, sync: d.Sync, trials: d.Trials, invoices: d.Invoices,
		events: d.Events, log: d.Log,
	}, nil
}

// Path is where Stripe posts. Referenced by the wiring and by `stripe listen`.
const Path = "/stripe/webhook"

// ServeHTTP verifies, deduplicates and applies one event.
//
// # The order is the design
//
//  1. read the RAW body            the signature covers exactly these bytes
//  2. verify the signature         before anything is parsed or trusted
//  3. claim the event id           the idempotency boundary
//  4. re-fetch from Stripe         never trust the payload (billing.md §4)
//  5. apply, then mark processed
//
// # Why this responds AFTER applying, where billing.md says to respond first
//
// billing.md §4 has the handler return 200 immediately and hand the work to a
// Temporal workflow. That is the better shape and it is where this ends up. It
// is not what this does today, because Temporal is optional in this build
// (TEMPORAL_ENABLED) and without it there is no durable queue to hand work to —
// so "respond first" would mean doing the work in a goroutine that a restart
// loses silently.
//
// Applying inline keeps Stripe's own retry as the durability, which is the same
// trade the notification path already makes when Temporal is off. The cost is
// that Stripe waits on us; the operation is a re-fetch and one append, and
// Stripe allows far longer than that.
func (w *Webhook) ServeHTTP(rw http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		rw.Header().Set("Allow", http.MethodPost)
		http.Error(rw, "method not allowed", http.StatusMethodNotAllowed)
		return
	}

	payload, err := io.ReadAll(http.MaxBytesReader(rw, r.Body, maxBody))
	if err != nil {
		// 400, not 500: the body was unreadable or oversized, and Stripe
		// retrying will not change that.
		http.Error(rw, "unreadable body", http.StatusBadRequest)
		return
	}

	event, err := w.verifier.Verify(payload, r.Header.Get("Stripe-Signature"))
	if err != nil {
		// Deliberately terse to the caller and detailed in the log. Anybody can
		// POST here; telling them WHY verification failed helps only them.
		w.log.WarnContext(r.Context(), "a webhook failed signature verification",
			"error", err, "remote", r.RemoteAddr)
		http.Error(rw, "signature verification failed", http.StatusBadRequest)
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 20*time.Second)
	defer cancel()

	claimed, err := w.events.Claim(ctx, event.ID, event.Type, payload)
	if err != nil {
		w.log.ErrorContext(ctx, "could not record a webhook event",
			"error", err, "event_id", event.ID, "type", event.Type)
		// 500 so Stripe retries: the event is verified and real, and losing it
		// silently is the one outcome worth avoiding.
		http.Error(rw, "could not record the event", http.StatusInternalServerError)
		return
	}
	if !claimed {
		// Already applied. Stripe retries by design, so this is the ordinary
		// case rather than an anomaly.
		rw.WriteHeader(http.StatusOK)
		return
	}

	if err := w.apply(ctx, event, payload); err != nil {
		if errors.Is(err, eventsourcing.ErrPoison) {
			// It can never succeed. Recorded, and answered 200 so Stripe stops
			// retrying something no retry can fix — the row is the trail.
			w.log.ErrorContext(ctx, "a webhook can never be applied and will not be retried",
				"error", err, "event_id", event.ID, "type", event.Type)
			w.note(ctx, event.ID, err)
			rw.WriteHeader(http.StatusOK)
			return
		}
		w.log.ErrorContext(ctx, "applying a webhook failed; Stripe will retry",
			"error", err, "event_id", event.ID, "type", event.Type)
		w.note(ctx, event.ID, err)
		http.Error(rw, "could not apply the event", http.StatusInternalServerError)
		return
	}

	// Logged on SUCCESS, not only on failure. A webhook is how a tenant's
	// lifecycle changes without anybody here doing anything, and the first
	// question when a customer says "we were suspended" is whether an event
	// arrived and what it said. Without this line the only record is a database
	// row nobody thinks to query.
	w.log.InfoContext(ctx, "stripe webhook applied",
		"event_id", event.ID, "type", event.Type)

	if err := w.events.MarkProcessed(ctx, event.ID); err != nil {
		// The work is done and the bookkeeping is not. A retry re-applies, which
		// is safe because applying current state is convergent.
		w.log.ErrorContext(ctx, "a webhook was applied but not marked processed",
			"error", err, "event_id", event.ID)
	}
	rw.WriteHeader(http.StatusOK)
}

func (w *Webhook) apply(ctx context.Context, event stripeadapter.Event, payload []byte) error {
	// Invoices first, and they are a SEPARATE object rather than a branch inside
	// the subscription path: an invoice event names an invoice, not a
	// subscription, so SubscriptionFor would report "not ours" for every one of
	// them and the subscription sync has nothing to say about any of them.
	if strings.HasPrefix(event.Type, invoiceEventPrefix) {
		return w.applyInvoice(ctx, event, payload)
	}

	state, err := w.verifier.SubscriptionFor(ctx, payload)
	if err != nil {
		// Not every event names a subscription — Stripe sends invoices, payment
		// intents and more to the same endpoint. Those are not this build's
		// business yet, and are not failures.
		w.log.DebugContext(ctx, "a webhook names no subscription this build handles",
			"event_id", event.ID, "type", event.Type, "reason", err)
		return nil
	}
	// The sync runs for EVERY event that names a subscription, including this
	// one, and it runs FIRST. `trial_will_end` reports `trialing`, which is
	// almost always the state the organization is already in — so the sync is a
	// no-op and the ordering looks arbitrary. It is not: if the provisioning
	// event has not been applied yet, the sync is what puts the organization
	// into Trialing, and the warning below refuses to fire for an organization
	// that is not.
	if err := w.sync.Apply(ctx, state, event.ID); err != nil {
		return err
	}
	if event.Type == TrialWillEndEvent {
		return w.trials.Warn(ctx, state.OrgID, state.TrialEndsAt, event.ID)
	}
	return nil
}

// applyInvoice records one invoice's current state.
func (w *Webhook) applyInvoice(
	ctx context.Context, event stripeadapter.Event, payload []byte,
) error {
	state, err := w.verifier.InvoiceFor(ctx, payload)
	if err != nil {
		// Not every invoice event names an invoice this build records. A
		// one-off invoice raised by an operator has no subscription and so no
		// organization; `invoice.upcoming` is a preview with no id at all.
		// Neither is a failure, and asking Stripe to redeliver them would park
		// an event that can never apply.
		w.log.DebugContext(ctx, "an invoice event names no invoice this build records",
			"event_id", event.ID, "type", event.Type, "reason", err)
		return nil
	}
	return w.invoices.Record(ctx, state, event.ID)
}

// note records why an event failed, without marking it processed.
func (w *Webhook) note(ctx context.Context, eventID string, cause error) {
	if err := w.events.MarkFailed(ctx, eventID, cause); err != nil {
		w.log.ErrorContext(ctx, "could not record a webhook failure",
			"error", err, "event_id", eventID)
	}
}
