package stripe

import (
	"context"
	"errors"
	"fmt"
	"time"

	stripe "github.com/stripe/stripe-go/v86"
	"github.com/stripe/stripe-go/v86/webhook"

	billingapp "github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

// ErrBadSignature is a payload that did not come from Stripe, or was altered.
var ErrBadSignature = errors.New("stripe: the webhook signature does not verify")

// Verifier checks a webhook's signature and re-fetches what it names.
type Verifier struct {
	api     *stripe.Client
	secrets []string
}

// NewVerifier builds one. At least one secret is required.
func NewVerifier(secretKey string, webhookSecrets []string) (*Verifier, error) {
	if secretKey == "" {
		return nil, fmt.Errorf("stripe: an API key is required to re-fetch what a webhook names")
	}
	if len(webhookSecrets) == 0 {
		// Refused at construction, so the endpoint is never SERVED without
		// verification. An endpoint that accepted unverified events would be an
		// unauthenticated way to suspend a tenant or mark one active.
		return nil, fmt.Errorf("stripe: at least one webhook signing secret is required; an " +
			"unverified webhook is an unauthenticated request that changes billing state")
	}
	return &Verifier{api: stripe.NewClient(secretKey), secrets: webhookSecrets}, nil
}

// Event is the verified envelope, before anything is trusted from its body.
type Event struct {
	ID   string
	Type string
}

// Verify checks the signature against every live secret.
//
// # The raw body, and nothing that has been through a JSON round trip
//
// The signature covers the exact bytes Stripe sent. Any middleware that decodes
// and re-encodes the payload — even to identical-looking JSON — changes those
// bytes and every signature fails, with an error that says the signature is
// wrong rather than that something rewrote the body.
//
// # Why more than one secret
//
// Rotation. Both the incoming and outgoing secrets are accepted while a rotation
// is in flight (billing.md §5 case 26), so no event is dropped between updating
// Stripe and restarting the process. Stripe retries for three days, so a dropped
// event is recoverable — but the alarm it raises at 3am is not worth the
// simplicity of one value.
func (v *Verifier) Verify(payload []byte, signatureHeader string) (Event, error) {
	var lastErr error
	for _, secret := range v.secrets {
		event, err := webhook.ConstructEventWithOptions(payload, signatureHeader, secret,
			webhook.ConstructEventOptions{
				// The signature and the timestamp tolerance stay ON. Only the
				// API-VERSION check is relaxed, and only because of how little
				// of the payload this build actually reads.
				//
				// # Why it is safe HERE
				//
				// SubscriptionFor takes exactly two strings out of the event —
				// `data.object.id` and `data.object.object` — and re-fetches
				// everything else through the SDK, which speaks its own pinned
				// version. So the shape of the delivered payload cannot change
				// what this system believes; the re-fetch decides that
				// (billing.md §4 step 5).
				//
				// # What it would cost elsewhere
				//
				// The moment any handler reads a FIELD off the event body, this
				// has to go back to false: an older version can spell that field
				// differently, and the result is a silent wrong answer rather
				// than a loud failure.
				//
				// # Why not just match the versions
				//
				// They are set in two places nobody keeps in step. The account's
				// default event version is a dashboard setting — this account
				// emits 2026-04-22.dahlia — and the SDK's is a Go module version
				// (2026-07-29.dahlia in v86). Requiring equality makes every
				// SDK bump a coordinated dashboard change, and makes
				// `stripe listen` fail with a message about the version that
				// reads like a broken signing secret.
				IgnoreAPIVersionMismatch: true,
			})
		if err == nil {
			return Event{ID: event.ID, Type: string(event.Type)}, nil
		}
		lastErr = err
	}
	return Event{}, fmt.Errorf("%w: %w", ErrBadSignature, lastErr)
}

// eventEnvelope is the sliver of a Stripe event this build reads directly.
//
// Deliberately tiny: the ID and the object kind, and nothing else. Every other
// field comes from the re-fetch, so a change to Stripe's payload shape cannot
// alter what this system believes.
type eventEnvelope struct {
	Data struct {
		Object struct {
			ID     string `json:"id"`
			Object string `json:"object"`
		} `json:"object"`
	} `json:"data"`
}

// SubscriptionFor re-fetches the subscription an event names.
//
// # Why the payload is never trusted
//
// billing.md §4 step 5, and it is the step people skip: Stripe does not
// guarantee ordering, so applying a payload as a delta will eventually apply a
// stale one. Re-fetching makes the handler CONVERGENT — processing an old event
// a second time reaches the same state as processing it once.
//
// The Customer Portal makes this mandatory rather than advisable. A customer can
// cancel or switch plans entirely inside Stripe's hosted UI, so for a large
// class of changes the webhook is the only signal we ever get, and its payload
// is a snapshot from whenever Stripe happened to emit it.
func (v *Verifier) SubscriptionFor(ctx context.Context, payload []byte) (app.SubscriptionState, error) {
	// TOLERANT, because this is somebody else's document: Stripe adds fields to
	// its events and a strict decode would turn "Stripe shipped a feature" into
	// "billing is broken". ADR-047 is explicit that this is the case Tolerant
	// exists for.
	//
	// Only the ID is taken from the payload. Everything else comes from the
	// re-fetch below.
	envelope, err := codec.Tolerant[eventEnvelope](payload)
	if err != nil {
		return app.SubscriptionState{}, fmt.Errorf("stripe: reading the event envelope: %w", err)
	}
	id := envelope.Data.Object.ID
	if envelope.Data.Object.Object != "subscription" || id == "" {
		return app.SubscriptionState{}, fmt.Errorf("stripe: this event does not name a "+
			"subscription (object %q)", envelope.Data.Object.Object)
	}

	sub, err := v.api.V1Subscriptions.Retrieve(ctx, id, nil)
	if err != nil {
		return app.SubscriptionState{}, fmt.Errorf("stripe: re-fetching subscription %s: %w",
			id, err)
	}

	orgID := sub.Metadata[orgMetadataKey]
	if orgID == "" {
		return app.SubscriptionState{}, fmt.Errorf("stripe: subscription %s carries no %s in "+
			"its metadata, so it belongs to no organization this system knows",
			id, orgMetadataKey)
	}

	// GraceEndsAt is deliberately left unset, and the use case supplies its own
	// default. `current_period_end` moved off the Subscription onto its items in
	// recent API versions, and reassembling it from there would be reimplementing
	// Stripe's billing-period arithmetic — which billing.md §6 refuses for
	// discounts and the same reasoning covers. Stripe owns the retry SCHEDULE;
	// what we hold is only what the customer is shown.
	// The deadline as STRIPE reports it, not as we might compute it. The warning
	// mail states a date, and a date computed here could differ from the one the
	// subscription actually enforces — which is a support ticket that begins
	// "your email said the 14th".
	var trialEndsAt time.Time
	if sub.TrialEnd != 0 {
		trialEndsAt = time.Unix(sub.TrialEnd, 0).UTC()
	}

	return app.SubscriptionState{
		OrgID:          orgID,
		SubscriptionID: sub.ID,
		Status:         domain.StripeStatus(sub.Status),
		TrialEndsAt:    trialEndsAt,
	}, nil
}

// InvoiceFor re-fetches the invoice an event names.
//
// The same discipline as SubscriptionFor and for the same reason (billing.md §4
// step 5): only the object ID is read from the payload, and every value comes
// from the re-fetch. Stripe does not guarantee ordering, so applying a payload
// as a delta will eventually apply a stale one.
//
// # Where the organization comes from
//
// Stripe's Invoice carries its own metadata, but ours is written on the CUSTOMER
// and the SUBSCRIPTION by the provisioner — not on invoices, which Stripe
// creates itself. So the org id is read from the invoice's parent subscription,
// which is where provisioning put it.
//
// An invoice with no subscription is not an error worth parking: Stripe permits
// an operator to raise a one-off invoice by hand, and this build has nothing to
// say about one. It is reported as "not ours" and skipped.
func (v *Verifier) InvoiceFor(ctx context.Context, payload []byte) (billingapp.InvoiceState, error) {
	// TOLERANT, because this is somebody else's document (ADR-047).
	envelope, err := codec.Tolerant[eventEnvelope](payload)
	if err != nil {
		return billingapp.InvoiceState{}, fmt.Errorf("stripe: reading the event envelope: %w", err)
	}
	id := envelope.Data.Object.ID
	if envelope.Data.Object.Object != "invoice" || id == "" {
		return billingapp.InvoiceState{}, fmt.Errorf("stripe: this event does not name an "+
			"invoice (object %q)", envelope.Data.Object.Object)
	}

	inv, err := v.api.V1Invoices.Retrieve(ctx, id, nil)
	if err != nil {
		return billingapp.InvoiceState{}, fmt.Errorf("stripe: re-fetching invoice %s: %w", id, err)
	}

	subscriptionID, snapshot := invoiceParent(inv)
	if subscriptionID == "" {
		return billingapp.InvoiceState{}, fmt.Errorf("stripe: invoice %s names no "+
			"subscription, so it is a one-off this build does not record", id)
	}

	// # Two ways to the organization, and the cheap one is tried first
	//
	// Stripe snapshots the subscription's metadata onto the invoice at
	// FINALIZATION, so a finalized invoice already carries our org id and needs
	// no second round trip. It is not a payload we are trusting — it arrived on
	// the object this method just re-fetched.
	//
	// A DRAFT has no snapshot yet, and invoices created before June 2023 never
	// got one. For those the subscription itself is fetched, which is where
	// provisioning wrote the id in the first place. Falling back rather than
	// always fetching keeps the common case to one call; falling back at all is
	// what stops a draft invoice from being unattributable.
	orgID := snapshot[orgMetadataKey]
	if orgID == "" {
		sub, err := v.api.V1Subscriptions.Retrieve(ctx, subscriptionID, nil)
		if err != nil {
			return billingapp.InvoiceState{}, fmt.Errorf(
				"stripe: re-fetching subscription %s for invoice %s: %w", subscriptionID, id, err)
		}
		orgID = sub.Metadata[orgMetadataKey]
	}
	if orgID == "" {
		return billingapp.InvoiceState{}, fmt.Errorf("stripe: neither invoice %s nor "+
			"subscription %s carries %s in its metadata, so it belongs to no organization "+
			"this system knows", id, subscriptionID, orgMetadataKey)
	}

	return billingapp.InvoiceState{
		OrgID:          orgID,
		InvoiceID:      inv.ID,
		SubscriptionID: subscriptionID,
		Number:         inv.Number,
		Status:         string(inv.Status),
		AmountDue:      inv.AmountDue,
		AmountPaid:     inv.AmountPaid,
		Currency:       string(inv.Currency),
		PeriodStart:    unixUTC(inv.PeriodStart),
		PeriodEnd:      unixUTC(inv.PeriodEnd),
		HostedURL:      inv.HostedInvoiceURL,
		PDFURL:         inv.InvoicePDF,
		CreatedAt:      unixUTC(inv.Created),
	}, nil
}

// unixUTC turns Stripe's epoch seconds into a UTC time, and 0 into a zero time.
//
// Stripe writes 0 for "no value", which as an epoch is 1970 — a date that
// renders happily and means nothing. The zero time is what the projection turns
// into NULL.
func unixUTC(sec int64) time.Time {
	if sec == 0 {
		return time.Time{}
	}
	return time.Unix(sec, 0).UTC()
}

// invoiceParent reads the subscription an invoice came from, and the metadata
// Stripe snapshotted from it.
//
// `Invoice.Subscription` no longer exists: recent API versions moved it under
// `Parent`, alongside a quote parent for invoices that came from one. The nested
// Subscription is expandable, so it can arrive as a stub carrying only an id —
// which is all this needs.
func invoiceParent(inv *stripe.Invoice) (subscriptionID string, metadata map[string]string) {
	if inv == nil || inv.Parent == nil || inv.Parent.SubscriptionDetails == nil {
		return "", nil
	}
	details := inv.Parent.SubscriptionDetails
	if details.Subscription != nil {
		subscriptionID = details.Subscription.ID
	}
	return subscriptionID, details.Metadata
}
