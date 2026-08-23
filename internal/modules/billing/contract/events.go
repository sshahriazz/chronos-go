// Package contract is billing's public event surface: what other modules and
// every binary may import (CONVENTIONS §2).
package contract

import "time"

// InvoiceRecorded mirrors what Stripe reported about one invoice.
//
// # It records an OBSERVATION, not a decision
//
// Every other event in this system records something this system DECIDED. This
// one records something it was TOLD: at time T, Stripe said invoice X was in
// state Y. That distinction is why it carries a timestamp for the observation
// separately from Stripe's own creation instant, and why replaying the stream
// gives a history of what we believed rather than of what we did.
//
// The values are Stripe's, unaltered. billing.md §6 states the rule for
// discounts and it generalises to every number here: we never compute a total,
// because reimplementing the arithmetic guarantees the two disagree eventually.
//
// # No personal data
//
// An invoice in Stripe carries a billing address, a name and an email. NONE of
// them are here (ADR-002). What is here is an id, a status, two amounts, a
// currency, a period and two URLs — and the URLs are Stripe's own hosted pages,
// which are reachable only with the token they embed.
type InvoiceRecorded struct {
	OrgID string

	// InvoiceID is Stripe's, and is the stream this is recorded on.
	InvoiceID string

	// SubscriptionID is what produced the invoice. Empty for a one-off invoice,
	// which this build does not create but an operator can raise in Stripe.
	SubscriptionID string

	// Number is the HUMAN-FACING reference (`INV-0001`), which is not the id and
	// is what a customer quotes to support. Empty until Stripe finalizes: a
	// draft has no number, and inventing one would create a reference nobody
	// else can match.
	Number string

	// Status is Stripe's own vocabulary — draft, open, paid, uncollectible,
	// void — not a mapping of ours. This value is shown to people, and a
	// translation would make our word and the word on Stripe's dashboard differ
	// during exactly the conversation where they must not.
	Status string

	// AmountDue and AmountPaid are MINOR UNITS as Stripe sent them: cents, or
	// whatever the currency's smallest denomination is. Not converted, because
	// converting means choosing a scale per currency, which is arithmetic.
	AmountDue  int64
	AmountPaid int64

	// Currency is ISO 4217, lower case, as Stripe sends it. billing.md §5 case
	// 12 locks a customer's currency to their first invoice, so this is also
	// where that fact becomes observable.
	Currency string

	// The billing period the invoice covers, as Stripe reports it. Zero when
	// Stripe reports none, which a one-off invoice does.
	PeriodStart time.Time
	PeriodEnd   time.Time

	// Stripe's hosted invoice page and PDF. We render neither.
	HostedURL string
	PDFURL    string

	// InvoiceCreatedAt is Stripe's creation instant — the ordering a person
	// reading their billing history expects, and immutable.
	InvoiceCreatedAt time.Time

	// RecordedAt is when WE observed this state. A different fact from the one
	// above, and the one that answers "how current is our copy".
	RecordedAt time.Time
}

func (*InvoiceRecorded) EventType() string { return "billing.InvoiceRecorded.v1" }
