package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/billing/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// InvoiceState is Stripe's current answer about one invoice, as re-fetched.
//
// The same shape as domain.Observation and deliberately a separate type: this
// one crosses the adapter boundary, and a domain type that the Stripe adapter
// constructed would make the adapter a producer of domain state rather than of
// facts about somebody else's system.
type InvoiceState struct {
	OrgID          string
	InvoiceID      string
	SubscriptionID string
	Number         string
	Status         string
	AmountDue      int64
	AmountPaid     int64
	Currency       string
	PeriodStart    time.Time
	PeriodEnd      time.Time
	HostedURL      string
	PDFURL         string
	CreatedAt      time.Time
}

// Invoices records what Stripe reports about invoices.
//
// # Why this appends an event instead of writing the row
//
// The webhook endpoint is a REQUEST HANDLER, and nothing in this system writes
// PostgreSQL from one: writes go to the event log and projectors fill the read
// model, so every projected table is reconstructable by replaying from position
// zero. An invoice mirror is no exception — a table filled directly by an
// endpoint is a table a rebuild silently empties.
type Invoices struct {
	repo *eventsourcing.Repository[*domain.Invoice]
	now  func() time.Time
}

// InvoicesDeps is what Invoices needs.
type InvoicesDeps struct {
	Repo *eventsourcing.Repository[*domain.Invoice]
	Now  func() time.Time
}

func NewInvoices(d InvoicesDeps) (*Invoices, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("billing: an invoice repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("billing: a clock is required")
	}
	return &Invoices{repo: d.Repo, now: d.Now}, nil
}

// Record observes one invoice.
//
// Convergent: it records Stripe's CURRENT state rather than applying a delta, so
// a duplicate or out-of-order webhook reaches the same place. The aggregate
// appends nothing when the state is unchanged, which is what stops a redelivery
// from growing the stream.
func (i *Invoices) Record(ctx context.Context, state InvoiceState, eventID string) error {
	switch {
	case state.InvoiceID == "":
		return fmt.Errorf("billing: an invoice observation needs Stripe's invoice id")
	case eventID == "":
		return fmt.Errorf("billing: an invoice observation needs the Stripe event id it " +
			"derives its idempotency from")
	}

	key := domain.InvoiceStreamKey(state.InvoiceID)
	invoice, err := i.repo.Load(ctx, key)
	if err != nil {
		return fmt.Errorf("billing: loading invoice %s: %w", state.InvoiceID, err)
	}

	now := i.now().UTC()
	if err := invoice.Record(domain.Observation{
		OrgID: state.OrgID, InvoiceID: state.InvoiceID,
		SubscriptionID: state.SubscriptionID, Number: state.Number, Status: state.Status,
		AmountDue: state.AmountDue, AmountPaid: state.AmountPaid, Currency: state.Currency,
		PeriodStart: state.PeriodStart, PeriodEnd: state.PeriodEnd,
		HostedURL: state.HostedURL, PDFURL: state.PDFURL,
		CreatedAt: state.CreatedAt,
	}, now); err != nil {
		// POISON, every one of them. Each rejection is about the CONTENT of a
		// re-fetched Stripe object — an unknown status, a missing currency, a
		// negative amount, an invoice that changed tenant — and a retry re-fetches
		// the same object and is refused identically. Returning a plain error
		// would have Stripe redeliver for three days and then give up quietly.
		return fmt.Errorf("%w: %w", eventsourcing.ErrPoison, err)
	}

	if _, err := i.repo.Save(ctx, key, invoice, eventID+":invoice",
		eventsourcing.Metadata{
			OrgID: state.OrgID, OccurredAt: now,
			// No SubjectIDs. An invoice notifies nobody — Stripe emails its own
			// receipts, and billing.md §5 case 5 refuses to double-message a
			// customer about money.
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another delivery won the race and recorded the same observation,
			// because both re-fetched the same object.
			return nil
		}
		return fmt.Errorf("billing: recording invoice %s: %w", state.InvoiceID, err)
	}
	return nil
}
