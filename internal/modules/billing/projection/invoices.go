// Package projection builds billing's read model.
package projection

import (
	"context"
	"time"

	billingdb "github.com/chronos/chronos-go/gen/sqlc/billing"
	"github.com/chronos/chronos-go/internal/modules/billing/contract"
	"github.com/chronos/chronos-go/internal/modules/billing/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// InvoicesName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const InvoicesName = "invoice_view"

// Invoices builds `invoice_view`.
//
// One table, one projection, one writer (CONVENTIONS §8). Every row is an
// upsert, because an invoice is observed several times — created, finalized,
// paid — and each observation carries the whole object. There is no incremental
// update to make.
type Invoices struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Invoices)(nil)

// NewInvoices wires the handler.
func NewInvoices(codec eventsourcing.Codec) *Invoices {
	d := projection.NewDispatch(codec)

	d.On[contract.InvoiceRecorded](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvoiceRecorded,
	) error {
		// Zero times become NULL rather than year 1. A one-off invoice reports
		// no period, and `0001-01-01` on a billing screen is a rendering bug
		// wearing a date.
		w.Exec(billingdb.UpsertInvoice,
			e.InvoiceID, e.OrgID, e.SubscriptionID, e.Number, e.Status,
			e.AmountDue, e.AmountPaid, e.Currency,
			nullableTime(e.PeriodStart), nullableTime(e.PeriodEnd),
			e.HostedURL, e.PDFURL,
			e.InvoiceCreatedAt, e.RecordedAt)
		return nil
	})

	return &Invoices{dispatch: d}
}

func (i *Invoices) Name() string { return InvoicesName }

// Filter covers invoice streams only.
func (i *Invoices) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.InvoiceCategory) + "-"},
	}
}

func (i *Invoices) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return i.dispatch.Apply(ctx, w, env)
}

// Reset empties the table for a rebuild.
func (i *Invoices) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, billingdb.TruncateInvoices)
	return err
}

// nullableTime turns a zero time into a NULL rather than year 1.
//
// A one-off invoice reports no billing period, and `0001-01-01` on a billing
// screen is a rendering bug wearing a date. NULL says "there is none", which is
// what a reader has to branch on anyway.
func nullableTime(t time.Time) *time.Time {
	if t.IsZero() {
		return nil
	}
	utc := t.UTC()
	return &utc
}
