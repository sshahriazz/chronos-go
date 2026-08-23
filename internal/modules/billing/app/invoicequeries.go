package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// invoicesQueryID binds a page token to THIS list.
const invoicesQueryID page.QueryID = "billing.invoice_view.by_org"

// invoiceSortColumns is the sort key, and it ends in a UNIQUE column.
//
// Stripe can create several invoices in the same second — a subscription cycle
// and a proration land together — so a cursor on the instant alone would either
// skip an invoice or repeat one. On a billing history, skipping is the worse
// half: the invoice a customer is looking for is the one they cannot find.
var invoiceSortColumns = []string{"created_at", "invoice_id"}

// Invoice is one row of the billing history.
//
// A reference and a status. Amounts are MINOR UNITS as Stripe sent them, never
// converted — see the contract event for why converting is arithmetic we refuse
// to reimplement.
type Invoice struct {
	InvoiceID   string
	Number      string
	Status      string
	AmountDue   int64
	AmountPaid  int64
	Currency    string
	PeriodStart time.Time
	PeriodEnd   time.Time
	HostedURL   string
	PDFURL      string
	CreatedAt   time.Time
}

// InvoicePage is one page of it.
type InvoicePage struct {
	Invoices      []Invoice
	NextPageToken string
}

// InvoiceReader is the read side of invoice_view.
//
// Declared by the consumer, satisfied by the adapter (CONVENTIONS §2). It writes
// nothing: the projector owns that table.
type InvoiceReader interface {
	List(ctx context.Context, orgID string, after page.Keyset, size page.Size) ([]Invoice, error)
}

// ListInvoicesQuery is what the caller asks for.
type ListInvoicesQuery struct {
	OrgID     string
	PageSize  int
	PageToken string
}

// InvoiceQueries serves the billing history.
type InvoiceQueries struct{ reads InvoiceReader }

func NewInvoiceQueries(reads InvoiceReader) (*InvoiceQueries, error) {
	if reads == nil {
		return nil, fmt.Errorf("billing: an invoice reader is required")
	}
	return &InvoiceQueries{reads: reads}, nil
}

// List returns one page of the organization's invoices, newest first.
//
// An EMPTY list is an ordinary answer, not a fault: a trialing organization has
// no invoices and a paused one generates none, so most tenants see nothing here
// for their first fourteen days.
func (q *InvoiceQueries) List(
	ctx context.Context, query ListInvoicesQuery,
) (InvoicePage, error) {
	if query.OrgID == "" {
		return InvoicePage{}, errs.Internalf("no organization reached the invoice list; " +
			"gate 1 resolved none")
	}

	size, err := page.Clamp(query.PageSize)
	if err != nil {
		return InvoicePage{}, errs.ValidationFailedf("page size: %v", err).Wrap(err)
	}

	// Every token failure is an ERROR and none of them is "start again". A
	// client handed page one for a token it believes points into the middle
	// walks the list forever, and nothing in the loop looks like a failure.
	cursor, err := page.Resume(page.Token(query.PageToken), invoicesQueryID)
	if err != nil {
		return InvoicePage{}, errs.ValidationFailedf(
			"this page token cannot be used for this list; restart from the first page").Wrap(err)
	}
	if !cursor.IsStart() && !slices.Equal(cursor.Columns(), invoiceSortColumns) {
		return InvoicePage{}, errs.ValidationFailedf(
			"this page token names the columns %v, but this list is sorted by %v",
			cursor.Columns(), invoiceSortColumns)
	}

	// One MORE than asked for, so "is there another page" is answered by the
	// query rather than guessed from a full page.
	rows, err := q.reads.List(ctx, query.OrgID, cursor, size+1)
	if err != nil {
		return InvoicePage{}, errs.Internalf("listing invoices").Wrap(err)
	}

	if len(rows) <= int(size) {
		return InvoicePage{Invoices: rows}, nil
	}
	rows = rows[:size]

	last := rows[len(rows)-1]
	keyset, err := page.NewKeyset(
		page.Key{Column: invoiceSortColumns[0], Value: last.CreatedAt},
		page.Key{Column: invoiceSortColumns[1], Value: last.InvoiceID, Unique: true},
	)
	if err != nil {
		return InvoicePage{}, errs.Internalf("building a page cursor").Wrap(err)
	}
	token, err := page.Encode(keyset, invoicesQueryID)
	if err != nil {
		return InvoicePage{}, errs.Internalf("encoding a page cursor").Wrap(err)
	}
	return InvoicePage{Invoices: rows, NextPageToken: string(token)}, nil
}
