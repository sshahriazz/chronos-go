package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/jackc/pgx/v5/pgtype"

	billingdb "github.com/chronos/chronos-go/gen/sqlc/billing"
	"github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// InvoiceReads is the read side of invoice_view.
//
// A TENANT transaction: every caller reaches it after gate 1 has resolved a
// scope, so the row security policy applies and another organization's invoices
// are invisible rather than merely unmatched. That distinction matters more here
// than almost anywhere — a missing WHERE on a billing history is one customer
// reading another's spend.
type InvoiceReads struct{ tx db.TX }

var _ app.InvoiceReader = (*InvoiceReads)(nil)

func NewInvoiceReads(tx db.TX) (*InvoiceReads, error) {
	if tx == nil {
		return nil, fmt.Errorf("billing: a transaction source is required")
	}
	return &InvoiceReads{tx: tx}, nil
}

// List returns one page, newest first, keyset-ordered by (created_at, invoice_id).
//
// A START cursor passes a NULL timestamp, which the query reads as "no lower
// bound" — so "first page" and "resume" are ONE statement rather than two that
// could drift apart.
func (r *InvoiceReads) List(
	ctx context.Context, orgID string, after page.Keyset, size page.Size,
) ([]app.Invoice, error) {
	var afterCreated pgtype.Timestamptz
	afterID := ""
	if !after.IsStart() {
		args := after.Args()
		if len(args) != 2 {
			return nil, fmt.Errorf("billing: a cursor for this list needs 2 keys, got %d",
				len(args))
		}
		created, ok := args[0].(time.Time)
		if !ok {
			return nil, fmt.Errorf("billing: the cursor's instant is %T, not a time", args[0])
		}
		id, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("billing: the cursor's id is %T, not a string", args[1])
		}
		afterCreated = pgtype.Timestamptz{Time: created.UTC(), Valid: true}
		afterID = id
	}

	var out []app.Invoice
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		if size > page.Size(math.MaxInt32) {
			return fmt.Errorf("billing: a page size of %d does not fit a query limit", size)
		}
		limit := int32(size) //nolint:gosec // bounded on the line above

		rows, err := q.Query(ctx, billingdb.ListInvoices, orgID, afterCreated, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var inv app.Invoice
			var periodStart, periodEnd pgtype.Timestamptz
			var createdAt time.Time
			if err := rows.Scan(
				&inv.InvoiceID, &inv.Number, &inv.Status,
				&inv.AmountDue, &inv.AmountPaid, &inv.Currency,
				&periodStart, &periodEnd,
				&inv.HostedURL, &inv.PDFURL, &createdAt,
			); err != nil {
				return err
			}
			if periodStart.Valid {
				inv.PeriodStart = periodStart.Time.UTC()
			}
			if periodEnd.Valid {
				inv.PeriodEnd = periodEnd.Time.UTC()
			}
			inv.CreatedAt = createdAt.UTC()
			out = append(out, inv)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("billing: listing invoices for %s: %w", orgID, err)
	}
	return out, nil
}
