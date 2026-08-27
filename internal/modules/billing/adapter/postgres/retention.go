package postgres

import (
	"context"
	"fmt"

	billingdb "github.com/chronos/chronos-go/gen/sqlc/billing"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// RetainedInvoices answers whether a person appears on a financial record that
// tax law requires us to keep (compliance.md §7).
//
// # A SYSTEM transaction, and why that is not a hole
//
// The question spans every organization the subject belongs to, and an erasure
// has no tenant scope — there is no single organization it happens "in". A
// tenant transaction would need one org chosen from the several a person may
// belong to, and would then answer about that one while the confirmation speaks
// about all of them.
//
// What makes it safe is the SHAPE of the answer: the statement returns a single
// boolean, filtered by `subject_id`, and no invoice, organization, amount or
// count crosses the boundary. There is nothing here for a caller to read out of
// another tenant, because nothing about any tenant is returned.
//
// The alternative — running it under whichever scope happened to be current —
// would be the actual hole: it would silently answer "no invoices" for a person
// whose invoices are in the org that is not in scope, which is the
// under-statement compliance.md §7 names as the misleading one.
type RetainedInvoices struct{ tx db.SystemTX }

// NewRetainedInvoices builds the reader.
func NewRetainedInvoices(tx db.SystemTX) (*RetainedInvoices, error) {
	if tx == nil {
		return nil, fmt.Errorf("billing: a system transaction source is required to " +
			"answer whether a subject appears on a retained invoice; the question spans " +
			"every organization they belong to and an erasure has no tenant scope")
	}
	return &RetainedInvoices{tx: tx}, nil
}

// HasInvoices reports whether any organization this subject belongs to has been
// invoiced.
//
// An error is returned rather than swallowed. The caller (compliance's
// Exemptions) states the class anyway and logs — the over-inclusive direction —
// and that decision belongs there, where the reason for it is written down,
// rather than here where it would look like a default.
func (r *RetainedInvoices) HasInvoices(ctx context.Context, subjectID string) (bool, error) {
	if subjectID == "" {
		return false, fmt.Errorf("billing: a subject is required")
	}
	var has bool
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, billingdb.SubjectHasRetainedInvoices, subjectID).Scan(&has)
	})
	if err != nil {
		return false, fmt.Errorf("billing: asking whether %s appears on a retained "+
			"invoice: %w", subjectID, err)
	}
	return has, nil
}
