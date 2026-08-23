//go:build integration

package projection_test

import (
	"context"
	"os"
	"testing"
	"time"

	billingdb "github.com/chronos/chronos-go/gen/sqlc/billing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/jackc/pgx/v5/pgtype"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The invoice projection's statements, run against the real schema.
//
// Asserted at this level rather than end to end for the reason workspace's
// invitation statements are: the properties here are properties of the
// STATEMENT — what a redelivered event does to a row a later event already
// moved, and what row security does to a query that names another tenant.
// Reproducing either end to end would need a subscription to deliver out of
// order, which it does not, which is exactly why that class of bug is invisible
// until it is not.
func TestInvoiceProjectionStatements(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)

	// invoice_view carries row security, so every statement below runs under a
	// scope. Connecting as chronos_app and forgetting the scope would make every
	// read return nothing and every assertion pass vacuously.
	orgID := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]

	scoped := func(t *testing.T, org string, fn func(q *billingdb.Queries)) {
		t.Helper()
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatalf("begin: %v", err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", org); err != nil {
			t.Fatalf("scope: %v", err)
		}
		fn(billingdb.New(tx))
		if err := tx.Commit(ctx); err != nil {
			t.Fatalf("commit: %v", err)
		}
	}

	freshInvoice := func() string {
		return "in_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]
	}

	draft := func(id string, created time.Time) billingdb.UpsertInvoiceParams {
		return billingdb.UpsertInvoiceParams{
			InvoiceID: id, OrgID: orgID, StripeSubscriptionID: "sub_1",
			Number: "", Status: "draft",
			AmountDue: 2400, AmountPaid: 0, Currency: "usd",
			PeriodStart: ts(created), PeriodEnd: ts(created.AddDate(0, 1, 0)),
			HostedUrl: "", PdfUrl: "",
			CreatedAt: ts(created), UpdatedAt: ts(created),
		}
	}

	// A REDELIVERED `invoice.created` DOES NOT UNDO A PAYMENT.
	//
	// This is the failure `invitation_view` actually shipped, in its billing
	// form: the conflict clause writes the CURRENT state, so an old event
	// arriving after a newer one must not put the row back. What makes it safe
	// here is the RE-FETCH — both deliveries ask Stripe for the object and write
	// what is true now — so the statement is asserted to overwrite everything
	// EXCEPT created_at, which is immutable and would otherwise move an invoice
	// in the customer's history.
	t.Run("an upsert overwrites state but never created_at", func(t *testing.T) {
		id := freshInvoice()
		created := time.Now().UTC().Truncate(time.Microsecond)

		scoped(t, orgID, func(q *billingdb.Queries) {
			if err := q.UpsertInvoice(ctx, draft(id, created)); err != nil {
				t.Fatalf("first upsert: %v", err)
			}
		})

		paid := draft(id, created.Add(48*time.Hour)) // a DIFFERENT created_at
		paid.Status = "paid"
		paid.Number = "C1D2E3F4-0001"
		paid.AmountPaid = 2400
		paid.HostedUrl = "https://invoice.stripe.com/i/acct_1/test_1"
		paid.UpdatedAt = ts(created.Add(time.Hour))

		scoped(t, orgID, func(q *billingdb.Queries) {
			if err := q.UpsertInvoice(ctx, paid); err != nil {
				t.Fatalf("second upsert: %v", err)
			}
		})

		var gotStatus, gotNumber, gotHosted string
		var gotPaid int64
		var gotCreated time.Time
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", orgID); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT status, number, hosted_url, amount_paid, created_at
			   FROM invoice_view WHERE invoice_id = $1`, id).
			Scan(&gotStatus, &gotNumber, &gotHosted, &gotPaid, &gotCreated); err != nil {
			t.Fatalf("reading back: %v", err)
		}

		if gotStatus != "paid" || gotPaid != 2400 {
			t.Errorf("status=%q paid=%d, want paid/2400 — the current state must overwrite",
				gotStatus, gotPaid)
		}
		if gotNumber == "" || gotHosted == "" {
			t.Errorf("number=%q hosted=%q; a finalization must fill both, or the customer's "+
				"invoice has no reference and no link", gotNumber, gotHosted)
		}
		if !gotCreated.UTC().Equal(created) {
			t.Errorf("created_at moved from %v to %v; a redelivery has reordered the "+
				"customer's billing history, and the keyset cursor built on it now skips "+
				"or repeats rows", created, gotCreated.UTC())
		}
	})

	// ANOTHER TENANT'S INVOICES ARE INVISIBLE, NOT MERELY UNMATCHED.
	//
	// The list query filters on org_id AND runs under a row security policy, and
	// this asserts the POLICY: a query scoped to one organization must not see
	// another's row even though the table holds it. On a billing history the
	// failure is one company reading another's spend.
	t.Run("row security hides another organization's invoices", func(t *testing.T) {
		otherOrg := "org_" + ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:]
		id := freshInvoice()
		created := time.Now().UTC().Truncate(time.Microsecond)

		scoped(t, orgID, func(q *billingdb.Queries) {
			if err := q.UpsertInvoice(ctx, draft(id, created)); err != nil {
				t.Fatalf("seeding: %v", err)
			}
		})

		var seen int
		tx, err := pool.Begin(ctx)
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = tx.Rollback(ctx) }()
		// Scoped to the OTHER organization, and asking for the row by its own id
		// — so a policy that did nothing would return it.
		if _, err := tx.Exec(ctx, "SELECT set_config('app.org_id', $1, true)", otherOrg); err != nil {
			t.Fatal(err)
		}
		if err := tx.QueryRow(ctx,
			`SELECT count(*) FROM invoice_view WHERE invoice_id = $1`, id).Scan(&seen); err != nil {
			t.Fatalf("counting: %v", err)
		}
		if seen != 0 {
			t.Fatalf("an organization scoped to %s can see %s's invoice; this is one "+
				"company reading another's spend", otherOrg, orgID)
		}
	})

	// THE LIST IS NEWEST FIRST AND ITS CURSOR CROSSES A TIE.
	//
	// Stripe can create several invoices in the same second — a cycle and a
	// proration land together — so the sort key ends in the invoice id. A cursor
	// on the instant alone would skip or repeat, and on a billing history
	// skipping is the worse half: the invoice a customer is looking for is the
	// one they cannot find.
	t.Run("paging crosses a shared created_at without skipping or repeating", func(t *testing.T) {
		instant := time.Now().UTC().Truncate(time.Microsecond)
		want := map[string]bool{}
		scoped(t, orgID, func(q *billingdb.Queries) {
			for range 5 {
				id := freshInvoice()
				want[id] = false
				if err := q.UpsertInvoice(ctx, draft(id, instant)); err != nil {
					t.Fatalf("seeding: %v", err)
				}
			}
			// Two more at a distinct instant, so the walk also crosses a real
			// boundary rather than only a tie.
			for range 2 {
				id := freshInvoice()
				want[id] = false
				if err := q.UpsertInvoice(ctx, draft(id, instant.Add(-time.Minute))); err != nil {
					t.Fatalf("seeding: %v", err)
				}
			}
		})

		var cursorAt pgtype.Timestamptz
		cursorID := ""
		seen := 0
		for pages := 0; ; pages++ {
			if pages > 10 {
				t.Fatal("the walk did not terminate; the list is handing out a cursor forever")
			}
			var rows []billingdb.ListInvoicesRow
			scoped(t, orgID, func(q *billingdb.Queries) {
				got, err := q.ListInvoices(ctx, billingdb.ListInvoicesParams{
					OrgID: orgID, Column2: cursorAt, Column3: cursorID, Limit: 2,
				})
				if err != nil {
					t.Fatalf("page %d: %v", pages, err)
				}
				rows = got
			})
			if len(rows) == 0 {
				break
			}
			for _, r := range rows {
				if _, ours := want[r.InvoiceID]; !ours {
					continue // another test's rows share this organization
				}
				if want[r.InvoiceID] {
					t.Fatalf("invoice %s came back twice", r.InvoiceID)
				}
				want[r.InvoiceID] = true
				seen++
			}
			last := rows[len(rows)-1]
			cursorAt = pgtype.Timestamptz{Time: last.CreatedAt.Time, Valid: true}
			cursorID = last.InvoiceID
		}

		if seen != len(want) {
			for id, found := range want {
				if !found {
					t.Errorf("invoice %s was never returned; a customer looking for it "+
						"cannot find it", id)
				}
			}
		}
	})
}

func openPool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)
	return pool
}

// appDSN connects as chronos_app, never the owner: the owner bypasses RLS, and a
// test that runs as one proves nothing about what the application can see.
func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func ts(t time.Time) pgtype.Timestamptz {
	return pgtype.Timestamptz{Time: t, Valid: true}
}
