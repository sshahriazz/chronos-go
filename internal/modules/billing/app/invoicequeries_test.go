package app_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
)

type fakeInvoiceReader struct {
	rows  []app.Invoice
	err   error
	orgID string
	after page.Keyset
	size  page.Size
	calls int
}

func (f *fakeInvoiceReader) List(
	_ context.Context, orgID string, after page.Keyset, size page.Size,
) ([]app.Invoice, error) {
	f.calls++
	f.orgID, f.after, f.size = orgID, after, size
	if f.err != nil {
		return nil, f.err
	}
	if int(size) < len(f.rows) {
		return f.rows[:size], nil
	}
	return f.rows, nil
}

func invoicesN(n int) []app.Invoice {
	out := make([]app.Invoice, 0, n)
	base := time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC)
	for i := range n {
		out = append(out, app.Invoice{
			InvoiceID: "in_" + string(rune('a'+i)),
			Status:    "paid",
			Currency:  "usd",
			CreatedAt: base.Add(-time.Duration(i) * time.Hour),
		})
	}
	return out
}

func queries(t *testing.T, reads *fakeInvoiceReader) *app.InvoiceQueries {
	t.Helper()
	q, err := app.NewInvoiceQueries(reads)
	if err != nil {
		t.Fatalf("NewInvoiceQueries: %v", err)
	}
	return q
}

// THE LIST IS SCOPED TO THE ORGANIZATION THE GATES RESOLVED.
//
// A billing history is the one list where a missing scope is somebody reading
// another company's spend.
func TestTheInvoiceListIsScopedToItsOrganization(t *testing.T) {
	reads := &fakeInvoiceReader{rows: invoicesN(2)}
	got, err := queries(t, reads).List(context.Background(), app.ListInvoicesQuery{
		OrgID: "org_theirs", PageSize: 10,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reads.orgID != "org_theirs" {
		t.Errorf("listed %q", reads.orgID)
	}
	if len(got.Invoices) != 2 {
		t.Errorf("returned %d invoices, want 2", len(got.Invoices))
	}
	if got.NextPageToken != "" {
		t.Error("a short page handed out a next-page token, so a client walks forever")
	}
}

// AN EMPTY HISTORY IS AN ORDINARY ANSWER.
//
// A trialing organization has no invoices and a paused one generates none, so
// most tenants see nothing here for their first fourteen days. Treating that as
// an error would make the normal case look broken.
func TestAnOrganizationWithNoInvoicesIsNotAnError(t *testing.T) {
	got, err := queries(t, &fakeInvoiceReader{}).List(
		context.Background(), app.ListInvoicesQuery{OrgID: "org_x", PageSize: 10})
	if err != nil {
		t.Fatalf("an empty billing history was an error: %v", err)
	}
	if len(got.Invoices) != 0 || got.NextPageToken != "" {
		t.Errorf("got %+v, want an empty page with no token", got)
	}
}

// A FULL PAGE HANDS OUT A TOKEN, AND THE WALK RESUMES WHERE IT STOPPED.
//
// One MORE row than asked for is fetched, so "is there another page" is answered
// by the query rather than guessed from a full page — guessing hands out a token
// at the exact end of the list, and the client fetches an empty page to discover
// it was already finished.
func TestAFullPageResumesFromItsLastRow(t *testing.T) {
	reads := &fakeInvoiceReader{rows: invoicesN(5)}
	q := queries(t, reads)

	first, err := q.List(context.Background(), app.ListInvoicesQuery{
		OrgID: "org_x", PageSize: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	if reads.size != 3 {
		t.Errorf("asked the reader for %d rows, want 3 — one more than the page size, so "+
			"'is there another page' is answered rather than guessed", reads.size)
	}
	if len(first.Invoices) != 2 {
		t.Fatalf("returned %d rows for a page size of 2", len(first.Invoices))
	}
	if first.NextPageToken == "" {
		t.Fatal("a full page with more behind it handed out no token; the rest of the " +
			"history is unreachable")
	}

	second, err := q.List(context.Background(), app.ListInvoicesQuery{
		OrgID: "org_x", PageSize: 2, PageToken: first.NextPageToken,
	})
	if err != nil {
		t.Fatalf("resuming: %v", err)
	}
	_ = second
	if reads.after.IsStart() {
		t.Fatal("the second page started from the beginning, so the client loops over " +
			"page one forever")
	}
	args := reads.after.Args()
	if len(args) != 2 {
		t.Fatalf("the cursor carries %d keys, want 2", len(args))
	}
	if got, want := args[1].(string), first.Invoices[1].InvoiceID; got != want {
		t.Errorf("resumed after %q, want the last row of page one (%q)", got, want)
	}
}

// A TOKEN FROM A DIFFERENT LIST IS REFUSED.
//
// Every token failure is an error and none of them is "start again": a client
// handed page one for a token it believes points into the middle walks the list
// forever, and nothing in the loop looks like a failure.
func TestAForeignPageTokenIsRefused(t *testing.T) {
	reads := &fakeInvoiceReader{rows: invoicesN(1)}

	_, err := queries(t, reads).List(context.Background(), app.ListInvoicesQuery{
		OrgID: "org_x", PageSize: 2, PageToken: "not-a-token-from-this-list",
	})
	if err == nil {
		t.Fatal("a foreign page token was accepted")
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("reason is %q, want VALIDATION_FAILED", got)
	}
	if reads.calls != 0 {
		t.Error("the reader ran with an unusable cursor")
	}
}

// AN UNREADABLE PROJECTION IS AN ERROR, NOT AN EMPTY HISTORY.
//
// Reporting an empty list would tell a customer they have never been billed.
func TestAnUnreadableProjectionIsNotAnEmptyHistory(t *testing.T) {
	_, err := queries(t, &fakeInvoiceReader{err: errors.New("postgres: down")}).List(
		context.Background(), app.ListInvoicesQuery{OrgID: "org_x", PageSize: 10})
	if err == nil {
		t.Fatal("an unreadable projection reported an empty billing history; the customer " +
			"is told they have never been billed")
	}
}

// NO ORGANIZATION IS AN INTERNAL FAILURE.
func TestAnInvoiceListNeedsAnOrganization(t *testing.T) {
	reads := &fakeInvoiceReader{}
	_, err := queries(t, reads).List(context.Background(), app.ListInvoicesQuery{PageSize: 10})
	if err == nil {
		t.Fatal("a list with no organization was served")
	}
	if reads.calls != 0 {
		t.Error("the reader ran with no organization, which is an unscoped billing query")
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
func TestInvoiceQueriesRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewInvoiceQueries(nil); err == nil {
		t.Error("a query use case with no reader was accepted")
	}
}
