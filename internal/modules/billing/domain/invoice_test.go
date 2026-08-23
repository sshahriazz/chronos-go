package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/billing/contract"
	"github.com/chronos/chronos-go/internal/modules/billing/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var (
	recordedAt = time.Date(2026, 3, 14, 9, 0, 0, 0, time.UTC)
	createdAt  = time.Date(2026, 3, 1, 0, 0, 4, 0, time.UTC)
)

func observation() domain.Observation {
	return domain.Observation{
		OrgID:          "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		InvoiceID:      "in_1MtHbELkdIwHu7ixl4OzzPMv",
		SubscriptionID: "sub_1",
		Number:         "C1D2E3F4-0001",
		Status:         "open",
		AmountDue:      2400,
		AmountPaid:     0,
		Currency:       "usd",
		PeriodStart:    time.Date(2026, 3, 1, 0, 0, 0, 0, time.UTC),
		PeriodEnd:      time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC),
		HostedURL:      "https://invoice.stripe.com/i/acct_1/test_1",
		PDFURL:         "https://pay.stripe.com/invoice/acct_1/test_1/pdf",
		CreatedAt:      createdAt,
	}
}

// recorded returns the events an aggregate has pending.
func recorded(t *testing.T, i *domain.Invoice) []eventsourcing.Event {
	t.Helper()
	return i.Uncommitted()
}

// THE SAME OBSERVATION TWICE APPENDS ONCE.
//
// This is the aggregate's only rule and the reason it exists. Stripe sends
// several events per invoice — created, finalized, paid — and retries each of
// them, and the handler RE-FETCHES rather than trusting a payload, so two
// different events arriving after the invoice settled both observe identical
// state. Without this the stream grows a duplicate per redelivery forever, and
// the history stops meaning "what changed" and starts meaning "how often Stripe
// retried".
func TestAnUnchangedObservationAppendsNothing(t *testing.T) {
	invoice := domain.NewInvoice()

	if err := invoice.Record(observation(), recordedAt); err != nil {
		t.Fatal(err)
	}
	first := len(recorded(t, invoice))
	if first != 1 {
		t.Fatalf("the first observation appended %d events, want 1", first)
	}

	// Replay so the aggregate holds the state, the way a repository would.
	replayed := domain.NewInvoice()
	for _, e := range recorded(t, invoice) {
		replayed.Apply(e)
	}

	if err := replayed.Record(observation(), recordedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := len(recorded(t, replayed)); got != 0 {
		t.Fatalf("an identical observation appended %d events; every Stripe redelivery now "+
			"grows this invoice's history by one", got)
	}
}

// A CHANGED OBSERVATION APPENDS.
//
// The other half, without which "append nothing, ever" passes the test above —
// and an invoice would be recorded as `open` for the rest of time.
func TestAChangedObservationIsRecorded(t *testing.T) {
	invoice := domain.NewInvoice()
	if err := invoice.Record(observation(), recordedAt); err != nil {
		t.Fatal(err)
	}
	replayed := domain.NewInvoice()
	for _, e := range recorded(t, invoice) {
		replayed.Apply(e)
	}

	paid := observation()
	paid.Status = "paid"
	paid.AmountPaid = 2400
	if err := replayed.Record(paid, recordedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}

	events := recorded(t, replayed)
	if len(events) != 1 {
		t.Fatalf("a status change appended %d events, want 1", len(events))
	}
	got, ok := events[0].(*contract.InvoiceRecorded)
	if !ok {
		t.Fatalf("appended %T", events[0])
	}
	if got.Status != "paid" || got.AmountPaid != 2400 {
		t.Errorf("recorded status=%q paid=%d, want paid/2400", got.Status, got.AmountPaid)
	}
}

// EVERY FIELD PARTICIPATES IN "UNCHANGED".
//
// The comparison is a struct equality rather than a hash over selected fields,
// and this test is what makes that concrete: a change to ANY observed value has
// to be recorded, because each one is shown to a customer. A comparison that
// ignored, say, the hosted URL would leave a billing page linking to a page
// Stripe has replaced.
func TestEveryObservedFieldCountsAsAChange(t *testing.T) {
	base := observation()

	for name, mutate := range map[string]func(*domain.Observation){
		"subscription": func(o *domain.Observation) { o.SubscriptionID = "sub_2" },
		"number":       func(o *domain.Observation) { o.Number = "C1D2E3F4-0002" },
		"status":       func(o *domain.Observation) { o.Status = "void" },
		"amount due":   func(o *domain.Observation) { o.AmountDue = 9900 },
		"amount paid":  func(o *domain.Observation) { o.AmountPaid = 2400 },
		"currency":     func(o *domain.Observation) { o.Currency = "eur" },
		"period start": func(o *domain.Observation) { o.PeriodStart = o.PeriodStart.AddDate(0, 1, 0) },
		"period end":   func(o *domain.Observation) { o.PeriodEnd = o.PeriodEnd.AddDate(0, 1, 0) },
		"hosted url":   func(o *domain.Observation) { o.HostedURL = "https://invoice.stripe.com/i/acct_1/test_2" },
		"pdf url":      func(o *domain.Observation) { o.PDFURL = "https://pay.stripe.com/invoice/x/pdf" },
		"created at":   func(o *domain.Observation) { o.CreatedAt = o.CreatedAt.Add(time.Second) },
	} {
		t.Run(name, func(t *testing.T) {
			seed := domain.NewInvoice()
			if err := seed.Record(base, recordedAt); err != nil {
				t.Fatal(err)
			}
			replayed := domain.NewInvoice()
			for _, e := range seed.Uncommitted() {
				replayed.Apply(e)
			}

			changed := base
			mutate(&changed)
			if err := replayed.Record(changed, recordedAt.Add(time.Hour)); err != nil {
				t.Fatal(err)
			}
			if len(replayed.Uncommitted()) != 1 {
				t.Errorf("a change to the %s was treated as no change, so the customer's "+
					"billing page keeps showing the old value forever", name)
			}
		})
	}
}

// AN UNKNOWN STATUS IS REFUSED HERE, NOT AT THE DATABASE.
//
// `invoice_view.status` has a CHECK carrying Stripe's five values. An unknown
// one would fail the INSERT inside the PROJECTOR, which stops the projection —
// so one strange invoice takes down every tenant's billing history rather than
// just its own row.
func TestAnUnknownStatusIsRefused(t *testing.T) {
	invoice := domain.NewInvoice()

	bad := observation()
	bad.Status = "partially_refunded"
	if err := invoice.Record(bad, recordedAt); err == nil {
		t.Fatal("an unknown status was recorded; the projector will stop on it and every " +
			"tenant's billing history stops with it")
	}
	if len(invoice.Uncommitted()) != 0 {
		t.Error("refused and recorded anyway")
	}
}

// AN INVOICE MAY NOT CHANGE TENANT.
//
// The org id comes from Stripe metadata, and `invoice_view`'s row security
// policy trusts that column. An invoice that suddenly named a different
// organization would move a billing record across a tenant boundary and make it
// visible to the wrong customer.
func TestAnInvoiceCannotChangeOrganization(t *testing.T) {
	seed := domain.NewInvoice()
	if err := seed.Record(observation(), recordedAt); err != nil {
		t.Fatal(err)
	}
	replayed := domain.NewInvoice()
	for _, e := range seed.Uncommitted() {
		replayed.Apply(e)
	}

	moved := observation()
	moved.OrgID = "org_01ARZ3NDEKTSV4RRFFQ69G5FBB"
	if err := replayed.Record(moved, recordedAt.Add(time.Hour)); err == nil {
		t.Fatal("an invoice was moved to another organization; the row security policy " +
			"trusts that column, so this billing record is now visible to the wrong customer")
	}
	if len(replayed.Uncommitted()) != 0 {
		t.Error("refused and recorded anyway")
	}
}

// THE INCOMPLETE AND THE IMPOSSIBLE ARE REFUSED.
func TestAnUnusableObservationIsRefused(t *testing.T) {
	for name, mutate := range map[string]func(*domain.Observation){
		"no invoice id":   func(o *domain.Observation) { o.InvoiceID = "" },
		"no organization": func(o *domain.Observation) { o.OrgID = "" },
		"no currency":     func(o *domain.Observation) { o.Currency = "" },
		"negative due":    func(o *domain.Observation) { o.AmountDue = -1 },
		"negative paid":   func(o *domain.Observation) { o.AmountPaid = -1 },
	} {
		t.Run(name, func(t *testing.T) {
			bad := observation()
			mutate(&bad)
			invoice := domain.NewInvoice()
			if err := invoice.Record(bad, recordedAt); err == nil {
				t.Error("accepted")
			}
			if len(invoice.Uncommitted()) != 0 {
				t.Error("refused and recorded anyway")
			}
		})
	}
}
