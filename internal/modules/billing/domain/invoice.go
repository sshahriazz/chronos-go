// Package domain is billing's aggregates.
//
// It may not import generated protobuf packages, Stripe's SDK, or any other
// module's internals (CONVENTIONS §2). Proto types are wire DTOs and Stripe's
// types are somebody else's wire DTOs; neither is a domain type.
package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/billing/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// InvoiceCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every invoice ever recorded.
const InvoiceCategory eventsourcing.Category = "invoice"

// InvoiceStreamKey is Stripe's invoice id.
//
// Stripe's, not one of ours, and that is the whole design: every webhook names
// Stripe's id, so a key of our own would need a mapping table looked up before
// the stream could be found — a second identifier for an object we do not own.
func InvoiceStreamKey(invoiceID string) string { return invoiceID }

// Invoice is one Stripe invoice as this system has observed it.
//
// # Why an aggregate for something with no rules of ours
//
// Stripe owns invoices completely: we set no status, compute no total and make
// no transition. So the only invariant here is the one that makes the stream
// worth having — DO NOT RECORD THE SAME STATE TWICE.
//
// That is not tidiness. Stripe sends several events per invoice (created,
// finalized, paid) and retries each of them, and the handler RE-FETCHES rather
// than trusting a payload — so two different events arriving after the invoice
// settled both observe identical state. Without this guard the stream grows a
// duplicate per redelivery forever, and the history stops meaning "what changed"
// and starts meaning "how often Stripe retried".
type Invoice struct {
	eventsourcing.Base

	invoiceID string
	orgID     string

	// The last observation, compared field by field against the next one.
	last observation
}

// observation is the comparable part of a recorded state.
//
// A struct rather than a hash so the comparison is total by construction: adding
// a field to InvoiceRecorded and forgetting it here is a compile error at the
// assignment below, whereas a hash over selected fields would silently keep
// ignoring the new one.
type observation struct {
	subscriptionID string
	number         string
	status         string
	amountDue      int64
	amountPaid     int64
	currency       string
	periodStart    time.Time
	periodEnd      time.Time
	hostedURL      string
	pdfURL         string
	createdAt      time.Time
}

var _ eventsourcing.Root = (*Invoice)(nil)

// NewInvoice returns an empty aggregate for the repository to rebuild into.
func NewInvoice() *Invoice { return &Invoice{} }

// Exists reports whether anything has been observed for this invoice.
func (i *Invoice) Exists() bool { return i.invoiceID != "" }

func (i *Invoice) InvoiceID() string { return i.invoiceID }
func (i *Invoice) OrgID() string     { return i.orgID }

// Status is the last status Stripe reported. Empty before the first
// observation.
func (i *Invoice) Status() string { return i.last.status }

// Apply rebuilds state from the log.
func (i *Invoice) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.InvoiceRecorded:
		i.invoiceID = ev.InvoiceID
		i.orgID = ev.OrgID
		i.last = observation{
			subscriptionID: ev.SubscriptionID,
			number:         ev.Number,
			status:         ev.Status,
			amountDue:      ev.AmountDue,
			amountPaid:     ev.AmountPaid,
			currency:       ev.Currency,
			periodStart:    ev.PeriodStart,
			periodEnd:      ev.PeriodEnd,
			hostedURL:      ev.HostedURL,
			pdfURL:         ev.PDFURL,
			createdAt:      ev.InvoiceCreatedAt,
		}
	}
}

// Observation is what a caller hands to Record: Stripe's current answer.
type Observation struct {
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

// Statuses is Stripe's invoice vocabulary, and the projection's CHECK
// constraint carries the same list.
//
// Validated here rather than trusted because the value is written to a column
// with a CHECK on it: an unknown status would fail the INSERT inside the
// projector, which STOPS the projection — one strange invoice takes down every
// tenant's billing history rather than just its own row.
var Statuses = map[string]bool{
	"draft": true, "open": true, "paid": true,
	"uncollectible": true, "void": true,
}

// Record observes Stripe's current answer for this invoice.
//
// Appends nothing when the answer is identical to the last one, which is the
// aggregate's only rule and the reason it exists — see the type's doc.
func (i *Invoice) Record(o Observation, at time.Time) error {
	switch {
	case o.InvoiceID == "":
		return fmt.Errorf("billing: an invoice observation needs Stripe's invoice id")
	case o.OrgID == "":
		return fmt.Errorf("billing: invoice %s names no organization", o.InvoiceID)
	case o.Currency == "":
		return fmt.Errorf("billing: invoice %s reports no currency; the amount is then a "+
			"number with no unit, which is worse on a billing page than no number at all",
			o.InvoiceID)
	case !Statuses[o.Status]:
		return fmt.Errorf("billing: invoice %s reports status %q, which is not one Stripe "+
			"documents; recording it would fail the projection's CHECK and stop every "+
			"tenant's billing history, not just this one", o.InvoiceID, o.Status)
	case o.AmountDue < 0 || o.AmountPaid < 0:
		return fmt.Errorf("billing: invoice %s reports a negative amount (%d due, %d paid), "+
			"which is not a Stripe invoice but a decode that went wrong",
			o.InvoiceID, o.AmountDue, o.AmountPaid)
	}

	// The organization must not change under an invoice. Stripe's metadata is
	// what supplies it, and an invoice that suddenly named a different tenant
	// would move a billing record across a tenant boundary — visible to the
	// wrong customer through a projection whose row security trusts this column.
	if i.Exists() && i.orgID != o.OrgID {
		return fmt.Errorf("billing: invoice %s belongs to %s and was observed under %s; "+
			"recording it would move a billing record between tenants",
			o.InvoiceID, i.orgID, o.OrgID)
	}

	next := observation{
		subscriptionID: o.SubscriptionID,
		number:         o.Number,
		status:         o.Status,
		amountDue:      o.AmountDue,
		amountPaid:     o.AmountPaid,
		currency:       o.Currency,
		periodStart:    o.PeriodStart.UTC(),
		periodEnd:      o.PeriodEnd.UTC(),
		hostedURL:      o.HostedURL,
		pdfURL:         o.PDFURL,
		createdAt:      o.CreatedAt.UTC(),
	}
	if i.Exists() && i.last == next {
		return nil // nothing changed
	}

	eventsourcing.Record(i, &contract.InvoiceRecorded{
		OrgID: o.OrgID, InvoiceID: o.InvoiceID,
		SubscriptionID: next.subscriptionID, Number: next.number, Status: next.status,
		AmountDue: next.amountDue, AmountPaid: next.amountPaid, Currency: next.currency,
		PeriodStart: next.periodStart, PeriodEnd: next.periodEnd,
		HostedURL: next.hostedURL, PDFURL: next.pdfURL,
		InvoiceCreatedAt: next.createdAt, RecordedAt: at.UTC(),
	})
	return nil
}
