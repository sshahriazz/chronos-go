package api

import (
	"context"
	"time"

	"connectrpc.com/connect"

	billingv1 "github.com/chronos/chronos-go/gen/proto/chronos/billing/v1"
	"github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Invoices is billing's read side, narrowed to what this layer calls.
type Invoices interface {
	List(ctx context.Context, query app.ListInvoicesQuery) (app.InvoicePage, error)
}

// ListInvoices returns the organization's billing history, newest first.
//
// The organization comes from the CONTEXT and never from the request, for the
// reason the portal handler gives: gate 2 authorised `billing_viewer` against
// the organization gate 1 resolved, so a request that named a different one
// would be authorised against one tenant and read another's spend.
func (s *Service) ListInvoices(
	ctx context.Context, req *connect.Request[billingv1.ListInvoicesRequest],
) (*connect.Response[billingv1.ListInvoicesResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the billing handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}

	result, err := s.invoices.List(ctx, app.ListInvoicesQuery{
		OrgID:     tenant.OrgID,
		PageSize:  int(req.Msg.GetPageSize()),
		PageToken: req.Msg.GetPageToken(),
	})
	if err != nil {
		return nil, fail(err)
	}

	out := make([]*billingv1.Invoice, 0, len(result.Invoices))
	for _, inv := range result.Invoices {
		out = append(out, &billingv1.Invoice{
			InvoiceId:  inv.InvoiceID,
			Number:     inv.Number,
			Status:     inv.Status,
			AmountDue:  inv.AmountDue,
			AmountPaid: inv.AmountPaid,
			Currency:   inv.Currency,
			// UNSET rather than year 1 when there is none. A one-off invoice
			// reports no period, and `0001-01-01T00:00:00Z` on a billing page is
			// a rendering bug wearing a date — one a client cannot distinguish
			// from a real, very old value.
			PeriodStart: timestamp(inv.PeriodStart),
			PeriodEnd:   timestamp(inv.PeriodEnd),
			HostedUrl:   inv.HostedURL,
			CreatedAt:   timestamp(inv.CreatedAt),
		})
	}

	return connect.NewResponse(&billingv1.ListInvoicesResponse{
		Invoices:      out,
		NextPageToken: result.NextPageToken,
	}), nil
}

// timestamp renders an instant, or nil when there is none.
func timestamp(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.UTC())
}
