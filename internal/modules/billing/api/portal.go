package api

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	billingv1 "github.com/chronos/chronos-go/gen/proto/chronos/billing/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/billing/v1/billingv1connect"
	"github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// Sessions is billing's portal use case, narrowed to what this layer calls.
//
// A port declared by the consumer (CONVENTIONS §2), narrow rather than the
// concrete struct so a handler cannot reach methods no RPC exposes.
type Sessions interface {
	Create(ctx context.Context, orgID, returnURL string) (app.PortalSession, error)
}

// Service serves BillingService.
type Service struct {
	billingv1connect.UnimplementedBillingServiceHandler

	sessions Sessions
	invoices Invoices
}

// Deps is what Service needs.
type Deps struct {
	Sessions Sessions
	Invoices Invoices
}

func New(d Deps) (*Service, error) {
	switch {
	case d.Sessions == nil:
		return nil, fmt.Errorf("billing: a portal session use case is required")
	case d.Invoices == nil:
		return nil, fmt.Errorf("billing: an invoice list use case is required; without one " +
			"ListInvoices answers 'unimplemented' and a customer being charged cannot see " +
			"what for")
	}
	return &Service{sessions: d.Sessions, invoices: d.Invoices}, nil
}

// CreateBillingPortalSession hands the caller a signed link into Stripe's
// Customer Portal.
//
// The organization comes from the CONTEXT and never from the request. There is
// no field for it in the schema and there must not be: gate 2 authorised
// `billing_manager` against the organization gate 1 resolved, so a request that
// named a different one would be authorised against one organization and act on
// another.
func (s *Service) CreateBillingPortalSession(
	ctx context.Context, req *connect.Request[billingv1.CreateBillingPortalSessionRequest],
) (*connect.Response[billingv1.CreateBillingPortalSessionResponse], error) {
	tenant, err := db.RequireTenant(ctx)
	if err != nil {
		return nil, fail(errs.Internalf("no tenant scope reached the billing handler; " +
			"gate 1 resolved no organization").Wrap(err))
	}
	// Read and discarded. The class is BILLING_MANAGE, which CONVENTIONS §6
	// counts as mutating, so gate 5 requires the header and this refuses a
	// request that somehow reached the handler without one. Nothing downstream
	// uses it: a Portal session is short-lived and single-use, so replaying a
	// key would hand somebody a session that has already been spent — which
	// reads as a broken billing page rather than as a safety property.
	if _, err := idempotencyKey(req.Header()); err != nil {
		return nil, fail(err)
	}

	session, err := s.sessions.Create(ctx, tenant.OrgID, req.Msg.GetReturnUrl())
	if err != nil {
		if errors.Is(err, app.ErrNotProvisioned) {
			// The provisioning window, and it closes by itself: creation appends
			// the event and a reactor mirrors the organization to Stripe seconds
			// later. Told as a CONFLICT — a state that will pass — rather than as
			// an internal failure, so the caller retries instead of paging
			// somebody.
			return nil, fail(errs.Conflictf("this organization's billing account is still " +
				"being set up; try again in a moment"))
		}
		// Everything else is Stripe's or ours, and the caller learns neither.
		// A message from Stripe's API can name a customer id, a price or an
		// account, none of which belongs in a response to a browser.
		return nil, fail(errs.Internalf("creating a billing portal session").Wrap(err))
	}

	return connect.NewResponse(&billingv1.CreateBillingPortalSessionResponse{
		Url: session.URL,
	}), nil
}

// idempotencyKey reads the client-generated key every mutating command needs.
func idempotencyKey(header interceptor.Header) (string, error) {
	key := header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return key, nil
}

// fail hands the error to the transport mapping the rest of the server uses.
func fail(err error) error { return srvconnect.Error(err) }
