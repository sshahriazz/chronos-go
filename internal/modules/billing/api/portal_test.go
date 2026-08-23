package api_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"

	billingv1 "github.com/chronos/chronos-go/gen/proto/chronos/billing/v1"
	billingapi "github.com/chronos/chronos-go/internal/modules/billing/api"
	"github.com/chronos/chronos-go/internal/modules/billing/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

type fakeSessions struct {
	url    string
	err    error
	orgID  string
	retURL string
	calls  int
}

func (f *fakeSessions) Create(
	_ context.Context, orgID, returnURL string,
) (app.PortalSession, error) {
	f.calls++
	f.orgID, f.retURL = orgID, returnURL
	if f.err != nil {
		return app.PortalSession{}, f.err
	}
	return app.PortalSession{URL: f.url}, nil
}

func portalService(t *testing.T, sessions *fakeSessions) *billingapi.Service {
	t.Helper()
	svc, err := billingapi.New(billingapi.Deps{
		Sessions: sessions, Invoices: &fakeInvoiceQueries{},
	})
	if err != nil {
		t.Fatalf("billingapi.New: %v", err)
	}
	return svc
}

// portalRequest builds a request the way the gates would have left it.
func portalRequest(returnURL, key string) *connect.Request[billingv1.CreateBillingPortalSessionRequest] {
	req := connect.NewRequest(&billingv1.CreateBillingPortalSessionRequest{
		ReturnUrl: returnURL,
	})
	if key != "" {
		req.Header().Set(interceptor.IdempotencyHeader, key)
	}
	return req
}

func tenantCtx(orgID string) context.Context {
	return db.WithTenant(context.Background(), db.Tenant{OrgID: orgID})
}

// fakeInvoiceQueries satisfies the read side for tests about the portal.
type fakeInvoiceQueries struct {
	page app.InvoicePage
	err  error
}

func (f *fakeInvoiceQueries) List(
	_ context.Context, _ app.ListInvoicesQuery,
) (app.InvoicePage, error) {
	return f.page, f.err
}

// THE ORGANIZATION COMES FROM THE CONTEXT.
//
// Gate 2 authorised `billing_manager` against the organization gate 1 resolved.
// There is no field for one in the schema and there must not be: a request that
// named its own organization would be authorised against one and act on another
// — and what it acts on is a portal that can cancel a subscription.
func TestThePortalActsOnTheOrganizationTheGatesResolved(t *testing.T) {
	sessions := &fakeSessions{url: "https://billing.stripe.com/p/session/test_1"}
	svc := portalService(t, sessions)

	res, err := svc.CreateBillingPortalSession(
		tenantCtx("org_resolved"), portalRequest("https://app.example.com/billing", "key-1"))
	if err != nil {
		t.Fatal(err)
	}
	if sessions.orgID != "org_resolved" {
		t.Errorf("acted on %q, want the organization from the context", sessions.orgID)
	}
	if got := res.Msg.GetUrl(); got != sessions.url {
		t.Errorf("returned %q, want the session url", got)
	}
}

// NO TENANT IS AN INTERNAL FAILURE, NOT A GUESS.
//
// Reaching this handler without a scope means gate 1 did not run. Continuing
// with an empty organization would mint against whatever an empty lookup
// returned.
func TestThePortalRefusesARequestWithNoTenant(t *testing.T) {
	sessions := &fakeSessions{url: "https://billing.stripe.com/p/session/test_1"}
	svc := portalService(t, sessions)

	if _, err := svc.CreateBillingPortalSession(
		context.Background(), portalRequest("https://app.example.com/billing", "key-1")); err == nil {
		t.Fatal("a request with no tenant scope was served")
	}
	if sessions.calls != 0 {
		t.Error("a session was minted for a request with no organization")
	}
}

// A MUTATING CLASS CARRIES AN IDEMPOTENCY-KEY.
//
// BILLING_MANAGE is mutating (CONVENTIONS §6), so gate 5 requires the header and
// this refuses a request that somehow arrived without one.
func TestThePortalRequiresAnIdempotencyKey(t *testing.T) {
	sessions := &fakeSessions{url: "https://billing.stripe.com/p/session/test_1"}
	svc := portalService(t, sessions)

	if _, err := svc.CreateBillingPortalSession(
		tenantCtx("org_x"), portalRequest("https://app.example.com/billing", "")); err == nil {
		t.Fatal("a mutating request with no Idempotency-Key was served")
	}
	if sessions.calls != 0 {
		t.Error("the use case ran for a request the header check should have refused")
	}
}

// THE PROVISIONING WINDOW IS A CONFLICT, NOT AN INTERNAL ERROR.
//
// It resolves by itself in seconds, so the caller should retry. Reported as
// INTERNAL it would page somebody instead, and the customer would see a failure
// where they should see "one moment".
func TestAnUnprovisionedOrganizationIsAConflict(t *testing.T) {
	sessions := &fakeSessions{err: app.ErrNotProvisioned}
	svc := portalService(t, sessions)

	_, err := svc.CreateBillingPortalSession(
		tenantCtx("org_x"), portalRequest("https://app.example.com/billing", "key-1"))
	// AlreadyExists is what the catalogue maps CONFLICT to over Connect. The
	// property under test is that it is NOT internal: a state that passes on its
	// own must read as "try again", not as a server fault that pages somebody.
	if got := connect.CodeOf(err); got == connect.CodeInternal {
		t.Fatalf("the provisioning window is reported as an internal error; the customer "+
			"sees a failure where they should see 'one moment', and somebody is paged for "+
			"a state that resolves in seconds (code %v)", got)
	}
	if got := connect.CodeOf(err); got != connect.CodeAlreadyExists {
		t.Fatalf("code is %v, want the CONFLICT mapping", got)
	}
}

// STRIPE'S OWN ERRORS DO NOT REACH THE CALLER.
//
// A message from Stripe's API can name a customer id, a price or an account.
// None of that belongs in a response to a browser, and ADR-036 makes the app
// layer — not the transport — the place that decides what a caller is told.
func TestStripesErrorTextIsNotReturnedToTheCaller(t *testing.T) {
	const leak = "No such customer: 'cus_SECRET123' for account 'acct_SECRET'"
	sessions := &fakeSessions{err: errors.New(leak)}
	svc := portalService(t, sessions)

	_, err := svc.CreateBillingPortalSession(
		tenantCtx("org_x"), portalRequest("https://app.example.com/billing", "key-1"))
	if err == nil {
		t.Fatal("a Stripe failure produced a successful response")
	}
	if got := connect.CodeOf(err); got != connect.CodeInternal {
		t.Errorf("code is %v, want internal", got)
	}
	if msg := err.Error(); strings.Contains(msg, "cus_SECRET123") ||
		strings.Contains(msg, "acct_SECRET") {
		t.Errorf("the response carries Stripe's own text: %q", msg)
	}
}

// AN INCOMPLETE WIRING IS REFUSED AT CONSTRUCTION.
func TestTheBillingServiceRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := billingapi.New(billingapi.Deps{
		Invoices: &fakeInvoiceQueries{},
	}); err == nil {
		t.Error("a service with no session use case was accepted; every call would " +
			"panic on a nil port at the moment a customer tries to pay")
	}
	if _, err := billingapi.New(billingapi.Deps{
		Sessions: &fakeSessions{},
	}); err == nil {
		t.Error("a service with no invoice list was accepted; a customer being charged " +
			"cannot see what for")
	}
}
