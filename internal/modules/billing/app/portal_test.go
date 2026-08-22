package app_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/billing/app"
)

type fakePortal struct {
	url        string
	err        error
	customerID string
	returnURL  string
	calls      int
}

func (f *fakePortal) Session(
	_ context.Context, customerID, returnURL string,
) (app.PortalSession, error) {
	f.calls++
	f.customerID, f.returnURL = customerID, returnURL
	if f.err != nil {
		return app.PortalSession{}, f.err
	}
	return app.PortalSession{URL: f.url}, nil
}

type fakeCustomers struct {
	id  string
	err error
}

func (f *fakeCustomers) CustomerID(_ context.Context, _ string) (string, error) {
	return f.id, f.err
}

func newSessions(t *testing.T, portal *fakePortal, customers *fakeCustomers) *app.PortalSessions {
	t.Helper()
	sessions, err := app.NewPortalSessions(app.PortalSessionsDeps{
		Portal: portal, Customers: customers,
	})
	if err != nil {
		t.Fatalf("NewPortalSessions: %v", err)
	}
	return sessions
}

// THE HAPPY PATH MINTS AGAINST THE ORGANIZATION'S OWN CUSTOMER.
//
// The customer id is asserted, not just the URL. Gate 2 authorised
// `billing_manager` against an ORGANIZATION, and a session is minted against a
// STRIPE CUSTOMER — so a lookup that returned somebody else's customer would
// hand one tenant's owner a portal into another tenant's subscription, where
// they could change the plan or cancel it outright.
func TestASessionIsMintedAgainstTheOrganizationsCustomer(t *testing.T) {
	portal := &fakePortal{url: "https://billing.stripe.com/p/session/test_1"}
	sessions := newSessions(t, portal, &fakeCustomers{id: "cus_theirs"})

	session, err := sessions.Create(
		context.Background(), "org_x", "https://app.example.com/billing")
	if err != nil {
		t.Fatal(err)
	}
	if session.URL != portal.url {
		t.Errorf("returned %q, want the portal's url", session.URL)
	}
	if portal.customerID != "cus_theirs" {
		t.Errorf("minted against %q, want cus_theirs; a session against another tenant's "+
			"customer is a door into their subscription", portal.customerID)
	}
	if portal.returnURL != "https://app.example.com/billing" {
		t.Errorf("the return url reached Stripe as %q", portal.returnURL)
	}
}

// THE PROVISIONING WINDOW IS ITS OWN ANSWER.
//
// An organization is created and a reactor mirrors it to Stripe seconds later.
// In between there is no customer, and the caller should be told to try again —
// not told nothing, and not told a failure that will never resolve. The two have
// different remedies and only a distinguishable error lets the caller pick one.
func TestAnUnprovisionedOrganizationIsToldToWait(t *testing.T) {
	portal := &fakePortal{url: "https://billing.stripe.com/p/session/test_1"}
	sessions := newSessions(t, portal, &fakeCustomers{id: ""})

	_, err := sessions.Create(context.Background(), "org_x", "https://app.example.com/billing")
	if !errors.Is(err, app.ErrNotProvisioned) {
		t.Fatalf("returned %v, want ErrNotProvisioned", err)
	}
	if portal.calls != 0 {
		t.Error("Stripe was asked for a session with an empty customer id")
	}
}

// AN UNREADABLE DIRECTORY IS A FAILURE, NOT AN EMPTY CUSTOMER.
//
// Collapsing the two would tell a paying customer whose event store is briefly
// unreachable that their billing account is "still being set up" — and they
// would wait for something that already happened.
func TestAnUnreadableCustomerDirectoryIsNotAProvisioningWindow(t *testing.T) {
	portal := &fakePortal{}
	sessions := newSessions(t, portal, &fakeCustomers{err: errors.New("kurrentdb: down")})

	_, err := sessions.Create(context.Background(), "org_x", "https://app.example.com/billing")
	switch {
	case err == nil:
		t.Fatal("an unreadable directory produced a session")
	case errors.Is(err, app.ErrNotProvisioned):
		t.Fatal("an unreadable directory was reported as the provisioning window; the " +
			"customer waits for something that already happened")
	}
	if portal.calls != 0 {
		t.Error("Stripe was called after the lookup failed")
	}
}

// A SESSION WITH NO URL IS A FAILURE.
//
// The one field the call exists to produce. Returned as-is it becomes a link to
// nowhere in somebody's billing screen — which reads as our bug and is
// unreportable, because nothing recorded that Stripe answered oddly.
func TestASessionWithNoURLIsRefused(t *testing.T) {
	sessions := newSessions(t, &fakePortal{url: ""}, &fakeCustomers{id: "cus_x"})

	if _, err := sessions.Create(
		context.Background(), "org_x", "https://app.example.com/billing"); err == nil {
		t.Fatal("an empty url was returned to the caller as a successful session")
	}
}

// BOTH INPUTS ARE REQUIRED.
//
// An empty organization means gate 1 resolved none and the request should never
// have arrived; an empty return url would send the customer nowhere after
// paying.
func TestASessionNeedsAnOrganizationAndAReturnURL(t *testing.T) {
	portal := &fakePortal{url: "https://billing.stripe.com/p/session/test_1"}
	sessions := newSessions(t, portal, &fakeCustomers{id: "cus_x"})
	ctx := context.Background()

	if _, err := sessions.Create(ctx, "", "https://app.example.com/b"); err == nil {
		t.Error("a session with no organization was minted")
	}
	if _, err := sessions.Create(ctx, "org_x", ""); err == nil {
		t.Error("a session with no return url was minted")
	}
	if portal.calls != 0 {
		t.Error("Stripe was called for an incomplete request")
	}
}

// AN INCOMPLETE WIRING IS REFUSED AT CONSTRUCTION.
func TestPortalSessionsRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewPortalSessions(app.PortalSessionsDeps{
		Customers: &fakeCustomers{},
	}); err == nil {
		t.Error("a use case with no portal was accepted; the portal is the only way a card " +
			"is ever added, so every trial would have exactly one outcome")
	}
	if _, err := app.NewPortalSessions(app.PortalSessionsDeps{
		Portal: &fakePortal{},
	}); err == nil {
		t.Error("a use case with no customer directory was accepted")
	}
}
