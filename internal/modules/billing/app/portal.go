// Package app is billing's use cases.
package app

import (
	"context"
	"fmt"
)

// PortalSession is a signed door into Stripe's Customer Portal.
//
// One field, and nothing is stored. The session is short-lived and single-use;
// recording it would create a second place where a billing credential lives and
// answer no question anybody asks.
type PortalSession struct{ URL string }

// Portal mints Portal sessions. Declared by its consumer (CONVENTIONS §2); the
// implementation is the Stripe adapter.
type Portal interface {
	Session(ctx context.Context, customerID, returnURL string) (PortalSession, error)
}

// Customers answers "which Stripe customer is this organization".
//
// A port rather than a repository handle, because the answer's HOME is the
// organization aggregate — billing does not own organizations, and
// `modules/billing/**` may not import `modules/organization/**` beyond its
// contract (CONVENTIONS §2). The composition root satisfies it.
type Customers interface {
	// CustomerID returns the organization's Stripe customer, or an empty string
	// if it has none yet.
	//
	// Empty is not an error. It is the PROVISIONING WINDOW: creation appends
	// OrganizationCreated and returns, and a reactor mirrors the organization to
	// Stripe seconds later. Distinguishing "not yet" from "failed" is what lets
	// the caller be told to try again rather than told nothing.
	CustomerID(ctx context.Context, orgID string) (string, error)
}

// PortalSessions is the use case behind CreateBillingPortalSession.
type PortalSessions struct {
	portal    Portal
	customers Customers
}

// PortalSessionsDeps is what it needs.
type PortalSessionsDeps struct {
	Portal    Portal
	Customers Customers
}

func NewPortalSessions(d PortalSessionsDeps) (*PortalSessions, error) {
	switch {
	case d.Portal == nil:
		return nil, fmt.Errorf("billing: a portal is required; without one a cardless trial " +
			"has exactly one outcome, because the only way to add a card is the portal")
	case d.Customers == nil:
		return nil, fmt.Errorf("billing: a customer directory is required")
	}
	return &PortalSessions{portal: d.Portal, customers: d.Customers}, nil
}

// ErrNotProvisioned reports that the organization has no Stripe customer yet.
//
// Its own error rather than a generic failure, because the two have different
// remedies and only the caller can tell them apart for the customer: this one
// resolves by itself in seconds, and every other failure does not.
var ErrNotProvisioned = fmt.Errorf("billing: this organization has no billing account yet")

// Create mints a session for an organization.
//
// The authorization question — `billing_manager`, which resolves to the owner
// alone — is the gate's, and is not repeated here. What IS here is the check the
// gate cannot make: that the organization named actually has a Stripe customer,
// because the gate authorises against an organization id and a portal session
// is minted against a Stripe customer id, and nothing in the graph knows whether
// the second exists.
func (p *PortalSessions) Create(
	ctx context.Context, orgID, returnURL string,
) (PortalSession, error) {
	switch {
	case orgID == "":
		return PortalSession{}, fmt.Errorf("billing: no organization reached the portal " +
			"handler; gate 1 resolved none")
	case returnURL == "":
		return PortalSession{}, fmt.Errorf("billing: a return url is required")
	}

	customerID, err := p.customers.CustomerID(ctx, orgID)
	if err != nil {
		return PortalSession{}, fmt.Errorf("billing: finding the customer of %s: %w", orgID, err)
	}
	if customerID == "" {
		return PortalSession{}, ErrNotProvisioned
	}

	session, err := p.portal.Session(ctx, customerID, returnURL)
	if err != nil {
		return PortalSession{}, err
	}
	if session.URL == "" {
		return PortalSession{}, fmt.Errorf("billing: the portal returned no url for %s", orgID)
	}
	return session, nil
}
