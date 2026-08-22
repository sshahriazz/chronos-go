package stripe

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	stripe "github.com/stripe/stripe-go/v86"

	billingapp "github.com/chronos/chronos-go/internal/modules/billing/app"
)

// Portal mints short-lived sessions into Stripe's hosted Customer Portal.
//
// # Why there is no configuration here
//
// What the Portal offers — update payment method, change plan, cancel, resume,
// view invoices, manage tax ids — is configured ONCE in the Stripe Dashboard,
// not per session. That is deliberate on Stripe's part and convenient on ours:
// the surface a customer can reach is a business decision, and a business
// decision that lives in a deploy is one that needs a deploy to change.
//
// The consequence is worth stating, because it is invisible from this file: if
// the Portal configuration does not permit resuming a paused subscription, a
// cardless trial that lapsed can never be recovered by the customer, and NOTHING
// in this repository will say so. That check belongs to whoever configures the
// account.
type Portal struct{ api *stripe.Client }

var _ billingapp.Portal = (*Portal)(nil)

// PortalConfig is what the portal needs.
type PortalConfig struct{ SecretKey string }

func NewPortal(cfg PortalConfig) (*Portal, error) {
	if cfg.SecretKey == "" {
		return nil, fmt.Errorf("stripe: an API key is required")
	}
	return &Portal{api: stripe.NewClient(cfg.SecretKey)}, nil
}

// Session creates a Portal session for one customer.
//
// # The return URL is validated here as well as at the edge
//
// protovalidate already refuses anything that is not an absolute `https://` URL,
// and this checks again rather than trusting it. The reason is what the value
// does: Stripe redirects a browser to it, so an attacker-chosen value is an open
// redirect that borrows our domain's credibility — and this method is reachable
// from any future caller, not only from the RPC whose schema carries the rule.
// A bound published in one place and enforced in another is a bound that ends
// one refactor away from being neither.
//
// # No idempotency key
//
// Stripe's idempotency keys are for calls that CREATE something durable, and a
// Portal session is neither: it expires on its own, and Stripe explicitly
// documents these sessions as short-lived and single-use. Replaying a key would
// hand a customer a session that has already been spent — which reads to them as
// a broken billing page, not as a safety property.
func (p *Portal) Session(
	ctx context.Context, customerID, returnURL string,
) (billingapp.PortalSession, error) {
	switch {
	case customerID == "":
		return billingapp.PortalSession{}, fmt.Errorf("stripe: a customer id is required")
	case returnURL == "":
		return billingapp.PortalSession{}, fmt.Errorf("stripe: a return url is required")
	}
	if err := checkReturnURL(returnURL); err != nil {
		return billingapp.PortalSession{}, err
	}

	session, err := p.api.V1BillingPortalSessions.Create(ctx,
		&stripe.BillingPortalSessionCreateParams{
			Customer:  stripe.String(customerID),
			ReturnURL: stripe.String(returnURL),
		})
	if err != nil {
		return billingapp.PortalSession{}, fmt.Errorf(
			"stripe: creating a portal session for %s: %w", customerID, err)
	}
	if session.URL == "" {
		// Stripe answered without the one field the call exists to produce.
		// Reported rather than returned, because an empty URL becomes a link to
		// nowhere in somebody's billing screen.
		return billingapp.PortalSession{}, fmt.Errorf(
			"stripe: the portal session for %s carries no url", customerID)
	}
	return billingapp.PortalSession{URL: session.URL}, nil
}

// checkReturnURL refuses anything Stripe should not redirect a browser to.
func checkReturnURL(raw string) error {
	parsed, err := url.Parse(raw)
	if err != nil {
		return fmt.Errorf("stripe: the return url is not a url: %w", err)
	}
	switch {
	case !strings.EqualFold(parsed.Scheme, "https"):
		// http would also carry the session's outcome over the wire in clear,
		// and `javascript:` is the classic open-redirect payload.
		return fmt.Errorf("stripe: a return url must be https, got %q", parsed.Scheme)
	case parsed.Host == "":
		// `https:///path` parses, and redirects to whatever the browser decides
		// the host is.
		return fmt.Errorf("stripe: the return url names no host")
	case parsed.User != nil:
		// `https://trusted.example.com@evil.example/` shows the trusted name to
		// a person reading the link and resolves to the other one.
		return fmt.Errorf("stripe: a return url must not carry credentials")
	}
	return nil
}
