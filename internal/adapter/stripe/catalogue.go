package stripe

import (
	"context"
	"errors"
	"fmt"

	stripe "github.com/stripe/stripe-go/v86"

	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
)

// planVersionKey is our plan-version id, stored on the Stripe Price.
//
// Written for the operator reading the Dashboard, not for lookup: the id is
// ALSO the Price's `lookup_key`, and that is what the mirror reads back.
const planVersionKey = "chronos_plan_version_id"

// planKey is the plan's stable identity, stored on the Stripe Product.
const planKey = "chronos_plan_id"

// productIDPrefix namespaces the Stripe Product ids this mirror owns.
//
// Product ids are account-global and Stripe lets us choose them, which is the
// whole point: a deterministic id is retrievable with a strongly consistent GET,
// where a search is not.
const productIDPrefix = "chronos_plan_"

// Mirror creates the Stripe objects a catalogue describes.
//
// # Ours → Stripe, never the reverse
//
// billing.md §2: a `price.updated` or `product.updated` webhook we did not
// originate means somebody edited in the Stripe Dashboard, and that is an
// INCIDENT rather than a merge. This type only ever writes; nothing here reads
// Stripe's version of a plan and adopts it.
type Mirror struct{ api *stripe.Client }

// NewMirror builds one.
func NewMirror(secretKey string) (*Mirror, error) {
	if secretKey == "" {
		return nil, errors.New("stripe: an API key is required to mirror the catalogue")
	}
	return &Mirror{api: stripe.NewClient(secretKey)}, nil
}

// EnsurePrice returns the Stripe price id for one plan version, creating the
// Product and Price if they do not exist.
//
// # Idempotent by lookup_key, and NOT by search
//
// The first version of this searched Stripe for a Price carrying the version id
// in metadata. It was wrong, and the integration test is what caught it: Stripe's
// search index is eventually consistent, a freshly created Price was still
// unfindable after SIXTY SECONDS, and the lag has no documented bound. A mirror
// built on it creates a duplicate Price on every deployment that lands inside
// the window — at the same amount, so nothing looks broken, while "what does pro
// cost" starts having more than one answer.
//
// `lookup_key` is Stripe's own answer to exactly this: a caller-chosen handle,
// unique across active Prices, readable with a strongly consistent list. The
// uniqueness is enforced by Stripe, so two deployments racing produce an error
// on the loser rather than two Prices — which is the correct direction to fail.
//
// Stripe's idempotency keys cannot do this job either: they expire after 24
// hours, and a mirror re-runs for the lifetime of the product.
func (m *Mirror) EnsurePrice(
	ctx context.Context, v billingdomain.PlanVersion,
) (string, error) {
	if err := v.Validate(); err != nil {
		return "", err
	}

	if id, err := m.findPrice(ctx, v); err != nil {
		return "", err
	} else if id != "" {
		return id, nil
	}

	product, err := m.ensureProduct(ctx, v.Plan)
	if err != nil {
		return "", err
	}

	price, err := m.createPrice(ctx, v, product, false)
	if err == nil {
		return price, nil
	}

	// The create was refused. Exactly one refusal is recoverable, and telling
	// the two apart is the whole of this branch.
	//
	// A CONCURRENT MIRROR took the lookup key first. Re-reading turns Stripe's
	// refusal into the id the other run created, which is the same answer this
	// call was about to return.
	if id, reread := m.findPrice(ctx, v); reread == nil && id != "" {
		return id, nil
	}

	// No ACTIVE price holds the key, and Stripe still refused it — so the holder
	// is an ARCHIVED price. This is the case the integration test found and the
	// first version of this code got wrong: Stripe's lookup-key uniqueness spans
	// archived Prices too, so a version that is still published but whose Price
	// somebody archived can never be re-created without moving the key.
	//
	// The catalogue is the source of truth (billing.md §2, ours → Stripe, never
	// the reverse), so a published version having no live Price is a state to
	// repair rather than to accept. `transfer_lookup_key` is Stripe's own
	// mechanism for it, and no subscriber is affected: a Subscription references
	// a price ID, not a lookup key.
	//
	// It is NOT set on the first attempt, deliberately. Transferring
	// unconditionally would let the loser of a race steal the key from the
	// winner's live Price and leave two active Prices where one was wanted. Only
	// reaching here proves the blocker is not live.
	if !isLookupKeyTaken(err) {
		return "", fmt.Errorf("stripe: creating the price for %s: %w", v.ID(), err)
	}
	price, transferred := m.createPrice(ctx, v, product, true)
	if transferred != nil {
		return "", fmt.Errorf("stripe: re-creating the price for %s, whose lookup key was "+
			"held by an archived price: %w", v.ID(), transferred)
	}
	return price, nil
}

// createPrice makes one Price for a version.
func (m *Mirror) createPrice(
	ctx context.Context, v billingdomain.PlanVersion, product string, transferKey bool,
) (string, error) {
	params := &stripe.PriceCreateParams{
		Product:    stripe.String(product),
		Currency:   stripe.String(v.Currency),
		UnitAmount: stripe.Int64(v.AmountMinor),
		LookupKey:  stripe.String(v.ID()),
		Recurring: &stripe.PriceCreateRecurringParams{
			Interval: stripe.String(string(v.Interval)),
		},
		Metadata: map[string]string{
			planVersionKey: v.ID(),
			planKey:        string(v.Plan),
		},
	}
	if transferKey {
		params.TransferLookupKey = stripe.Bool(true)
	}
	price, err := m.api.V1Prices.Create(ctx, params)
	if err != nil {
		return "", err
	}
	return price.ID, nil
}

// isLookupKeyTaken reports whether Stripe refused a create because something
// else already holds the lookup key.
//
// Matched on the PARAMETER rather than the message, which is prose Stripe may
// reword. Everything else — a bad key, a network failure, a currency Stripe does
// not accept — must NOT be retried with a lookup-key transfer, because the
// transfer would then be attempted against an error that has nothing to do with
// the key.
func isLookupKeyTaken(err error) bool {
	var serr *stripe.Error
	return errors.As(err, &serr) && serr.Param == "lookup_key"
}

// findPrice looks for the ACTIVE Price holding this version's lookup key.
//
// Active only, and deliberately. An archived Price KEEPS its lookup key — Stripe
// refuses to reuse the key even then, which is what EnsurePrice's transfer
// branch exists to resolve — so a lookup that ignored `active` would hand back
// exactly the Price an operator withdrew, with a valid price id and nothing
// looking wrong.
func (m *Mirror) findPrice(
	ctx context.Context, v billingdomain.PlanVersion,
) (string, error) {
	list := m.api.V1Prices.List(ctx, &stripe.PriceListParams{
		LookupKeys: []*string{stripe.String(v.ID())},
		Active:     stripe.Bool(true),
		ListParams: stripe.ListParams{Limit: stripe.Int64(1)},
	})
	for existing, err := range list.All(ctx) {
		if err != nil {
			return "", fmt.Errorf("stripe: reading the price of %s: %w", v.ID(), err)
		}
		if existing != nil {
			return existing.ID, nil
		}
	}
	return "", nil
}

// ensureProduct finds or creates the Product a plan's Prices hang from.
//
// One Product per PLAN, not per version: Stripe models a Product as the thing
// being sold and a Price as what it costs, so every version and interval of
// "pro" belongs to one Product. Creating one per version would make a customer's
// invoice name a version rather than a product.
//
// The id is DERIVED from the plan rather than assigned by Stripe, for the same
// reason the Price uses a lookup key: a retrieve is strongly consistent and a
// search is not. `PlanID` is constrained to the character set Stripe accepts in
// an id, which is what makes the derivation total.
func (m *Mirror) ensureProduct(ctx context.Context, plan billingdomain.PlanID) (string, error) {
	id := productIDPrefix + string(plan)

	switch _, err := m.api.V1Products.Retrieve(ctx, id, nil); {
	case err == nil:
		return id, nil
	case !isMissing(err):
		return "", fmt.Errorf("stripe: reading the product for %s: %w", plan, err)
	}

	product, err := m.api.V1Products.Create(ctx, &stripe.ProductCreateParams{
		ID:       stripe.String(id),
		Name:     stripe.String(string(plan)),
		Metadata: map[string]string{planKey: string(plan)},
	})
	if err != nil {
		// Another mirror created it between the retrieve and the create. The id
		// is deterministic, so the winner made exactly what this call wanted.
		if _, reread := m.api.V1Products.Retrieve(ctx, id, nil); reread == nil {
			return id, nil
		}
		return "", fmt.Errorf("stripe: creating the product for %s: %w", plan, err)
	}
	return product.ID, nil
}

// isMissing reports whether Stripe said the object does not exist.
//
// Distinguished from every other failure on purpose: "no such product" means
// create one, and a network error or a revoked key means STOP. Treating them
// alike would turn an outage into an attempt to create a Product that already
// exists, over and over.
func isMissing(err error) bool {
	var serr *stripe.Error
	return errors.As(err, &serr) && serr.Code == stripe.ErrorCodeResourceMissing
}

// EnsureAll mirrors every version a catalogue publishes, returning the Stripe
// price id for each by its plan-version id.
//
// # Why the whole catalogue and not just the one being subscribed to
//
// A Price created lazily at the moment somebody subscribes is a Price created
// during a customer-facing request, which turns a Stripe hiccup into a failed
// signup. Mirroring at startup moves that failure to deployment, where somebody
// is watching.
//
// Order is the catalogue's, which is sorted — so two runs against a fresh
// account create the same objects in the same sequence, and a log from one is
// comparable with a log from the other.
func (m *Mirror) EnsureAll(
	ctx context.Context, catalogue *billingdomain.Catalogue,
) (map[string]string, error) {
	if catalogue == nil {
		return nil, errors.New("stripe: no catalogue to mirror")
	}
	versions := catalogue.All()
	prices := make(map[string]string, len(versions))
	for _, v := range versions {
		id, err := m.EnsurePrice(ctx, v)
		if err != nil {
			return nil, err
		}
		prices[v.ID()] = id
	}
	return prices, nil
}
