//go:build integration

package stripe_test

import (
	"context"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	stripe "github.com/stripe/stripe-go/v86"

	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

func mirror(t *testing.T) *stripeadapter.Mirror {
	t.Helper()
	key := os.Getenv("STRIPE_SECRET_KEY")
	if key == "" {
		t.Skip("STRIPE_SECRET_KEY is not set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; this test creates Products and Prices")
	}
	m, err := stripeadapter.NewMirror(key)
	if err != nil {
		t.Fatalf("NewMirror: %v", err)
	}
	return m
}

// MIRRORING TWICE RETURNS THE SAME PRICE, IMMEDIATELY.
//
// This is the property the whole design turns on, and only the live API settles
// it: the mirror re-runs on every deployment for the lifetime of the product,
// and Stripe's own idempotency keys expire after 24 hours.
//
// IMMEDIATELY is the assertion, not a detail. The first version of the mirror
// looked the Price up by searching Stripe metadata, and this test is what proved
// that wrong — the freshly created Price was still unfindable after SIXTY
// SECONDS of polling, because the search index is eventually consistent with no
// documented bound. Every deployment landing inside that window would have
// created another Price at the same amount, and "what does pro cost" would have
// had more than one answer with nothing looking broken.
//
// A `lookup_key` is read back with a strongly consistent list, so no polling
// belongs here. If this test ever needs a retry loop again, the mirror has
// regressed to a search.
func TestMirroringTwiceReturnsTheSamePrice(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m := mirror(t)
	// A version unique to this run, so the assertion is about THIS test's
	// idempotency rather than about whatever previous runs left behind.
	v := billingdomain.PlanVersion{
		Plan:        billingdomain.PlanID("itest" + runSuffix()),
		Version:     1,
		Interval:    billingdomain.Monthly,
		AmountMinor: 500,
		Currency:    "usd",
	}

	first, err := m.EnsurePrice(ctx, v)
	if err != nil {
		t.Fatalf("first mirror: %v", err)
	}
	if first == "" {
		t.Fatal("the mirror returned no price id")
	}

	second, err := m.EnsurePrice(ctx, v)
	if err != nil {
		t.Fatalf("second mirror: %v", err)
	}
	if second != first {
		t.Fatalf("mirroring twice produced %s then %s. Every deployment creates another "+
			"Price at the same amount, and the catalogue's answer to what a plan costs "+
			"becomes whichever duplicate was read back", first, second)
	}
	t.Logf("%s mirrored idempotently to %s", v.ID(), first)
}

// A SECOND PLAN VERSION REUSES THE PRODUCT.
//
// One Product per plan is what keeps a customer's invoice naming the product
// they bought rather than the revision of it. The Product id is derived from the
// plan, so this also exercises the retrieve-then-create path finding an existing
// Product — the half that a first run can never reach.
func TestASecondVersionReusesThePlansProduct(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	m := mirror(t)
	plan := billingdomain.PlanID("itest" + runSuffix())

	v1 := billingdomain.PlanVersion{
		Plan: plan, Version: 1, Interval: billingdomain.Monthly,
		AmountMinor: 500, Currency: "usd",
	}
	v2 := v1
	v2.Version = 2
	v2.AmountMinor = 900

	firstID, err := m.EnsurePrice(ctx, v1)
	if err != nil {
		t.Fatalf("v1: %v", err)
	}
	secondID, err := m.EnsurePrice(ctx, v2)
	if err != nil {
		t.Fatalf("v2: %v", err)
	}
	if firstID == secondID {
		t.Fatalf("both versions mirrored to %s; a price change that reuses its Price "+
			"rewrites what every existing subscriber agreed to", firstID)
	}

	// Both Prices must hang off the SAME Product.
	one, err := priceProduct(ctx, t, firstID)
	if err != nil {
		t.Fatal(err)
	}
	two, err := priceProduct(ctx, t, secondID)
	if err != nil {
		t.Fatal(err)
	}
	if one != two {
		t.Fatalf("v1 hangs off product %s and v2 off %s; one plan became two products, "+
			"so an invoice names the revision instead of the thing bought", one, two)
	}
	t.Logf("both versions of %s hang off %s", plan, one)
}

// MONTHLY AND YEARLY ARE DIFFERENT PRICES.
//
// They share a plan and a version and differ only by interval, which is exactly
// the case an id that omitted the interval would collapse — and a customer
// choosing annual would be charged monthly forever.
func TestMonthlyAndYearlyMirrorSeparately(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	m := mirror(t)
	plan := billingdomain.PlanID("itest" + runSuffix())

	monthly, err := m.EnsurePrice(ctx, billingdomain.PlanVersion{
		Plan: plan, Version: 1, Interval: billingdomain.Monthly,
		AmountMinor: 2400, Currency: "usd",
	})
	if err != nil {
		t.Fatalf("monthly: %v", err)
	}
	yearly, err := m.EnsurePrice(ctx, billingdomain.PlanVersion{
		Plan: plan, Version: 1, Interval: billingdomain.Yearly,
		AmountMinor: 24000, Currency: "usd",
	})
	if err != nil {
		t.Fatalf("yearly: %v", err)
	}

	if monthly == yearly {
		t.Fatalf("monthly and yearly mirrored to the same price %s; every annual customer "+
			"is billed monthly", monthly)
	}
	t.Logf("monthly=%s yearly=%s", monthly, yearly)
}

// AN UNPRICEABLE VERSION NEVER REACHES STRIPE.
func TestAnInvalidVersionIsRefusedBeforeStripe(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	if _, err := mirror(t).EnsurePrice(ctx, billingdomain.PlanVersion{
		Plan: "broken", Version: 1, Interval: billingdomain.Monthly,
		AmountMinor: 100, Currency: "",
	}); err == nil {
		t.Fatal("a version with no currency was sent to Stripe")
	}
}

// A MIRROR NEEDS A KEY.
func TestTheMirrorNeedsAKey(t *testing.T) {
	if _, err := stripeadapter.NewMirror(""); err == nil {
		t.Error("a mirror with no API key was accepted")
	}
}

// priceProduct reads which Product a Price hangs off.
func priceProduct(ctx context.Context, t *testing.T, priceID string) (string, error) {
	t.Helper()
	client := stripe.NewClient(os.Getenv("STRIPE_SECRET_KEY"))
	p, err := client.V1Prices.Retrieve(ctx, priceID, nil)
	if err != nil {
		return "", err
	}
	if p.Product == nil {
		return "", fmt.Errorf("price %s has no product", priceID)
	}
	return p.Product.ID, nil
}

// runSuffix makes each run's plan ids unique.
//
// Without it a second run finds the FIRST run's Price and passes without ever
// exercising the create path — a test that proves idempotency by never creating
// anything.
func runSuffix() string {
	// Lower case, because PlanID is constrained to the character set Stripe
	// accepts in an identifier and Crockford base32 is upper case.
	return strings.ToLower(ids.New[ids.Org](time.Now(), ids.Entropy()).String()[4:14])
}

// AN ARCHIVED PRICE IS NEVER HANDED BACK.
//
// Stripe scopes `lookup_key` uniqueness to ACTIVE Prices, so an archived Price
// keeps its key and a fresh one may take the same key alongside it. An operator
// archives a Price to stop selling it; a mirror that returned the archived one
// would subscribe every new customer to exactly the Price that was withdrawn,
// and nothing would look broken because a valid price id came back.
//
// Only the live API settles this: the `active: true` filter in findPrice is
// invisible to every unit test, and removing it changes nothing until an
// operator archives something months later.
func TestAnArchivedPriceIsNotReturned(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	m := mirror(t)
	v := billingdomain.PlanVersion{
		Plan: billingdomain.PlanID("itest" + runSuffix()), Version: 1,
		Interval: billingdomain.Monthly, AmountMinor: 700, Currency: "usd",
	}

	original, err := m.EnsurePrice(ctx, v)
	if err != nil {
		t.Fatalf("first mirror: %v", err)
	}

	client := stripe.NewClient(os.Getenv("STRIPE_SECRET_KEY"))
	if _, err := client.V1Prices.Update(ctx, original, &stripe.PriceUpdateParams{
		Active: stripe.Bool(false),
	}); err != nil {
		t.Fatalf("archiving %s: %v", original, err)
	}

	replacement, err := m.EnsurePrice(ctx, v)
	if err != nil {
		t.Fatalf("mirroring after the archive: %v", err)
	}
	if replacement == original {
		t.Fatalf("the mirror returned the ARCHIVED price %s; every new customer would be "+
			"subscribed to the Price an operator withdrew, and a valid price id came "+
			"back so nothing looks wrong", original)
	}

	// And the replacement is genuinely active.
	got, err := client.V1Prices.Retrieve(ctx, replacement, nil)
	if err != nil {
		t.Fatalf("reading %s: %v", replacement, err)
	}
	if !got.Active {
		t.Fatalf("the mirror created %s and it is not active", replacement)
	}
	t.Logf("archived %s, replaced by %s", original, replacement)
}
