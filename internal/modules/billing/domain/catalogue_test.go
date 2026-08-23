package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/billing/domain"
)

func version(plan domain.PlanID, n int, in domain.Interval) domain.PlanVersion {
	return domain.PlanVersion{
		Plan: plan, Version: n, Interval: in,
		AmountMinor: 100, Currency: "usd",
	}
}

// THE VERSION ID CARRIES THE INTERVAL.
//
// It is what the mirror writes into Stripe metadata and searches on, so two
// versions sharing an id means the second silently reuses the first's Price.
// Monthly and yearly are different Prices of the same version — an id that
// omitted the interval would make the yearly one look like a retry of the
// monthly one, and a customer choosing annual would be charged monthly forever.
func TestTheVersionIDDistinguishesIntervals(t *testing.T) {
	monthly := version("pro", 1, domain.Monthly).ID()
	yearly := version("pro", 1, domain.Yearly).ID()

	if monthly == yearly {
		t.Fatalf("monthly and yearly share the id %q; the mirror keys Stripe metadata on "+
			"it, so annual silently reuses the monthly Price and every annual customer "+
			"is charged monthly", monthly)
	}
	if !strings.Contains(monthly, "month") || !strings.Contains(yearly, "year") {
		t.Errorf("ids %q / %q do not name their interval", monthly, yearly)
	}
}

// AND THE VERSION NUMBER.
//
// A price change is a new version, and a new version must be a new Stripe Price
// — `unit_amount` is immutable so historical invoices stay truthful (ADR-022).
func TestTheVersionIDDistinguishesVersions(t *testing.T) {
	if version("pro", 1, domain.Monthly).ID() == version("pro", 2, domain.Monthly).ID() {
		t.Fatal("two versions share an id; a price change would reuse the old Price and " +
			"every new customer would be charged the old amount")
	}
}

// A DUPLICATE ID IS REFUSED AT CONSTRUCTION.
func TestACatalogueRefusesDuplicateIDs(t *testing.T) {
	_, err := domain.NewCatalogue(
		version("pro", 1, domain.Monthly),
		version("pro", 1, domain.Monthly),
	)
	if err == nil {
		t.Fatal("a catalogue with two versions under one id was accepted")
	}
}

// LATEST IS THE HIGHEST VERSION FOR THAT INTERVAL.
//
// What a NEW subscription gets. Existing subscribers stay where they are —
// grandfathering is the default (billing.md §2) — so a Latest that crossed
// intervals would move somebody's billing period on signup.
func TestLatestIsPerInterval(t *testing.T) {
	c, err := domain.NewCatalogue(
		version("pro", 1, domain.Monthly),
		version("pro", 3, domain.Monthly),
		version("pro", 2, domain.Yearly),
	)
	if err != nil {
		t.Fatal(err)
	}

	monthly, err := c.Latest("pro", domain.Monthly)
	if err != nil {
		t.Fatal(err)
	}
	if monthly.Version != 3 {
		t.Errorf("latest monthly is v%d, want v3", monthly.Version)
	}

	yearly, err := c.Latest("pro", domain.Yearly)
	if err != nil {
		t.Fatal(err)
	}
	if yearly.Version != 2 {
		t.Errorf("latest yearly is v%d, want v2; the monthly versions leaked across "+
			"intervals", yearly.Version)
	}
}

// AN UNKNOWN PLAN IS AN ERROR, NOT A ZERO VALUE.
//
// A zero PlanVersion is priced at nothing, in no currency, on no interval — and
// returning one silently would give somebody a free subscription.
func TestAnUnknownPlanIsRefused(t *testing.T) {
	c, err := domain.NewCatalogue(version("pro", 1, domain.Monthly))
	if err != nil {
		t.Fatal(err)
	}

	if _, err := c.Latest("enterprise", domain.Monthly); err == nil {
		t.Error("an unknown plan returned a version")
	}
	if _, err := c.Version("pro", 9, domain.Monthly); err == nil {
		t.Error("an unknown version returned one")
	}
}

// ALL IS DETERMINISTIC.
//
// The mirror creates Stripe objects from it. Map order would make one
// deployment's Products appear in a different sequence from another's, and "did
// this run do the same thing" stops being answerable from a log.
func TestAllIsOrdered(t *testing.T) {
	c, err := domain.NewCatalogue(
		version("pro", 2, domain.Yearly),
		version("alpha", 1, domain.Monthly),
		version("pro", 1, domain.Monthly),
	)
	if err != nil {
		t.Fatal(err)
	}

	first := c.All()
	for range 20 {
		got := c.All()
		for i := range got {
			if got[i].ID() != first[i].ID() {
				t.Fatalf("All() is not deterministic: %q then %q at %d",
					first[i].ID(), got[i].ID(), i)
			}
		}
	}
}

// AN UNPRICEABLE VERSION IS REFUSED.
func TestAnUnpriceableVersionIsRefused(t *testing.T) {
	base := version("pro", 1, domain.Monthly)

	for name, mutate := range map[string]func(*domain.PlanVersion){
		"no plan":          func(v *domain.PlanVersion) { v.Plan = "" },
		"version zero":     func(v *domain.PlanVersion) { v.Version = 0 },
		"unknown interval": func(v *domain.PlanVersion) { v.Interval = "fortnight" },
		"negative amount":  func(v *domain.PlanVersion) { v.AmountMinor = -1 },
		"no currency":      func(v *domain.PlanVersion) { v.Currency = "" },
		"bad currency":     func(v *domain.PlanVersion) { v.Currency = "dollars" },
		"absurd trial":     func(v *domain.PlanVersion) { v.TrialDays = 1000 },
	} {
		t.Run(name, func(t *testing.T) {
			v := base
			mutate(&v)
			if err := v.Validate(); err == nil {
				t.Error("accepted")
			}
			if _, err := domain.NewCatalogue(v); err == nil {
				t.Error("a catalogue accepted it")
			}
		})
	}
}

// A FREE PLAN IS PRICEABLE.
//
// billing.md §2: free plans get a $0 Price so every customer has a real
// subscription and the lifecycle has exactly one shape. A validator that refused
// zero would force the second code path that decision exists to avoid.
func TestAZeroPriceIsValid(t *testing.T) {
	v := version("trial", 1, domain.Monthly)
	v.AmountMinor = 0
	if err := v.Validate(); err != nil {
		t.Fatalf("a $0 plan was refused: %v; free customers would need a second code path "+
			"through every state machine", err)
	}
}

// THE SHIPPED CATALOGUE IS VALID AND CARRIES BOTH INTERVALS.
//
// The decision recorded before the catalogue existed: annual ships from day one,
// so `Interval` is a dimension rather than a field added later.
func TestThePublishedCatalogueShipsAnnual(t *testing.T) {
	c, err := domain.Published()
	if err != nil {
		t.Fatalf("the shipped catalogue does not build: %v", err)
	}

	if _, err := c.Latest("pro", domain.Monthly); err != nil {
		t.Errorf("no monthly pro: %v", err)
	}
	if _, err := c.Latest("pro", domain.Yearly); err != nil {
		t.Errorf("no yearly pro: %v; annual was decided to ship from the start", err)
	}

	trial, err := c.Latest(domain.TrialPlan, domain.Monthly)
	if err != nil {
		t.Fatalf("no trial plan: %v; provisioning has nothing to subscribe a new "+
			"organization to", err)
	}
	if trial.TrialDays <= 0 {
		t.Error("the trial plan has no trial days; a trial that never ends is a free " +
			"forever account nothing alarms on")
	}
	if trial.AmountMinor != 0 {
		t.Errorf("the trial plan costs %d", trial.AmountMinor)
	}
}

// A PLAN ID MUST BE USABLE AS A STRIPE IDENTIFIER.
//
// The mirror DERIVES the Stripe Product id from this string, because a
// deterministic id can be read back with a strongly consistent GET where a
// search cannot. A plan id Stripe refuses would therefore fail at deployment,
// after the catalogue was written, reviewed and shipped — so the constraint sits
// on the type and the failure arrives at the first test that builds one.
func TestAPlanIDMustBeUsableAsAStripeIdentifier(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name string
		plan domain.PlanID
		ok   bool
	}{
		{"lower case", "pro", true},
		{"digits", "pro2", true},
		{"a hyphen", "pro-plus", true},
		{"upper case", "Pro", false},
		{"a space", "pro plus", false},
		{"a colon", "pro:v1", false},
		{"a slash", "pro/plus", false},
		{"a path traversal", "../../pro", false},
		{"empty", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			err := domain.PlanVersion{
				Plan: tc.plan, Version: 1, Interval: domain.Monthly,
				AmountMinor: 100, Currency: "usd",
			}.Validate()
			if tc.ok && err != nil {
				t.Fatalf("plan id %q was refused: %v", tc.plan, err)
			}
			if !tc.ok && err == nil {
				t.Fatalf("plan id %q was accepted; the mirror derives a Stripe Product id "+
					"from it, and Stripe would refuse the id at deployment", tc.plan)
			}
		})
	}
}

// EVERY PUBLISHED PLAN CAN BE MIRRORED.
//
// The rule above is only worth anything if it is applied to what this build
// actually ships. `NewCatalogue` validates every version, so `Published()`
// returning an error is the assertion — but a test that only checked for a nil
// error would pass if `Published` were emptied, so the plan ids are named here
// as well.
func TestEveryPublishedPlanIDIsMirrorable(t *testing.T) {
	t.Parallel()

	catalogue, err := domain.Published()
	if err != nil {
		t.Fatalf("the published catalogue does not validate: %v", err)
	}
	seen := map[domain.PlanID]bool{}
	for _, v := range catalogue.All() {
		seen[v.Plan] = true
	}
	for _, want := range []domain.PlanID{domain.TrialPlan, "pro"} {
		if !seen[want] {
			t.Errorf("the published catalogue has no %q plan", want)
		}
	}
}
