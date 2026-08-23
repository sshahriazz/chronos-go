package main

import (
	"testing"

	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
	entitlementdomain "github.com/chronos/chronos-go/internal/modules/entitlement/domain"
)

// EVERY LIMIT BILLING PUBLISHES IS ONE ENTITLEMENT ENFORCES.
//
// The two modules cannot import each other (CONVENTIONS §2), so billing carries
// its limits as opaque strings and nothing in either module can check them
// against the other. This is where they meet, and it is the only place the
// mismatch is visible.
//
// The mismatch is silent in the direction that matters: a plan advertising
// `seats.contractor` that entitlement has never heard of is a number in a
// catalogue with no enforcement behind it — customers are sold a limit that is
// never applied, and nothing errors.
//
// `entitlementdomain.NewCatalogue` already refuses an unknown key, so this
// asserts the bridge actually reaches it rather than silently dropping keys on
// the way.
func TestEveryPublishedLimitIsEnforceable(t *testing.T) {
	allowances, err := allowancesFromBilling()
	if err != nil {
		t.Fatalf("billing's catalogue does not translate: %v", err)
	}
	if len(allowances) == 0 {
		t.Fatal("no allowances were produced; every capped operation would be refused")
	}

	// The construction is the check: it refuses a limit key this build cannot
	// reserve against.
	if _, err := entitlementdomain.NewCatalogue(allowances...); err != nil {
		t.Fatalf("entitlement refuses billing's limits: %v. A limit nothing reserves "+
			"against is a number with no enforcement behind it", err)
	}

	// And no allowance is empty. A plan with no limits grants everything, which
	// is the opposite of what an absent limit should mean.
	for _, a := range allowances {
		if len(a.Limits) == 0 {
			t.Errorf("plan %q publishes no limits at all; an empty allowance grants "+
				"everything", a.Name)
		}
	}
}

// THE TRIAL PLAN IS AMONG THEM.
//
// Every organization is created on it, so a catalogue without it means gate 4
// cannot price a single tenant.
func TestTheTrialPlanIsEnforceable(t *testing.T) {
	allowances, err := allowancesFromBilling()
	if err != nil {
		t.Fatal(err)
	}
	catalogue, err := entitlementdomain.NewCatalogue(allowances...)
	if err != nil {
		t.Fatal(err)
	}

	trial, err := catalogue.Plan(string(billingdomain.TrialPlan))
	if err != nil {
		t.Fatalf("the trial plan is not enforceable: %v. Every organization is created on "+
			"it, so gate 4 cannot price a single tenant", err)
	}
	if trial.Limits[entitlementdomain.SeatsMember] <= 0 {
		t.Error("the trial plan grants no member seats; nobody can be invited to anything")
	}
}

// ONE ALLOWANCE PER PLAN, NOT PER VERSION OR INTERVAL.
//
// A limit is a property of the plan: monthly and yearly grant the same thing.
// Producing one allowance per interval would give entitlement two plans named
// "pro" — which NewCatalogue refuses outright, so this would fail loudly, but it
// is worth pinning the intent rather than relying on that refusal.
func TestOneAllowancePerPlan(t *testing.T) {
	allowances, err := allowancesFromBilling()
	if err != nil {
		t.Fatal(err)
	}

	seen := map[string]bool{}
	for _, a := range allowances {
		if seen[a.Name] {
			t.Errorf("plan %q appears twice; monthly and yearly grant the same thing and "+
				"must not become two plans", a.Name)
		}
		seen[a.Name] = true
	}

	published, err := billingdomain.Published()
	if err != nil {
		t.Fatal(err)
	}
	plans := map[billingdomain.PlanID]bool{}
	for _, v := range published.All() {
		plans[v.Plan] = true
	}
	if len(allowances) != len(plans) {
		t.Errorf("billing publishes %d plans and entitlement got %d allowances; a plan "+
			"that did not translate is one gate 4 cannot price", len(plans), len(allowances))
	}
}

// EVERY LIMIT ARRIVES, WITH THE NUMBER BILLING PUBLISHED.
//
// The tests above check that every limit billing publishes is one entitlement
// KNOWS. That is a weaker claim than it reads as, and two mutations survived it:
// dropping a key on the way across, and taking the yearly version's limits
// instead of the monthly one's. Both leave a catalogue entitlement accepts —
// the surviving limits are all valid keys — while a plan silently grants
// something other than what it was sold as.
//
// A missing limit is the worse half. `Allowance.Limits` is a map, and gate 4
// reads an absent key as zero or as uncapped depending on the limit; either way
// the number the customer was sold is not the number enforced, and nothing
// errors in either direction.
//
// So this compares the bridged allowance against the published MONTHLY version
// key by key, which is the only assertion that pins both the completeness and
// the source.
func TestEachAllowanceMatchesItsMonthlyVersionExactly(t *testing.T) {
	allowances, err := allowancesFromBilling()
	if err != nil {
		t.Fatal(err)
	}
	published, err := billingdomain.Published()
	if err != nil {
		t.Fatal(err)
	}

	bridged := map[string]entitlementdomain.Allowance{}
	for _, a := range allowances {
		bridged[a.Name] = a
	}

	// Every plan billing publishes monthly, and the limits it publishes for it.
	for _, v := range published.All() {
		if v.Interval != billingdomain.Monthly {
			continue
		}
		got, ok := bridged[string(v.Plan)]
		if !ok {
			t.Errorf("plan %q is published and reached entitlement as nothing; gate 4 "+
				"cannot price a tenant on it", v.Plan)
			continue
		}

		if len(got.Limits) != len(v.Limits) {
			t.Errorf("plan %q publishes %d limits and %d arrived: %v vs %v. A limit that "+
				"does not arrive is read as zero or as uncapped, and either way the "+
				"number sold is not the number enforced",
				v.Plan, len(v.Limits), len(got.Limits), v.Limits, got.Limits)
		}
		for key, want := range v.Limits {
			if have, ok := got.Limits[entitlementdomain.LimitKey(key)]; !ok {
				t.Errorf("plan %q publishes %s=%d and it did not arrive", v.Plan, key, want)
			} else if have != want {
				t.Errorf("plan %q publishes %s=%d and entitlement enforces %d",
					v.Plan, key, want, have)
			}
		}
	}
}

// THE LIMITS COME FROM THE LATEST MONTHLY VERSION OF EACH PLAN.
//
// Two separate claims, and the first is the one that bit. The bridge used to
// walk `Catalogue.All()` and keep the first monthly version it saw per plan.
// `All` is sorted by plan-version id, so "pro:v1:month" precedes
// "pro:v2:month" — the day a second version shipped, entitlement would have gone
// on enforcing v1's limits while every new subscriber was sold v2's, with no
// error anywhere.
//
// It survived every test then, because only one version of each plan exists. So
// this asserts it against a catalogue with two, built here rather than
// published, which is the only way to exercise a case the shipped catalogue does
// not contain yet.
//
// The interval half is asserted structurally: monthly is the interval every plan
// is guaranteed to have — a trial has no yearly form — so the bridge is only
// well-defined while that holds.
func TestTheBridgeTakesTheLatestMonthlyVersion(t *testing.T) {
	older := billingdomain.PlanVersion{
		Plan: "pro", Version: 1, Interval: billingdomain.Monthly,
		AmountMinor: 2400, Currency: "usd",
		Limits: map[string]int{"workspaces.count": 25},
	}
	newer := older
	newer.Version = 2
	newer.Limits = map[string]int{"workspaces.count": 40}

	// Deliberately in the order `All` would yield them, so a first-wins bridge
	// picks the wrong one. Driven through the REAL translation, not through
	// Catalogue.Latest: asserting that Latest works would leave the question of
	// whether the bridge calls it, which is where the bug actually was.
	catalogue, err := billingdomain.NewCatalogue(older, newer)
	if err != nil {
		t.Fatal(err)
	}
	allowances, err := allowancesFrom(catalogue)
	if err != nil {
		t.Fatal(err)
	}
	if len(allowances) != 1 {
		t.Fatalf("two versions of one plan produced %d allowances, want 1", len(allowances))
	}
	if got := allowances[0].Limits[entitlementdomain.WorkspacesCount]; got != 40 {
		t.Fatalf("entitlement enforces %d workspaces; v2 grants 40 and v1 granted 25, so "+
			"every subscriber sold v2 is capped at what v1 allowed, with no error "+
			"anywhere", got)
	}
}

// A PLAN WITH NO MONTHLY VERSION IS REFUSED, NOT SKIPPED.
//
// Skipping is the tempting handling and the wrong one: the plan reaches
// entitlement as nothing, `Plans` never mentions it, and every capped operation
// by a tenant on that plan is denied by gate 4 with no explanation — while the
// catalogue, the invoice and the marketing page all agree the plan exists.
func TestAPlanWithNoMonthlyVersionIsRefused(t *testing.T) {
	// A HEALTHY plan alongside the broken one, which is what makes this an
	// assertion about refusing rather than about emptiness. With only the
	// yearly-only plan in the catalogue, skipping it and refusing it both end in
	// an error — the "no allowances at all" guard catches the skip — so a bridge
	// that silently dropped the plan would pass. Here the skip yields one
	// perfectly valid allowance and no error at all.
	mixed, err := billingdomain.NewCatalogue(
		billingdomain.PlanVersion{
			Plan: "basic", Version: 1, Interval: billingdomain.Monthly,
			AmountMinor: 500, Currency: "usd",
			Limits: map[string]int{"workspaces.count": 3},
		},
		billingdomain.PlanVersion{
			Plan: "annualonly", Version: 1, Interval: billingdomain.Yearly,
			AmountMinor: 24000, Currency: "usd",
			Limits: map[string]int{"workspaces.count": 25},
		},
	)
	if err != nil {
		t.Fatal(err)
	}

	got, err := allowancesFrom(mixed)
	if err == nil {
		t.Fatalf("a plan with no monthly version was skipped rather than refused; %d "+
			"allowances came back and the catalogue looks healthy, while every capped "+
			"operation by a tenant on `annualonly` is denied by gate 4 with no "+
			"explanation", len(got))
	}
}

// EVERY PUBLISHED PLAN HAS A MONTHLY VERSION TO BRIDGE.
func TestEveryPublishedPlanHasAMonthlyVersionToBridge(t *testing.T) {
	published, err := billingdomain.Published()
	if err != nil {
		t.Fatal(err)
	}

	monthly := map[billingdomain.PlanID]bool{}
	all := map[billingdomain.PlanID]bool{}
	for _, v := range published.All() {
		all[v.Plan] = true
		if v.Interval == billingdomain.Monthly {
			monthly[v.Plan] = true
		}
	}
	for plan := range all {
		if !monthly[plan] {
			t.Errorf("plan %q publishes no monthly version; the bridge takes its limits "+
				"from the monthly one, so allowancesFromBilling refuses outright and "+
				"gate 4 can price no tenant at all", plan)
		}
	}
}
