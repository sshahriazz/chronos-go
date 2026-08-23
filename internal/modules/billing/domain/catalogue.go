package domain

import (
	"fmt"
	"sort"
)

// Interval is how often a plan bills.
//
// A DIMENSION of the catalogue from day one rather than a field added later,
// which is the decision recorded in the worklist: deciding it before the
// catalogue exists costs a type, and deciding it afterwards costs a migration of
// every published version.
type Interval string

const (
	Monthly Interval = "month"
	Yearly  Interval = "year"
)

// Intervals is every interval this build knows, for exhaustive tests.
var Intervals = []Interval{Monthly, Yearly}

func (i Interval) valid() bool { return i == Monthly || i == Yearly }

// PlanID is a plan's stable identity across every version of it.
//
// "pro" is the same plan whether its price changed three times or never. It is
// what a customer thinks they bought, and what a migration moves them between.
type PlanID string

// TrialPlan is the plan a cardless trial subscribes to.
//
// Named here rather than configured, because provisioning has to name SOMETHING
// and a plan id that could differ between deployments is a plan id that makes
// "what did this customer sign up to" unanswerable across environments.
const TrialPlan PlanID = "trial"

// PlanVersion is one priced, immutable revision of a plan.
//
// # Why immutable
//
// `stripe.Price.unit_amount` is immutable, by Stripe's design, so historical
// invoices stay truthful (ADR-022). Modelling a plan any other way guarantees a
// drift bug the first time somebody changes a price: our record says one number,
// every invoice already issued says another, and nothing reconciles them.
//
// A price change is therefore a NEW VERSION. Existing subscribers stay on theirs
// until an explicit migration — grandfathering is the default, not a feature.
type PlanVersion struct {
	Plan    PlanID
	Version int

	Interval Interval

	// AmountMinor is the price in the currency's smallest unit, as Stripe
	// expects it. Not a decimal, for the reason every amount in this system is
	// minor units: converting means choosing a scale per currency, which is
	// arithmetic Stripe already did.
	AmountMinor int64

	// Currency is ISO 4217, lower case.
	Currency string

	// TrialDays is how long a trial on this version runs. Zero for a plan that
	// does not trial.
	TrialDays int

	// Limits are what the version grants. The keys are entitlement's LimitKeys,
	// carried as strings so `modules/billing` does not import
	// `modules/entitlement` — the two meet at the composition root, which is what
	// the import contract requires (CONVENTIONS §2).
	Limits map[string]int
}

// ID is the stable identifier written into Stripe metadata.
//
// # This string is what makes mirroring idempotent
//
// The mirror searches Stripe for a Price carrying this value and creates one
// only if it finds none, so a retried mirror finds what the last attempt made
// rather than creating a second Price at the same amount. Stripe's own
// idempotency keys expire after 24 hours; metadata does not, and a mirror can be
// re-run long after that.
//
// It includes the INTERVAL because monthly and yearly are different Prices of
// the same version, and a key that omitted it would make the second one look
// like a retry of the first.
func (v PlanVersion) ID() string {
	return fmt.Sprintf("%s:v%d:%s", v.Plan, v.Version, v.Interval)
}

// valid reports whether a plan id can be carried into Stripe.
//
// # Why a character set, and why here
//
// The mirror DERIVES the Stripe Product id from this string, because a
// deterministic id can be read back with a strongly consistent GET where a
// search cannot. That only works if every plan id is a legal Stripe id, so the
// constraint belongs on the type rather than in the adapter: a plan id that
// cannot be mirrored is not a plan id, and finding out at deployment time is
// finding out too late.
//
// Lower case, digits and hyphens. Stripe accepts more, and the extra characters
// buy nothing a plan id needs.
func (p PlanID) valid() bool {
	if p == "" || len(p) > 100 {
		return false
	}
	for _, r := range p {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-':
		default:
			return false
		}
	}
	return true
}

// Validate refuses a version that cannot be mirrored or priced.
func (v PlanVersion) Validate() error {
	switch {
	case v.Plan == "":
		return fmt.Errorf("billing: a plan version needs a plan id")
	case !v.Plan.valid():
		return fmt.Errorf("billing: plan id %q is not usable as a Stripe identifier; the "+
			"mirror derives the Product id from it, so it must be lower case letters, "+
			"digits and hyphens", v.Plan)
	case v.Version < 1:
		return fmt.Errorf("billing: plan %q has version %d; versions start at 1", v.Plan, v.Version)
	case !v.Interval.valid():
		return fmt.Errorf("billing: plan %q v%d bills %q, which is not an interval Stripe "+
			"accepts here", v.Plan, v.Version, v.Interval)
	case v.AmountMinor < 0:
		return fmt.Errorf("billing: plan %q v%d is priced at %d", v.Plan, v.Version, v.AmountMinor)
	case v.Currency == "":
		return fmt.Errorf("billing: plan %q v%d has no currency; an amount with no unit is "+
			"not a price", v.Plan, v.Version)
	case len(v.Currency) != 3:
		return fmt.Errorf("billing: plan %q v%d has currency %q, which is not ISO 4217",
			v.Plan, v.Version, v.Currency)
	case v.TrialDays < 0 || v.TrialDays > 730:
		return fmt.Errorf("billing: plan %q v%d has a trial of %d days, outside Stripe's "+
			"1..730", v.Plan, v.Version, v.TrialDays)
	}
	return nil
}

// Catalogue is every plan version this build publishes.
//
// # Why it is code and not a table
//
// billing.md §2 describes an operator editing a catalogue, with a two-phase
// publication and a mirror reactor behind it. That flow needs `operator`, which
// is a separate deployable that does not exist — so the EDITING half is not
// built, and building a draft/published state machine nothing can drive would be
// a state machine wired to nothing.
//
// What is built is the half with real consumers today: a definition provisioning
// can ask for a price id instead of reading an environment variable, and that
// entitlement can ask for limits instead of holding its own copy. When the
// operator arrives, this becomes its seed rather than its replacement.
type Catalogue struct {
	versions map[string]PlanVersion
}

// NewCatalogue builds one, refusing anything it could not mirror.
func NewCatalogue(versions ...PlanVersion) (*Catalogue, error) {
	if len(versions) == 0 {
		return nil, fmt.Errorf("billing: a catalogue with no versions prices nothing")
	}
	byID := make(map[string]PlanVersion, len(versions))
	for _, v := range versions {
		if err := v.Validate(); err != nil {
			return nil, err
		}
		if _, taken := byID[v.ID()]; taken {
			return nil, fmt.Errorf("billing: two versions share the id %q; the mirror keys "+
				"Stripe metadata on it, so the second would silently reuse the first's "+
				"Price", v.ID())
		}
		byID[v.ID()] = v
	}
	return &Catalogue{versions: byID}, nil
}

// Version returns one priced revision.
func (c *Catalogue) Version(plan PlanID, version int, interval Interval) (PlanVersion, error) {
	key := PlanVersion{Plan: plan, Version: version, Interval: interval}.ID()
	v, ok := c.versions[key]
	if !ok {
		return PlanVersion{}, fmt.Errorf("billing: no plan version %q in this catalogue", key)
	}
	return v, nil
}

// Latest returns the highest-numbered version of a plan for one interval.
//
// What a NEW subscription gets. Existing subscribers are not moved by a newer
// version appearing — grandfathering is the default (billing.md §2) — so nothing
// but signup and an explicit migration should call this.
func (c *Catalogue) Latest(plan PlanID, interval Interval) (PlanVersion, error) {
	var found []PlanVersion
	for _, v := range c.versions {
		if v.Plan == plan && v.Interval == interval {
			found = append(found, v)
		}
	}
	if len(found) == 0 {
		return PlanVersion{}, fmt.Errorf("billing: no %s version of plan %q", interval, plan)
	}
	sort.Slice(found, func(i, j int) bool { return found[i].Version > found[j].Version })
	return found[0], nil
}

// All returns every version, ordered so a mirror runs deterministically.
//
// Deterministic because the mirror creates Stripe objects: a run that visited
// them in map order would make one deployment's Products appear in a different
// sequence from another's, which turns "did this run do the same thing" into a
// question nobody can answer from a log.
func (c *Catalogue) All() []PlanVersion {
	out := make([]PlanVersion, 0, len(c.versions))
	for _, v := range c.versions {
		out = append(out, v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].ID() < out[j].ID() })
	return out
}
