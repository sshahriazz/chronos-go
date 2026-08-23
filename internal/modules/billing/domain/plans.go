package domain

// Published is the catalogue this build ships.
//
// # Annual ships from day one
//
// Decided before the catalogue existed, which is why `Interval` is a dimension
// of PlanVersion rather than a field added to it later: two Prices per plan per
// currency, and a monthly→annual switch is a subscription UPDATE that Stripe
// prorates — never a second subscription (billing.md §5 case 19, one active
// subscription per organization).
//
// # The trial is a real priced plan, not an absence
//
// billing.md §2: free plans get a $0 Price "so every customer has a real
// subscription and the lifecycle has exactly one shape. The alternative — free
// customers with no Stripe object — creates a second code path through every
// state machine, and that second path is where the bugs live."
//
// So `trial` is priced at zero and mirrored like everything else. Provisioning
// asks this catalogue for its price id and its trial length, which is what
// retired STRIPE_TRIAL_PRICE_ID and STRIPE_TRIAL_DAYS.
//
// # Limits are the same numbers entitlement enforces
//
// Carried as strings so `modules/billing` does not import
// `modules/entitlement` (CONVENTIONS §2). The composition root hands them across
// and a test asserts every key is one entitlement knows — a limit nothing
// reserves against is a number with no enforcement behind it.
func Published() (*Catalogue, error) {
	return NewCatalogue(
		// The cardless trial. Zero, monthly, fourteen days.
		//
		// No YEARLY trial, and the absence is deliberate: a trial's interval
		// never matters because it is replaced by conversion before a single
		// period elapses, and publishing one would create a Stripe Price nothing
		// could ever subscribe to.
		PlanVersion{
			Plan: TrialPlan, Version: 1, Interval: Monthly,
			AmountMinor: 0, Currency: "usd", TrialDays: 14,
			Limits: map[string]int{
				"workspaces.count": 3,
				"seats.member":     5,
				// Zero, not absent: the plan has an opinion about guest seats and
				// it is "none".
				"seats.guest": 0,
			},
		},

		// Pro, monthly and yearly.
		//
		// The yearly amount is ten months' worth rather than twelve, which is the
		// ordinary shape of an annual discount. It is stated here rather than
		// computed, because a computed discount is arithmetic that has to agree
		// with Stripe's invoice, and billing.md §6 refuses that everywhere else.
		PlanVersion{
			Plan: "pro", Version: 1, Interval: Monthly,
			AmountMinor: 2400, Currency: "usd",
			Limits: map[string]int{
				"workspaces.count": 25,
				"seats.member":     50,
				"seats.guest":      25,
			},
		},
		PlanVersion{
			Plan: "pro", Version: 1, Interval: Yearly,
			AmountMinor: 24000, Currency: "usd",
			Limits: map[string]int{
				"workspaces.count": 25,
				"seats.member":     50,
				"seats.guest":      25,
			},
		},
	)
}
