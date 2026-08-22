package domain

// StripeStatus is a subscription status as Stripe spells it.
//
// Its own type rather than a bare string so the mapping below is total by
// construction: a status Stripe adds that we have not considered maps to
// StatusUnknown and is refused, rather than silently reading as something else.
type StripeStatus string

const (
	StripeIncomplete        StripeStatus = "incomplete"
	StripeIncompleteExpired StripeStatus = "incomplete_expired"
	StripeTrialing          StripeStatus = "trialing"
	StripeActive            StripeStatus = "active"
	StripePastDue           StripeStatus = "past_due"
	StripeUnpaid            StripeStatus = "unpaid"
	StripePaused            StripeStatus = "paused"
	StripeCanceled          StripeStatus = "canceled"
)

// StripeStatuses is every status Stripe documents, for exhaustive tests.
func StripeStatuses() []StripeStatus {
	return []StripeStatus{
		StripeIncomplete, StripeIncompleteExpired, StripeTrialing, StripeActive,
		StripePastDue, StripeUnpaid, StripePaused, StripeCanceled,
	}
}

// StatusFromStripe maps a subscription status onto the org lifecycle.
//
// billing.md §3: Stripe status is the INPUT, org status is the OUTPUT that gates
// the whole tenant. This is that table, with the two entries the cardless trial
// changes.
//
// # `paused` is the one that makes the trial end
//
// A cardless trial that lapses becomes `paused`, because that is the
// `missing_payment_method` behaviour the provisioner sets. It maps to
// Suspended: unreachable, not gone, and reversible the moment a card arrives.
// Without this row a trial would end in Stripe and never end here — the tenant
// would keep working for free, and nothing would say so.
//
// # `incomplete` and `incomplete_expired` have no producer at signup
//
// billing.md maps them to PendingActivation and Expired, both of which were
// deleted with the cardless trial: there is no initial payment to be incomplete
// (BILLING-PLAN §1). `incomplete` can still occur on a RENEWAL that needs SCA,
// and that subscription was already active, so it lands in PastDue where the
// existing dunning path handles it. `incomplete_expired` cannot occur at all
// for a subscription that never had an incomplete first payment, so it maps to
// nothing and is refused rather than guessed at.
func StatusFromStripe(s StripeStatus) Status {
	switch s {
	case StripeTrialing:
		return StatusTrialing
	case StripeActive:
		return StatusActive
	case StripePastDue, StripeIncomplete:
		return StatusPastDue
	case StripePaused, StripeUnpaid:
		return StatusSuspended
	case StripeCanceled:
		return StatusClosed
	default:
		// Includes incomplete_expired and anything Stripe adds later. Refused
		// rather than mapped to a default: guessing here would move a real
		// tenant into a lifecycle state nobody chose.
		return StatusUnknown
	}
}
