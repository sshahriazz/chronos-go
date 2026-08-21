# Plan: Stripe, webhooks, invoicing and the customer portal

Reconciles [billing.md](domains/billing.md) with the cardless-trial decision in
[ORG-WORKSPACE-SCOPE.md](ORG-WORKSPACE-SCOPE.md) §3, and settles the mechanics
against the current Stripe API (`2026-04-22.dahlia`).

billing.md is already a strong spec — two-phase plan publication, re-fetch on
every webhook, 26 edge cases, reconciliation as the backstop. Most of it stands
unchanged. What follows is what the cardless trial CHANGES, plus the mechanics
the spec leaves to implementation.

## 1. What the cardless trial changes

billing.md §3 was written for a card-first trial: `incomplete → PendingActivation`,
and the trial begins only once a payment clears. Removing the card removes that
entry state. The rest of the mapping survives intact, and one row of it turns
out to be exactly what we need.

### Stripe supports this natively — verified, not assumed

A subscription can be created with a trial and **no payment method**, and
`trial_settings.end_behavior.missing_payment_method` decides what happens when
the trial ends without one:

| Setting | Stripe status at trial end | Event | Invoices while there |
| --- | --- | --- | --- |
| `cancel` | `canceled` | `customer.subscription.deleted` | — |
| `pause` | `paused` | `customer.subscription.paused` | **none generated** |
| `create_invoice` | `past_due` | `invoice.payment_failed` | one, unpaid |

**We choose `pause`**, and the reason is that billing.md §3 already maps
`paused → Suspended`, which is precisely the behaviour ORG-WORKSPACE-SCOPE §3
settled on: unreachable, not gone, reversible the moment a card arrives.

The other two are wrong for us and it is worth saying why, because each looks
plausible:

- `cancel` maps to `canceled → Closed`, which opens the export window and starts
  retention. A customer who forgot to add a card has not closed their account,
  and treating them as though they had is data loss driven by a billing state.
- `create_invoice` leaves an unpaid invoice and `past_due`. It accrues a real
  debt for a service the customer never agreed to pay for, and dunning then
  chases them for it.

`pause` also generates **no invoices while paused**, which matters: a suspended
trial must not quietly accumulate a balance that appears on the first real
invoice if they convert months later.

### Revised status mapping

| Stripe status | Org status | Reached by |
| --- | --- | --- |
| `trialing` | `Trialing` | org creation (cardless) |
| `active` | `Active` | card added, trial converted |
| `past_due` | `PastDue` | a renewal failed; Smart Retries running |
| `paused` | `Suspended` | trial ended with no card |
| `unpaid` | `Suspended` | retries exhausted |
| `canceled` | `Closed` | explicit cancellation |
| `incomplete` | *(does not occur at signup)* | see below |
| `incomplete_expired` | *(does not occur at signup)* | |

`incomplete` was the entire justification for `PendingActivation`. With no
payment at signup there is no initial charge to be incomplete, so the state has
no producer and is deleted along with `provisional_owner`.

It can still occur *later* — SCA on a renewal — but that is a subscription that
was already `active`, so it lands in `past_due` and the existing dunning path
handles it. Nothing needs a pending state.

## 2. Who owns the truth, and when

The rule billing.md §1 states — Stripe owns subscriptions and invoices, we own
the plan catalogue and the mapping to org lifecycle — is unchanged. The cardless
trial raises one question the spec does not answer: **does a Stripe object exist
during the trial at all?**

### Option A — Stripe from org creation (recommended)

`OrganizationCreated` triggers a reactor that creates the Stripe Customer and a
trialing Subscription. Stripe status drives org status for the org's entire
life, and there is exactly one lifecycle.

This is what billing.md §2 already argues for in a different context: free plans
get a $0 Price *"so every customer has a real subscription and the lifecycle has
exactly one shape. The alternative — free customers with no Stripe object —
creates a second code path through every state machine, and that second path is
where the bugs live."* A cardless trial is that same case.

Cost: a Stripe Customer per trial signup, spam included. Bounded by one org per
verified subject (organization.md §1) plus identity's registration ceilings —
which is also Stripe's own advice, since their docs warn that cardless trials
*"can allow spammers to create lots of fake customers"* and recommend requiring
an account before the trial starts. We already do.

### Option B — Stripe only on upgrade

No Stripe object while trialing. Org status is locally owned during the trial
and Stripe-owned afterwards; trial expiry is our Temporal workflow rather than
Stripe's.

Cheaper and spam-proof, and it is the second code path billing.md warns about:
two producers of org status, two expiry mechanisms, and a handoff between them
at the single most valuable moment in the customer's life.

**Recommendation: A.** The failure modes of B cluster exactly where the money is.

### The provisioning window

Option A means org creation depends on a network call to Stripe, and the
architecture forbids that in a request handler — writes go to the event log,
external I/O belongs in reactors and activities.

So `CreateOrganization` appends `OrganizationCreated` and returns. A reactor
creates the Stripe objects and appends `OrganizationTrialStarted` carrying the
customer and subscription ids. Between the two the org is **`Provisioning`**.

`Provisioning` is not `PendingActivation` returning under a new name, and the
difference is the point: `PendingActivation` waited on a *human* to pay and
lasted days, which is why it needed expiry, purging and a near-powerless
relation. `Provisioning` waits on a *reactor* and lasts seconds. It needs a
spinner and a timeout alarm, not a lifecycle.

Mirroring is idempotent on our org id in Stripe metadata plus a Stripe
idempotency key, the same pattern billing.md §2 uses for plan mirroring, so a
retried reactor finds the existing objects rather than creating a second
customer.

## 3. Upgrade: adding a card

The subscription created at trial start is the subscription the org keeps for
its whole life. billing.md §5 case 25 already states this for the free→paid
transition — *"the $0 subscription is UPDATED, never replaced — the subscription
id is stable for the org's whole life, so billing history stays continuous and
our mirror needs no re-keying."* The same rule applies here, and it rules out
the obvious implementation:

> **Do not create a Checkout Session in `mode: 'subscription'` to upgrade.**
> That creates a SECOND subscription on the customer, which billing.md §5 case
> 19 forbids outright — one active subscription per org — and leaves two
> sources of status for the same tenant.

Two supported paths to attach a payment method to an existing trialing
subscription:

1. **Customer Portal** (recommended). Stripe's hosted UI collects the card,
   attaches it, and can resume a paused subscription directly — their docs
   describe exactly this flow for trials that ended without payment. No card
   field of ours, no PCI surface, no UI to maintain.
2. **Checkout Session in `mode: 'setup'`**, then attach the resulting payment
   method and set it as the subscription default. Use when the upgrade needs to
   sit inside our own flow rather than a redirect.

**Converting immediately** — ending the trial early rather than waiting for it
to lapse — is a subscription update with `trial_end: 'now'`. Stripe then issues
the first invoice immediately, and `billing_cycle_anchor` defaults to `now`, so
the customer is charged a full interval with no proration. If we want the
original anchor preserved instead, that is an explicit `unchanged`.

**Never pass `payment_method_types`.** Omit it entirely so Stripe serves the
payment methods configured in the Dashboard; hardcoding `['card']` locks out
methods that convert better and is a one-line revenue regression.

## 4. Webhooks

billing.md §4 already specifies the pipeline correctly. Restated with the
verification steps made explicit, because this is the part where a mistake is
silent:

```
POST /stripe/webhook
  1. verify the signature against the signing secret   ← BEFORE parsing
  2. reject unless the source IP is Stripe's           ← defence in depth
  3. persist the raw event keyed by Stripe event id    ← idempotency boundary
  4. return 200                                        ← Stripe never waits on us
  5. Temporal workflow, workflow id = Stripe event id
  6. RE-FETCH the object from Stripe                   ← never trust the payload
  7. reconcile → append domain events
```

Four properties, each of which fails silently if skipped:

- **Signature first, parse second.** An unverified webhook is an unauthenticated
  request that changes billing state. Verify against the raw body — any
  middleware that re-serializes the JSON before verification breaks the
  signature.
- **Dedupe on Stripe's event id, not ours.** Stripe retries; the same event
  arrives more than once by design.
- **Re-fetch, always.** Stripe does not guarantee ordering, so applying a
  payload as a delta will eventually apply a stale one. Re-fetching makes the
  handler convergent — processing an old event twice reaches the same state.
  The Customer Portal makes this mandatory rather than advisable: a customer can
  cancel or switch plans entirely inside Stripe's UI, and for those changes the
  webhook is the only signal we ever get.
- **200 immediately.** Work happens in the workflow. A handler that does its
  work before responding turns a slow reconcile into a Stripe retry storm.

### Events that matter for the cardless trial specifically

On top of billing.md §4's list:

| Event | Why it matters here |
| --- | --- |
| `customer.subscription.trial_will_end` | Fires **3 days** before trial end. The only warning the customer gets. Drives the "add a card" notification. |
| `customer.subscription.paused` | Trial ended with no card → org `Suspended`. |
| `customer.subscription.resumed` | Card added to a paused subscription → org back to `Active`. |
| `customer.subscription.updated` | Trial converted to paid; entitlements apply immediately. |

## 5. Invoicing

We render no invoices and compute no totals. Stripe's invoice is the number —
billing.md §6 states the rule for discounts and it generalises: *"we never
compute a discounted amount. Reimplementing the arithmetic guarantees the two
disagree eventually."*

What we hold is a **reference and a status**, projected from webhooks:
invoice id, number, status, amount, currency, period, and the hosted URL. The
customer views and downloads the PDF from Stripe's hosted invoice page or the
Portal. Tax is Stripe Tax; we store validation status only.

A trialing org has no invoices, and a paused one generates none. The first
invoice appears when the trial converts.

## 6. Customer Portal

Configured once in the Dashboard, and it covers the whole self-service surface:
update payment method, view and download invoices, change plan, cancel, resume a
paused subscription, manage tax ids.

Access is a short-lived portal session created server-side for the org's Stripe
customer, and **gated by the `billing_manager` relation** — which organization.md
§5.1 resolves to the owner alone. An org admin gets `billing_viewer` and can see
spend and invoices without being able to change what the company is committed
to (ADR-027). Those two relations belong in the organization fragment of the
authorization model, which is why this plan had to exist before slice 1 wrote
that fragment.

Everything the Portal can do arrives back as a webhook and nowhere else. That is
the concrete reason step 6 of §4 is not optional.

## 7. Keys, secrets and environments

- **Restricted API key** (`rk_`), not a secret key, scoped to the resources this
  integration touches.
- Keys and the webhook signing secret live in **OpenBao** (ADR-028), never in
  the environment and never in the repository.
- **Rotation with an overlap window**: two signing secrets are accepted while
  rotating, so no webhook is dropped mid-cut (billing.md §5 case 26).
- **A live key outside production fails startup** (ADR-008, billing.md case 20).
  Test and live have separate keys, separate webhook secrets, separate data.
- Stripe objects carry our ids in `metadata`; our projections carry Stripe ids.
  Neither system's id is derivable from the other's, so both directions are
  stored.

## 8. What "correct by design" means here, concretely

Properties, and what proves each. A billing bug is not found by reading code.

| Property | Proved by |
| --- | --- |
| A duplicate webhook changes nothing | Deliver the same event id twice; assert one set of domain events |
| An out-of-order webhook changes nothing | Deliver `updated` events in reverse; assert final state matches the re-fetched object |
| A forged webhook is refused | Valid body, wrong signature → 400, no state change |
| Trial end with no card suspends, never closes | **Stripe test clock** advanced past trial end; assert `paused` → `Suspended`, data intact |
| Adding a card resumes the same subscription | Assert the subscription id is unchanged across the whole lifecycle |
| One subscription per org, always | Attempt a second; reconciliation flags it |
| A failed mirror never exposes a plan | Force the mirror to fail; assert the version stays `draft` and is unpurchasable |
| Entitlements follow status immediately on upgrade | Assert caps lift on `subscription.updated`, not at the next projection tick |
| Downgrade below usage never deletes | Assert `over_limit`: reads work, `grow` refused |

**Stripe test clocks are the mechanism that makes most of these testable at all.**
A 14-day trial cannot be waited out in a test suite; a test clock advances
Stripe's own view of time so the real webhooks fire in the real order. This is
the billing equivalent of ADR-054's movable clock, and the two need to agree —
advancing Stripe's clock without advancing ours produces a suspension our own
deadlines disagree with.

## 9. Open decisions

1. **Which plan does a cardless trial subscribe to?** A subscription needs a
   Price. Either the customer picks a plan at signup without paying, or every
   trial starts on a designated default plan and choosing happens at upgrade.
   The second is fewer decisions before value; the first makes the trial
   represent what they intend to buy.
2. **`Provisioning` state, or accept the drift window?** §2 recommends the
   state. The alternative is to mark the org `Trialing` optimistically and let
   reconciliation repair a failed mirror — simpler, at the cost of a tenant that
   believes it has a subscription it does not.
3. **Does the trial convert automatically at trial end when a card was added
   mid-trial?** Stripe's default is yes — that is what a trial is. Worth
   confirming it is what we want rather than inheriting it.
4. **Annual plans at launch?** Changes nothing structurally, but it changes the
   proration surface and the catalogue's shape, and is cheaper to decide before
   the catalogue exists than after.
