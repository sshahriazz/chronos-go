# Domain: billing

**Stripe does the hard parts; we do the parts only we can do.** This domain is a
translation layer plus a catalogue — not a billing engine.

Governed by ADR-004 (Stripe owns money), ADR-016 (webhooks are hostile),
ADR-022 (we own the catalogue), ADR-023 (hosted surfaces only).

---

## 1. The boundary

| Stripe owns | We own |
| --- | --- |
| Subscriptions, invoices, payments | The **plan catalogue** and its versions |
| Proration, dunning, Smart Retries | Which **entitlements** a plan grants |
| Tax calculation and remittance | **Usage metering** (ours first, reported second) |
| Card data, SCA/3DS, payment methods | The mapping Stripe status → **org lifecycle** |
| Coupon redemption and stacking | Coupon **definition** and operator workflow |
| Hosted Checkout, Portal, invoices | Nothing that renders a card field |

If a capability exists in Stripe, we integrate it. The bar for building an
alternative is that Stripe genuinely cannot express it.

---

## 2. The plan catalogue

### Model

```
Plan            stable identity — "pro", "team", "enterprise"
 └── PlanVersion   IMMUTABLE once published
       ├── price, currency, interval, trial length
       ├── entitlements { features, limits, meters }
       └── stripe_price_id        ← written back after mirroring
```

**`PlanVersion` is immutable because `stripe.Price.unit_amount` is immutable**
(ADR-022). Stripe refuses price edits by design so historical invoices stay
truthful; modelling plans any other way guarantees a drift bug the first time an
operator changes a price.

### Publication is two-phase (review D9)

```
draft ──publish requested──► mirroring ──stripe_price_id confirmed──► published
                                  │
                                  └── mirror failed ──► draft (with the error)
```

**A version is only ever exposed to customers once its Stripe price is
confirmed.** Without this, a failed mirror leaves a plan visible in our catalogue
and unpurchasable — customers select it and checkout errors.

- The catalogue projection exposes `published` versions **only**.
- `mirroring` is retried by the reactor with backoff; persistent failure returns
  it to `draft` and raises an operator incident.
- A version can be archived from `published`, never deleted.

### The mirror — ours → Stripe

```
operator edits catalogue
        ↓  PlanVersionPublished
   reactor (ADR-019)
        ↓
  Stripe: create Product (if new) → create Price
          metadata: { plan_version_id: <ours> }   ← makes the mirror idempotent
        ↓
  PlanVersionMirrored { stripe_price_id }
```

- **Idempotent** by our `plan_version_id` in Stripe metadata: a retry finds the
  existing Price rather than creating a duplicate.
- **Publishing a new version archives the old Price** (`active: false`) so no new
  customer can land on it, while existing subscribers continue on it untouched.
- **Grandfathering is the default.** Existing subscribers stay on their version
  until an explicit, audited migration.
- **Reverse-drift detection:** a `price.updated` or `product.updated` webhook we
  did not originate means someone edited in the Stripe Dashboard. That is an
  incident, not a merge.

### Free plans get a $0 Price

So every customer has a real subscription and the lifecycle has exactly one
shape. The alternative — free customers with no Stripe object — creates a second
code path through every state machine, and that second path is where the bugs
live.

---

## 3. Subscription lifecycle mapping

Stripe status is the input; **org status (ADR-020) is the output** that gates the
whole tenant.

| Stripe status | Org status | Notes |
| --- | --- | --- |
| `incomplete` | `PendingActivation` | initial payment unfinished — often SCA |
| `incomplete_expired` | `Expired` | Stripe gives up after ~23h; org is reclaimed |
| `trialing` | `Trialing` | |
| `active` | `Active` | |
| `past_due` | `PastDue` | Smart Retries running; grace period |
| `unpaid` | `Suspended` | retries exhausted |
| `paused` | `Suspended` | paused trial with no payment method |
| `canceled` | `Closed` | export window opens |

Transitions are applied by a **reactor** on billing events, never by billing
calling `organization` directly.

---

## 4. Webhook ingestion

The pipeline, applying ADR-016:

```
POST /stripe/webhook
  1. verify signature (+ Stripe IP allowlist)     ← before parsing
  2. persist raw event, keyed by Stripe event id  ← idempotency boundary
  3. return 200 immediately                        ← Stripe never waits on us
  4. Temporal workflow, workflow id = stripe event id
  5. RE-FETCH the authoritative object from Stripe ← never trust the payload
  6. reconcile local state → emit domain events
```

**Step 5 is the one people skip.** Stripe does not guarantee ordering, so
applying a payload as a delta will eventually apply a stale one. Re-fetching the
current object makes the handler *convergent*: processing an old event a second
time reaches the same state.

**The Customer Portal makes this mandatory, not optional.** A customer can cancel
or switch plans entirely inside Stripe's hosted UI, so for a large class of
changes the webhook is the *only* signal we ever get (ADR-023).

### Events consumed

| Group | Events |
| --- | --- |
| Checkout | `checkout.session.completed` · `async_payment_succeeded` · `async_payment_failed` · `expired` |
| Subscription | `customer.subscription.created` · `.updated` · `.deleted` · `.paused` · `.resumed` · `.trial_will_end` |
| Invoice | `invoice.created` · `.finalized` · `.paid` · `.payment_failed` · `.payment_action_required` · `.upcoming` · `.marked_uncollectible` · `.voided` |
| Payment | `payment_intent.succeeded` · `.payment_failed` · `.requires_action` |
| Risk | `charge.dispute.created` · `.closed` · `charge.refunded` · `radar.early_fraud_warning.created` |
| Method | `payment_method.attached` · `.detached` · `.automatically_updated` |
| Discount | `customer.discount.created` · `.updated` · `.deleted` |
| Catalogue drift | `price.updated` · `product.updated` |

---

## 5. Edge cases

The part that separates a demo from a billing system.

| # | Case | Handling |
| --- | --- | --- |
| 1 | **SCA / 3DS required** | Subscription sits `incomplete`. Org stays `PendingActivation`. The user must complete authentication — surface the hosted action URL; never treat as failure. |
| 2 | **Checkout abandoned** | `checkout.session.expired` → pending org expires via Temporal, slug released. |
| 3 | **`incomplete_expired`** | Stripe abandons after ~23h. Org → `Expired`, purged. Not a payment failure — it never started. |
| 4 | **Trial ends, no payment method** | `trial_will_end` (3 days out) → notify. At end: `past_due` or `paused` → grace, then suspend. Never silent data loss. |
| 5 | **Dunning** | Stripe Smart Retries own the schedule. We only react to terminal outcomes. **We send no retry emails** — duplicating Stripe's would double-message the customer. |
| 6 | **Upgrade mid-cycle** | Stripe prorates. Entitlements apply **immediately** on `subscription.updated`. |
| 7 | **Downgrade mid-cycle** | Entitlement reduction takes effect at **period end** by default, so nothing is yanked away mid-cycle. |
| 8 | **Downgrade below current usage** | The hard one — 10 workspaces on a plan allowing 3. **Never delete.** Enter `over_limit`: existing resources stay readable, `grow` operations are blocked, customer is told what to reduce. Grace period, then read-only on the excess. |
| 9 | **Seat count change** | Quantity update → Stripe prorates. Seat *release* is deferred to period end to prevent add/remove churn gaming. |
| 10 | **Dispute / chargeback** | `charge.dispute.created` → flag, **notify operator, do not auto-suspend**. A dispute is often a confused customer; auto-suspension converts a query into a lost account. Suspension only on `dispute.closed` = lost. |
| 11 | **Refund** | Recorded. Entitlement clawback is **policy, not automatic** — surfaced to the operator. |
| 12 | **Currency lock** | A customer's currency is fixed by their first invoice. The catalogue must expose a Price in that currency or the change is refused with a clear error. |
| 13 | **Tax / reverse charge** | Stripe Tax. Tax ID collection is a Checkout/Portal feature; we store only validation status. |
| 14 | **Card expiring** | `payment_method.automatically_updated` usually resolves it silently. Otherwise notify before renewal. |
| 15 | **Missed webhook** | Stripe retries ~3 days, then stops. The **reconciliation job** is the real backstop. |
| 16 | **Duplicate webhook** | Deduped on Stripe event id (step 2). |
| 17 | **Out-of-order webhook** | Neutralised by re-fetch (step 5). |
| 18 | **Plan version migration** | Explicit operator action, Temporal workflow, batched with rate limiting, proration chosen per migration, resumable, dry-run first. |
| 19 | **Multiple subscriptions on one customer** | Not permitted — one active subscription per org. Enforced on our side; detected by reconciliation. |
| 20 | **Test vs live mode** | Separate keys, separate webhook secrets, separate DB. A live key in a non-production environment **fails startup** (ADR-008). |
| 21 | **Coupon expires mid-subscription** | Stripe applies duration rules; we mirror the resulting amount. We never compute discounts ourselves. |
| 22 | **Cancel-at-period-end vs immediate** | Default is period end — they paid for it. Immediate cancellation is an operator action with proration. |
| 23 | **Reactivation after cancel** | Before period end: undo the cancellation. After: new subscription, entitlements re-derived. |
| 24 | **Org closed with data retained** | Closure never deletes. Export window, retention, then `compliance` erasure. |
| 25 | **Free → paid transition** (review D11) | The $0 subscription is **updated**, never replaced — the subscription id is stable for the org's whole life, so billing history stays continuous and our mirror needs no re-keying. |
| 26 | **Secret rotation** (review D10) | Restricted API key and webhook signing secret both rotate with an **overlap window**: two signing secrets are accepted during rotation, so no webhook is dropped mid-cut. Secrets live in OpenBao (ADR-028), not the environment. |

---

## 6. Coupons and discounts

Defined by operators, **redeemed by Stripe**.

- **Coupon** — percent or fixed amount, duration (`once` / `repeating` /
  `forever`), redemption cap, applicable products.
- **Promotion code** — the customer-facing string mapping to a coupon, with
  first-time-only, minimum-amount and expiry restrictions.
- Operators CRUD in the panel; a reactor mirrors to Stripe, same idempotent
  metadata pattern as plans (§2).
- Applied at Checkout (customer-entered) or attached directly to a subscription
  (operator-granted, for retention and negotiated deals).
- **We never compute a discounted amount.** Stripe's invoice is the number;
  reimplementing the arithmetic guarantees the two disagree eventually.
- Our mirror exists for the operator UI, redemption analytics and audit.

---

## 7. Usage reporting to Stripe

Usage is metered by `entitlement` (ours, authoritative). Billing only *reports*
it.

```
UsageRecorded (ours)  →  reactor  →  stripe.billing.meter_events.create
                                       identifier = OUR event id
```

> **`identifier` is the deduplication key — and Stripe auto-generates one if you
> omit it, which silently defeats deduplication.** A retry would then be counted
> as new usage and overbill the customer. It is always set from our event id.

- Reporting is **at-least-once**; the identifier makes it effectively-once.
- A failed report is a *reporting* failure, never data loss — usage lives in our
  event log first (ADR-025).
- Period-boundary cutoff is aligned to the Stripe period in UTC (ADR-008).
- Corrections use `MeterEventAdjustment`, never a compensating fake event.

---

## 8. Reconciliation

Runs on a schedule and after any webhook gap:

- Every active subscription: compare local mirror against Stripe; repair.
- Catalogue: every published `PlanVersion` has a live Price with matching
  metadata; flag orphans in both directions.
- Coupons: same.
- Meter events: reported vs recorded totals per period, with a variance alarm.
- **Any repair is an incident, not a routine** — a repair means a webhook was
  lost, and the frequency is a health metric.

---

## 9. Events published

`PlanCreated` · `PlanVersionPublished` · `PlanVersionMirrored` ·
`PlanVersionArchived` · `CouponDefined` · `CouponMirrored` · `CouponRevoked` ·
`CheckoutSessionCreated` · `SubscriptionActivated` · `SubscriptionChanged` ·
`SubscriptionTrialEnding` · `SubscriptionPastDue` · `SubscriptionUnpaid` ·
`SubscriptionCanceled` · `PaymentSucceeded` · `PaymentFailed` ·
`PaymentActionRequired` · `InvoiceFinalized` · `DisputeOpened` ·
`DisputeResolved` · `RefundIssued` · `UsageReported` · `CatalogueDriftDetected`

---

## 10. Read models

| Projection | Serves |
| --- | --- |
| `plan_catalogue_view` | pricing page, operator catalogue editor |
| `subscription_view` | org billing page, operator customer view |
| `invoice_view` | invoice history (links to Stripe hosted PDFs) |
| `payment_status_view` | feeds `org_status_view` (ADR-020 gate 3) |
| `dispute_view` | operator risk queue |
| `usage_period_view` | current-cycle usage vs allowance |
| `webhook_ledger` | raw events, processing state — the audit and replay surface |

---

## 11. Temporal workflows (ADR-017)

| Workflow | Purpose |
| --- | --- |
| `WebhookProcessingWorkflow` | one per Stripe event; retries with visibility |
| `BillingCycleWorkflow` | period close → usage rollup → meter report → verify |
| `PlanMigrationWorkflow` | batched, rate-limited, resumable, dry-run capable |
| `TrialLifecycleWorkflow` | `trial_will_end` notice → conversion or suspension |
| `DunningObservationWorkflow` | observe Stripe's retries; act only on terminal outcomes |
| `ReconciliationWorkflow` | scheduled drift detection and repair |

---

## 12. What this domain does **not** own

- **Quota counting and enforcement** → `entitlement`
- **Org lifecycle** → `organization` (billing publishes; a reactor applies)
- **Operator UI and permissions** → `operator`
- **Emails about payment** → `notification`; Stripe's own dunning mail is
  configured on, and ours must not duplicate it

---

## 13. Test plan

- **Stripe Test Clocks** for every time-dependent path: trial end, renewal,
  dunning escalation, cancel-at-period-end. This is the only honest way to test
  billing without waiting a month.
- Webhook suite: duplicate delivery, out-of-order delivery, replayed event,
  forged signature (**rejected**), gap followed by reconciliation.
- Every row of the §5 edge-case table asserted, especially #8 downgrade-below-usage
  and #10 dispute-does-not-suspend.
- Catalogue mirror: publish → mirror → re-publish is idempotent; Dashboard edit
  raises `CatalogueDriftDetected`.
- Meter idempotency: the same `UsageRecorded` reported twice bills once.
- Outage: with Stripe unreachable, reads and access are unaffected and only
  billing mutations fail (ADR-025).
