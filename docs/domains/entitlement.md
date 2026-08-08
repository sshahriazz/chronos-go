# Domain: entitlement

**Answers two questions on the request path:** *is this capability purchased?*
and *is there any left?*

Distinct from `access`, and the pair is easy to conflate:

> `access` asks **"may this principal?"** · `entitlement` asks **"did this org
> buy it, and is any remaining?"**

Both must pass. A workspace admin (access ✅) on a plan capped at 3 workspaces
who already has 3 (entitlement ❌) is refused — and the error must say *which*
gate rejected them, because "upgrade your plan" and "ask an admin" are completely
different user journeys.

Governed by ADR-025 (derived state, survives a Stripe outage) and ADR-021 (gate 4).

---

## 1. The catalogue

Three kinds of entitlement, and the distinction drives everything downstream:

| Kind | Example | Enforcement |
| --- | --- | --- |
| **Feature** — boolean | `sso.enabled`, `audit_log.export` | present or absent |
| **Limit** — a ceiling | `workspaces.count: 10`, `seats.member: 50`, `seats.guest: 20` | **reserve before consume** |
| **Meter** — accumulates | `api_calls`, `storage_bytes` | record, aggregate, bill |

Only **limits** need the reservation protocol (§4). Features are a lookup; meters
are append-only.

Entitlements attach to a **`PlanVersion`** (ADR-022), never to a `Plan`. What a
customer bought cannot change underneath them when a price is revised.

---

## 2. Derivation

Entitlements are **computed, never stored as the truth**:

```
PlanVersion.entitlements        (what the plan grants)
  + Override                    (negotiated deals, support credits)
  + org status                  (Trialing / Active / PastDue / Suspended)
  ────────────────────────────
  = entitlement snapshot        → projection → Valkey → gate 4
```

The whole chain is local. **The gate never calls Stripe** — if it did, a Stripe
incident would make every quota unevaluable and take down every gated operation
for every customer (ADR-025).

### Overrides

Real customers negotiate. An override is a first-class, audited record scoped to
an org or a single workspace, optionally time-boxed, with a reason and an author.
It layers on top of the plan rather than editing it — so upgrading a customer
with a bespoke deal does not silently discard the deal.

---

## 3. Org pool, workspace consumption

Per ADR-003 the subscription is at the **org** and entitlements apply at the
**workspace**. The allocation model:

> **Limits are pooled at the org and consumed by workspaces**, with an optional
> per-workspace cap.

An org on 50 seats may spread them across workspaces however it likes; a
per-workspace cap exists only where an admin sets one. Pooling is what customers
expect and avoids stranded capacity — 10 unused seats in a dormant workspace
blocking a hire is an obviously wrong outcome.

Counters therefore live at org scope, keyed `(org_id, limit_key)`, with
workspace attribution recorded for reporting.

### Member and guest seats are separate pools (ADR-027)

`seats.member` and `seats.guest` are **independent limits**, reserved
independently. An invitation reserves against the pool matching the role being
offered, so exhausting guest seats never blocks hiring, and vice versa.

The two consequences that need coding for:

- **Role change crosses pools.** Promoting a guest to member releases a guest
  seat and reserves a member seat — as one atomic operation, so a failure cannot
  consume both or neither.
- **Guests are usually cheaper or free**, which makes the guest pool the
  abuse-prone one. It gets its own cap and its own over-limit behaviour (§7)
  rather than sharing the member pool's.

---

## 4. Enforcement: check → reserve → commit/release

A plain check-then-act is a race. Two admins inviting the last seat
simultaneously both read `49 < 50` and both proceed.

```
1. CHECK     is there headroom?                    (fast, cached)
2. RESERVE   atomically claim it, TTL-bounded       ← the actual gate
3. …handler runs…
4. COMMIT    on success — reservation becomes usage
   RELEASE   on failure — returned immediately
   EXPIRE    on crash — TTL reclaims it
```

- The reservation is taken **after** the subscription gate, so a suspended org
  never holds one (ADR-021).
- **Reservations are held in Postgres, not Valkey** (review D12). A standing
  invariant says Valkey must survive `FLUSHALL` — but flushing would destroy
  in-flight reservations and let two requests take the last seat. The reservation
  *is* the correctness mechanism, so it lives in the durable store, in the same
  transaction as the counter it guards.
  Valkey still serves the **read-side** `CHECK` as a hot cache; only `RESERVE`
  touches Postgres, and only on operations that consume a limit.
- A TTL is mandatory: a process that dies between 2 and 4 must not leak a seat
  forever. Expiry is swept by a Temporal Schedule, not a lazy check, so a leaked
  reservation cannot sit unnoticed until someone hits the limit.
- Invitations reserve at **issue** time, not acceptance — otherwise 60 pending
  invitations against 50 seats all appear valid and the 51st acceptance fails
  for someone who did nothing wrong.

---

## 5. The hot path

Gate 4 runs on every request that declares an entitlement, so:

- The snapshot is small, immutable per version, cached in Valkey keyed
  `(org_id, plan_version_id)`.
- Invalidated **by event** — subscription change, override change, plan
  migration — never by TTL alone, so an upgrade is visible immediately.
- Counters are read from Valkey with the Postgres projection as the source of
  truth and periodic reconciliation.
- A cache miss falls back to the projection; a projection miss **fails closed**
  for `grow` operations and **open** for reads. Being unable to prove headroom
  must never invent it.

---

## 6. Metering

```
domain event  →  UsageRecorded (ours, authoritative)
                        ↓
              period aggregation (projection)
                        ↓
              reactor → Stripe Billing Meters (billing §7)
```

- **Exactly-once over an at-least-once stream**: an idempotency key per usage
  event, and the counter increment committed in the same transaction as the
  projector checkpoint (ADR-013).
- Period boundaries align to the Stripe billing period in **UTC** (ADR-008) — a
  meter that rolls over at a different instant than the invoice produces
  disputes that are extremely painful to reconstruct.
- Corrections are **explicit adjustment events**, never edits to a counter.
- Usage is ours first and reported second, so a Stripe outage costs a report, not
  a record.

---

## 7. Downgrade and over-limit

The case most systems handle badly.

When a plan reduction leaves an org above a limit — 10 workspaces on a plan
allowing 3:

1. **Never delete anything.** Not on downgrade, not on non-payment.
2. Enter **`over_limit`** for that key: existing resources stay fully readable,
   and `grow` operations on that key are blocked.
3. The customer is told exactly what to reduce and by how much.
4. After a grace period the excess becomes **read-only**, chosen by a stable,
   published rule (most recently created first), never arbitrarily.
5. Restoring the plan clears the state immediately.

Downgrades take effect at **period end** by default (billing §5 case 7); nothing
is withdrawn mid-cycle that was paid for.

---

## 7.5 Metering while suspended (review D13)

**Usage keeps being recorded; it does not keep being billed.**

- Recording continues — usage is a *fact*, and a gap in the record makes the
  post-reinstatement invoice impossible to explain or audit.
- `UsageRecorded` events carry the org status at the time, so the billing rollup
  can exclude suspended periods without reconstructing history.
- In practice a suspended org generates almost no usage anyway (writes are
  blocked, ADR-020 §5.2) — but "almost none" is not "none", and the difference
  becomes a customer dispute.

The rollup rule: **suspended-period usage is reported to Stripe as zero and
retained locally**, so reinstatement produces a clean invoice and the record is
still available for a support query.

---

## 8. Trials

- Trial entitlements come from the `PlanVersion` and may be capped below the paid
  tier.
- Expiry is a Temporal timer, not a cron scan.
- On expiry without conversion: entitlements drop to the free version and §7
  governs the excess.

---

## 9. Events published

`EntitlementSnapshotChanged` · `OverrideGranted` · `OverrideRevoked` ·
`OverrideExpired` · `UsageRecorded` · `UsageAdjusted` · `QuotaReserved` ·
`QuotaCommitted` · `QuotaReleased` · `QuotaWarning` · `QuotaExceeded` ·
`OverLimitEntered` · `OverLimitCleared` · `TrialEntitlementExpired`

---

## 10. Read models

| Projection | Serves | Notes |
| --- | --- | --- |
| `entitlement_snapshot` | **gate 4** | hot; event-invalidated Valkey cache |
| `quota_counter` | current consumption per limit | authoritative counter |
| `usage_period_view` | usage vs allowance UI, invoicing | period-aligned |
| `override_view` | operator panel | audited |
| `over_limit_view` | remediation prompts | |

---

## 11. Ports

```
Catalogue     entitlements for a PlanVersion
Reserver      Reserve · Commit · Release        ← the concurrency-safe core
Meter         Record · Adjust
Snapshotter   resolve(org) → snapshot
```

No Stripe types appear anywhere in this domain (ADR-001, ADR-025).

---

## 12. What this domain does **not** own

- Prices, invoices, payment state → `billing`
- **Whether a principal may act** → `access` (the other half of the pair)
- Org lifecycle → `organization` (entitlement *reads* status, never sets it)
- Seat *assignment* → `workspace` (entitlement counts them, does not place them)

---

## 13. Test plan

- **Concurrency (`testing/synctest`)**: N goroutines racing for the last seat —
  exactly one wins; released reservations are immediately reusable; a crashed
  holder's reservation expires by TTL.
- **Exactly-once metering**: replay the whole usage stream — totals unchanged.
- **Derivation**: plan × override × org-status matrix, exhaustively.
- **Over-limit**: downgrade below usage deletes nothing, blocks `grow`, permits
  reads, and clears on restore.
- **Outage**: Stripe unreachable ⇒ entitlements still evaluate (ADR-025).
- **Boundaries**: usage attributed to the correct period across a UTC period
  rollover.
- **Gate distinction**: an access failure and an entitlement failure return
  different, actionable errors — never a generic 403.
