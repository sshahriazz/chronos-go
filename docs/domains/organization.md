# Domain: organization

**The commercial boundary.** One organization = one customer contract = one
subscription. It owns *who pays, what was bought, and what the tenant is allowed
to be* — and nothing about day-to-day collaboration.

This is the domain where four enforcement systems converge (§5): access, payment,
entitlement and RLS. That makes it the most connected domain in the system and
the one most at risk of becoming a dumping ground, so its exclusions (§11) matter
as much as its contents.

Dependency direction is fixed: **`workspace → organization`, never the reverse**
(ADR-020).

---

## 1. What an organization owns

| Owns | Does not own |
| --- | --- |
| Tenant identity — name, slug, branding | Members, teams, invitations → `workspace` |
| The **owner** and org-level admins | Authentication → `identity` |
| The subscription reference | Prices, invoices, payment methods → `billing` |
| Org-level policy (MFA required, session limits, allowed domains) | Permission evaluation → `access` |
| **Verified domains** | Quota counting → `entitlement` |
| The **set of workspaces** (as references) | Anything *inside* a workspace |
| Lifecycle state that gates everything beneath it | |

The org is deliberately **thin on data and heavy on authority**. It holds few
fields; what it holds decides what the entire tenant may do.

### One customer, one organization

**A subject OWNS at most one organization.** The org is the tenant and the
commercial boundary, and a customer contract is not something one person holds
several of. `CreateOrganization` refuses a subject who already owns one.

This was decided long before it was written here, and its absence cost a round
of re-litigation: the line above implies it, and an implication is not a rule a
handler can enforce or a reviewer can check.

It constrains OWNERSHIP only. A person may be a **member** of many
organizations — the seat model depends on it, since a seat is per person per
organization (workspace.md §2) and is released only when they leave that
organization entirely.

---

## 2. Aggregates

| Aggregate | Why its own boundary |
| --- | --- |
| `Organization` | Core. Holds status, owner, org-admin set, settings, billing reference. |
| `OrganizationDomain` | Domain verification has its own lifecycle — DNS polling, expiry, re-verification — and one org may hold many. |
| `OwnershipTransfer` | A multi-party, time-boxed process with its own state; modelling it inside `Organization` would smear a workflow across an entity. |

### Why the admin set lives *inside* `Organization`

Members are a separate domain and can number thousands, but **org admins are a
small bounded set**, and the invariant "an organization always has at least one
owner" must hold transactionally. Putting owner and admins inside the aggregate
keeps that invariant enforceable in one stream, while high-churn membership stays
out of the boundary entirely.

This is the general rule: *invariant-bearing sets go inside the aggregate;
high-volume collections do not.*

---

## 3. Lifecycle

Organization status is the master switch for the whole tenant.

```
                 CreateOrganization
                         │
                         ▼
              ┌────────────────────┐   no payment within N days
              │ PendingActivation  │ ─────────────────────────► Expired ─► purged
              └─────────┬──────────┘
                 payment confirmed
                         ▼
        ┌──────────► Trialing ──────────┐
        │                │ trial ends   │
        │                ▼              ▼
        │            ┌────────┐    (no payment)
        └────────────│ Active │◄────────────┐
                     └───┬────┘             │
            payment failed │                │ payment recovered
                           ▼                │
                     ┌──────────┐           │
                     │ PastDue  │───────────┘
                     └────┬─────┘
                grace exhausted
                          ▼
                   ┌────────────┐   owner cancels    ┌────────┐
                   │ Suspended  │ ─────────────────► │ Closed │
                   └────────────┘                    └───┬────┘
                                                export window
                                                         ▼
                                              retention → compliance erasure
```

Every transition out of `PendingActivation`, into `PastDue`, `Suspended` or
`Closed` is driven by a **reactor on a billing event** (ADR-019), never by a
direct call from billing into organization.

**Nothing is ever hard-deleted on non-payment.** Suspension makes data
unreachable, not gone. Destruction happens only through `compliance` retention
policy or an explicit erasure request.

---

## 4. Bootstrap — ownership is granted by payment

The flow you specified, with the chicken-and-egg problem resolved.

```
1. authenticated user  →  CreateOrganization(name)
                          org: PendingActivation
                          user: PROVISIONAL owner
2. access projector    →  grants `provisional_owner` on the org   ← immediately
3. user                →  CreateCheckoutSession  →  Stripe
4. Stripe              →  webhook  →  billing  →  PaymentConfirmed
5. reactor             →  OrganizationActivated
6. access projector    →  grant `owner`, revoke `provisional_owner`
```

### The chicken-and-egg, and its resolution

Ownership comes from payment, but the user must be able to *reach checkout* for
their own pending org before they have paid. If no relation exists at step 1,
they cannot see the org they just created.

`provisional_owner` resolves it — a deliberately near-powerless relation:

| Capability | `provisional_owner` | `owner` |
| --- | --- | --- |
| View the org shell | ✅ | ✅ |
| Manage billing / checkout | ✅ | ✅ |
| Delete the pending org | ✅ | ✅ |
| Create workspaces | ❌ | ✅ |
| Invite anyone | ❌ | ✅ |
| Change org policy | ❌ | ✅ |

This is enforced by the `subscription` gate on operation class (§5.2), not by
special-casing in handlers.

### Correctness properties

- **Idempotent activation.** Keyed by org id; a duplicate Stripe webhook is a
  no-op (ADR-016).
- **Order-independent.** Activation reconciles against Stripe rather than
  trusting webhook arrival order.
- **Abandoned checkout is reclaimed.** A Temporal workflow expires the pending
  org after N days and purges it, so abandoned signups do not accumulate or
  squat on slugs.
- **The first tuple for an org is written by a billing-driven reactor**, not by
  `organization` — which is exactly why `access` must stay agnostic (ADR-006).

---

## 5. The four enforcements

All four are declared per RPC and applied by the pipeline (ADR-021). None is
implemented inside a handler.

### 5.1 Access enforcement — the org is a resource in the graph

The org is simply another node in the access topology, and **workspaces hang off
it as children**:

```
organization:acme
   ├── owner           : [user]              ← exactly one, always
   ├── admin           : [user] or owner     ← many
   ├── billing_viewer  : admin               ← view only
   └── billing_manager : owner               ← OWNER ONLY
        ▲
        │ parent   (breakable — see below)
   workspace:eng ──────► inherits org roles automatically
        ▲
        │ parent
   (future resource types)
```

Because `workspace.parent = organization`, the owner and every org admin have
admin rights on every workspace **present and future**, with no fan-out — the
same inheritance property proved in [access.md §1](access.md). Tenancy roles cost
the same one tuple as any other grant.

**Billing is the one thing admins cannot change** (ADR-027).
`billing_manager` resolves to the owner alone, so an admin can see spend,
invoices and plan without being able to alter what the company is committed to.

### Breaking inheritance

A workspace can be made private to its own members by breaking the org edge
(access.md §3). Two guards apply, and both live in the **domain**, because
`access` must stay ignorant of what a workspace is (ADR-006):

1. **Never orphan a workspace.** The break is refused unless the workspace
   already has at least one **direct** admin who does not depend on inheritance.
2. **Break-glass reclaim.** The owner can always restore org access to any
   workspace in the org. Audited, and workspace admins are notified — never
   silent.

Without (2) a departing workspace admin could permanently lock an organization
out of its own data — data loss by permission, with no recovery short of touching
the database.

**Existence stays visible; content does not.** A broken-inheritance workspace
still appears in the org workspace list with its name and admin count, because
`organization` owns the set of workspaces as references (§1). The owner can see
that it exists, and reclaim it, without first being able to read inside it.

### 5.2 Payment enforcement — operation class × org status

Every RPC declares an **operation class**. The gate is a table, not a set of
conditionals.

| Operation class | Pending | Trialing | Active | PastDue | Suspended | Closed |
| --- | --- | --- | --- | --- | --- | --- |
| **read** | own shell only | ✅ | ✅ | ✅ | ✅ | ✅ |
| **write** | ❌ | ✅ | ✅ | ✅ *(grace)* | ❌ | ❌ |
| **grow** — consumes seats/quota | ❌ | ✅ *(capped)* | ✅ | ❌ | ❌ | ❌ |
| **billing:view** | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **billing:manage** — owner only | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| **export** | ❌ | ✅ | ✅ | ✅ | ✅ | ✅ |

Note the two billing classes are gated **differently by role but identically by
status** (ADR-027): an org admin may view billing in every state and change it in
none; the owner may do both in every state.

Three rules that are easy to get wrong and expensive when you do:

1. **Neither billing class is ever blocked.** Locking a past-due customer out of
   the page where they would pay you is self-inflicted revenue loss.
2. **`export` is never blocked.** Withholding data from a suspended tenant is a
   GDPR portability violation, not leverage.
3. **`grow` is blocked before `write`.** Stop them adding seats before you stop
   them working — it protects revenue while staying far less hostile, and it is
   reversible the moment payment lands.

### 5.3 Entitlement enforcement

Declared per RPC (`option (chronos.entitlement) = "workspaces.count"`). Counted
resources use **check → reserve → commit/release**, so two concurrent requests
cannot both consume the last workspace or seat.

The reservation is taken **after** the subscription gate, so a suspended org
never holds one.

### 5.4 RLS enforcement — two levels

Session variables set per transaction (ADR-011):

```sql
SET LOCAL app.org_id       = '…';
SET LOCAL app.workspace_id = '…';   -- when workspace-scoped
SET LOCAL app.user_id      = '…';
```

**Every workspace-scoped row carries `org_id` as well as `workspace_id`**, and
policies check both:

```sql
CREATE POLICY tenant_isolation ON <table>
  USING (org_id = current_setting('app.org_id')::uuid
     AND workspace_id = current_setting('app.workspace_id')::uuid);
```

Carrying `org_id` on workspace-scoped rows is not redundancy — it is what stops a
**forged or leaked `workspace_id` from another org** resolving. Without it, the
workspace-level policy alone would happily serve a row from a different tenant.

`FORCE ROW LEVEL SECURITY` is on, and the application role is neither owner nor
superuser.

**Projectors run under RLS too.** A projector knows the org for each event, so it
sets tenant context per event rather than bypassing policy. Only schema
migrations use a bypass role — which means a compromised projector cannot read
across tenants either.

---

## 6. Multi-workspace

An org owns many workspaces. The link is **data** (`org_id`), and the
relationship in the graph is `workspace.parent = organization` (§5.1).

Creating a workspace crosses three boundaries and passes through the pipeline in
order: authz (org `admin`) → subscription (`grow`, so blocked unless
`Trialing`/`Active`) → entitlement (`workspaces.count` reserve) → handler.

`organization` neither creates nor inspects workspaces. It publishes
`OrganizationActivated`, `OrganizationSuspended`, `OrganizationClosed`; the
`workspace` module reacts.

---

## 7. Built to expand — the extension seam

You will want whitelabeling, custom domains, SSO and more. The seam must exist
now even though the features do not.

> **New org capabilities are configuration and entitlement, never new columns on
> `Organization`.**

Adding a capability:

| Step | Where |
| --- | --- |
| 1. Define an entitlement key (`org.whitelabel`) | `entitlement` catalogue |
| 2. Add a **versioned settings section** | `Organization.settings` (JSONB, schema-versioned) |
| 3. Validate its shape at the edge | protobuf + protovalidate (ADR-007) |
| 4. *(if it introduces resources)* register a type | `access` fragment (ADR-006) |

The `Organization` aggregate gains **no fields**. Settings are data with a
declared schema version, so old documents remain readable and migrations are
explicit rather than a column-add ritual.

### Domain verification is already a primitive

`OrganizationDomain` is needed **now** for email-domain claiming (auto-join,
invitation restriction). It is deliberately generic — a DNS TXT challenge,
Temporal-driven polling, expiry and re-verification — so **custom domains for
whitelabeling reuse it unchanged**. Only certificate provisioning and routing
would be new.

This is the pattern: build the primitive the near-term feature needs, in the
shape the long-term feature will want.

---

## 8. Ownership transfer

**Exactly one owner, always** (ADR-027). Never zero, never two; an org admin
never becomes owner implicitly. The *cardinality* and the owner↔payment binding
are invariant — the *person* is transferable.

- Requires **step-up to AAL2** (`identity` §2) — it is the single most
  destructive operation available.
- The recipient must **accept**; ownership is never assigned unilaterally.
- Time-boxed by a Temporal workflow, with reminders and expiry.
- On acceptance: new owner gains `owner`, previous owner is demoted to `admin`
  (never removed — silently ejecting the person who just handed over is hostile
  and irreversible).
- Billing responsibility follows the org, not the person: the Stripe customer is
  unchanged, only the human accountable for it.
- Rejected while the org is `PendingActivation` — there is nothing to transfer
  yet.

---

## 9. Events published

`OrganizationCreated` · `OrganizationActivated` · `OrganizationTrialStarted` ·
`OrganizationTrialEnded` · `OrganizationPastDue` · `OrganizationSuspended` ·
`OrganizationReinstated` · `OrganizationClosed` · `OrganizationExpired` ·
`OrganizationRenamed` · `OrganizationPolicyChanged` · `OrganizationSettingsChanged`
· `OrgAdminAdded` · `OrgAdminRemoved` · `OwnershipTransferRequested` ·
`OwnershipTransferAccepted` · `OwnershipTransferExpired` ·
`OrganizationDomainClaimed` · `OrganizationDomainVerified` ·
`OrganizationDomainRemoved`

`SubjectID` pseudonyms only (ADR-002).

---

## 10. Read models

| Projection | Serves | Notes |
| --- | --- | --- |
| `organization_view` | org profile, settings | |
| **`org_status_view`** | **the subscription gate** | hot path — every request reads it; cached in Valkey with event-driven invalidation |
| `org_admin_view` | admin management | |
| `org_domain_view` | domain claims and verification state | |
| `org_workspace_summary` | workspace count for quota display | built from `workspace` contract events |
| `ownership_transfer_view` | pending transfers | |

`org_status_view` is the most performance-critical projection in the system —
gate 3 consults it on **every** request. It is tiny, cacheable, and invalidated by
event rather than TTL.

---

## 11. Temporal workflows (ADR-017)

| Workflow | Purpose |
| --- | --- |
| `PendingActivationWorkflow` | expire and purge abandoned signups |
| `OwnershipTransferWorkflow` | acceptance window, reminders, expiry |
| `DomainVerificationWorkflow` | DNS polling with backoff, expiry, re-verification |
| `OrganizationClosureSaga` | cascade closure to workspaces, then export window, then hand off to `compliance` |
| `SuspensionWorkflow` | grace period, escalating notice, then suspend |

---

## 12. What this domain does **not** own

- **Members, teams, invitations** → `workspace` (ADR-020)
- **Prices, invoices, payment methods, dunning** → `billing`; organization holds
  a *reference* and reacts to state
- **Quota counting and feature catalogue** → `entitlement`
- **Permission evaluation** → `access`; organization is a node in the graph, not
  the evaluator
- **Authentication and sessions** → `identity`
- **Data retention and erasure execution** → `compliance`

---

## 13. Test plan

**Domain (pure):**
- Full lifecycle transition table, including every illegal transition
- Last-owner protection under every removal and demotion permutation
- Operation-class × status matrix (§5.2) as an exhaustive table test — this is
  the payment enforcement contract and deserves every cell asserted
- Settings schema versioning: an old document still loads

**Bootstrap:**
- `provisional_owner` can reach checkout and **cannot** create a workspace or
  invite
- Activation is idempotent across duplicate and out-of-order webhooks
- Abandoned pending org expires and releases its slug

**Enforcement (integration):**
- Suspended org: writes rejected, **billing-manage and export still succeed**
- Past-due org: `grow` rejected, `write` permitted during grace
- Org admin inherits admin on a workspace created *afterwards* (§5.1)
- **RLS negative test with gates disabled**: a forged `workspace_id` from another
  org returns zero rows on `org_id` alone (§5.4)
- Projector writing under tenant context cannot touch another org's rows

**Cross-boundary:**
- `OrganizationClosed` cascades to workspaces via saga, and is resumable after a
  mid-cascade failure
- `organization` compiles with the `workspace` module absent — proving ADR-020's
  one-directional dependency is real and not merely intended
