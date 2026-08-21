# Scope: organization and workspace

Written after reading [organization.md](domains/organization.md),
[workspace.md](domains/workspace.md) and [access.md](domains/access.md) against
the tree as it actually stands. The purpose is to decide what the first slice
is, in what order, and which decisions have to be made before any of it starts.

## 1. Where we actually are

Verified, not recalled:

| Thing | State |
| --- | --- |
| `internal/modules/` | `identity`, `notification`, `profile`. No `access`, `organization`, `workspace`, `entitlement` or `billing`. |
| OpenFGA adapter | **Exists** — `checker.go`, `writer.go`, `dial.go`, `probe.go`, both with integration tests. |
| `internal/platform/authz` | **Exists** — `Guard`, `Decision`, tuple helpers, depth cap. |
| `OPENFGA_STORE_ID` | Declared in config. **Not set**, so the checker is not constructed and the server logs it at every boot. |
| Authorization model | **Does not exist.** No `.fga` file anywhere in the tree. |
| `OrgResolver`, `Subscriptions`, `Entitlements` | Interfaces declared in `interceptor`. **Zero implementations.** |
| Authorization declarations | 22 of 22 are `self` on `user`. Nothing reaches the org-context, authz, subscription or entitlement gates. |

The last row is the important one. The enforcement pipeline is built and tested,
and four of its six gates have never been exercised by a real method. They are
not broken; they are unused.

## 2. The prerequisite that cannot be skipped

**`access` is the next module, not `organization`.**

Both specs assume a working graph. `workspace.parent = organization` is what
makes an org admin an admin of every workspace "present and future, with no
fan-out" (organization.md §5.1) — that inheritance IS the design, and it lives
entirely in OpenFGA. Without it, every role question becomes a query, which
[access.md §7](domains/access.md) forbids outright: *never authorize from a
projection*.

So the first org RPC that is not `CreateOrganization` cannot be enforced until
access works. Building organization first would mean writing handlers whose gate
refuses them, which is the state we are already in.

What `access` still owes, none of which exists:

1. **The authorization model, assembled from module fragments** (ADR-006,
   access.md §10). Never hand-edited as one file — each module contributes its
   own types, and a build step assembles them. This is a new tool under
   `internal/tools/`, and it is the piece that most wants getting right first,
   because of (3).
2. **Store provisioning and model pinning.** A model deploy produces an
   immutable model id; checks pin it. That id has to reach config and the
   running server.
3. **Deploy ordering, which access.md calls not negotiable:** model first, then
   code that pins it, then code that writes tuples. A tuple naming a type absent
   from the pinned model is *rejected*, and the access projector then falls
   behind — which surfaces as newly created resources being unreachable. This
   ordering constrains how every later slice ships.
4. **The access projector.** Tuples are a projection; the event log is truth.
   `TupleWriter` is reachable only from a projector — enforced by package
   visibility, not convention.
5. **Revocation tombstones** (ADR-045). A removed member must be denied
   *before* the projection catches up, and the tombstone is cleared by the
   projector confirming the tuple is gone, never by a timer.

## 3. Activation: a cardless trial, upgrading with a card — DECIDED

An organization starts in **Trialing on creation, with no payment method**, and
upgrades to **Active by adding a card**. This is a permanent product decision,
not scaffolding to be removed once billing lands.

It changes the documented state machine. organization.md §3 has payment come
*first* — `PendingActivation` sits in front of `Trialing`, and the trial itself
begins only once a card is confirmed:

```
CreateOrganization → PendingActivation → (payment confirmed) → Trialing → Active
```

What we are building instead:

```
CreateOrganization → Trialing ──(card added, checkout completes)──► Active
                         │
                         └──(trial ends, no card)──► Suspended
```

### Three consequences, none of them cosmetic

**1. `provisional_owner` probably disappears.** It exists to solve one problem,
stated in organization.md §4: ownership comes from payment, but the user has to
reach checkout for their own unpaid org before they have paid. A cardless trial
dissolves that problem — the creator is a real `owner` from the first event,
with a fully working org. Unless we keep a second card-first entry path, the
relation, its capability table and the `subscription` gate's special-casing of it
all go away.

That is a simplification worth taking deliberately rather than inheriting the
mechanism because the document describes it. **Open: do we keep a card-first
path at all?** If every org begins as a cardless trial, we should not.

**2. The card was the anti-abuse control, and removing it removes that.** A
cardless trial is farmable: one person, unlimited orgs, unlimited trial quota.
The spec never addresses this because its trial required a card, and requiring a
card *is* the control. So we now owe explicit ones, and they are new work the
domain specs do not describe:

- a cap on orgs created per subject, and per verified email domain
- rate limiting on `CreateOrganization` (identity already has the shape for this
  — the per-caller and per-address ceilings registration uses)
- trial quotas low enough that farming is not worth it, which makes the
  entitlement catalogue load-bearing during the trial rather than after it

**3. Trial end must SUSPEND, not expire.** organization.md's `Expired → purged`
path is for an abandoned *pending* org: no payment, no data, and purging it
frees the slug. A cardless trial org has real workspaces, real members and real
content, and purging that on a missed upgrade is data loss driven by a billing
state. Suspended is already the correct state for it — unreachable, not gone,
and reversible the moment a card arrives. `Expired` stays only if we keep a
pending state at all, which (1) suggests we will not.

### Settled parameters

| Parameter | Value | Note |
| --- | --- | --- |
| Entry path | **Cardless trial only** | `provisional_owner` and `PendingActivation` are deleted, not carried |
| Trial length | **14 days** | |
| Trial caps | **3 workspaces, 5 seats** | `grow` refused past these while `Trialing` |
| Orgs owned per subject | **1** | Not a tunable — a model invariant (organization.md §1) |
| Trial end without a card | **Suspended** | Unreachable, not purged; reversible when a card arrives |

The last row of the table is the one that changes the threat model, and it was
already true rather than newly decided: **a subject owns at most one
organization.** That was settled long ago and recorded nowhere, which is why it
came up again here; it now lives in organization.md §1 where a handler author
will find it.

### What trial farming actually looks like, given one org per subject

Materially better than the general case. An attacker cannot turn one signup into
many free orgs — they need one verified identity per org. So the control is not
a new org-creation quota; it is the registration path identity already guards,
with its per-address and per-caller mail ceilings and its attempt ceilings.

What remains is the cost of a single trial org per verified address, bounded by
3 workspaces and 5 seats for 14 days. That is a bounded, monitorable number
rather than an open-ended one, and it needs no new mechanism.

### The billing mechanics are planned separately

[BILLING-PLAN.md](BILLING-PLAN.md) settles how this is implemented against
Stripe: the cardless trial uses `trial_settings.end_behavior.missing_payment_method
= pause`, which produces Stripe status `paused` — the status billing.md §3
already maps to `Suspended`, and the behaviour §3 above settled on. It also
records why `billing_viewer` and `billing_manager` have to be in the
organization fragment of the authorization model, which is a slice 1 output.

### What this unblocks

Everything through invitations, with no Stripe. Billing becomes the thing that
drives `Trialing → Active`, which is a single reactor on a payment event — the
seam organization.md §3 already puts there. Nothing built before billing is
rewritten when it arrives; the same `OrganizationActivated` gets a second
producer.

## 4. Proposed slices

Each slice is shippable and independently verifiable. Sizes are relative to the
identity slice, which is the only calibrated yardstick this repo has.

### Slice 1 — access substrate (~0.75× identity)

Model fragments and the assembly tool; store provisioning; model pinning into
config; the access projector; tombstones; the `Org` resolver so gate 1 answers;
wiring `Guard` into `cmd/api` so gate 2 answers.

Done when: a method declaring a non-`self` relation is enforced end to end
against real OpenFGA, and `gates.Blocking()` is empty for it.

### Slice 2 — organization core (~1× identity)

The `Organization` aggregate, lifecycle state machine, owner and admin set with
the last-owner invariant, settings with schema versioning, `org_status_view`,
and the **subscription gate** — the operation-class × status table from §5.2,
which is the whole of gate 3.

Deliberately excluded here: domain verification, ownership transfer. Both are
their own aggregates with their own Temporal workflows and neither blocks
workspace.

Done when: the §5.2 matrix is asserted cell by cell, and a suspended org refuses
writes while `billing:manage` and `export` still succeed.

### Slice 3 — entitlement and the trial catalogue (~0.75× identity)

Moved AHEAD of workspace. The reason is not primarily abuse — one org per
subject already bounds that (§3) — it is that **3 workspaces is product
behaviour a trial org must actually experience**, and the thing enforcing it is
a reservation on `workspaces.count`.

organization.md §6 spells the order out: creating a workspace runs authz →
subscription (`grow`) → entitlement (reserve) → handler. Build workspace first
and that pipeline ships with its third stage missing, so every trial org gets
unlimited workspaces until the retrofit lands. Retrofitting a reservation around
a handler that already exists is also the harder direction: the check and the
commit have to be threaded back through a write path written without them.

Entitlement is generic — a catalogue keyed by string, and counters — so it can
be built before the resources it counts exist.

The catalogue, check → reserve → commit/release, and gate 4. Seats are the
highest-risk correctness surface in either spec:

> A seat is consumed by a person in an organization, not by a membership.

Five workspaces, one seat. Removing someone from one workspace releases nothing.
Concurrent acceptance of the last seat must have exactly one winner — the same
property `MultiAppender.AppendToMany` was measured for in identity, and it wants
the same treatment.

Done when: two concurrent requests cannot both consume the last workspace, and a
trial org is refused the workspace past its cap while reads and export still
work.

### Slice 4 — workspace and membership (~1× identity)

`Workspace`, `Membership`, the never-zero-admins invariant, inheritance and the
break/reclaim guards, `member_view`, and `org_member_index`.

Quota-gated from its first commit, because slice 3 landed first: creation runs
the full pipeline in order — authz (org `admin`) → subscription (`grow`, so
blocked outside Trialing/Active) → entitlement (`workspaces.count` reserve) →
handler.

Done when: an org admin inherits admin on a workspace created *afterwards* — the
property that proves inheritance is doing the work rather than fan-out.

### Slice 5 — invitations (~1× identity)

The terminal feature, where three domains meet. Token hashed as a credential,
seat reserved at issue rather than acceptance, every check revalidated at
acceptance, the full edge-case table, and `InvitationLifecycleWorkflow`.

### Slice 6 — teams (~0.5× identity)

Flat, grantable subjects. Deletion cascades to every grant naming the team, and
team ids are never reused.

## 5. Where this will go wrong if it goes wrong

Ranked by cost of getting it wrong, not by difficulty:

1. **Seat accounting.** Overcharges customers or leaks revenue, and both are
   silent. Wants exhaustive tests before any UI depends on the numbers.
2. **Trial farming.** Created by the cardless trial (§3) — the card was the
   anti-abuse control and it is gone — but bounded by one org per subject, so an
   attacker needs a verified identity per org rather than a single signup. The
   controls are identity's existing registration ceilings plus the trial caps.
   Still worth a dashboard: free orgs created per day, and the ratio that ever
   reach a second workspace.
3. **Model deploy ordering.** Reversing it makes newly created resources
   unreachable and the projector fall behind — a failure that presents as
   "sometimes things do not appear".
4. **Tombstone before projection.** Get the order wrong and a removed member
   keeps access for as long as the projector lags. The TTL is garbage
   collection, and reaching it is an alert (ADR-045).
5. **`workspace → organization` direction.** A cycle means the split failed.
   Worth a build-level test from the first commit of slice 4: `organization`
   must compile with `workspace` absent.
6. **`org_status_view` on the hot path.** Gate 3 reads it on every request.
   Cached in Valkey with event-driven invalidation, never TTL.

## 6. Open decisions

Activation, trial length, caps and entry path are settled (§3). Two remain, and
neither blocks slice 1:

1. **Does slice 1 include the shadow-check phase** (access.md §10: run old and
   new models in parallel and diff decisions before switching)? Right for a live
   system, pure cost for one with no traffic. Recommendation: build fragment
   assembly and model pinning now, defer shadow-check until there is traffic to
   shadow.
2. **First milestone: slices 1–4 or 1–5?** 1–4 is a usable multi-tenant surface
   with quotas and no billing. 1–5 adds invitations, which is the point of the
   product. Billing is additive after either, and does not change anything built
   before it.
