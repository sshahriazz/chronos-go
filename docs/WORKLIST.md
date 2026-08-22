# Worklist

The live list. Updated as items move. Read this to know what is happening and
why, without reading the code.

**Status key:** `[x]` done and green · `[>]` in progress · `[ ]` not started

---

## Now: Slice 1 — access substrate

Why this slice: nothing in organization or workspace can be *enforced* until
OpenFGA answers. All 22 authz rules today are `self`, which never reaches the
graph. See [ORG-WORKSPACE-SCOPE.md](ORG-WORKSPACE-SCOPE.md) §2.

### 1a — model pipeline  ✅ complete

- [x] **Fragment vocabulary** — `internal/platform/authz/model`
      Modules declare their types in domain words; access assembles them.
      *Why:* ADR-006 — access must not know what a workspace is.
- [x] **Assembler + validation** — same package
      Refuses undefined types, duplicate owners, unholdable relations, dead
      inheritance. *Why:* each of those fails silently at runtime otherwise.
- [x] **Wire translation + deploy** — `internal/adapter/openfga/deploy.go`
      Fragment → OpenFGA Userset; store provisioning; model deploy.
- [x] **Proof against live OpenFGA** — `deploy_integration_test.go`
      Org admin inherits admin on a workspace created afterwards, 2 tuples.
      *Why:* that inheritance is the reason this topology was chosen.
- [x] **`genauthzmodel` tool** — assemble → `docs/access/authorization-model.fga`,
      plus `-check`, now part of `make check`.
      *Why:* the model becomes diffable in review, and the gate catches fragments
      drifting from the reviewed artifact. Same pattern as the OpenAPI gate.
- [x] **Store provisioned, model pinned** — `make authz-deploy`
      *Why:* `OPENFGA_STORE_ID` was blank, so the checker was never built.
      **The server now boots with zero ERROR lines** (it had two).
- [x] **`make authz-model` / `authz-check` / `authz-deploy`**

### 1b — the access module  ⏸ deferred until organization exists

**Reordered, deliberately.** Every item here needs events to react to, and there
are none: all 22 authz rules are `self`, which writes no tuples, and
organization and workspace do not exist. Building them now would mean adapters
wired to nothing — which this repo has already done once, with `inapp`,
`webpush` and `seaweedfs` fully built, fully tested and constructed by no
binary. So 1b now FOLLOWS the organization aggregate.

- [ ] **Access projector** — writes tuples from module events
      *Blocked on:* `OrganizationCreated`, whose owner grant is its first job.
- [ ] **Revocation tombstones (ADR-045)** — deny before the projection catches up
      *Blocked on:* a revocation event to react to.
- [ ] **Gate 1 (`OrgResolver`)** — "which organization is this request in"
      *Blocked on:* organizations existing.

## Slice 2 — organization core  ✅ complete

Pulled forward ahead of 1b, because 1b has nothing to react to until this
exists. Built inside-out: the pure domain first, since it needs no
infrastructure and every later piece depends on its shape.

- [x] **`Organization` aggregate + lifecycle state machine**
      30 transitions asserted, legal and illegal. `PendingActivation` and
      `Expired` are gone — both were about a card at signup.
- [x] **Owner + admin set, last-owner invariant**
      The owner cannot be removed as an admin, and adding the owner as an admin
      records nothing (it would put them in a set they can be removed from).
- [x] **Organization access fragment** — now used by the 1a proof instead of its
      fixture. `billing_manager` resolves to the owner alone (ADR-027).
- [x] **Events registered in all three binaries** + a notification decision for
      each. The existing gates caught both omissions.
- [x] **Subscription gate (the decision)** — all 42 cells of the operation-class
      × status matrix asserted. Pure, so it needed no projection; fails CLOSED
      when the status cannot be read.
- [x] **`org_status_view`** — migration 00018 with RLS, sqlc queries, the
      projection, and the `StatusReader` gate 3 depends on. Proved against a real
      database: one org cannot read another's status, and an unprojected org is
      refused rather than waved through.
- [x] **`CreateOrganization` use case + RPC** — proto, use case, handler, wired
      into cmd/api. Both uniqueness rules hold at the WRITE: one atomic append
      to three streams, each with `NoStream`. Two concurrent creations by one
      person produce exactly one organization, proved against real KurrentDB.
- [x] **Billing: provisioning only** — a THIN slice of billing, pulled forward.

      *Why the plan changed:* it said "billing is additive after" the other
      slices. That was wrong. An organization is unusable in `provisioning`, and
      BILLING-PLAN §2 Option A — chosen to avoid two code paths — makes Stripe
      the only thing that can start a trial. So slices 3–5 all sit behind this.

      In scope: the Stripe customer, a cardless trialing subscription, and the
      reactor that appends `OrganizationTrialStarted`.
      OUT of scope, still slice 6: invoicing, the customer portal, webhook
      ingestion, the plan catalogue. The trial Price comes from config, not a
      catalogue.

      - [x] Config: `STRIPE_SECRET_KEY`, `STRIPE_TRIAL_PRICE_ID`,
            `STRIPE_TRIAL_DAYS`. A LIVE key outside production fails startup.
      - [x] `app.Provisioning` + `app.Trials` — Stripe first, event second, and
            a test proving a failed provisioner appends nothing.
      - [x] `internal/adapter/stripe` — the only package that imports the SDK.
            Cardless, `missing_payment_method: pause`, idempotent on our org id
            in Stripe metadata.
      - [x] The reactor, wired into cmd/worker.
      - [x] Stripe test key and $0 recurring Price configured.
      - [x] **Proved against the real Stripe test account:** a cardless trialing
            subscription with no payment method, `missing_payment_method: pause`,
            and provisioning twice returns the SAME customer and subscription.
      - [x] **The loop closes:** `OrganizationCreated` -> reactor -> Stripe ->
            `trialing`, asserted against the event log. A redelivery changes
            nothing — same subscription, same revision.
- [ ] **Then 1b**: access projector consuming `OrganizationCreated`, tombstones,
      `OrgResolver`

Deliberately excluded: domain verification, ownership transfer. Neither blocks
workspace.

---

## Billing — webhook ingestion  ✅ complete

**Pulled forward for the same reason provisioning was.** Stripe pauses a
cardless trial at day 14 and emits `customer.subscription.paused`. Without an
endpoint to receive it we never learn, `org_status_view` says `trialing`
forever, and the trial that was supposed to end never does — a free forever
account, which is exactly the leak the `Provisioning` state was introduced to
prevent.

- [x] `STRIPE_WEBHOOK_SECRET` config, with rotation overlap
- [x] The endpoint: verifies the signature against the RAW body, dedupes on
      Stripe's event id, refuses to be served at all without a secret
- [x] Re-fetches the object from Stripe rather than trusting the payload
- [x] Stripe status -> org lifecycle, all 8 statuses asserted
- [x] **Proved end to end with `stripe listen`:** cancelling a real trialing
      subscription drove `customer.subscription.deleted` through verification,
      dedupe, re-fetch and append, and the organization reached `closed`.
- [x] **`customer.subscription.paused` at real trial end**, via a Stripe test
      clock: a real subscription reaches day 14, Stripe pauses it, and the
      organization suspends. `trial ended -> stripe paused -> org suspended`.

## Now: Slices 3+4 MERGED — entitlement, then workspace

**Merged, and the reason is the 1b lesson again.** Gate 4 has no consumer until
a method declares an entitlement, and none does: `CreateWorkspace` is the first.
Building entitlement alone would leave the gate implemented and unreachable —
adapters wired to nothing. The ordering reason still stands, so entitlement
comes FIRST INSIDE this slice rather than as a slice of its own, and
`CreateWorkspace` is quota-gated from its first commit.

Trial caps: **3 workspaces, 5 seats**.

### Entitlement first

- [x] The catalogue: limits keyed by string, with the trial plan a REAL plan
      rather than an `if trialing` branch in the derivation
- [x] check -> reserve -> commit/release in POSTGRES, not Valkey. **Two
      concurrent reservations for the last unit: exactly one wins**, and 5 of 5
      runs fail without the advisory lock.
- [x] Gate 4, the `Entitlements` interface that had never had an implementation

### Then workspace, gated from the start

- [x] `Workspace` aggregate, never-zero-admins (proved by mutation), archive/restore
- [x] `CreateWorkspace` declaring `authz(admin on organization)` + `GROW` +
      `entitlement(workspaces.count)` — the FIRST RPC to declare an entitlement,
      so the first that gate 4 has ever run for
- [x] **1b finished, because this needed it:** gate 1 (`OrgResolver`, verifying
      membership rather than trusting a header), the `org_member_index`
      projection, and the ACCESS PROJECTOR writing tuples from the event log
- [x] **cmd/api now boots with all six gates wired and zero ERROR lines**
- [x] **End-to-end proof: 3 workspaces succeed, the 4th is refused** with
      QUOTA_EXCEEDED, through authn -> org-context -> authz -> subscription ->
      entitlement -> idempotency. Raising the cap to 4 fails the test.
- [x] **Seat accounting: one person per ORGANIZATION, not per membership.**
      All three rules proved by mutation — reserving per membership overcharges
      5x, releasing on every removal leaks revenue, and releasing the old pool
      before taking the new one leaves the person holding neither.
      Seats are reserved in the USE CASE, not gate 4: gate 4 reserves
      unconditionally, and the rule is conditional.
- [x] The member RPCs — `AddWorkspaceMember`, `RemoveWorkspaceMember` and
      `ChangeWorkspaceMemberRole`. `Seats` now has a caller, and the seat rule is
      proved through the RPC as well as in isolation.
- [x] **Revocation tombstones (ADR-045) now have a writer.** The machinery was
      complete — the Guard consults them, the confirming writer clears them — and
      nothing had ever laid one, so every revocation waited on projector lag. A
      removal and a demotion lay one now, after the append and before returning,
      and the access projector's delete is what confirms it.
- [x] **`resource_id_field` works.** It had been declared in the schema and
      published in the OpenAPI document since the option existed, while the gate
      returned `ErrGateUnavailable` for every method that used one. These are the
      first three RPCs that could ever have carried it.
- [x] **The creator is a real member.** `WorkspaceCreated` named the first admin
      and nothing carried that into the membership category, so the creator had
      no Membership aggregate: removing them was a no-op that returned 200,
      changing their role was NOT_FOUND, and their membership consumed no seat.
      Creation is now one atomic append of the workspace and their `MemberJoined`.
- [x] **`org_member_index` moved to the workspace module.** Membership comes from
      organization events AND from workspace joins; one table has one writer, and
      `workspace -> organization` is the only permitted direction (ADR-020), so
      the projection has to live on the workspace side. Without the join handler
      a person added to a workspace could authenticate and then do nothing —
      gate 1 refuses to resolve an organization they demonstrably belong to.
- [x] **The access projector was skipping every membership event.** Its filter
      named `workspace-` and `organization-`; memberships live in their own
      category. A grant that never lands DENIES, which is what a healthy
      authorization graph looks like from the outside.
- [x] `entitlement.ReserveFor` / `ReleaseFor` implemented — `Seats` declared the
      port and nothing satisfied it, so the seat rule could not have run.

## Now — Slice 5, invitations

workspace.md §5. Decomposed because it is the largest slice so far and touches
four modules; each step below is a commit that leaves the tree green.

The shape of the problem: an invitation is a **credential sent to an address**,
and both halves cross a module boundary. The token is a credential, and identity
owns credentials. The address is personal data, and only the vault may hold it.
`modules/A` may import `modules/B/contract` and nothing else (CONVENTIONS §2), so
neither can be reached for directly — the port is declared by workspace and
satisfied at the composition root.

- [x] **5a — the token primitive moves to `platform/`.** Identity's minter is
      module-private, so workspace may not import it, and copying 200 lines of
      credential-hashing into a second module is the version of this that rots.
      Behaviour unchanged; identity's adapter becomes a thin wrapper.
- [x] **5b — the Invitation aggregate.** Pending → Accepted / Revoked / Expired /
      Declined / Undeliverable, as a transition table. Its own stream category,
      for the reason memberships have one.
- [x] **5c — Issue.** Seat reserved AT ISSUE and conditionally (workspace.md §5):
      60 pending invitations against 50 seats otherwise all look valid, and the
      51st acceptance fails for somebody who did nothing wrong. Address goes to
      the vault and never into an event; the blind index is what the event
      carries.
- [x] **5d — Accept.** Five checks, all revalidated at acceptance rather than
      trusted from issue time. Two paths: an existing user authenticates first; a
      new user's acceptance IS proof of address control, so it completes email
      verification rather than sending a second mail.
- [x] **5e — Revoke, decline, resend.** Resend rotates the token and extends
      expiry; the old token stays dead.
- [x] **5f — `invitation_view`** projection, keyed `(workspace_id, status,
      expires_at)`.
- [ ] **5g — the invitation mail**, through the notification reactor and a
      Temporal activity, addressed from the vault at send time (ADR-002).
- [ ] **5h — the Temporal workflow**: expiry, reminders and seat release. The
      invitation outlives any request, so a timer in a handler cannot own it.

## Then
- [ ] **Slice 6** — teams
- [ ] **Billing** — Stripe, per [BILLING-PLAN.md](BILLING-PLAN.md). Additive
      after any of the above.

---

## Parked

- [ ] `TestTheIdempotencyContractHoldsForEveryAuthenticatedMutation/DeactivateAccount`
      flake — seen once in a full-package run, passes in isolation and on every
      re-run. Same family as the one below: deactivation racing the rest of the
      package. NOT investigated; recorded so a second sighting is a pattern
      rather than a surprise.
- [ ] **The integration suite is not repeatably runnable in one day.** Two per-IP
      buckets exhaust after several full runs — `mail_caller:daily` (a daily mail
      cap) and `username_check` — and the failures then look like broken
      features: `RequestPasswordReset`, `ResendEmailVerification` and
      `TestAnUnknownFieldIsDiscarded` all fail with RATE_LIMITED. The controls
      are correct; the suite has no way to reset them. Clearing the keys in
      Valkey is the current workaround.
- [ ] `TestADeactivatedAccountCanGetBackIn` flake — 0/8 in isolation, so it
      needs concurrency with the rest of its package. Narrowed, not fixed.
- [ ] `account_name` deprecated field — delete at the first release boundary.
- [ ] WebAuthn 3-field ADR.
- [ ] CONVENTIONS §5 doc/code reconciliation.

---

## Decisions already made (not open)

| | |
| --- | --- |
| Trial | Cardless, 14 days, 3 workspaces / 5 seats |
| Trial end, no card | Suspended (Stripe `paused`), never purged |
| Entry path | Cardless trial only — `provisional_owner` and `PendingActivation` deleted |
| Orgs owned per subject | 1 (organization.md §1) |
| Trial plan | A designated `trial` plan at $0; plan chosen at upgrade |
| Stripe object | Created at org creation, brief `Provisioning` state |
| Upgrade | Card attached to the EXISTING subscription, never a new one |
