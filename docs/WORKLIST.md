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

### 1b — the access module

- [ ] **Access projector** — writes tuples from module events
      *Why:* tuples are a projection; the event log is truth. `TupleWriter` is
      reachable from a projector only.
- [ ] **Revocation tombstones (ADR-045)** — deny before the projection catches up
      *Why:* otherwise a removed member keeps access for as long as the
      projector lags.
- [x] **Gate 2 (`Guard`) now functional** — it was wired in code but dead
      without a store id. `authz` has dropped off the unwired list.
- [ ] **Gate 1 (`OrgResolver`)** — still an interface with no implementation.
      *Why:* it answers "which organization is this request in", so nothing
      org-scoped can be enforced until it exists.

---

## Next: Slice 2 — organization core

- [ ] `Organization` aggregate, lifecycle state machine
- [ ] Owner + admin set, last-owner invariant
- [ ] `org_status_view` (hot path — gate 3 reads it every request)
- [ ] Subscription gate: the operation-class × status table
- [ ] Organization access fragment (`owner`, `admin`, `billing_viewer`,
      `billing_manager`) — replaces the fixtures in the 1a test

Deliberately excluded: domain verification, ownership transfer. Neither blocks
workspace.

---

## Then

- [ ] **Slice 3** — entitlement + trial catalogue (before workspace, so
      `CreateWorkspace` is quota-gated from its first commit)
- [ ] **Slice 4** — workspace + membership
- [ ] **Slice 5** — invitations
- [ ] **Slice 6** — teams
- [ ] **Billing** — Stripe, per [BILLING-PLAN.md](BILLING-PLAN.md). Additive
      after any of the above.

---

## Parked

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
