# Design Review — 2026-08-08

> **Status: all findings resolved.** Each is marked ✅ with where the fix landed.
> Nothing below is outstanding; the file is kept as the record of what was found
> and why each decision was made.

Review of infra utilisation, structure, and feature surfaces before any Go is
written. Findings are graded by when they hurt:

- 🔴 **Bites hard later** — expensive or impossible to retrofit. Fix before the
  relevant domain is built.
- 🟡 **Fix during the domain** — cheap now, annoying later.
- 🟢 **Note** — record it, act when it matters.

---

# Part A — Infrastructure utilisation

## A1 ✅🔴 Reactors should use persistent subscriptions, not catch-up

**Neither document says which KurrentDB subscription type anything uses.**

ADR-019 requires reactor checkpoints that are *never rewound*, with dedup and
poison handling. That is a precise description of KurrentDB **persistent
subscriptions** — server-side checkpoint, ack/nack, a parking queue for poison
messages, and competing consumers for throughput. Building that on catch-up
subscriptions means reimplementing all four in Go.

Conversely projectors must be rebuildable from position zero, which is exactly
what catch-up subscriptions give and what persistent subscriptions deliberately
do not.

**Fix:** state it as a rule — *projectors use catch-up subscriptions on `$all`
with a client-held checkpoint; reactors use persistent subscriptions with
server-held checkpoints and parking.* This also makes ADR-019's "cannot be
rebuilt" structural rather than conventional: a persistent subscription has no
rebuild API to call by accident.

## A2 ✅🔴 SeaweedFS is running and nothing uses it

No domain spec writes an object. The stack has an S3 store with a verified
bucket and zero writers, because file verticals are out of scope.

Its real near-term users are: **GDPR export bundles** (compliance), **operator
report exports**, and eventually avatars and email attachments. None are
specified.

**Fix:** either name those users in `compliance` when it is written, or drop
SeaweedFS from the running stack until the first writer exists. An unused
dependency that everyone assumes is load-bearing is worse than no dependency.

## A3 ✅🟡 Temporal Schedules vs workflows are never distinguished

Every recurring process — scavenging (ADR-032), billing reconciliation, digest
notifications, retention sweeps — is described as "a Temporal workflow". Temporal
has **Schedules** as a first-class primitive for exactly this, with pause,
backfill, and overlap policy. A workflow that loops with a timer reimplements
them badly and cannot be paused during an incident.

**Fix:** recurring ⇒ Schedule; one-shot or entity-lifecycle ⇒ Workflow. Overlap
policy `skip` for scavenge and reconciliation.

## A4 ✅🟡 One Valkey instance serves two very different jobs

It is both the Centrifugo backplane and the application's ephemeral store —
sessions, rate limits, entitlement reservations, deny tombstones. INFRA.md flags
"split before production", but no ADR or domain carries that forward, so it will
be forgotten.

It also interacts with **C12** below: a backplane incident that justifies
flushing Valkey would silently destroy entitlement reservations.

**Fix:** carry the split into the deployment ADR, and namespace keys by purpose
now so splitting later is a config change.

## A5 ✅🟡 OpenBao holds only the KEK

It should also hold the Stripe restricted key, the Centrifugo HMAC secret, the
OpenFGA pre-shared key, and the webhook signing secrets. ADR-034 says "secrets
from the host environment and OpenBao" without saying which goes where — which
in practice means everything stays in the environment.

Its **dynamic database credentials** engine would also give short-lived Postgres
credentials instead of a long-lived password in `.env`.

**Fix:** decide the split explicitly. Suggested: OpenBao holds every secret that
is *rotatable*; the environment holds only what is needed to reach OpenBao.

## A6 🟢 No domain declares what it emits

CONVENTIONS §11 defines metric and span naming, but no domain spec says which
business metrics it produces. Dashboards will be retrofitted from whatever
happens to exist.

## A7 ✅🟢 Centrifugo recovery is on and unaccounted for

`force_recovery` is enabled, so a reconnecting client replays missed messages.
The notification arbitration (ADR-026) does not consider that a recovered
message may re-deliver an alert already shown via push.

**Fix:** the client seen-set must survive a reconnect, keyed by
`notification_id`.

---

# Part B — Structure and clean-architecture / CQRS

## B1 ✅🔴 There is nowhere for the server to live

The tree has `cmd/api` and modules, but no home for the ConnectRPC bootstrap,
the **interceptor chain** (ADR-021), the **health/readyz/probe endpoints** and
the **dependency registry** (ADR-010). These are cross-module and belong to
neither `platform/` (they know about modules) nor any single module.

**Fix:** add `internal/server/` — `server/connect` (bootstrap, h2c, reflection),
`server/interceptor` (the gate chain), `server/health` (registry + probes).

## B2 ✅🔴 Temporal workflows have no home in the tree

ADR-017 mandates workflows for a long list of processes, and every domain spec
lists its own. The tree has `cmd/worker` but no per-module package for the
workflow and activity definitions.

**Fix:** `modules/<m>/workflow/` — workflows are deterministic orchestration
(domain-adjacent), activities are I/O and belong with adapters.

## B3 ✅🔴 The structure does not express CQRS

`app/` holds "use cases" undivided. But in this architecture the two sides share
nothing: **commands** load an aggregate from KurrentDB, decide, and append;
**queries** read a Postgres projection and never touch an aggregate. Collapsing
them into one package is how, six months in, a query handler acquires an
aggregate load.

**Fix:**

```
app/
├── command/     load aggregate → decide → append   (KurrentDB)
└── query/       read projection                    (Postgres, sqlc)
```

## B4 ✅🟡 Two different "repository" concepts share one directory

`adapter/` currently holds both event-store repositories (write side) and
read-model queries (read side). They have different lifetimes, different
consistency, different tests.

**Fix:** `adapter/eventstore/` and `adapter/readmodel/`.

## B5 ✅🟡 Cross-module *causation* is not in the import contract

`organization.md` states the rule — *"driven by a reactor on a billing event,
never a direct call from billing into organization"* — but CONVENTIONS §2 only
governs imports, not causation. Someone will eventually add a query port that
mutates.

**Fix:** state it generally — **a module never invokes another module's
commands. It subscribes to their contract events and issues commands to
itself.** Query ports exposed in `contract/` are read-only, by definition.

## B6 ✅🟡 Upcaster registration has no home

ADR-029 requires an upcaster per schema version, registered somewhere the event
store consults on read. `contract/events.go` holds the types; the registry
mechanism is unspecified.

## B7 🟢 Confirmed: no cycle between `access` and `workspace`

Worth recording because it looks like there should be one. `workspace/app` needs
permission checks but imports `platform/authz.Checker`, a **kernel** port — not
the access module. `access/projection` imports `workspace/contract` to build
tuples. The dependency runs one way only, and it does so **because authorization
is a kernel port**. Anyone "simplifying" that into a direct module dependency
creates the cycle.

---

# Part C — API documentation (first-class, currently undesigned)

ADR-007 asserts *"documentation is generated from the protobuf source"* and stops
there. That is a claim, not a design. For an API-first product this is a gap on
the level of the missing structure.

## C0 ✅🔴 What is actually missing

| Concern | Status |
| --- | --- |
| Generated reference docs | asserted, no pipeline, no hosting |
| **Breaking-change detection** | none — `buf breaking` is not in CI |
| Published error catalogue | none — clients branch on reason codes they cannot discover |
| Client SDKs | none, though buf generates them for free |
| Changelog / deprecation policy | none |
| Worked examples per RPC | none |
| Auth and idempotency documented | none — they are transport concerns no schema shows |

**The error catalogue is the sharpest one.** CONVENTIONS §5 defines reason codes
that clients must branch on — `PLAN_UPGRADE_REQUIRED` versus `ACCESS_DENIED`
drives completely different UI. If those are not published as part of the API
contract, every client hardcodes strings scraped from responses.

**Fix — treat docs as build output, gated in CI:**

1. `buf lint` + **`buf breaking` against the main branch** — a breaking change
   fails the build, not review.
2. Reference docs generated from proto comments and published per version.
3. **Comments are mandatory** on every service, RPC, message and field —
   enforced by a lint rule, since an undocumented field ships forever.
4. The **reason-code catalogue is generated from the same enum** the server uses,
   so docs and behaviour cannot drift.
5. SDKs generated by buf for the languages clients actually use.
6. Every RPC carries an example request/response.
7. Deprecation uses `[deprecated = true]` plus a documented sunset window; a
   field is never removed inside a version.
8. The declared gates (ADR-021) are **rendered into the docs** — each RPC's
   required permission, operation class and entitlement, generated from the same
   options the interceptors read.

Point 8 is the payoff of ADR-021: the enforcement policy is machine-readable, so
"what permission does this endpoint need?" is answerable from the schema instead
of from the source.

---

# Part D — Feature holes

## Identity

### D1 ✅🔴 Duplicate accounts have no resolution path

A user signs up with email + password. Later they click "Sign in with Google"
using the same address. We correctly refuse to auto-link when the provider's
email is unverified (identity §7 — the takeover defence). **They now have two
accounts, and nothing merges them.**

This is one of the most common real-world identity situations, and it gets worse
with time as data accumulates on both sides. Left unhandled it becomes a support
burden that cannot be solved without a merge tool nobody planned for.

**Fix:** design account merge now — detect at sign-in ("an account already
exists for this address"), require proof of both, then merge under a single
`SubjectID`, with the losing identity's memberships and grants transferred and
its sessions revoked.

### D2 ✅🔴 API keys have no organization scope

A personal access token belongs to a user, who may be a member of several orgs.
**Which org does it act in?** Unspecified. Left as-is a key silently inherits
*all* of the user's orgs — a token leaked from one customer's CI reaches another
customer's data.

**Fix:** every key is scoped to exactly one org at creation; that scope is
immutable, and the intersection rule (identity §10) applies within it.

### D3 ✅🟡 Erased users and email reuse

After erasure the subject key is destroyed, so the blind index is meaningless and
the address is effectively free. Does the same person re-registering get a fresh
account? Almost certainly yes — but it must be stated, because the alternative
(blocking the address forever) requires retaining exactly the data erasure was
meant to remove.

### D4 ✅🟡 No last-resort account recovery

All factors lost, recovery codes lost. The operator cannot impersonate (correct).
There is no documented path, so this becomes an unplanned manual database
intervention the first time it happens — which is precisely the situation that
produces a badly-audited back door.

## Access

### D5 ✅🔴 Nothing prevents a cycle in the parent graph

A container's parent can be set to its own descendant. OpenFGA bounds resolution
depth, so this surfaces as wrong answers and latency rather than a crash.

**Fix:** an explicit acyclicity check on every move/re-parent, against the
structural tree in Postgres before writing the tuple.

### D6 ✅🔴 Team deletion orphans its grants

Grants target `team:x#member`. Deleting the team leaves those tuples in place.
Worse, if a team id is ever reused, **the new team silently inherits the old
team's access**.

**Fix:** deleting a team cascades to every grant naming it, as part of the same
saga; team ids are never reused.

### D7 ✅🟡 Resource deletion tuple cleanup

The same class of problem for workspaces and any future resource type. The drift
reconciler will flag orphans forever unless deletion cascades.

### D8 ✅🟡 What a guest actually cannot do is unspecified

Guests are described as "reduced default scope" in three documents and defined in
none. Since guests now consume a separate seat pool (ADR-027), the boundary needs
to be real.

## Billing

### D9 ✅🔴 Plan publication is not two-phase

`PlanVersionPublished` fires, then a reactor mirrors to Stripe. **If the mirror
fails, the plan is visible in our catalogue and unpurchasable.** Customers see a
plan that errors at checkout.

**Fix:** `draft → mirrored (stripe_price_id confirmed) → published`. Publication
is gated on a confirmed Stripe price; the catalogue only ever exposes published
versions.

### D10 ✅🟡 Secret rotation is undesigned

Stripe restricted key and webhook signing secret rotation (both with overlap
windows) are unspecified. Related to A5.

### D11 ✅🟡 Free → paid transition unspecified

Does the org get a new Stripe subscription or an update to the $0 one? Affects
subscription id stability, which billing history depends on.

## Entitlement

### D12 ✅🔴 Reservations live in a store declared losable

Reservations are held in Valkey. A standing invariant says **`FLUSHALL` must be
survivable** — but flushing destroys in-flight reservations, letting concurrent
requests both consume the last seat.

The committed counters in Postgres stay correct, so this is bounded over-issue
rather than corruption. But it is currently undocumented, which means it will be
discovered in production.

**Fix:** either hold reservations in Postgres alongside the authoritative
counter, or state the bounded over-issue window explicitly and add reconciliation
that detects and reports it.

### D13 ✅🟡 Metering during suspension

Does usage keep accruing while an org is suspended? It determines what the
invoice looks like after reinstatement, and the customer will notice either way.

## Operator and compliance

### D14 ✅🔴 Audit retention conflicts with erasure

Operator audit records reference tenant subjects and are deliberately retained
beyond an operator's employment. GDPR erasure must destroy a subject's personal
data. **These two requirements meet head-on and nothing resolves them.**

**Fix:** the audit log records `SubjectID` pseudonyms only, never resolvable
personal data, so erasure destroys the key and the audit record survives as a
non-identifying fact. Where an audit entry must remain identifying for a legal
obligation, that basis is recorded per-entry and documented in the Article 30
register. Decide this before `compliance` is written — retrofitting means
rewriting the audit schema.

### D15 ✅🟡 Concurrent operator catalogue edits

Two operators publishing plan versions simultaneously. Optimistic concurrency on
the aggregate covers it, but it is not stated.

---

# Resolution map

| Finding | Fixed in |
| --- | --- |
| A1 subscription types | CONVENTIONS §1.4 · EVENT-SOURCING §6 |
| A2 SeaweedFS | kept — GDPR exports + operator reports are its writers |
| A3 Temporal Schedules | CONVENTIONS §1.5 |
| A4 Valkey split | ADR-034 |
| A5 OpenBao secret scope | ADR-034 |
| A6 per-domain metrics | CONVENTIONS §11 — declared with each domain as built |
| A7 Centrifugo recovery | notification.md §3 |
| B1–B4 structure | CONVENTIONS §1, §1.2, §1.3 |
| B5 causation rule | CONVENTIONS §2 |
| B6 upcaster home | CONVENTIONS §1 (`contract/upcaster.go`) · ADR-029 |
| C0 API documentation | CONVENTIONS §7.1 |
| D1 account merge | identity.md §7.5 |
| D2 API key org scope | identity.md §10 |
| D3 identifier reuse | identity.md §7.5 · EVENT-SOURCING §5 |
| D4 last-resort recovery | identity.md §7.5 |
| D5 cycle guard | access.md §7.5 |
| D6 team deletion cascade | access.md §7.5 |
| D7 tuple cleanup | access.md §7.5 |
| D8 guest scope | access.md §7.6 |
| D9 two-phase publish | billing.md §2 |
| D10 secret rotation | billing.md §5 case 26 · ADR-034 |
| D11 free → paid | billing.md §5 case 25 |
| D12 durable reservations | entitlement.md §4 |
| D13 metering while suspended | entitlement.md §7.5 |
| D14 audit vs erasure | operator.md §5 |
| D15 concurrent operator edits | operator.md §5 |

---

# Original suggested order

1. **B1–B4 and C0** — structure and API documentation. They change the tree and
   the CI pipeline, so they must land before the first Go file.
2. **A1, A3** — subscription types and Schedules. They change what the kernel
   primitives look like.
3. **D14, D1, D2** — decide during `compliance` and `identity`; all three are
   schema-shaping.
4. **D5, D6, D9, D12** — decide during their domains; each is a guard or a state
   machine change, not a rewrite.
5. Everything 🟡 — fold into the relevant domain as it is built.
