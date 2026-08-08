# Architecture Decisions

Short, dated records of choices that are expensive to reverse. Anything here is
settled; everything else is still open. Supersede a record rather than editing
its decision in place.

---

## ADR-001 — The kernel is primitive-only; infrastructure never enters the domain

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

`internal/platform/**` is a **primitive kernel**: generic, domain-free building
blocks plus **port interfaces**. Concrete infrastructure lives only in
`internal/modules/<m>/adapters/**` and `internal/platform/*/adapter*`.

No package under any `domain/` directory may import a driver, SDK, or transport
library. The banned list is enforced in CI, not by review:

```
kurrentdb-client-go · jackc/pgx · openfga/go-sdk · stripe/stripe-go
aws-sdk-go-v2 · centrifugal/* · go.temporal.io/* · valkey-io/*
net/http · database/sql · encoding/json
```

`encoding/json` and `net/http` are on the list deliberately. A domain type that
carries `json:"..."` tags has let a wire format dictate its shape; a domain that
imports `net/http` has let a transport leak into a business rule. Serialization
belongs to adapters.

### The dependency rule

```
        ┌──────────────────────────────────────────────┐
        │  adapters/   api/        (know everything)   │
        └───────────────────┬──────────────────────────┘
                            │ implements ports, depends inward
        ┌───────────────────▼──────────────────────────┐
        │  app/        use cases, ports declared HERE  │
        └───────────────────┬──────────────────────────┘
                            │ depends inward
        ┌───────────────────▼──────────────────────────┐
        │  domain/     aggregates, events, invariants  │
        │              stdlib + platform primitives    │
        └───────────────────┬──────────────────────────┘
                            │
        ┌───────────────────▼──────────────────────────┐
        │  platform/   generic primitives + ports      │
        │              imports NO module               │
        └──────────────────────────────────────────────┘
```

**Ports are declared by the consumer, not the provider.** `app/` defines the
interface it needs; the adapter satisfies it. This keeps the arrow pointing
inward and makes every use case testable with a fake.

### Consequences

- A domain expressing "give me every workspace Alice can administer" calls an
  `access.Lister` port, not OpenFGA. Swapping OpenFGA out is an adapter change.
- Domain tests need no containers and no `testing.Short()` guards — they are
  pure functions over in-memory state.
- Some translation cost at every adapter boundary. Accepted; it is the price of
  the boundary being real.

---

## ADR-002 — GDPR erasure by crypto-shredding plus a PII vault

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Events **never carry raw personal data**. They carry a `SubjectID` pseudonym.
Personal data lives in a mutable PII vault keyed by that pseudonym. Where
personal data is genuinely unavoidable inside an event payload, it is encrypted
with a **per-data-subject key** held in a keyring.

Erasure under Art. 17 = destroy the subject key + purge the vault row + rebuild
affected projections. The event log stays append-only and fully replayable;
erased subjects replay as opaque tombstones.

### Why

Article 17 and an immutable log are irreconcilable without indirection. The
alternatives are worse: rewriting history destroys the audit trail (and the
integrity guarantee CASA/ASVS wants), and a vault with no encryption fails the
moment one email address is pasted into an event payload — an error no reviewer
reliably catches.

### Consequences

- **This constrains every event schema in the system**, which is why it is
  decided before the first event is written.
- The kernel owns `crypto.KeyRing`, `crypto.SubjectKey`, `pii.Vault` as
  primitives — see ADR-001; domains use them without knowing the backing store.
- Replaying an erased subject must be a first-class, tested path, not an
  afterthought. A projection that panics on a tombstone is a compliance bug.
- Export (portability) and erasure share the same subject-graph traversal, so
  they are built together.

---

## ADR-003 — Tenancy is Organization → Workspace → Team → Member

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

**Organization** is the billing and contract boundary; it owns the subscription.
**Workspace** sits beneath it and owns resources and entitlements. One
organization may own many workspaces. **Teams** are groups within a workspace.
**Members** are users bound to an organization and admitted to workspaces.

### Why

Retrofitting an organization layer later is a migration of every projection
table, every OpenFGA tuple, and every event carrying a tenant reference. The
enterprise case — one contract, several isolated workspaces — is common enough
that the cost of adding it now is far below the cost of adding it later.

### Consequences

- Every resource carries `workspace_id`; every workspace carries `org_id`.
- Entitlements attach to **workspace**; subscriptions attach to **organization**.
  An org-level plan grants workspace-level entitlements — the mapping is
  explicit and lives in the `entitlement` domain.
- Postgres row-level security on `workspace_id` as defence in depth, with
  OpenFGA remaining the authority on access.

---

## ADR-004 — Stripe owns money; we own metering

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Stripe owns subscriptions, prices, invoices, proration, dunning, tax and the
payment lifecycle. We own **usage metering** and report it to Stripe. Our
`billing` domain holds a local projection of Stripe state, never a competing
source of truth for money.

### Why

Tax, SCA, card lifecycle and dunning are large, regulated, and unrewarding to
rebuild. Metering is where our domain knowledge actually lives.

### Consequences

- Stripe webhooks are ingested **idempotently, signature-verified**, and
  translated into domain events at the adapter boundary — Stripe types never
  reach the domain (ADR-001).
- Usage counting must be exactly-once over an at-least-once event stream:
  idempotency keys plus checkpoint-in-transaction (see FEATURES → entitlement).
- Stripe is an outage dependency for checkout, not for authorization: a Stripe
  failure must never block reads or resource access.

---

## ADR-005 — Build to OWASP ASVS 4.0 Level 2; no formal CASA audit

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Implement the CASA 2.0 control set — OWASP ASVS 4.0 **Level 2**, 14 categories —
as the engineering baseline. Do not produce a formal audit evidence package.

### Why

CASA is triggered by accessing Google restricted API scopes (Drive, Gmail,
Workspace). We are not integrating those, so the certification does not apply.
Its underlying standard is still the right security bar for a multi-tenant SaaS
holding customer documents.

### Consequences

- Security requirements are tracked as ASVS control IDs against features, so
  that if a formal assessment is ever needed the gap is evidence, not
  engineering.
- Revisit immediately if Google Workspace integration is added — that changes
  this from a checklist to a mandatory Tier 2 lab assessment.

---

## ADR-006 — Access control is a generic resource-topology engine, not a feature

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

We do **not** build Drive. Drive is the *reference topology* the access engine
must be able to express:

- containers that nest arbitrarily deep,
- permission inheritance flowing down the tree,
- **break-inheritance** on a subtree (a restricted folder inside a shared one),
- direct grants to a user or a team,
- link shares with expiry and audience scoping,
- ownership transfer.

The `access` domain models these as **resource-agnostic primitives**. A resource
is `(type, id, parent)` — the engine neither knows nor cares what the type means.
Modules **register** their resource types into the authorization model.

Today the registered types are `organization`, `workspace`, and `team`. A future
vertical adds `folder` and `document` by registering them and emitting the same
lifecycle events. **The access domain does not change.**

### Why

The brief asked for Drive-style sharing but no Drive. Encoding folder/document
semantics into the access engine would mean rewriting it when the first real
vertical arrives — and would duplicate hierarchy logic in every future module,
which the "no duplication" rule forbids outright.

### Consequences

- The OpenFGA authorization model is **assembled from module contributions**, not
  hand-written as one file. Each module owns its type definitions; the access
  domain owns composition, versioning and deployment.
- `workspace` is just the first non-trivial container. Getting the topology right
  now is what makes later verticals cheap.
- The engine must be tested against a Drive-shaped fixture — deep nesting,
  broken inheritance, team grants — even though no such product feature exists
  yet. That fixture is the proof the abstraction holds.
- Resource lifecycle events (`ResourceCreated`, `ResourceMoved`,
  `ResourceDeleted`) are kernel-level contracts so that any module can
  participate in the hierarchy without depending on `access` internals.

### The reuse guarantee, stated as a checklist

Adding a resource type to a future feature must touch **zero lines** of the
`access` module. The complete procedure:

1. Declare the type in the module's own `access.fga` fragment
   (`type document; relations: parent, viewer, editor, owner`).
2. Emit the kernel resource-lifecycle events on create / move / delete.
3. Register the type's role catalogue in the module's provider set.
4. Call `access.Checker` / `access.Lister` ports from use cases.

That is the whole integration. Inheritance, break-inheritance, link shares,
team grants, conditional (expiring) grants, `Expand` debugging and the drift
reconciler all work immediately, because none of them know what a `document` is.

**This is enforced by a test, not by intent.** The access test suite runs its
full behavioural matrix against a synthetic `testresource` type declared only in
the test fixture. If a change to `access` requires knowing a concrete business
type, that suite stops compiling — the abstraction leak is caught at the moment
it is introduced rather than at the first real vertical.

---

## ADR-007 — ConnectRPC is the only server framework, on a single port

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

All RPC — gRPC, gRPC-Web and HTTP/JSON — is served by **ConnectRPC** on **one
port**. Protobuf is the interface definition language; `buf` is the build
toolchain. No `gin`, `echo`, `chi`, `gorilla`, no hand-written REST handlers, no
separate gRPC server.

The sanctioned ecosystem, all first-party:

| Concern | Package |
| --- | --- |
| Core server/client | `connectrpc.com/connect` |
| Request validation | `connectrpc.com/validate` (protovalidate interceptor) |
| Tracing & metrics | `connectrpc.com/otelconnect` |
| Health checks | `connectrpc.com/grpchealth` |
| Server reflection | `connectrpc.com/grpcreflect` |
| REST transcoding | `connectrpc.com/vanguard` (only if a REST shape is required) |
| Codegen & lint | `buf` |

**Validation is declarative.** Constraints live in `.proto` as protovalidate
rules and are enforced by an interceptor before a handler runs. Handlers never
hand-check required fields.

**Errors are `connect.Error` with canonical codes.** The kernel's `DomainError`
maps to a code plus a machine-readable `ErrorDetail` message. Internal detail
never crosses the boundary (see ADR-015).

**Documentation is generated** from the protobuf source — the schema is the
documentation, and drift is impossible by construction.

**Interceptor order is fixed and defined once:**

```
recovery → telemetry → request-id/correlation → authn → rate-limit →
validate → tenant-context → authz → idempotency → handler
```

### Why

Connect serves gRPC and HTTP/JSON from the same handler on the same port, which
is precisely the requirement. One schema produces the wire format, the
validation rules, the docs and the client SDKs — so there is one source of truth
instead of four that drift.

### Consequences

- **Generated protobuf types are wire DTOs, never domain types.** This is the
  single biggest spaghettification risk: it is very tempting to pass
  `*workspacev1.Workspace` into a use case. ADR-001 forbids it — the API adapter
  maps proto ↔ domain, and `domain/` may not import generated packages.
- Plaintext gRPC on a shared port needs **h2c**; with TLS it is ALPN. Local dev
  runs h2c.
- `net/http` lives only in the API adapter layer, per ADR-001.

---

## ADR-008 — Typed configuration, UTC everywhere

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

One config module loads `.env` and environment into a **typed, validated struct**
at boot. Invalid or missing configuration is a **startup failure with a precise
message**, never a zero value discovered at request time. Secrets are never
logged and never appear in a `String()`.

Config is **parsed once and injected**; no package reads `os.Getenv` at runtime.

`APP_TIMEZONE` defaults to `UTC` and is configurable. The process sets it at
startup. Independently and non-negotiably:

- All timestamps are stored in UTC (`timestamptz`).
- The kernel `Clock` returns UTC.
- Timezone conversion happens only at presentation.

### Why

`APP_TIMEZONE` exists for operator convenience (log readability, scheduled-job
boundaries). It must not become permission for local-time storage — mixed
timezones in a billing period boundary is a class of bug that only shows up
across a DST change, in production.

### Consequences

- Config validation is a unit test: a table of bad environments, each asserting
  a specific error.
- Temporal workflows use `workflow.Now()`, which is UTC and deterministic, not
  the process timezone.

---

## ADR-009 — Compile-time dependency injection

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Dependency injection is **compile-time and reflection-free**, using a Wire-style
code generator (`goforj/wire`, the maintained drop-in fork of `google/wire`).
Each module exposes a provider set; the composition root wires them.

Runtime/reflective containers — `uber/fx`, `samber/do`, `dig` — are **excluded
by the requirement itself**: they resolve graphs at runtime, so a missing
dependency is a boot-time panic rather than a compile error.

### Why

`google/wire` is feature-complete but no longer actively maintained; the fork is
API-compatible and maintained. Generated wiring is ordinary Go — the compiler
type-checks the whole object graph, and there is no runtime container to reason
about.

### Consequences

- Adding a dependency to a use case is a compile error until wired. That is the
  point.
- Provider sets are per module and mirror the module boundary, so an illegal
  cross-module dependency shows up as a wiring error, reinforcing ADR-001.
- If the fork ever stalls, the fallback is a **hand-written composition root** —
  more verbose, equally compile-time-safe, zero dependencies. The generated code
  is readable Go, so that exit is cheap.

---

## ADR-010 — The server is infrastructure-aware and never crashes on dependency loss

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

The process **starts and stays up regardless of dependency availability**.
Connections are lazy, supervised, and self-healing with exponential backoff and
jitter. No dependency failure — at boot or at runtime — terminates the process.

Every adapter registers a probe with a kernel **dependency registry**. Three
surfaces expose it:

| Endpoint | Meaning |
| --- | --- |
| `/healthz` | Liveness. 200 while the process is alive. Never gated on dependencies. |
| `/readyz` | Readiness. 200 only when **critical** dependencies are up. |
| `SystemService/GetStatus` (Connect RPC) | Per-dependency detail for the frontend to degrade its UI. |

### Degradation policy — decided per dependency, not per incident

| Dependency | Down ⇒ | Rationale |
| --- | --- | --- |
| PostgreSQL | **Critical** — not ready | No read model, nothing to serve |
| KurrentDB | **Writes rejected, reads served** | Projections still answer queries |
| **OpenFGA** | **FAIL CLOSED — deny all** | See below |
| **OpenBao** | **PII reads fail; everything else continues** | no key ⇒ no plaintext; non-PII paths are unaffected |
| Valkey | **Degraded** — fall back to source, disable rate limiting counters | Cache, not truth |
| Centrifugo | **Degraded** — no realtime, clients poll | Notifications are not data of record |
| Temporal | **Degraded** — async work queues, deferred | Nothing is lost, only delayed |
| Stripe | **Degraded** — billing changes blocked, access unaffected | Never blocks reads (ADR-004) |
| SMTP | **Degraded** — mail retried by Temporal | Delivery is inherently retryable |
| SeaweedFS | **Degraded** — object ops fail, metadata fine | |

**OpenFGA failing closed is a deliberate exception to "stay resilient."** An
authorization service that is unreachable must deny, never allow. Resilience
must not become a privilege-escalation path — an attacker who can DoS OpenFGA
must not thereby gain access. The only softening permitted is a **short-TTL
positive-decision cache**, so an outage degrades gradually for already-active
sessions instead of instantly locking everyone out; negative results and
anything uncached still deny.

### Consequences

- Every outbound call has a **timeout, circuit breaker, and bounded retry**. A
  half-open breaker probes for recovery, so the server heals without a restart.
- Recovery is a tested path: kill a container, assert the endpoint reports
  degraded, restart it, assert recovery — without restarting the app.
- The frontend consumes `GetStatus` to grey out affected features rather than
  showing failed requests.

---

## ADR-011 — Atlas migrations, sqlc queries, no hand-written SQL at runtime

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

- **Atlas** owns schema: versioned migrations, planned and linted in CI, with
  drift detection against the live database.
- **sqlc** generates all query code from `.sql` files into typed Go against
  **pgx/v5**.
- **No SQL string ever appears in Go source.** No query builder, no ORM, no
  `fmt.Sprintf` into a statement. Repositories call generated methods only.
- Every query executes through the pooled, context-aware engine below.

To be precise about "raw SQL is banned": SQL is still *written*, in reviewed
`.sql` files that generate typed Go. What is banned is **SQL assembled or
embedded in Go at runtime** — the injection surface and the thing that defeats
static analysis.

### The RLS-aware query engine

RLS reads tenant context from Postgres session variables. With a connection
pool, a variable set with plain `SET` **leaks into the next request on that
connection** — a cross-tenant data breach. Therefore:

> **Every query runs inside a transaction that begins with
> `SET LOCAL app.workspace_id / app.org_id / app.user_id`, injected from the
> request context.** `SET LOCAL` is scoped to the transaction and cannot outlive
> it. This applies to reads as well as writes.

The engine is a kernel primitive with one entry point:

```
db.InTenantTx(ctx, func(q *sqlcgen.Queries) error { ... })
```

It refuses to run when the context carries no tenant scope. There is no bypass
API; the escape hatch for genuinely cross-tenant work (system projectors,
migrations) is a **separate, explicitly-named role and function** that is
auditable in review.

The generated queries still take `workspace_id` explicitly. Belt and braces: the
application scopes the query, RLS enforces it independently, and the two must
agree.

### Consequences

- Read-heavy paths pay transaction overhead. Accepted: correctness of tenant
  isolation is not tradeable, and pgx pools transactions efficiently.
- RLS is enabled with **`FORCE ROW LEVEL SECURITY`** so the table owner is not
  exempt — a common and silent misconfiguration.
- The app's runtime database role is **not** the schema owner and **not**
  superuser.
- Migration review includes an index review — see ADR-013.

---

## ADR-012 — Encryption is application-side; pgcrypto is defence in depth only

**Date:** 2026-08-08 · **Status:** Accepted · **Supersedes part of the stated requirement**

### Decision

Personal data is encrypted **in the application**, using envelope encryption:
a per-data-subject DEK, wrapped by a KEK held outside the database. Postgres
stores ciphertext it cannot read.

`pgcrypto` is used **only** where the database genuinely must operate on a value
(deterministic blind-index columns for equality lookup, HMAC digests). It is
**not** used for the crypto-shredding path in ADR-002.

### Why this departs from the brief

The requirement asked for encryption via Postgres extensions. Two findings make
that the wrong tool for the primary path:

1. **Verified on this stack:** the `postgres:18.4` image ships `pgcrypto` only.
   `pgsodium` — the extension with proper server-side key management — **is not
   available**. `pgcrypto` alone means the key must be supplied by the client on
   every call.
2. **That breaks crypto-shredding.** With `pgcrypto`, the key travels to the
   database in the statement, lives in server memory, and can surface in
   `log_statement`, error messages, and core dumps. ADR-002's guarantee is that
   destroying a key makes data unrecoverable *even to someone holding a database
   backup*. A key the database has seen cannot make that promise.

Given "data leak protection must be built into the system design — it can't go
wrong", the primary path has to keep key material out of the database entirely.

### Consequences

- Postgres cannot filter or sort on encrypted columns. Equality lookup is served
  by a **blind index** (HMAC of the normalized value with a separate key);
  substring search over personal data is unavailable by design.
- Defence in depth remains: RLS (ADR-011), TLS in transit, encrypted volumes at
  rest, and `pgcrypto` digests where useful.
- Revisit if a managed Postgres with `pgsodium` or a KMS-integrated extension is
  adopted — that would allow server-side keys without the logging exposure.
- **Custody was settled later in ADR-028**: the KEK lives in OpenBao's transit
  engine, so this ADR's "application-side" means *outside the database*, not
  *inside the process*. Read the two together.

---

## ADR-013 — Store ownership: who owns which byte

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Three stores, non-overlapping ownership. Anything not listed as a system of
record is **derived and rebuildable**.

| Data | Store | Nature |
| --- | --- | --- |
| Domain events (all of them) | **KurrentDB** | System of record. Append-only. |
| Read models / projections | **Postgres** | Derived. Droppable and rebuildable. |
| Projector checkpoints | **Postgres** | Derived, committed *with* the rows they track. |
| **PII vault** | **Postgres** | **System of record — the one mutable one.** |
| Encryption key metadata | **Postgres** (wrapped) | System of record; keys wrapped by external KEK. |
| Idempotency keys | **Postgres** | System of record, TTL-bounded. |
| Authorization tuples | **OpenFGA** (own DB) | Derived from events; reconcilable. |
| Sessions, rate limits, hot counters | **Valkey** | Ephemeral. Must survive `FLUSHALL`. |
| Workflow state | **Temporal** (own DBs) | System of record for in-flight processes. |
| Object bytes | **SeaweedFS** | System of record. Immutable keys. |
| Money | **Stripe** | System of record; Postgres holds a mirror (ADR-004). |

**The PII vault is the important asymmetry.** It is the only mutable system of
record, and it exists precisely because GDPR requires hard deletion that an
append-only log cannot provide (ADR-002). It is not derived from events and
cannot be rebuilt from them — so it is backed up and audited differently from
everything else in Postgres.

### The CQRS split, stated plainly

- **Write side** — commands load an aggregate from KurrentDB, decide, append.
  Writes never touch a projection table.
- **Read side** — queries read Postgres projections only. Queries never load an
  aggregate.
- Projections are **owned by exactly one projector**. Two projectors writing one
  table is banned; it makes rebuild order undefined.
- A projection may be **denormalized across module boundaries** (a member list
  view carrying user display names) — that is the point of CQRS — but it is
  built from *published contract events*, never by importing another module.

### Indexing is a first-class design step

Every projection ships with its indexes designed **before** the query that needs
them, not added after a slow query is noticed:

- Every tenant-scoped table leads with `workspace_id` in its composite indexes —
  it is in the predicate of every query, RLS included.
- Cursor pagination indexes match sort order exactly, `(workspace_id, created_at
  DESC, id)`, so keyset pagination stays index-only.
- GIN for `JSONB` and trigram search; partial indexes for soft-delete and status
  filters.
- Migration review requires an `EXPLAIN` for each new access path. A sequential
  scan on a tenant-scoped table fails review.

---

## ADR-014 — KurrentDB is accessed as a secured dependency

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

The event-store client is written against the **secure** connection model from
day one, even though local dev runs insecure:

- Credentials and TLS supplied by config (ADR-008) — never a hardcoded
  connection string.
- A dedicated, least-privilege database user per role: the writer appends, the
  projector reads `$all`, and no application user is `$admin`.
- **Stream-level ACLs** restricting which users may read or write which stream
  prefixes.
- TLS with certificate verification in every non-local environment;
  `?tls=false` permitted only when the environment is `local`, enforced by a
  config validation rule that **refuses to start** otherwise.
- Connection failure is degraded behaviour, not a crash (ADR-010).

### Why

The local stack runs `KURRENTDB_INSECURE=true` for convenience. The risk is that
code written against an unauthenticated store acquires no place to put
credentials, and "add auth later" becomes a rewrite of every call site plus an
outage. Writing the client against the secure model costs nothing now.

### Consequences

- The `EventStore` adapter takes a credential provider even in dev, where it
  supplies empty credentials.
- A CI test asserts that a non-local environment with `tls=false` fails to boot.

---

## ADR-015 — Data-leak prevention is structural, not procedural

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Tenant isolation is enforced at **four independent layers**, each sufficient to
stop a leak on its own. A single bug must never be enough.

1. **Authorization** — OpenFGA `Check` before any resource access; fails closed
   (ADR-010).
2. **Application scoping** — every query carries `workspace_id`; the query
   engine refuses to run without tenant context (ADR-011).
3. **Database RLS** — `FORCE ROW LEVEL SECURITY` re-enforces the same predicate
   independently, under a non-owner role.
4. **Response mapping** — handlers return explicitly-mapped proto messages.
   Domain structs and database rows are **never** serialized directly, so a new
   column cannot silently become a new API field.

### Supporting rules

- **No personal data in events** (ADR-002); no personal data in logs. The kernel
  logger accepts a `Redactable` type; `SubjectID` prints as a pseudonym, and
  logging a raw email is a compile-time-visible mistake, not a review-time one.
- **Errors are opaque outward.** Clients get a canonical code and a stable
  reason; stack traces, SQL, and driver text stay in logs correlated by trace ID.
- **No cross-tenant enumeration.** Not-found and forbidden return the same
  response, so IDs cannot be probed for existence.
- **Test the negative case.** Every projection query gets a test asserting that
  tenant B cannot read tenant A's row *with RLS as the only defence* — the app
  scoping is deliberately disabled in that test so the database layer is proven
  on its own.

### Consequences

- Layer 4 costs mapping boilerplate on every endpoint. Accepted: the failure it
  prevents is the one that ends companies.
- Blind indexes, not raw columns, back lookups on personal data (ADR-012).

---

## ADR-016 — Stripe webhooks are treated as untrusted, unordered, and repeatable

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Webhook handling assumes the worst of the transport:

1. **Signature verification** against the endpoint secret before parsing. A
   failed signature is dropped and alerted, never processed.
2. **Idempotent by event ID.** Every Stripe event ID is recorded; a duplicate is
   acknowledged and ignored.
3. **Order is not guaranteed.** Handlers never infer state from arrival order.
   On any subscription-affecting event, the handler **re-reads the authoritative
   object from Stripe** and reconciles, rather than applying a delta.
4. **Acknowledge fast, process asynchronously.** The endpoint persists the raw
   event and returns 2xx immediately; a Temporal workflow does the work with
   retries. Stripe must never wait on our projection.
5. **Reconciliation job** periodically compares local subscription state against
   Stripe and repairs drift — because a permanently missed webhook is a
   question of when, not if.
6. Stripe types are translated to domain events **at the adapter edge**
   (ADR-001).

### Consequences

- Billing state is eventually consistent with Stripe by design; the UI reads
  local state and shows a pending indicator during reconciliation.
- Webhook replay from the Stripe dashboard is a supported recovery action, safe
  because of (2).

---

## ADR-017 — Temporal is evaluated before any feature is built

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Every feature answers this before implementation: **does it span time, retries,
or more than one system?** If yes, it is a Temporal workflow, not a goroutine, a
cron row, or a `time.AfterFunc`.

Committed to workflows from the outset:

| Process | Why |
| --- | --- |
| Invitation lifecycle | Expiry, reminders, revocation over days |
| Billing cycle | Period close → usage rollup → meter report → invoice |
| Dunning | Multi-day retry schedule with escalation |
| GDPR erasure | Multi-store orchestration under a 30-day statutory clock |
| Data export | Long-running, resumable, produces an artifact |
| Trial expiry | A timer measured in weeks |
| Email delivery | Retry with backoff, bounce handling |
| Projection rebuild | Long, resumable, needs progress visibility |
| Stripe webhook processing | Retry with visibility (ADR-016) |

Deliberately **not** workflows: request-path work, single-store operations, and
anything that must complete within one HTTP request.

### Why

The infrastructure is already running and its cost is already paid. The failure
mode this prevents is the familiar one: a `pending_jobs` table, a cron, an
at-least-once retry loop and a half-built state machine, reinvented per feature
and debuggable only through logs.

### Consequences

- Workflow determinism rules bind (no `time.Now()`, no `rand`, no I/O outside
  activities) — already in `CLAUDE.md`.
- Workflow IDs are derived from the triggering event ID, making duplicate starts
  naturally idempotent.
- Every workflow is tested with the Temporal test environment, including the
  replay test that catches non-determinism introduced by a later edit.

---

## ADR-018 — Authentication token and session model

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

**Two tokens, different jobs.**

| Token | Form | Lifetime | Revocation |
| --- | --- | --- | --- |
| Access | Signed JWT (EdDSA), audience-scoped | 10 min | TTL expiry; Valkey denylist for emergencies |
| Refresh | Opaque, 256-bit, stored hashed | 30 days sliding | Immediate, server-side |

The **session is server-side state** (Postgres projection, Valkey hot copy). The
JWT is a short-lived bearer of an existing session, never the session itself.

**Refresh tokens rotate on every use, with reuse detection.** Each session owns a
token *family*. Using a refresh token issues a new one and retires the old. If a
retired token is ever presented again, that is proof of theft: the **entire
family is revoked**, the session moves to `Compromised`, and the user is
notified.

### Why

The requirement is per-device visibility and individual revocation. Pure JWTs
cannot do that — a stateless token is valid until it expires, so "log out this
device now" is unimplementable. Pure server-side sessions solve revocation but
put a datastore lookup on every request.

The split gives both: revocation is immediate on the refresh path and bounded to
10 minutes on the access path, while the hot path stays a signature check. Ten
minutes is the deliberate, stated exposure window; anything needing instant
effect (compromise, forced logout) uses the denylist.

Rotation with reuse detection is what converts a stolen refresh token from
persistent access into a **detected incident**.

### Consequences

- The ConnectRPC `authn` interceptor verifies a JWT only — no database read on
  the hot path (ADR-007).
- Key rotation needs overlapping JWKS validity; access tokens must remain
  verifiable across a rotation.
- Centrifugo's connection token is minted from the same session, with its own
  short TTL, so realtime disconnects follow revocation.
- Clock skew tolerance is bounded and explicit; all times UTC (ADR-008).

---

## ADR-019 — Reactors are not projectors: side effects never replay

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Two kinds of event consumer, with different rules and separate checkpoints.

| | **Projector** | **Reactor** |
| --- | --- | --- |
| Produces | rows in a read model | side effects — email, push, webhook, workflow start |
| Rebuildable | **yes** — drop and replay from zero | **never** |
| Checkpoint | resettable | **append-only, never rewound** |
| Idempotency | natural (upsert by key) | **required** — dedup by event ID |
| On replay | recomputes identical state | must produce **nothing** |

A projector may be rebuilt at any time; that is the whole point of CQRS. A
reactor's checkpoint is **never rewound**, and every reactor additionally dedups
on event ID, so even an operational mistake cannot double-send.

Reactors start Temporal workflows using **the event ID as the workflow ID**, so
Temporal's own deduplication is the final backstop (ADR-017).

### Why

This is the classic event-sourcing catastrophe. Rebuilding a read model is a
routine operation — a schema change, a bug fix, a new column. If the code that
sends the welcome email lives in a projector, that routine operation emails every
user who has ever registered, along with every password-reset link and every
security alert ever generated.

It is unrecoverable: mail cannot be unsent, and the reputational and
deliverability damage is immediate. The separation must be structural, because
"remember not to rebuild that one" is not a control.

### Consequences

- Reactor and projector are **different kernel types**. A reactor cannot be
  registered with the rebuild command — it is not merely discouraged, it does not
  compile.
- Reactors are the only consumers permitted to touch `Mailer`, `Publisher`, or
  `Workflow` ports.
- A projector that needs to trigger something records **intent** in a table; a
  reactor picks it up. Intent is data and replays safely; sending is not.
- Every reactor gets a test asserting that replaying its entire input stream a
  second time produces zero side effects.
- Deploying a *new* reactor starts it at the **current** position by default,
  not zero. Backfilling is a deliberate, separately-authorised action.

---

## ADR-020 — `organization` and `workspace` are separate contexts, one-directional

**Date:** 2026-08-08 · **Status:** Accepted · **Refines ADR-003**

### Decision

Two modules, not one `tenancy` module:

- **`organization`** — the **commercial** boundary. One per customer contract.
  Owns the subscription link, the owner, org-level policy, verified domains, and
  the set of workspaces.
- **`workspace`** — the **collaboration** boundary. Many per org. Owns members,
  teams and invitations.

> **The dependency is strictly one-directional: `workspace → organization`.**
> `organization` must never import `workspace`, in any form.

A cycle between the two is the failure signal. If `organization` ever needs to
reach into `workspace`, merge them — a cycle gives you the ceremony of separation
with none of the isolation.

### Why

Their lifecycles and growth directions differ. Organization grows
*commercially* — whitelabeling, custom domains, SSO, reseller relationships,
compliance configuration. Workspace grows *collaboratively* — membership, teams,
invitations, high churn. Fused, a whitelabel-branding change would sit beside
invitation-token logic, and the module becomes the place everything lands because
everything is a little bit tenancy.

Cross-module coordination is already the norm here: workspace creation must
consult `entitlement` for quota and `access` for permission regardless. Adding
`organization` as a third does not introduce a new class of problem.

### Consequences

- **The link is data, not code**: every workspace-scoped record carries `org_id`
  as well as `workspace_id`. This is also what stops a forged `workspace_id` from
  crossing an org boundary under RLS.
- Synchronous cross-boundary questions ("may a workspace be created in this
  org?") are answered by the **enforcement pipeline** reading an org-status
  projection (ADR-021), never by module coupling.
- Multi-step cross-boundary processes (closing an org and its workspaces) are
  **Temporal sagas** (ADR-017). `organization` publishes; it never orchestrates
  workspace internals.
- **The accepted risk:** "workspace under a suspended org" becomes a runtime gate
  rather than a compile-time invariant. That gate must therefore be centrally
  applied and never per-handler — which ADR-021 enforces.
- Would be reconsidered if workspaces ever became independently billable; the
  commercial boundary would move down and the two would collapse into one.

---

## ADR-021 — One enforcement pipeline; gates are declared, never hand-written

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Four enforcement systems converge on every request. They run in **one fixed
order**, as ConnectRPC interceptors (ADR-007), and **no gate may ever be
implemented inside a handler**.

```
recovery → telemetry → request-id → authn ──► Principal + AuthContext
   │
   ├─ 1. org-context      resolve org (+ workspace) for this request
   ├─ 2. authz            access.Check — FAIL CLOSED
   ├─ 3. subscription     org lifecycle state vs operation class
   ├─ 4. entitlement      feature purchased? quota available? (reserve)
   ├─ 5. idempotency
   │
   └──► handler ──► repository ──► 6. RLS  (database backstop, always on)
```

### Order rationale

**authz precedes the subscription gate** so a non-member learns nothing about an
org — not even that its payment is overdue. Existence and billing state are both
privileged information.

**The subscription gate precedes entitlement** because a suspended org's quota is
irrelevant; checking it would leak plan details and waste a reservation.

**Entitlement reserves last**, immediately before the handler, so a reservation
is never taken for a request that a later gate would reject.

**RLS is unconditional and independent.** It re-enforces the same scope in the
database under a non-owner role, so a bug in gates 1–4 is contained rather than
catastrophic (ADR-015).

### Gates are declared in protobuf

Enforcement is **declarative**, read from RPC options by the interceptors:

```protobuf
rpc CreateWorkspace(CreateWorkspaceRequest) returns (CreateWorkspaceResponse) {
  option (chronos.authz)       = { relation: "admin", resource: "organization" };
  option (chronos.operation)   = OPERATION_GROW;      // seat/quota consuming
  option (chronos.entitlement) = "workspaces.count";
  option (chronos.min_aal)     = AAL_1;
}
```

An RPC that declares no policy **fails closed at startup**, not at request time:
the server refuses to boot with an unannotated method. Forgetting a gate is
therefore impossible rather than merely discouraged — the failure mode of a
per-handler design is that the one endpoint nobody remembered is the one that
leaks.

### Consequences

- The policy for every endpoint is readable in one place — the `.proto` — which
  is also the generated documentation (ADR-007).
- Adding a fifth enforcement concern later means one interceptor and one option,
  not an edit to every handler.
- The gates are testable independently of any domain logic, and a conformance
  test asserts every registered RPC carries a policy.

---

## ADR-022 — We own the catalogue; Stripe owns the ledger

**Date:** 2026-08-08 · **Status:** Accepted · **Refines ADR-004**

### Decision

ADR-004 said "Stripe owns money." That is now split precisely, because the two
halves flow in opposite directions:

| | Source of truth | Direction |
| --- | --- | --- |
| **Catalogue** — what we sell: plans, features, limits, prices | **our database** | we **push** to Stripe |
| **Ledger** — what happened: subscriptions, invoices, payments, disputes | **Stripe** | we **mirror** from Stripe |

Operators CRUD plans in our admin panel; a reconciler projects them into Stripe
Products and Prices, storing the returned Stripe IDs.

### Plan versioning is mandatory, because Stripe Prices are immutable

**A Stripe `Price`'s `unit_amount` cannot be changed — by design**, so that
historical transactions stay accurate. "Edit the price of a plan" is therefore
not an update; it is: create a new Price, archive the old one, and decide what
happens to existing subscribers.

So our model is:

```
Plan  (stable identity: "pro")
 └── PlanVersion  (immutable: price, currency, interval, entitlements)
        └── stripe_price_id
```

- A `PlanVersion` is **immutable** once published. Editing means publishing a new
  version.
- Existing subscribers stay on their version — **grandfathering is the default**,
  not an afterthought.
- Migrating subscribers between versions is an explicit, audited operator action
  with a proration choice, run as a Temporal workflow.
- Entitlements are attached to the **version**, so what a customer bought never
  silently changes underneath them.

### Consequences

- Our `plan_version_id` is written into Stripe `metadata`, making the mirror
  idempotent and reconcilable in both directions.
- Drift is detectable: a `price.updated` webhook we did not originate means
  someone edited in the Stripe Dashboard, which raises an incident.
- Free plans still get a $0 Stripe Price, so every customer has a subscription
  and the lifecycle has exactly one shape.

---

## ADR-023 — Use Stripe's hosted surfaces; never touch a card number

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Every payment surface is Stripe-hosted. We build none of them.

| Need | Stripe surface | We do not build |
| --- | --- | --- |
| Purchase / signup | **Checkout Session** (`mode: subscription`) | card forms, 3DS handling |
| Plan change, cancel, payment method, invoice history | **Customer Portal** | a billing settings UI |
| VAT / GST / sales tax | **Stripe Tax** | tax engines, rate tables |
| Failed-payment recovery | **Smart Retries + Stripe dunning email** | retry schedulers |
| Invoices and receipts | **Stripe hosted invoices** | PDF generation, delivery |
| Usage-based billing | **Billing Meters** | usage aggregation for invoicing |
| Fraud | **Radar** | fraud scoring |

**No card data ever reaches our infrastructure**, which keeps us at PCI SAQ-A —
the lightest scope available.

Two rules from Stripe's own guidance that are easy to violate:

- **Never pass `payment_method_types`.** Omitting it enables dynamic payment
  methods, configured from the Dashboard. Hardcoding `['card']` silently locks
  out every other method and costs conversion.
- **Use a restricted API key (`rk_`), not a secret key**, with least-privilege
  permissions and an IP allowlist. Keys live in a secrets vault, never in the
  repository.

### Why

These are solved, regulated, and unrewarding to rebuild. Every hour spent on a
card form is an hour not spent on the entitlement model, which is where our
domain knowledge actually is.

### Consequences

- Some UI control is traded away; Portal branding is configurable but not
  arbitrary. Accepted.
- The Customer Portal can change subscriptions **without our API being involved**,
  so webhooks are not an optimization — they are the *only* way we learn about a
  large class of changes. This is why ADR-016's reconciliation job is mandatory
  rather than defensive.

---

## ADR-024 — The operator plane is a separate deployable

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

The operator back-office is its own bounded context **and its own binary, port
and database role**. It is not a route group inside the tenant API.

| | Tenant plane | Operator plane |
| --- | --- | --- |
| Principal | `user` — scoped to an org | `operator` — a Chronos employee |
| Tenancy | one org per request | **cross-tenant by definition** |
| Authorization | OpenFGA relationship graph | operator roles + explicit scope |
| DB role | RLS-enforced, non-owner | separate role with audited, narrow bypass |
| Network | public | internal / VPN only |

### Why

Everything else in this architecture assumes exactly one tenant per request:
RLS policies, the enforcement pipeline, the four isolation layers of ADR-015.
The operator plane **breaks that assumption on purpose**, and it is the only
thing in the system that does.

A cross-tenant capability sharing a process with the tenant API is one routing
mistake, one middleware ordering bug, or one forgotten annotation away from
being a total data breach. Physical separation converts that class of bug from
catastrophic to impossible: an operator endpoint is not reachable from the
public surface because it is **not in the running binary**.

### Consequences

- Shared domain logic is imported; **the tenant API never imports operator
  packages**, and the operator binary is deployed and access-controlled
  separately.
- Every operator read of tenant data is an **audited event**, not just a log
  line — including reads, because under GDPR looking is processing.
- Operator access to personal data is minimised by default and elevated only
  through time-boxed break-glass with a recorded justification.
- Two binaries means two deployments and some duplicated wiring. Accepted
  without hesitation for what it prevents.

---

## ADR-025 — Entitlement is derived state that must survive a Stripe outage

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Entitlements are computed from **our own** projections — the plan version a
subscription points at, plus recorded usage. The entitlement gate **never calls
Stripe** on the request path.

The derivation chain is entirely local:

```
PlanVersion (ours)  +  subscription state (mirrored)  +  usage (ours)
                              ↓
                     entitlement snapshot  →  Valkey  →  gate 4
```

### Why

ADR-010 requires that a Stripe outage degrade billing changes only, never reads
or access. If the entitlement gate called Stripe, a Stripe incident would become
a total outage for every customer — quotas would be unevaluable, so every
gated operation would fail.

### Consequences

- Entitlement remains correct and enforceable while Stripe is unreachable; only
  *changing* a subscription is blocked.
- Webhook lag means entitlements are eventually consistent with Stripe. That is
  acceptable in the safe direction: an upgrade lands a few seconds late, and a
  downgrade never revokes access mid-request.
- Usage metering is **ours first**, reported to Stripe second — so a failed meter
  report is a reporting problem, never a loss of billing data (ADR-013).

---

## ADR-026 — Alert channel arbitration is server-decided, client-backstopped

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Separate **persistence** from **alerting**:

- The **in-app feed item is always written.** It is the durable record and is
  never arbitrated.
- The **alert** — the thing that interrupts the user — goes to exactly **one**
  of in-app realtime or web push, never both.

Arbitration is **server-side, driven by presence**, with a client-side backstop
only for the race:

```
                 ┌─ presence: a connected client with a VISIBLE tab?
                 │
        yes ─────┴─────► in-app realtime alert (Centrifugo). No push.
        no  ───────────► hold T seconds
                            ├─ in-app ack arrives  → cancel push
                            └─ timeout             → web push
```

Both channels carry the same `notification_id` as a deduplication key. Clients
keep a short-lived seen-set and drop a duplicate.

### Why server-side and not purely client-side

The obvious design is to always send push and let the service worker decide.
**Browsers do not reliably permit that.** Web Push requires
`userVisibleOnly: true`, and a service worker that receives a push without
calling `showNotification()` risks the browser displaying its own generic *"this
site was updated in the background"* message — and repeated silent pushes can
cost the origin its push permission entirely.

So "send push and suppress on arrival" is not a safe primitive. The decision to
send **must** be made before the push leaves, which makes presence a first-class
input rather than an optimisation.

### Presence is two signals, not one

A connected client is **not** the same as an attentive one — a WebSocket stays
open in a background tab for hours.

| Signal | Source |
| --- | --- |
| Connected | Centrifugo presence on the user's channel |
| **Attentive** | client heartbeat driven by the Page Visibility API |

Only *connected **and** visible* suppresses push. Connected-but-hidden is treated
as absent, which is exactly the "tab not active" case in the requirement.

### Consequences

- Centrifugo presence must be **enabled on the user namespace** — it is now
  load-bearing, not diagnostic.
- The hold window `T` (default ~15s) is a tunable trade between duplicate alerts
  and push latency. It applies only when the user appears absent, so the common
  attentive case has no added latency.
- If presence is unavailable (Centrifugo degraded, ADR-010), the fallback is
  **send the push** — a possible duplicate alert is a far better failure than a
  security notification nobody receives.
- Email is **not** part of this arbitration. Its policy is by class
  (see NOTIFICATIONS.md §3): Security and Transactional always send, regardless
  of whether the user saw an in-app alert.

---

## ADR-027 — Organization authority model

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Authority splits along one line: **many people may run the product; exactly one
person is accountable for the money.**

| | Owner | Org admin |
| --- | --- | --- |
| Count | **exactly one, always** | many |
| Workspaces and everything inherited | full | **full** |
| Org policy, domains, settings | full | full |
| Billing — **view** | ✅ | ✅ |
| Billing — **change** (plan, payment method, cancel, refund) | ✅ | ❌ |
| Transfer ownership | ✅ (initiates) | ❌ |

**Owner cardinality is invariant.** Never zero, never two; an admin never becomes
owner implicitly. The owner is transferable as a deliberate act — step-up to
AAL2, the recipient must accept, fully audited — but the role itself is singular
and permanently bound to payment responsibility.

**Org admins get billing read, never billing write.** They can see spend,
invoices and plan without being able to change what the company is committed to.

### Workspace inheritance

Owner and org admins are **default admins of every workspace** in the org —
present and future — by the topology edge `workspace.parent = organization`
(ADR-006). No fan-out, no per-workspace grant.

Inheritance **may be broken** per workspace, making it private to its own
members. Two invariants govern it:

1. **Never orphan a workspace.** Inheritance may only be broken once the
   workspace has at least one **direct** admin who does not depend on
   inheritance. Otherwise breaking it produces a workspace nobody can administer.
2. **Break-glass reclaim.** The owner can always restore org access to any
   workspace in their organization. It is audited, and workspace admins are
   notified — it is never silent.

Without (2), a departing workspace admin could permanently lock an organization
out of its own data: data loss by permission, with no recovery path that does not
involve us touching the database.

**Existence is always visible; content is not.** A broken-inheritance workspace
still appears in the org's workspace list with its name and admins, because
`organization` owns the set of workspaces as references. The owner can see that
it exists — and reclaim it — without being able to read inside it first.

### Seats

**Guest seats are counted separately from member seats.** Two independent
entitlement limits (`seats.member`, `seats.guest`), reserved independently, and
an invitation reserves against the pool matching the role being offered.

### Consequences

- The access model gains `billing_viewer` (admins) distinct from
  `billing_manager` (owner only).
- The operation-class matrix splits `billing-manage` into **`billing:view`** and
  **`billing:manage`** (organization.md §5.2).
- Breaking inheritance is a guarded command, not a raw tuple delete — the
  last-admin check lives in the domain, since `access` must stay ignorant of what
  a workspace is (ADR-006).
- Owner departure is covered by transfer rather than by an operator
  intervention, so the common case needs no support ticket.

---

## ADR-028 — Key custody: OpenBao transit, envelope encryption

**Date:** 2026-08-08 · **Status:** Accepted · **Completes ADR-002**

### Decision

**OpenBao** (LF fork of Vault, MPL-2.0) holds the KEK. Per-subject data keys are
wrapped by an OpenBao **transit** key; the KEK never leaves OpenBao, and
plaintext key material never touches Postgres or application logs.

Erasure = destroy the subject's key. Ciphertext remains, permanently unreadable.

**✅ Verified end to end** on `openbao:2.6.1`: encrypt → decrypt → destroy key →
decrypt fails with `encryption key not found`. That is ADR-002's guarantee
demonstrated rather than asserted.

Self-hosted rather than cloud KMS, consistent with the rest of the stack
(Valkey over Redis, SeaweedFS over MinIO, OpenFGA over a SaaS).

### Consequences

- **OpenBao becomes a second unrebuildable store** (ADR-033). Losing the keyring
  destroys every encrypted record irrecoverably — worse than losing Postgres,
  which replays.
- Local dev runs `-dev`: in-memory, auto-unsealed, fixed token. **Production runs
  sealed** with persistent storage and a real unseal procedure; a dev-mode
  OpenBao in production voids the entire guarantee, so config validation refuses
  to start with a dev token outside `local` (ADR-008).
- Erasure and decryption depend on OpenBao availability. It joins the critical
  set in ADR-010: unreachable ⇒ PII reads fail, but non-PII reads continue.

---

## ADR-029 — Event schema evolution by upcasting on read

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Events are persisted **exactly as written, forever**. A versioned **upcaster
chain** transforms older payloads into the current shape at read time, so domain
code only ever sees the latest version of an event.

```
stored v1 ──upcast──► v2 ──upcast──► v3 ──► domain handler (knows only v3)
```

- Every event carries `type` and `schema_version` in its envelope.
- An upcaster is a pure function `(vN) → (vN+1)`, registered per event type.
- **Chains are tested against real historical payloads**, captured as golden
  fixtures when each version is retired.

### Why

The log is immutable and permanent, so this is the one decision that cannot be
refactored later. Versioned types side by side (`MemberInvitedV1`, `V2`) push
history into every handler, and the domain accumulates branches forever.
Tolerant-reader-only forbids renames and type changes outright, leaving no
escape hatch the first time one is genuinely needed.

Upcasting keeps history byte-accurate *and* keeps the domain ignorant of it.

### Consequences

- Rewriting stored events is **forbidden**, including "harmless" backfills.
- An upcaster is written in the same commit as the schema change; a new
  `schema_version` with no upcaster fails the build.
- Replay cost grows slowly with chain length; collapse chains only by rewriting
  a *snapshot*, never the log.

---

## ADR-030 — Public IDs are prefixed and opaque

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

ULID internally; exposed publicly with a **type prefix**:

```
org_01H8XG5N2QK7VB3C9WPYZR4TFM
ws_01H8XG7B4M2E8NDKQ5RJTV6WYA
usr_ · team_ · inv_ · key_ · sub_ · plan_ · notif_
```

- The prefix is part of the public API contract and never changes.
- Parsing validates the prefix, so passing a workspace ID where an org ID is
  expected is a **validation error at the boundary**, not a mysterious
  not-found three layers in.
- Typed Go IDs stay distinct at compile time (`OrgID` ≠ `WorkspaceID`).

### Consequences

- IDs are self-describing in logs, traces, support tickets and URLs.
- Prefixes are greppable, which makes secret-scanning and log redaction rules
  simpler.
- ULIDs are time-ordered, so an ID leaks approximate creation time. Acceptable
  for tenant-scoped resources; anything where that matters gets a random ID
  instead.

---

## ADR-031 — Tests run against the shared stack, isolated per suite

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Three tiers:

| Tier | Infrastructure | Speed |
| --- | --- | --- |
| **Domain** | none — pure functions over in-memory state | milliseconds |
| **Use case** | in-memory fakes of ports | milliseconds |
| **Adapter / integration** | **the running compose stack** | seconds |

Integration tests isolate by **creating their own namespace, not their own
containers**: a fresh Postgres schema, a fresh OpenFGA store, a KurrentDB stream
prefix, and a Valkey key prefix — all per suite, torn down after.

Not testcontainers: KurrentDB and Temporal are heavy to boot, and per-package
containers would dominate the test run. The compose stack is already verified
and already running.

### Consequences

- CI starts the stack once, then runs everything against it.
- Suites must be **parallel-safe by construction**, since they share a server.
  Namespacing is what makes that true.
- `testing/synctest` (Go 1.26) for concurrent logic — deterministic, virtual
  time, no sleeps.
- The fakes must be kept honest: every port fake has a **contract test** run
  against both the fake and the real adapter, asserting identical behaviour.
  Without that, fakes drift and green tests stop meaning anything.

---

## ADR-032 — KurrentDB scavenging is scheduled, not licensed

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

A Temporal workflow triggers KurrentDB's scavenge API on a schedule, with
metrics on duration, reclaimed bytes and failures, and alerting when a run is
skipped or overruns.

### Why

**AutoScavenge is licence-gated** — verified in the startup log:
`AutoScavenge is not licensed, stopping.` Without intervention the log grows
without bound. Deferring is the trap: scavenging first matters exactly when the
database is large, which is when the operation is slowest and riskiest.

### Consequences

- Scavenge runs are visible in the Temporal UI like every other durable process.
- Scavenging is I/O-heavy; the schedule targets low-traffic windows and the
  workflow refuses to start a second concurrent run.
- Revisit if the enterprise licence is bought for other reasons.

---

## ADR-033 — Two stores cannot be rebuilt; they get their own DR posture

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Everything in this architecture replays from the event log — **except two
stores**, which are therefore backed up, escrowed and restore-tested differently
from everything else:

| Store | Why it cannot be rebuilt | Loss means |
| --- | --- | --- |
| **PII vault** | mutable by law; erasure hard-deletes (ADR-002) | personal data unrecoverable |
| **OpenBao keyring** | the KEK wraps every data key (ADR-028) | **every encrypted record unreadable, permanently** |

The keyring is the more severe of the two: losing it is worse than losing
Postgres, because Postgres replays and ciphertext without a key does not.

Designed now, implemented alongside `compliance`:

- Keyring **escrow** with split custody, stored separately from its backups.
- **Restore drills are scheduled and their success recorded.** An untested
  backup of a KEK is indistinguishable from no backup.
- Backup of the event log (the source of truth) and of the two special stores are
  separate procedures with separate RPOs.
- Restore order is documented: keyring → PII vault → event log → rebuild
  projections.

---

## ADR-034 — Deploy target: Docker Compose on VMs

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

Production runs the same Compose topology on real hosts. The compose file stays
the source of truth; environments differ by `.env` and overlay files, never by a
separate orchestration description.

**OpenBao runs sealed** in production with persistent storage and a documented
unseal procedure — the one place production genuinely differs from local.

### The secret split (review A5)

| Held in | What | Why |
| --- | --- | --- |
| **OpenBao** | everything **rotatable**: KEK, Stripe restricted key + webhook secrets, Centrifugo HMAC + API key, OpenFGA pre-shared key, VAPID private key, argon2 pepper | rotation without a redeploy, and an audit trail of access |
| **Host environment** | only what is needed to *reach* OpenBao: address, role id, secret id | the irreducible bootstrap |

Nothing rotatable lives in the environment, so rotating a secret never means
editing a `.env` on a host.

Postgres credentials use OpenBao's **dynamic database credentials** where
practical, so the long-lived password disappears entirely.

### Valkey is split before production (review A4)

Two instances, not one: the **Centrifugo backplane** and the **application store**
(sessions, rate limits, caches). They have different failure tolerances — flushing
the backplane during an incident is routine, and doing it to the application
store must never be casually available. Keys are namespaced by purpose from day
one so the split is a config change.

### Consequences

- Least new machinery, and what was verified locally is what ships.
- Rolling deploys and scaling are manual. Accepted at this stage.
- Nothing may depend on a platform SDK, so a later move to Kubernetes is a
  deployment change rather than an application change.
- A live Stripe key, a dev OpenBao token, or `tls=false` outside `local` all fail
  startup (ADR-008, ADR-014, ADR-028).

---

## ADR-035 — Single region now, residency tagged from day one

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

One region. But **every organization carries a `residency` attribute from the
first migration**, and no code assumes a global namespace.

### Why

Adding residency later touches tenant routing, every projection, object-storage
layout and key custody — realistically a re-platform. Carrying an unused column
and a routing seam costs almost nothing now and converts that re-platform into a
deployment problem.

### Consequences

- `residency` is on the organization aggregate and every tenant-scoped
  projection.
- Object keys and OpenBao paths are namespaced by region even with one region.
- Cross-region queries are not merely unimplemented — they are **structurally
  absent**, so nothing accidentally depends on being able to make one.

---

## ADR-036 — Error disclosure follows the gate ladder

**Date:** 2026-08-08 · **Status:** Accepted · **Resolves the conflict between ADR-015 and entitlement.md**

### The conflict

Two earlier rules appear to contradict each other:

- **ADR-015**: forbidden and not-found must be indistinguishable, or IDs can be
  probed for existence.
- **entitlement.md**: a generic 403 is a product bug — "ask an admin" and
  "upgrade your plan" are completely different journeys and must be
  distinguishable.

Both are correct. They apply at different points.

### Decision

> **A caller may be told exactly as much as the last gate they passed entitles
> them to know.**

The gate ladder is ADR-021's pipeline, and each rung discloses more than the one
below it:

| Failed at | Response | Discloses |
| --- | --- | --- |
| authn | `UNAUTHENTICATED` | nothing |
| org-context | `NOT_FOUND` | nothing — identical whether the org exists or not |
| **authz** | **`NOT_FOUND` or `ACCESS_DENIED`** | **the disclosure boundary** — see below |
| subscription | `ORG_SUSPENDED` | payment state (caller is already a member) |
| entitlement | `PLAN_UPGRADE_REQUIRED` · `QUOTA_EXCEEDED` | plan detail (likewise) |
| handler | domain reason | full detail |

**The authz gate is the boundary.** Below it, every failure is
indistinguishable. At or above it, the caller has already proven they belong, so
specificity is safe *and* required.

### The rule at the authz gate

On an authorization failure, one additional check decides which error is
returned:

```
authz denies (principal, relation, resource):

    can the principal see the resource's PARENT?
        yes → ACCESS_DENIED     they already know it exists; tell the truth
        no  → NOT_FOUND         they must not learn it exists
```

This is mechanical, not a judgment call, and it reuses machinery that already
exists — the parent edge is the topology from ADR-006. Each registered resource
type declares a **minimum-visibility relation** alongside its role catalogue,
which is what the parent check asks for.

For a top-level resource (an organization) there is no parent, so the rule
degrades correctly to: no relationship to the org at all ⇒ `NOT_FOUND`.

A resource that genuinely does not exist also returns `NOT_FOUND`, so all three
cases — absent, invisible, and forbidden-but-invisible — are one response.

### Consequences

- **This lives in the interceptor, never in a handler** (ADR-021). The
  interceptor already knows the relation and resource from the RPC's declared
  policy, so it can run the parent check with no per-endpoint code. Handlers
  cannot get it wrong because they are not consulted.
- The extra check costs one `Check` **on the denial path only**; success paths
  are unaffected, and denials are rare.
- Both `NOT_FOUND` branches must perform the same lookups, so response timing
  does not reintroduce the oracle the rule exists to close.
- Cross-tenant probing stays impossible; in-tenant errors stay actionable.

---

## ADR-037 — Adapters use gRPC wherever the dependency offers it

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

If a dependency exposes gRPC, the adapter uses gRPC. HTTP is a fallback for
dependencies that have no gRPC surface, never a convenience choice.

| Dependency | Transport | Client |
| --- | --- | --- |
| **KurrentDB** | **gRPC** `:2113` | official Go client (gRPC-native) |
| **Temporal** | **gRPC** `:7233` | official SDK (gRPC-native) |
| **OpenFGA** | **gRPC** `:8081` | **generated from `buf.build/openfga/api`** — see cost below |
| **Centrifugo** | **gRPC** `:10000` | generated; metadata `authorization: apikey <KEY>` |
| **SeaweedFS** filer / master | **gRPC** `:18888` / `:19333` | generated, for metadata operations |
| SeaweedFS object bytes | S3 REST `:8333` | `aws-sdk-go-v2` — the S3 API is REST by definition |
| OpenBao | HTTP `:8200` | no gRPC surface exists |
| PostgreSQL | pgx wire | — |
| Valkey | RESP | — |
| SMTP relay | SMTP | — |
| Stripe | HTTPS REST | official SDK; hosted surfaces (ADR-023) |

### Why

Beyond binary framing and multiplexing, the decisive point is that several of
these HTTP endpoints are **already a gRPC gateway in front of the gRPC service** —
OpenFGA's explicitly is. Using HTTP therefore pays for a protocol translation on
every authorization check, on the hottest path in the system (access.md §1.5
measures it at ~2 ms; the hop is not free at that scale).

gRPC also gives properly propagated deadlines and cancellation, typed clients
generated from the vendor's own schema rather than hand-modelled JSON, and
`grpc.health.v1` probes that feed the dependency registry (ADR-010) instead of
bespoke health parsing per vendor.

### The cost, stated plainly

**OpenFGA's official Go SDK (`openfga/go-sdk`) is HTTP-only.** Using gRPC means
generating a client from `buf.build/openfga/api` — one extra `buf` dependency and
a generation step. We already run `buf` for our own schema (ADR-007), so this is
a line of config rather than new machinery, but it is real work and it means we
own the generated client rather than consuming a supported SDK.

Accepted because authorization is on every request and fails closed: a
translation hop there is the least attractive place in the system to spend
latency.

### Rules for every gRPC adapter

- **One long-lived `grpc.ClientConn` per dependency, shared.** `ClientConn` is
  safe for concurrent use; creating one per request defeats multiplexing and
  exhausts sockets.
- Every call carries a **context deadline**. No unbounded calls, ever.
- **Keepalive is configured**, so a half-open connection is detected rather than
  hanging until the OS notices.
- `otelgrpc` interceptors on the client, so adapter calls appear as child spans
  (CONVENTIONS §11).
- Auth travels as **per-RPC metadata**, from OpenBao (ADR-034) — never a
  hardcoded header.
- Health is `grpc.health.v1` where the dependency implements it; the adapter
  registers that probe with the dependency registry (ADR-010).
- Connections are **lazy and self-healing**: construction never fails at boot,
  matching ADR-010's "the server never crashes on dependency loss".

---

## ADR-038 — Performance and concurrency rules

**Date:** 2026-08-08 · **Status:** Accepted

### Decision

**Allocation, concurrency safety and parallelism are first-order design
constraints, and they are measured rather than asserted.**

#### Zero allocation — scoped to where it means something

The rule is *zero allocation on hot paths*, not zero allocation everywhere.
A hot path is anything on the per-request or per-event path: identifier
parsing and rendering, error classification, authorization decisions, event
deserialization, projector inner loops.

Config loading, startup wiring and admin operations run once; making them
allocation-free would produce worse code — pools and `unsafe` in places that
gain nothing — which contradicts the requirement to write *good* Go.

**Enforcement, not intention:**

- Every hot-path package carries **benchmarks with `-benchmem`**.
- Budgets are asserted with `testing.AllocsPerRun` in a normal test, so a
  regression **fails the build** rather than being noticed in a benchmark diff
  nobody reads.
- Hot types expose an `AppendTo([]byte) []byte` form so callers already holding
  a buffer can render with **zero** allocations. `String()` exists for
  convenience and costs exactly one.

**Benchmarks must defeat escape analysis.** Assigning to `_` lets the compiler
prove a value never escapes and stack-allocate it, measuring a program nobody
runs. Results go to a package-level sink. This is not pedantry — it produced a
40% error in our own first measurement.

Measured on the current kernel:

| Operation | ns/op | allocs |
| --- | --- | --- |
| `ids.Parse` | 35.4 | **0** |
| `ids.AppendTo` | 15.5 | **0** |
| `ids.String` | 30.6 | 1 (the string) |
| `errs.ReasonOf` | 2.7 | **0** |
| `errs` constructor, no args | 20.7 | 1 (the error) |

`ReasonOf` went from 54.3 ns / 1 alloc to 2.7 ns / 0 by asserting the concrete
type before falling back to `errors.As`, which walks the chain reflectively.

#### Concurrency safety and parallelism

- **`-race` on every test run**, in `make test` and CI. Not an occasional check.
- Concurrent logic is tested with **`testing/synctest`** (stable in Go 1.25,
  experiment removed in 1.26): virtual time, deterministic scheduling, no
  sleeps.
- **`goroutineleak` profiling** (new in Go 1.26) in CI, because this design has
  many long-lived subscriptions and a leaked projector goroutine is invisible
  until it isn't.
- Work that can be parallel **is** parallel: probes, `BatchCheck` fan-out,
  independent projectors. Each is bounded — an unbounded `go` per item is a
  denial-of-service you wrote yourself.
- Shared state is either immutable, owned by one goroutine, or explicitly
  guarded. "Probably fine" is not a synchronisation strategy.

#### Generics

Use them where they remove duplication or add compile-time safety, not for
their own sake. `ID[K Kind]` makes `OrgID` and `WorkspaceID` distinct types the
compiler enforces, from one implementation. The same applies to `Aggregate[ID,E]`,
`Projector[S]` and `Page[T]`.

A generic function that is instantiated once is worse than a concrete one.

### Consequences

- New hot-path code arrives with a benchmark and a budget test, or it is not
  finished.
- Some APIs carry both `AppendTo` and `String`. That is deliberate: the fast
  path exists and the convenient path is honest about its cost.
- Budgets are ratchets. Raising one is a reviewed decision with a reason, not a
  quiet edit.
