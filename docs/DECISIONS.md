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

- **Goose** owns schema: versioned migrations, applied by `cmd/migrate` with the
  SQL **embedded in the binary**. See the amendment below.
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

### Amendment (2026-08-08): Goose replaces Atlas

Atlas was chosen for **declarative** schema management — write the desired
schema, let it plan the diff. That turned out to be unusable here: Atlas
Community refuses three things we depend on, each behind `atlas login`:

| Needed | Atlas Community |
| --- | --- |
| `CREATE ROLE` / `GRANT` | ✗ *"available to logged-in users only"* |
| **RLS policies** | ✗ *"available to logged-in users only"* |
| `migrate lint` (destructive-change detection) | ✗ *"available to logged-in users only"* |

RLS is the backbone of tenant isolation (ADR-015), so keeping policies outside
the migration system was never an option. Atlas therefore degraded to "applies
versioned SQL files" — which Goose also does, plus two things we will use:

- **Migrations embed in the binary** (`embed.FS`). `cmd/migrate` is
  self-contained and cannot drift from a mounted directory — the same property
  `cmd/apidocs` has for documentation, and it matters for Compose-on-VMs
  (ADR-034). *Verified: the binary applies migrations when run from an empty
  directory.*
- **Go migrations** for backfills needing real logic — re-wrapping keys or
  populating blind indexes for crypto-shredding (ADR-002) is not expressible in
  SQL.

It is also consistent with every other choice here — OpenBao over Vault, Valkey
over Redis, SeaweedFS over MinIO — all made to avoid exactly this kind of
feature gating.

**What we gave up, and the replacement.** Atlas checksums migration files and
detects tampering; Goose records applied versions but does not hash contents, so
an edit to an already-applied migration is invisible — the file says one thing,
the database contains another, and a fresh environment silently diverges from
production.

Replaced by `scripts/check_migrations.sh`, run in `make check`: migrations are
**append-only** relative to the base branch. A file may be added; modifying,
renaming or deleting one fails the build. *Verified: an edit to an applied
migration is rejected.*

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

### Implementation notes — verified 2026-08-08

Built as `internal/platform/projection` and proved end-to-end against the running
KurrentDB and PostgreSQL in `internal/adapter/projectionit`.

- **Atomicity is the load-bearing property.** `Runner.handle` applies the event
  and saves the checkpoint in ONE `InSystemTx`. Rows without a checkpoint means
  the event is reapplied — harmless, because Apply is idempotent. A checkpoint
  without rows means the event is lost forever and nothing ever notices. One
  transaction removes the second case; the unit tests assert that the apply and
  the save carry the same transaction identifier.
- **Single writer via Postgres advisory lock**, not a lease row. The lock is
  bound to the connection, so a crashed or partitioned holder loses it when the
  server drops the connection — no heartbeat, no clock agreement, no fencing
  token, and no window in which two holders both believe they are the writer.
  The key is FNV-1a of the projection name: it must be identical across
  processes, which Go's per-process-seeded map hash is not.
- **Reset uses `TRUNCATE`, not `DELETE`.** A rebuild empties the table from an
  *unscoped* system transaction, which under RLS can see no rows and would
  therefore delete none — leaving a "rebuilt" projection still holding its old
  contents, with a checkpoint at zero. `TRUNCATE` is a table-level operation and
  is not filtered by row security. Every read-model table must therefore grant
  `TRUNCATE` to the application role.
- **Scope per event, not per run.** A system transaction sees nothing until it
  scopes itself; the runner applies the event's own `orgId`/`workspaceId` before
  calling Apply, so projected rows are written *under* policy rather than around
  it. Events with no org stay unscoped and may only touch tables without RLS.
- **Typed dispatch.** `projection.On[T]` derives the stored event type and the
  constructor from the type parameter, so the string literal and the type
  assertion that used to sit in every projector's `switch` are both gone. A
  duplicate registration panics at wiring time.
- **Subscription tuning.** Filtered `$all` subscriptions run with
  `MaxSearchWindow=4096` and `CheckpointInterval=8` rather than the SDK defaults
  of 32 and 1: at 32, a projection interested in one module pays a round trip for
  every 32 events in the entire system.
- The rebuild proof is the strong one: after `Rebuild`, the projected rows are
  compared field by field against the rows produced by the original catch-up run
  and must be identical.

### Measured, 2026-08-08 (Apple M3 Pro, Docker Desktop, `make bench-integration`)

Kernel hot paths, in memory:

| | ns/op | allocs |
| --- | --- | --- |
| `Dispatch.Apply` — no handler (the common case) | 13.4 | **0** |
| `Dispatch.Apply` — handler + JSON decode | 262 | 1 |
| `Envelope.Tenant()` | 8.3 | **0** |
| `After` / `IsBeginning` | 0.6 | **0** |

Our own code is not a factor: ~1 µs of CPU per event against a round trip
measured at 47 µs natively. Everything below is round trips and commits.

**Where the time went, before.** One event cost five round trips — BEGIN,
`set_config`, the projection's write, the checkpoint upsert, COMMIT:

| | µs/event | events/sec |
| --- | --- | --- |
| From the macOS host (Docker Desktop) | 808 | 1,238 |
| Natively, inside the container (`pgbench`, same SQL, `chronos_app`) | 299 | 3,342 |

The gap is the Docker Desktop VM boundary: a round trip costs 160 µs from the
host and 47 µs natively. **Roughly 63% of the local number is a development
environment artifact**, not something production pays.

**Two changes, both measured.**

1. *Pipeline the statements* (`db.BatchTX`). Every statement for one event goes
   in a single packet with one trailing Sync, which PostgreSQL runs as one
   implicit transaction. Five round trips become one, and there is no BEGIN or
   COMMIT to pay for.
2. *Commit asynchronously* (`db.Replayable`, `synchronous_commit = off`). Safe
   here for a specific reason: a projection is derived (ADR-013), and its rows
   and checkpoint are written in the SAME batch, so a crash loses them together.
   The projection stays self-consistent and simply reapplies those events. Not
   permitted for the PII vault or anything else with nothing to replay from.

Async commit is worth nothing on its own — 299 µs → 319 µs — because
round-trip latency was hiding the WAL flush. It only pays once pipelined:

| Native, per event | µs | events/sec |
| --- | --- | --- |
| 5 round trips, durable (the original) | 299 | 3,342 |
| 5 round trips, async commit | 319 | 3,138 |
| Pipelined, durable | 201 | 4,966 |
| **Pipelined + async commit (shipped)** | **139** | **7,219** |

Confirmed through the real Go path, from the host: **808 µs → 215 µs, 3.6×**,
which is 1.3 round trips — essentially the floor. Durable commit for comparison
costs 267 µs.

**Atomicity is preserved, and that was tested rather than assumed.** The first
version of the test passed for the wrong reason: a bad column name fails while
the batch is being *prepared*, before any statement executes, which proves
nothing about rollback. The test now forces a CHECK-constraint violation — well
formed SQL that fails only at execution — and asserts the earlier INSERT did not
survive.

**A design consequence worth having anyway.** `Projection.Apply` receives a
`db.Writer`, which can only queue statements — it cannot read. That is what
makes one round trip possible, but it is also the more correct interface: a
projector that reads its own tables and branches on what it finds is not
replay-safe, because the same event applied to a different starting state gives
a different answer, which is exactly what a rebuild must never do.
Read-modify-write belongs in SQL (`UPDATE ... SET n = n + 1`,
`INSERT ... SELECT`), where the database evaluates it atomically.

**What is deliberately not done:** batching multiple *events* into one
transaction. It would be faster still and would trade a structural guarantee for
one that depends on every projection staying disciplined. At ~7,200 events/sec
per projection, with projections running concurrently, there is no evidence it
is needed.

### Reactors, implemented — 2026-08-09

`internal/platform/reactor` plus persistent subscriptions in the KurrentDB
adapter. The transport differences are what make the rules structural:

- The package exposes **no Rebuild and no Reset**, and a test asserts it never
  grows one. Replaying a reactor re-sends every effect in history.
- New groups start at the **END** of the log (`StartFrom: End`), so deploying a
  notification handler does not email everyone who ever registered.
- `EnsureGroup` is idempotent and never reconfigures an existing group. Silently
  changing redelivery behaviour as a side effect of a deploy is its own outage.
- Handler outcome maps to the transport: `nil` → Ack, an error → Nack(Retry)
  with the server parking after `MaxRetryCount`, and `ErrPoison` → Nack(Park)
  immediately for events that can never succeed.
- Order within `handle` is the OPPOSITE of a projector's: the effect happens
  first and is recorded second. Recording first means a crash before the effect
  leaves it permanently unsent, and an unsent password reset is worse than a
  duplicated one. The residue — effect done, record lost — is a duplicate, which
  `React` is required to tolerate anyway.
- `reactor_processed` (migration 00003) filters at-least-once redelivery. It is
  a filter, not a guarantee; Temporal workflow IDs keyed by event ID are the
  backstop under it (ADR-017).

### ⚠️ Enabling system projections quadruples delivery if links are resolved

Found while integration-testing reactors, and worth stating plainly because
nothing about it is obvious.

With `RUN_PROJECTIONS=System`, `$all` carries not only domain events but the
**link events** that `$streams`, `$et-` and `$ce-` write. Setting
`ResolveLinkTos` on a `$all` subscription resolves each of those links back to
the SAME original event, and because the server filter matches on the *resolved*
stream name, all four copies pass the filter.

Measured: three appended events produced **twelve deliveries**, every one with
`retryCount = 0` — so nothing looks like a retry, and a reactor sends four
emails per event.

**Rule: `ResolveLinkTos` belongs on reads of link streams (`$ce-`, `$et-`) and
nowhere else.** It is off on `$all` catch-up subscriptions and off on persistent
subscriptions; it is on, and required, in `ReadCategory`. An integration test
asserts exactly-once delivery to pin this.

### Rebuild reads category streams — 2026-08-09

`Runner.Rebuild` replays `$ce-<category>` instead of scanning `$all`, when the
projection's filter resolves to exactly **one** category. Measured at **14.8x**
(253 ms → 17 ms for 1,000 events in a 20,000-event log).

Two or more categories fall back to `$all`, deliberately: reading them in
sequence would apply every event of the first before any of the second, losing
global order, and a projection joining across aggregate types would rebuild into
a different state than it holds live. Merging category streams by commit
position would fix it and is not worth the complexity until something needs it.

The category read is an optimisation with a fallback at every step — no
`$by_category`, a lagging projection, a read error — all log and fall through to
`$all`, which is always correct.

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

---

## ADR-039 — Aggregates snapshot themselves; a bad snapshot degrades to slow

**Date:** 2026-08-09 · **Status:** Accepted · **Refines ADR-001, ADR-029**

### Decision

An aggregate may implement `Snapshotter` — `Snapshot() Event` and
`Restore(Event) error`. The repository then loads from the latest snapshot and
replays only what came after it, and writes a new snapshot every
`SnapshotEvery` (100) events.

**A snapshot is an ordinary domain Event**, not a second serialization path. It
is a plain struct registered with the codec like any other event, so the domain
keeps no wire tags (ADR-001) and the upcaster chain applies unchanged (ADR-029).

Snapshots live in their own stream — `<category>Snapshot-<key>` — carrying
`$maxCount = 1` so the server scavenges superseded ones. The suffix has no dash,
so `organizationSnapshot-org_1` is its own category and is NOT matched by a
projector filtering `organization-`.

### Why

`Repository.Load` replayed the entire stream on every command. Measured:

| Aggregate | Replay | Snapshot | |
| --- | --- | --- | --- |
| 1,000 events | 13.2 ms · 2.1 MB · 39k allocs | **2.1 ms** · 92 KB · 1.3k allocs | **6.3x** |
| 5,000 events | 59.3 ms · 12.6 MB · 196k allocs | **3.6 ms** · 942 KB · 5.3k allocs | **16.5x** |

Replay grows linearly and snapshot load stays flat. At 50,000 events replay
costs roughly 590 ms **per command** and allocates over 100 MB — a long-lived
organization would get slower forever.

### The safety rule

**Degrading to slow is always allowed; degrading to wrong never is.** Every
failure path falls back to a full replay:

- no snapshot stream, or no snapshot in it;
- a snapshot whose event type is no longer registered;
- a payload that will not decode;
- an aggregate whose `Restore` rejects it — the correct response to a schema
  change is to reject the old snapshot;
- a snapshot describing a stream that does not exist.

Failures are surfaced through `OnSnapshotError` rather than returned, because a
snapshot must never fail a command: writing one happens AFTER the append, so the
events are already durable and the only consequence is a slower next load.

### Consequences

- Aggregates that do not implement `Snapshotter` are unaffected; a repository
  configured with snapshots is inert for them.
- `Snapshot()` must return COMPLETE state. Anything omitted is silently lost for
  every load that starts from that snapshot.
- Verified by 60 randomised trials comparing snapshot-load against full replay —
  state and version — mutation-tested against an off-by-one in the resume
  revision and a missing reposition, both of which the test catches.

---

## ADR-040 — Streams carry server-side retention

**Date:** 2026-08-09 · **Status:** Accepted

### Decision

`StreamAdmin` exposes `$maxCount`, `$maxAge` and `$truncateBefore` per stream,
and `Deleter` exposes soft delete and tombstone.

### Why

Without retention every stream grows forever. Session streams, audit trails and
snapshot streams all need bounding, and the enforcement belongs in the server:
it needs no coordination, cannot fall behind, and keeps working when every
application instance is down. A cleanup job in Go would have none of those
properties.

`$truncateBefore` is also the mechanism for erasure that must remove events
rather than re-encrypt them — the fallback when destroying a key is not enough
(ADR-002). `Tombstone` is permanent and burns the stream name forever, so it is
reserved for exactly that case.

### Consequences

- Snapshot streams set `$maxCount = 1` on their first write.
- Retention on a stream with no policy reads back as the zero value, not an
  error.

---

## ADR-041 — The PII vault caches keys in-process; Valkey carries only the invalidation

**Date:** 2026-08-10 · **Status:** Accepted

### Context

Resolving one subject costs three round trips: read the wrapped data key from
PostgreSQL, unwrap it at OpenBao, read the sealed values. Every tenant-facing
notification pays all three, and a fan-out pays them per recipient.

The obvious fix — cache the resolved profile in Valkey — is not available to us.
A profile is personal data, and no projection may contain a personal-data column
(compliance.md §1). A cache is a projection with a shorter life, and putting
names and addresses in Valkey would also make erasure a cache-eviction problem
layered on top of a key-destruction one.

The other obvious fix — cache the unwrapped DEK — collides with the guarantee
ADR-002 rests on. A key cached indefinitely in a process is a key that survives
its own destruction, and erasure is a lie for as long as it does.

### Decision

The vault caches the **unwrapped data key**, in the process, bounded by a TTL and
a capacity. Valkey stores no key material and no personal data. What travels over
Valkey is the invalidation message: a `SubjectID`, which is a pseudonym and
already appears in events, logs and projections.

1. **Cache the key, not the profile.** Collapses two of the three round trips and
   leaves every byte of personal data sealed in PostgreSQL. The saving is
   structural rather than disciplinary: there is no code path that could place
   personal data in the cache.
2. **In-process only.** An unwrapped DEK is the plaintext of the thing OpenBao
   exists to protect. Valkey is Degradable, unauthenticated in development, and
   its contents are disposable by contract.
3. **An invalidation bus is mandatory, not an optimisation.** `NewKeyCache`
   refuses to build without one rather than degrading to TTL-only, because a
   TTL-only key cache is silently incorrect as soon as a second replica exists.
4. **Tombstones are sticky.** Erasure is terminal, so a cached "erased" can never
   become wrong. Stickiness also closes the write-back race: a reader that
   fetched the wrapped key before an erasure cannot cache it afterwards.
5. **A dropped subscription purges.** A subscriber that missed messages cannot
   learn which, so every key it holds becomes suspect at once.
6. **Expiry zeroes, it does not merely hide.** A sweep runs on a ticker; lazy
   expiry alone would leave destroyed key material resident until somebody
   happened to ask for that subject again.
7. **The TTL is capped at five minutes and validated at startup.** It is the
   window in which an erased subject's key can still decrypt their data in a
   replica that never received the invalidation. Nothing at runtime reveals a
   value set too high — no error, no log line, only a guarantee quietly weakened.

### Consequences

- Erasure now has a failure mode that must not be swallowed. `Erase` returns an
  error when the invalidation cannot be published even though the durable
  erasure succeeded. The operation is idempotent, so retrying is cheap; leaving
  another replica holding a destroyed key is not.
- The composition root gains two duties it cannot skip: running `Watch` and
  running the sweep. A cache handed to the vault with nobody running `Watch`
  holds keys no erasure can reach, so `cmd/worker` asserts both in a test.
- Losing Valkey degrades to the pre-cache behaviour — every resolve unwraps at
  OpenBao — which is slower and still correct.
- `internal/platform/cache` also provides a shared, TTL-enforcing `Cache` and a
  typed `Store` for everything that is genuinely disposable: sessions, rate
  limits, page caches. Those may use Valkey freely. The rule they inherit is that
  there is no `Set` without a TTL.

### Rejected

- **Caching the resolved profile in Valkey.** Fastest, and forbidden: personal
  data in a shared cache.
- **Caching the wrapped DEK in Valkey.** Ciphertext, so disclosure is bounded —
  but it moves key material from a store protected by database authentication to
  one that is unauthenticated in development, and saves only the PostgreSQL read.
- **TTL-only, no bus.** Works in development, wrong in production, with no signal
  in between.
- **Valkey client-side caching (RESP3 tracking).** A second coherence mechanism
  underneath a security-critical one; its invalidation semantics are Valkey's,
  not ours.

---

## ADR-042 — A filtered projection advances on the server's checkpoint

**Date:** 2026-08-10 · **Status:** Accepted

### Context

A projector's position advanced only when it APPLIED an event. For a projection
whose filter matches everything that matters to it, that is fine. For a
projection filtered to one module — which is every projection in this codebase —
it means the position stands still while the rest of the system writes.

The consequence is paid on every ordinary restart, not on a deliberate act: the
server re-scans the whole log since the last MATCH to find nothing. It grows with
the log and never stops growing.

Measured against the running server with 50k intervening unmatched events:

| Resume from | Time to reach live |
| --- | --- |
| the last matched event (previous behaviour) | 866 ms |
| the server's checkpoint (current behaviour) | 3 ms |

A filtered `$all` subscription already emits `CheckPointReached` for spans it
scanned and found no match in. The code received it and called `continue`, with a
comment arguing the checkpoint should always name an event that was projected.

### Decision

Honour it. `SubscribeOptions` gains `OnCheckpoint`, and the projector persists
the position with `EventsProcessed` unchanged — nothing was projected, so nothing
is counted.

Three properties make it safe, and each is asserted by a test that fails when the
property is removed:

1. **The server guarantees no matching event lies in the skipped span.** Resuming
   at the checkpoint therefore skips no work this projection would have done.
2. **The position never regresses.** A checkpoint can trail the last applied
   event; rewinding would replay events already processed. Apply is idempotent so
   that is not corruption, but it is silent repeated work that looks exactly like
   the problem being fixed.
3. **A failed write stops the subscription.** A checkpoint that silently fails to
   persist reproduces the original behaviour with no signal at all.

### Consequences

- The checkpoint row no longer always names an event that was projected. It names
  a RESUME POINT, which is what it was always for. `EventsProcessed` remains the
  count of applied events and is the number to reason about when asking what a
  projection has done.
- A checkpoint write is its own system transaction, because by definition there
  are no rows to batch it with. At the default settings — `MaxSearchWindow=4096`,
  `CheckpointInterval=8` — that is one small write per ~32k scanned events.

---

## ADR-043 — A push endpoint is unique per organization

**Date:** 2026-08-10 · **Status:** Accepted

### Context

`push_subscription` made `endpoint` globally unique, so that a browser
re-subscribing collapsed onto one row instead of receiving every notification
twice. That reasoning is sound and still holds.

What it missed is that a person belongs to several organizations (workspace.md
§2) and their browser produces ONE endpoint across all of them. The upsert
conflicted on the endpoint alone, `ON CONFLICT DO UPDATE` has to read the
conflicting row, and RLS hid that row because it belonged to the other
organization:

```
ERROR: new row violates row-level security policy (USING expression)
       for table "push_subscription"
```

Not a duplicate and not a warning. The second organization's subscribe failed
outright, and that person received no web push there at all.

### Decision

The unique index is `(org_id, endpoint)` and the upsert conflicts on the same
pair (migration 00006). Re-subscribing within one organization still collapses
onto a single row.

### Consequences

- One row per person per browser per organization is the correct shape, and a
  send fans out per organization as it already did.
- The old index also leaked across tenants: the shape of the failure told a
  caller whether an endpoint existed in some other organization. Scoping the
  index removes that.
- `Down` recreates a NON-unique index. Rows that are legitimate under the new
  rule violate the old one, so a faithful reversal would either fail or delete
  somebody's subscription to make the constraint fit.

### Rejected

- **Deleting the other organization's row on conflict.** Silently unsubscribing
  someone from an organization they never touched.
- **Keying on (subject_id, endpoint).** Correct in practice, but org_id is the
  RLS predicate; leading with it keeps the index usable for the same reason every
  other index here leads with it (ADR-013).

---

## ADR-044 — Sharded rebuild partitions by stream; event metadata is flat strings

**Date:** 2026-08-10 · **Status:** Accepted

### Sharded rebuild

A rebuild may apply events through N workers (`PROJECTOR_REBUILD_SHARDS`).
Partitioning is by **stream hash**, never by revision range.

Revision-range slicing is the obvious design and it is wrong here. Two events for
the same aggregate land in different ranges; every projection in this codebase
upserts by row; the surviving row is then whichever range committed last. That is
a read model wrong in a way nothing detects — no error, no failing test, just a
value from the middle of an aggregate's history.

Hashing the stream puts every event of one aggregate in one worker, in order.
Ordering ACROSS aggregates is lost, which is exactly what a rebuild already gives
up by reading a link stream instead of `$all`.

Consequences:

- **No worker writes a checkpoint.** The position advances out of order by
  construction, so a per-event checkpoint would name a position whose
  predecessors have not all been applied, and a crash would resume from it and
  skip them. The coordinator writes one checkpoint at the end; a crash mid-rebuild
  restarts the rebuild, which is the correct outcome for a half-rebuilt
  projection.
- **Shards are capped at 16 and validated against `POSTGRES_MAX_CONNS`.** Each
  holds a pooled connection for the whole rebuild — the same exhaustion already
  verified for projection leases, where a 3-connection pool with 3 leases could
  not execute `SELECT 1`.
- **Live consumption is never sharded.** It must preserve the global commit order
  the `$all` subscription exists to provide.
- The default is 1. Sharding is a decision, not something a deployment acquires
  by upgrading.

### Event metadata is written as map[string]string

KurrentDB's v2 append APIs — `MultiStreamAppend` and `AppendRecords` — carry
event metadata as `map<string,string>` and reject anything else before the
request leaves the process:

```
event metadata must be a valid JSON map[string]string:
json: cannot unmarshal number into Go struct field .schemaVersion of type string
```

Our metadata had three non-string fields: `schemaVersion`, `snapshotRevision`,
`subjectIds`. Keeping them typed makes both APIs permanently unusable.

So the wire format is now all strings — integers formatted, `subjectIds`
comma-joined (a prefixed ULID can never contain a comma, ADR-030).

**Reads accept both shapes, permanently.** An event log is append-only, so the
typed shape is not a migration to finish; it exists forever and must decode
forever. `flexInt` and `flexStrings` handle either.

**The one real cost:** a rolled-back deployment running an older binary cannot
read metadata written after this change. Rolling back across this boundary
requires the tolerant reader to ship first.

#### Keeping it that way

A constraint that lives only in one function is a constraint that gets broken by
someone adding an ordinary field a year from now, and discovered much later when
somebody finally uses a multi-stream append. Three guards make that a failing
test at the moment the field is added:

- `metadataWireKeys` maps every field of `Metadata` to its wire key, checked by
  reflection. A new field with no entry fails immediately, with a message saying
  why the format is what it is.
- A fully-populated `Metadata` — built by reflection, so new fields are covered
  automatically — must still encode to `map[string]string`. This is the exact
  check the SDK performs before sending, so a failure here means "cannot write at
  all", not "slightly wrong".
- The same value must survive a round trip, which catches a field that is written
  but never read back.

A field whose type has no flat-string encoding (a struct, a map) fails the
populate step with an explicit message rather than producing nested JSON that
only breaks on the append path.

**`subjectIds` refuses a value containing its own separator.** The type is
`[]string` and nothing upstream forces entries to be well-formed ids; an entry
carrying a comma would decode as two subjects, silently widening who an event
concerns — which drives erasure and notification targeting. There is no
legitimate value with a comma in it, so it is rejected at the write rather than
escaped.

### MultiStreamAppend does not relax the aggregate boundary

One aggregate is still one stream and one consistency boundary. If an invariant
spans two aggregates it belongs in one aggregate, or it is a process — and a
process is a Temporal workflow (ADR-017).

What it IS for is pairing a claim with the thing that claims it: reserving
`reservation_email-<hex(HMAC-SHA256(k_res, email))>` with `NoStream` **and**
creating `user-<id>` with `NoStream`, atomically. (The reservation value is
HMACed, never the raw address — a stream name is permanent and unshreddable,
ADR-048.) As two appends, a crash between them
leaves a reservation nobody owns and an address unclaimable forever.

Verified against the running server, not assumed: with one precondition already
violated, the other stream was **not created** — `ReadStream` returned
`ErrStreamNotFound`. A partial write would make the operation worse than two
appends, because callers would believe it atomic.

Also verified: the multi-append path reports a precondition failure as
`ErrorCodeStreamRevisionConflict`, **not** the `ErrorCodeWrongExpectedVersion` a
single-stream append returns. Mapping only the latter made every contended
reservation look like an infrastructure fault.

## ADR-045 — Authorization is fail-closed by type, and revocation does not wait for a projector

**Date:** 2026-08-10 · **Status:** Accepted

ADR-006 put the authorization model in OpenFGA and ADR-010 said it fails closed.
This records how that is made true in Go, because "fails closed" as a rule is
kept by discipline and lost by the first forgotten branch.

### The zero value denies

```go
type Decision struct {
	allowed bool
	reason  string
}
```

`Decision` is a struct with unexported fields and no way to construct an allow
except `Allow(reason)`. Every zero value, every `var d Decision`, every element of
a slice that an implementation returned short, and every early return that forgot
to set an answer is therefore a **denial**. The property is carried by the type,
not by review.

This is why `Check` returns a `Decision` rather than `(bool, error)`. A bool
default is `false` too, but a caller who ignores the error still holds a usable
answer; here there is no answer to hold that is not a deny.

The rule the Guard exists to keep: **an error is a denial, never a skip.** An
unreachable OpenFGA, a timeout, a malformed query, a batch answered with the
wrong number of answers — all deny. Anything else makes degrading a dependency a
way to gain access.

### Grant and revoke use opposite mechanisms

They have opposite risk profiles, so they get opposite designs (access.md §6.1):

| | Late by a second | Mechanism |
| --- | --- | --- |
| Grant | user does not yet see their own new access — harmless | contextual tuples, then the access projector |
| Revoke | a removed member still reads the workspace — a breach | a **tombstone**, consulted on the hot path |

A tombstone can only ever produce a **deny**. There is no shape of the
`Tombstones` interface that can grant anything, which is what makes consulting an
eventually-consistent store in the request path safe: the worst a stale or
duplicated tombstone can do is deny access that was already being removed.

### A tombstone is cleared by confirmation, never by a timer

An earlier formulation had it "expire once the projector has certainly caught
up." That is a bug with a comfortable-sounding description. If the TTL fires
before the access projector removes the tuple, access **silently returns** — no
event, no log line, nothing to notice.

So the access projector deletes the tombstone after it has removed the tuple, by
positive confirmation. The one-hour TTL is garbage collection for a tombstone
whose projector died, and a tombstone that reaches it is an alert: it means the
access projector is broken.

### Only permits are cached, and a revocation invalidates all of them at once

`Decisions` has no method that could store a refusal. A cached deny would outlive
the grant that fixed it, and unlike a cached permit nothing a user or operator
does would clear it.

Cached permits are keyed on the principal's **revocation epoch**, a counter
bumped by any revoke. One `INCR` invalidates every decision cached for that
principal — including permits for *other* resources, which a per-key eviction
would miss. That counter has **no expiry**, deliberately: if it expired and reset
to zero, permits cached under the old epoch would become live again — a
revocation undone by garbage collection.

Permits also carry a TTL, capped at 15 minutes (`MaxDecisionTTL`), because that
TTL is the window in which a revocation whose epoch bump was lost still grants
access. No latency argument outweighs that, so the cap is enforced at
construction rather than documented.

If the epoch cannot be read, the cache is **skipped**, not used with a guessed
value. A cache that cannot be reasoned about is a cache that is bypassed.

### The order of operations in `Guard.Check`

1. Validate. A malformed query is never sent on.
2. Consult the decision cache — permits only.
3. Ask OpenFGA. Any error denies.
4. **Only if the answer is allow**, consult the tombstones.
5. Cache the permit.

Step 4 runs only on allow because a deny needs no second opinion. That keeps the
extra lookup off the majority path and cannot weaken anything, since a tombstone
only ever turns an allow into a deny. A cached permit takes the same step 4 — a
revocation that had to wait for a cache entry to expire would not be immediate.

A batch answered with the wrong number of answers denies the **whole page**.
Answers shifted by one position attach somebody else's permit to this resource,
which is worse than denying everything.

### Depth is capped at 15, against OpenFGA's 25

OpenFGA raises a hard error past 25 levels, and a check that errors fails closed.
A tree allowed to grow too deep therefore does not produce a warning — it
produces users locked out of resources they own, with no obvious cause.

The cap is enforced where a hierarchy is **built**, not where it is read, so
breaching it is a rejected write that names the resource and the person doing it.
The ten-level gap is headroom: hitting ours is a rejected write, hitting theirs is
an outage. `WouldExceedDepth` covers re-parenting, where each subtree is within
the limit and the combined tree is not.

Paths are also checked for cycles. A container that transitively contains itself
makes depth unbounded, and OpenFGA would then answer by exhausting its traversal
limit rather than by returning a decision.

### The official Go SDK is HTTP-only, so the client is generated

ADR-037 mandates gRPC wherever a service offers it. OpenFGA's server offers gRPC
on `:8081`, but `openfga/go-sdk` is generated from the OpenAPI spec and speaks
HTTP only — verified by inspecting the module, not assumed.

The client is therefore generated from `buf.build/openfga/api` into
`gen/thirdparty/` and wired into `make proto-thirdparty`. Managed mode is
**disabled** for googleapis, protoc-gen-validate and grpc-gateway: left on, buf
rewrites those transitive protos into our module path and the generated code no
longer compiles against the real ones.

Batch answers are correlated by the **id we send**, never by position — OpenFGA
does not promise response order, and a batch that happens to come back in order
during testing is not a guarantee.

### What is verified, and how

Every property above is mutation-tested; a test suite that passes against
deliberately broken code is documenting nothing. Thirteen mutations across the
kernel, the composition root and the Valkey adapter, all caught.

One initially **survived**, and it is the most useful finding here: swallowing a
tombstone read error and returning `(false, nil)` passed the entire integration
suite, because every test ran against a healthy Valkey and no test ever executed
the error branch. `TestUnreadableTombstoneStoreIsAnError` closes the client
deliberately. A mutation that survives is the suite naming a path it never runs.

The composition root is asserted separately (`cmd/api/wiring_test.go`), because
the ports that make revocation immediate are **optional in the kernel and
invisible at runtime when absent** — checks still work, they just keep permitting
a principal whose access was revoked seconds ago. Three adapters in this codebase
were once built, fully tested, and constructed by no binary; a Guard has a worse
version of that failure, because a Guard nobody holds does not deny, it is
skipped.

## ADR-046 — The idempotency claim is one SQL statement, scoped to the principal

**Date:** 2026-08-10 · **Status:** Accepted

CONVENTIONS §6 and ADR-021 say every mutating RPC carries an `Idempotency-Key`
and that a replay returns the stored response. This records how that is made
true, because two of the three failure modes here are silent.

### The claim is atomic in SQL, not in Go

```sql
INSERT INTO idempotency_key (principal, operation, key, fingerprint, expires_at)
VALUES ($1, $2, $3, $4, now() + make_interval(secs => $5::double precision))
ON CONFLICT (principal, operation, key) DO UPDATE SET ...
WHERE idempotency_key.expires_at <= now();
```

A `SELECT` followed by an `INSERT` lets two concurrent requests both read
"nothing stored" and both proceed — reintroducing the double-click the gate
exists to stop, by way of the check meant to stop it. One statement makes that
impossible: rows-affected 1 means this caller owns the claim, 0 means somebody
else does.

**This cannot be verified against a fake.** The atomicity is Postgres behaviour,
so a check-then-act implementation passes every unit test. The test that matters
runs 16 concurrent claims against a real database and asserts exactly one is told
to execute.

The `ON CONFLICT` branch takes over an EXPIRED row rather than refusing it, so a
request that died mid-flight does not hold its key until the retention sweep
runs — with the client, correctly retrying with the same key, refused the whole
time.

### The scope is (principal, operation, key)

The principal is not decoration. Keyed on the key alone, one tenant sending
another's key is handed that request's stored response — a cross-tenant read
through a header, reachable by anyone who can guess a ULID. `cqrs.Scope` refuses
to be built without one, and the refusal happens before anything reaches the
database.

The operation covers the milder version: the same key on two different RPCs.

`|` separates the parts of the stored key and is rejected in all three, for the
same reason `:` is rejected in an authorization reference — a value carrying the
separator addresses a scope the caller did not name.

### Same key, different body, never returns the stored response

A reused key is a client bug and is refused with `CONFLICT`. What must NOT happen
is returning the stored response: that tells the client its request succeeded
when a different request is what actually ran.

The check is a SHA-256 of the request body, stored beside the response. SHA-256
rather than something cheaper because a collision here does not fail — it
returns a different request's answer as though it were this one's.

The same refusal applies while the first request is still RUNNING, not only once
it has completed. Without that, a reused key falls through to the in-flight path
and the caller waits for — and then receives — somebody else's response.

### Only successes are recorded; failures release the claim

A failed handler releases its claim so a retry can run. Keeping it would turn a
transient error into a permanent one for the whole TTL, and the client's retries
— correctly using the same key — would all be refused.

`response IS NULL` marks a row as an in-flight claim, which makes two things
true by construction: `Release` can only ever delete an *uncompleted* claim
(deleting a completed one would let the mutation run twice — the gate failing
open), and `Complete` cannot overwrite an answer a client has already been given.

A `Complete` affecting zero rows is an ERROR. It means the claim expired or was
taken over while the handler ran, so the response was not stored — and a caller
told "recorded" would believe a retry will replay it.

### A store that cannot answer denies

An unreachable idempotency store does not let the mutation through. Executing
anyway defeats the gate exactly when it matters most: a struggling store is a
store under the retry storm the gate exists for. This is the same rule as
ADR-010's authorization exception, for the same reason.

### The TTL is a retention bound

A stored response is a serialized reply and can contain personal data (ADR-002),
so the 24-hour default is not a cache setting. It is capped at 7 days and
validated **twice**: config refuses to boot above the cap with a named
environment variable, and `cqrs.NewOnce` refuses again at construction. The first
gives a precise startup failure; the second means no code path can build an
unbounded gate.

The sweep is registered in `cmd/api`'s `backgroundTasks` list rather than started
by a bare `go` statement. That is `Dedup.Forget`'s failure in its original shape:
written, documented, indexed for, and called by no binary at all while its unit
test passed. A test asserting on the list catches it; a test calling `Sweep`
directly reproduces the blind spot.

### The table carries no RLS, deliberately

The gate runs BEFORE the request is authorized, so there is no tenant scope to
set and a policy on this table could never be satisfied. Isolation comes from the
principal being part of the primary key instead — which is why the scope refuses
to exist without one. `principal` is a pseudonymous subject id, never an email or
a name.

### Verification

Fifteen mutations across the SQL, the adapter and the composition root; thirteen
caught, one an equivalent mutant, one a genuine gap that is now covered.

The equivalent mutant is worth recording so nobody "fixes" it later:
`GetIdempotencyKey`'s `expires_at > now()` is unreachable, because `Claim` takes
over an expired row before that read happens and `now()` is the transaction
timestamp, so the two statements cannot disagree about which side of the expiry a
row falls on. Removing that predicate alone changes nothing; removing it AND the
claim's expiry check is caught. It stays as the second line of defence if the
takeover is ever loosened.

## ADR-047 — All JSON goes through one kernel package, on encoding/json/v2

**Date:** 2026-08-10 · **Status:** Accepted

Every encode and decode in this codebase goes through `internal/platform/codec`,
which wraps `encoding/json/v2` (stdlib since Go 1.27 — no build flag; it was `GOEXPERIMENT=jsonv2` on 1.26, already on by
default in this toolchain). No other package imports a JSON library.

Three reasons, none of them speed. The strictness decision is **forced to be made
at the call site** rather than inherited from whatever default a library happens
to ship. Determinism is required here and v2 can provide it, which v1 could not
for maps. And v2 changes observable behaviour, so a single wrapper is what keeps
those changes reviewable in one file instead of scattered across every decode.

### Strict for what we wrote; tolerant for what somebody else wrote

`Unmarshal`, `Into` and `DecodeFrom` REJECT unknown members. Their inputs are
ours — a page cursor, a cache entry, a config document — and an unknown member
there is a typo or a version mismatch. Ignoring it silently produces a setting
that never took effect, which is worse than a startup error, because nothing ever
reports it.

`Tolerant` and `IntoTolerant` ignore unknown members, and they are the ONLY
sanctioned leniency. They exist for the event log and for third-party payloads. A
newer producer adds a field; during a rolling deploy both versions are running;
rejecting the unknown member would stall a projector on an event that is
perfectly valid (ADR-029). That is not a hypothetical — it is the normal state of
a deploy.

The function NAME carries the answer, so "does this one tolerate junk?" is
settled by reading the call, not the body. A boolean option would have put the
same decision somewhere nobody looks.

### Determinism is on by default, not on request

Map ordering is stable in every encode. Anything that is hashed, fingerprinted or
compared byte-for-byte needs that, and the concrete dependency is ADR-046's
idempotency gate: the fingerprint is a SHA-256 of the request body, so a
non-deterministic marshal makes a client's legitimate retry — same key, same body
— hash differently and come back as `CONFLICT`, a reused key that was never
reused. The cost is a key sort, paid only by values that contain maps.

### `Marshal` never returns nil

An empty value encodes to zero bytes, and a nil slice is how several stores here
spell "nothing recorded". Conflating the two was a real bug, not a tidiness
concern: an empty idempotency response became indistinguishable from an
unfinished claim, and the replay path refused every retry of a method whose reply
is an empty message.

### The four v1→v2 behaviour changes

Each of these is a silent-data-corruption risk. None of them is a style
difference:

- A nil slice or map marshals as `[]` / `{}`, where v1 emitted `null`.
  `codec.NullEmpty` restores the v1 shape, and is only for a format a third party
  already parses. For anything we own the v2 default is better.
- **Field matching is case-sensitive.** v1 matched case-insensitively, so a
  stored `{"occurredat":...}` populated `OccurredAt`; under v2 the field stays
  zero and there is no error. This is the one that reaches back into data already
  written.
- **Duplicate object members are an error**, where v1 took the last. Two parsers
  disagreeing about which value is real is a security problem, not a parsing
  nicety.
- `time.Duration` marshals as a string, not integer nanoseconds.

### The event codec's registry is copy-on-write, and only the parallel benchmark shows why

`internal/adapter/eventcodec` moved its type registry from `sync.RWMutex` to
`atomic.Pointer` copy-on-write. Measured on Go 1.26.5, Apple M3 Pro:

| Registry lookup     | mutex  | atomic  |
| ------------------- | ------ | ------- |
| serial              | 13.2ns | 10.8ns  |
| parallel, 11 cores  | 110ns  | 1.27ns  |

Serial, this is noise and nobody would ship a change for it. Parallel it is 87x,
because `RLock` is a contended atomic read-modify-write on one shared word, so
every core invalidates every other core's cache line on every event. The mutex
gets roughly 8x SLOWER under parallelism while the atomic gets faster. Against a
487 ns parallel payload decode, the lock was about 20% of the total.

That matters here specifically because a sharded rebuild decodes on N workers at
once (ADR-044) — the parallel column is the production shape, and the serial one
is not. **Record this as the lesson, not the number: a benchmark suite with only
the serial case would have dismissed the change as noise, which is exactly how a
contention point survives a benchmark suite.**

`Freeze()` closes the registry once the composition root has finished wiring.
After it, a late registration panics at the call site rather than producing a
codec whose behaviour depends on package initialisation order — where a projector
that started earlier has already treated those events as unknown and stopped, and
nothing connects that failure to its cause.

v2 honours the v1 `Marshaler`/`Unmarshaler` interfaces — the method names are
identical — so the `flexInt` and `flexStrings` readers, which decode both stored
metadata shapes (ADR-044), needed no signature change. They were deliberately
left on the v1 interface rather than moved to v2's `UnmarshalJSONFrom`: a type on
the read path of a permanent log should not be decodable by exactly one library
version.

### The other measured numbers, and where the win lands

Go 1.26.5, Apple M3 Pro:

- metadata `Unmarshal`: 1500 ns → 1195 ns (−20%)
- legacy typed-shape metadata `Unmarshal`: 1430 ns → 1030 ns (−28%, 4 allocs → 3)
- metadata `Marshal`: 760 ns → 778 ns (flat)

The gain is entirely on the read path, which is the right side: an event is
written once and spent many times.

### How the migration was verified — round-tripping proves nothing here

A marshal-then-unmarshal round-trip test passes identically under v1 and v2,
because it never reads a byte the current code did not just write. For an
append-only permanent log the question is not "can we read what we write", it is
**"can we read what we wrote"** — by binaries that no longer exist, under a JSON
library whose field matching has since changed.

So the test (`internal/adapter/kurrentdb/codecmigration_integration_test.go`)
reads 5000 events from the live KurrentDB `$all` and decodes each one's metadata:
1348 non-system events decoded, and 1315 timestamps compared against their RAW
STORED BYTES using an **independent parser** (`encoding/json` v1). The
independence is the point — producing the expected value with the codec under
test would make both sides fail identically and the test would pass through the
exact corruption it exists to catch.

The first version of that test asserted `OccurredAt` was non-zero and reported
715 failures. **That was the test being wrong, not the codec:**
`snaptest.RosterSnapshot.v1` legitimately stores `"0001-01-01T00:00:00Z"`.
Probing the raw bytes rather than "fixing" the codec to satisfy the assertion is
what caught it. The lesson is worth more than the fix: the assertion has to
compare against what is actually on disk, because "non-zero" and "decoded
correctly" are not the same property, and only one of them is the property we
need.

### The accepted risk

`encoding/json/v2` is EXPERIMENTAL and explicitly outside the Go 1 compatibility
promise. On Go 1.26 it existed only under `GOEXPERIMENT=jsonv2`; since 1.27 it is ordinary stdlib gated on go.mod's language version. `gopls` reports every v2
symbol as "requires go1.27", although `go build`, `go vet` and `golangci-lint`
all pass — so the editor is noisy in a way that is easy to mistake for a real
error.

The hedge is the whole reason the kernel package exists: `internal/platform/codec`
is the only package that imports it, so if the API changes, one file changes with
it. Rejected alternative — importing `encoding/json/v2` directly at each call
site — makes the blast radius the whole codebase and loses the strict/tolerant
naming at the same time.

Reconsider if the experiment is withdrawn, or if any release changes read-path
behaviour for events already stored. Neither would be a refactor; both would be a
correctness incident, which is why the read path is verified against the live log
rather than against freshly-marshalled bytes.

## ADR-048 — A reservation stream is named by a keyed HMAC, and its key is never rotated

**Date:** 2026-08-13 · **Status:** Accepted

Uniqueness of an email address is enforced by appending to a stream named after
the address, with `NoStream` as the precondition: two concurrent registrations
contend on one stream and exactly one wins (ADR-044). That makes the address part
of a **stream name**, and a stream name is not a payload — which is why ADR-002's
rule about personal data in events does not directly cover it, and why it needs
its own decision.

The name is `reservation_email-<hex(HMAC-SHA256(k_res, normalized_email))>`, full
width, 64 hex characters. Never the address, and never a plain hash.

### Why not the address in the clear

Because erasure could not reach it. Crypto-shredding works by destroying a key so
ciphertext becomes unreadable (ADR-002); a stream name has no ciphertext to
shred. It persists in the `$streams` index and in the `$ce-reservation_email`
category stream, surfaces in metrics labels and client logs, and KurrentDB's
deletion is a soft delete. An erasure would release the reservation while the
address stayed readable forever, in the one place nothing can rewrite.

### Why not a plain hash

The space of real email addresses is small enough to enumerate. `SHA-256(address)`
is reversible in practice for anyone holding the log, so an unkeyed digest is a
dictionary with extra steps. A keyed hash is not, because the key is not in the
log or the database.

### Why the key is never rotated, and never destroyed

`k_res` is dedicated to this derivation, and it is the one key in the system that
erasure does not revoke. Stream names are immutable: rotating the key produces
new names while the old streams still hold the claims, so uniqueness would
silently stop being enforced for every address registered before the rotation —
no error, no event, and two accounts able to claim one address.

Renaming the existing streams instead is not available. There is no in-place
rename, and copying every reservation stream under a new name would rewrite
history that other things reference by position.

So the exception is accepted deliberately and its blast radius is stated rather
than hoped about. An attacker holding **both** `k_res` and the log can confirm
whether a **guessed** address has an account. They cannot enumerate addresses,
recover one they have not guessed, or learn anything else about the person. That
is the entire cost, and it buys atomic uniqueness with no lookup table.

### No version column, deliberately

IDENTITY-REVIEW C7 asked for one. It is absent, and the absence is the honest
position: a version column advertises a rotation capability that cannot exist
here, and the next reader would build a rotation job against it. C7's other half
— truncation — was real and is fixed: the index is the full 32 bytes. A truncated
index collides, and under the constraint that enforces uniqueness a collision
means one person's registration fails because a stranger's address shares a
prefix. That is unreproducible, unexplainable, and tells a determined attacker
that some other address collides with theirs.

### Consequences

The same derivation names the stream and fills the `email_index` column, so the
uniqueness mechanism and the lookup cannot disagree — two derivations would let
them, and the disagreement would look exactly like projection lag.

Comparisons against a derived index are constant-time (`hmac.Equal`). The
comparison happens during verification against a caller-supplied address, and a
byte-wise compare there leaks a prefix of the index the key exists to protect.

The category is `reservation_email`, with an underscore. KurrentDB derives a
category from everything before the FIRST dash, so a dash would file every
reservation under `reservation` and break the prefix-filtered subscription.

`k_res` must be backed up wherever it lives. Losing it is not recoverable by
re-deriving: every existing reservation stream becomes unreachable, and
uniqueness stops being enforced for every address already registered.

## ADR-049 — TOTP replay state is authoritative, in PostgreSQL, and fails closed

**Date:** 2026-08-13 · **Status:** Accepted

RFC 6238 codes are valid for a whole time step, and this authenticator accepts a
skew of one step either side (`totp.Skew = 1`), so any single six-digit code
validates across three steps — a 90-second window. Without a replay guard, a code
that has been OBSERVED once — a shoulder-surf, a screenshot, a log line, a
phishing relay that forwards the victim's code to the real login — can be
presented a second time inside that window and will validate. The second factor
is then not a second factor; it is a 90-second bearer token.

This records where the "already used" state lives, and why the three properties
that make it a control rather than a decoration — authoritative storage, an
atomic claim, and failing closed — are each non-negotiable.

### The state lives in PostgreSQL, and Valkey is disqualified by its own rules

`app.TOTPReplayGuard` is backed by `totp_replay` (migration `00008_identity.sql`)
and nothing else. Two alternatives were rejected.

An **in-process map** is wrong at any scale above one pod: the attacker replays
the observed code against a different instance and it works. The failure is
invisible, because every test passes — the map is consulted, it is just not the
same map.

**Valkey** is the tempting answer, and it is disqualified by the exact property
that makes it good at everything else it does here. Everything in Valkey carries
a TTL and `FLUSHALL` must be survivable (ADR-010 lists it as *degraded, fall back
to source*). There is no source to fall back to for "was this code already
spent", and "the entry was evicted under memory pressure" is not an acceptable
reason to accept a replayed code. A cache that may forget is fine for a
projection; it is a silent removal of a security control here.

### It is authoritative, not projected

`totp_replay` is one of the few tables in this system that is NOT derived from
the event log. Spending a time step produces no event and cannot: the fact is
created by a verification attempt, is meaningful for at most 90 seconds, and
carries no business history worth replaying. Rebuilding the read model from
position zero (ADR-013) therefore does not reconstruct this table, and must not
try — a rebuild that emptied it would un-spend every live step.

It is also not personal data. A `credential_id` and an integer step say that a
credential verified at an instant; that is the same thing the login history
already records, and ADR-002 is untouched.

### The primary key IS the guard

```sql
INSERT INTO totp_replay (credential_id, step, expires_at)
VALUES ($1, $2, $3)
ON CONFLICT (credential_id, step) DO NOTHING;
```

`PRIMARY KEY (credential_id, step)` is not a backstop for application logic; it
is the atomicity the port contract demands. `ClaimTOTPStep` is `:execrows` and
the affected-row count IS the answer — 1 means this caller spent the step, 0
means somebody already had, and `Guards.Claim` translates the 0 into
`app.ErrCodeReplayed`. Nothing reads first.

The obvious implementation — `SELECT`, then `INSERT` if absent — races two
simultaneous presentations of the same code and both observe it as unused, so
both win. That concurrency is not a thought experiment; it is precisely what an
attacker relaying a code produces, and it defeats the guard through the check
written to enforce it. As in ADR-046, **a check-then-act implementation passes
every unit test against a fake**, so the property is only demonstrable against a
real database: eight concurrent executions for one step, exactly one winner.

Keying on `(credential_id, step)` rather than on the step alone matters for the
same reason the guard exists at all — a step-only key would let one user's login
consume every other user's step at that instant, turning the control into a
denial-of-service on everyone.

### Validate first, then claim

`Authenticator.Verify` finds WHICH step matched and only then claims it. A
validator that answers "valid somewhere in the window" cannot prevent replay at
all, because the step is what the claim is keyed on. The order is also the
security property in the other direction: claiming before validating would let an
attacker burn a step with a WRONG code and deny the legitimate user their next 30
seconds.

### Failing closed — the second deliberate exception to ADR-010

ADR-010 says the server stays up and degrades per dependency, and names OpenFGA
as the one deliberate exception. **This is the second.** When the guard cannot be
consulted, `Verify` returns an error and the verification fails; it does not fall
through to "the code looked right".

The reasoning is ADR-010's own, applied to a different store. Accepting a code
without claiming its step IS the compromise — it is not a reduced-functionality
mode, it is the control switched off — so there is no safe degraded behaviour to
choose. An attacker who can make the replay store unreachable would otherwise
have turned the second factor off for everybody, which makes resilience an
escalation path. A failed login during a PostgreSQL outage is the cheaper
failure, and PostgreSQL is already **critical** in ADR-010's table, so nothing is
being served at that moment anyway.

`totp.New(issuer, guard)` REFUSES a nil guard rather than accepting one and
running unguarded, and `postgres.NewGuards` refuses a nil transaction for the
same reason. An authenticator that silently has no guard is the worst version of
this failure: every code still validates exactly as expected, and nothing
anywhere reports that replay protection is absent.

### Row count, expiry, and why the rows still need sweeping

The claim's expiry is the end of the last step that could still accept the code:
`(step + Skew + 1) * Period`, so at most 90 seconds from the start of the matched
step. Keeping it longer stores nothing useful; keeping it shorter reopens the
window it exists to close.

With a one-step skew, a credential can hold at most three unexpired rows at once,
so the LIVE working set is bounded at roughly 3 × (credentials verifying in the
last 90 seconds) — trivial. **The rows do not remove themselves.** PostgreSQL has
no TTL, so `expires_at` is a predicate, not a mechanism, and without a sweep the
table grows by one row per successful TOTP verification for the lifetime of the
deployment. `SweepTOTPReplay` (`DELETE FROM totp_replay WHERE expires_at <=
now()`, served by `totp_replay_expiry_idx`) is retention, not correctness: an
expired step cannot validate anyway, so the row protects nothing once it is past.
`ON DELETE CASCADE` from `credential` handles the other direction — deleting a
credential takes its spent steps with it.

### Consequences

- **Every successful TOTP verification costs a database write, on the login hot
  path.** That is the price and it is paid deliberately. It is one indexed insert
  in a system transaction, next to a password verify that is already an
  intentionally expensive KDF, so it is not the cost that matters here — the
  cost that matters is the coupling: TOTP verification now requires PostgreSQL
  to be writable, and a read-only database means nobody with MFA can log in.
- Identity's tables carry no RLS, so this runs through `db.SystemTX`, never a
  tenant transaction. A user exists before any organization does, so a tenant
  policy on these tables could never be satisfied.
- It rules out verifying a TOTP code in any context that cannot reach PostgreSQL
  — an edge validator, an offline check, a read-replica-only path. There is no
  cache tier to add in front of it: a cache that can answer "not yet spent" from
  stale state is the exact hole this closes.
- `ErrCodeReplayed` is distinct from a wrong code and must stay that way. A wrong
  code is a typo; a replayed one means somebody has OBSERVED a genuine code. It
  is recorded as `contract.ReasonReplayedCode` and is worth alerting on — it is
  one of the few signals in this system that names an attack rather than a fault.
- **Two things this decision requires are not yet wired.** `SweepTOTPReplay` has
  no scheduled caller — the retention job does not exist — and no binary
  constructs `totp.Authenticator` at all, because slice 1 stops short of the MFA
  verification flow. Both are stated here rather than left implied, because the
  failure mode of the second is precisely the one ADR-045 records: a control that
  is built, tested, and held by nobody.

### Reconsider if

The skew widens. Every extra step lengthens the window in which an observed code
is replayable, which is the window this guard has to cover; the row count and the
claim's expiry follow from `Skew` and would need to be re-derived, not just
re-tuned.

## ADR-050 — A login presents both factors in one call, and there is no half-authentication ticket

**Date:** 2026-08-13 · **Status:** Accepted

`Authenticate` takes the password and, optionally, the TOTP code. With no code it
records `SecondFactorChallenged`, reports which kinds the account can complete
with, and returns nothing else. The client then calls again with the password AND
the code. Nothing is stored between the two calls.

The consequence is explicit: a completed login pays **two** Argon2id evaluations,
one per call, at 32 MiB and ~51 ms each.

### What the alternative would cost

The obvious fix is a ticket: after the password verifies, hand the client
something that says "the first factor is done", so the second call skips the
hash. Every place to put it is worse than the hash it saves.

A row in `identity_token` gives a half-authentication the same storage, lifetime
and revocation surface as a password reset — a thing an attacker can steal and
replay, holding one factor's worth of proof. An in-process map is per-pod, so it
breaks the moment a second replica exists and produces a login that works only
when the load balancer happens to be sticky. A signed stateless challenge is the
serious option — an HMAC over `(subject, AAL1, expiry, nonce)` with the nonce
spent once in Valkey — and it is still a **bearer artifact for a partial
authentication**, which is precisely what `app.Proof` was designed to make
impossible: unexported fields, no constructor, not serializable, so evidence of
an authentication cannot leave the process that performed it.

### Why the cost is acceptable now

The hasher is bounded at `GOMAXPROCS` concurrent evaluations, which is the
measured saturation point — beyond it, throughput falls while memory keeps
climbing. On the 11-core development machine that is roughly 100 completed
logins per second sustained, with the doubling already counted. This system is
not near that, and the first thing to hit it would be a burst of registrations
rather than steady login traffic.

Adding a bearer token to a system that has none, to solve a capacity problem it
does not have, is the trade this ADR refuses.

### When to revisit

Two triggers, and both are measurable rather than a matter of taste:

- Sustained completed logins approach the concurrency bound — watch the queue
  wait, not the CPU: the hasher sheds with `RATE_LIMITED` after two seconds, so
  the symptom is refusals during normal traffic.
- Password-only authentication becomes reachable for any account. The second
  hash exists because a second factor is mandatory; if that stops being true,
  this whole shape changes and so does ADR-036's disclosure argument.

Adding the challenge later is **not** a breaking API change: the request gains an
optional field and the response an optional one, which `buf breaking` permits.
That is why the decision could be taken now rather than deferred into the proto.

### Consequences

The client holds the password for the duration of the ceremony, which is what a
browser's form already does and what a native client must be told not to persist.
The RPC surface says so, in the field's own documentation, rather than leaving it
to be inferred.

`contract.SecondFactorChallenged` is appended on the first call. It is the record
that a password was accepted for an account, which is a real security signal on
its own — someone knows the password and does not have the device.

---

## ADR-051 — A username is a public handle, is not in the vault, and its tombstone outlives the account

**Date:** 2026-08-16 · **Status:** Accepted

Every account has a **username**: a public, human-chosen handle used for
mentions, profile URLs and anywhere the product needs to name a person to other
people. It is mandatory, not an optional profile field.

It is stored **in the clear, in a projection column**, and it is the first
deliberate exception to "no projection may contain a personal-data column"
(compliance.md §1). That exception needs stating rather than assuming, because
the rule it breaks is the one that makes erasure a key deletion instead of a
migration.

### Why it is not in the PII vault

The vault exists so that personal data can be destroyed by destroying a key
(ADR-002). That mechanism requires the data to be *secret* — crypto-shredding
makes ciphertext unreadable, and it does nothing to a value that was published.

A username is published by design. Its entire purpose is that other people see
it: `@alice` in a comment, `/u/alice` in a URL, "alice invited you" in an email
somebody else received. Putting it in the vault would give the appearance of
protection while every copy that matters lives in somebody else's inbox and
somebody else's screenshot. Worse, it would make the read model resolve a vault
key on every page render that names a person, which is the cost the vault exists
to avoid paying on non-secret data.

So the handle goes in `user_view` as an ordinary column, and it is the one piece
of user-supplied text this system deliberately publishes.

### The erasure consequence, which is the hard part

Because it is cleartext, **erasure must DELETE it** — key destruction does
nothing. That is a second exception: erasure elsewhere in this system never needs
to touch a projection, and here it does.

**And the handle must never be reissued.** If `@alice` is erased and somebody
else may claim it, every old mention, link and cached reference silently
re-points at a stranger. An erasure request — a privacy action taken to protect
someone — would create an impersonation vector aimed at that same person. So
erasure leaves a **tombstone**: the handle is marked taken, permanently, and no
future registration may claim it.

The tombstone outlives the account, which means it is data retained after an
erasure request, and that has to be justified rather than waved through. It is
justifiable on two grounds: it protects **third parties** (readers of old
content, who would otherwise be deceived) rather than the controller, and it
retains **no personal data** — the tombstone is the handle string and the fact
"never reissue", with no subject id, no timestamp tied to a person, and nothing
that links it back to who held it. It is a reservation with no owner.

### Why it is a reservation aggregate, not a column with a unique index

Same reasoning as ADR-044/ADR-048 for email: uniqueness under concurrency is a
write-path invariant, and a unique index in a projection cannot enforce it
because projections are derived and eventually consistent. Two simultaneous
claims must contend on one stream, with exactly one winner, before either becomes
a fact.

`UsernameReservation` therefore mirrors `EmailReservation` — with one difference
that follows directly from the decision above: **the stream is named by the
handle itself, not by a keyed HMAC.** ADR-048 hides the email because the email
is secret; hiding a public handle would buy nothing and cost the ability to read
the log while debugging.

### Why it is NOT a login identifier

`Authenticate` and `CreateSession` continue to accept the email address only.

A public handle is half of a credential pair that is published on purpose. Making
it a login identifier hands an attacker an enumerable, harvestable target list —
every visible `@handle` becomes a login to spray — and turns the account-lockout
ceiling into a denial-of-service tool aimed at anyone whose handle can be read.
The email identifier is private today, and that privacy is doing real work
alongside ADR-036's undifferentiated refusal.

Systems that permit both (GitHub, most social products) pay for it with
substantial secondary defence. That is a reasonable trade for a product whose
users expect it; it is not a trade to make by accident because the field happened
to exist.

## ADR-052 — `user_view.email_index` is unique among CURRENT holders, not among all rows

**Date:** 2026-08-20 · **Status:** Accepted

Migration 00008 gave `user_view.email_index` a bare `UNIQUE` constraint and
described it as "a backstop rather than the mechanism", on the reasoning that
uniqueness is enforced at write time by the reservation stream (ADR-044). The
reasoning is right. The constraint was still wrong, because it asserted a
property the domain has never guaranteed.

**What the domain guarantees is that at most one account HOLDS an address at any
instant. It does not guarantee that at most one account was ever registered with
it.** An unverified claim lapses after `app.DefaultReservationLease` — that lapse
is the entire bound on the squatting attack IDENTITY-REVIEW C8 leaves open — and
`EmailReservation.Reserve` then takes the lapsed claim over, recording
`EmailReleased` followed by `EmailReserved`. The previous holder's `Pending`
account is not deleted by a release and is not supposed to be: nothing in the log
says it ever went away.

So the designed squat-recovery path produces two `UserRegistered` events sharing
one email index, and the old constraint made that state unrepresentable. The
consequence was not a rejected write in a request handler:

```
projection: apply failed: ... UpsertUser: duplicate key value violates
unique constraint "user_view_email_index_key" (SQLSTATE 23505)
```

The `identity_user` projector stopped, and `projector -rebuild identity_user`
failed at the same event — so the table was no longer reconstructable by
replaying from position zero, which is the property every projection in this
codebase is required to have. **A constraint that turns a bounded 48h denial of
service into a permanently stalled projection is not a backstop.**

### The shape of the fix

`user_view` gains `email_released_at`, written from `EmailReleased` by the
account projection, and the constraint becomes partial:

```sql
CREATE UNIQUE INDEX user_view_email_index_held_key
    ON user_view (email_index) WHERE email_released_at IS NULL;
```

This keeps a real uniqueness guarantee and narrows it to the claim the domain
actually makes. It still fails closed on the case worth failing on: two
SIMULTANEOUS holders means the reservation stream admitted two winners, and the
projector stopping is the correct direction for that failure.

The superseded row keeps its `email_index` rather than having it blanked:

- It is not personal data — a keyed HMAC whose key is not in this database
  (ADR-048), so ADR-002 is satisfied by keeping it exactly as it is satisfied by
  keeping it on the live row.
- Blanking would need the column to become nullable, collapsing every abandoned
  registration into one indistinguishable class — replacing "this account used to
  hold that address" with "this account has no address", which is false.
- `''` is not available as a sentinel: `SetUserState` inserts a placeholder row
  with `email_index = ''`, so a blanked row would collide with that rather than
  with nothing.

### The read side moves with it, and that half is a security fix

`GetUserByEmailIndex` — the login lookup, and a `:one` query — gains
`AND email_released_at IS NULL`. Without it, two rows match after a
lapse-and-reclaim and `QueryRow` returns whichever the planner reached first: an
authentication attempt for the address could resolve to the SQUATTER's abandoned
account. That is a worse failure than the stalled projector, and unlike the
stalled projector it is silent.

### What this was NOT

The symptom — two `UserRegistered` events carrying one email index, minted
milliseconds apart during a run of `TestConcurrentRegistrationsForOneAddress` —
reads exactly like the reservation stream admitting two winners, and that was the
first diagnosis. It was wrong. The events belonged to
`TestALapsedReservationIsReleasedAndTheAddressIsRegisterableAgain`, which
registers an address, runs the sweep at an instant past the lease, and registers
it again on purpose. The `EmailReleased` between the two carried
`$causationId: identity.reservation.sweep:<index>:<expiry>` and a `ReleasedAt` 49
hours in the future — the sweep's own clock offset. Reading the stream's payloads
is what settled it; the ULID prefixes did not, because eight shared characters of
a ULID cover a 1024 ms window rather than one millisecond.

`MultiAppender.AppendToMany` was re-verified under real concurrency at the same
time — eight goroutines contending on one `NoStream` reservation stream, 320
trials — and it is atomic: exactly one winner every time, and no loser's
aggregate stream exists afterwards. See
`TestAtomicAppendUnderConcurrencyHasExactlyOneWinner`.

### Why the test that was supposed to catch this could not

`TestConcurrentRegistrationsForOneAddress` asserted
`SELECT count(*) FROM user_view WHERE email_index = $1` equals 1. Under the bare
`UNIQUE`, a second account for one address was not a second row — it was a
rejected INSERT that stopped the projector, after which the count still read 1.
**The assertion measured the projection, and the projection was the thing
concealing the duplicate.** It now asserts against `$all`, which cannot filter.

Demonstrated rather than argued: with the append precondition deliberately
removed so that all eight racers win, the run reports `accounts=1` from
`user_view` — the old assertion passing — while the log assertion reports eight
`UserRegistered` events for one address.
