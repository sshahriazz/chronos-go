# Conventions

**Where everything goes, and what may import what.** This is the document that
makes the first Go file writable.

Companion to [DECISIONS.md](DECISIONS.md) — that says *what* was decided, this
says *how it is expressed in the tree*.

---

## 1. Repository layout

```
chronos-go/
├── cmd/                        one directory per binary
│   ├── api/                    tenant ConnectRPC server
│   ├── operator/               operator plane — SEPARATE BINARY (ADR-024)
│   ├── worker/                 Temporal workers
│   ├── projector/              projection + reactor runners
│   └── migrate/                Atlas runner
│
├── proto/                      protobuf source (buf module)
│   └── chronos/
│       ├── options/v1/         custom RPC options: authz, operation, entitlement
│       ├── common/v1/          Page, Cursor, ErrorDetail, Money, Timestamps
│       ├── identity/v1/
│       ├── organization/v1/
│       ├── workspace/v1/
│       ├── access/v1/
│       ├── entitlement/v1/
│       ├── billing/v1/
│       ├── notification/v1/
│       └── operator/v1/
│
├── gen/                        GENERATED — never hand-edited, always committed
│   ├── proto/                  buf output
│   └── sqlc/                   sqlc output, per module
│
├── internal/
│   ├── platform/               THE KERNEL — imports no module, ever (ADR-001)
│   │   ├── eventsourcing/      Aggregate, EventStore port, Envelope, upcasters
│   │   ├── projection/         Projector, Checkpoint, Runner   (rebuildable)
│   │   ├── reactor/            Reactor                          (NEVER rebuilt, ADR-019)
│   │   ├── cqrs/               Command, Query, Bus, middleware
│   │   ├── authz/              Subject/Relation/Object, Checker, Lister ports
│   │   ├── crypto/             KeyRing, Encryptor, Shredder ports (ADR-028)
│   │   ├── pii/                Vault port, SubjectID             (ADR-002)
│   │   ├── ids/                typed IDs + prefix registry       (ADR-030)
│   │   ├── errs/               DomainError, reason codes         (§5)
│   │   ├── idem/               idempotency                       (§6)
│   │   ├── db/                 InTenantTx, RLS session vars      (ADR-011)
│   │   ├── clock/ money/ page/ validation/
│   │   ├── realtime/           Publisher + Presence ports        (ADR-026)
│   │   ├── blob/ mail/ workflow/
│   │   ├── config/             typed loader                      (ADR-008)
│   │   └── obs/                tracing, metrics, logging
│   │
│   ├── adapter/                implementations of KERNEL ports only (§1.1)
│   │   ├── kurrentdb/          → platform/eventsourcing.EventStore
│   │   ├── postgres/           → platform/db  (pool + InTenantTx machinery)
│   │   ├── openfga/            → platform/authz.Checker, Lister
│   │   ├── openbao/            → platform/crypto.KeyRing
│   │   ├── centrifugo/         → platform/realtime.Publisher, Presence
│   │   ├── temporal/  seaweedfs/  smtp/
│   │   └── (NOT stripe — see §1.1)
│   │
│   ├── server/                 cross-module server concerns (§1.2)
│   │   ├── connect/            ConnectRPC bootstrap, h2c, reflection
│   │   ├── interceptor/        THE GATE CHAIN (ADR-021, ADR-036)
│   │   └── health/             dependency registry + probes (ADR-010)
│   │
│   ├── modules/<module>/
│   │   ├── contract/           ★ THE ONLY PACKAGE OTHER MODULES MAY IMPORT
│   │   │   ├── events.go       published event types
│   │   │   ├── upcaster.go     schema-version chain (ADR-029)
│   │   │   ├── ids.go          typed IDs
│   │   │   └── ports.go        query ports — READ-ONLY by definition
│   │   ├── domain/             aggregates, invariants — PURE
│   │   ├── app/                ← CQRS split (§1.3)
│   │   │   ├── command/        load aggregate → decide → append (KurrentDB)
│   │   │   └── query/          read a projection (Postgres)
│   │   ├── adapter/
│   │   │   ├── eventstore/     aggregate load/append (write side)
│   │   │   ├── readmodel/      sqlc-backed queries (read side)
│   │   │   └── <vendor>/       e.g. billing/adapter/stripe
│   │   ├── projection/         projectors  — catch-up subs, REBUILDABLE
│   │   ├── reactor/            reactors    — persistent subs, NEVER rebuilt
│   │   ├── workflow/           Temporal workflows + activities (ADR-017)
│   │   ├── api/                Connect handlers + proto↔domain mapping
│   │   └── module.go           wire provider set
│   │
│   └── operator/               operator plane; NEVER imported by cmd/api
│
├── db/
│   ├── schema.sql              Atlas desired state
│   ├── migrations/             Atlas versioned migrations
│   └── query/<module>/         .sql files consumed by sqlc
│
├── test/
│   ├── harness/                stack wiring, per-suite namespace isolation
│   ├── fixture/                builders
│   ├── contract/               port fake ⟷ real adapter conformance (ADR-031)
│   └── e2e/
│
├── infra/  docs/  scripts/     (existing)
```

### 1.1 Which `adapter/` does a new integration go in?

One question decides it, mechanically:

> **Where is the port interface defined?**
> Defined in `platform/**` → `internal/adapter/`.
> Defined in `modules/<m>/app/` → `modules/<m>/adapter/`.

Follow the port; never the vendor.

| Integration | Port lives in | Adapter goes in | Transport (ADR-037) |
| --- | --- | --- | --- |
| KurrentDB | `platform/eventsourcing` | `internal/adapter/kurrentdb` | **gRPC** |
| OpenFGA | `platform/authz` | `internal/adapter/openfga` | **gRPC** (generated) |
| Centrifugo | `platform/realtime` | `internal/adapter/centrifugo` | **gRPC** |
| Temporal | `platform/workflow` | `internal/adapter/temporal` | **gRPC** |
| SeaweedFS | `platform/blob` | `internal/adapter/seaweedfs` | gRPC filer · S3 REST for bytes |
| OpenBao | `platform/crypto` | `internal/adapter/openbao` | HTTP (no gRPC exists) |
| Postgres pool / `InTenantTx` | `platform/db` | `internal/adapter/postgres` | pgx wire |
| **Stripe** | **`modules/billing/app`** | **`modules/billing/adapter/stripe`** | HTTPS |
| A module's SQL queries | that module's `app` | `modules/<m>/adapter/postgres` | pgx wire |

**Use gRPC wherever the dependency offers it** (ADR-037). Several of these HTTP
endpoints are a gRPC gateway in front of the gRPC service, so choosing HTTP pays
for a translation hop — on the authorization path that is the worst place in the
system to spend latency.

**Stripe is the clarifying case.** It is tempting to file it with the other
vendors, but there is no kernel "payments" port and there must not be — only
`billing` knows what a subscription is. Putting Stripe in the kernel would drag
commercial concepts into a package that must stay domain-free (ADR-001).

**The two layers compose rather than compete.** A module's Postgres adapter
holds the *queries*; the kernel's holds the *connection and transaction
machinery*. Module adapters call `platform/db.InTenantTx` and never open a
connection themselves — which is also what makes the RLS rule unbypassable
(ADR-011).

### 1.2 Why `internal/server/` exists

The interceptor chain, the health/probe endpoints and the dependency registry are
**cross-module**: they consult `access`, `organization` and `entitlement`. They
belong to neither `platform/` (which must not know a module exists) nor any one
module. Without a home they end up in `cmd/api`, where they cannot be tested.

### 1.3 The CQRS split is structural, not conventional

The two sides share nothing:

| | Command side | Query side |
| --- | --- | --- |
| Reads from | KurrentDB aggregate stream | Postgres projection |
| Writes to | KurrentDB (append) | nothing |
| Consistency | optimistic concurrency on revision | eventually consistent |
| Adapter | `adapter/eventstore/` | `adapter/readmodel/` |

Separate packages so a query handler cannot quietly acquire an aggregate load —
which is how CQRS erodes in practice, one "just this once" at a time.

### 1.4 Subscription type follows the consumer type

| Consumer | Subscription | Checkpoint | Rebuildable |
| --- | --- | --- | --- |
| **Projector** | catch-up on `$all` | ours, in the same tx as the rows | **yes** |
| **Reactor** | **persistent** | **KurrentDB's**, with ack/nack + parking | **never** |

This makes ADR-019 structural: a persistent subscription has no rebuild API to
call by accident, and its parking queue gives poison handling for free instead of
reimplemented in Go.

### 1.5 Recurring work uses Temporal Schedules

Schedules for anything periodic — scavenging, reconciliation, digests, retention
sweeps — because they can be paused, backfilled and given an overlap policy
during an incident. Workflows for one-shot and entity-lifecycle processes. A
workflow looping on a timer is a Schedule reimplemented badly.

---

## 2. The import contract

Enforced by `depguard` in CI, not by review. A violation fails the build.

| Package | May import | Must never import |
| --- | --- | --- |
| `platform/**` | stdlib, tiny generic libs | **any module**, any driver/SDK |
| `modules/*/domain` | stdlib, `platform/**` | drivers, `gen/**`, other modules, `net/http`, `encoding/json`, `database/sql` |
| `modules/*/app` | own `domain`, `platform/**`, own `contract` | drivers, `gen/proto` |
| `modules/*/adapter` | own `app` (ports), `platform`, drivers, `gen/sqlc` | other modules' internals |
| `modules/*/api` | own `app`, `gen/proto`, `platform` | own `domain` directly, other modules |
| `modules/*/contract` | `platform/ids`, stdlib | **everything else** — it must stay tiny |
| `modules/A/**` | `modules/B/contract` **only** | any other `modules/B/**` |
| `internal/operator/**` | module `contract`s, `platform` | — |
| `cmd/api` | modules, platform, adapter | **`internal/operator/**`** |

### The three rules that matter most

1. **`domain/` may not import `encoding/json` or `gen/proto`.** A struct with
   `json:` tags or a generated protobuf type has let a wire format dictate the
   shape of a business rule. Serialization belongs to adapters.
2. **Cross-module access goes through `contract/` only.** If module A needs
   something from B that isn't in B's contract, either it belongs in the
   contract or A shouldn't need it.
3. **`cmd/api` must not link `internal/operator`.** A conformance test asserts
   this against the built binary (ADR-024).

### Causation, not just imports

Imports are only half the boundary. The other half:

> **A module never invokes another module's commands.** It subscribes to their
> `contract` events and issues commands to *itself*.

So billing does not activate an organization — `organization` runs a reactor on
billing's `PaymentConfirmed` and issues its own `ActivateOrganization` command.
Query ports exposed in `contract/` are **read-only by definition**; a port that
mutates has smuggled a cross-module command past the rule.

### Ports are declared by the consumer

`app/` defines the interface it needs; `adapter/` satisfies it. Never the
reverse. This is what keeps the dependency arrow pointing inward and makes every
use case testable with a fake.

---

## 3. Events

### Naming

Past tense, no prefix, no suffix: `MemberInvited`, `PasswordChanged`,
`SubscriptionActivated`. Never `UpdateMember`, never `MemberInvitedEvent`.

Wire type is `<module>.<Name>.v<N>` — `workspace.MemberInvited.v2`.

### Envelope

Every event carries, outside the payload:

```
event_id        ULID — the idempotency key for every consumer
type            workspace.MemberInvited.v2
schema_version  2
occurred_at     UTC (ADR-008)
subject_ids     [] — pseudonyms only, NEVER personal data (ADR-002)
org_id          tenant scope
workspace_id    workspace scope; empty on org-level facts
residency       region tag (ADR-035)
correlation_id  the originating request
causation_id    the event or command that produced this one
```

`workspace_id` rides in the envelope rather than being parsed back out of the
stream name: every workspace-owned read model has an RLS policy checking **both**
columns (ADR-020), and a projector must be able to scope itself from the event
alone — during a rebuild there is nothing to look it up in.

### Payload rules

- **No personal data.** Ever. Only `SubjectID` pseudonyms; the vault resolves
  them at the point of use (ADR-002).
- No enums as raw ints — string constants, so a reordered enum cannot rewrite
  history.
- No `time.Time` zero values as "unset"; use an explicit optional.
- No embedded aggregate state — events record *what changed*, not a snapshot.

### Versioning by upcasting (ADR-029)

```go
// registered in the same commit as the schema change
func upcastMemberInvitedV1toV2(v1 []byte) ([]byte, error)
```

- Stored events are **never rewritten**, including "harmless" backfills.
- A new `schema_version` without a registered upcaster **fails the build**.
- Retiring a version captures a **golden fixture** of real payloads; the chain is
  tested against those fixtures forever.

---

## 4. Identifiers (ADR-030)

```
org_01H8XG5N2QK7VB3C9WPYZR4TFM
```

| Prefix | Type | Prefix | Type |
| --- | --- | --- | --- |
| `org_` | Organization | `sub_` | Subscription |
| `ws_` | Workspace | `plan_` | Plan |
| `usr_` | User | `pv_` | PlanVersion |
| `team_` | Team | `inv_` | Invitation |
| `sess_` | Session | `key_` | ApiKey |
| `notif_` | Notification | `evt_` | Event |

- The prefix registry lives in `platform/ids` and is the single source of truth.
- Parsing **validates the prefix**: a workspace ID passed where an org ID is
  expected is an `invalid_argument` at the boundary, not a not-found three layers
  down.
- Go types are distinct (`OrgID` ≠ `WorkspaceID`) so the compiler catches it too.
- ULIDs are time-ordered and therefore leak approximate creation time. Fine for
  tenant-scoped resources; anything where that matters uses a random ID.

---

## 5. Errors

`platform/errs.DomainError` carries a **reason**, mapped once to a Connect code
at the API boundary. Handlers never construct transport errors.

| Reason | Connect code | Meaning | User action |
| --- | --- | --- | --- |
| `UNAUTHENTICATED` | `Unauthenticated` | no/invalid session | sign in |
| `STEP_UP_REQUIRED` | `PermissionDenied` | AAL too low | re-authenticate |
| `ACCESS_DENIED` | `PermissionDenied` | authorization said no | **ask an admin** |
| `PLAN_UPGRADE_REQUIRED` | `FailedPrecondition` | feature not in plan | **upgrade** |
| `QUOTA_EXCEEDED` | `FailedPrecondition` | limit reached | reduce or upgrade |
| `ORG_SUSPENDED` | `FailedPrecondition` | payment state | pay |
| `NOT_FOUND` | `NotFound` | absent, or invisible | — |
| `CONFLICT` | `Aborted` | optimistic concurrency | retry |
| `VALIDATION_FAILED` | `InvalidArgument` | protovalidate or domain | fix input |
| `RATE_LIMITED` | `ResourceExhausted` | throttled | back off |
| `INTERNAL` | `Internal` | ours | — |

**The gate distinction is the point.** `ACCESS_DENIED` and
`PLAN_UPGRADE_REQUIRED` are completely different user journeys — "ask an admin"
versus "upgrade" — so a generic 403 for both is a product bug, not a shortcut.

### 5.1 Which error may I return? — the disclosure ladder (ADR-036)

ADR-015 says forbidden and not-found must be indistinguishable; entitlement.md
says a generic 403 is a bug. Both hold, at different rungs:

> **A caller may be told exactly as much as the last gate they passed entitles
> them to know.**

The **authz gate is the boundary**. Fail below it and every response is
`NOT_FOUND`. Fail at or above it and the caller has proven they belong, so the
error must be specific and actionable.

At the authz gate itself, one extra check decides:

```
authz denies (principal, relation, resource):
    can the principal see the resource's PARENT?
        yes → ACCESS_DENIED    they know it exists — tell them the truth
        no  → NOT_FOUND        they must not learn it exists
```

Mechanical, not a judgment call: the parent edge is the ADR-006 topology, and
each registered type declares a **minimum-visibility relation** for this check.
It runs **in the interceptor** — handlers are never consulted, so they cannot
get it wrong — and costs one `Check` on the denial path only.

**Outward errors are opaque.** Reason plus stable metadata. No SQL, no driver
text, no stack traces — those go to logs correlated by trace ID (ADR-015).

---

## 6. Idempotency

Gate 5 of the pipeline (ADR-021).

- Header: `Idempotency-Key` — client-generated ULID or UUID.
- **Required** on every mutating RPC; the interceptor rejects a mutation without
  one.
- Scope: `(principal, full_method, key)`.
- Stored with a hash of the request body and the serialized response.
- **Replay** with the same key and same body ⇒ the stored response, not a
  re-execution.
- Same key, **different** body ⇒ `CONFLICT`. This catches client bugs rather
  than silently returning someone else's answer.
- TTL 24h in Postgres.
- In-flight duplicates take a lock and wait, so a double-click cannot execute
  twice concurrently.

Distinct from **event-level** idempotency, where consumers dedup on `event_id`
(ADR-019). Both exist; they solve different problems.

---

## 7. API conventions

- **Package**: `chronos.<module>.v1`. Version at the package, never per message.
- **Service naming**: `WorkspaceService`, RPCs are verb-first — `CreateWorkspace`,
  `ListMembers`, `InviteMember`.
- **Every RPC declares its policy** or the server refuses to boot (ADR-021):

```protobuf
rpc InviteMember(InviteMemberRequest) returns (InviteMemberResponse) {
  option (chronos.authz)       = { relation: "admin", resource: "workspace" };
  option (chronos.operation)   = OPERATION_GROW;
  option (chronos.entitlement) = "seats.member";
  option (chronos.min_aal)     = AAL_1;
}
```

- **Validation is declarative** — protovalidate rules in the `.proto`. Handlers
  never hand-check required fields.
- **Pagination is cursor-based everywhere**: `page_size`, `page_token` →
  `next_page_token`. No offsets — they break under concurrent writes and cannot
  use the keyset indexes (ADR-013).
- **Proto is a DTO, never a domain type.** `api/` maps both directions.
- Timestamps are `google.protobuf.Timestamp`, always UTC.
- Money is minor units + currency code, never a float or a formatted string.

### 7.1 API documentation is a build artifact, not a chore

The schema is the product surface. Documentation is generated from it and gated
in CI, so it cannot drift from behaviour.

| Rule | Enforcement |
| --- | --- |
| **`buf breaking` against `main`** | a breaking change **fails the build**, not review |
| `buf lint` | style and naming |
| **Comments mandatory** on every service, RPC, message, field | lint rule — an undocumented field ships forever |
| Reference docs generated per version | CI publishes on merge |
| **Reason-code catalogue generated from the server's own enum** | docs and behaviour cannot disagree |
| Worked example per RPC | reviewed with the RPC |
| Client SDKs | generated by buf, versioned with the API |
| Deprecation | `[deprecated = true]` + documented sunset; **never removed inside a version** |

Two of these deserve emphasis.

**The reason-code catalogue is part of the API contract.** Clients branch on
`PLAN_UPGRADE_REQUIRED` versus `ACCESS_DENIED` to show completely different UI
(§5.1). If those codes are not published, every client hardcodes strings scraped
out of live responses, and changing one silently breaks them.

**The declared gates are rendered into the docs.** Each RPC's required
permission, operation class and entitlement come from the same protobuf options
the interceptors read (ADR-021), so *"what permission does this endpoint need?"*
is answered by the schema rather than by reading the source. That is the payoff
of declaring enforcement rather than writing it.

---

### Aggregates and snapshots (ADR-039)

- An aggregate that will accumulate events implements `Snapshotter`. One that
  will not, does not — a repository with snapshots configured is inert for it.
- `Snapshot()` returns **complete** state. A partial snapshot is worse than none.
- `Restore()` REJECTS a snapshot it does not recognise. Falling back to a full
  replay is always safe; restoring half a schema is not.
- Snapshot types are registered with the codec like any other event and are
  versioned the same way.

### Consuming the log

- `ResolveLinkTos` belongs on reads of link streams (`$ce-`, `$et-`) and
  **nowhere else**. On `$all` it resolves the system projections' link events
  back to the same originals and delivers every event four times (ADR-019).
- A projector filters `$all` and owns its checkpoint; a reactor consumes a
  persistent subscription and the server owns the checkpoint. Never mix them.
- A reactor's `React` must tolerate running twice. Return `ErrPoison` for events
  that can never succeed, so they park instead of consuming every retry.

## 8. Database

- **Migrations**: Goose, embedded in `cmd/migrate` via `embed.FS` so an image
  cannot drift from a mounted directory (ADR-011). They are **append-only**,
  enforced by `scripts/check_migrations.sh` in `make check`: a file may be
  added, never modified, renamed or deleted.
- **Queries**: `.sql` files under `db/query/<module>/`, generated by sqlc, which
  validates every query against the real schema at generate time — a renamed
  column fails `make check`, not production. **No SQL string appears in Go
  source**, enforced by `scripts/check_sql.sh`.

  Schema comes from the goose migrations themselves rather than a separate
  desired-state file: a second description of the schema is a second thing to
  keep in sync.

  `emit_exported_queries: true`, because a projector **queues** statements into
  one pipelined round trip (ADR-019) and cannot call a generated method that
  executes immediately. It queues the generated *constant* instead — authored in
  `.sql`, schema-checked, absent from Go.

  Platform-owned tables (`projection_checkpoint`, `reactor_processed`) generate
  into `gen/sqlc/platform`; module tables into `gen/sqlc/<module>`.

  **The one carve-out** is database *primitives*: `set_config`,
  `pg_try_advisory_lock`, `pg_roles` inspection. They are not queries against our
  schema, so sqlc has nothing to validate them against and expressing them as
  `.sql` would add ceremony without adding verification. They are confined to
  `internal/adapter/postgres/{tx,batch,lease,postgres}.go`; the guard fails if
  SQL appears anywhere else.
- **Every query runs inside `InTenantTx`**, which sets `SET LOCAL app.org_id` /
  `app.workspace_id` / `app.user_id` — reads included. There is no bypass API.
- Every tenant-scoped table carries **both** `org_id` and `workspace_id`
  (ADR-020), plus `residency` (ADR-035).
- `FORCE ROW LEVEL SECURITY`; the app role is neither owner nor superuser.
- Composite indexes lead with `org_id`. Keyset pagination indexes match sort
  order exactly. A sequential scan on a tenant-scoped table fails migration
  review.
- **A projection may write but never read.** `Apply` receives a `db.Writer`,
  which only queues statements. This ships every statement for an event in one
  round trip, and it removes read-modify-write from projectors — logic that is
  not replay-safe, because the same event against a different starting state
  produces a different result. Express it in SQL instead.
- **Projected writes use `db.Replayable`** (`synchronous_commit = off`). The read
  model is derived and rebuildable (ADR-013); the PII vault and every other
  system of record use `db.Durable`.
- One projector owns one table. Two writers to one projection is banned — it
  makes rebuild order undefined, and the advisory lease enforces it at runtime.
- **Every read-model table grants `TRUNCATE` to the app role.** A rebuild empties
  the table from an unscoped system transaction, which under RLS can see no rows
  and would therefore `DELETE` none — leaving a "rebuilt" projection full of its
  old contents. `TRUNCATE` is a table-level operation and is not filtered by row
  security (ADR-019).

---

## 9. Testing (ADR-031)

| Tier | Location | Infrastructure |
| --- | --- | --- |
| Domain | `modules/*/domain/*_test.go` | none |
| Use case | `modules/*/app/*_test.go` | in-memory port fakes |
| Adapter | `modules/*/adapter/*_test.go` | **shared compose stack** |
| Contract | `test/contract/` | both fake and real |
| E2E | `test/e2e/` | full stack |

**Isolation is by namespace, not by container**: a fresh Postgres schema, a fresh
OpenFGA store, a KurrentDB stream prefix and a Valkey key prefix per suite. Every
suite must therefore be parallel-safe by construction.

**Contract tests are what keep fakes honest.** Each port fake and its real
adapter run the *same* suite; without that, fakes drift and green tests stop
meaning anything.

`testing/synctest` (Go 1.27) for concurrent logic — virtual time, deterministic,
no sleeps. Prefer `synctest.Sleep`, added in 1.27, over `time.Sleep` followed by
`synctest.Wait`: it is the same two steps with no window between them to forget.
`httptest.NewTestServer` (also 1.27) gives a synctest-compatible in-memory server,
so an HTTP test no longer has to leave the virtual clock to talk to a real port.

`goroutineleak` profiling, given how many long-lived subscriptions this design
implies. **It went generally available in Go 1.27** (`runtime/pprof`, and the
`/debug/pprof/goroutineleak` endpoint); the `goroutineleakprofile` GOEXPERIMENT
that gated it in 1.26 is deleted. Its documented limitation is worth knowing
before trusting it: it may miss a leak reachable through a global variable, or
through a runnable goroutine's locals.

**TDD order**: failing domain test → domain → failing use-case test → use case →
adapter → API.

---

## 9.1 The Go version, and what it changes

**Go 1.27.x.** `go.mod` declares `go 1.27.0`, and that declaration is load-bearing
rather than cosmetic — it is what makes `encoding/json/v2` usable at all.

**`encoding/json/v2` is stdlib now.** It graduated from `GOEXPERIMENT=jsonv2` in
1.27 and is gated on the module's language version instead. `internal/platform/codec`
needs no build flag; a comment or document still telling someone to set
`GOEXPERIMENT` is stale, and the opt-out went the other way (`GOEXPERIMENT=nojsonv2`,
expected to be removed). ADR-047 is unchanged in substance: all JSON goes through
the one kernel package.

**Run the modernizers.** `go fix ./...` applies every registered analyzer by
default — `waitgroupgo` (`wg.Add(1)`/`go`/`wg.Done()` → `wg.Go`), `newexpr`
(`new(expr)`, so a local `ptr[T]` helper is now dead weight), `slicesbackward`,
`atomictypes`, `unsafefuncs`, `stringscut`, `rangeint` and the rest. It does NOT
see files behind a build tag, so integration-tagged code needs
`go fix -tags=integration` explicitly — the same blind spot that let
integration tests break invisibly before `make check` gained `vet-integration`.

**One exception, and the reason for it: `-embedlit=false`.** Go 1.27 allows a
struct literal key to be any field selector, and the `embedlit` modernizer
rewrites nested literals into that form. `staticcheck` (honnef.co/go/tools
v0.7.0, vendored inside golangci-lint) cannot parse it and does not degrade
gracefully — it panics:

```
buildir: package "reactor_test": unexpected expr: *ast.KeyValueExpr
```

which takes the whole lint run down. Keep `embedlit` disabled until staticcheck
supports the syntax. This is a tooling lag, not a style judgement; the rewrite
itself is correct.

**Build the linter from source, never from a release binary.** golangci-lint's
published binaries are compiled with whatever Go that release used, and a linter
built with an older Go cannot typecheck a module declaring a newer one — again by
panicking, not by reporting:

```
panic: file requires newer Go version go1.27 (application built with go1.26)
```

`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.13.0`
compiles it with this module's toolchain. CI does the same.

**v2.13.0 is a floor, not a preference.** v2.12.2 cannot typecheck a **generic
method** (Go 1.27): a package calling one on a type from another package — loaded
from export data — reports `d.On undefined (type *projection.Dispatch has no
field or method On)` while `go build` accepts it, and gosec's SSA pass panics on
the type parameter outright. Anything below v2.13.0 therefore rejects code the
compiler accepts. A related landmine survives even on v2.13.0: taking a generic
method VALUE (`f := d.On[T]`) still panics staticcheck's IR builder. Plain calls
are fine; no code here takes one.

---

## 10. Naming and style

- Packages: singular, lowercase, no underscores (`workspace`, not `workspaces`).
- No `util`, `helper`, `common`, `misc` packages — they are where cohesion goes
  to die. Name the concept.
- Files mirror the type: `invitation.go`, `invitation_test.go`.
- Interfaces are named for behaviour (`Checker`, `Mailer`), not `IThing`.
- Constructors return concrete types; **accept interfaces, return structs**.
- `context.Context` first parameter, always; never stored in a struct.
- Errors wrap with `%w` and carry a reason from §5.

---

## 11. Observability

- **Trace span** per RPC (via `otelconnect`) and per use case; span name is the
  full RPC method or `module.UseCase`.
- **Structured logs** with a fixed base field set: `trace_id`, `org_id`,
  `principal_id` (pseudonym), `module`, `reason`. Never an email, never a token,
  never a raw payload.
- **Metric names** are `chronos_<module>_<thing>_<unit>`, so every dashboard
  query can be written from the module name alone.
- Personal data reaches logs only via a `Redactable` type, which makes logging a
  raw email a compile-time-visible mistake rather than a review-time one.
