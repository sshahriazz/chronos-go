# Event Sourcing with KurrentDB

How this system uses the event store, and the data flows that follow from it.

Everything marked **✅ verified** was measured against the running KurrentDB
`26.1.2`. Reproduce with
[`docs/evidence/kurrentdb-semantics-probe.py`](evidence/kurrentdb-semantics-probe.py)
(12/12 pass).

---

## 1. Verified semantics

| Behaviour | Result | What it buys us |
| --- | --- | --- |
| Append with `ExpectedVersion=NoStream` (-1) to a new stream | `201` | aggregate creation is atomic |
| **Stale expected version** | **`400`** | **the aggregate consistency boundary** |
| Correct expected version | `201` | |
| **Replay: same `eventId` + same expected version** | **`201`, no duplicate** | **command retries are safe** |
| Second claim on an existing stream with `NoStream` | **`400`** | **atomic uniqueness reservation** |
| `$ce-<category>` read | **`404`** | category streams need projections — **we have none** |
| `$all` contents | includes `$$`/`$` system events | **projector filters must exclude them** |
| Stream metadata (`$maxCount`) | `201` | snapshot-stream pattern available |
| Soft delete → append | `204` then `201` | streams are reopenable |

Two of these directly shape the architecture: **no category streams** (§4) and
**idempotent append** (§3).

---

## 2. Stream design

### Naming

```
<category>-<id>
organization-01H8XG5N2QK7VB3C9WPYZR4TFM
```

The **category is everything before the first dash** — a KurrentDB convention,
not ours. Two consequences:

- **IDs must not contain a dash.** ULIDs (Crockford base32) do not. Prefixed
  public IDs (`org_01H8…`, ADR-030) use an underscore precisely so the prefix
  never becomes a category.
- Category names are lowercase singular and stable forever: `organization`,
  `workspace`, `user`, `session`, `apikey`, `invitation`, `team`,
  `subscription`, `plan`, `notification`.

### One aggregate = one stream = one consistency boundary

There are **no cross-stream transactions**. This is not a limitation to work
around; it is the rule that makes aggregate boundaries real. If an invariant
spans two streams, either it belongs in one aggregate or it is not an invariant —
it is a process, and processes are Temporal workflows (ADR-017).

This is why `Organization` holds the owner and admin set inside the aggregate
while membership lives elsewhere (organization.md §2): the "at least one owner"
invariant must be enforceable in a single append.

---

## 3. Writing: optimistic concurrency and idempotency

```
load stream → rebuild aggregate → decide → append at expectedVersion
                                              │
                                              ├── 201  committed
                                              └── 400  WrongExpectedVersion
                                                       → reload, re-decide, retry
```

**✅ Verified**: a stale expected version is rejected. That rejection *is* the
concurrency control — no locks, no `SELECT … FOR UPDATE`.

### Idempotent append is a feature, and we exploit it

**✅ Verified**: re-appending the same `eventId` at the same expected version
returns `201` and does **not** duplicate the event.

So event IDs are **derived deterministically**, never random:

```
eventId = uuidv5(namespace, commandIdempotencyKey + ":" + sequenceInCommand)
```

A retried command therefore produces byte-identical event IDs, and the store
collapses the duplicate itself. This is the layer beneath the idempotency gate
(CONVENTIONS §6): the gate stops the work, and this stops the damage if the gate
is bypassed by a crash mid-append.

### Retry policy

`WrongExpectedVersion` is **retried with reload**, bounded (3 attempts), and
surfaced as `CONFLICT` (CONVENTIONS §5) if it persists. It is expected under
concurrency, not an error condition.

---

## 4. Reading: `$all`, not category streams

**✅ Verified**: `$ce-organization` returns `404`. Category streams are produced
by the `$by_category` system projection, and we run
`KURRENTDB_RUN_PROJECTIONS=None` deliberately (INFRA.md §1).

So every subscriber reads **`$all` with a server-side filter**:

```
subscribe $all
  filter: streamNamePrefix ∈ { "organization-", "workspace-", … }
       or eventTypePrefix  ∈ { … }
  from: stored commit position
```

| | `$ce-` category streams | **`$all` + filter** |
| --- | --- | --- |
| Needs projections | yes | **no** |
| Ordering | per category | **global** |
| Extra writes | a link event per event | **none** |
| Cross-aggregate ordering | not guaranteed | **guaranteed** |

The global ordering is worth more than the convenience. A projection joining
`organization` and `workspace` events sees them in true commit order, so
"member added before workspace created" cannot occur — a class of bug that
category streams would reintroduce.

> **✅ Verified and load-bearing: `$all` carries system events**, including `$$`
> metadata streams. Every filter **must** exclude `$`-prefixed streams, or the
> first projector to run will try to deserialize `$metadata` as a domain event.

---

## 5. Uniqueness: the reservation stream

An event store has no unique index. Email addresses, org slugs and team names
still need one.

**✅ Verified pattern** — the stream name *is* the constraint:

```
stream:  reservation_email-alice@example.com
append with ExpectedVersion = NoStream

  first caller  → 201   claim granted
  second caller → 400   claim refused, atomically
```

Note `reservation_email` uses an underscore so the category stays stable.

Rules:

- Reserve **before** the aggregate append; release on failure.
- Changing a value = reserve the new, append the change, release the old — in a
  **Temporal workflow**, because it spans three appends and must not half-happen.
- Release is a soft delete, so the value can be reclaimed later (✅ verified
  reopenable).
- The Postgres projection also carries a unique index. Belt and braces: the
  reservation makes it *atomic*, the index makes it *checkable*.

**Erasure interaction (D3):** erasure destroys the subject key, so the blind
index is meaningless and the reservation is released. The address becomes
available again, and a returning person gets a fresh `SubjectID`. Retaining a
permanent block would mean keeping exactly the data erasure was meant to remove.

---

## 6. Subscriptions: projector vs reactor

The distinction from ADR-019, expressed in KurrentDB primitives:

| | **Projector** | **Reactor** |
| --- | --- | --- |
| Subscription | **catch-up** on `$all` | **persistent** |
| Checkpoint | ours, committed **in the same Postgres tx as the rows** | **KurrentDB's**, server-held |
| Rebuild | drop tables, restart from position 0 | **impossible — no rebuild API** |
| Failure handling | retry, then halt the projector | **nack → park** (poison queue) |
| Parallelism | single consumer, ordered | competing consumers |
| Produces | rows | **side effects** — email, push, workflows |

Using persistent subscriptions for reactors makes ADR-019 **structural**: there
is no "rebuild" call to make by accident, and the parking queue gives poison
handling without writing any.

### Projector checkpointing

```sql
BEGIN;
  -- projected rows
  INSERT INTO member_view …;
  -- checkpoint, same transaction
  UPDATE projection_checkpoint
     SET commit_position = $1, prepare_position = $2
   WHERE name = 'member_view';
COMMIT;
```

Atomic with the rows it describes — the property that makes replay idempotent
and restart safe. A checkpoint in Valkey or in a separate transaction breaks it.

---

## 7. Snapshots — only when measured

KurrentDB has no built-in snapshots. The convention:

```
stream:   <category>-<id>-snapshot
metadata: { "$maxCount": 1 }     ← ✅ verified accepted
```

**Not built by default.** Aggregates here are short — an organization has tens of
events, a session a handful. Snapshots are added only when a stream is measured
long enough to matter, and the snapshot records the version it was taken at so
load is *snapshot + events since*.

The one aggregate likely to need it eventually is `Session` on a busy account;
`UsageCounter` is deliberately not an aggregate for this reason.

---

## 8. Event envelope

Stored alongside the payload, in event metadata:

```json
{
  "$correlationId": "…",   "$causationId": "…",
  "schemaVersion": 2,
  "orgId": "org_…",  "residency": "eu",
  "subjectIds": ["sub_…"],
  "occurredAt": "2026-08-08T09:14:22Z"
}
```

`$correlationId` and `$causationId` use KurrentDB's reserved names so its own
tooling can trace causation chains. `schemaVersion` drives the upcaster chain
(ADR-029). **No personal data**, ever (ADR-002).

---

## 9. Data flows

### Write path

```
Connect RPC
  → interceptors: authn → org-ctx → authz → subscription → entitlement → idem
  → app/command
      ├── reserve uniqueness            (§5, if needed)
      ├── load aggregate                adapter/eventstore  ← KurrentDB
      ├── domain.Decide()               PURE — no I/O
      └── append at expectedVersion     KurrentDB  ✅ concurrency boundary
  → return: id + consistency token (commit position)
```

The handler **never writes to Postgres**. It never calls another module.

### Read path

```
Connect RPC → interceptors → app/query → adapter/readmodel → Postgres (sqlc)
                                              ↑
                                   InTenantTx: SET LOCAL app.org_id  (RLS)
```

Never loads an aggregate. Never reads KurrentDB.

### Projection path

```
KurrentDB $all (catch-up, filtered)
   → projector
       BEGIN
         upsert rows
         update checkpoint          ← same tx
       COMMIT
   → publish to Centrifugo          ← realtime, after commit
```

### Reaction path

```
KurrentDB (persistent subscription)
   → reactor  — dedup on eventId
       ├── start Temporal workflow (workflowId = eventId → idempotent)
       ├── write OpenFGA tuples        (access)
       └── send mail / push            (notification)
   → ack   |   nack → park
```

### Cross-module causation

```
billing:      PaymentConfirmed  ──► published to $all
organization: reactor on billing/contract.PaymentConfirmed
                 → issues its OWN ActivateOrganization command
                 → OrganizationActivated
access:       projector on organization/contract.OrganizationActivated
                 → writes the `owner` tuple
```

**No module ever calls another's command.** Three modules cooperate and none
imports the other's internals — only `contract` (CONVENTIONS §2).

---

## 10. Operational constraints

| Constraint | Consequence |
| --- | --- |
| Append size is capped (default ~1 MiB per append) | large payloads go to SeaweedFS; events carry a reference |
| Scavenging is licence-gated | scheduled Temporal workflow (ADR-032) |
| Soft-deleted streams stay in `$all` until scavenged | projectors must tolerate events from deleted streams |
| Projections disabled | no `$ce-`, no `$et-`, no `$streams` — `$all` + filters only |
| `$all` position is a **pair** (commit, prepare) | checkpoints store both |

---

## 11. What we deliberately do not do

- **No server-side JavaScript projections.** A second runtime, untyped, with its
  own failure modes.
- **No category or event-type streams** — they need those projections, and `$all`
  filtering is strictly better for cross-aggregate ordering.
- **No event rewriting**, including backfills (ADR-029). Upcast on read instead.
- **No aggregate spanning streams.** If an invariant needs two streams, it is a
  process, not an invariant.
- **No reading the event store on the query path.** Ever. That is what
  projections are for.
