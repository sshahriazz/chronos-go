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
| `$ce-<category>` read | **works** | requires `RUN_PROJECTIONS=System` + `ResolveLinkTos` (corrected 2026-08-08) |
| `$all` contents | includes `$$`/`$` system events | **projector filters must exclude them** |
| Stream metadata (`$maxCount`) | `201` | snapshot-stream pattern available |
| Soft delete → append | `204` then `201` | streams are reopenable |

Two of these directly shape the architecture: **link streams are available**
(§4, corrected) and **idempotent append** (§3).

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

## 4. Reading: `$all` live, link streams to rebuild

Two different jobs, two different sources.

**Live subscriptions read `$all` with a server-side filter.** The global commit
ordering is the point: a projection joining `organization` and `workspace` events
sees them in true commit order, so "member added before workspace created" cannot
occur — a class of bug per-category ordering would reintroduce.

```
subscribe $all
  filter: streamNamePrefix ∈ { "organization-", "workspace-", … }
       or eventType        ∈ { … }          (anchored, whole types)
  from: stored commit position
```

**Rebuilds read link streams.** A rebuild replays one projection's own slice and
does not need cross-aggregate ordering within it, so scanning the whole log is
pure waste. See "Rebuild reads the narrowest link stream available" below.

> **✅ Verified and load-bearing: `$all` carries system events**, including `$$`
> metadata streams. Every filter **must** exclude `$`-prefixed streams, or the
> first projector to run will try to deserialize `$metadata` as a domain event.

### How this section used to read, and why that matters

Until 2026-08-08 this section was titled "**`$all`, not category streams**" and
stated that `$ce-organization` returns `404`, citing a verified probe.

The probe was real. Its cause was our own compose file setting
`KURRENTDB_RUN_PROJECTIONS=None`, which disables every projection. The ADR bans
*user JavaScript* projections, which need `All`; `System` runs only the built-in
native ones and no JS. With `System`, `$ce-` and `$et-` both work — and reads must
set `ResolveLinkTos`, because a link stream holds links, not the originals.

So the document verified a misconfiguration and enshrined it as a property of the
server, and every rebuild paid for it. Measured after the fix, on a 20,000-event
log where the projection wants 1,000 (5%):

| Strategy | Time | Note |
| --- | --- | --- |
| `$all`, filtered client-side | 726 ms | transfers the whole log — never what we shipped |
| `$all`, filtered server-side | 253 ms | what we shipped |
| **`$ce-` category read** | **17 ms** | **14.8x faster** |

The first row is kept because the original comparison used it and overstated the
win as 29x. Server-side filtering already avoids transferring non-matching events;
the remaining 14.8x is the server not having to *scan* them.

This is the origin of the working rule: **probe the system, do not recall it** —
and when a probe disagrees with expectation, suspect the configuration before the
vendor.

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

#### Rebuild reads the narrowest link stream available

A rebuild does not need the global commit ordering a live subscription gives, so
it skips the rest of the log entirely:

| Filter resolves to | Rebuild source |
| --- | --- |
| exactly one whole event type | `$et-<type>` |
| exactly one category | `$ce-<category>` |
| anything else | `$all`, correct and slow |

Measured on the running server — 2000 events in one category, 200 of the wanted
type:

| Source | Events read | Time |
| --- | --- | --- |
| `$et-<type>` | 200 | 7.1 ms |
| `$ce-<category>` | 2000 (1800 discarded) | 105.3 ms |
| `$all` + filter | 200 | 3.17 s |

`$et-` is 14.7x faster than `$ce-` here because a category carries every type its
aggregate emits. The `$all` figure scales with TOTAL log size, not with the
projection's slice, which is the whole reason link streams exist.

**Exactly one, in both cases.** Reading two link streams in sequence applies every
event of the first before any of the second, so a projection that joins across
types would rebuild into a different state than it holds live.

**Whole types only, never prefixes.** There is no `$et-` stream for a prefix, and
`x.Created.v1` used as one also selects `x.Created.v10`. `SubscriptionFilter`
therefore separates `EventTypes` (whole) from `EventTypePrefixes`, and the
server-side filter for the former is an anchored regex rather than a prefix match.

#### The other kind of checkpoint: scanned, not applied

A filtered `$all` subscription also emits `CheckPointReached` for spans the
server scanned and found **no match** in. Those are persisted too, on their own,
because there are no rows to be atomic with — nothing was projected.

This is not an optimisation to skip. Without it a projection's position advances
only on a match, so a projector filtered to a quiet module stands still while the
rest of the system writes, and every restart re-scans the whole log since its last
match to find nothing. The cost grows with the log and never stops growing.

Measured against the running server, 50k intervening unmatched events:

| Resume from | Time to reach live |
| --- | --- |
| last matched event | 866 ms |
| server checkpoint | 3 ms |

Three rules make it safe (ADR-042):

- The server guarantees no matching event lies in the skipped span, so nothing
  this projection would have applied is skipped.
- `EventsProcessed` does not move. A checkpoint is not an event, and the count is
  what answers "what has this projection done?".
- The position never regresses, and a checkpoint that fails to persist stops the
  subscription rather than being dropped.

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
  "orgId": "org_…",  "workspaceId": "ws_…",  "residency": "eu",
  "subjectIds": ["sub_…"],
  "occurredAt": "2026-08-08T09:14:22Z"
}
```

`$correlationId` and `$causationId` use KurrentDB's reserved names so its own
tooling can trace causation chains. `schemaVersion` drives the upcaster chain
(ADR-029). **No personal data**, ever (ADR-002).

`workspaceId` is present on workspace-scoped events and empty on org-level ones.
It rides in metadata rather than being parsed back out of the stream name because
every workspace-owned read model has an RLS policy checking **both** `org_id` and
`workspace_id` (ADR-020), and a projector must be able to scope itself from the
event alone — a lookup would be stale during a rebuild, or return nothing at all.

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
