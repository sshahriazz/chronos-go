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
stream:  reservation_email-<hex(HMAC-SHA256(k_res, normalized_email))>
append with ExpectedVersion = NoStream

  first caller  → 201   claim granted
  second caller → 400   claim refused, atomically
```

Note `reservation_email` uses an underscore so the category stays stable.

**The value is HMACed, never written in the clear.** A stream name is not a
payload, and ADR-002's rule was written about payloads — but a raw address here
would be permanent personal data that crypto-shredding cannot reach, because
there is no ciphertext to shred. Stream names persist in the `$streams` index and
in the `$ce-reservation_email` category stream, surface in metrics labels and
client logs, and KurrentDB deletion is a soft delete. Erasure would release the
reservation while the address stayed readable forever.

`k_res` is a **dedicated key, never rotated and never destroyed** (ADR-048).
Stream names are immutable, so rotating it would mean renaming every reservation
stream, which cannot be done in place. It is the one key in the system that
erasure does not revoke, and its blast radius is deliberately narrow: it protects
only the address-to-stream-name linkage, so compromise permits offline
confirmation of *guessed* addresses and nothing else.

The same rule applies to every other reservation category — org slugs and team
names are not personal data, but the derivation is uniform so nobody has to
decide case by case.

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

#### Behind the head, many events share one transaction

Atomicity is per TRANSACTION, and so is the round trip that dominates a
projector's cost — measured earlier in this project at 63% of per-event latency.
So while a projector is **behind**, events accumulate into one transaction that
carries all their rows and the single checkpoint covering them:

```sql
BEGIN;
  INSERT INTO member_view …;   -- event 1
  INSERT INTO member_view …;   -- event 2 … up to CatchUpBatch (default 64)
  UPDATE projection_checkpoint SET commit_position = <last>;
COMMIT;
```

Nothing about the guarantee changes: rows and checkpoint still commit together,
so a crash loses the batch as a unit and the projector reapplies it. What
changes is that 1,000 catch-up events cost ~16 round trips instead of 1,000.

Measured against the running stack (`BenchmarkProjectOneEvent` vs
`BenchmarkProjectBatchOfEvents`, batch of 64, Apple M3 Pro, Postgres over Docker
Desktop's loopback):

| Path | Per event |
| --- | --- |
| one event, one transaction (live) | 364.8 µs |
| **64 events, one transaction (catching up)** | **16.7 µs — 21.9x** |

The gap is round trips, which is why it is this large and why it grows with
network distance to the database rather than with the projection's own work.

Four rules keep it safe, and each is a test:

- **A batch never spans tenants.** Every statement runs under a scope set by
  `SET LOCAL`, so a scope change ends the batch.
- **A batch is flushed before the position can move past it** — on a server
  checkpoint, on reaching the head of the log, and at the end of a rebuild
  replay. A checkpoint written over buffered rows would claim work no
  transaction performed, which is the one way a projection loses an event
  instead of reapplying it.
- **Once LIVE, every event commits on its own.** Batching there would only add
  latency between a write landing in the log and appearing in the read model.
- **A failed batch is dropped, not retried.** The projector stops (ADR-019), the
  checkpoint still names the last committed batch, and the log is re-read on
  restart.

A **sharded** rebuild batches too, per worker. Each shard owns whole streams, so
its buffer is scoped to its own partition and no lock sits on the hot path; the
coordinator still writes the single checkpoint at the end.

Realtime announcements moved off this path at the same time: they publish from
their own goroutine behind a bounded queue that DROPS when full, counted in
`chronos_projection_announcements_dropped_total`. A publish is a call to a
service that is not the system of record, and the read model must not advance at
its speed. Shutdown waits at most 5s for that queue rather than blocking on an
unresponsive Centrifugo.

#### A rebuild can be paced

`PROJECTOR_REBUILD_EVENTS_PER_SECOND` (0 = unthrottled) bounds how fast a rebuild
applies events. Batching made rebuilds fast enough that the constraint moved: the
same PostgreSQL pool serves the API, so an unthrottled rebuild is a load test
against production run at the moment someone is already fixing something.

The limit is an AVERAGE — events applied against events the rate allows by now,
sleeping the deficit — so a burst is permitted and then paid for. It paces the
rebuild path only. A projector catching up after downtime is never throttled:
there the whole point is to become current.

| Knob | Default | What it bounds |
| --- | --- | --- |
| `PROJECTOR_CATCHUP_BATCH` | 64 | events per transaction while behind (max 512) |
| `PROJECTOR_REBUILD_SHARDS` | 1 | rebuild workers, partitioned by stream (max 16) |
| `PROJECTOR_REBUILD_EVENTS_PER_SECOND` | 0 | rebuild pace; 0 is unthrottled |
| `PROJECTOR_ANNOUNCE_BUFFER` | 256 | queued realtime messages before dropping |

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

### The chain is filled in by the kernel, not by each handler

A correlation id that was not written at append time can never be added — the
log is append-only — so "every handler remembers to set it" is not a workable
rule. `Repository.Save` resolves it instead:

| Situation | Correlation | Causation |
| --- | --- | --- |
| Caller set the field explicitly | the caller's value | the caller's value |
| `eventsourcing.Trace` in the context | inherited from it | inherited from it |
| Neither — a root write | the first derived event id | the command's idempotency key |

Both fallbacks are deterministic, so a **retried command produces the same
chain** rather than a second one, and every event of one command shares a
correlation id.

The context is populated at each hop. `reactor.Runner` attaches
`eventsourcing.CausedBy(env)` before calling `React`, which inherits the
correlation id and replaces the causation id with the handled event's own id —
that is what makes a chain a tree rather than a flat list.

The **RPC edge** attaches it in the idempotency gate, once the key is known and
before the handler runs: correlation and causation both start as the idempotency
key, so a request touching two aggregates produces ONE chain instead of two
unrelated ones, keyed by a value the client can quote in a support ticket. A
read attaches nothing — it writes no events.

**Temporal** carries it as HEADERS, through a `ContextPropagator` installed on
the client and its workers. An ordinary workflow argument would have to be
threaded through every workflow and activity signature, and one that forgets is
a hole nothing detects; headers travel whether or not the workflow author knows
they exist. Verified against the running server: a chain set at a start reaches
the activity after crossing gRPC and a real workflow history.

**OpenTelemetry** closes the loop: `otelhttp` extracts the incoming W3C trace
context at the edge, and the idempotency gate uses that trace id as the
correlation id, falling back to the key when there is no span. An event in the
log and a span in Tempo therefore line up with no join table.

The W3C propagator is installed **whether or not exporting is enabled**. What
lands in a permanent log must not depend on an observability toggle: with
`OTEL_ENABLED=false` a process still reads an incoming trace id and still writes
it, it simply exports no spans of its own. Temporal carries its own tracing
interceptor alongside the causation propagator — the tracer links spans for a
human reading Tempo, the propagator carries the ids that are written into the
log, and the second must not depend on the first.

---

## 8a. Durable work (Temporal)

A REACTOR performs one effect and is done; its retries belong to the
subscription. Work that spans several effects, needs timers, or must survive the
process dying halfway is a WORKFLOW (ADR-017). The banned alternatives — a cron
table, `time.AfterFunc`, an ad-hoc goroutine — share one flaw: none outlives the
process that created them.

```
reactor (persistent subscription)
   → workflow.Starter.Start{ID: <event id>, Name: …}   ← id DERIVED, never random
        → Temporal history                              ← pseudonyms only
             → activity: the I/O                        ← mail, push, HTTP
```

Four rules, each carried by a test:

- **The workflow id is derived from the event.** A random id turns every
  redelivery into a second run, which for mail is a second email. A duplicate
  start returns `ErrAlreadyStarted`, which the caller treats as success. That
  needs `WorkflowExecutionErrorWhenAlreadyStarted` — verified: without it the SDK
  returns the first run's id and a nil error, so "already ran" and "started" are
  indistinguishable.
- **Workflow input carries no personal data.** History is durable, replicated and
  long-lived, so the event-log rule applies unchanged (ADR-002): the input holds
  a `SubjectID`, and the activity resolves the address from the vault at the
  moment it sends.
- **Workflow names are permanent.** They are written into history; renaming one
  strands every in-flight execution against a worker that no longer answers to
  it. Registration goes through the same constants a test asserts.
- **A start needs a worker.** Work queued where nothing polls is CREATED, the
  caller is told it started, and it never runs. `NewWorker` refuses to build with
  nothing registered, and the composition root publishes the client only once its
  worker is polling.

### The notification path runs on it

`chronos.notification.Send.v1` — one activity, an hour of bounded retries, and
non-retryable errors for the two failures no retry can fix: an invalid
notification and an erased subject.

The reactor starts **one run per recipient**, keyed by the delivery's
idempotency key (`<event id>:<index>`), so the id is derived, unique per person,
and stable across redeliveries.

```
notification reactor
  ├─ TEMPORAL_ENABLED=true  → start chronos.notification.Send.v1, ack
  │                            the WORKFLOW owns the retry
  └─ TEMPORAL_ENABLED=false → dispatch inline
                               the SUBSCRIPTION owns the retry
```

Both paths dispatch the same notification through the same dispatcher; what
differs is who owns the retry, and that is the whole point. Inline, an SMTP
server out for twenty minutes exhausts the group's redeliveries and becomes a
parked backlog a human has to replay. As a workflow, the retry survives this
process restarting and the reactor has already acked.

Three rules on the seam:

- **Never both.** A reactor that started a run AND delivered inline would send
  everything twice.
- **`ErrAlreadyStarted` is success.** The run is already going or already went,
  which is what the call wanted; treating it as a failure would park an event
  whose notification was delivered perfectly.
- **A failed start is returned**, so the subscription redelivers rather than
  acking a notification nobody will ever send.

Off by default: a binary that dials a service it never uses reports a DOWN probe
for a dependency nothing needs. A composition-root test asserts which path the
running binary wired, because from outside the two are indistinguishable until a
transport fails.

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
| Append size is capped (default ~1 MiB per append) | enforced in code at **768 KiB per event** (`eventsourcing.MaxEventBytes`); over **50 KiB** logs a warning. Large payloads go to SeaweedFS; events carry a reference |
| Scavenging is licence-gated | scheduled Temporal workflow (ADR-032) |
| Soft-deleted streams stay in `$all` until scavenged | projectors must tolerate events from deleted streams |
| Only NATIVE projections run (`RUN_PROJECTIONS=System`) | `$ce-`, `$et-` and `$streams` are available; user JavaScript projections stay banned |
| A KurrentDB filter matches streams **or** event types, never both | a filter naming two dimensions is refused at startup (`SubscriptionFilter.Validate`), because the adapter could only honour one and the loss would be silent |
| `$all` position is a **pair** (commit, prepare) | checkpoints store both |

### Event size, enforced rather than documented

The limit is checked after encoding and before the wire, in the one place both
append paths share. Being refused by our own code names the event and the fix;
being refused by the server is a generic write failure arriving mid-command,
after uniqueness has already been reserved.

The soft threshold exists because the interesting failure is not the 1 MiB
event — it is the 200 KiB one, appended a thousand times an hour, that nobody
notices until log throughput falls off.

---

## 11. What we deliberately do not do

- **No server-side JavaScript projections.** A second runtime, untyped, with its
  own failure modes. The built-in NATIVE projections do run — that is what makes
  `$ce-` and `$et-` available (§4) — and they involve no JavaScript.
- **No link stream on the LIVE path.** `$ce-`/`$et-` are for rebuilds only.
  A live subscription reads `$all` because cross-aggregate commit ordering is the
  property it exists to provide, and a category stream does not have it.
- **No event rewriting**, including backfills (ADR-029). Upcast on read instead.
- **No aggregate spanning streams.** If an invariant needs two streams, it is a
  process, not an invariant.
- **No reading the event store on the query path.** Ever. That is what
  projections are for.
