# Chronos — Infrastructure Blueprint

> Status: **infra-only**. No application code yet. This document is the contract the
> Go services will be written against.
>
> Every capability claim below was checked against the vendor's own current
> documentation (August 2026). Where the popular write-up on the internet and the
> official docs disagree, the official docs win and the correction is called out
> inline under **⚠ Correction**.

---

## 0. Shape of the system

```
                        ┌──────────────┐
  browser ──ws/sse────► │  Centrifugo  │ ◄──── HTTP API (publish) ──┐
                        └──────┬───────┘                            │
                               │ Redis PUB/SUB backplane            │
                        ┌──────▼───────┐                            │
                        │    Valkey    │ sessions, rate limit, JWT  │
                        └──────────────┘ denylist                   │
                                                                    │
  browser ──REST/gRPC──►┌──────────────────────────────────┐        │
                        │        Go API (writes)           │────────┘
                        └───────┬──────────────────┬───────┘
                                │ append           │ Check()
                        ┌───────▼──────┐   ┌───────▼───────┐
                        │  KurrentDB   │   │    OpenFGA    │  who can do what
                        │ (event log)  │   │  (ReBAC graph)│
                        └───────┬──────┘   └───────┬───────┘
                                │ catch-up subs    │ (own PG schema)
                        ┌───────▼──────┐           │
                        │ Go projectors│           │
                        └───┬──────┬───┘           │
                            │      │ signal        │
                    ┌───────▼──┐ ┌─▼─────────┐ ┌───▼──────────┐
                    │PostgreSQL│ │ Temporal  │ │  PostgreSQL  │
                    │(read mdl)│ │(durable   │ │ (openfga db) │
                    └──────────┘ │ workflows)│ └──────────────┘
                                 └─────┬─────┘
                                       │ activities
                            ┌──────────▼─────────┐   ┌──────────┐
                            │     SeaweedFS      │   │ Mailpit  │
                            │  (S3 object store) │   │  (SMTP)  │
                            └────────────────────┘   └──────────┘
```

**The one rule that keeps this coherent:** every component owns exactly one
question.

| Question | Owner |
| --- | --- |
| *What happened?* | KurrentDB |
| *Who may do what?* | OpenFGA |
| *What does it look like right now?* | PostgreSQL |
| *What is hot / ephemeral?* | Valkey |
| *Who is connected?* | Centrifugo |
| *What is still in flight?* | Temporal |
| *Where are the bytes?* | SeaweedFS |
| *What mail did we try to send?* | Mailpit (dev only) |
| *Who holds the keys?* | OpenBao |

---

## 1. KurrentDB — the event log

**Image:** `kurrentplatform/kurrentdb` · **Pinned:** `26.1.2` (current stable) ·
**Protocol:** gRPC over HTTP/2, port `2113`

### ⚠ Corrections to the original blueprint

1. **"EventStoreDB (Kurrent)" is now just KurrentDB.** EventStoreDB was renamed;
   `eventstore/eventstore` is the legacy repo. Current images live at
   `kurrentplatform/kurrentdb` on Docker Hub (also mirrored at
   `docker.kurrent.io`). 26.0 is the LTS tag, 26.1 is the current STS tag.
2. **License is KLv1, not "source-available free tier" in the loose sense.**
   The Kurrent License v1 is *not* an OSI-approved open-source licence. The
   source is readable and the core database is free to run; a licence key gates
   *enterprise* features (auto-scavenge, connectors, archiving, etc.). Core event
   append/read/subscribe — everything this architecture needs — needs no key.
3. **There is no separate HTTP port any more.** 1113/TCP (the legacy client
   protocol) was removed in 24.10. Everything — gRPC clients, the Admin UI, the
   health endpoints — is multiplexed on `2113`.
4. **AtomPub is off by default.** The Admin UI's stream browser is greyed out
   until `KURRENTDB_ENABLE_ATOM_PUB_OVER_HTTP=true`. This is a dev-UI
   convenience, not something Go code should use.
5. **The embedded web UI in 26.x is nearly empty — do not plan around it.**
   Verified on this instance: `/` redirects to `/ui/cluster`, which is the only
   route that exists (`/ui/streams`, `/ui/projections`,
   `/ui/persistent-subscriptions` all return **404**). `/info` reports
   `projections: false`, `userManagement: false`. Kurrent has moved the real UI
   out of the server into **Kurrent Navigator**, a desktop app — see §1.1.

### Capabilities we are actually buying

- **Append-only streams with optimistic concurrency.** Each write carries an
  expected revision; a mismatch is a `WrongExpectedVersion` error. That is our
  aggregate-level consistency boundary — no `SELECT … FOR UPDATE` needed.
- **`$all` stream + catch-up subscriptions.** A subscription can be opened from
  position zero or from a stored commit position, streams history at disk speed,
  then transparently flips to live tailing. This is the *entire* mechanism by
  which PostgreSQL read models get built and rebuilt.
- **Persistent subscriptions (server-side).** Unlike catch-up subs, the *server*
  tracks the checkpoint and can fan one stream out to competing consumers with
  ack/nack and a parking queue for poison messages. Use this when you want
  message-broker semantics (parallel workers, retries) instead of a strictly
  ordered single reader.
- **Server-side filtering.** `$all` subscriptions accept prefix/regex filters on
  stream name or event type, so a projector for `folder-*` does not have to
  receive and discard every unrelated event.

### Rules for this project

- Write events first, always. The event log is the source of truth; PostgreSQL is
  derived and disposable.
- **JavaScript projections stay off**; the built-in native ones run
  (`KURRENTDB_RUN_PROJECTIONS=System`, which is what the compose file sets).
  `System` enables `$by_category` and `$by_event_type` — the link streams a
  rebuild reads — and no JS runtime. `All` would add user JavaScript: a separate
  runtime with its own failure modes and no type safety, and it stays banned.
  Read-model projections are Go code, versioned in this repo.
- Each Go projector persists its own `$all` commit position in PostgreSQL, in the
  same transaction as the rows it writes. That makes replay idempotent and
  restart-safe.
- Events are immutable facts in past tense: `FolderCreated`, `DocumentShared`,
  `DocumentContentUpdated`. Never `UpdateDocument`.

### Local endpoints

| What | URL |
| --- | --- |
| gRPC / clients | `kurrentdb://localhost:2113?tls=false` |
| Cluster status page | <http://localhost:2113/ui/cluster> |
| Metrics | <http://localhost:2113/metrics> |
| Liveness | <http://localhost:2113/health/live> |

### 1.1 What you actually get for a UI

The honest answer, verified against this running instance:

**The embedded UI is a cluster status page and nothing else.** Everything a
developer wants from a UI — browsing streams, inspecting events, managing
projections and subscriptions — is either gone from the embedded UI in 26.x or
sits behind a licence.

What the startup log shows is loaded but **unlicensed** on the free tier:

| Plugin | State without a licence |
| --- | --- |
| `AutoScavenge` | `AutoScavenge is not licensed, stopping.` |
| `logs-endpoint` (`/admin/logs`) | `Failed to get license, endpoint will not be available.` |
| `connectors`, `schema-registry` | loaded, licence-gated |
| `encryption-at-rest` | loaded, disabled (also needs config) |
| `otlp-exporter` | loaded, disabled — **also licence-gated** (see note below) |
| `user-certificates` | loaded, disabled — needs config |

So your read is right: on the free tier the server-side UI story is thin.
**Kurrent Navigator is the replacement**, and it is a **desktop application** —
Windows, macOS (Apple Silicon and Intel), and Linux via Flatpak/.deb/.rpm.
**There is no Docker image for it**, so it cannot be added to this compose file;
install it on the host and point it at the container.

**Navigator is gRPC-only.** An `http://…` connection string fails with *"The
endpoint uses an unsupported protocol."* Use:

```
kurrentdb://localhost:2113?tls=false
```

(`esdb://localhost:2113?tls=false` is the legacy scheme and also works.) The
`?tls=false` is required because this stack runs `KURRENTDB_INSECURE=true`.

Navigator gives you stream browsing, queries, projection and connector
management, and cluster health — the things the embedded UI dropped.

> **Correction to an earlier draft of this document:** the OTLP exporter plugin
> is *not* free. Kurrent's own docs state it "requires a license key", and it
> exports **metrics and logs only — not traces**. The free path to KurrentDB
> observability is Prometheus scraping `/metrics` directly, which is what this
> stack does (2,579 series, no licence).

Practical division of labour for this project:

- **Navigator** — ad-hoc stream/event inspection during development.
- **Grafana** (§12) — the 2,579 KurrentDB metric series: append latency, index
  lag, subscription counts, queue depth. This is the operational view and it
  needs no licence.
- **Go integration tests** — the real regression surface. Do not rely on a UI.

---

## 2. OpenFGA — the authorization graph

**Image:** `openfga/openfga` · **Pinned:** `v1.18.3` ·
**Protocol:** HTTP `8080`, gRPC `8081`, playground `3000`, Prometheus `2112`

### ⚠ Corrections to the original blueprint

1. **"Sub-millisecond" is a marketing number, not a guarantee.** OpenFGA is a
   Zanzibar-style graph evaluator backed by *our* PostgreSQL. Latency depends on
   model depth, tuple count, and the datastore. Budget single-digit milliseconds
   for a warm `Check`, and treat anything deeper as something to measure.
2. **The tuple syntax in the original write-up was wrong.** It is
   `folder:executive#parent@folder:company`-style (object, relation, user), not
   "folder:executive parent folder:company". Tuples are written as
   `{user, relation, object}` triples.
3. **OpenFGA is CNCF Incubating** (promoted from Sandbox), Apache-2.0. That part
   of the blueprint was right and is worth keeping — it is the licence-safe
   Zanzibar.
4. **The playground and authentication are mutually exclusive.** Verified against
   `v1.18.3`: enabling both makes the server panic at startup with
   `panic: the playground only supports authn method 'none'`. This stack keeps
   `OPENFGA_AUTHN_METHOD=preshared` and leaves the playground **off**, so Go code
   is written against the authenticated path from the first line. To use the
   playground temporarily, set `OPENFGA_PLAYGROUND_ENABLED=true` *and*
   `OPENFGA_AUTHN_METHOD=none` together in `.env`.

### Capabilities we are actually buying

- **`Check(user, relation, object)`** — the hot path. One boolean, evaluated over
  the relationship graph, regardless of how deep the folder nesting goes.
- **`BatchCheck`** — one round trip for many `Check`s. This is what a file-listing
  screen should call, not N sequential `Check`s.
- **`ListObjects(user, relation, type)`** — "which documents can alice view?".
  Already running on the new **weighted-graph** resolution algorithm.
- **`ListUsers(object, relation)`** — "who has access to this document?" — powers
  the share dialog.
- **`Expand`** — returns the *reason* for an access decision as a tree. This is
  the debugging tool for "why can Bob see this?".
- **Contextual tuples** — tuples supplied *at request time* and not persisted.
  Use for link-sharing, time-boxed grants, and IP/device conditions without
  polluting the stored graph.
- **Conditions (ABAC)** — CEL expressions attached to a tuple, e.g. grant valid
  only until a timestamp. This is how "share expires in 7 days" is modelled
  without a cron job.
- **Model versioning** — every `WriteAuthorizationModel` returns a new immutable
  model ID. Old IDs keep working, so a model migration is a deploy, not an
  outage. **Always pin the model ID in `Check` calls** — omitting it means "use
  latest", which makes deploys racy.

### Rules for this project

- No recursive CTEs, no `WITH RECURSIVE`, no adjacency-list walking in Go.
  Hierarchy lives in OpenFGA.
- OpenFGA gets its **own PostgreSQL database** (`openfga`), never shares tables
  with the read model.
- The playground (`:3000`) is **dev-only** — the compose file disables it via an
  env flag for anything non-local, and there is no auth on it.
- `OPENFGA_AUTHN_METHOD=preshared` even locally, so the Go client is written
  against the authenticated path from day one.

### Local endpoints

| What | URL |
| --- | --- |
| HTTP API | <http://localhost:8080> |
| gRPC API | `localhost:8081` |
| Playground | <http://localhost:3000/playground> (off by default — see correction 4) |
| Metrics | <http://localhost:2112/metrics> |

Authenticated calls carry `Authorization: Bearer $OPENFGA_PRESHARED_KEY`.
Unauthenticated calls return `401`.

---

## 3. PostgreSQL — the read model

**Image:** `postgres` · **Pinned:** `18.4` · **Protocol:** SQL, port `5432`

### ⚠ Correction

**PostgreSQL 18 moved the data directory.** `PGDATA` is now
`/var/lib/postgresql/18/docker` and the declared `VOLUME` is
`/var/lib/postgresql` (not `/var/lib/postgresql/data`). Mounting the old path on
an 18 image silently gives you a non-persistent database. The compose file here
mounts `/var/lib/postgresql`.

### Capabilities we are actually buying

- **The read side of CQRS.** Denormalized, query-shaped tables written by Go
  projectors. Schema is free to change because it can always be rebuilt from the
  event log.
- **`JSONB` + GIN indexes** for the parts of a projection whose shape is not yet
  settled, without a migration per field.
- **Transactional checkpointing.** Projector position and projected rows commit
  together. This is the property that makes the whole CQRS story safe.
- **PG18 async I/O (`io_method`)** — new in 18, meaningfully faster sequential
  scans on the analytics queries this read model will accumulate.
- **Backing store for OpenFGA and Temporal**, in separate databases on the same
  server. One engine to operate, three isolated schemas.

### Databases created by this stack

| Database | Owner | Purpose |
| --- | --- | --- |
| `chronos` | app | CQRS read model + projector checkpoints |
| `openfga` | OpenFGA | relationship tuples + authorization models |
| `temporal` | Temporal | workflow history / mutable state |
| `temporal_visibility` | Temporal | workflow search & list APIs |

### Rules for this project

- **Never** evaluate permissions here. No `permissions` table, no ACL joins.
  PostgreSQL stores *what a resource is*; OpenFGA stores *who can touch it*.
- Never write to PostgreSQL from the request path. Writes go to KurrentDB;
  projectors fill PostgreSQL.
- Any table a projector owns must be reconstructable by replaying from position
  zero. If it isn't, it's in the wrong database.

---

## 4. Valkey — ephemeral state

**Image:** `valkey/valkey` · **Pinned:** `9.1.1-alpine` ·
**Protocol:** RESP, port `6379`

### ⚠ Correction

Valkey is at **9.x** (the BSD-3 Linux Foundation fork of Redis 7.2). Anything
written against "Valkey 8" advice is a year stale. Note also that this stack uses
Valkey for **two different jobs**: our own ephemeral state, *and* the Centrifugo
PUB/SUB backplane. Those are namespaced apart by key prefix and should be split
into separate instances before production.

### Capabilities we are actually buying

- **TTL on every key.** Sessions, JWT denylist entries, and rate-limit windows
  all expire themselves. No cleanup job.
- **Atomic counters + `EXPIRE`** for rate limiting; Lua or a `MULTI` block for a
  correct sliding window.
- **PUB/SUB** as the Centrifugo backplane, so Centrifugo nodes can scale
  horizontally and a publish on one node reaches subscribers on another.
- **Valkey 9 multi-threaded I/O**, meaningfully better than the single-threaded
  Redis model on a many-core box.

### Rules for this project

- If a key cannot be deleted without a user noticing data loss, it does not
  belong here. `FLUSHALL` must be survivable.
- No durable business state. No "source of truth" counters.
- Everything gets a TTL. A key with no TTL is a bug.

---

## 5. Centrifugo — the realtime edge

**Image:** `centrifugo/centrifugo` · **Pinned:** `v6.9.1` ·
**Protocol:** WebSocket / SSE / HTTP-stream on `8000`; HTTP + gRPC server API

### ⚠ Corrections to the original blueprint

1. **v6 restructured configuration.** Options are now nested paths —
   `client.token.hmac_secret_key`, `engine.type`, `http_server.port` — mapped to
   env as `CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY` etc. Every v3/v4-era flat key
   (`CENTRIFUGO_TOKEN_HMAC_SECRET_KEY`) is gone. Config file may be JSON, YAML,
   or TOML.
2. **v6 can split the broker from the engine.** A dedicated `broker` section
   overrides the engine's PUB/SUB half, and `presence_manager` is separately
   configurable. Useful later when presence traffic and message traffic want
   different Redis instances.
3. **The health endpoint is opt-in.** `health.enabled` defaults to `false`;
   `/health` only exists once you turn it on. Our config turns it on.
4. **Pin the exact tag.** Centrifugo's own docs say to pin, e.g.
   `centrifugo/centrifugo:v6.9.1` — and v6.7.0 shipped a fix for CVE-2026-32301
   (SSRF in dynamic JWKS), so floating below that is a real risk.

### Capabilities we are actually buying

- **Connection offload.** Go services never hold a WebSocket. Centrifugo holds
  them, in its own process, with its own memory profile.
- **JWT-based connection auth.** The Go API mints a short-lived HMAC token; the
  browser presents it to Centrifugo. Centrifugo never calls back into our API for
  the common case.
- **Server API `publish` / `broadcast`.** After a projector updates PostgreSQL,
  it fires one HTTP call to Centrifugo and the change lands in every open browser.
- **Channel namespaces** with per-namespace policy (presence, history, join/leave,
  subscribe-token-required). Configure once, not per-connection.
- **Subscription tokens** for private channels — a document channel can require a
  token our API only issues after an OpenFGA `Check`. This is the seam where
  realtime and authorization meet.
- **Redis engine** for horizontal scale, pointed at Valkey.

### Rules for this project

- No `gorilla/websocket` or `nhooyr/websocket` loops in business services.
- Realtime authorization is: Go API does `Check` → mints subscription token →
  browser subscribes. Centrifugo is not an authorization system.
- Payloads pushed through Centrifugo are *notifications*, not the data of record.
  A client that missed a message re-reads from the API.

### Local endpoints

| What | URL |
| --- | --- |
| WebSocket | `ws://localhost:8000/connection/websocket` |
| Server API | <http://localhost:8000/api> (needs `X-API-Key`) |
| Admin UI | <http://localhost:8000> |
| Health | <http://localhost:8000/health> |

---

## 6. Temporal — durable execution

**Images:** `temporalio/auto-setup:1.29.1`, `temporalio/ui:2.34.0`,
`temporalio/admin-tools:1.29.1-…` · **Protocol:** gRPC `7233`

### ⚠ Corrections to the original blueprint

1. **`temporalio/auto-setup` is explicitly a development image.** It creates
   schemas and the default namespace on boot. Production self-hosting uses
   `temporalio/server` with `temporal-sql-tool` run as a deliberate migration
   step. This is fine — and correct — for local, but the blueprint should not
   imply it is production shape.
2. **The DB plugin is still called `postgres12`.** That is the plugin name for
   all modern PostgreSQL, not a version constraint.
3. **The UI defaults to port 8080**, which collides with OpenFGA. Remapped to
   `8233` here.
4. **Temporal is MIT-licensed**, as the blueprint said — but note the SDK and
   server version skew matters; pin both.

### Capabilities we are actually buying

- **Durable execution.** Workflow state is reconstructed by replaying its event
  history. A worker crash mid-workflow is a non-event; execution resumes on
  another worker.
- **Activities with retry policies, timeouts, and heartbeats.** All the retry
  logic that would otherwise be hand-rolled in every worker.
- **Timers that outlive processes.** `workflow.Sleep(30 * 24 * time.Hour)` is a
  legitimate way to model a trial expiry. No cron, no scheduled-jobs table.
- **Sagas / compensation.** Multi-step distributed transactions with rollback,
  expressed as ordinary Go control flow.
- **Signals & queries** — external events into a running workflow, and read-only
  introspection of its state.
- **Schedules** — first-class recurring workflow execution.
- **Full history in the Web UI.** Every step, input, output, and failure of every
  workflow, browsable. This is the debugging capability that justifies the
  operational cost.

### Rules for this project

- Workflow functions are **deterministic**. No `time.Now()`, no `rand`, no
  `uuid.New()`, no direct network or disk I/O, no goroutines outside
  `workflow.Go`. Use `workflow.Now()`, `workflow.SideEffect`,
  `workflow.NewTimer`.
- All I/O lives in Activities.
- Changing a workflow's shape after it has running executions requires
  `workflow.GetVersion` or a new task queue. Replay determinism is not optional.
- Trigger point: a Go projector reads an event from KurrentDB and starts a
  workflow. Use the event ID as the workflow ID for natural idempotency.

### Local endpoints

| What | URL |
| --- | --- |
| gRPC | `localhost:7233` |
| Web UI | <http://localhost:8233> |
| Namespace | `default` |

---

## 7. SeaweedFS — object storage

**Image:** `chrislusf/seaweedfs` · **Pinned:** `4.41` · **Protocol:** S3 REST

### ⚠ Corrections to the original blueprint

1. **The Haystack claim is real but narrower than stated.** SeaweedFS's README
   says it "started by implementing Facebook's Haystack design paper" and targets
   **O(1) disk access** per file read — one seek, driven by an in-memory
   needle-to-offset map on the volume server. The "regardless of 1,000 or 10
   billion files" framing is the marketing gloss; the actual constraint is that
   the volume server's index must fit in memory (or use the leveldb/rocksdb index
   modes for very large deployments).
2. **`weed server -s3` is one process running four roles** (master, volume,
   filer, S3 gateway). Handy locally, but it is not the production topology —
   those are separate deployables with separate scaling characteristics. There is
   also a newer `weed mini` convenience command with auto-tuned defaults.
3. **The S3 gateway is unauthenticated unless you give it a config.** Access keys
   come from a JSON identities file passed as `-s3.config`. Without it, anyone
   who can reach `:8333` has full access.

### Capabilities we are actually buying

- **S3-compatible API** — standard `aws-sdk-go-v2` works unmodified, so swapping
  in real S3 or R2 later is a config change.
- **O(1) read path** — file ID resolves to volume + offset via an in-memory
  index; one disk seek to the bytes.
- **Filer with a pluggable metadata store**, giving real directory semantics on
  top of the flat volume layer.
- **Apache-2.0**, no licence-change risk (the reason this is here rather than
  MinIO).
- **Tiering & TTL** on volumes for lifecycle policy later.

### Rules for this project

- Object keys are opaque. **No business meaning in paths or bucket names** — no
  `/tenant-42/private/`. The relationship between an object and a tenant lives in
  PostgreSQL; permission to read it lives in OpenFGA.
- Uploads are written once and never mutated. New version = new key + a new
  event in KurrentDB.
- Go services talk to it through `aws-sdk-go-v2` with a custom endpoint and
  path-style addressing.

### Local endpoints

| What | URL |
| --- | --- |
| S3 API | <http://localhost:8333> |
| Filer UI | <http://localhost:8888> |
| Master UI | <http://localhost:9333> |
| Credentials | `chronos` / `chronos-secret-key` (dev only) |

---

## 7.5 OpenBao — key custody

**Image:** `openbao/openbao` · **Pinned:** `2.6.1` · **Protocol:** HTTP `8200`

The Linux Foundation fork of Vault (MPL-2.0), chosen over HashiCorp Vault (BUSL)
and over cloud KMS for the same reason as the rest of this stack: self-hosted,
OSI-licensed, no vendor lock-in (ADR-028).

### What it holds

- The **KEK** that wraps per-subject data keys — the mechanism GDPR erasure rests
  on (ADR-002).
- Every **rotatable secret**: Stripe restricted key and webhook secrets,
  Centrifugo HMAC and API key, OpenFGA pre-shared key, VAPID private key, the
  argon2 pepper (ADR-034).
- Optionally, **dynamic Postgres credentials**, removing the long-lived password.

### Capabilities we are actually buying

- **Transit engine** — encrypt/decrypt without the key ever leaving OpenBao. The
  application never holds key material, so a database dump plus an application
  compromise still cannot decrypt.
- **Destroyable keys** — the entire basis of crypto-shredding.
- Versioned keys, rotation, and per-path policies.
- An audit log of every key access.

**✅ Verified** end to end: encrypt → decrypt → destroy key → decrypt fails with
`encryption key not found`.

### Rules for this project

- **Dev runs `-dev`**: in-memory, auto-unsealed, fixed root token. **Production
  runs sealed** with persistent storage and a real unseal procedure — a dev-mode
  OpenBao in production voids the guarantee entirely, so config validation
  refuses to start with a dev token outside `local`.
- OpenBao is one of the **two unrebuildable stores** (ADR-033). Losing the
  keyring is worse than losing Postgres: Postgres replays, ciphertext without a
  key does not. It needs escrow, split custody, and *tested* restores.
- Unreachable ⇒ PII reads fail, non-PII reads continue (ADR-010).

### Local endpoints

| What | URL |
| --- | --- |
| API | <http://localhost:8200> |
| Health | <http://localhost:8200/v1/sys/health> |
| Dev token | `chronos_dev_root_token` (dev only) |

---

# 8. Mailpit — SMTP capture (development)

**Image:** `axllent/mailpit` · **Pinned:** `v1.30.6` ·
**Protocol:** SMTP `1025`, HTTP UI + API `8025`

This is the one component that is **development-only by design**. In production
the same `SMTP_*` env vars point at a real relay (SES, Postmark, Resend); nothing
in the Go code changes.

### Capabilities we are actually buying

- **A real SMTP server that never delivers.** Point the app at `mailpit:1025`
  and no mail can escape to a real inbox — the standard safety property for a
  dev environment.
- **Web UI on `:8025`** with HTML/plain-text/raw source views, and per-message
  headers.
- **REST API** over the captured mailbox, so integration tests can assert
  "a verification email was sent to X containing link Y" without mocking the
  mailer.
- **HTML check & link check** — reports client-compatibility issues and broken
  links in templates before a real customer sees them.
- **Spam analysis** (via optional SpamAssassin) and message tagging/search.
- **Chaos testing** — configurable SMTP error injection, so retry paths in the
  Temporal mail workflow can actually be exercised.

### Rules for this project

- Mail is sent from a **Temporal Activity**, never inline in a request handler.
  Delivery is an unreliable network call; that is precisely what Activities and
  their retry policies exist for.
- Templates render from read-model data, not from events directly.
- Integration tests assert against the Mailpit API, not against logs.

### Local endpoints

| What | URL |
| --- | --- |
| SMTP | `localhost:1025` (no auth, no TLS) |
| Web UI | <http://localhost:8025> |
| API | <http://localhost:8025/api/v1/messages> |

---

## 9. Version & licence matrix

All pins are the current stable release as of August 2026. No pre-release,
nightly, or vendor-experimental builds are used.

| Component | Image | Pin | Licence | Notes |
| --- | --- | --- | --- | --- |
| KurrentDB | `kurrentplatform/kurrentdb` | `26.1.2` | Kurrent v1 (source-available, **not** OSI) | amd64 build; see arch note |
| OpenFGA | `openfga/openfga` | `v1.18.3` | Apache-2.0 (CNCF Incubating) | |
| PostgreSQL | `postgres` | `18.4` | PostgreSQL Licence | PGDATA path changed in 18 |
| Valkey | `valkey/valkey` | `9.1.1-alpine` | BSD-3 (Linux Foundation) | |
| Centrifugo | `centrifugo/centrifugo` | `v6.9.1` | Apache-2.0 | ≥ v6.7.0 for CVE-2026-32301 |
| Temporal | `temporalio/auto-setup` | `1.29.7` | MIT | dev-only image |
| Temporal UI | `temporalio/ui` | `2.53.1` | MIT | remapped to `:8233` |
| Temporal admin-tools | `temporalio/admin-tools` | `1.29.7-tctl-1.18.4-cli-1.7.2` | MIT | `tools` profile |
| SeaweedFS | `chrislusf/seaweedfs` | `4.41` | Apache-2.0 | |
| Mailpit | `axllent/mailpit` | `v1.30.6` | MIT | dev-only |
| **OpenBao** | `openbao/openbao` | `2.6.1` | MPL-2.0 (Linux Foundation) | key custody; **unrebuildable** (ADR-033) |
| Prometheus | `prom/prometheus` | `v3.13.2` | Apache-2.0 | |
| Grafana | `grafana/grafana` | `13.1.3` | AGPL-3.0 | |
| Tempo | `grafana/tempo` | `2.9.4` | AGPL-3.0 | |
| OTel Collector | `otel/opentelemetry-collector-contrib` | `0.158.0` | Apache-2.0 | |
| postgres-exporter | `prometheuscommunity/postgres-exporter` | `v0.20.1` | Apache-2.0 | |
| redis/valkey-exporter | `oliver006/redis_exporter` | `v1.88.0-alpine` | MIT | supports Valkey 9.x |

### Architecture note (Apple Silicon)

**Kurrent publishes no stable arm64 build.** Every arm64 tag they ship is
vendor-labelled `-experimental-arm64-*`; only the x86_64 tags are GA. Rather than
run a binary its own vendor calls experimental, this stack pins the **stable
x86_64 build** and sets `platform: linux/amd64`, running it under Docker
Desktop's emulation on Apple Silicon.

Verified: `/info` reports `"dbVersion": "26.1.2.3778"` with no `-experimental`
suffix (the arm64 build reports `26.0.3.3493-experimental`).

`KURRENTDB_PLATFORM` in `.env` is a no-op on x86_64 hosts. If you would rather
have native speed than a GA build, switch `KURRENTDB_IMAGE` to
`26.1.2-experimental-arm64-10.0-noble` and `KURRENTDB_PLATFORM` to
`linux/arm64`. **Every other image in the stack is native multi-arch.**

---

## 10. Port map

| Port | Service | Kind |
| --- | --- | --- |
| 1025 | Mailpit SMTP | wire |
| 2112 | OpenFGA metrics | metrics |
| 2113 | KurrentDB | gRPC + UI + health + metrics, all multiplexed |
| 3001 | Grafana | UI |
| 3200 | Tempo | trace query API |
| 4317 | OTel Collector | OTLP gRPC — **apps send traces here** |
| 4318 | OTel Collector | OTLP HTTP |
| 5432 | PostgreSQL | wire |
| 6379 | Valkey | wire |
| 7233 | Temporal | gRPC frontend |
| 8000 | Centrifugo | WS + HTTP API + admin + metrics |
| 8025 | Mailpit | UI + API + metrics |
| 8080 | OpenFGA | HTTP API |
| 8081 | OpenFGA | gRPC API |
| 8200 | **OpenBao** | key custody API |
| 8233 | Temporal UI | moved off 8080 to avoid OpenFGA |
| 8333 | SeaweedFS S3 | HTTP |
| 8888 | SeaweedFS filer | HTTP |
| 8889 | OTel Collector | metrics |
| 9090 | Prometheus | UI + API |
| 9091 | Temporal metrics | metrics |
| 9121 | valkey-exporter | metrics |
| 9187 | postgres-exporter | metrics |
| 9327 | SeaweedFS metrics | metrics |
| 9333 | SeaweedFS master | HTTP |
| 10000 | Centrifugo | gRPC API |
| 18333 | SeaweedFS s3 | gRPC |
| 18888 | SeaweedFS filer | gRPC |
| 19333 | SeaweedFS master | gRPC |

Deliberately **not** published:

- **SeaweedFS volume server** (`:8080` HTTP, `:18080` gRPC in-container) — 8080
  collides with OpenFGA, and S3 clients reach object data through the filer.
- **OpenFGA playground** (`:3000`) — it cannot run alongside authentication
  (§2, correction 4), so the port mapping was removed rather than left dangling.
  Port 3000 is therefore free for a frontend dev server; Grafana sits on 3001.

---

## 11. gRPC surface

Every component that speaks gRPC has it enabled and published. Verified with
`grpcurl` against each port — these are real gRPC servers, not just open TCP
sockets.

| Component | Port | Reflection | Auth | Notes |
| --- | --- | --- | --- | --- |
| KurrentDB | 2113 | ✗ | insecure (local) | gRPC and HTTP multiplexed on one port |
| OpenFGA | 8081 | ✗ (auth-gated) | **bearer token** | returns `Code(1010) missing bearer token` unauthenticated |
| Temporal | 7233 | ✓ | none (local) | `WorkflowService`, `OperatorService`, `AdminService` |
| Centrifugo | 10000 | ✗ | **api key** | `grpc_api.enabled`; same protobuf as the HTTP API |
| SeaweedFS master | 19333 | ✓ | none | `master_pb.Seaweed`, `protobuf.Raft` |
| SeaweedFS filer | 18888 | ✓ | none | `filer_pb.SeaweedFiler`, `iam_pb.…` |
| SeaweedFS s3 | 18333 | ✓ | none | `s3_lifecycle_pb.…`, IAM cache |

PostgreSQL, Valkey, and Mailpit have no gRPC interface — they speak their own
wire protocols and are listed here only so the absence is deliberate.

Two things worth knowing before writing clients:

- **Centrifugo's gRPC API has no authentication by default.** Their docs are
  explicit about it. `CENTRIFUGO_GRPC_API_KEY` is set in this stack, and clients
  must send `authorization: apikey <KEY>` metadata per RPC.
- **SeaweedFS uses `gRPC port = HTTP port + 10000`** as a hard convention. The
  volume server's gRPC (18080) is not published, matching its HTTP port.

---

## 12. Telemetry

The goal is that any question about system behaviour has an answer that does not
require adding instrumentation first.

### 12.1 Metrics — every component reports

| Component | Endpoint | Native? | Series |
| --- | --- | --- | --- |
| KurrentDB | `kurrentdb:2113/metrics` | ✓ built in, no config | 2,579 |
| Temporal | `temporal:9090/metrics` | ✓ via `PROMETHEUS_ENDPOINT` | 6,272 |
| Prometheus | `prometheus:9090/metrics` | ✓ | 943 |
| PostgreSQL | `postgres-exporter:9187` | ✗ **sidecar exporter** | 732 |
| Valkey | `valkey-exporter:9121` | ✗ **sidecar exporter** | 580 |
| Centrifugo | `centrifugo:8000/metrics` | ✓ via `prometheus.enabled` | 354 |
| SeaweedFS | `seaweedfs:9327/metrics` | ✓ via `-metricsPort` | 333 |
| OpenFGA | `openfga:2112/metrics` | ✓ via `OPENFGA_METRICS_ENABLED` | 105 |
| Mailpit | `mailpit:8025/metrics` | ✓ via `MP_ENABLE_PROMETHEUS` | 15 |
| OTel Collector | `otel-collector:8889/metrics` | ✓ | OTLP re-served for scraping |
| Tempo | `tempo:3200/metrics` | ✓ | trace pipeline health |

PostgreSQL and Valkey speak no HTTP, so they are the only two that need a
sidecar. Everything else was already capable and just needed switching on.

### 12.2 Tracing

```
Go services ──OTLP──┐
                    ├──► OTel Collector ──► Tempo ──► metrics-generator
OpenFGA ────OTLP────┘      :4317/:4318       :3200        │
                                                          ▼
                                              Prometheus (span RED metrics)
```

**Nothing sends traces to Tempo directly.** Everything goes through the
collector, so sampling, attribute scrubbing, and backend routing are configured
in one file (`infra/otel-collector/config.yaml`) rather than in every service.

- **OpenFGA is the only stack component that emits OTLP traces without a
  licence** (`OPENFGA_TRACE_ENABLED=true`). Every `Check` becomes a span.
- **KurrentDB cannot** — its OTLP exporter is licence-gated and does metrics and
  logs only, no traces.
- **Centrifugo, SeaweedFS, PostgreSQL, Valkey, Mailpit** have no OTLP tracing.
- **Go services are the intended main producer.** Point them at
  `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317` and they appear
  automatically — including in the span-metrics panels, with no dashboard edit.

Tempo's **metrics-generator** converts spans into RED metrics
(`traces_spanmetrics_calls_total`, `traces_spanmetrics_latency_bucket`) and a
service graph, then remote-writes them to Prometheus. A service gets latency
dashboards purely by emitting traces. Prometheus runs with
`--web.enable-remote-write-receiver` and `--enable-feature=exemplar-storage` so
that a spike on a latency graph links straight to the trace that caused it.

### 12.3 Dashboards

Six dashboards are provisioned into the **Chronos** folder. `chronos-overview`
is the Grafana home page.

| Dashboard | Answers |
| --- | --- |
| **Stack Overview** | Is anything down? One row per question the architecture assigns to a component. |
| **Event Log (KurrentDB)** | Ingest rate, **index lag** (bounds read-model staleness), writer flush time, gRPC load. |
| **Authorization (OpenFGA)** | Check rate by method, **cache hit ratio**, CEL condition cost, plus live span metrics. |
| **Workflows (Temporal)** | **Task-queue backlog age**, poller count, persistence latency, SQL pool saturation. |
| **Realtime & Cache** | Connections/subscriptions, **dropped PUB/SUB messages**, Valkey evictions and TTL coverage. |
| **Storage & Data** | Per-database connections and cache hit ratio, S3 object counts, filer latency, SMTP accept/reject. |

Dashboards are **code**: `scripts/gen_dashboards.py` is the source of truth and
`allowUiUpdates` is off, so UI edits are overwritten on the next reload.

```bash
make dashboards        # regenerate JSON from the generator
make dashboards-check  # run all 103 queries against live Prometheus
```

`make dashboards-check` exists because a panel that renders nothing looks like
"zero" when it actually means "wrong metric name". Every expression in every
dashboard was validated against a running stack — **103/103 return data**. Metric
names were read out of the live registry, not guessed from documentation.

### 12.4 What is not here

- **No log aggregation (Loki/Elasticsearch).** Container logs are still
  `docker compose logs`, capped at 10MB × 3 files per service. This is the
  obvious next addition if log search becomes necessary.
- **No alerting rules.** Prometheus has no `rule_files` and Grafana has no alert
  provisioning. Thresholds are a decision to make once real traffic exists.
- **No tracing from the datastores themselves** — see 12.2 for why.

---

## 13. What this stack deliberately does not include

Named so nobody adds them by reflex:

- **No message broker (Kafka/NATS/RabbitMQ).** KurrentDB catch-up and persistent
  subscriptions cover fan-out; Temporal covers reliable work. Adding a broker
  would create a second, competing source of truth.
- **No Elasticsearch.** Temporal's advanced visibility can use it, but standard
  SQL visibility is enough at this size. PostgreSQL GIN handles read-model search
  until proven otherwise.
- **No service mesh, no API gateway.** Premature at one Go service.
- **No log aggregation and no alert rules.** Metrics and traces are wired
  (§12); log search and alert thresholds are the next additions, and both want
  real traffic before being designed.

---

## 14. Bringing it up

```bash
cp .env.example .env      # then edit the secrets
make up                   # docker compose up -d (creates .env if missing)
make status               # health of every container
make smoke                # hit every service's health endpoint
make urls                 # print every local endpoint
make logs                 # tail everything
make down                 # stop, keep volumes
make nuke                 # stop and destroy volumes

make dashboards           # regenerate Grafana dashboards from the generator
make dashboards-check     # run all 103 dashboard queries against Prometheus
make targets              # Prometheus scrape target health
make traces               # services currently reporting traces to Tempo
```

`make up` is safe to re-run. Startup order is enforced with health-gated
`depends_on`, so PostgreSQL is ready before OpenFGA's migration runs, and the
migration completes before the OpenFGA server starts.

---

## 15. Verification status

This stack was brought up on Apple Silicon (Docker 29.1.3, Compose v2.40.3) and
exercised end-to-end. `make smoke` re-runs the health half of this.

**Services**

| Check | Result |
| --- | --- |
| All 16 containers running, every health-checked one `healthy` | ✅ |
| OpenBao transit: encrypt → decrypt → **destroy key → decrypt fails** | ✅ |
| `chronos`, `openfga`, `temporal`, `temporal_visibility` databases exist | ✅ |
| Temporal `auto-setup` migrates cleanly against **PostgreSQL 18** | ✅ |
| Temporal `default` namespace created, cluster health OK | ✅ |
| KurrentDB runs the **stable** `26.1.2` build (`/info` has no `-experimental`) | ✅ |
| OpenFGA rejects unauthenticated requests (`401` HTTP / `1010` gRPC) | ✅ |
| OpenFGA accepts pre-shared key, store CRUD works | ✅ |
| KurrentDB append (`201`) and read-back over `$all`/stream API | ✅ |
| Centrifugo publish API rejects missing `X-API-Key` (`401`) | ✅ |
| Centrifugo publish succeeds and returns a history offset (Valkey engine live) | ✅ |
| SeaweedFS S3: bucket create, put, list, get with SigV4 | ✅ |
| SeaweedFS S3 rejects anonymous reads (`403`) | ✅ |
| `seaweedfs-init` bucket bootstrap is idempotent, preserves objects | ✅ |
| Mailpit accepts SMTP on `1025`, message visible via API | ✅ |

**gRPC** — probed with `grpcurl`, not just a port check

| Check | Result |
| --- | --- |
| Temporal reflection lists `WorkflowService`/`OperatorService`/`AdminService` | ✅ |
| SeaweedFS master/filer/s3 reflection lists real service descriptors | ✅ |
| KurrentDB + Centrifugo return proper gRPC responses (no reflection support) | ✅ |
| OpenFGA gRPC **enforces auth** — `Code(1010) missing bearer token` | ✅ |

**Telemetry**

| Check | Result |
| --- | --- |
| 11/11 Prometheus scrape targets `up` | ✅ |
| ~11,900 series stored across 9 component jobs | ✅ |
| 6 Grafana dashboards provisioned into the Chronos folder | ✅ |
| **103/103 dashboard expressions return live data** (`make dashboards-check`) | ✅ |
| Prometheus + Tempo datasources provisioned, Tempo↔Prometheus correlated | ✅ |
| OpenFGA → collector → Tempo: traces searchable by `service.name` | ✅ |
| Tempo metrics-generator remote-writes `traces_spanmetrics_*` to Prometheus | ✅ |

Findings worth remembering, all reflected above:

1. OpenFGA's playground cannot coexist with authentication — the port is gone.
2. Temporal's `auto-setup` works against PostgreSQL 18 despite upstream pinning
   PG16; `postgres12` is a plugin name, not a version bound.
3. Kurrent ships no stable arm64 build — hence emulation rather than an
   experimental binary.
4. KurrentDB's OTLP exporter is licence-gated and does not emit traces, so
   Prometheus scraping is the only free path to its telemetry.

Two findings worth remembering, both already reflected above:

1. OpenFGA's playground cannot coexist with authentication (correction §2.4).
2. Temporal's `auto-setup` works against PostgreSQL 18 despite the official
   compose pinning PG16 — the `postgres12` plugin name is not a version bound.

---

## Sources

- [Kurrent Docs — Installation](https://docs.kurrent.io/server/v26.0/quick-start/installation) · [Persistent subscriptions](https://docs.kurrent.io/server/v25.1/features/persistent-subscriptions) · [KurrentDB LICENSE.md](https://github.com/kurrent-io/KurrentDB/blob/master/LICENSE.md) · [Docker Hub `kurrentplatform/kurrentdb`](https://hub.docker.com/r/kurrentplatform/kurrentdb)
- [OpenFGA — Docker Setup](https://openfga.dev/docs/getting-started/setup-openfga/docker) · [Relationship Queries](https://openfga.dev/docs/interacting/relationship-queries) · [openfga/openfga `docker-compose.yaml`](https://github.com/openfga/openfga/blob/main/docker-compose.yaml) · [CHANGELOG](https://github.com/openfga/openfga/blob/main/CHANGELOG.md)
- [PostgreSQL official image](https://hub.docker.com/_/postgres) · [docker-library/postgres — PostgreSQL 18](https://deepwiki.com/docker-library/postgres/5.1-postgresql-18)
- [Valkey downloads](https://valkey.io/download/) · [Docker Hub `valkey/valkey`](https://hub.docker.com/r/valkey/valkey/)
- [Centrifugo — Configuration](https://centrifugal.dev/docs/server/configuration) · [Engines](https://centrifugal.dev/docs/server/engines) · [Console commands](https://centrifugal.dev/docs/server/console_commands) · [v6.7.0 release](https://github.com/centrifugal/centrifugo/releases/tag/v6.7.0)
- [temporalio/docker-compose](https://github.com/temporalio/docker-compose) · [`docker-compose-postgres.yml`](https://github.com/temporalio/docker-compose/blob/main/docker-compose-postgres.yml) · [Deploying a Temporal Service](https://docs.temporal.io/self-hosted-guide/deployment) · [Docker Hub `temporalio/auto-setup`](https://hub.docker.com/r/temporalio/auto-setup)
- [SeaweedFS README](https://github.com/seaweedfs/seaweedfs) · [Getting Started wiki](https://github.com/seaweedfs/seaweedfs/wiki/Getting-Started) · [Amazon S3 API wiki](https://github.com/seaweedfs/seaweedfs/wiki/Amazon-S3-API) · [S3 Credentials wiki](https://github.com/seaweedfs/seaweedfs/wiki/S3-Credentials) · [`seaweedfs-compose.yml`](https://github.com/seaweedfs/seaweedfs/blob/master/docker/seaweedfs-compose.yml)
- [Mailpit — Docker images](https://mailpit.axllent.org/docs/install/docker/) · [axllent/mailpit](https://github.com/axllent/mailpit)
