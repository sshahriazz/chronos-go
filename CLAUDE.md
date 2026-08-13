# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## Project state

**Design complete; the platform kernel is under construction.** Read in this
order before touching anything:

1. [docs/DECISIONS.md](docs/DECISIONS.md) — 47 ADRs. Settled; do not relitigate.
2. [docs/CONVENTIONS.md](docs/CONVENTIONS.md) — **layout, import contract, event
   schema, IDs, errors, idempotency, API and test conventions.** Read before
   writing any Go.
3. [docs/FEATURES.md](docs/FEATURES.md) — feature inventory, all domains.
4. Deep specs (supersede the inventory where they exist):
   [identity](docs/domains/identity.md) · [access](docs/domains/access.md) ·
   [organization](docs/domains/organization.md) ·
   [billing](docs/domains/billing.md) · [entitlement](docs/domains/entitlement.md) ·
   [operator](docs/domains/operator.md) · [notification](docs/domains/notification.md) ·
   [workspace](docs/domains/workspace.md) · [compliance](docs/domains/compliance.md)
5. [docs/NOTIFICATIONS.md](docs/NOTIFICATIONS.md) — what gets sent, and when.
6. [docs/INFRA.md](docs/INFRA.md) — the running runtime substrate.
7. [docs/EVENT-SOURCING.md](docs/EVENT-SOURCING.md) — **KurrentDB semantics and
   data flows.** Verified against the running server; read before writing any
   command handler, projector or reactor.
8. [docs/REVIEW.md](docs/REVIEW.md) — design review, all findings resolved.

`organization` and `workspace` are **separate** modules with a strictly
one-directional dependency — `workspace → organization`, never the reverse
(ADR-020). A cycle means the split has failed; merge rather than tolerate it.

Scope terminates at **workspace + teams + member invitations**. Feature verticals
_inside_ a workspace (Drive, docs, files) are explicitly out of scope — Drive is
only the reference topology for access control (ADR-006).

## Mandated stack (ADR-007 … ADR-017)

| Concern                | Choice                                         | Banned alternative                               |
| ---------------------- | ---------------------------------------------- | ------------------------------------------------ |
| RPC                    | ConnectRPC, one port, gRPC + HTTP/JSON         | gin, echo, chi, separate gRPC server             |
| Schema/validation/docs | protobuf + protovalidate + buf                 | hand-written DTOs or validators                  |
| DI                     | compile-time codegen (`goforj/wire`)           | uber/fx, samber/do, dig (runtime reflection)     |
| Migrations             | **Goose**, embedded in `cmd/migrate` (ADR-011) | Atlas, hand-run SQL                              |
| Queries                | sqlc → pgx/v5                                  | ORM, query builder, SQL strings in Go            |
| Async                  | Temporal                                       | cron tables, `time.AfterFunc`, ad-hoc goroutines |
| Adapter transport      | **gRPC wherever offered** (ADR-037)            | HTTP when gRPC exists                            |

**API documentation is enforced, not encouraged.** `buf lint` runs the COMMENTS
category, so a service, RPC, message or field without a doc comment **fails the
build**. `buf breaking` runs in `make check`. The OpenAPI spec and the error
catalogue are generated from the same sources the server uses, and a test fails
if an `errs.Reason` is declared without a catalogue entry.
| Go | 1.26.x (installed: 1.26.5) | |
| Key custody | OpenBao transit (ADR-028) | cloud KMS, app-held KEK |
| Event evolution | upcast on read (ADR-029) | rewriting stored events |
| Subscriptions | projector=catch-up, reactor=persistent | rebuilding a reactor |
| Category streams | **`$ce-` available** (`RUN_PROJECTIONS=System`) | `RUN_PROJECTIONS=None`; user JS projections (`All`) |
| Nesting depth | capped at 15 | >25 = OpenFGA hard error, fails closed |
| Public IDs | prefixed ULID `org_…` (ADR-030) | raw UUID/ULID |

## Non-negotiable invariants

- **Proto types are wire DTOs, never domain types.** `domain/` may not import
  generated protobuf packages. This is the likeliest way this codebase rots.
- **Every query runs in a transaction opened with `SET LOCAL app.workspace_id`**
  — reads included. Plain `SET` leaks tenant context across pooled connections;
  that is a cross-tenant breach, not a style issue (ADR-011).
- **OpenFGA fails closed.** If it is unreachable, deny. This is the one
  deliberate exception to "the server stays resilient" (ADR-010). The property is
  carried by the type: `authz.Decision`'s zero value denies, so a forgotten
  branch, a short batch response and an ignored error all deny by construction.
- **A revocation tombstone is cleared by confirmation, never by a timer.** The
  access projector deletes it after removing the tuple; the TTL is garbage
  collection for a dead projector, and reaching it is an alert. A timer that
  fires before the projector restores access to a revoked principal with no
  event and no log line (ADR-045).
- **Personal data never enters an event or a log** — only `SubjectID`
  pseudonyms. Erasure works by destroying a key (ADR-002).
- **The PII vault is the only mutable system of record.** Everything else in
  Postgres is derived and rebuildable from the event log (ADR-013).
- **No projection may contain a personal-data column.** Projections store
  `SubjectID`; the vault resolves it at read time. This is what makes erasure a
  key deletion instead of a migration (compliance.md §1).
- **A seat is per person per organization**, not per membership — five
  workspaces, one seat (workspace.md §2). The corollary bites schema design: one
  person's browser has ONE push endpoint across every organization they belong
  to, so uniqueness there is `(org_id, endpoint)` (ADR-043). A globally unique
  constraint on a per-person artefact makes the upsert read a row RLS hides, and
  the second organization fails outright.
- **The app connects to Postgres as `chronos_app`, never the owner.** A
  superuser bypasses RLS entirely — `FORCE ROW LEVEL SECURITY` removes only the
  _owner_ exemption. Connecting as the owner silently disables tenant isolation
  at the database while every test still passes. `cmd/api` verifies this at
  startup.
- **Migrations are append-only.** Never edit an applied migration; add a new
  one. `make migrate-check` enforces it (ADR-011).
- **All times UTC.** `APP_TIMEZONE` affects presentation and operator
  convenience only — never storage.

## Commands

```bash
make check       # fmt + proto-lint + proto-breaking + lint + test (CI runs this)
make api         # regenerate Go, Connect, OpenAPI and the error catalogue
make api-docs    # OpenAPI spec + docs/api/errors.md only
make test        # go test ./... -race
make lint        # includes the depguard import contract (CONVENTIONS §2)

make up          # start stack (creates .env from .env.example if missing); idempotent
make down        # stop, keep volumes
make nuke        # stop AND destroy all data volumes
make status      # per-container health
make smoke       # bash scripts/smoke.sh — hits every service's health endpoint, exits non-zero on failure
make urls        # print every local endpoint
make logs        # tail all containers
make psql        # psql into the read model
make valkey-cli  # Valkey shell
make config      # render the fully-resolved compose file
make check-centrifugo  # validate infra/centrifugo/config.json before restarting

make dashboards        # regenerate Grafana dashboards from scripts/gen_dashboards.py
make dashboards-check  # run every dashboard query against live Prometheus
make targets           # Prometheus scrape target health
make traces            # services currently reporting traces to Tempo
```

Temporal's CLI is behind a compose profile, so it does not run by default:

```bash
make temporal-cli                                     # interactive shell
docker compose --profile tools run --rm temporal-admin-tools tctl namespace list
```

To restart one service after editing its config, use `docker compose up -d <service>`
rather than a full `make restart`.

## Architecture

Eight components, each owning exactly one question. Violating this split is the
main way to break the design:

| Question                    | Owner                                                      |
| --------------------------- | ---------------------------------------------------------- |
| What happened?              | KurrentDB (event log, `:2113`)                             |
| Who may do what?            | OpenFGA (`:8080` HTTP, `:8081` gRPC)                       |
| What does it look like now? | PostgreSQL read model (`:5432`)                            |
| What is ephemeral?          | Valkey (`:6379`) — also the cache-invalidation bus          |
| Who is connected?           | Centrifugo (`:8000`)                                       |
| What is in flight?          | Temporal (`:7233`, UI `:8233`)                             |
| Where are the bytes?        | SeaweedFS S3 (`:8333`)                                     |
| What mail was sent?         | Mailpit (SMTP `:1025`, UI `:8025`) — dev only              |
| What is the system doing?   | Prometheus (`:9090`) + Grafana (`:3001`) + Tempo (`:3200`) |

The write path is: **Go API appends an event to KurrentDB** → Go projectors read
`$all` via catch-up subscriptions → they write PostgreSQL rows **and their own
`$all` commit position in the same transaction** → they fire a Centrifugo publish
so browsers see the change. Events that need long-running work start a Temporal
workflow, keyed by the event ID for idempotency.

PostgreSQL hosts four isolated databases on one server: `chronos` (read model),
`openfga`, `temporal`, `temporal_visibility`. Only `openfga` is created by
`infra/postgres/init/`; Temporal's `auto-setup` image creates its own two.

### Constraints that are not negotiable

- **Never evaluate permissions in PostgreSQL or Go.** No `permissions` table, no
  recursive CTEs, no tree walking. Hierarchy and ACLs live in OpenFGA. PostgreSQL
  stores what a resource _is_; OpenFGA stores who may touch it.
- **Never write to PostgreSQL from a request handler.** Writes go to KurrentDB;
  projectors fill PostgreSQL. Every projected table must be reconstructable by
  replaying from position zero.
- **A projector's checkpoint is a RESUME POINT, not the last event it applied.**
  Filtered subscriptions persist the server's `CheckPointReached` for spans that
  matched nothing; without that a quiet projection re-scans the whole log on
  every restart (ADR-042, measured 866ms → 3ms at 50k intervening events).
  `EventsProcessed` is the count of applied events and does not move.
- **KurrentDB server-side JS projections stay off** (`KURRENTDB_RUN_PROJECTIONS=None`).
  Projections are Go code in this repo.
- **Temporal workflow functions must be deterministic.** No `time.Now()`, `rand`,
  `uuid.New()`, network, or disk I/O — use `workflow.Now()`, `workflow.SideEffect`,
  `workflow.NewTimer`, and put all I/O in Activities. Changing a workflow with
  live executions needs `workflow.GetVersion` or a new task queue.
- **No WebSocket loops in Go services.** Realtime auth is: Go API does an OpenFGA
  `Check` → mints a Centrifugo subscription JWT → browser subscribes. Centrifugo
  payloads are notifications, not the data of record.
- **Everything in Valkey gets a TTL.** `FLUSHALL` must be survivable. There is no
  `Set` without one — `internal/platform/cache` rejects a non-positive TTL rather
  than treating it as "forever".
- **No personal data and no key material in Valkey.** A cache is a projection
  with a shorter life, so the same rule applies. The PII vault caches unwrapped
  data keys IN-PROCESS under a capped TTL, and Valkey carries only the
  invalidation — a `SubjectID` pseudonym meaning "forget that key" (ADR-041).
  Erasure fails loudly if that message cannot be published.
- **No business meaning in S3 keys or bucket names.** Object↔tenant mapping lives
  in PostgreSQL; permission lives in OpenFGA. Objects are immutable — a new
  version is a new key plus a new event.
- **Mail is sent from a Temporal Activity**, never inline in a handler. The
  notification reactor starts `chronos.notification.Send.v1` per recipient, keyed
  by `<event id>:<index>` so a redelivery is refused rather than sent twice. With
  `TEMPORAL_ENABLED=false` it falls back to inline dispatch through the same
  dispatcher — correct, but the retry is then the subscription's, and an SMTP
  outage becomes a parked backlog instead of an hour of durable retries.
- **Nothing personal enters workflow history.** It is durable and replicated, so
  ADR-002 applies exactly as it does to the event log: a workflow carries a
  `SubjectID`, and the activity resolves the address from the vault at send time.
- **Go services export OTLP to the collector, never to Tempo directly.** Set
  `OTEL_EXPORTER_OTLP_ENDPOINT=http://localhost:4317`. Sampling and attribute
  scrubbing belong in `infra/otel-collector/config.yaml`, not in service code.
  Emitting traces is enough to get latency dashboards — Tempo's
  metrics-generator turns spans into `traces_spanmetrics_*` automatically.
- **Dashboards are code.** Edit `scripts/gen_dashboards.py` and run
  `make dashboards`; Grafana has `allowUiUpdates: false`, so UI edits are
  overwritten. Always run `make dashboards-check` after — a panel with a wrong
  metric name renders as "0", which reads as healthy when it isn't.

## Gotchas discovered while building this

- **OpenFGA's playground cannot coexist with authentication.** Setting both
  `OPENFGA_PLAYGROUND_ENABLED=true` and `OPENFGA_AUTHN_METHOD=preshared` makes the
  server panic on boot. The playground is off and its port (3000) is not
  published — 3000 is free for a frontend dev server, Grafana is on 3001.
- **Kurrent ships no stable arm64 build** — every arm64 tag is vendor-labelled
  `-experimental`. The stack pins the stable x86_64 image and sets
  `platform: linux/amd64`, running under emulation on Apple Silicon. Do not
  "fix" this by switching to an arm64 tag without saying so explicitly.
- **KurrentDB's OTLP exporter is licence-gated** and exports metrics + logs only,
  no traces. Prometheus scraping `/metrics` is the free path and is what's wired.
- **PostgreSQL 18 moved `PGDATA`.** The volume mounts `/var/lib/postgresql`, not
  `/var/lib/postgresql/data`; the old path silently gives a non-persistent DB.
- **Temporal's UI defaults to 8080**, which OpenFGA owns — it is remapped to 8233.
  SeaweedFS's volume server also sits on 8080 in-container and is deliberately
  not published.
- **Temporal's `postgres12` DB plugin name is not a version bound** — it runs fine
  against PostgreSQL 18 despite the upstream compose pinning PG16.
- **Centrifugo v6 restructured every config key** into nested paths
  (`client.token.hmac_secret_key` → `CENTRIFUGO_CLIENT_TOKEN_HMAC_SECRET_KEY`).
  v3/v4-era flat env vars are silently ignored. Its `/health` endpoint is opt-in
  via `health.enabled`.
- **`temporalio/auto-setup` is a development image** — it migrates schema on boot.
  Production uses `temporalio/server` plus an explicit `temporal-sql-tool` step.

## Configuration layout

- `.env` is gitignored; `.env.example` is the committed source of truth for image
  pins, ports, and dev credentials. Change pins there, not in `docker-compose.yml`.
- `infra/centrifugo/config.json` — channel namespaces and engine. No namespace
  grants client subscribe rights, so **channels are private by default** and
  require a subscription token.
- `infra/seaweedfs/s3.json` — S3 identities. Keys here must match `S3_ACCESS_KEY`
  / `S3_SECRET_KEY` in `.env`.
- `infra/postgres/init/` — runs once, only on an empty volume. After `make nuke`.
- `infra/temporal/dynamicconfig/` — dev-only Temporal tuning.
- `infra/prometheus/prometheus.yml` — scrape targets, one job per component.
- `infra/otel-collector/config.yaml` — the only OTLP ingress; sampling and
  attribute policy live here.
- `infra/grafana/dashboards/*.json` — **generated**, do not hand-edit.

## Other agent configs

A `~/.gemini` directory exists on this machine. If you want its MCP servers,
commands, or instructions brought into Claude Code, reply `/import` to see what
is importable, then `/import --yes=<digest>` to apply it.
