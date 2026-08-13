#!/usr/bin/env python3
"""
Source of truth for the provisioned Grafana dashboards.

Grafana reads the generated JSON from infra/grafana/dashboards/. Edit THIS file
and run `make dashboards`, not the JSON (the provisioner has allowUiUpdates
disabled, so UI edits are overwritten anyway).

Every PromQL expression here is validated against a live Prometheus by
scripts/check_dashboards.py — run `make dashboards-check` after changing one.
"""
import json
import pathlib

OUT = pathlib.Path(__file__).resolve().parent.parent / "infra" / "grafana" / "dashboards"
PROM = {"type": "prometheus", "uid": "chronos-prometheus"}
TEMPO = {"type": "tempo", "uid": "chronos-tempo"}

# ---------------------------------------------------------------------------
# panel helpers
# ---------------------------------------------------------------------------

_Y = {"y": 0}


def _pos(w, h):
    """Naive left-to-right, top-to-bottom layout on Grafana's 24-column grid."""
    x = _pos.x
    if x + w > 24:
        x = 0
        _Y["y"] += _pos.h
    _pos.x = x + w
    _pos.h = h
    return {"h": h, "w": w, "x": x, "y": _Y["y"]}


def reset_layout():
    _pos.x = 0
    _pos.h = 0
    _Y["y"] = 0


reset_layout()


def target(expr, legend=None, instant=False, ds=PROM, fmt="time_series"):
    t = {"datasource": ds, "expr": expr, "refId": chr(65 + target.n % 26), "format": fmt}
    target.n += 1
    if legend:
        t["legendFormat"] = legend
    if instant:
        t["instant"] = True
        t["range"] = False
    return t


target.n = 0


def ts(title, targets, unit="short", w=12, h=8, desc="", stack=False, legend="list", minval=None):
    """Time series panel."""
    custom = {
        "lineWidth": 1,
        "fillOpacity": 12,
        "showPoints": "never",
        "spanNulls": True,
        "gradientMode": "opacity",
    }
    if stack:
        custom["stacking"] = {"mode": "normal", "group": "A"}
    defaults = {"unit": unit, "custom": custom, "color": {"mode": "palette-classic"}}
    if minval is not None:
        defaults["min"] = minval
    return {
        "type": "timeseries",
        "title": title,
        "description": desc,
        "datasource": PROM,
        "gridPos": _pos(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "legend": {"displayMode": legend, "placement": "bottom", "calcs": ["lastNotNull", "max"]},
            "tooltip": {"mode": "multi", "sort": "desc"},
        },
        "targets": targets,
    }


def stat(title, expr, unit="short", w=4, h=4, desc="", legend=None, steps=None,
         text_mode="auto", color_mode="value", decimals=None, graph=False):
    """Single-value stat panel."""
    thresholds = steps or [{"color": "text", "value": None}]
    defaults = {
        "unit": unit,
        "thresholds": {"mode": "absolute", "steps": thresholds},
        "color": {"mode": "thresholds"},
        "mappings": [],
    }
    if decimals is not None:
        defaults["decimals"] = decimals
    return {
        "type": "stat",
        "title": title,
        "description": desc,
        "datasource": PROM,
        "gridPos": _pos(w, h),
        "fieldConfig": {"defaults": defaults, "overrides": []},
        "options": {
            "reduceOptions": {"calcs": ["lastNotNull"], "fields": "", "values": False},
            "colorMode": color_mode,
            "graphMode": "area" if graph else "none",
            "textMode": text_mode,
            "justifyMode": "auto",
        },
        "targets": [target(expr, legend, instant=not graph)],
    }


def row(title):
    return {
        "type": "row",
        "title": title,
        "collapsed": False,
        "gridPos": _pos(24, 1),
        "panels": [],
    }


def table(title, targets, w=12, h=8, desc="", overrides=None):
    return {
        "type": "table",
        "title": title,
        "description": desc,
        "datasource": PROM,
        "gridPos": _pos(w, h),
        "fieldConfig": {
            "defaults": {"custom": {"align": "auto", "filterable": True}, "mappings": []},
            "overrides": overrides or [],
        },
        "options": {"showHeader": True, "cellHeight": "sm"},
        "targets": targets,
    }


def dashboard(uid, title, description, panels, tags, refresh="30s"):
    reset_layout()
    return {
        "uid": uid,
        "title": title,
        "description": description,
        "tags": ["chronos"] + tags,
        "timezone": "browser",
        "schemaVersion": 39,
        "version": 1,
        "editable": False,
        "refresh": refresh,
        "time": {"from": "now-1h", "to": "now"},
        "timepicker": {"refresh_intervals": ["10s", "30s", "1m", "5m", "15m"]},
        "panels": panels,
        "annotations": {"list": []},
        "templating": {"list": []},
    }


UP_STEPS = [{"color": "red", "value": None}, {"color": "green", "value": 1}]
INV_STEPS = [{"color": "green", "value": None}, {"color": "orange", "value": 1}]


def health(title, job, unit="short"):
    return stat(title, f'up{{job="{job}"}}', unit=unit, w=3, h=4, steps=UP_STEPS,
                text_mode="value_and_name",
                desc=f"1 = Prometheus is successfully scraping {job}.")


# ===========================================================================
# 1. Stack overview — the "is anything on fire" dashboard
# ===========================================================================
def overview():
    reset_layout()
    p = [
        row("Component health"),
        health("Event log", "kurrentdb"),
        health("AuthZ", "openfga"),
        health("Read model", "postgres"),
        health("Cache", "valkey"),
        health("Realtime", "centrifugo"),
        health("Workflows", "temporal"),
        health("Object store", "seaweedfs"),
        health("SMTP", "mailpit"),

        row("Throughput — one panel per owned question"),
        ts("What happened? — KurrentDB event I/O",
           [target("sum(rate(kurrentdb_io_events_total[5m])) by (activity)", "{{activity}}")],
           unit="ops", w=8,
           desc="Events read from and written to the log. The write line is the "
                "true ingest rate of the whole system."),
        ts("Who may do what? — OpenFGA gRPC calls",
           [target('sum(rate(grpc_server_started_total{job="openfga"}[5m])) by (grpc_method)',
                   "{{grpc_method}}")],
           unit="reqps", w=8,
           desc="Check/BatchCheck/ListObjects rate. This is the request-path "
                "authorization load."),
        ts("What is in flight? — Temporal service requests",
           [target('sum(rate(service_requests{job="temporal"}[5m])) by (operation)',
                   "{{operation}}")],
           unit="reqps", w=8, legend="hidden",
           desc="Frontend/history/matching operations across the Temporal service."),

        ts("Who is connected? — Centrifugo",
           [target("centrifugo_node_num_clients", "clients"),
            target("centrifugo_node_num_subscriptions", "subscriptions"),
            target("centrifugo_node_num_channels", "channels")],
           w=8,
           desc="Live WebSocket state. Go services hold none of these connections."),
        ts("What is ephemeral? — Valkey ops",
           [target("rate(redis_commands_processed_total[5m])", "commands/s"),
            target("redis_connected_clients", "clients")],
           unit="ops", w=8,
           desc="Sessions, rate limiting and the Centrifugo backplane share this instance."),
        ts("What does it look like now? — PostgreSQL connections",
           [target("sum(pg_stat_activity_count) by (datname)", "{{datname}}")],
           w=8, stack=True,
           desc="Per-database connection count. chronos = read model, "
                "openfga / temporal = their own stores."),

        row("Capacity"),
        stat("S3 objects", "sum(SeaweedFS_s3_bucket_object_count)", graph=True),
        stat("S3 bytes", "sum(SeaweedFS_s3_bucket_size_bytes)", unit="bytes", graph=True),
        stat("Read-model size", 'sum(pg_database_size_bytes{datname="chronos"})',
             unit="bytes", graph=True),
        stat("Valkey memory", "redis_memory_used_bytes", unit="bytes", graph=True),
        stat("KurrentDB memory", "kurrentdb_proc_mem_bytes", unit="bytes", graph=True),
        stat("Captured mail", "mailpit_messages", graph=True,
             desc="Mailpit never delivers — this only ever grows in development."),
    ]
    return dashboard("chronos-overview", "Chronos — Stack Overview",
                     "One row per question the architecture assigns to a component. "
                     "Start here; drill into a component dashboard from the tag list.",
                     p, ["overview"])


# ===========================================================================
# 2. Event log — KurrentDB
# ===========================================================================
def eventlog():
    reset_layout()
    p = [
        row("Ingest"),
        ts("Event throughput",
           [target("sum(rate(kurrentdb_io_events_total[5m])) by (activity)", "{{activity}}")],
           unit="ops",
           desc="Writes are appends from the Go API. Reads are dominated by "
                "projector catch-up subscriptions."),
        ts("Byte throughput",
           [target("sum(rate(kurrentdb_io_bytes_total[5m])) by (activity)", "{{activity}}")],
           unit="Bps"),

        row("Projector health — the numbers that break CQRS"),
        ts("Secondary index lag",
           [target("kurrentdb_indexes_secondary_lag_seconds", "lag")],
           unit="s",
           desc="Time between a record being appended and being indexed. If this "
                "climbs, read models fall behind writes."),
        ts("Secondary index gap",
           [target("kurrentdb_indexes_secondary_gap_bytes", "gap")],
           unit="bytes",
           desc="Bytes between the log tail and the last indexed record."),

        row("gRPC — the client-facing surface"),
        ts("Incoming gRPC call rate",
           [target("sum(rate(kurrentdb_incoming_grpc_calls_total[5m])) by (kind)", "{{kind}}")],
           unit="reqps"),
        ts("In-flight gRPC calls",
           [target("kurrentdb_current_incoming_grpc_calls", "in flight")]),

        row("Storage engine"),
        ts("Queue time (max)",
           [target("topk(5, kurrentdb_queue_queueing_duration_max_seconds)", "{{queue}}")],
           unit="s", desc="Top 5 internal queues by queueing delay."),
        ts("Writer flush duration (max)",
           [target("kurrentdb_writer_flush_duration_max_seconds", "flush")],
           unit="s",
           desc="How long the chunk writer takes to fsync. Directly bounds append latency."),
        ts("Disk I/O",
           [target("sum(rate(kurrentdb_disk_io_bytes_total[5m])) by (activity)", "{{activity}}")],
           unit="Bps"),
        ts("Record read duration p99",
           [target("histogram_quantile(0.99, sum(rate(kurrentdb_io_record_read_duration_seconds_bucket[5m])) by (le))",
                   "p99")],
           unit="s", desc="The Haystack-style O(1) read path, measured."),

        row("Process"),
        ts("CPU",
           [target("kurrentdb_proc_cpu", "process"),
            target("kurrentdb_sys_cpu", "system")],
           unit="percentunit"),
        ts("Memory",
           [target("kurrentdb_proc_mem_bytes", "process"),
            target("sum(kurrentdb_gc_heap_size_bytes)", "GC heap")],
           unit="bytes"),
    ]
    return dashboard("chronos-eventlog", "Chronos — Event Log (KurrentDB)",
                     "The single source of truth. Index lag is the metric that matters "
                     "most: it bounds how stale every PostgreSQL read model can be.",
                     p, ["kurrentdb", "event-sourcing"])


# ===========================================================================
# 3. Authorization — OpenFGA (+ traces)
# ===========================================================================
def authz():
    reset_layout()
    p = [
        row("Request path"),
        ts("gRPC calls by method",
           [target('sum(rate(grpc_server_started_total{job="openfga"}[5m])) by (grpc_method)',
                   "{{grpc_method}}")],
           unit="reqps", w=16,
           desc="Check and BatchCheck should dominate. A high ListObjects rate on "
                "the request path usually means a screen is asking the wrong question."),
        # `or vector(0)` so an idle, healthy server renders "0" rather than
        # "No data" — the two look identical at a glance but mean opposite things.
        stat("Errors / sec",
           'sum(rate(grpc_server_handled_total{job="openfga",grpc_code!="OK"}[5m])) or vector(0)',
           unit="reqps", w=4, h=8, steps=INV_STEPS, graph=True,
           desc="Non-OK gRPC responses. Note: unauthenticated calls count here."),
        stat("Goroutines", 'go_goroutines{job="openfga"}', w=4, h=8, graph=True),

        row("Cache — the difference between fast and slow authorization"),
        ts("Check cache hit ratio",
           [target("rate(openfga_check_cache_hit_count[5m]) / "
                   "clamp_min(rate(openfga_check_cache_total_count[5m]), 1)", "hit ratio")],
           unit="percentunit", minval=0,
           desc="Cold cache means every Check walks the graph in PostgreSQL."),
        ts("Cache activity",
           [target("rate(openfga_check_cache_total_count[5m])", "lookups/s"),
            target("rate(openfga_check_cache_hit_count[5m])", "hits/s"),
            target("rate(openfga_cachecontroller_cache_invalidation_count[5m])", "invalidations/s")],
           unit="ops",
           desc="Invalidations spike after WriteTuples — expected right after a share."),

        row("Conditions (ABAC)"),
        ts("Condition evaluation p95",
           [target("histogram_quantile(0.95, sum(rate(openfga_condition_evaluation_duration_ms_bucket[5m])) by (le))",
                   "p95")],
           unit="ms",
           desc="CEL expression cost — this is where 'share expires in 7 days' is enforced."),
        ts("Iterators in flight",
           [target("openfga_shared_iterator_count", "shared iterators")],
           desc="Graph-walk iterators. Growth without bound means a query is fanning out."),

        row("Traces — OpenFGA is the only component emitting OTLP without a licence"),
        ts("Span rate by service",
           [target("sum(rate(traces_spanmetrics_calls_total[5m])) by (service)", "{{service}}")],
           unit="reqps", w=12,
           desc="Generated by Tempo's metrics-generator from received spans. "
                "Go services appear here automatically once they export OTLP."),
        ts("Span latency p95 by service",
           [target("histogram_quantile(0.95, sum(rate(traces_spanmetrics_latency_bucket[5m])) by (le, service))",
                   "{{service}}")],
           unit="s", w=12),
    ]
    return dashboard("chronos-authz", "Chronos — Authorization (OpenFGA)",
                     "Every access decision in the system. If a permission question is "
                     "being answered anywhere else (a SQL join, a Go loop), that is a bug.",
                     p, ["openfga", "authorization"])


# ===========================================================================
# 4. Workflows — Temporal
# ===========================================================================
def workflows():
    reset_layout()
    p = [
        row("Service"),
        ts("Request rate by operation",
           [target('sum(rate(service_requests{job="temporal"}[5m])) by (operation)',
                   "{{operation}}")],
           unit="reqps", legend="hidden"),
        ts("Service latency p95",
           [target('histogram_quantile(0.95, sum(rate(service_latency_bucket{job="temporal"}[5m])) by (le, operation))',
                   "{{operation}}")],
           unit="s", legend="hidden"),
        ts("Errors by type",
           [target('sum(rate(service_error_with_type{job="temporal"}[5m])) by (error_type)',
                   "{{error_type}}")],
           unit="reqps",
           desc="Some error types are normal control flow in Temporal "
                "(e.g. NotFound on a first poll)."),
        ts("gRPC connections",
           [target('service_grpc_conn_active{job="temporal"}', "active")],
           desc="Worker connections. Zero here means no Go worker is polling yet."),

        row("Task queues — where work waits"),
        ts("Backlog size",
           [target("sum(approximate_backlog_count) by (taskqueue)", "{{taskqueue}}")],
           desc="Tasks waiting for a worker. Sustained growth means too few workers."),
        ts("Backlog age",
           [target("sum(approximate_backlog_age_seconds) by (taskqueue)", "{{taskqueue}}")],
           unit="s",
           desc="How long the oldest queued task has waited. The user-visible number."),
        ts("Pollers",
           [target("sum(temporal_num_pollers) by (poller_type)", "{{poller_type}}")],
           desc="Long-poll connections from Go workers."),
        ts("Loaded task queue partitions",
           [target("loaded_task_queue_partition_count", "partitions")]),

        row("Persistence — Temporal's PostgreSQL usage"),
        ts("Persistence request rate",
           [target('sum(rate(persistence_requests{job="temporal"}[5m])) by (operation)',
                   "{{operation}}")],
           unit="reqps", legend="hidden"),
        ts("Persistence latency p95",
           [target('histogram_quantile(0.95, sum(rate(persistence_latency_bucket{job="temporal"}[5m])) by (le))',
                   "p95")],
           unit="s",
           desc="Temporal shares the PostgreSQL instance with the read model — "
                "watch this when the read model is under load."),
        ts("SQL connection pool",
           [target("sum(persistence_sql_in_use)", "in use"),
            target("sum(persistence_sql_open_conn)", "open"),
            target("sum(persistence_sql_max_open_conn)", "max")],
           desc="Hitting max is the classic cause of workflow stalls."),
        ts("Shard queue lag p95",
           [target("histogram_quantile(0.95, sum(rate(shardinfo_immediate_queue_lag_bucket[5m])) by (le))",
                   "immediate"),
            target("histogram_quantile(0.95, sum(rate(shardinfo_scheduled_queue_lag_bucket[5m])) by (le))",
                   "scheduled")],
           desc="Scheduled-queue lag is why a workflow timer might fire late."),
    ]
    return dashboard("chronos-workflows", "Chronos — Workflows (Temporal)",
                     "Durable execution. Backlog age and scheduled-queue lag are the two "
                     "numbers that show up as user-visible delay.",
                     p, ["temporal", "workflows"])


# ===========================================================================
# 5. Realtime + cache — Centrifugo and Valkey
# ===========================================================================
def realtime():
    reset_layout()
    p = [
        row("Centrifugo — connection state"),
        stat("Clients", "centrifugo_node_num_clients", graph=True),
        stat("Users", "centrifugo_node_num_users", graph=True),
        stat("Channels", "centrifugo_node_num_channels", graph=True),
        stat("Subscriptions", "centrifugo_node_num_subscriptions", graph=True),
        stat("Nodes", "centrifugo_node_num_nodes", graph=True,
             desc="More than one requires the Valkey backplane to be working."),
        stat("Connection limit", "centrifugo_node_client_connection_limit"),

        row("Centrifugo — message flow"),
        ts("Messages sent",
           [target("sum(rate(centrifugo_node_messages_sent_count[5m])) by (type)", "{{type}}")],
           unit="ops",
           desc="'publication' is application data; 'control' is inter-node gossip."),
        ts("Messages received",
           [target("sum(rate(centrifugo_node_messages_received_count[5m])) by (type)", "{{type}}")],
           unit="ops"),
        ts("Client command duration p99",
           [target("histogram_quantile(0.99, sum(rate(centrifugo_client_command_duration_seconds_histogram_bucket[5m])) by (le, method))",
                   "{{method}}")],
           unit="s"),
        ts("Redis PUB/SUB buffer",
           [target("centrifugo_broker_redis_pub_sub_buffered_messages", "buffered"),
            target("centrifugo_broker_redis_pub_sub_dropped_messages", "dropped")],
           desc="Dropped messages mean subscribers missed updates — clients must "
                "re-read from the API, which is why pushes are notifications only."),

        row("Valkey — ephemeral state"),
        ts("Command rate",
           [target("rate(redis_commands_processed_total[5m])", "commands/s"),
            target("rate(redis_connections_received_total[5m])", "new connections/s")],
           unit="ops"),
        ts("Memory",
           [target("redis_memory_used_bytes", "used"),
            target("redis_config_maxmemory", "maxmemory")],
           unit="bytes",
           desc="maxmemory-policy is allkeys-lru: reaching the limit evicts, "
                "it does not error."),
        ts("Keys by database",
           [target("redis_db_keys", "db{{db}} keys"),
            target("redis_db_keys_expiring", "db{{db}} with TTL")],
           desc="Every key in this stack should have a TTL. A widening gap between "
                "these two lines is a leak."),
        ts("Evictions and expiries",
           [target("rate(redis_evicted_keys_total[5m])", "evicted/s"),
            target("rate(redis_expired_keys_total[5m])", "expired/s")],
           unit="ops",
           desc="Evictions mean Valkey is dropping data early — raise maxmemory."),
    ]
    return dashboard("chronos-realtime", "Chronos — Realtime & Cache",
                     "Centrifugo holds the WebSockets so Go services do not, and Valkey "
                     "is both its backplane and the app's ephemeral store.",
                     p, ["centrifugo", "valkey"])


# ===========================================================================
# 6. Storage & data — PostgreSQL, SeaweedFS, Mailpit
# ===========================================================================
def storage():
    reset_layout()
    p = [
        row("PostgreSQL — read model + OpenFGA + Temporal"),
        ts("Connections by database",
           [target("sum(pg_stat_activity_count) by (datname)", "{{datname}}")],
           stack=True,
           desc="Four databases share one server: chronos, openfga, temporal, "
                "temporal_visibility."),
        ts("Transaction rate",
           [target("sum(rate(pg_stat_database_xact_commit[5m])) by (datname)", "{{datname}} commit"),
            target("sum(rate(pg_stat_database_xact_rollback[5m])) by (datname)", "{{datname}} rollback")],
           unit="ops"),
        ts("Cache hit ratio",
           [target("sum(rate(pg_stat_database_blks_hit[5m])) by (datname) / "
                   "clamp_min(sum(rate(pg_stat_database_blks_hit[5m]) + "
                   "rate(pg_stat_database_blks_read[5m])) by (datname), 1)", "{{datname}}")],
           unit="percentunit", minval=0,
           desc="Below ~0.95 sustained means shared_buffers is too small for the "
                "working set."),
        ts("Database size",
           [target("pg_database_size_bytes", "{{datname}}")],
           unit="bytes",
           desc="A read model that outgrows the event log usually means a "
                "projection is storing derived data it could recompute."),

        row("SeaweedFS — object storage"),
        stat("Master is leader", "SeaweedFS_master_is_leader", steps=UP_STEPS),
        stat("Volumes", "SeaweedFS_volumeServer_volumes"),
        stat("Max volumes", "SeaweedFS_volumeServer_max_volumes"),
        stat("Disk used", "sum(SeaweedFS_volumeServer_total_disk_size)", unit="bytes"),
        stat("Objects", "sum(SeaweedFS_s3_bucket_object_count)", graph=True),
        stat("Bucket bytes", "sum(SeaweedFS_s3_bucket_size_bytes)", unit="bytes", graph=True),

        ts("Filer request rate",
           [target("sum(rate(SeaweedFS_filer_request_total[5m])) by (type)", "{{type}}")],
           unit="reqps", w=8,
           desc="S3 clients reach object data through the filer, not the volume "
                "server directly."),
        ts("Filer latency p95",
           [target("histogram_quantile(0.95, sum(rate(SeaweedFS_filer_request_seconds_bucket[5m])) by (le, type))",
                   "{{type}}")],
           unit="s", w=8),
        ts("In-flight uploads",
           [target("SeaweedFS_s3_in_flight_upload_count", "s3 uploads"),
            target("SeaweedFS_filer_in_flight_requests", "filer requests")],
           w=8),

        row("Mailpit — SMTP capture (development only)"),
        ts("SMTP activity",
           [target("rate(mailpit_smtp_accepted_total[5m])", "accepted/s"),
            target("rate(mailpit_smtp_rejected_total[5m])", "rejected/s"),
            target("rate(mailpit_smtp_ignored_total[5m])", "ignored/s")],
           unit="ops", w=8,
           desc="Mail is sent from a Temporal Activity, so a rejection spike here "
                "should show as activity retries on the Workflows dashboard."),
        stat("Messages held", "mailpit_messages", w=4, h=8, graph=True),
        stat("Unread", "mailpit_messages_unread", w=4, h=8, graph=True),
        ts("Mailbox size",
           [target("mailpit_database_size_bytes", "database")],
           unit="bytes", w=8),
    ]
    return dashboard("chronos-storage", "Chronos — Storage & Data",
                     "PostgreSQL stores what a resource is, SeaweedFS stores its bytes, "
                     "Mailpit catches everything the app tries to email.",
                     p, ["postgres", "seaweedfs", "mailpit"])


# ===========================================================================
# 7. Application — the Go services themselves
# ===========================================================================
def application():
    """The chronos_* metrics the Go binaries publish.

    Every other dashboard here watches a dependency. This one watches OUR code,
    and it is the one that answers the two questions an operator actually asks:
    is the read model current, and did anything we tried to send go nowhere.

    A panel that renders "No data" here is usually correct rather than broken:
    the Go services run on the host and are not always up during local work.
    """
    reset_layout()
    p = [
        row("Is the read model current?"),
        stat("Projections live", "sum(chronos_projection_live)",
             desc="Projections caught up to the head of the log. Compare against the "
                  "number of projections the projector registers: a projection that is "
                  "BEHIND serves stale reads while looking healthy by every other measure.",
             steps=[{"color": "red", "value": None}, {"color": "green", "value": 1}]),
        stat("Projections stopped", "sum(increase(chronos_projection_errors_total[1h]))",
             desc="Applies that failed in the last hour. A projector does not retry "
                  "(ADR-019), so anything above zero means a read model has STOPPED and "
                  "is falling further behind with every event.",
             steps=[{"color": "green", "value": None}, {"color": "red", "value": 1}]),
        stat("Parked events", "sum(chronos_reactor_parked)",
             desc="Events that exhausted every redelivery and are waiting for a human. "
                  "Parked mail is mail nobody received.",
             steps=[{"color": "green", "value": None},
                    {"color": "orange", "value": 1}, {"color": "red", "value": 10}]),
        stat("Announcements dropped", "sum(increase(chronos_projection_announcements_dropped_total[1h]))",
             desc="Realtime messages discarded because the publisher was behind. Dropping "
                  "is deliberate — the read model never waits on Centrifugo — so this is "
                  "not an error rate. It is the only sign that live updates are failing "
                  "while every row stays correct.",
             steps=[{"color": "green", "value": None}, {"color": "orange", "value": 1}]),

        row("Projections"),
        ts("Live",
           [target("chronos_projection_live", "{{projection}}")],
           desc="1 = caught up. This is the metric to alert on.",
           minval=0),
        ts("Events applied",
           [target("sum(rate(chronos_projection_events_total[5m])) by (projection)",
                   "{{projection}}")],
           unit="ops",
           desc="Applied per second. A projection at zero while others move is either "
                "filtered to a quiet module or stuck."),
        ts("Apply latency p95",
           [target("histogram_quantile(0.95, sum(rate(chronos_projection_batch_seconds_bucket[5m])) by (le, projection))",
                   "{{projection}}")],
           unit="s",
           desc="One event's rows and checkpoint in a single round trip. While a projector "
                "is BEHIND many events share one transaction, so this falls sharply during "
                "catch-up — that is the batching working, not a measurement error."),
        ts("Commit position",
           [target("chronos_projection_commit_position", "{{projection}}")],
           desc="Position in $all. Two projections diverging means one is behind; flat "
                "while others climb means stopped."),
        ts("Events skipped",
           [target("sum(rate(chronos_projection_skipped_total[5m])) by (projection)",
                   "{{projection}}")],
           unit="ops",
           desc="Offered and not handled. Dwarfing the applied rate means the filter is "
                "too wide and the projection pays for events it never wanted."),
        table("Single-writer leases",
              [target("chronos_projection_lease_held", instant=True, fmt="table")],
              desc="Which process holds each projection's lease. Two holders for one "
                   "projection would mean two writers racing on the same checkpoint."),

        row("Reactors — effects on the outside world"),
        ts("Effects performed",
           [target("sum(rate(chronos_reactor_handled_total[5m])) by (reactor)", "{{reactor}}")],
           unit="ops"),
        ts("Effect latency p95",
           [target("histogram_quantile(0.95, sum(rate(chronos_reactor_seconds_bucket[5m])) by (le, reactor))",
                   "{{reactor}}")],
           unit="s",
           desc="For mail this is dominated by the SMTP conversation."),
        ts("Failures and poison",
           [target("sum(rate(chronos_reactor_failures_total[5m])) by (reactor)", "failed {{reactor}}"),
            target("sum(rate(chronos_reactor_poison_total[5m])) by (reactor)", "poison {{reactor}}")],
           unit="ops",
           desc="A failure is retried; poison is parked immediately because it can never "
                "succeed. A rising poison rate is a bug, not an outage."),
        ts("Parked backlog",
           [target("chronos_reactor_parked", "{{reactor}}")],
           desc="Server-side parked count, polled. Alert on this one."),
        ts("Duplicates suppressed",
           [target("sum(rate(chronos_reactor_duplicates_total[5m])) by (reactor)", "{{reactor}}")],
           unit="ops",
           desc="Redeliveries the dedup table caught. A rising rate means acks are being "
                "lost or handlers are timing out — the effect still happened once, but "
                "the transport does not know it."),

        row("Notifications"),
        ts("Delivered by channel",
           [target("sum(rate(chronos_notify_delivered_total[5m])) by (channel)", "{{channel}}")],
           unit="ops", stack=True,
           desc="A channel flat at zero while others move is usually a channel that was "
                "built and wired into nothing."),
        ts("Suppressed by reason",
           [target("sum(rate(chronos_notify_suppressed_total[5m])) by (reason)", "{{reason}}")],
           unit="ops", stack=True,
           desc="Suppression is the system WORKING — a preference switched off, an in-app "
                "read, an erased subject. Never alert on this as if it were a failure."),
        ts("Delivery failures",
           [target("sum(rate(chronos_notify_failed_total[5m])) by (channel)", "{{channel}}")],
           unit="ops", desc="Alert on this one."),
        ts("Mail",
           [target("sum(rate(chronos_mail_sent_total[5m]))", "sent"),
            target("sum(rate(chronos_mail_failed_total[5m]))", "failed"),
            target("sum(rate(chronos_mail_skipped_total[5m]))", "skipped")],
           unit="ops",
           desc="Skipped includes a subject whose personal data has been erased, which is "
                "a correct outcome and must not read as a failure."),

        row("Authorization and cache"),
        ts("Authorization decisions",
           [target("sum(rate(chronos_authz_allowed_total[5m])) by (source)", "allowed ({{source}})"),
            target("sum(rate(chronos_authz_denied_total[5m]))", "denied"),
            target("sum(rate(chronos_authz_failed_total[5m]))", "FAILED")],
           unit="ops",
           desc="Denied is the system working. FAILED is the one to alert on: every one of "
                "those denied too, so a rising rate is users losing access to resources "
                "they own (ADR-010)."),
        ts("Cache hit rate",
           [target("sum(rate(chronos_cache_hits_total[5m])) by (cache) / "
                   "clamp_min(sum(rate(chronos_cache_hits_total[5m])) by (cache) + "
                   "sum(rate(chronos_cache_misses_total[5m])) by (cache), 1)",
                   "{{cache}}")],
           unit="percentunit", minval=0,
           desc="A cache near zero costs a round trip and saves nothing."),
        ts("Cache faults",
           [target("sum(rate(chronos_cache_errors_total[5m])) by (op)", "{{op}}")],
           unit="ops",
           desc="Every one was survived by falling through to the source, so this is not "
                "alertable on its own. A sustained rate means the cache is effectively absent."),
        ts("Cache invalidations",
           [target("sum(rate(chronos_cache_invalidations_total[5m])) by (cache)", "{{cache}}")],
           unit="ops",
           desc="For the PII key cache this is the erasure-propagation signal: erasures "
                "happening with NO invalidations recorded means destroyed keys are still "
                "cached somewhere (ADR-041)."),
    ]
    return dashboard("chronos-application", "Chronos — Application",
                     "The Go services' own metrics. Projection liveness and parked events "
                     "are the two numbers worth paging on.",
                     p, ["application", "projections", "reactors"])


DASHBOARDS = {
    "chronos-overview.json": overview,
    "chronos-eventlog.json": eventlog,
    "chronos-authz.json": authz,
    "chronos-workflows.json": workflows,
    "chronos-realtime.json": realtime,
    "chronos-storage.json": storage,
    "chronos-application.json": application,
}


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    for name, fn in DASHBOARDS.items():
        target.n = 0
        d = fn()
        (OUT / name).write_text(json.dumps(d, indent=2) + "\n")
        n = len([p for p in d["panels"] if p["type"] != "row"])
        print(f"  wrote {name:28s} {n:2d} panels")


if __name__ == "__main__":
    main()
