package main

// The seven provisioned dashboards, in the order they are written.
//
// Every PromQL expression here is validated against a live Prometheus by
// internal/tools/checkdashboards — run `make dashboards-check` after changing
// one. A panel with a wrong metric name renders as "0", which reads as healthy
// when it is not, so a query that has never been run against real data is a
// panel that has never been checked.

// overview is the "is anything on fire" dashboard: one row per question the
// architecture assigns to a component.
func overview() obj {
	resetLayout()
	p := arr{
		row("Component health"),
		health("Event log", "kurrentdb"),
		health("AuthZ", "openfga"),
		health("Read model", "postgres"),
		health("Cache", "valkey"),
		health("Realtime", "centrifugo"),
		health("Workflows", "temporal"),
		health("Object store", "seaweedfs"),
		health("SMTP", "mailpit"),

		// `up{job=...}` and chronos_dependency_health answer DIFFERENT questions,
		// and both rows are kept because the gap between them is where incidents
		// live. `up` is scrape reachability: can Prometheus open a socket to the
		// exporter. chronos_dependency_health is our own probe's answer: does the
		// dependency work FOR US. A PostgreSQL that accepts connections and
		// rejects our credentials is up=1 and health down. A sealed OpenBao is
		// up=1 and health down. And the two Temporal schedule probes have no `up`
		// equivalent at all — Temporal is perfectly reachable while the recurring
		// job it was supposed to run does not exist.
		row("Dependency health — our probes, not scrape reachability"),
		stat("Dependencies down", `sum(chronos_dependency_health{state="down"})`,
			steps(depSteps),
			desc("Dependencies our own probes report as DOWN. This is not the row "+
				"above: that one says Prometheus can reach an exporter, this one says "+
				"the dependency works for us. Credentials rejected, a sealed vault or "+
				"a missing schedule all show here and nowhere else.")),
		stat("Dependencies degraded", `sum(chronos_dependency_health{state="degraded"})`,
			steps(degradedSteps),
			desc("Degradable dependencies that are failing. The product still serves; "+
				"some capability is gone. Sustained is the alertable state — brief is "+
				"the design working.")),
		stat("Recurring jobs scheduled",
			`sum(chronos_dependency_health{dependency=~"`+scheduleProbes+`", state="up"})`,
			steps(arr{
				obj{{"color", "red"}, {"value", nil}},
				obj{{"color", "green"}, {"value", 2}},
			}),
			desc("Should be 2: the lapsed-email-reservation sweep and identity "+
				"retention. Below 2 means a recurring job has no schedule and will "+
				"never run — silently, with nothing else reporting it.")),
		table("Dependency probes",
			arr{query("chronos_dependency_health == 1", instant(), tableFormat())},
			width(12), height(8),
			desc("One row per dependency, showing the state currently in effect and "+
				"its criticality. CRITICAL down fails readiness; FAIL_CLOSED down "+
				"means authorization denies everything but the instance stays in the "+
				"load balancer (ADR-010). The error text is deliberately not a label "+
				"— read it from the status endpoint.")),

		row("Throughput — one panel per owned question"),
		timeseries("What happened? — KurrentDB event I/O",
			arr{query("sum(rate(kurrentdb_io_events_total[5m])) by (activity)", legendFormat("{{activity}}"))},
			unit("ops"), width(8),
			desc("Events read from and written to the log. The write line is the "+
				"true ingest rate of the whole system.")),
		timeseries("Who may do what? — OpenFGA gRPC calls",
			arr{query(`sum(rate(grpc_server_started_total{job="openfga"}[5m])) by (grpc_method)`,
				legendFormat("{{grpc_method}}"))},
			unit("reqps"), width(8),
			desc("Check/BatchCheck/ListObjects rate. This is the request-path "+
				"authorization load.")),
		timeseries("What is in flight? — Temporal service requests",
			arr{query(`sum(rate(service_requests{job="temporal"}[5m])) by (operation)`,
				legendFormat("{{operation}}"))},
			unit("reqps"), width(8), legend("hidden"),
			desc("Frontend/history/matching operations across the Temporal service.")),

		timeseries("Who is connected? — Centrifugo",
			arr{
				query("centrifugo_node_num_clients", legendFormat("clients")),
				query("centrifugo_node_num_subscriptions", legendFormat("subscriptions")),
				query("centrifugo_node_num_channels", legendFormat("channels")),
			},
			width(8),
			desc("Live WebSocket state. Go services hold none of these connections.")),
		timeseries("What is ephemeral? — Valkey ops",
			arr{
				query("rate(redis_commands_processed_total[5m])", legendFormat("commands/s")),
				query("redis_connected_clients", legendFormat("clients")),
			},
			unit("ops"), width(8),
			desc("Sessions, rate limiting and the Centrifugo backplane share this instance.")),
		timeseries("What does it look like now? — PostgreSQL connections",
			arr{query("sum(pg_stat_activity_count) by (datname)", legendFormat("{{datname}}"))},
			width(8), stacked(),
			desc("Per-database connection count. chronos = read model, "+
				"openfga / temporal = their own stores.")),

		row("Capacity"),
		stat("S3 objects", "sum(SeaweedFS_s3_bucket_object_count)", graph()),
		stat("S3 bytes", "sum(SeaweedFS_s3_bucket_size_bytes)", unit("bytes"), graph()),
		stat("Read-model size", `sum(pg_database_size_bytes{datname="chronos"})`,
			unit("bytes"), graph()),
		stat("Valkey memory", "redis_memory_used_bytes", unit("bytes"), graph()),
		stat("KurrentDB memory", "kurrentdb_proc_mem_bytes", unit("bytes"), graph()),
		stat("Captured mail", "mailpit_messages", graph(),
			desc("Mailpit never delivers — this only ever grows in development.")),
	}
	return dashboard("chronos-overview", "Chronos — Stack Overview",
		"One row per question the architecture assigns to a component. "+
			"Start here; drill into a component dashboard from the tag list.",
		p, arr{"overview"})
}

// eventlog watches KurrentDB: the single source of truth.
func eventlog() obj {
	resetLayout()
	p := arr{
		row("Ingest"),
		timeseries("Event throughput",
			arr{query("sum(rate(kurrentdb_io_events_total[5m])) by (activity)", legendFormat("{{activity}}"))},
			unit("ops"),
			desc("Writes are appends from the Go API. Reads are dominated by "+
				"projector catch-up subscriptions.")),
		timeseries("Byte throughput",
			arr{query("sum(rate(kurrentdb_io_bytes_total[5m])) by (activity)", legendFormat("{{activity}}"))},
			unit("Bps")),

		row("Projector health — the numbers that break CQRS"),
		timeseries("Secondary index lag",
			arr{query("kurrentdb_indexes_secondary_lag_seconds", legendFormat("lag"))},
			unit("s"),
			desc("Time between a record being appended and being indexed. If this "+
				"climbs, read models fall behind writes.")),
		timeseries("Secondary index gap",
			arr{query("kurrentdb_indexes_secondary_gap_bytes", legendFormat("gap"))},
			unit("bytes"),
			desc("Bytes between the log tail and the last indexed record.")),

		row("gRPC — the client-facing surface"),
		timeseries("Incoming gRPC call rate",
			arr{query("sum(rate(kurrentdb_incoming_grpc_calls_total[5m])) by (kind)", legendFormat("{{kind}}"))},
			unit("reqps")),
		timeseries("In-flight gRPC calls",
			arr{query("kurrentdb_current_incoming_grpc_calls", legendFormat("in flight"))}),

		row("Storage engine"),
		timeseries("Queue time (max)",
			arr{query("topk(5, kurrentdb_queue_queueing_duration_max_seconds)", legendFormat("{{queue}}"))},
			unit("s"), desc("Top 5 internal queues by queueing delay.")),
		timeseries("Writer flush duration (max)",
			arr{query("kurrentdb_writer_flush_duration_max_seconds", legendFormat("flush"))},
			unit("s"),
			desc("How long the chunk writer takes to fsync. Directly bounds append latency.")),
		timeseries("Disk I/O",
			arr{query("sum(rate(kurrentdb_disk_io_bytes_total[5m])) by (activity)", legendFormat("{{activity}}"))},
			unit("Bps")),
		timeseries("Record read duration p99",
			arr{query("histogram_quantile(0.99, sum(rate(kurrentdb_io_record_read_duration_seconds_bucket[5m])) by (le))",
				legendFormat("p99"))},
			unit("s"), desc("The Haystack-style O(1) read path, measured.")),

		row("Process"),
		timeseries("CPU",
			arr{
				query("kurrentdb_proc_cpu", legendFormat("process")),
				query("kurrentdb_sys_cpu", legendFormat("system")),
			},
			unit("percentunit")),
		timeseries("Memory",
			arr{
				query("kurrentdb_proc_mem_bytes", legendFormat("process")),
				query("sum(kurrentdb_gc_heap_size_bytes)", legendFormat("GC heap")),
			},
			unit("bytes")),
	}
	return dashboard("chronos-eventlog", "Chronos — Event Log (KurrentDB)",
		"The single source of truth. Index lag is the metric that matters "+
			"most: it bounds how stale every PostgreSQL read model can be.",
		p, arr{"kurrentdb", "event-sourcing"})
}

// authz watches OpenFGA, plus the span metrics Tempo generates.
func authz() obj {
	resetLayout()
	p := arr{
		row("Request path"),
		timeseries("gRPC calls by method",
			arr{query(`sum(rate(grpc_server_started_total{job="openfga"}[5m])) by (grpc_method)`,
				legendFormat("{{grpc_method}}"))},
			unit("reqps"), width(16),
			desc("Check and BatchCheck should dominate. A high ListObjects rate on "+
				"the request path usually means a screen is asking the wrong question.")),
		// `or vector(0)` so an idle, healthy server renders "0" rather than
		// "No data" — the two look identical at a glance but mean opposite things.
		stat("Errors / sec",
			`sum(rate(grpc_server_handled_total{job="openfga",grpc_code!="OK"}[5m])) or vector(0)`,
			unit("reqps"), width(4), height(8), steps(invSteps), graph(),
			desc("Non-OK gRPC responses. Note: unauthenticated calls count here.")),
		stat("Goroutines", `go_goroutines{job="openfga"}`, width(4), height(8), graph()),

		row("Cache — the difference between fast and slow authorization"),
		timeseries("Check cache hit ratio",
			arr{query("rate(openfga_check_cache_hit_count[5m]) / "+
				"clamp_min(rate(openfga_check_cache_total_count[5m]), 1)", legendFormat("hit ratio"))},
			unit("percentunit"), minVal(0),
			desc("Cold cache means every Check walks the graph in PostgreSQL.")),
		timeseries("Cache activity",
			arr{
				query("rate(openfga_check_cache_total_count[5m])", legendFormat("lookups/s")),
				query("rate(openfga_check_cache_hit_count[5m])", legendFormat("hits/s")),
				query("rate(openfga_cachecontroller_cache_invalidation_count[5m])", legendFormat("invalidations/s")),
			},
			unit("ops"),
			desc("Invalidations spike after WriteTuples — expected right after a share.")),

		row("Conditions (ABAC)"),
		timeseries("Condition evaluation p95",
			arr{query("histogram_quantile(0.95, sum(rate(openfga_condition_evaluation_duration_ms_bucket[5m])) by (le))",
				legendFormat("p95"))},
			unit("ms"),
			desc("CEL expression cost — this is where 'share expires in 7 days' is enforced.")),
		timeseries("Iterators in flight",
			arr{query("openfga_shared_iterator_count", legendFormat("shared iterators"))},
			desc("Graph-walk iterators. Growth without bound means a query is fanning out.")),

		row("Traces — OpenFGA is the only component emitting OTLP without a licence"),
		timeseries("Span rate by service",
			arr{query("sum(rate(traces_spanmetrics_calls_total[5m])) by (service)", legendFormat("{{service}}"))},
			unit("reqps"), width(12),
			desc("Generated by Tempo's metrics-generator from received spans. "+
				"Go services appear here automatically once they export OTLP.")),
		timeseries("Span latency p95 by service",
			arr{query("histogram_quantile(0.95, sum(rate(traces_spanmetrics_latency_bucket[5m])) by (le, service))",
				legendFormat("{{service}}"))},
			unit("s"), width(12)),
	}
	return dashboard("chronos-authz", "Chronos — Authorization (OpenFGA)",
		"Every access decision in the system. If a permission question is "+
			"being answered anywhere else (a SQL join, a Go loop), that is a bug.",
		p, arr{"openfga", "authorization"})
}

// workflows watches Temporal: durable execution.
func workflows() obj {
	resetLayout()
	p := arr{
		row("Service"),
		timeseries("Request rate by operation",
			arr{query(`sum(rate(service_requests{job="temporal"}[5m])) by (operation)`,
				legendFormat("{{operation}}"))},
			unit("reqps"), legend("hidden")),
		timeseries("Service latency p95",
			arr{query(`histogram_quantile(0.95, sum(rate(service_latency_bucket{job="temporal"}[5m])) by (le, operation))`,
				legendFormat("{{operation}}"))},
			unit("s"), legend("hidden")),
		timeseries("Errors by type",
			arr{query(`sum(rate(service_error_with_type{job="temporal"}[5m])) by (error_type)`,
				legendFormat("{{error_type}}"))},
			unit("reqps"),
			desc("Some error types are normal control flow in Temporal "+
				"(e.g. NotFound on a first poll).")),
		timeseries("gRPC connections",
			arr{query(`service_grpc_conn_active{job="temporal"}`, legendFormat("active"))},
			desc("Worker connections. Zero here means no Go worker is polling yet.")),

		row("Task queues — where work waits"),
		timeseries("Backlog size",
			arr{query("sum(approximate_backlog_count) by (taskqueue)", legendFormat("{{taskqueue}}"))},
			desc("Tasks waiting for a worker. Sustained growth means too few workers.")),
		timeseries("Backlog age",
			arr{query("sum(approximate_backlog_age_seconds) by (taskqueue)", legendFormat("{{taskqueue}}"))},
			unit("s"),
			desc("How long the oldest queued task has waited. The user-visible number.")),
		timeseries("Pollers",
			arr{query("sum(temporal_num_pollers) by (poller_type)", legendFormat("{{poller_type}}"))},
			desc("Long-poll connections from Go workers.")),
		timeseries("Loaded task queue partitions",
			arr{query("loaded_task_queue_partition_count", legendFormat("partitions"))}),

		row("Persistence — Temporal's PostgreSQL usage"),
		timeseries("Persistence request rate",
			arr{query(`sum(rate(persistence_requests{job="temporal"}[5m])) by (operation)`,
				legendFormat("{{operation}}"))},
			unit("reqps"), legend("hidden")),
		timeseries("Persistence latency p95",
			arr{query(`histogram_quantile(0.95, sum(rate(persistence_latency_bucket{job="temporal"}[5m])) by (le))`,
				legendFormat("p95"))},
			unit("s"),
			desc("Temporal shares the PostgreSQL instance with the read model — "+
				"watch this when the read model is under load.")),
		timeseries("SQL connection pool",
			arr{
				query("sum(persistence_sql_in_use)", legendFormat("in use")),
				query("sum(persistence_sql_open_conn)", legendFormat("open")),
				query("sum(persistence_sql_max_open_conn)", legendFormat("max")),
			},
			desc("Hitting max is the classic cause of workflow stalls.")),
		timeseries("Shard queue lag p95",
			arr{
				query("histogram_quantile(0.95, sum(rate(shardinfo_immediate_queue_lag_bucket[5m])) by (le))",
					legendFormat("immediate")),
				query("histogram_quantile(0.95, sum(rate(shardinfo_scheduled_queue_lag_bucket[5m])) by (le))",
					legendFormat("scheduled")),
			},
			desc("Scheduled-queue lag is why a workflow timer might fire late.")),
	}
	return dashboard("chronos-workflows", "Chronos — Workflows (Temporal)",
		"Durable execution. Backlog age and scheduled-queue lag are the two "+
			"numbers that show up as user-visible delay.",
		p, arr{"temporal", "workflows"})
}

// realtime watches Centrifugo and Valkey.
func realtime() obj {
	resetLayout()
	p := arr{
		row("Centrifugo — connection state"),
		stat("Clients", "centrifugo_node_num_clients", graph()),
		stat("Users", "centrifugo_node_num_users", graph()),
		stat("Channels", "centrifugo_node_num_channels", graph()),
		stat("Subscriptions", "centrifugo_node_num_subscriptions", graph()),
		stat("Nodes", "centrifugo_node_num_nodes", graph(),
			desc("More than one requires the Valkey backplane to be working.")),
		stat("Connection limit", "centrifugo_node_client_connection_limit"),

		row("Centrifugo — message flow"),
		timeseries("Messages sent",
			arr{query("sum(rate(centrifugo_node_messages_sent_count[5m])) by (type)", legendFormat("{{type}}"))},
			unit("ops"),
			desc("'publication' is application data; 'control' is inter-node gossip.")),
		timeseries("Messages received",
			arr{query("sum(rate(centrifugo_node_messages_received_count[5m])) by (type)", legendFormat("{{type}}"))},
			unit("ops")),
		timeseries("Client command duration p99",
			arr{query("histogram_quantile(0.99, sum(rate(centrifugo_client_command_duration_seconds_histogram_bucket[5m])) by (le, method))",
				legendFormat("{{method}}"))},
			unit("s")),
		timeseries("Redis PUB/SUB buffer",
			arr{
				query("centrifugo_broker_redis_pub_sub_buffered_messages", legendFormat("buffered")),
				query("centrifugo_broker_redis_pub_sub_dropped_messages", legendFormat("dropped")),
			},
			desc("Dropped messages mean subscribers missed updates — clients must "+
				"re-read from the API, which is why pushes are notifications only.")),

		row("Valkey — ephemeral state"),
		timeseries("Command rate",
			arr{
				query("rate(redis_commands_processed_total[5m])", legendFormat("commands/s")),
				query("rate(redis_connections_received_total[5m])", legendFormat("new connections/s")),
			},
			unit("ops")),
		timeseries("Memory",
			arr{
				query("redis_memory_used_bytes", legendFormat("used")),
				query("redis_config_maxmemory", legendFormat("maxmemory")),
			},
			unit("bytes"),
			desc("maxmemory-policy is allkeys-lru: reaching the limit evicts, "+
				"it does not error.")),
		timeseries("Keys by database",
			arr{
				query("redis_db_keys", legendFormat("db{{db}} keys")),
				query("redis_db_keys_expiring", legendFormat("db{{db}} with TTL")),
			},
			desc("Every key in this stack should have a TTL. A widening gap between "+
				"these two lines is a leak.")),
		timeseries("Evictions and expiries",
			arr{
				query("rate(redis_evicted_keys_total[5m])", legendFormat("evicted/s")),
				query("rate(redis_expired_keys_total[5m])", legendFormat("expired/s")),
			},
			unit("ops"),
			desc("Evictions mean Valkey is dropping data early — raise maxmemory.")),
	}
	return dashboard("chronos-realtime", "Chronos — Realtime & Cache",
		"Centrifugo holds the WebSockets so Go services do not, and Valkey "+
			"is both its backplane and the app's ephemeral store.",
		p, arr{"centrifugo", "valkey"})
}

// storage watches PostgreSQL, SeaweedFS and Mailpit.
func storage() obj {
	resetLayout()
	p := arr{
		row("PostgreSQL — read model + OpenFGA + Temporal"),
		timeseries("Connections by database",
			arr{query("sum(pg_stat_activity_count) by (datname)", legendFormat("{{datname}}"))},
			stacked(),
			desc("Four databases share one server: chronos, openfga, temporal, "+
				"temporal_visibility.")),
		timeseries("Transaction rate",
			arr{
				query("sum(rate(pg_stat_database_xact_commit[5m])) by (datname)", legendFormat("{{datname}} commit")),
				query("sum(rate(pg_stat_database_xact_rollback[5m])) by (datname)", legendFormat("{{datname}} rollback")),
			},
			unit("ops")),
		timeseries("Cache hit ratio",
			arr{query("sum(rate(pg_stat_database_blks_hit[5m])) by (datname) / "+
				"clamp_min(sum(rate(pg_stat_database_blks_hit[5m]) + "+
				"rate(pg_stat_database_blks_read[5m])) by (datname), 1)", legendFormat("{{datname}}"))},
			unit("percentunit"), minVal(0),
			desc("Below ~0.95 sustained means shared_buffers is too small for the "+
				"working set.")),
		timeseries("Database size",
			arr{query("pg_database_size_bytes", legendFormat("{{datname}}"))},
			unit("bytes"),
			desc("A read model that outgrows the event log usually means a "+
				"projection is storing derived data it could recompute.")),

		row("SeaweedFS — object storage"),
		stat("Master is leader", "SeaweedFS_master_is_leader", steps(upSteps)),
		stat("Volumes", "SeaweedFS_volumeServer_volumes"),
		stat("Max volumes", "SeaweedFS_volumeServer_max_volumes"),
		stat("Disk used", "sum(SeaweedFS_volumeServer_total_disk_size)", unit("bytes")),
		stat("Objects", "sum(SeaweedFS_s3_bucket_object_count)", graph()),
		stat("Bucket bytes", "sum(SeaweedFS_s3_bucket_size_bytes)", unit("bytes"), graph()),

		timeseries("Filer request rate",
			arr{query("sum(rate(SeaweedFS_filer_request_total[5m])) by (type)", legendFormat("{{type}}"))},
			unit("reqps"), width(8),
			desc("S3 clients reach object data through the filer, not the volume "+
				"server directly.")),
		timeseries("Filer latency p95",
			arr{query("histogram_quantile(0.95, sum(rate(SeaweedFS_filer_request_seconds_bucket[5m])) by (le, type))",
				legendFormat("{{type}}"))},
			unit("s"), width(8)),
		timeseries("In-flight uploads",
			arr{
				query("SeaweedFS_s3_in_flight_upload_count", legendFormat("s3 uploads")),
				query("SeaweedFS_filer_in_flight_requests", legendFormat("filer requests")),
			},
			width(8)),

		row("Mailpit — SMTP capture (development only)"),
		timeseries("SMTP activity",
			arr{
				query("rate(mailpit_smtp_accepted_total[5m])", legendFormat("accepted/s")),
				query("rate(mailpit_smtp_rejected_total[5m])", legendFormat("rejected/s")),
				query("rate(mailpit_smtp_ignored_total[5m])", legendFormat("ignored/s")),
			},
			unit("ops"), width(8),
			desc("Mail is sent from a Temporal Activity, so a rejection spike here "+
				"should show as activity retries on the Workflows dashboard.")),
		stat("Messages held", "mailpit_messages", width(4), height(8), graph()),
		stat("Unread", "mailpit_messages_unread", width(4), height(8), graph()),
		timeseries("Mailbox size",
			arr{query("mailpit_database_size_bytes", legendFormat("database"))},
			unit("bytes"), width(8)),
	}
	return dashboard("chronos-storage", "Chronos — Storage & Data",
		"PostgreSQL stores what a resource is, SeaweedFS stores its bytes, "+
			"Mailpit catches everything the app tries to email.",
		p, arr{"postgres", "seaweedfs", "mailpit"})
}

// application watches the chronos_* metrics the Go binaries publish.
//
// Every other dashboard here watches a dependency. This one watches OUR code,
// and it is the one that answers the two questions an operator actually asks: is
// the read model current, and did anything we tried to send go nowhere.
//
// A panel that renders "No data" here is usually correct rather than broken: the
// Go services run on the host and are not always up during local work.
func application() obj {
	resetLayout()
	p := arr{
		row("Is the read model current?"),
		stat("Projections live", "sum(chronos_projection_live)",
			desc("Projections caught up to the head of the log. Compare against the "+
				"number of projections the projector registers: a projection that is "+
				"BEHIND serves stale reads while looking healthy by every other measure."),
			steps(arr{
				obj{{"color", "red"}, {"value", nil}},
				obj{{"color", "green"}, {"value", 1}},
			})),
		stat("Projections stopped", "sum(increase(chronos_projection_errors_total[1h]))",
			desc("Applies that failed in the last hour. A projector does not retry "+
				"(ADR-019), so anything above zero means a read model has STOPPED and "+
				"is falling further behind with every event."),
			steps(arr{
				obj{{"color", "green"}, {"value", nil}},
				obj{{"color", "red"}, {"value", 1}},
			})),
		stat("Parked events", "sum(chronos_reactor_parked)",
			desc("Events that exhausted every redelivery and are waiting for a human. "+
				"Parked mail is mail nobody received."),
			steps(arr{
				obj{{"color", "green"}, {"value", nil}},
				obj{{"color", "orange"}, {"value", 1}},
				obj{{"color", "red"}, {"value", 10}},
			})),
		stat("Announcements dropped", "sum(increase(chronos_projection_announcements_dropped_total[1h]))",
			desc("Realtime messages discarded because the publisher was behind. Dropping "+
				"is deliberate — the read model never waits on Centrifugo — so this is "+
				"not an error rate. It is the only sign that live updates are failing "+
				"while every row stays correct."),
			steps(arr{
				obj{{"color", "green"}, {"value", nil}},
				obj{{"color", "orange"}, {"value", 1}},
			})),

		row("Projections"),
		timeseries("Live",
			arr{query("chronos_projection_live", legendFormat("{{projection}}"))},
			desc("1 = caught up. This is the metric to alert on."),
			minVal(0)),
		timeseries("Events applied",
			arr{query("sum(rate(chronos_projection_events_total[5m])) by (projection)",
				legendFormat("{{projection}}"))},
			unit("ops"),
			desc("Applied per second. A projection at zero while others move is either "+
				"filtered to a quiet module or stuck.")),
		timeseries("Apply latency p95",
			arr{query("histogram_quantile(0.95, sum(rate(chronos_projection_batch_seconds_bucket[5m])) by (le, projection))",
				legendFormat("{{projection}}"))},
			unit("s"),
			desc("One event's rows and checkpoint in a single round trip. While a projector "+
				"is BEHIND many events share one transaction, so this falls sharply during "+
				"catch-up — that is the batching working, not a measurement error.")),
		timeseries("Commit position",
			arr{query("chronos_projection_commit_position", legendFormat("{{projection}}"))},
			desc("Position in $all. Two projections diverging means one is behind; flat "+
				"while others climb means stopped.")),
		timeseries("Events skipped",
			arr{query("sum(rate(chronos_projection_skipped_total[5m])) by (projection)",
				legendFormat("{{projection}}"))},
			unit("ops"),
			desc("Offered and not handled. Dwarfing the applied rate means the filter is "+
				"too wide and the projection pays for events it never wanted.")),
		table("Single-writer leases",
			arr{query("chronos_projection_lease_held", instant(), tableFormat())},
			desc("Which process holds each projection's lease. Two holders for one "+
				"projection would mean two writers racing on the same checkpoint.")),

		row("Reactors — effects on the outside world"),
		timeseries("Effects performed",
			arr{query("sum(rate(chronos_reactor_handled_total[5m])) by (reactor)", legendFormat("{{reactor}}"))},
			unit("ops")),
		timeseries("Effect latency p95",
			arr{query("histogram_quantile(0.95, sum(rate(chronos_reactor_seconds_bucket[5m])) by (le, reactor))",
				legendFormat("{{reactor}}"))},
			unit("s"),
			desc("For mail this is dominated by the SMTP conversation.")),
		timeseries("Failures and poison",
			arr{
				query("sum(rate(chronos_reactor_failures_total[5m])) by (reactor)", legendFormat("failed {{reactor}}")),
				query("sum(rate(chronos_reactor_poison_total[5m])) by (reactor)", legendFormat("poison {{reactor}}")),
			},
			unit("ops"),
			desc("A failure is retried; poison is parked immediately because it can never "+
				"succeed. A rising poison rate is a bug, not an outage.")),
		timeseries("Parked backlog",
			arr{query("chronos_reactor_parked", legendFormat("{{reactor}}"))},
			desc("Server-side parked count, polled. Alert on this one.")),
		timeseries("Duplicates suppressed",
			arr{query("sum(rate(chronos_reactor_duplicates_total[5m])) by (reactor)", legendFormat("{{reactor}}"))},
			unit("ops"),
			desc("Redeliveries the dedup table caught. A rising rate means acks are being "+
				"lost or handlers are timing out — the effect still happened once, but "+
				"the transport does not know it.")),

		row("Notifications"),
		timeseries("Delivered by channel",
			arr{query("sum(rate(chronos_notify_delivered_total[5m])) by (channel)", legendFormat("{{channel}}"))},
			unit("ops"), stacked(),
			desc("A channel flat at zero while others move is usually a channel that was "+
				"built and wired into nothing.")),
		timeseries("Suppressed by reason",
			arr{query("sum(rate(chronos_notify_suppressed_total[5m])) by (reason)", legendFormat("{{reason}}"))},
			unit("ops"), stacked(),
			desc("Suppression is the system WORKING — a preference switched off, an in-app "+
				"read, an erased subject. Never alert on this as if it were a failure.")),
		timeseries("Delivery failures",
			arr{query("sum(rate(chronos_notify_failed_total[5m])) by (channel)", legendFormat("{{channel}}"))},
			unit("ops"), desc("Alert on this one.")),
		timeseries("Mail",
			arr{
				query("sum(rate(chronos_mail_sent_total[5m]))", legendFormat("sent")),
				query("sum(rate(chronos_mail_failed_total[5m]))", legendFormat("failed")),
				query("sum(rate(chronos_mail_skipped_total[5m]))", legendFormat("skipped")),
			},
			unit("ops"),
			desc("Skipped includes a subject whose personal data has been erased, which is "+
				"a correct outcome and must not read as a failure.")),

		row("Authorization and cache"),
		timeseries("Authorization decisions",
			arr{
				query("sum(rate(chronos_authz_allowed_total[5m])) by (source)", legendFormat("allowed ({{source}})")),
				query("sum(rate(chronos_authz_denied_total[5m]))", legendFormat("denied")),
				query("sum(rate(chronos_authz_failed_total[5m]))", legendFormat("FAILED")),
			},
			unit("ops"),
			desc("Denied is the system working. FAILED is the one to alert on: every one of "+
				"those denied too, so a rising rate is users losing access to resources "+
				"they own (ADR-010).")),
		timeseries("Cache hit rate",
			arr{query("sum(rate(chronos_cache_hits_total[5m])) by (cache) / "+
				"clamp_min(sum(rate(chronos_cache_hits_total[5m])) by (cache) + "+
				"sum(rate(chronos_cache_misses_total[5m])) by (cache), 1)",
				legendFormat("{{cache}}"))},
			unit("percentunit"), minVal(0),
			desc("A cache near zero costs a round trip and saves nothing.")),
		timeseries("Cache faults",
			arr{query("sum(rate(chronos_cache_errors_total[5m])) by (op)", legendFormat("{{op}}"))},
			unit("ops"),
			desc("Every one was survived by falling through to the source, so this is not "+
				"alertable on its own. A sustained rate means the cache is effectively absent.")),
		timeseries("Cache invalidations",
			arr{query("sum(rate(chronos_cache_invalidations_total[5m])) by (cache)", legendFormat("{{cache}}"))},
			unit("ops"),
			desc("For the PII key cache this is the erasure-propagation signal: erasures "+
				"happening with NO invalidations recorded means destroyed keys are still "+
				"cached somewhere (ADR-041).")),

		row("Dependency probes — what the status endpoint says"),
		timeseries("Recurring jobs scheduled",
			arr{query(`chronos_dependency_health{dependency=~"`+scheduleProbes+`", state="up"}`,
				legendFormat("{{dependency}}"))},
			minVal(0),
			desc("1 = the Temporal schedule EXISTS. Not that its last run succeeded — a "+
				"failed run is Temporal's to retry and shows in its own UI. A schedule "+
				"that was never created is invisible everywhere else: no error, no failed "+
				"workflow, no metric that moves. At 0, lapsed email reservations are never "+
				"released and identity retention never runs, so totp_replay grows without "+
				"bound (ADR-049).")),
		timeseries("Dependencies not up",
			arr{
				query(`sum by (dependency) (chronos_dependency_health{state="down"})`,
					legendFormat("down {{dependency}}")),
				query(`sum by (dependency) (chronos_dependency_health{state="degraded"})`,
					legendFormat("degraded {{dependency}}")),
			},
			minVal(0),
			desc("Our probes' answer, which is not up{job=...}: that one is scrape "+
				"reachability, this one is whether the dependency works for us. Rejected "+
				"credentials and a sealed vault are up=1 here and down.")),
		timeseries("Probe latency p99",
			arr{query("histogram_quantile(0.99, sum(rate(chronos_dependency_check_seconds_bucket[5m])) "+
				"by (le, dependency))", legendFormat("{{dependency}}"))},
			unit("s"),
			desc("A dependency that is up but answering slowly is the state that precedes "+
				"an outage, and a boolean cannot show it. The probe timeout is 2s, so a "+
				"line pinned at the top bucket is a probe timing out.")),
		timeseries("Probe evaluations",
			arr{query("sum by (state) (rate(chronos_dependency_checks_total[5m]))", legendFormat("{{state}}"))},
			unit("ops"),
			desc("The registry is only evaluated when something calls readiness or the "+
				"status endpoint. Flat at zero means NOBODY IS ASKING — the gauges above "+
				"are then stale, not healthy.")),
	}
	return dashboard("chronos-application", "Chronos — Application",
		"The Go services' own metrics. Projection liveness and parked events "+
			"are the two numbers worth paging on.",
		p, arr{"application", "projections", "reactors"})
}

// generator is one dashboard file and the function that builds it.
type generator struct {
	name  string
	build func() obj
}

// dashboards is the full set, in write order.
func dashboards() []generator {
	return []generator{
		{"chronos-overview.json", overview},
		{"chronos-eventlog.json", eventlog},
		{"chronos-authz.json", authz},
		{"chronos-workflows.json", workflows},
		{"chronos-realtime.json", realtime},
		{"chronos-storage.json", storage},
		{"chronos-application.json", application},
	}
}
