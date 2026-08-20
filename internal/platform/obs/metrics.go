// Package obs is the metrics surface for the event-sourcing runtime.
//
// It exists because the two questions an operator actually asks at 3am —
// "is the read model current?" and "how much mail did we fail to send?" —
// cannot be answered from logs. A projector that is a day behind and one that is
// idle produce identical log output: nothing.
//
// Metric names follow Prometheus convention: `chronos_<subsystem>_<thing>_<unit>`,
// counters end in `_total`, and every series carries the projection or reactor
// name so one broken consumer is distinguishable from a broken fleet.
package obs

import (
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
)

// Metrics holds every instrument the runtime publishes.
//
// One struct rather than package-level globals: globals make two instances in
// one test process fight over the same registry, and they hide which subsystem
// owns what.
type Metrics struct {
	registry *prometheus.Registry

	// ---- projections -----------------------------------------------------

	// ProjectionEvents counts events applied, per projection.
	ProjectionEvents *prometheus.CounterVec

	// ProjectionSkipped counts events a projection was offered and did not
	// handle. A projection whose skipped count dwarfs its applied count is
	// filtering badly and paying for events it never wanted.
	ProjectionSkipped *prometheus.CounterVec

	// ProjectionErrors counts failed applies. Any value above zero means a
	// projection has stopped: it does not retry (ADR-019).
	ProjectionErrors *prometheus.CounterVec

	// ProjectionLive is 1 when a projection has caught up to the head of the
	// log, 0 while it is replaying or disconnected. This is the metric to alert
	// on — a projection that is behind serves stale reads while looking healthy
	// by every other measure.
	ProjectionLive *prometheus.GaugeVec

	// ProjectionPosition is the $all commit position a projection has reached.
	// Compared against the log head it gives lag in bytes, which is the only
	// lag measure available without a second subscription.
	ProjectionPosition *prometheus.GaugeVec

	// ProjectionBatchSeconds measures one event's full write: scope, rows and
	// checkpoint in a single round trip.
	ProjectionBatchSeconds *prometheus.HistogramVec

	// ProjectionHolder reports which process holds each projection's lease.
	ProjectionHolder *prometheus.GaugeVec

	// ProjectionAnnouncementsDropped counts realtime messages discarded because
	// the publisher was behind. Dropping is deliberate — the read model never
	// waits on Centrifugo — so this is not an error rate; it is the only sign
	// that the realtime path is failing, since the rows and checkpoints stay
	// perfectly healthy while browsers stop seeing updates.
	ProjectionAnnouncementsDropped *prometheus.CounterVec

	// ---- reactors --------------------------------------------------------

	// ReactorHandled counts effects actually performed.
	ReactorHandled *prometheus.CounterVec

	// ReactorDuplicates counts redeliveries suppressed by the dedup table. A
	// rising rate means acks are being lost or handlers are timing out.
	ReactorDuplicates *prometheus.CounterVec

	// ReactorFailures counts effects that failed and will be retried.
	ReactorFailures *prometheus.CounterVec

	// ReactorPoison counts events parked immediately as unhandleable.
	ReactorPoison *prometheus.CounterVec

	// ReactorParked is the server-side parked count per group: events that
	// exhausted every retry and are waiting for a human. This is the other
	// metric to alert on — parked mail is mail nobody received.
	ReactorParked *prometheus.GaugeVec

	// ReactorSeconds measures how long an effect takes, which for mail is
	// dominated by the SMTP conversation.
	ReactorSeconds *prometheus.HistogramVec

	// ---- mail ------------------------------------------------------------

	// MailSent counts messages accepted by the transport, by template and class.
	MailSent *prometheus.CounterVec

	// MailFailed counts sends the transport rejected.
	MailFailed *prometheus.CounterVec

	// MailSkipped counts sends deliberately not made — most importantly a
	// subject whose personal data has been erased, which is a correct outcome
	// and must not read as a failure (NOTIFICATIONS §4).
	MailSkipped *prometheus.CounterVec

	// MailRenderSeconds measures template rendering, separate from delivery, so
	// a slow template is distinguishable from a slow mail server.
	MailRenderSeconds *prometheus.HistogramVec

	// ---- notifications ---------------------------------------------------

	// NotifyDelivered counts notifications delivered, by channel.
	NotifyDelivered *prometheus.CounterVec

	// NotifySuppressed counts notifications deliberately NOT delivered, with
	// the reason. Suppression is the system working — a preference switched
	// off, an in-app read, an erased subject — so this must never be alerted on
	// as if it were a failure.
	NotifySuppressed *prometheus.CounterVec

	// NotifyFailed counts delivery failures. Alert on this one.
	NotifyFailed *prometheus.CounterVec

	// ---- caches ----------------------------------------------------------

	// CacheHits and CacheMisses give the hit rate per cache. A cache whose hit
	// rate is near zero costs a round trip and saves nothing.
	CacheHits   *prometheus.CounterVec
	CacheMisses *prometheus.CounterVec

	// CacheErrors counts cache faults by operation. Deliberately not alertable
	// on its own: every one of them was survived by falling through to the
	// source. A sustained rate means the cache is effectively absent.
	CacheErrors *prometheus.CounterVec

	// CacheInvalidations counts entries dropped ahead of their TTL. For the PII
	// key cache this is the erasure-propagation signal: erasures happening with
	// no invalidations recorded means destroyed keys are still cached somewhere.
	CacheInvalidations *prometheus.CounterVec

	// ---- authorization ---------------------------------------------------

	// AuthzAllowed counts permits, labelled by where the answer came from — the
	// decision cache or the authorization service.
	AuthzAllowed *prometheus.CounterVec

	// AuthzDenied counts refusals with their reason. Refusing is the system
	// working; this must never be alerted on as if it were a fault.
	AuthzDenied *prometheus.CounterVec

	// AuthzFailed counts checks that could not be evaluated. Every one of them
	// DENIED, so this is the metric that separates "refused" from "broken" — and
	// the one to alert on, because a rising rate is users losing access to
	// resources they own.
	AuthzFailed *prometheus.CounterVec

	// ---- dependency health ------------------------------------------------

	// DependencyHealth is OUR probe's answer about a dependency, which is not
	// what `up{job="postgres"}` reports. That one says whether Prometheus can
	// reach an exporter; this one says whether the thing works FOR US. They
	// disagree exactly when it matters: a PostgreSQL that accepts connections
	// and rejects our credentials is up=1 and health down, and a sealed OpenBao
	// is up=1 and health down. Both panels are worth keeping — they answer
	// different questions.
	//
	// It is a state set: one series per (dependency, state), exactly one of
	// which is 1. That costs three series per probe and buys alert rules that
	// read as English, with no magic numeric encoding to remember at 3am.
	//
	//	chronos_dependency_health{state="down", criticality="critical"} == 1
	//	chronos_dependency_health{dependency="email_reservation_sweep", state="up"} == 0
	//	sum by (state) (chronos_dependency_health)
	DependencyHealth *prometheus.GaugeVec

	// DependencyCheckSeconds is how long a probe took. A dependency that is up
	// but answering in seconds is the state that precedes an outage, and it is
	// invisible in a boolean.
	//
	//	histogram_quantile(0.99, sum by (le, dependency) (rate(chronos_dependency_check_seconds_bucket[5m])))
	DependencyCheckSeconds *prometheus.HistogramVec

	// DependencyChecks counts evaluations by outcome. The gauge alone cannot
	// tell a dependency that has been down for an hour from one that flaps
	// between scrapes, and it cannot tell a healthy dependency from one nobody
	// is checking at all — a registry is only evaluated when something calls
	// the readiness or status endpoint.
	//
	//	rate(chronos_dependency_checks_total{state="down"}[5m]) > 0
	//	sum(rate(chronos_dependency_checks_total[5m])) == 0   # nothing is polling us
	DependencyChecks *prometheus.CounterVec

	// RPCInternal counts requests answered with a code that told the caller
	// nothing — INTERNAL, or the UNKNOWN that connect assigns an error which
	// reached the transport through no mapping at all.
	//
	// It is the alertable half of the same event `ErrorLog` logs. Every one of
	// these is a request a user could do nothing about and a cause only the
	// server saw: a classified refusal (NOT_FOUND, QUOTA_EXCEEDED,
	// VALIDATION_FAILED) is the system working and is deliberately NOT counted
	// here, so any value at all is a fault.
	//
	// Labelled by PROCEDURE and CODE and by nothing else. Both are closed sets —
	// the procedures are the ones registered at boot, the codes are a Connect
	// enum — and the obvious third label, the error text, is exactly what must
	// never be one: it is attacker-influenceable and unbounded, and it would take
	// the metrics backend down with the same traffic this counter exists to
	// reveal.
	//
	//	sum(rate(chronos_rpc_internal_total[5m])) > 0        # page: users are seeing 500s
	//	topk(5, sum by (procedure) (rate(chronos_rpc_internal_total[5m])))
	//	sum by (procedure) (rate(chronos_rpc_internal_total{code="unknown"}[5m])) > 0
	//	  # an error reached the wire through no mapping: a defect, not an incident
	RPCInternal *prometheus.CounterVec

	// AuthThrottled counts authentication attempts refused by the attempt
	// ceiling, by the rule that tripped.
	//
	// These attempts appear NOWHERE else. Every other outcome on the login path
	// is an event, projected into login_history_view, which is what the
	// credential-stuffing signal counts — but an attempt refused above the
	// ceiling appends nothing, deliberately, because refusals are unbounded and
	// one event each would let an unauthenticated caller drive unbounded writes
	// into the log. So the attempts that most indicate an attack in progress are
	// precisely the ones the log cannot show, and this is the only place they
	// are visible.
	//
	//	sum(rate(chronos_auth_throttled_total[5m])) by (rule)
	//	sum(rate(chronos_auth_throttled_total[5m])) > 50   # a campaign, not a forgotten password
	AuthThrottled *prometheus.CounterVec

	// AuthCeilingUnavailable counts attempts allowed because the ceiling could
	// not be evaluated.
	//
	// The limiter fails OPEN (ratelimit.Limiter.Allow), so this counts requests
	// that proceeded UNTHROTTLED. That trade is defensible only while somebody
	// can see it has been taken; until this existed the only trace was a log
	// line, which nothing alerts on.
	//
	//	rate(chronos_auth_ceiling_unavailable_total[5m]) > 0   # page: guessing is unthrottled
	AuthCeilingUnavailable prometheus.Counter
}

// New builds the metric set and its own registry.
//
// The registry is private rather than prometheus.DefaultRegisterer so that
// tests, and two binaries in one process, cannot collide on duplicate
// registration — which panics.
func New() *Metrics {
	reg := prometheus.NewRegistry()

	// Go runtime and process metrics come along: GC pause and heap size are the
	// first things to check when a projector slows down, and collecting them
	// separately would mean a second scrape target.
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
	)

	m := &Metrics{
		registry: reg,

		ProjectionEvents: counter(reg, "chronos_projection_events_total",
			"Events applied by a projection.", "projection"),
		ProjectionSkipped: counter(reg, "chronos_projection_skipped_total",
			"Events offered to a projection that it does not handle.", "projection"),
		ProjectionErrors: counter(reg, "chronos_projection_errors_total",
			"Failed applies. Above zero means the projection has stopped.", "projection"),
		ProjectionLive: gauge(reg, "chronos_projection_live",
			"1 when a projection has caught up to the head of the log, 0 otherwise.", "projection"),
		ProjectionPosition: gauge(reg, "chronos_projection_commit_position",
			"The $all commit position a projection has reached.", "projection"),
		ProjectionBatchSeconds: histogram(reg, "chronos_projection_batch_seconds",
			"Time to write one event's rows and checkpoint in a single round trip.",
			// Buckets around the measured 215us, out to a second: the
			// interesting range is sub-millisecond, and defaults start at 5ms
			// and would put every observation in the first bucket.
			[]float64{.0001, .00025, .0005, .001, .0025, .005, .01, .05, .25, 1},
			"projection"),
		ProjectionHolder: gauge(reg, "chronos_projection_lease_held",
			"1 on the instance holding a projection's single-writer lease.", "projection", "holder"),
		ProjectionAnnouncementsDropped: counter(reg, "chronos_projection_announcements_dropped_total",
			"Realtime messages discarded because the publisher was behind.", "projection"),

		ReactorHandled: counter(reg, "chronos_reactor_handled_total",
			"Effects performed by a reactor.", "reactor"),
		ReactorDuplicates: counter(reg, "chronos_reactor_duplicates_total",
			"Redeliveries suppressed by the dedup table.", "reactor"),
		ReactorFailures: counter(reg, "chronos_reactor_failures_total",
			"Effects that failed and will be retried.", "reactor"),
		ReactorPoison: counter(reg, "chronos_reactor_poison_total",
			"Events parked immediately as unhandleable.", "reactor"),
		ReactorParked: gauge(reg, "chronos_reactor_parked",
			"Events that exhausted every retry and are waiting for a human.", "reactor"),
		ReactorSeconds: histogram(reg, "chronos_reactor_seconds",
			"Time to perform one effect.",
			[]float64{.001, .005, .01, .05, .1, .5, 1, 5, 15, 60},
			"reactor"),

		MailSent: counter(reg, "chronos_mail_sent_total",
			"Messages accepted by the mail transport.", "template", "class"),
		MailFailed: counter(reg, "chronos_mail_failed_total",
			"Messages the mail transport rejected.", "template", "class"),
		MailSkipped: counter(reg, "chronos_mail_skipped_total",
			"Messages deliberately not sent, by reason.", "template", "reason"),
		MailRenderSeconds: histogram(reg, "chronos_mail_render_seconds",
			"Template rendering time, excluding delivery.",
			[]float64{.0001, .0005, .001, .005, .01, .05, .25},
			"template"),

		NotifyDelivered: counter(reg, "chronos_notify_delivered_total",
			"Notifications delivered, by channel.", "template", "class", "channel"),
		NotifySuppressed: counter(reg, "chronos_notify_suppressed_total",
			"Notifications deliberately not delivered, by reason. NOT a failure.",
			"template", "class", "channel", "reason"),
		NotifyFailed: counter(reg, "chronos_notify_failed_total",
			"Notification delivery failures.", "template", "class", "channel"),

		CacheHits: counter(reg, "chronos_cache_hits_total",
			"Cache hits, by cache name.", "cache"),
		CacheMisses: counter(reg, "chronos_cache_misses_total",
			"Cache misses, by cache name.", "cache"),
		CacheErrors: counter(reg, "chronos_cache_errors_total",
			"Cache faults, by cache name and operation. Survived by falling through to the source.",
			"cache", "op"),
		CacheInvalidations: counter(reg, "chronos_cache_invalidations_total",
			"Entries dropped ahead of their TTL, by cache name.", "cache"),

		AuthzAllowed: counter(reg, "chronos_authz_allowed_total",
			"Permitted checks, by relation, resource type and answer source.",
			"relation", "resource_type", "source"),
		AuthzDenied: counter(reg, "chronos_authz_denied_total",
			"Refused checks with their reason. NOT a failure.",
			"relation", "resource_type", "reason"),
		AuthzFailed: counter(reg, "chronos_authz_failed_total",
			"Checks that could not be evaluated. All of them denied. ALERT ON THIS.",
			"relation", "resource_type"),

		DependencyHealth: gauge(reg, "chronos_dependency_health",
			"Our own probe's answer per dependency: 1 on the current state, 0 on the others. "+
				"Not the same question as up{job=...}, which is scrape reachability.",
			"dependency", "criticality", "state"),
		DependencyCheckSeconds: histogram(reg, "chronos_dependency_check_seconds",
			"Time one dependency probe took to answer.",
			// The registry's per-probe timeout is 2s, so the top bucket is
			// where "timed out" lands and the resolution belongs below it:
			// most probes are a single round trip on a local network.
			[]float64{.001, .0025, .005, .01, .025, .05, .1, .25, .5, 1, 2},
			"dependency"),
		DependencyChecks: counter(reg, "chronos_dependency_checks_total",
			"Dependency probe evaluations, by outcome.", "dependency", "state"),

		RPCInternal: counter(reg, "chronos_rpc_internal_total",
			"Requests answered with a code that disclosed nothing to the caller. "+
				"Classified refusals are NOT counted. ALERT ON THIS.",
			"procedure", "code"),

		// Labelled by RULE only. The identifier being attempted is unbounded and
		// chosen by the caller, so it is not a label — putting it in one is how a
		// metrics backend is taken down by the same traffic this counter exists
		// to reveal.
		AuthThrottled: counter(reg, "chronos_auth_throttled_total",
			"Authentication attempts refused by the attempt ceiling, by rule.", "rule"),
		AuthCeilingUnavailable: counterOne(reg, "chronos_auth_ceiling_unavailable_total",
			"Authentication attempts allowed because the attempt ceiling could not be evaluated."),
	}
	return m
}

// Registry exposes the collector set for an HTTP handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// InitProjection publishes a projection's series at zero, before it has done
// anything.
//
// A Prometheus *Vec exports NOTHING for a label value it has never seen, so a
// projection that has applied no events is ABSENT rather than zero — and absent
// and broken look identical on a dashboard and in an alert rule. `rate(...) == 0`
// never fires for a series that does not exist, which is precisely the case
// worth alerting on: a projector that started and then applied nothing.
//
// Called from the composition root, where the set of projections is known, so
// every panel renders a number from the first scrape.
func (m *Metrics) InitProjection(name string) {
	m.ProjectionEvents.WithLabelValues(name)
	m.ProjectionSkipped.WithLabelValues(name)
	m.ProjectionErrors.WithLabelValues(name)
	m.ProjectionAnnouncementsDropped.WithLabelValues(name)
	m.ProjectionBatchSeconds.WithLabelValues(name)
	// Gauges are published explicitly rather than left at their zero value: a
	// projection that has not yet reported live IS behind, and saying so is the
	// honest answer while it catches up.
	m.ProjectionLive.WithLabelValues(name).Set(0)
	m.ProjectionPosition.WithLabelValues(name).Set(0)
}

// InitReactor does the same for a reactor.
//
// The parked gauge matters most here: a reactor with a parked backlog and no
// series is indistinguishable from a healthy one, and parked mail is mail
// nobody received.
func (m *Metrics) InitReactor(name string) {
	m.ReactorHandled.WithLabelValues(name)
	m.ReactorDuplicates.WithLabelValues(name)
	m.ReactorFailures.WithLabelValues(name)
	m.ReactorPoison.WithLabelValues(name)
	m.ReactorSeconds.WithLabelValues(name)
	m.ReactorParked.WithLabelValues(name).Set(0)
}

func counter(reg prometheus.Registerer, name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
	reg.MustRegister(c)
	return c
}

// counterOne is a counter with no labels.
//
// Separate from counter because a CounterVec with zero labels exports NOTHING
// until somebody calls WithLabelValues, so a metric that has legitimately never
// fired is absent rather than zero — and absent means `rate(...) > 0` cannot
// alert and a dashboard renders a gap. A plain Counter is registered at zero and
// is therefore visibly "not happening" rather than missing.
func counterOne(reg prometheus.Registerer, name, help string) prometheus.Counter {
	c := prometheus.NewCounter(prometheus.CounterOpts{Name: name, Help: help})
	reg.MustRegister(c)
	return c
}

func gauge(reg prometheus.Registerer, name, help string, labels ...string) *prometheus.GaugeVec {
	g := prometheus.NewGaugeVec(prometheus.GaugeOpts{Name: name, Help: help}, labels)
	reg.MustRegister(g)
	return g
}

func histogram(
	reg prometheus.Registerer, name, help string, buckets []float64, labels ...string,
) *prometheus.HistogramVec {
	h := prometheus.NewHistogramVec(
		prometheus.HistogramOpts{Name: name, Help: help, Buckets: buckets}, labels)
	reg.MustRegister(h)
	return h
}
