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
	}
	return m
}

// Registry exposes the collector set for an HTTP handler.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

func counter(reg prometheus.Registerer, name, help string, labels ...string) *prometheus.CounterVec {
	c := prometheus.NewCounterVec(prometheus.CounterOpts{Name: name, Help: help}, labels)
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
