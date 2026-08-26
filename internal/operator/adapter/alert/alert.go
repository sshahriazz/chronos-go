// Package alert raises the break-glass alert operator.md §5 requires.
//
// # Why a metric, on a plane that deliberately holds no addresses
//
// §5 asks for an alert "to a second person AT THE TIME OF USE — not in a report
// someone reads next quarter". The obvious implementation is mail, and mail
// needs operator addresses. This plane does not hold them, on purpose: an
// operator is a pseudonym here so that the audit trail survives their erasure,
// which is §5's own retention rule.
//
// So the alert is a Prometheus counter and a log line at WARN, routed by the
// same alerting stack that already pages a human for every other operational
// problem. Prometheus scrapes on the order of seconds, so "at the time of use"
// holds — and the routing is somebody's on-call rotation rather than a list of
// addresses this binary has to keep current.
//
// The alerting RULE ships alongside, in infra/prometheus. A counter nobody
// alerts on is a report someone reads next quarter, which is the thing §5 names
// and rejects.
package alert

import (
	"context"
	"log/slog"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/operator/domain"
)

// Elevations is the break-glass alerter.
type Elevations struct {
	granted *prometheus.CounterVec
	log     *slog.Logger
}

var _ app.ElevationAlerter = (*Elevations)(nil)

// NewElevations registers the counter and builds the alerter.
//
// It takes a Registerer rather than reaching for a package-level default, so
// the composition root decides where it lands and a test can hand it its own —
// which is what lets TestTheAlerterIsWired assert the alert FIRED rather than
// that a counter exists somewhere.
func NewElevations(reg prometheus.Registerer, log *slog.Logger) *Elevations {
	if log == nil {
		log = slog.Default()
	}
	c := prometheus.NewCounterVec(prometheus.CounterOpts{
		Name: "chronos_operator_elevations_granted_total",
		Help: "Break-glass elevations granted, by role and capability. " +
			"Any increase is an operator taking a privilege their role does not hold " +
			"(operator.md §5) and should page a second person.",
	}, []string{"role", "capability"})
	reg.MustRegister(c)

	// # Pre-initialise every series, at zero
	//
	// A CounterVec emits NOTHING until a label combination is first observed,
	// and `increase()` needs two samples to compute anything. So without this,
	// the first break-glass in a deployment's life would be invisible to the
	// alert until the second scrape after it — the one case where the alert
	// most needs to be immediate.
	//
	// It is the same reason obs.Metrics has InitProjection and InitReactor, and
	// the same failure `make dashboards-check` exists to catch: a metric that is
	// absent reads as a metric that is zero, and zero reads as healthy.
	//
	// The set is bounded by construction — it is exactly the pairs
	// internal/operator/domain permits, so a role that may reach nothing
	// contributes nothing, and the cardinality is the elevation table's own
	// size rather than an unbounded product.
	for _, role := range domain.Roles() {
		for _, cap := range domain.ElevatableBy(role) {
			c.WithLabelValues(string(role), string(cap))
		}
	}

	return &Elevations{granted: c, log: log}
}

// Alert records the grant.
//
// # It cannot fail, and that is a decision rather than an omission
//
// There is no error return. An alerting outage must not be a reason a
// break-glass is unavailable during an incident — that would make the control
// into a single point of failure at exactly the moment somebody needs to act.
//
// The audit trail is what makes that safe: the elevation is already in the
// event log with its justification before this is called, so an alert that
// never reaches anybody costs the grant its punctuality and not its record.
//
// The LABELS are role and capability, both closed sets. Not the operator id,
// which is unbounded in principle and would put a per-employee time series in
// Prometheus — the cardinality rule, and also a small privacy one: who broke
// the glass belongs in the audit log, which has access controls, rather than in
// a metrics store that usually does not.
func (e *Elevations) Alert(
	ctx context.Context, actor app.Actor, capability, reason string, expiresAt time.Time,
) {
	e.granted.WithLabelValues(string(actor.Role), capability).Inc()

	// WARN, not INFO. This is a human-attention event by definition: somebody
	// took a privilege their role does not hold, and the log line is the half of
	// the alert that carries WHO and WHY — the two things the metric
	// deliberately does not.
	e.log.WarnContext(ctx, "BREAK-GLASS: an operator took a capability their role does not hold",
		"operator_id", actor.OperatorID,
		"role", actor.Role,
		"capability", capability,
		"reason", reason,
		"expires_at", expiresAt,
		"session_id", actor.SessionID,
		"from_ip", actor.FromIP)
}
