package obs

// ProjectionObserver and ReactorObserver satisfy the Metrics interfaces the
// kernel declares, WITHOUT either package importing the other. Go's structural
// typing is what makes that possible, and it is why the kernel carries no
// dependency on Prometheus.

// Projections returns the observer a projection.Runner accepts.
func (m *Metrics) Projections() ProjectionObserver { return ProjectionObserver{m} }

type ProjectionObserver struct{ m *Metrics }

func (o ProjectionObserver) Applied(name string, seconds float64) {
	o.m.ProjectionEvents.WithLabelValues(name).Inc()
	o.m.ProjectionBatchSeconds.WithLabelValues(name).Observe(seconds)
}

func (o ProjectionObserver) Skipped(name string) {
	o.m.ProjectionSkipped.WithLabelValues(name).Inc()
}

func (o ProjectionObserver) Failed(name string) {
	o.m.ProjectionErrors.WithLabelValues(name).Inc()
}

func (o ProjectionObserver) Live(name string, live bool) {
	v := 0.0
	if live {
		v = 1
	}
	o.m.ProjectionLive.WithLabelValues(name).Set(v)
}

func (o ProjectionObserver) Position(name string, commit uint64) {
	// float64 loses precision above 2^53, which a commit position will not
	// reach: that is 9 petabytes of log.
	o.m.ProjectionPosition.WithLabelValues(name).Set(float64(commit))
}

// Reactors returns the observer a reactor.Runner accepts.
func (m *Metrics) Reactors() ReactorObserver { return ReactorObserver{m} }

type ReactorObserver struct{ m *Metrics }

func (o ReactorObserver) Handled(name string, seconds float64) {
	o.m.ReactorHandled.WithLabelValues(name).Inc()
	o.m.ReactorSeconds.WithLabelValues(name).Observe(seconds)
}

func (o ReactorObserver) Duplicate(name string) { o.m.ReactorDuplicates.WithLabelValues(name).Inc() }
func (o ReactorObserver) Failed(name string)    { o.m.ReactorFailures.WithLabelValues(name).Inc() }
func (o ReactorObserver) Poison(name string)    { o.m.ReactorPoison.WithLabelValues(name).Inc() }

// SetParked records a group's server-side parked count. Polled rather than
// pushed: the number lives in KurrentDB, not in this process, and a reactor
// that has stopped entirely still needs its backlog reported.
func (m *Metrics) SetParked(reactor string, parked int64) {
	m.ReactorParked.WithLabelValues(reactor).Set(float64(parked))
}

// SetLeaseHeld records which instance holds a projection's single-writer lease.
func (m *Metrics) SetLeaseHeld(projection, holder string, held bool) {
	v := 0.0
	if held {
		v = 1
	}
	m.ProjectionHolder.WithLabelValues(projection, holder).Set(v)
}

// Mail returns the observer the email transport accepts.
func (m *Metrics) Mail() MailObserver { return MailObserver{m} }

type MailObserver struct{ m *Metrics }

func (o MailObserver) Sent(template, class string) {
	o.m.MailSent.WithLabelValues(template, class).Inc()
}

func (o MailObserver) Failed(template, class string) {
	o.m.MailFailed.WithLabelValues(template, class).Inc()
}

// Skipped is NOT a failure. The commonest reason is an erased subject, which is
// a correct outcome and must never page anyone (NOTIFICATIONS §4).
func (o MailObserver) Skipped(template, reason string) {
	o.m.MailSkipped.WithLabelValues(template, reason).Inc()
}

func (o MailObserver) Rendered(template string, seconds float64) {
	o.m.MailRenderSeconds.WithLabelValues(template).Observe(seconds)
}

// Notifications returns the observer notify.Dispatcher accepts.
//
// It counts CHANNEL outcomes — what policy decided and whether delivery
// succeeded. MailObserver counts what the email transport itself did; the two
// answer different questions and a discrepancy between them is informative.
func (m *Metrics) Notifications() NotifyObserver { return NotifyObserver{m} }

type NotifyObserver struct{ m *Metrics }

func (o NotifyObserver) Delivered(template, class, channel string) {
	o.m.NotifyDelivered.WithLabelValues(template, class, channel).Inc()
}

// Suppressed is not a failure: a preference was off, the recipient had already
// read it in-app, or the subject was erased. All three are the system working.
func (o NotifyObserver) Suppressed(template, class, channel, reason string) {
	o.m.NotifySuppressed.WithLabelValues(template, class, channel, reason).Inc()
}

func (o NotifyObserver) Failed(template, class, channel string) {
	o.m.NotifyFailed.WithLabelValues(template, class, channel).Inc()
}

// Caches returns the cache observer.
//
// Labelled by cache NAME rather than by subsystem, because the interesting
// comparison is between caches: one with a hit rate near zero is pure overhead,
// and one whose invalidation count is near zero is not being invalidated at all
// — which for the PII key cache would mean erasure is not propagating.
func (m *Metrics) Caches() CacheObserver { return CacheObserver{m} }

type CacheObserver struct{ m *Metrics }

func (o CacheObserver) Hit(name string)  { o.m.CacheHits.WithLabelValues(name).Inc() }
func (o CacheObserver) Miss(name string) { o.m.CacheMisses.WithLabelValues(name).Inc() }

// Error counts cache faults. Never fatal: by the time this is called the caller
// has already fallen through to the source of truth.
func (o CacheObserver) Error(name, op string) {
	o.m.CacheErrors.WithLabelValues(name, op).Inc()
}

func (o CacheObserver) Invalidated(name string, count int) {
	o.m.CacheInvalidations.WithLabelValues(name).Add(float64(count))
}

// Authz returns the authorization observer.
//
// Failed is the one to alert on. Every failed check DENIED, so a rising rate is
// users losing access to things they own — an outage that looks, in every other
// metric, exactly like a quiet period.
func (m *Metrics) Authz() AuthzObserver { return AuthzObserver{m} }

type AuthzObserver struct{ m *Metrics }

func (o AuthzObserver) Allowed(relation, resourceType, source string) {
	o.m.AuthzAllowed.WithLabelValues(relation, resourceType, source).Inc()
}

// Denied counts refusals. NOT a failure: refusing is the system working.
func (o AuthzObserver) Denied(relation, resourceType, reason string) {
	o.m.AuthzDenied.WithLabelValues(relation, resourceType, reason).Inc()
}

func (o AuthzObserver) Failed(relation, resourceType string) {
	o.m.AuthzFailed.WithLabelValues(relation, resourceType).Inc()
}
