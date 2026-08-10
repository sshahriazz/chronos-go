package projection

// Metrics observes a projector.
//
// Declared here, as a narrow interface, so the kernel never imports a metrics
// library: swapping Prometheus for anything else must not touch this package
// (ADR-001). Implemented in platform/obs by structural typing — that package
// does not import this one either.
type Metrics interface {
	// Applied records one event written, with the time its batch took.
	Applied(projection string, seconds float64)

	// Skipped records an event the projection was offered and does not handle.
	Skipped(projection string)

	// Failed records an apply that failed. Above zero means stopped: a
	// projector does not retry (ADR-019).
	Failed(projection string)

	// Live records whether the projection has caught up to the head of the log.
	Live(projection string, live bool)

	// Position records the $all commit position reached.
	Position(projection string, commit uint64)
}

// noMetrics is the default, so every call site can be unconditional rather than
// guarded by a nil check that will eventually be forgotten.
type noMetrics struct{}

func (noMetrics) Applied(string, float64) {}
func (noMetrics) Skipped(string)          {}
func (noMetrics) Failed(string)           {}
func (noMetrics) Live(string, bool)       {}
func (noMetrics) Position(string, uint64) {}
