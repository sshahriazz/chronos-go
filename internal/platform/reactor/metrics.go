package reactor

// Metrics observes a reactor. See projection.Metrics for why this is an
// interface declared in the kernel rather than a metrics library import.
type Metrics interface {
	// Handled records one effect performed, with how long it took.
	Handled(reactor string, seconds float64)

	// Duplicate records a redelivery suppressed by the dedup table.
	Duplicate(reactor string)

	// Failed records an effect that failed and will be retried.
	Failed(reactor string)

	// Poison records an event parked immediately as unhandleable.
	Poison(reactor string)
}

type noMetrics struct{}

func (noMetrics) Handled(string, float64) {}
func (noMetrics) Duplicate(string)        {}
func (noMetrics) Failed(string)           {}
func (noMetrics) Poison(string)           {}
