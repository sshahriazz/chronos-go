package obs

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Handler serves the metrics this process publishes.
//
// Every binary exposes it on its own health port rather than a shared one, so a
// scrape failure names the process that is unreachable.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{
		// A broken collector must not take the whole scrape down: report what
		// worked and surface the failure as a metric of its own.
		ErrorHandling: promhttp.ContinueOnError,
	})
}
