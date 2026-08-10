package centrifugo

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
)

// Probe reports Centrifugo reachability over the same gRPC API the publish path
// uses, so it fails for the same reasons a real publish would.
//
// Degradable, not Critical. When realtime is down, browsers stop receiving live
// updates — but every notification is still written to its projection, still
// sent by email, and still visible on the next page load. Taking the API out of
// rotation because a toast did not appear would turn a cosmetic degradation into
// an outage (ADR-010).
type Probe struct{ Publisher *Publisher }

func (Probe) Name() string                    { return "centrifugo" }
func (Probe) Criticality() health.Criticality { return health.Degradable }
func (Probe) Impact() string {
	return "Live updates stop. Notifications are still stored, emailed, and visible on reload."
}

// Check calls the server API, which exercises the connection AND the API key
// together. A connection that dials but is unauthenticated is a state a ping
// reports as healthy, and is exactly what a rotated key produces.
func (p Probe) Check(ctx context.Context) error {
	if p.Publisher == nil {
		return fmt.Errorf("publisher not initialised")
	}
	return p.Publisher.Info(ctx)
}
