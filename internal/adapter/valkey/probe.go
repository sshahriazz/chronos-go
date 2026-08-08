// Package valkey adapts Valkey for ephemeral state: sessions, rate limits,
// caches and the Centrifugo backplane.
package valkey

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/valkey-io/valkey-go"
)

// Probe reports Valkey reachability.
//
// DEGRADABLE: everything here is rebuildable by definition — `FLUSHALL` must be
// survivable. Losing it costs cache hits and rate limiting, not correctness.
type Probe struct{ Client valkey.Client }

func (Probe) Name() string                    { return "valkey" }
func (Probe) Criticality() health.Criticality { return health.Degradable }
func (Probe) Impact() string {
	return "Caches and rate limiting are unavailable; requests fall back to the source of truth and run slower."
}

func (p Probe) Check(ctx context.Context) error {
	if p.Client == nil {
		return fmt.Errorf("client not initialised")
	}
	return p.Client.Do(ctx, p.Client.B().Ping().Build()).Error()
}
