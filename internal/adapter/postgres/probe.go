package postgres

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/jackc/pgx/v5/pgxpool"
)

// Probe reports PostgreSQL reachability.
//
// CRITICAL: the read model lives here, so an outage means we cannot serve.
type Probe struct{ Pool *pgxpool.Pool }

func (Probe) Name() string                    { return "postgres" }
func (Probe) Criticality() health.Criticality { return health.Critical }
func (Probe) Impact() string {
	return "Reads and writes are unavailable; the service is not ready."
}

func (p Probe) Check(ctx context.Context) error {
	if p.Pool == nil {
		return fmt.Errorf("pool not initialised")
	}
	return p.Pool.Ping(ctx)
}
