package openfga

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
	"google.golang.org/grpc"
	"google.golang.org/grpc/health/grpc_health_v1"
)

// Probe reports OpenFGA reachability over gRPC (ADR-037), using the standard
// grpc.health.v1 service rather than a bespoke HTTP check.
//
// FAIL_CLOSED: if authorization is unreachable every check denies. Readiness
// deliberately still passes — see health.Registry.Check.
type Probe struct{ Conn *grpc.ClientConn }

func (Probe) Name() string                    { return "openfga" }
func (Probe) Criticality() health.Criticality { return health.FailClosed }
func (Probe) Impact() string {
	return "Authorization is unavailable, so every permission check is denied."
}

func (p Probe) Check(ctx context.Context) error {
	if p.Conn == nil {
		return fmt.Errorf("connection not initialised")
	}
	resp, err := grpc_health_v1.NewHealthClient(p.Conn).Check(ctx, &grpc_health_v1.HealthCheckRequest{})
	if err != nil {
		return err
	}
	if resp.GetStatus() != grpc_health_v1.HealthCheckResponse_SERVING {
		return fmt.Errorf("not serving: %s", resp.GetStatus())
	}
	return nil
}
