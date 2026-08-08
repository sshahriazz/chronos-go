package health

import (
	"context"
	"time"

	"connectrpc.com/connect"
	systemv1 "github.com/chronos/chronos-go/gen/proto/chronos/system/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Service implements chronos.system.v1.SystemService over the registry.
//
// It is deliberately the only handler that answers while the system is
// degraded — including when authentication itself is unavailable — so it must
// depend on nothing but the registry.
type Service struct {
	registry  *Registry
	version   string
	startedAt time.Time
	timezone  string
}

func NewService(r *Registry, version, timezone string, startedAt time.Time) *Service {
	return &Service{registry: r, version: version, startedAt: startedAt, timezone: timezone}
}

func (s *Service) GetStatus(
	ctx context.Context,
	_ *connect.Request[systemv1.GetStatusRequest],
) (*connect.Response[systemv1.GetStatusResponse], error) {
	rep := s.registry.Check(ctx)

	deps := make([]*systemv1.Dependency, 0, len(rep.Dependencies))
	for _, d := range rep.Dependencies {
		deps = append(deps, &systemv1.Dependency{
			Name:          d.Name,
			Health:        toProtoHealth(d.Health),
			Criticality:   toProtoCriticality(d.Criticality),
			Detail:        d.Detail,
			Impact:        d.Impact,
			LastCheckedAt: timestamppb.New(d.CheckedAt),
			LatencyMs:     d.Latency.Milliseconds(),
		})
	}

	return connect.NewResponse(&systemv1.GetStatusResponse{
		Ready:            rep.Ready,
		FullyOperational: rep.FullyOperational,
		Dependencies:     deps,
		Version:          s.version,
		StartedAt:        timestamppb.New(s.startedAt),
		Timezone:         s.timezone,
	}), nil
}

func toProtoHealth(h Health) systemv1.Health {
	switch h {
	case Up:
		return systemv1.Health_HEALTH_UP
	case Degraded:
		return systemv1.Health_HEALTH_DEGRADED
	case Down:
		return systemv1.Health_HEALTH_DOWN
	default:
		return systemv1.Health_HEALTH_UNSPECIFIED
	}
}

func toProtoCriticality(c Criticality) systemv1.Criticality {
	switch c {
	case Critical:
		return systemv1.Criticality_CRITICALITY_CRITICAL
	case Degradable:
		return systemv1.Criticality_CRITICALITY_DEGRADABLE
	case FailClosed:
		return systemv1.Criticality_CRITICALITY_FAIL_CLOSED
	default:
		return systemv1.Criticality_CRITICALITY_UNSPECIFIED
	}
}
