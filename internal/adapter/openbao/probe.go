// Package openbao adapts OpenBao for key custody (ADR-028): the KEK that wraps
// per-subject data keys, and every rotatable secret.
package openbao

import (
	"context"
	"fmt"

	"github.com/chronos/chronos-go/internal/server/health"
	openbao "github.com/openbao/openbao/api/v2"
)

// Dial builds a client. It does not contact the server, so a process can start
// while OpenBao is still sealed or coming up (ADR-010).
func Dial(addr, token string) (*openbao.Client, error) {
	cfg := openbao.DefaultConfig()
	cfg.Address = addr
	c, err := openbao.NewClient(cfg)
	if err != nil {
		return nil, fmt.Errorf("openbao: %w", err)
	}
	if token != "" {
		c.SetToken(token)
	}
	return c, nil
}

// Probe reports OpenBao reachability using the official SDK.
//
// DEGRADABLE: without it, per-subject data keys cannot be unwrapped, so PII
// resolution fails — every non-PII path continues (ADR-010, ADR-028).
type Probe struct{ Client *openbao.Client }

func (Probe) Name() string                    { return "openbao" }
func (Probe) Criticality() health.Criticality { return health.Degradable }
func (Probe) Impact() string {
	return "Personal data cannot be decrypted, so names and email addresses render as unavailable. Everything else works."
}

func (p Probe) Check(ctx context.Context) error {
	if p.Client == nil {
		return fmt.Errorf("client not initialised")
	}
	h, err := p.Client.Sys().HealthWithContext(ctx)
	if err != nil {
		return err
	}
	// Sealed is a real outage for us: a sealed vault cannot unwrap anything.
	if h.Sealed {
		return fmt.Errorf("sealed")
	}
	if !h.Initialized {
		return fmt.Errorf("not initialised")
	}
	return nil
}
