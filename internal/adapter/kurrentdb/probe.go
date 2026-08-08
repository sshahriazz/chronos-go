package kurrentdb

import (
	"context"
	"errors"
	"fmt"
	"io"

	"github.com/chronos/chronos-go/internal/server/health"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
)

// Probe reports KurrentDB reachability using the official client over gRPC
// (ADR-037) — the same transport the write path uses, so the probe fails for
// the same reasons a real append would.
//
// CRITICAL for writes: no appends means no writes at all. Reads continue to be
// served from projections, so the impact is asymmetric.
type Probe struct{ Client *kurrentdb.Client }

func (Probe) Name() string                    { return "kurrentdb" }
func (Probe) Criticality() health.Criticality { return health.Critical }
func (Probe) Impact() string {
	return "Writes are rejected. Reads continue to be served from projections."
}

// Check performs a real read of the tail of $all.
//
// This is deliberately an actual operation rather than a ping: it exercises the
// gRPC connection, credentials and the read path together. A connection that
// dials but cannot read is a state a ping would call healthy.
func (p Probe) Check(ctx context.Context) error {
	if p.Client == nil {
		return fmt.Errorf("client not initialised")
	}
	stream, err := p.Client.ReadAll(ctx, kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Backwards,
		From:      kurrentdb.End{},
	}, 1)
	if err != nil {
		return err
	}
	defer stream.Close()

	// An empty store is healthy — EOF here means "reachable, nothing written".
	if _, err := stream.Recv(); err != nil && !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}
