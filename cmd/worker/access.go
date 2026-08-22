package main

import (
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	accessprojection "github.com/chronos/chronos-go/internal/modules/access/projection"
	"github.com/chronos/chronos-go/internal/modules/organization"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

// newAccessTuples builds the projector that writes the authorization graph.
//
// # Why it runs here and not in cmd/projector
//
// Every other projection writes rows and its own checkpoint in ONE transaction,
// which is what makes it exactly-once. This one writes to OpenFGA, and no
// transaction spans a database and an external service — so it is at-least-once
// and belongs with the other at-least-once work. Its writes are idempotent for
// that reason: `on_duplicate: ignore` on the way in, and a delete of an absent
// tuple is not an error.
//
// # What its absence costs
//
// Nothing is granted. Gate 2 asks OpenFGA and OpenFGA answers from an empty
// graph, so every non-self-scoped method is DENIED — which is the correct
// direction to fail (ADR-010) and completely silent: no error, no parked event,
// just a tenant that cannot touch its own data.
func newAccessTuples(codec *eventcodec.JSON, d *dependencies) (reactor.Reactor, error) {
	if d.cfg.OpenFGA.StoreID == "" {
		return nil, errors.New("OPENFGA_STORE_ID is not set, so there is no graph to write " +
			"into; run `make authz-deploy`")
	}

	conn, err := fgaadapter.Dial(d.cfg.OpenFGA.Endpoint, d.cfg.OpenFGA.PresharedKey.Expose())
	if err != nil {
		return nil, fmt.Errorf("openfga: %w", err)
	}
	d.closes = append(d.closes, func() { _ = conn.Close() })

	writer, err := fgaadapter.NewWriter(conn, fgaadapter.Config{
		StoreID: d.cfg.OpenFGA.StoreID,
		ModelID: d.cfg.OpenFGA.ModelID,
	})
	if err != nil {
		return nil, fmt.Errorf("tuple writer: %w", err)
	}

	// Its OWN codec, registering only the modules whose events grant something.
	// The shared worker codec would do, and this keeps the registration next to
	// the filter it has to agree with: a module in one and not the other is a
	// reactor that silently ignores half its own subscription.
	upcasters := eventsourcing.NewUpcasterRegistry()
	organization.RegisterSchemas(upcasters)
	workspace.RegisterSchemas(upcasters)

	tupleCodec := eventcodec.NewJSON(upcasters)
	organization.RegisterEvents(tupleCodec)
	workspace.RegisterEvents(tupleCodec)

	return accessprojection.NewTuples(writer, tupleCodec)
}
