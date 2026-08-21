package main

import (
	"errors"
	"fmt"
	"log/slog"

	orgapi "github.com/chronos/chronos-go/internal/modules/organization/api"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
)

// buildOrganization assembles the organization service, or explains why it
// could not be.
//
// Failure is loud and NOT fatal (ADR-010). An organization service that cannot
// be built means nobody can create a tenant; every other RPC in the process is
// unaffected, and saying so precisely beats refusing to start.
func (d *dependencies) buildOrganization(log *slog.Logger) (*orgapi.Service, error) {
	if d.store == nil {
		return nil, errors.New("no event store: creating an organization is an atomic append " +
			"across three streams, and there is nowhere to append")
	}
	if d.upcasters == nil {
		return nil, errors.New("no schema registry: an event stored without its version " +
			"cannot be upcast later (ADR-029)")
	}

	creation, err := orgapp.NewCreation(orgapp.CreationDeps{
		// The MultiAppender, not a repository. Creation writes three streams in
		// one atomic append — the organization, the owner reservation and the
		// slug reservation — and a repository per aggregate could not make them
		// succeed or fail together.
		Appender: d.store,
		Schemas:  d.upcasters,
		Now:      d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("organization creation: %w", err)
	}

	log.Info("organization service constructed",
		// Named at startup because it is the property most likely to surprise an
		// operator reading the lifecycle: nothing here waits for a payment.
		"trial", "cardless", "first_status", "provisioning")

	return orgapi.New(orgapi.Deps{Creation: creation})
}
