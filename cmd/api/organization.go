package main

import (
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	orgapi "github.com/chronos/chronos-go/internal/modules/organization/api"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
)

// buildSubscriptions assembles gate 3: payment enforcement.
//
// It reads org_status_view on every request, which is why organization.md §10
// calls that the most performance-critical projection in the system.
func (d *dependencies) buildSubscriptions(log *slog.Logger) (*orgapi.SubscriptionGate, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: gate 3 reads the organization's status " +
			"from org_status_view")
	}
	reader, err := orgpg.NewStatusReader(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("status reader: %w", err)
	}
	gate, err := orgapp.NewSubscriptionGate(reader)
	if err != nil {
		return nil, fmt.Errorf("subscription gate: %w", err)
	}
	log.Info("subscription gate constructed", "reads", "org_status_view")
	return orgapi.NewSubscriptionGate(gate)
}

// buildOrgContext assembles gate 1: which organization is this request in.
//
// # What its absence costs
//
// Every method that is not self-scoped is refused, because the pipeline treats
// an unwired gate as an error rather than a skip. That is the right direction —
// deleting an implementation must not silently open every endpoint that relied
// on it — and it means the symptom is a refusal rather than a request acting in
// no tenant at all.
func (d *dependencies) buildOrgContext(log *slog.Logger) (*orgapi.OrgResolver, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: gate 1 verifies membership against " +
			"org_member_index rather than trusting the header a request sent")
	}
	members, err := orgpg.NewMembership(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("membership: %w", err)
	}
	log.Info("org-context gate constructed", "header", orgapi.OrgHeader)
	return orgapi.NewOrgResolver(members)
}

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
