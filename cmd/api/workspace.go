package main

import (
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	entitlementpg "github.com/chronos/chronos-go/internal/modules/entitlement/adapter/postgres"
	entitlementapi "github.com/chronos/chronos-go/internal/modules/entitlement/api"
	entitlementapp "github.com/chronos/chronos-go/internal/modules/entitlement/app"
	entitlementdomain "github.com/chronos/chronos-go/internal/modules/entitlement/domain"
	workspaceapi "github.com/chronos/chronos-go/internal/modules/workspace/api"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	workspacedomain "github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// buildEntitlements assembles gate 4.
//
// # What its absence costs
//
// Every RPC declaring an entitlement is REFUSED for the lifetime of the process
// — the pipeline treats an unwired gate as an error rather than a skip, which is
// the right direction (deleting an implementation must not silently open every
// endpoint that relied on it). So the visible symptom is `CreateWorkspace`
// failing, not a cap quietly not applying.
func (d *dependencies) buildEntitlements(log *slog.Logger) (interceptor.Entitlements, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: reservations live in the durable store, " +
			"because one Valkey FLUSHALL would let two requests take the last seat")
	}

	catalogue, err := entitlementdomain.NewCatalogue(entitlementdomain.Trial())
	if err != nil {
		return nil, fmt.Errorf("entitlement catalogue: %w", err)
	}
	// One plan exists. When billing's catalogue lands this reads the
	// organization's subscription instead, and no caller changes.
	plans, err := entitlementapp.NewOrgPlans(catalogue, "trial")
	if err != nil {
		return nil, fmt.Errorf("entitlement plans: %w", err)
	}

	adapter := pgadapter.New(d.pool)
	store, err := entitlementpg.NewReservations(adapter, adapter)
	if err != nil {
		return nil, fmt.Errorf("reservation store: %w", err)
	}

	reserver, err := entitlementapp.NewReserver(entitlementapp.ReserverDeps{
		Store: store,
		Plans: plans,
		Now:   d.clock.Now,
		NewID: func() string {
			return ids.New[ids.Event](d.clock.Now(), ids.Entropy()).String()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("reserver: %w", err)
	}
	d.reserver = reserver

	trial, _ := catalogue.Plan("trial")
	log.Info("entitlement gate constructed",
		// Named at startup because these are the numbers a support question
		// starts from, and they are also the anti-abuse bound on a free signup.
		"plans", catalogue.Plans(),
		"trial_workspaces", trial.Limits[entitlementdomain.WorkspacesCount],
		"trial_member_seats", trial.Limits[entitlementdomain.SeatsMember])

	return entitlementapi.NewGate(reserver, log)
}

// buildWorkspace assembles the workspace service.
func (d *dependencies) buildWorkspace(log *slog.Logger) (*workspaceapi.Service, error) {
	if d.store == nil {
		return nil, errors.New("no event store: creating a workspace is an append")
	}
	if d.reserver == nil {
		return nil, errors.New("no reserver: a workspace consumes quota, and without a way " +
			"to COMMIT the reservation gate 4 granted, every creation would hand the unit " +
			"back and the cap would never bind")
	}

	repo := eventsourcing.NewRepository[*workspacedomain.Workspace](
		d.store, d.codec, d.upcasters, workspacedomain.Category, workspacedomain.NewWorkspace)

	creation, err := workspaceapp.NewCreation(workspaceapp.CreationDeps{
		Repo:  repo,
		Quota: d.reserver,
		Now:   d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace creation: %w", err)
	}

	log.Info("workspace service constructed", "quota", "workspaces.count")
	return workspaceapi.New(workspaceapi.Deps{Creation: creation})
}
