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
	workspacepg "github.com/chronos/chronos-go/internal/modules/workspace/adapter/postgres"
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

	if d.pool == nil {
		return nil, errors.New("no postgres pool: whether a join consumes a seat is a count " +
			"of existing memberships, and without it every join would take one")
	}
	if d.authzCache == nil {
		return nil, errors.New("no revocation store: removing a member would leave every " +
			"permission working until a projector caught up, and being late to revoke is a " +
			"security failure rather than a delay (access.md §6.1)")
	}

	repo := eventsourcing.NewRepository[*workspacedomain.Workspace](
		d.store, d.codec, d.upcasters, workspacedomain.Category, workspacedomain.NewWorkspace)

	// Its OWN repository and its own category. A membership is a separate
	// aggregate from the workspace it belongs to, so that thousands of joins do
	// not contend for one stream's revision (workspace.md §1).
	memberships := eventsourcing.NewRepository[*workspacedomain.Membership](
		d.store, d.codec, d.upcasters,
		workspacedomain.MembershipCategory, workspacedomain.NewMembership)

	counter, err := workspacepg.NewMembership(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("workspace membership counter: %w", err)
	}

	// Seats are reserved HERE and not by gate 4. Gate 4 reserves
	// unconditionally, and the seat rule is conditional — one seat per person
	// per organization, however many workspaces they are in (workspace.md §2) —
	// so declaring `seats.member` on the RPC would charge somebody a second seat
	// every time they joined another workspace.
	seats, err := workspaceapp.NewSeats(workspaceapp.SeatsDeps{
		Reserver: &seatReserver{inner: d.reserver},
		Members:  counter,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace seats: %w", err)
	}

	// Creation needs the appender, not just the repository: the workspace and
	// its creator's membership are ONE atomic append. Two appends would leave a
	// workspace whose own creator is not a member of it — which is the state
	// this system was in until the member RPCs made it visible.
	var appender eventsourcing.MultiAppender = d.store

	creation, err := workspaceapp.NewCreation(workspaceapp.CreationDeps{
		Repo:     repo,
		Appender: appender,
		Schemas:  d.upcasters,
		Quota:    d.reserver,
		Seats:    seats,
		Now:      d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace creation: %w", err)
	}

	// Invitations. Every port below is satisfied here and could not be satisfied
	// inside the module: two of them are identity's and one is the vault's, and
	// `modules/A` may import `modules/B/contract` and nothing more.
	if d.emailIndex == nil || d.accounts == nil {
		return nil, errors.New("no blind index or account directory: identity did not " +
			"construct, so an invitation could neither recognise an existing account nor " +
			"keep the invitee's address out of the event")
	}
	if d.piiVault == nil {
		return nil, errors.New("no vault: an invitation names a pseudonym, and without the " +
			"entry behind it the mail has no address to resolve at send time")
	}

	invitationRepo := eventsourcing.NewRepository[*workspacedomain.Invitation](
		d.store, d.codec, d.upcasters,
		workspacedomain.InvitationCategory, workspacedomain.NewInvitation)

	invitationTokens, err := workspacepg.NewInvitationTokens(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("invitation token store: %w", err)
	}

	if d.subscriptions == nil {
		return nil, errors.New("no subscription gate: acceptance revalidates that the " +
			"organization still permits growth, and it cannot use the interceptor's — the " +
			"person clicking the link is not in the organization yet")
	}

	invitations, err := workspaceapp.NewInvitations(workspaceapp.InvitationsDeps{
		Repo:        invitationRepo,
		Workspaces:  repo,
		Memberships: memberships,
		Appender:    appender,
		Schemas:     d.upcasters,
		Subs:        &joinPermission{gate: d.subscriptions},
		Tokens:      invitationTokens,
		Indexer:     d.emailIndex,
		Dir:         d.accounts,
		Vault:       &vaultAddresses{vault: d.piiVault},
		Subjects:    &ulidSubjects{clock: d.clock},
		Seats:       seats,
		Now:         d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace invitations: %w", err)
	}

	members, err := workspaceapp.NewMembers(workspaceapp.MembersDeps{
		Workspaces:  repo,
		Memberships: memberships,
		Seats:       seats,
		Counter:     counter,
		Revoker:     revokerOrNil(d.authzCache),
		Now:         d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace members: %w", err)
	}

	log.Info("workspace service constructed",
		"quota", "workspaces.count", "seats", "member+guest",
		"revocation", "tombstones", "invitations", workspaceapp.InvitationTTL.String())
	invitationReads, err := workspacepg.NewInvitationReads(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("invitation reads: %w", err)
	}
	invitationQueries, err := workspaceapp.NewInvitationQueries(invitationReads)
	if err != nil {
		return nil, fmt.Errorf("invitation queries: %w", err)
	}

	return workspaceapi.New(workspaceapi.Deps{
		Creation: creation, Members: members,
		Invitations: invitations, InvitationQueries: invitationQueries,
	})
}
