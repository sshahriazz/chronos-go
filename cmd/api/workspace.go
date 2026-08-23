package main

import (
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	billingdomain "github.com/chronos/chronos-go/internal/modules/billing/domain"
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

	// BILLING'S catalogue is now the source, which is what the comment here used
	// to promise. It holds one definition of what a plan grants; entitlement
	// enforces those numbers and billing prices them, and two copies of the same
	// limits would disagree the first time somebody changed one.
	//
	// The two modules do not import each other (CONVENTIONS §2): billing carries
	// the limits as strings and this is where they become entitlement's typed
	// LimitKeys. `NewCatalogue` refuses a key this build does not know, so a
	// limit billing publishes that nothing reserves against fails startup rather
	// than becoming a number with no enforcement behind it.
	allowances, err := allowancesFromBilling()
	if err != nil {
		return nil, err
	}
	catalogue, err := entitlementdomain.NewCatalogue(allowances...)
	if err != nil {
		return nil, fmt.Errorf("entitlement catalogue: %w", err)
	}
	// Still "trial" for every organization: reading the SUBSCRIPTION's plan is
	// the next step, and it needs the plan id on org_status_view, which the
	// catalogue's arrival is the prerequisite for rather than the whole of.
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

	// Built before the use case, because ISSUING reads it: a second invitation to
	// one address supersedes the first rather than taking a second seat
	// (workspace.md §5).
	invitationReads, err := workspacepg.NewInvitationReads(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("invitation reads: %w", err)
	}

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
		Outstanding: invitationReads,
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
	invitationQueries, err := workspaceapp.NewInvitationQueries(invitationReads)
	if err != nil {
		return nil, fmt.Errorf("invitation queries: %w", err)
	}

	teamRepo := eventsourcing.NewRepository[*workspacedomain.Team](
		d.store, d.codec, d.upcasters, workspacedomain.TeamCategory, workspacedomain.NewTeam)
	teams, err := workspaceapp.NewTeams(workspaceapp.TeamsDeps{
		Repo: teamRepo, Now: d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace teams: %w", err)
	}
	teamReads, err := workspacepg.NewTeamReads(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("team reads: %w", err)
	}
	teamQueries, err := workspaceapp.NewTeamQueries(teamReads)
	if err != nil {
		return nil, fmt.Errorf("team queries: %w", err)
	}

	if d.authz == nil {
		return nil, errors.New("no authorization guard: a team's membership may be changed " +
			"by a maintainer OR a workspace admin, and without the second a team whose " +
			"last maintainer leaves can never be managed again")
	}

	teamMembershipRepo := eventsourcing.NewRepository[*workspacedomain.TeamMembership](
		d.store, d.codec, d.upcasters,
		workspacedomain.TeamMembershipCategory, workspacedomain.NewTeamMembership)

	teamMembers, err := workspaceapp.NewTeamMembers(workspaceapp.TeamMembersDeps{
		Teams:       teamRepo,
		Memberships: teamMembershipRepo,
		Workspace:   counter,
		Admins:      &workspaceAdmins{guard: d.authz},
		Now:         d.clock.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace team members: %w", err)
	}

	return workspaceapi.New(workspaceapi.Deps{
		Creation: creation, Members: members,
		Invitations: invitations, InvitationQueries: invitationQueries,
		Teams: teams, TeamQueries: teamQueries, TeamMembers: teamMembers,
	})
}

// allowancesFromBilling turns billing's published catalogue into entitlement's.
//
// # Why the composition root and not either module
//
// `modules/billing` may not import `modules/entitlement` and the reverse is
// equally forbidden (CONVENTIONS §2). Billing knows what a plan COSTS and
// carries its limits as opaque strings; entitlement knows what a limit MEANS and
// refuses one it cannot enforce. Assembling the two is what a composition root
// is for.
//
// One allowance per PLAN rather than per version: a limit is a property of the
// plan, and monthly and yearly grant the same thing. Taking the latest monthly
// version's limits is therefore not a choice about interval — it is the only
// interval guaranteed to exist for every plan, since a trial has no yearly form.
func allowancesFromBilling() ([]entitlementdomain.Allowance, error) {
	published, err := billingdomain.Published()
	if err != nil {
		return nil, fmt.Errorf("billing catalogue: %w", err)
	}
	return allowancesFrom(published)
}

// allowancesFrom is the translation itself, over any catalogue.
//
// Split from the function above so a test can drive it with a catalogue the
// build does not publish. That is not a testability nicety: the bridge's rule is
// "the LATEST monthly version of each plan", and every published plan has
// exactly one version, so a bridge that took the FIRST version passed every test
// while being wrong — which is precisely what it did until a mutation of it
// survived. The rule cannot be exercised against a catalogue that has only one
// version to choose from.
func allowancesFrom(published *billingdomain.Catalogue) ([]entitlementdomain.Allowance, error) {
	// The distinct plans, in the catalogue's deterministic order.
	var plans []billingdomain.PlanID
	seen := map[billingdomain.PlanID]bool{}
	for _, v := range published.All() {
		if !seen[v.Plan] {
			seen[v.Plan] = true
			plans = append(plans, v.Plan)
		}
	}

	var out []entitlementdomain.Allowance
	for _, plan := range plans {
		// LATEST, asked for by name rather than taken as the first monthly
		// version the list yields. The distinction is invisible today and stops
		// being invisible the moment a second version ships: `All` is sorted by
		// plan-version id, so "pro:v1:month" precedes "pro:v2:month" and a
		// first-wins loop would enforce v1's limits forever while every new
		// subscriber was sold v2's.
		v, err := published.Latest(plan, billingdomain.Monthly)
		if err != nil {
			// A plan with no monthly version. Refused rather than skipped: a
			// plan that reaches entitlement as nothing is one gate 4 cannot
			// price, and every capped operation on it is denied with no
			// explanation.
			return nil, fmt.Errorf("billing publishes plan %q with no monthly version, so "+
				"entitlement has no allowance for it and every capped operation on that "+
				"plan would be refused: %w", plan, err)
		}

		limits := make(map[entitlementdomain.LimitKey]int, len(v.Limits))
		for key, n := range v.Limits {
			limits[entitlementdomain.LimitKey(key)] = n
		}
		out = append(out, entitlementdomain.Allowance{Name: string(v.Plan), Limits: limits})
	}
	if len(out) == 0 {
		return nil, errors.New("billing publishes no monthly plan version, so entitlement " +
			"has no allowance to enforce and every capped operation would be refused")
	}
	return out, nil
}
