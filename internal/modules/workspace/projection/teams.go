package projection

import (
	"context"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// TeamsName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const TeamsName = "team_view"

// Teams builds `team_view` and `team_member_view`.
//
// TWO tables from one projection, which CONVENTIONS §8's "one projection per
// table" does not permit lightly. It is one here because deletion writes both in
// the same batch: a team's row becomes `deleted` and its members' rows go, and
// splitting that across two projections with two checkpoints would let a rebuild
// leave members attached to a deleted team — a team that grants to people it no
// longer contains.
//
// The alternative — a second projection that also watches TeamDeleted — is two
// writers for one fact, which is the thing the rule exists to prevent.
type Teams struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Teams)(nil)

// NewTeams wires the handlers.
func NewTeams(codec eventsourcing.Codec) *Teams {
	d := projection.NewDispatch(codec)

	d.On[contract.TeamCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.TeamCreated,
	) error {
		w.Exec(workspacedb.UpsertTeam,
			e.TeamID, e.WorkspaceID, e.OrgID, e.Name, e.CreatedBy, e.CreatedAt)
		return nil
	})

	d.On[contract.TeamRenamed](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.TeamRenamed,
	) error {
		w.Exec(workspacedb.RenameTeam, e.TeamID, e.Name)
		return nil
	})

	// A status change and the membership going, in ONE batch. The team's row is
	// KEPT: access.md §7.5 requires that a team id is never reused, and a DELETE
	// would make the id look free to anything reading this table.
	d.On[contract.TeamDeleted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.TeamDeleted,
	) error {
		w.Exec(workspacedb.DeleteTeam, e.TeamID, e.DeletedAt)
		w.Exec(workspacedb.DeleteTeamMembers, e.TeamID)
		return nil
	})

	// Maintainers are NOT projected. They live in the aggregate, every decision
	// that reads them is taken there, and a projected copy would be a second
	// answer to "may this person manage the team" that lags the first.

	d.On[contract.TeamMemberAdded](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.TeamMemberAdded,
	) error {
		w.Exec(workspacedb.UpsertTeamMember,
			e.TeamID, e.WorkspaceID, e.OrgID, e.SubjectID, e.AddedAt)
		return nil
	})

	d.On[contract.TeamMemberRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.TeamMemberRemoved,
	) error {
		w.Exec(workspacedb.DeleteTeamMember, e.TeamID, e.SubjectID)
		return nil
	})

	return &Teams{dispatch: d}
}

func (t *Teams) Name() string { return TeamsName }

// Filter covers team streams and team-membership streams both.
func (t *Teams) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{
			string(domain.TeamCategory) + "-",
			string(domain.TeamMembershipCategory) + "-",
		},
	}
}

func (t *Teams) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return t.dispatch.Apply(ctx, w, env)
}

// Reset empties BOTH tables, for the reason NewTeams gives: they are one
// projection because deletion writes both, so a rebuild has to start from both
// being empty or the second would keep rows the first no longer explains.
func (t *Teams) Reset(ctx context.Context, q db.Querier) error {
	if _, err := q.Exec(ctx, workspacedb.TruncateTeamMembers); err != nil {
		return err
	}
	_, err := q.Exec(ctx, workspacedb.TruncateTeams)
	return err
}
