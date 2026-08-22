package postgres

import (
	"context"
	"fmt"
	"math"
	"time"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// TeamReads is the read side of team_view.
//
// A TENANT transaction: every caller reaches it after gate 1 has resolved a
// scope, so the row security policy applies and another organization's teams are
// invisible rather than merely unmatched.
type TeamReads struct{ tx db.TX }

var _ app.TeamReader = (*TeamReads)(nil)

func NewTeamReads(tx db.TX) (*TeamReads, error) {
	if tx == nil {
		return nil, fmt.Errorf("workspace: a transaction source is required")
	}
	return &TeamReads{tx: tx}, nil
}

// ListByWorkspace returns one page, keyset-ordered by (name, team_id).
//
// A START cursor uses the empty name and id, which sort before every real row —
// so "first page" and "resume" are ONE query rather than two that could drift.
func (r *TeamReads) ListByWorkspace(
	ctx context.Context, workspaceID string, after page.Keyset, size page.Size,
) ([]app.TeamSummary, error) {
	afterName, afterID := "", ""
	if !after.IsStart() {
		args := after.Args()
		if len(args) != 2 {
			return nil, fmt.Errorf("workspace: a cursor for this list needs 2 keys, got %d",
				len(args))
		}
		name, ok := args[0].(string)
		if !ok {
			return nil, fmt.Errorf("workspace: the cursor's name is %T, not a string", args[0])
		}
		id, ok := args[1].(string)
		if !ok {
			return nil, fmt.Errorf("workspace: the cursor's id is %T, not a string", args[1])
		}
		afterName, afterID = name, id
	}

	var out []app.TeamSummary
	err := r.tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		if size > page.Size(math.MaxInt32) {
			return fmt.Errorf("workspace: a page size of %d does not fit a query limit", size)
		}
		limit := int32(size) //nolint:gosec // bounded on the line above

		rows, err := q.Query(ctx, workspacedb.ListTeams,
			workspaceID, afterName, afterID, limit)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var summary app.TeamSummary
			var createdAt time.Time
			if err := rows.Scan(&summary.TeamID, &summary.Name,
				&summary.CreatedBy, &createdAt); err != nil {
				return err
			}
			summary.CreatedAt = createdAt.UTC()
			out = append(out, summary)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: listing teams for %s: %w", workspaceID, err)
	}
	return out, nil
}

// TeamRosters answers "which teams inside this workspace is this person in".
//
// Its own type rather than a method on TeamReads, because the caller is not a
// screen: the departure cascade drives it, and it runs in a REACTOR, after a
// removal, with no request and therefore no gate 1 to have resolved a scope.
type TeamRosters struct{ system db.SystemTX }

var _ app.TeamRoster = (*TeamRosters)(nil)

func NewTeamRosters(system db.SystemTX) (*TeamRosters, error) {
	if system == nil {
		return nil, fmt.Errorf("workspace: a system transaction source is required")
	}
	return &TeamRosters{system: system}, nil
}

// TeamsOf lists every team of one workspace this person belongs to.
//
// # A SYSTEM transaction, and why that is not a shortcut
//
// A reactor has no request and no gate 1, so there is no `app.org_id` to set and
// a tenant transaction would match nothing — which would look exactly like "this
// person was in no teams" and silently skip the whole cascade. The isolation the
// row security policy would give is supplied instead by the WHERE clause: the
// workspace id comes from the event that has just been appended to that
// workspace's own stream, so a cross-tenant row cannot be reached from it.
func (r *TeamRosters) TeamsOf(
	ctx context.Context, workspaceID, subjectID string,
) ([]string, error) {
	if workspaceID == "" || subjectID == "" {
		return nil, fmt.Errorf("workspace: listing somebody's teams needs both a workspace " +
			"and a subject")
	}
	var out []string
	err := r.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, workspacedb.TeamsOfMember, workspaceID, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()

		for rows.Next() {
			var teamID string
			if err := rows.Scan(&teamID); err != nil {
				return err
			}
			out = append(out, teamID)
		}
		return rows.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("workspace: listing %s's teams in %s: %w",
			subjectID, workspaceID, err)
	}
	return out, nil
}
