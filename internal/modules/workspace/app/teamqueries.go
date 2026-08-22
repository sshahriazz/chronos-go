package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// teamsQueryID binds a page token to THIS list.
const teamsQueryID page.QueryID = "workspace.team_view.by_workspace"

// teamSortColumns is the sort key, and it ends in a UNIQUE column.
//
// Two teams may share a display name — nothing forbids it, and nothing should:
// the access engine knows a team by its id, so a duplicate name is a human
// problem rather than a correctness one. A cursor on the name alone would then
// either skip a team or repeat one.
var teamSortColumns = []string{"name", "team_id"}

// TeamSummary is one row of the team list.
type TeamSummary struct {
	TeamID    string
	Name      string
	CreatedBy string
	CreatedAt time.Time
}

// TeamPage is one page of it.
type TeamPage struct {
	Teams         []TeamSummary
	NextPageToken string
}

// TeamReader is the read side of team_view.
//
// Declared by the consumer, satisfied by the adapter. It WRITES NOTHING, and
// that is structural: there is no write on this interface for a bug to reach.
type TeamReader interface {
	ListByWorkspace(
		ctx context.Context, workspaceID string, after page.Keyset, size page.Size,
	) ([]TeamSummary, error)
}

// ListTeamsQuery asks for one page of a workspace's teams.
type ListTeamsQuery struct {
	WorkspaceID string
	PageSize    int
	PageToken   string
}

// TeamQueries is workspace's team read side.
type TeamQueries struct{ reads TeamReader }

func NewTeamQueries(reads TeamReader) (*TeamQueries, error) {
	if reads == nil {
		return nil, fmt.Errorf("workspace: a team reader is required")
	}
	return &TeamQueries{reads: reads}, nil
}

// List returns one page of a workspace's teams.
func (q *TeamQueries) List(ctx context.Context, query ListTeamsQuery) (TeamPage, error) {
	if query.WorkspaceID == "" {
		return TeamPage{}, errs.ValidationFailedf("a workspace is required")
	}

	size, err := page.Clamp(query.PageSize)
	if err != nil {
		return TeamPage{}, errs.ValidationFailedf("page size: %v", err).Wrap(err)
	}

	// Every token failure is an ERROR and none of them is "start again". A client
	// handed page one for a token it believes points into the middle walks the
	// list forever, and nothing in the loop looks like a failure.
	cursor, err := page.Resume(page.Token(query.PageToken), teamsQueryID)
	if err != nil {
		return TeamPage{}, errs.ValidationFailedf(
			"this page token cannot be used for this list; restart from the first page").Wrap(err)
	}
	if !cursor.IsStart() && !slices.Equal(cursor.Columns(), teamSortColumns) {
		return TeamPage{}, errs.ValidationFailedf(
			"this page token names the columns %v, but this list is sorted by %v",
			cursor.Columns(), teamSortColumns)
	}

	// One MORE than asked for, so "is there another page" is answered by the
	// query rather than guessed from a full page.
	rows, err := q.reads.ListByWorkspace(ctx, query.WorkspaceID, cursor, size+1)
	if err != nil {
		return TeamPage{}, errs.Internalf("listing teams").Wrap(err)
	}

	if len(rows) <= int(size) {
		return TeamPage{Teams: rows}, nil
	}
	rows = rows[:size]

	last := rows[len(rows)-1]
	keyset, err := page.NewKeyset(
		page.Key{Column: teamSortColumns[0], Value: last.Name},
		page.Key{Column: teamSortColumns[1], Value: last.TeamID, Unique: true},
	)
	if err != nil {
		return TeamPage{}, errs.Internalf("building a page cursor").Wrap(err)
	}
	token, err := page.Encode(keyset, teamsQueryID)
	if err != nil {
		return TeamPage{}, errs.Internalf("encoding a page cursor").Wrap(err)
	}
	return TeamPage{Teams: rows, NextPageToken: string(token)}, nil
}
