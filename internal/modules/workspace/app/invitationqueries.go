package app

import (
	"context"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// invitationsQueryID binds a page token to THIS list.
//
// A token minted here and presented to another list is refused rather than
// silently answered from the wrong rows — see page/token.go. It must be unique
// across every list in the process, which is why it names the module as well as
// the table.
const invitationsQueryID page.QueryID = "workspace.invitation_view.by_workspace"

// invitationSortColumns is the sort key, and it ends in a UNIQUE column.
//
// `expires_at` alone is not unique — a bulk invite mints many with the same
// deadline — so a cursor on it would either skip rows or repeat them. The
// invitation id breaks the tie.
var invitationSortColumns = []string{"expires_at", "invitation_id"}

// InvitationSummary is one row of the admin screen.
//
// It carries the invitee's PSEUDONYM and not their address. Rendering a list of
// invitations to a human needs the address, and the vault resolves it at read
// time under the key erasure destroys — putting it here would mean a screen's
// query result is a place personal data lives (ADR-002).
type InvitationSummary struct {
	InvitationID string
	SubjectID    string
	InvitedBy    string
	Role         contract.MemberRole
	Status       domain.InvitationStatus
	ExpiresAt    time.Time
	IssuedAt     time.Time
}

// InvitationPage is one page of the admin screen.
type InvitationPage struct {
	Invitations []InvitationSummary

	// NextPageToken is empty on the last page.
	NextPageToken string
}

// InvitationReader is the read side of invitation_view.
//
// Declared by the consumer, satisfied by the adapter. It WRITES NOTHING, and
// that is structural rather than a convention: there is no write on this
// interface for a bug to reach.
type InvitationReader interface {
	ListByWorkspace(
		ctx context.Context, workspaceID string, status domain.InvitationStatus,
		after page.Keyset, size page.Size,
	) ([]InvitationSummary, error)
}

// ListInvitationsQuery asks for one page of a workspace's invitations.
type ListInvitationsQuery struct {
	WorkspaceID string

	// Status filters the list. Empty means pending, which is the only one an
	// admin screen usually wants — settled invitations are history.
	Status domain.InvitationStatus

	PageSize  int
	PageToken string
}

// InvitationQueries is workspace's invitation read side.
type InvitationQueries struct{ reads InvitationReader }

func NewInvitationQueries(reads InvitationReader) (*InvitationQueries, error) {
	if reads == nil {
		return nil, fmt.Errorf("workspace: an invitation reader is required")
	}
	return &InvitationQueries{reads: reads}, nil
}

// List returns one page of a workspace's invitations.
func (q *InvitationQueries) List(
	ctx context.Context, query ListInvitationsQuery,
) (InvitationPage, error) {
	if query.WorkspaceID == "" {
		return InvitationPage{}, errs.ValidationFailedf("a workspace is required")
	}

	status := query.Status
	if status == "" {
		status = domain.InvitationPending
	}
	// InvitationStatuses includes Unknown — deliberately, so an exhaustive test
	// covers the zero value — and Unknown is not a filter. It is excluded
	// explicitly rather than by trimming the list, because trimming would make
	// the lifecycle test blind to exactly the state that must never be reachable.
	if status == domain.InvitationUnknown ||
		!slices.Contains(domain.InvitationStatuses(), status) {
		return InvitationPage{}, errs.ValidationFailedf("%q is not an invitation status", status)
	}

	size, err := page.Clamp(query.PageSize)
	if err != nil {
		return InvitationPage{}, errs.ValidationFailedf("page size: %v", err).Wrap(err)
	}

	// Every token failure is an ERROR and none of them is "start again". A client
	// handed page one for a token it believes points into the middle walks the
	// list forever, and nothing in the loop looks like a failure.
	cursor, err := page.Resume(page.Token(query.PageToken), invitationsQueryID)
	if err != nil {
		return InvitationPage{}, errs.ValidationFailedf(
			"this page token cannot be used for this list; restart from the first page").Wrap(err)
	}
	if !cursor.IsStart() && !slices.Equal(cursor.Columns(), invitationSortColumns) {
		return InvitationPage{}, errs.ValidationFailedf(
			"this page token names the columns %v, but this list is sorted by %v",
			cursor.Columns(), invitationSortColumns)
	}

	// One MORE than asked for, so "is there another page" is answered by the
	// query rather than guessed from a full page — a full last page would
	// otherwise mint a token that returns nothing.
	rows, err := q.reads.ListByWorkspace(ctx, query.WorkspaceID, status, cursor, size+1)
	if err != nil {
		return InvitationPage{}, errs.Internalf("listing invitations").Wrap(err)
	}

	if len(rows) <= int(size) {
		return InvitationPage{Invitations: rows}, nil
	}
	rows = rows[:size]

	last := rows[len(rows)-1]
	keyset, err := page.NewKeyset(
		page.Key{Column: invitationSortColumns[0], Value: last.ExpiresAt.UTC()},
		page.Key{Column: invitationSortColumns[1], Value: last.InvitationID, Unique: true},
	)
	if err != nil {
		return InvitationPage{}, errs.Internalf("building a page cursor").Wrap(err)
	}
	token, err := page.Encode(keyset, invitationsQueryID)
	if err != nil {
		return InvitationPage{}, errs.Internalf("encoding a page cursor").Wrap(err)
	}
	return InvitationPage{Invitations: rows, NextPageToken: string(token)}, nil
}
