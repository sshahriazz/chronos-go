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

// MembersName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const MembersName = "workspace_member_view"

// Members builds `workspace_member_view`, which the seat rule counts.
//
// # Why it is separate from OrgMembers
//
// Different tables, and CONVENTIONS §8 gives one projection per table so that a
// rebuild has a defined order. They also answer different questions: this one
// says which workspaces a person is in, and `org_member_index` says whether they
// are in the organization at all. A count of the second is always one, so it
// cannot stand in for the first.
type Members struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Members)(nil)

// NewMembers wires the handlers.
//
// # WorkspaceCreated is NOT handled here
//
// The creator's row comes from their own `MemberJoined`, appended atomically
// with `WorkspaceCreated` by the creation use case. This projection used to
// special-case the creation event instead, and that special case was the visible
// end of a real hole: the creator had no Membership aggregate at all, so
// removing them was a no-op that reported success, changing their role was
// NOT_FOUND, and their membership had consumed no seat.
//
// Deriving the row from one event and every other membership fact from another
// is what made the two disagree. One source now, for everybody.
func NewMembers(codec eventsourcing.Codec) *Members {
	d := projection.NewDispatch(codec)

	d.On[contract.MemberJoined](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.MemberJoined,
	) error {
		w.Exec(workspacedb.UpsertWorkspaceMember,
			e.WorkspaceID, e.OrgID, e.SubjectID, string(e.Role), e.JoinedAt)
		return nil
	})

	d.On[contract.MemberRoleChanged](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.MemberRoleChanged,
	) error {
		w.Exec(workspacedb.SetWorkspaceMemberRole, e.WorkspaceID, e.SubjectID, string(e.To))
		return nil
	})

	d.On[contract.MemberRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.MemberRemoved,
	) error {
		w.Exec(workspacedb.DeleteWorkspaceMember, e.WorkspaceID, e.SubjectID)
		return nil
	})

	return &Members{dispatch: d}
}

func (m *Members) Name() string { return MembersName }

// Filter covers membership streams only.
//
// Every fact this table holds is a membership fact, including the creator's —
// the creation use case appends their `MemberJoined` atomically with the
// workspace, so there is nothing on the workspace stream left to read.
func (m *Members) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.MembershipCategory) + "-"},
	}
}

func (m *Members) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return m.dispatch.Apply(ctx, w, env)
}

func (m *Members) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, workspacedb.TruncateWorkspaceMembers)
	return err
}
