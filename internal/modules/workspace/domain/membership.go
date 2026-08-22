package domain

import (
	"fmt"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// MembershipCategory holds one stream per (workspace, person).
//
// Its OWN aggregate rather than a set inside Workspace, and workspace.md §1
// gives the rule: invariant-bearing sets go inside the aggregate; high-volume
// collections do not. A workspace may hold thousands of members and they churn
// constantly, so putting them in the Workspace stream would make every join
// contend with every other one for the same revision.
const MembershipCategory eventsourcing.Category = "membership"

// MembershipStreamKey names one person's membership of one workspace.
//
// Joined with '.', because a stream key may not contain '-' — KurrentDB derives
// the category from everything before the first dash — and both ids already use
// '_' to separate their own prefix (ADR-030). A third separator would be
// ambiguous; '.' appears in neither.
func MembershipStreamKey(workspaceID, subjectID string) string {
	return workspaceID + "." + subjectID
}

// Membership is one person's place in one workspace.
type Membership struct {
	eventsourcing.Base

	workspaceID string
	orgID       string
	subjectID   string
	role        contract.MemberRole
	active      bool

	// seatConsumed records whether THIS membership took a seat. It is read back
	// at removal to decide whether one comes back, rather than recomputed from
	// present state — which would answer a question about the past wrongly the
	// moment memberships are removed out of order.
	seatConsumed bool
}

var _ eventsourcing.Root = (*Membership)(nil)

// NewMembership returns an empty aggregate for the repository to rebuild into.
func NewMembership() *Membership { return &Membership{} }

func (m *Membership) WorkspaceID() string       { return m.workspaceID }
func (m *Membership) OrgID() string             { return m.orgID }
func (m *Membership) SubjectID() string         { return m.subjectID }
func (m *Membership) Role() contract.MemberRole { return m.role }
func (m *Membership) Active() bool              { return m.active }
func (m *Membership) SeatConsumed() bool        { return m.seatConsumed }
func (m *Membership) Exists() bool              { return m.subjectID != "" }

// Apply replays one event. Pure, and it validates nothing.
func (m *Membership) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.MemberJoined:
		m.workspaceID = ev.WorkspaceID
		m.orgID = ev.OrgID
		m.subjectID = ev.SubjectID
		m.role = ev.Role
		m.seatConsumed = ev.SeatConsumed
		m.active = true
	case *contract.MemberRoleChanged:
		m.role = ev.To
	case *contract.MemberRemoved:
		m.active = false
	}
}

// Join records somebody joining a workspace.
//
// seatConsumed is decided by the CALLER, because the question — "is this person
// already in this organization" — is about the organization and not about this
// membership. The aggregate records the answer; it cannot compute it, and a
// version that tried would be reaching across an aggregate boundary to guess.
func (m *Membership) Join(
	workspaceID, orgID, subjectID string,
	role contract.MemberRole, seatConsumed bool, at time.Time,
) error {
	if m.Exists() && m.active {
		return fmt.Errorf("workspace: %s is already a member of %s", subjectID, workspaceID)
	}
	switch {
	case workspaceID == "":
		return fmt.Errorf("workspace: a workspace is required")
	case orgID == "":
		return fmt.Errorf("workspace: an organization is required; a seat is per person per " +
			"organization, and without one there is no pool to draw from")
	case subjectID == "":
		return fmt.Errorf("workspace: a subject is required")
	}
	if err := validRole(role); err != nil {
		return err
	}
	eventsourcing.Record(m, &contract.MemberJoined{
		WorkspaceID: workspaceID, OrgID: orgID, SubjectID: subjectID,
		Role: role, SeatConsumed: seatConsumed, JoinedAt: at,
	})
	return nil
}

// ChangeRole promotes or demotes.
//
// CrossesPools reports whether the change moves between the member and guest
// pools, which the caller needs because that case is a release and a reserve
// rather than a no-op.
func (m *Membership) ChangeRole(to contract.MemberRole, at time.Time) error {
	if !m.Exists() || !m.active {
		return fmt.Errorf("workspace: not a member")
	}
	if err := validRole(to); err != nil {
		return err
	}
	if to == m.role {
		return nil
	}
	eventsourcing.Record(m, &contract.MemberRoleChanged{
		WorkspaceID: m.workspaceID, OrgID: m.orgID, SubjectID: m.subjectID,
		From: m.role, To: to, ChangedAt: at,
	})
	return nil
}

// CrossesPools reports whether moving to `to` changes which seat pool is drawn
// from (ADR-027). Guest seats and member seats are independent limits.
func (m *Membership) CrossesPools(to contract.MemberRole) bool {
	return m.role.SeatPool() != to.SeatPool()
}

// Remove records somebody leaving a workspace.
//
// seatReleased is the caller's answer to "was this their last membership in the
// organization", for the same reason Join takes seatConsumed: it is a fact about
// the organization, which this aggregate cannot see.
//
// A seat can only be released if one was consumed. Releasing otherwise would
// return a unit to the pool that this membership never took, which inflates the
// allowance by one every time it happens.
func (m *Membership) Remove(seatReleased bool, at time.Time) error {
	if !m.Exists() {
		return fmt.Errorf("workspace: not a member")
	}
	if !m.active {
		return nil // already gone
	}
	if seatReleased && !m.seatConsumed {
		return fmt.Errorf("workspace: %s would release a seat it never consumed; a seat is "+
			"held by the membership that took it, and returning one from a membership that "+
			"did not inflates the pool", m.subjectID)
	}
	eventsourcing.Record(m, &contract.MemberRemoved{
		WorkspaceID: m.workspaceID, OrgID: m.orgID, SubjectID: m.subjectID,
		Role: m.role, SeatReleased: seatReleased, RemovedAt: at,
	})
	return nil
}

func validRole(r contract.MemberRole) error {
	switch r {
	case contract.RoleAdmin, contract.RoleMember, contract.RoleGuest:
		return nil
	default:
		return fmt.Errorf("workspace: %q is not a role", strings.TrimSpace(string(r)))
	}
}
