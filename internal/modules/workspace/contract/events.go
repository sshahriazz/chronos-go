// Package contract is the workspace module's published event vocabulary.
//
// Past-tense facts, carrying SubjectID pseudonyms and never personal data
// (ADR-002). `workspace` depends on `organization` and never the reverse
// (ADR-020) — nothing here is imported by that module.
package contract

import "time"

// WorkspaceCreated is a new collaboration space inside an organization.
//
// It carries the OrgID because every workspace-scoped row does: organization.md
// §5.4 requires both ids on the row and both in the RLS predicate, and the
// reason is not redundancy. It is what stops a forged or leaked workspace_id
// from ANOTHER organization resolving — the workspace-level policy alone would
// happily serve a row from a different tenant.
type WorkspaceCreated struct {
	WorkspaceID string
	OrgID       string
	Name        string
	CreatedBy   string // a SubjectID pseudonym
	CreatedAt   time.Time
}

func (*WorkspaceCreated) EventType() string { return "workspace.Created.v1" }

// WorkspaceRenamed changes the display name and nothing else.
type WorkspaceRenamed struct {
	WorkspaceID string
	OrgID       string
	Name        string
	RenamedAt   time.Time
}

func (*WorkspaceRenamed) EventType() string { return "workspace.Renamed.v1" }

// WorkspaceArchived makes a workspace read-only without destroying anything.
//
// Members are retained and SEATS ARE STILL CONSUMED (workspace.md §3). That is
// deliberate and is the difference from deletion: archiving is reversible, so
// the seats have to still be there to come back to.
type WorkspaceArchived struct {
	WorkspaceID string
	OrgID       string
	ArchivedAt  time.Time
}

func (*WorkspaceArchived) EventType() string { return "workspace.Archived.v1" }

// WorkspaceRestored returns an archived workspace to use.
type WorkspaceRestored struct {
	WorkspaceID string
	OrgID       string
	RestoredAt  time.Time
}

func (*WorkspaceRestored) EventType() string { return "workspace.Restored.v1" }

// WorkspaceAdminAdded grants workspace administration.
//
// Admins are INSIDE the Workspace aggregate, for the rule organization.md §2
// states and workspace.md §1 repeats: invariant-bearing sets go inside the
// aggregate, high-volume collections do not. "Never zero admins" must hold
// transactionally; ordinary members number thousands and live in their own
// aggregate.
type WorkspaceAdminAdded struct {
	WorkspaceID string
	OrgID       string
	AdminID     string
	AddedAt     time.Time
}

func (*WorkspaceAdminAdded) EventType() string { return "workspace.AdminAdded.v1" }

// WorkspaceAdminRemoved revokes workspace administration.
type WorkspaceAdminRemoved struct {
	WorkspaceID string
	OrgID       string
	AdminID     string
	RemovedAt   time.Time
}

func (*WorkspaceAdminRemoved) EventType() string { return "workspace.AdminRemoved.v1" }

// MemberRole is what somebody may do inside a workspace.
//
// Guests are structurally the ABSENCE of the membership edge (access.md §7.6),
// not a role with deny rules — so the distinction here is about which seat pool
// they consume and which relation the access projector writes, never about
// subtracting permissions from a member.
type MemberRole string

const (
	RoleAdmin  MemberRole = "admin"
	RoleMember MemberRole = "member"
	RoleGuest  MemberRole = "guest"
)

// SeatPool names which independent pool a role draws from (ADR-027).
//
// `seats.member` and `seats.guest` are separate limits, reserved separately, so
// exhausting guest seats never blocks hiring and vice versa.
func (r MemberRole) SeatPool() string {
	if r == RoleGuest {
		return "seats.guest"
	}
	return "seats.member"
}

// MemberJoined records somebody joining a workspace.
//
// # SeatConsumed is a FACT, not a decision to re-derive
//
// A seat is per person per ORGANIZATION, not per membership (workspace.md §2):
// somebody in five workspaces of one org holds one seat. So joining a second
// workspace consumes nothing, and this field records which of the two happened.
//
// Storing it matters because the alternative — recomputing "was this their first
// workspace" at removal time — asks a question about the PAST using the present
// state, and gets it wrong the moment memberships are removed out of order.
type MemberJoined struct {
	WorkspaceID string
	OrgID       string
	SubjectID   string
	Role        MemberRole

	// SeatConsumed is true when this membership took a seat from the pool —
	// that is, when the person was not already in the organization.
	SeatConsumed bool

	JoinedAt time.Time
}

func (*MemberJoined) EventType() string { return "workspace.MemberJoined.v1" }

// MemberRoleChanged records a promotion or demotion.
//
// A change that CROSSES POOLS — guest to member, or back — releases one pool's
// seat and reserves the other's, and workspace.md §2 requires that to be atomic:
// a failure must not consume both or neither.
type MemberRoleChanged struct {
	WorkspaceID string
	OrgID       string
	SubjectID   string
	From        MemberRole
	To          MemberRole
	ChangedAt   time.Time
}

func (*MemberRoleChanged) EventType() string { return "workspace.MemberRoleChanged.v1" }

// MemberRemoved records somebody leaving a workspace.
//
// # SeatReleased is the mirror of MemberJoined.SeatConsumed
//
// Removing somebody from one workspace of several releases NOTHING — they are
// still in the organization and still hold their seat. The seat comes back only
// when they leave the organization entirely, which is the removal of their LAST
// membership in it.
type MemberRemoved struct {
	WorkspaceID string
	OrgID       string
	SubjectID   string
	Role        MemberRole

	// SeatReleased is true when this removal returned a seat to the pool —
	// that is, when it was the person's last membership in the organization.
	SeatReleased bool

	RemovedAt time.Time
}

func (*MemberRemoved) EventType() string { return "workspace.MemberRemoved.v1" }
