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

// ---------------------------------------------------------------------------
// Invitations (workspace.md §5)
// ---------------------------------------------------------------------------

// InvitationIssued records an invitation being sent.
//
// # No address, anywhere
//
// The invitee's email is personal data and never enters an event (ADR-002). What
// travels is the blind INDEX — a keyed HMAC of the normalised address that
// answers "is this the same address?" and nothing else. It cannot be rendered to
// a human, and no notification may be addressed from it; the mail activity
// resolves the real address from the vault at send time.
//
// # No token, either
//
// An invitation token is a credential. Only its digest is stored, and not even
// the digest goes in the event: an event log is replicated, retained far longer
// than any token's lifetime, and readable by every projector. The digest lives
// in the invitation's own store, which is the same reasoning that keeps session
// tokens out of the log.
type InvitationIssued struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string

	// SubjectID is the pseudonym for the invitee's address. It exists whether or
	// not an account does — an invitation to somebody with no account still needs
	// a stable handle for the vault entry holding their address.
	SubjectID string

	// EmailIndex is the keyed blind index, so a second invitation to the same
	// address can be recognised as such without either event carrying it.
	EmailIndex string

	// InvitedBy is the pseudonym of whoever issued it. Retained because the
	// inviter losing permission does NOT invalidate the invitation — it was
	// authorised when issued — but their removal from the organization DOES
	// revoke what they issued (workspace.md §5), and that reactor needs to know
	// whose invitations to revoke.
	InvitedBy string

	Role MemberRole

	// SeatConsumed records whether issuing took a seat. Conditional for the same
	// reason a join is: somebody already in the organization holds one already.
	//
	// The seat is taken AT ISSUE and not at acceptance. Otherwise 60 pending
	// invitations against 50 seats all look valid, and the 51st acceptance fails
	// for somebody who did nothing wrong.
	SeatConsumed bool

	ExpiresAt time.Time
	IssuedAt  time.Time
}

func (*InvitationIssued) EventType() string { return "workspace.InvitationIssued.v1" }

// InvitationTokenRotated records a resend.
//
// A separate event from the issue, because the invitation is the same invitation
// — same id, same seat, same authorisation — and only the credential changed.
// Recording it as a fresh issue would take a second seat and lose the link to
// the original.
//
// The old token stays dead: the digest it hashed to is replaced in the store, so
// a presented copy of it matches nothing.
type InvitationTokenRotated struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string
	SubjectID    string

	// ExpiresAt is extended, which is the other half of what a resend is for: a
	// link that arrived after the original window closed is useless.
	ExpiresAt time.Time

	RotatedAt time.Time
}

func (*InvitationTokenRotated) EventType() string { return "workspace.InvitationTokenRotated.v1" }

// InvitationAccepted records a redemption.
//
// The membership it produces is a SEPARATE event on a separate stream, appended
// by the same command. This one says the invitation is spent; MemberJoined says
// who is now in the workspace.
type InvitationAccepted struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string

	// SubjectID is the pseudonym the invitation was issued to. It may differ
	// from the ACCEPTING account's pseudonym when an address later merged
	// accounts (identity §7.5), which is why the accepting subject is recorded
	// separately rather than assumed equal.
	SubjectID string

	// AcceptedBy is the account that actually redeemed it.
	AcceptedBy string

	Role MemberRole

	AcceptedAt time.Time
}

func (*InvitationAccepted) EventType() string { return "workspace.InvitationAccepted.v1" }

// InvitationRevoked records the organization withdrawing it.
type InvitationRevoked struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string
	SubjectID    string

	// RevokedBy is empty when the revocation was a consequence rather than a
	// decision — an inviter removed from the organization takes their
	// outstanding invitations with them, and no person issued that command.
	RevokedBy string

	// SeatReleased mirrors MemberRemoved.SeatReleased: a fact recorded rather
	// than a condition to re-derive, because "was this their last hold on a
	// seat" is a question about the past that present state answers wrongly the
	// moment two invitations are settled out of order.
	SeatReleased bool

	RevokedAt time.Time
}

func (*InvitationRevoked) EventType() string { return "workspace.InvitationRevoked.v1" }

// InvitationDeclined records the invitee refusing.
//
// Distinct from revoked, and the distinction is not cosmetic: re-inviting
// somebody who declined is a decision a human should make deliberately, while
// re-inviting after an accidental revocation is routine.
type InvitationDeclined struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string
	SubjectID    string
	SeatReleased bool
	DeclinedAt   time.Time
}

func (*InvitationDeclined) EventType() string { return "workspace.InvitationDeclined.v1" }

// InvitationExpired records the window closing.
//
// Written by the Temporal workflow, not by a lazy check at redemption: the seat
// has to come back whether or not anybody ever clicks the link, and a lazy check
// only runs when somebody does.
type InvitationExpired struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string
	SubjectID    string
	SeatReleased bool
	ExpiredAt    time.Time
}

func (*InvitationExpired) EventType() string { return "workspace.InvitationExpired.v1" }

// InvitationUndeliverable records a hard bounce.
//
// Separate from expired because the ADDRESS is wrong rather than the timing:
// resending changes nothing, and an inviter who is not told will resend forever.
type InvitationUndeliverable struct {
	InvitationID string
	WorkspaceID  string
	OrgID        string
	SubjectID    string
	SeatReleased bool

	// Reason is the bounce classification, never the provider's raw message: a
	// bounce report routinely quotes the recipient's address back, and that would
	// put personal data in the log (ADR-002).
	Reason string

	BouncedAt time.Time
}

func (*InvitationUndeliverable) EventType() string { return "workspace.InvitationUndeliverable.v1" }
