package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// InvitationCategory holds one stream per invitation.
//
// Its own aggregate for the reason Membership is one: invitations are
// high-volume and churn, and putting them inside Workspace would make every
// invite contend with every other for the same stream revision (workspace.md
// §1). It is also the boundary the lifecycle needs — an invitation's state
// machine is entirely about itself.
const InvitationCategory eventsourcing.Category = "invitation"

// InvitationStreamKey names one invitation's stream.
//
// The invitation id, which is a fresh ULID per invitation. NOT keyed on the
// address or its blind index: re-inviting after a revocation must produce a NEW
// invitation with a new token, and an address-keyed stream would append the
// second invitation onto the first's history — where a replay would rebuild one
// aggregate that had been through the lifecycle twice.
func InvitationStreamKey(invitationID string) string { return invitationID }

// MaxBounceReasonLen bounds the classification recorded for a hard bounce.
const MaxBounceReasonLen = 64

// Invitation is one offer to join one workspace.
type Invitation struct {
	eventsourcing.Base

	invitationID string
	workspaceID  string
	orgID        string
	subjectID    string
	emailIndex   string
	invitedBy    string
	role         contract.MemberRole
	status       InvitationStatus
	expiresAt    time.Time

	// seatConsumed records whether ISSUING this invitation took a seat. Read
	// back at settlement to decide whether one comes back, rather than
	// recomputed from present state — which would answer a question about the
	// past wrongly the moment two invitations are settled out of order.
	seatConsumed bool
}

var _ eventsourcing.Root = (*Invitation)(nil)

// NewInvitation returns an empty aggregate for the repository to rebuild into.
func NewInvitation() *Invitation { return &Invitation{} }

func (i *Invitation) InvitationID() string      { return i.invitationID }
func (i *Invitation) WorkspaceID() string       { return i.workspaceID }
func (i *Invitation) OrgID() string             { return i.orgID }
func (i *Invitation) SubjectID() string         { return i.subjectID }
func (i *Invitation) EmailIndex() string        { return i.emailIndex }
func (i *Invitation) InvitedBy() string         { return i.invitedBy }
func (i *Invitation) Role() contract.MemberRole { return i.role }
func (i *Invitation) Status() InvitationStatus  { return i.status }
func (i *Invitation) ExpiresAt() time.Time      { return i.expiresAt }
func (i *Invitation) SeatConsumed() bool        { return i.seatConsumed }
func (i *Invitation) Exists() bool              { return i.invitationID != "" }

// Pending reports whether this invitation is still outstanding.
func (i *Invitation) Pending() bool { return i.status == InvitationPending }

// Expired reports whether the window has closed, by the clock passed in.
//
// A QUESTION, not a transition. Reaching the expiry instant does not by itself
// make an invitation Expired — the workflow records that, because the SEAT has
// to come back whether or not anybody ever clicks the link. This is what a
// redemption asks so that a link clicked after the window is refused even in the
// seconds before the workflow has written the event.
func (i *Invitation) Expired(now time.Time) bool {
	return !i.expiresAt.IsZero() && !now.Before(i.expiresAt)
}

// Apply replays one event. Pure, and it validates nothing.
func (i *Invitation) Apply(e eventsourcing.Event) {
	switch ev := e.(type) {
	case *contract.InvitationIssued:
		i.invitationID = ev.InvitationID
		i.workspaceID = ev.WorkspaceID
		i.orgID = ev.OrgID
		i.subjectID = ev.SubjectID
		i.emailIndex = ev.EmailIndex
		i.invitedBy = ev.InvitedBy
		i.role = ev.Role
		i.seatConsumed = ev.SeatConsumed
		i.expiresAt = ev.ExpiresAt
		i.status = InvitationPending
	case *contract.InvitationTokenRotated:
		// The invitation is unchanged except for its window. The token itself
		// never enters the log, so there is nothing else here to replay.
		i.expiresAt = ev.ExpiresAt
	case *contract.InvitationAccepted:
		i.status = InvitationAccepted
	case *contract.InvitationRevoked:
		i.status = InvitationRevoked
	case *contract.InvitationDeclined:
		i.status = InvitationDeclined
	case *contract.InvitationExpired:
		i.status = InvitationExpired
	case *contract.InvitationUndeliverable:
		i.status = InvitationUndeliverable
	}
}

// Issue records an invitation being sent.
//
// seatConsumed is decided by the CALLER, because the question — "is this person
// already in this organization" — is about the organization and not about this
// invitation. The aggregate records the answer; it cannot compute it, and a
// version that tried would be reaching across an aggregate boundary to guess.
func (i *Invitation) Issue(
	invitationID, workspaceID, orgID, subjectID, emailIndex, invitedBy string,
	role contract.MemberRole, seatConsumed bool, expiresAt, at time.Time,
) error {
	if i.Exists() {
		return fmt.Errorf("workspace: invitation %s already exists", i.invitationID)
	}
	switch {
	case invitationID == "":
		return fmt.Errorf("workspace: an invitation id is required")
	case workspaceID == "":
		return fmt.Errorf("workspace: a workspace is required")
	case orgID == "":
		return fmt.Errorf("workspace: an organization is required; a seat is per person per " +
			"organization, and without one there is no pool to draw from")
	case subjectID == "":
		return fmt.Errorf("workspace: a subject is required; the invitee's address lives in " +
			"the vault under this pseudonym and never in the event")
	case emailIndex == "":
		return fmt.Errorf("workspace: a blind index is required; without one a second " +
			"invitation to the same address cannot be recognised as one")
	case invitedBy == "":
		return fmt.Errorf("workspace: an inviter is required; their removal from the " +
			"organization revokes what they issued, and that needs to be attributable")
	case expiresAt.IsZero():
		return fmt.Errorf("workspace: an expiry is required; an invitation that never " +
			"expires holds a seat forever")
	case !expiresAt.After(at):
		return fmt.Errorf("workspace: an invitation cannot expire at or before it is issued")
	}
	if err := validRole(role); err != nil {
		return err
	}
	if !i.status.CanTransitionTo(InvitationPending) {
		return errIllegalInvitationTransition(i.status, InvitationPending)
	}

	eventsourcing.Record(i, &contract.InvitationIssued{
		InvitationID: invitationID, WorkspaceID: workspaceID, OrgID: orgID,
		SubjectID: subjectID, EmailIndex: emailIndex, InvitedBy: invitedBy,
		Role: role, SeatConsumed: seatConsumed, ExpiresAt: expiresAt, IssuedAt: at,
	})
	return nil
}

// RotateToken records a resend: a new credential and a longer window.
//
// Only a PENDING invitation can be resent. Resending a settled one would be a
// live token for an invitation that was revoked, declined or already redeemed —
// which is the exact failure "the old token stays dead" exists to prevent, in
// the other direction.
func (i *Invitation) RotateToken(expiresAt, at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	if !expiresAt.After(at) {
		return fmt.Errorf("workspace: a resent invitation cannot expire at or before it is sent")
	}
	if expiresAt.Before(i.expiresAt) {
		// Refused rather than silently kept. A resend that SHORTENED the window
		// would be a support request nobody can explain, and it can only come
		// from a caller computing the new expiry from the wrong base.
		return fmt.Errorf("workspace: a resend may not shorten the window; %s is earlier "+
			"than the current expiry %s", expiresAt.UTC(), i.expiresAt.UTC())
	}
	eventsourcing.Record(i, &contract.InvitationTokenRotated{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, ExpiresAt: expiresAt, RotatedAt: at,
	})
	return nil
}

// Accept records a redemption.
//
// acceptedBy may differ from the invited subject: an address that later merged
// accounts follows the SURVIVING pseudonym (identity §7.5), so the accepting
// account is recorded rather than assumed equal to the invited one.
//
// Expiry is checked HERE as well as by the workflow. The workflow is what
// releases the seat, and it may be seconds behind; a link clicked in that window
// must still be refused, and the aggregate is the only place that cannot be
// bypassed.
func (i *Invitation) Accept(acceptedBy string, at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	if acceptedBy == "" {
		return fmt.Errorf("workspace: an accepting subject is required")
	}
	if i.Expired(at) {
		return fmt.Errorf("workspace: invitation %s expired at %s",
			i.invitationID, i.expiresAt.UTC())
	}
	eventsourcing.Record(i, &contract.InvitationAccepted{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, AcceptedBy: acceptedBy, Role: i.role, AcceptedAt: at,
	})
	return nil
}

// Revoke records the organization withdrawing it.
//
// revokedBy is empty when the revocation was a consequence rather than a
// decision — an inviter removed from the organization takes their outstanding
// invitations with them, and no person issued that command.
func (i *Invitation) Revoke(revokedBy string, at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	eventsourcing.Record(i, &contract.InvitationRevoked{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, RevokedBy: revokedBy,
		SeatReleased: i.seatConsumed, RevokedAt: at,
	})
	return nil
}

// Decline records the invitee refusing.
func (i *Invitation) Decline(at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	eventsourcing.Record(i, &contract.InvitationDeclined{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, SeatReleased: i.seatConsumed, DeclinedAt: at,
	})
	return nil
}

// Expire records the window closing.
//
// It refuses to run early. The workflow owns the timer, and a workflow that
// fired on a replay or a clock skew would release a seat and kill a live token
// for an invitation somebody is about to accept — so the aggregate checks the
// deadline rather than trusting the caller reached it.
func (i *Invitation) Expire(at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	if !i.Expired(at) {
		return fmt.Errorf("workspace: invitation %s does not expire until %s",
			i.invitationID, i.expiresAt.UTC())
	}
	eventsourcing.Record(i, &contract.InvitationExpired{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, SeatReleased: i.seatConsumed, ExpiredAt: at,
	})
	return nil
}

// MarkUndeliverable records a hard bounce.
func (i *Invitation) MarkUndeliverable(reason string, at time.Time) error {
	if err := i.mustBePending(); err != nil {
		return err
	}
	switch {
	case reason == "":
		return fmt.Errorf("workspace: a bounce reason is required; an inviter who is not " +
			"told why will resend forever")
	case len(reason) > MaxBounceReasonLen:
		// Bounded because a provider's raw message routinely quotes the
		// recipient's address back, and an unbounded field is how that reaches
		// the log. The caller passes a CLASSIFICATION; this is the backstop.
		return fmt.Errorf("workspace: a bounce reason may not exceed %d characters; pass a "+
			"classification rather than the provider's message, which quotes the address",
			MaxBounceReasonLen)
	}
	eventsourcing.Record(i, &contract.InvitationUndeliverable{
		InvitationID: i.invitationID, WorkspaceID: i.workspaceID, OrgID: i.orgID,
		SubjectID: i.subjectID, SeatReleased: i.seatConsumed,
		Reason: reason, BouncedAt: at,
	})
	return nil
}

// mustBePending is the one guard every settlement shares.
//
// It distinguishes "no such invitation" from "already settled" for the caller's
// benefit, because the API layer maps them to different answers: an unknown id
// is NOT_FOUND and a settled one is a CONFLICT the caller can act on.
func (i *Invitation) mustBePending() error {
	if !i.Exists() {
		return fmt.Errorf("workspace: no such invitation")
	}
	if !i.Pending() {
		return fmt.Errorf("workspace: invitation %s is %s", i.invitationID, i.status)
	}
	return nil
}
