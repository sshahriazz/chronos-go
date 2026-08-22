package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// InviterDepartures revokes what somebody left outstanding when they leave an
// organization.
//
// workspace.md §5: "Inviter is removed from the org — invitations they issued
// are revoked." The authorisation to join came from somebody who is no longer
// there, and an invitation nobody can vouch for should not still be redeemable
// by whoever holds the mail.
//
// # It is deliberately not "invitations they issued are invalid"
//
// An invitation stands when the inviter merely loses PERMISSION — it was
// authorised when it was issued, and workspace.md §5 says so explicitly. This is
// the narrower case: they are gone from the organization entirely, so there is
// nobody left who could answer for the invitation at all.
type InviterDepartures struct {
	outstanding OutstandingInvitations
	settlements *Settlements
	log         *slog.Logger
}

// DepartureResult is what one departure settled.
type DepartureResult struct {
	// Found is how many outstanding invitations the departing inviter had.
	Found int

	// Revoked is how many this call actually withdrew.
	Revoked int

	// Stale is how many were settled between the list and the write. Not an
	// error: the projection lags, and somebody accepting an invitation while its
	// inviter is being removed is a race the design tolerates rather than
	// prevents.
	Stale int
}

func NewInviterDepartures(
	outstanding OutstandingInvitations, settlements *Settlements, log *slog.Logger,
) (*InviterDepartures, error) {
	switch {
	case outstanding == nil:
		return nil, fmt.Errorf("workspace: a work list is required; without one a departing " +
			"inviter's invitations stay live and redeemable by whoever holds the mail")
	case settlements == nil:
		return nil, fmt.Errorf("workspace: settlements are required; without them the " +
			"invitations would be found and left alone")
	}
	if log == nil {
		log = slog.Default()
	}
	return &InviterDepartures{outstanding: outstanding, settlements: settlements, log: log}, nil
}

// Depart revokes every invitation this person left outstanding here.
//
// # A failure on one is returned, unlike the sweep
//
// The sweep counts failures and carries on, because every row it skips is a seat
// that comes back on the next pass. Here a skipped row is a LIVE CREDENTIAL for
// an invitation nobody can vouch for, and there is no next pass — this runs once
// per departure. Returning makes the reactor redeliver, which is the retry.
func (d *InviterDepartures) Depart(
	ctx context.Context, orgID, subjectID string,
) (DepartureResult, error) {
	if orgID == "" || subjectID == "" {
		return DepartureResult{}, errs.Internalf("a departure needs an organization and a " +
			"subject")
	}

	pending, err := d.outstanding.ListPendingBy(ctx, orgID, subjectID)
	if err != nil {
		return DepartureResult{}, errs.Internalf("listing what %s left outstanding", subjectID).
			Wrap(err)
	}

	result := DepartureResult{Found: len(pending)}
	for _, p := range pending {
		// RevokedBy is EMPTY, and the event's own comment says why: this
		// revocation is a consequence rather than a decision. Nobody issued the
		// command, and recording the departing inviter as the revoker would read
		// as them withdrawing their own invitations on the way out.
		_, err := d.settlements.settle(ctx, orgID, p.WorkspaceID, p.InvitationID,
			"inviter-departed:"+subjectID+":"+p.InvitationID,
			func(inv *domain.Invitation, at time.Time) error { return inv.Revoke("", at) })
		switch {
		case err == nil:
			result.Revoked++
		case errs.ReasonOf(err) == errs.Conflict, errs.ReasonOf(err) == errs.NotFound:
			// Settled between the list and the write.
			result.Stale++
		default:
			return result, err
		}
	}

	if result.Revoked > 0 {
		d.log.InfoContext(ctx, "revoked the invitations a departing inviter left outstanding",
			"org", orgID, "inviter", subjectID,
			"revoked", result.Revoked, "stale", result.Stale)
	}
	return result, nil
}
