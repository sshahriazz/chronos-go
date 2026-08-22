package app_test

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/workspace/app"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
)

// fakeOutstandingList is the departure's work list.
type fakeOutstandingList struct {
	rows []app.PendingInvitation
	err  error

	// asked records what it was asked about, which is how "scoped to the right
	// organization" is asserted.
	asked []string
}

func (f *fakeOutstandingList) ListPendingBy(
	_ context.Context, orgID, subjectID string,
) ([]app.PendingInvitation, error) {
	f.asked = append(f.asked, orgID+"/"+subjectID)
	if f.err != nil {
		return nil, f.err
	}
	return f.rows, nil
}

func departures(
	t *testing.T, list app.OutstandingInvitations, s *app.Settlements,
) *app.InviterDepartures {
	t.Helper()
	d, err := app.NewInviterDepartures(list, s, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err != nil {
		t.Fatal(err)
	}
	return d
}

// A DEPARTING INVITER'S OUTSTANDING INVITATIONS ARE REVOKED.
//
// workspace.md §5. The authorisation to join came from somebody who is no longer
// there, and an invitation nobody can vouch for should not still be redeemable
// by whoever holds the mail. The seat it holds comes back with it.
func TestADepartingInviterLeavesNoLiveInvitations(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}

	list := &fakeOutstandingList{rows: []app.PendingInvitation{
		{InvitationID: issued.InvitationID, WorkspaceID: h.workspaceID},
	}}
	result, err := departures(t, list, h.settlements).
		Depart(context.Background(), testOrg, founder)
	if err != nil {
		t.Fatalf("departing: %v", err)
	}

	if result.Found != 1 || result.Revoked != 1 {
		t.Fatalf("found %d and revoked %d, want 1 and 1", result.Found, result.Revoked)
	}
	if inv := h.loadInvitation(t, issued.InvitationID); inv.Status() != domain.InvitationRevoked {
		t.Errorf("the invitation is %s, want revoked", inv.Status())
	}
	// The LINK is dead, which is the half that matters more than the seat: an
	// invitation nobody can vouch for must not be redeemable.
	if _, err := h.accept(issued.Token, acceptor); err == nil {
		t.Fatal("an invitation issued by somebody who has left the organization was still " +
			"accepted")
	}
	if len(h.reserver.released) != 1 {
		t.Errorf("released %v, want the seat back", h.reserver.released)
	}
}

// IT IS SCOPED TO THE ORGANIZATION THEY LEFT.
//
// A consultant who administers two tenants keeps what they issued in the one
// they are still in.
func TestADepartureIsScopedToOneOrganization(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	list := &fakeOutstandingList{}

	if _, err := departures(t, list, h.settlements).
		Depart(context.Background(), testOrg, founder); err != nil {
		t.Fatal(err)
	}
	if len(list.asked) != 1 || list.asked[0] != testOrg+"/"+founder {
		t.Fatalf("asked about %v; a departure that ignored the organization would revoke "+
			"invitations in tenants the person is still part of", list.asked)
	}
}

// AN INVITATION SETTLED IN THE MEANTIME IS STALE, NOT A FAILURE.
//
// The projection lags. Somebody accepting while their inviter is being removed
// is a race the design tolerates rather than prevents, and counting it as an
// error would park the departure and leave the REST of their invitations live.
func TestASettledInvitationIsStaleDuringADeparture(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	issued, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.accept(issued.Token, acceptor); err != nil {
		t.Fatal(err)
	}

	list := &fakeOutstandingList{rows: []app.PendingInvitation{
		{InvitationID: issued.InvitationID, WorkspaceID: h.workspaceID},
	}}
	result, err := departures(t, list, h.settlements).
		Depart(context.Background(), testOrg, founder)
	if err != nil {
		t.Fatalf("an invitation accepted during the departure failed it: %v", err)
	}
	if result.Stale != 1 || result.Revoked != 0 {
		t.Errorf("stale %d and revoked %d, want 1 and 0", result.Stale, result.Revoked)
	}
}

// A FAILING WORK LIST FAILS THE DEPARTURE.
func TestAFailingListFailsTheDeparture(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	list := &fakeOutstandingList{err: errors.New("postgres: down")}

	if _, err := departures(t, list, h.settlements).
		Depart(context.Background(), testOrg, founder); err == nil {
		t.Fatal("a departure that could not read the work list reported success; every " +
			"invitation the person left stays live and nothing will look again")
	}
}

// EVERY DEPENDENCY IS REQUIRED.
func TestDeparturesRefuseAnIncompleteWiring(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	if _, err := app.NewInviterDepartures(&fakeOutstandingList{}, h.settlements, nil); err != nil {
		t.Fatalf("precondition: a complete wiring was refused: %v", err)
	}
	if _, err := app.NewInviterDepartures(nil, h.settlements, nil); err == nil {
		t.Error("constructed with no work list")
	}
	if _, err := app.NewInviterDepartures(&fakeOutstandingList{}, nil, nil); err == nil {
		t.Error("constructed with no settlements")
	}
}

// ---------------------------------------------------------------------------
// supersession
// ---------------------------------------------------------------------------

// A SECOND INVITATION TO ONE ADDRESS SUPERSEDES THE FIRST.
//
// workspace.md §5: one seat, not two. And the OLD LINK dies — two live links to
// one address means the person can accept the invitation nobody meant to send
// them, into the wrong workspace or with the wrong role.
func TestASecondInvitationSupersedesTheFirst(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})

	first, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	if !first.SeatConsumed {
		t.Fatal("precondition: the first invitation took no seat")
	}

	// The projection now reports it as outstanding, which is what the second
	// issue looks for.
	h.outstanding.pending = app.PendingInvitation{
		InvitationID: first.InvitationID, WorkspaceID: h.workspaceID,
	}
	h.outstanding.found = true

	second, err := h.issue(contract.RoleAdmin)
	if err != nil {
		t.Fatalf("the second invitation failed: %v", err)
	}

	if h.outstanding.lookups == 0 {
		t.Fatal("nothing looked for an outstanding invitation to that address, so the " +
			"second one took a second seat")
	}
	if inv := h.loadInvitation(t, first.InvitationID); inv.Status() != domain.InvitationRevoked {
		t.Errorf("the first invitation is %s, want revoked", inv.Status())
	}
	if _, err := h.accept(first.Token, acceptor); err == nil {
		t.Fatal("the FIRST link still works. Two live links to one address means the " +
			"person can accept the invitation nobody meant to send them")
	}
	if _, err := h.accept(second.Token, acceptor); err != nil {
		t.Fatalf("the second link does not work, so superseding destroyed the invitation "+
			"it was meant to replace: %v", err)
	}
}

// SUPERSESSION RETURNS THE FIRST SEAT.
//
// The net is one seat for one person, which is the whole rule. Without the
// release the organization pays twice for somebody who has not even replied
// once.
func TestSupersessionLeavesOneSeat(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})
	first, err := h.issue(contract.RoleMember)
	if err != nil {
		t.Fatal(err)
	}
	h.outstanding.pending = app.PendingInvitation{
		InvitationID: first.InvitationID, WorkspaceID: h.workspaceID,
	}
	h.outstanding.found = true

	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatal(err)
	}

	if len(h.reserver.released) != 1 {
		t.Fatalf("released %v; the superseded invitation's seat has to come back, or the "+
			"organization pays twice for one person", h.reserver.released)
	}
	if got := len(h.reserver.reserved) - len(h.reserver.released); got != 1 {
		t.Errorf("net seats held is %d, want 1", got)
	}
}

// NOTHING OUTSTANDING IS THE ORDINARY CASE.
func TestIssuingWithNothingOutstandingSupersedesNothing(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{})

	if _, err := h.issue(contract.RoleMember); err != nil {
		t.Fatal(err)
	}
	if h.outstanding.lookups != 1 {
		t.Errorf("looked %d times, want 1", h.outstanding.lookups)
	}
	if len(h.reserver.released) != 0 {
		t.Errorf("released %v with nothing to supersede", h.reserver.released)
	}
}

// A FAILING LOOKUP FAILS THE ISSUE.
//
// Carrying on would leave two live links and two seats for one person, which is
// the precise outcome the rule exists to prevent. Refusing is recoverable: the
// admin retries.
func TestAFailingSupersessionLookupFailsTheIssue(t *testing.T) {
	h := newInviteHarness(t, inviteOpts{outstandingErr: errors.New("postgres: down")})

	if _, err := h.issue(contract.RoleMember); err == nil {
		t.Fatal("an invitation was issued without checking for an outstanding one; two " +
			"live links and two seats for one person is exactly what supersession prevents")
	}
	if h.invitationStreams() != 0 {
		t.Error("an invitation was appended anyway")
	}
}
