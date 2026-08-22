package domain_test

import (
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

const (
	invID   = "inv_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	invWS   = "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	invOrg  = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	invSub  = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAB"
	inviter = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAA"
	invIdx  = "idx_deadbeef"
)

var (
	issuedAt = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)
	expiry   = issuedAt.Add(7 * 24 * time.Hour)
)

// issued returns a pending invitation, rebuilt from its own event so the test
// starts from a state the system can actually produce.
func issued(t *testing.T, seat bool) *domain.Invitation {
	t.Helper()
	inv := domain.NewInvitation()
	if err := inv.Issue(invID, invWS, invOrg, invSub, invIdx, inviter,
		contract.RoleMember, seat, expiry, issuedAt); err != nil {
		t.Fatalf("issuing: %v", err)
	}
	inv.ClearUncommitted()
	return inv
}

// ---------------------------------------------------------------------------
// the lifecycle, in full
// ---------------------------------------------------------------------------

// EVERY TRANSITION, LEGAL AND ILLEGAL.
//
// The table is data precisely so this can enumerate it. A switch statement
// cannot be enumerated, so the illegal half would go untested — and the illegal
// half is where the money is: a settled invitation that can be re-settled
// releases its seat twice, and the pool grows by one every time it happens.
func TestTheInvitationLifecycle(t *testing.T) {
	legal := map[domain.InvitationStatus]map[domain.InvitationStatus]bool{
		domain.InvitationUnknown: {domain.InvitationPending: true},
		domain.InvitationPending: {
			domain.InvitationAccepted:      true,
			domain.InvitationRevoked:       true,
			domain.InvitationExpired:       true,
			domain.InvitationDeclined:      true,
			domain.InvitationUndeliverable: true,
		},
		// Every terminal state is terminal. Nothing returns to Pending: a resend
		// rotates the token of an invitation that is ALREADY pending, and
		// re-inviting after a settlement is a NEW invitation with a new id —
		// which is what makes "the old token stays dead" true by construction.
		domain.InvitationAccepted:      {},
		domain.InvitationRevoked:       {},
		domain.InvitationExpired:       {},
		domain.InvitationDeclined:      {},
		domain.InvitationUndeliverable: {},
	}

	all := domain.InvitationStatuses()
	if len(all) != len(legal) {
		t.Fatalf("InvitationStatuses lists %d statuses and this table covers %d; a status "+
			"missing from either side is one whose transitions nothing checks",
			len(all), len(legal))
	}

	for _, from := range all {
		want, ok := legal[from]
		if !ok {
			t.Fatalf("%s is not in the expectation table", from)
		}
		for _, to := range all {
			t.Run(from.String()+"->"+to.String(), func(t *testing.T) {
				got := from.CanTransitionTo(to)
				if got != want[to] {
					if got {
						t.Fatalf("%s -> %s is ALLOWED and must not be", from, to)
					}
					t.Fatalf("%s -> %s is refused and must be allowed", from, to)
				}
			})
		}
	}
}

// A SEAT IS HELD BY EXACTLY ONE STATE, and returned by exactly four.
//
// Accepted is the one that catches people. The seat still exists after
// acceptance — it belongs to the MEMBERSHIP now — so counting it here as well
// double-counts the person for as long as they stay, and releasing it hands back
// a seat the new member is holding.
func TestOnlyPendingHoldsASeat(t *testing.T) {
	for _, s := range domain.InvitationStatuses() {
		t.Run(s.String(), func(t *testing.T) {
			wantHolds := s == domain.InvitationPending
			if s.HoldsSeat() != wantHolds {
				t.Errorf("%s reports HoldsSeat=%v, want %v", s, s.HoldsSeat(), wantHolds)
			}

			wantReleases := s == domain.InvitationRevoked ||
				s == domain.InvitationExpired ||
				s == domain.InvitationDeclined ||
				s == domain.InvitationUndeliverable
			if s.ReleasesSeat() != wantReleases {
				t.Errorf("%s reports ReleasesSeat=%v, want %v — releasing on acceptance "+
					"hands back a seat the new member holds, and not releasing on the "+
					"others leaks one per invitation nobody took up",
					s, s.ReleasesSeat(), wantReleases)
			}
		})
	}
}

// A SETTLED INVITATION CANNOT BE SETTLED AGAIN.
//
// The double-release is the reason. Each of these commands records
// SeatReleased, and the projector that returns the seat acts on it — so a
// second settlement returns a second seat for one invitation, and the allowance
// grows silently.
func TestASettledInvitationRefusesEverything(t *testing.T) {
	settlements := map[string]func(*domain.Invitation) error{
		"accept":  func(i *domain.Invitation) error { return i.Accept(invSub, issuedAt) },
		"revoke":  func(i *domain.Invitation) error { return i.Revoke(inviter, issuedAt) },
		"decline": func(i *domain.Invitation) error { return i.Decline(issuedAt) },
		"expire":  func(i *domain.Invitation) error { return i.Expire(expiry) },
		"bounce":  func(i *domain.Invitation) error { return i.MarkUndeliverable("mailbox_full", issuedAt) },
		"resend":  func(i *domain.Invitation) error { return i.RotateToken(expiry.Add(time.Hour), issuedAt) },
	}

	for firstName, first := range settlements {
		if firstName == "resend" {
			continue // a resend does not settle; it is the second half of each pair
		}
		for secondName, second := range settlements {
			t.Run(firstName+"_then_"+secondName, func(t *testing.T) {
				inv := issued(t, true)
				if err := first(inv); err != nil {
					t.Fatalf("the first %s failed, so this proves nothing: %v", firstName, err)
				}
				inv.ClearUncommitted()

				if err := second(inv); err == nil {
					t.Fatalf("%s succeeded on an invitation already %s; each settlement "+
						"records SeatReleased, so a second one returns a second seat for "+
						"one invitation", secondName, inv.Status())
				}
			})
		}
	}
}

// ---------------------------------------------------------------------------
// issue
// ---------------------------------------------------------------------------

// ISSUING REQUIRES EVERYTHING THE LIFECYCLE LATER DEPENDS ON.
func TestIssueRefusesAnIncompleteInvitation(t *testing.T) {
	type args struct {
		id, ws, org, subject, index, by string
		role                            contract.MemberRole
		expires                         time.Time
	}
	full := args{invID, invWS, invOrg, invSub, invIdx, inviter, contract.RoleMember, expiry}

	if err := domain.NewInvitation().Issue(full.id, full.ws, full.org, full.subject,
		full.index, full.by, full.role, true, full.expires, issuedAt); err != nil {
		t.Fatalf("precondition: a complete invitation was refused, so every case below "+
			"would pass for the wrong reason: %v", err)
	}

	tests := []struct {
		name string
		mut  func(*args)
		why  string
	}{
		{"no id", func(a *args) { a.id = "" }, "the stream is named by it"},
		{"no workspace", func(a *args) { a.ws = "" }, "there is nothing to join"},
		{
			"no organization", func(a *args) { a.org = "" },
			"a seat is per person per organization, so there is no pool to draw from",
		},
		{
			"no subject", func(a *args) { a.subject = "" },
			"the address lives in the vault under this pseudonym; without it the mail " +
				"cannot be addressed and the event would have to carry the address itself",
		},
		{
			"no blind index", func(a *args) { a.index = "" },
			"a second invitation to the same address could not be recognised as one, so " +
				"two seats would be taken for one person",
		},
		{
			"no inviter", func(a *args) { a.by = "" },
			"an inviter removed from the organization takes their outstanding invitations " +
				"with them, and that reactor needs to know whose",
		},
		{
			"no expiry", func(a *args) { a.expires = time.Time{} },
			"an invitation that never expires holds a seat forever",
		},
		{
			"expiry in the past", func(a *args) { a.expires = issuedAt.Add(-time.Hour) },
			"it could never be redeemed, and the seat would wait for a workflow that " +
				"fires immediately",
		},
		{
			"expiry at the instant of issue", func(a *args) { a.expires = issuedAt },
			"the same, with a window of zero",
		},
		{"unknown role", func(a *args) { a.role = "superuser" }, "there is no seat pool for it"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			a := full
			tt.mut(&a)
			inv := domain.NewInvitation()
			err := inv.Issue(a.id, a.ws, a.org, a.subject, a.index, a.by,
				a.role, true, a.expires, issuedAt)
			if err == nil {
				t.Fatalf("accepted it: %s", tt.why)
			}
			if len(inv.Uncommitted()) != 0 {
				t.Error("a refused issue still recorded an event")
			}
		})
	}
}

// AN INVITATION CANNOT BE ISSUED TWICE INTO ONE STREAM.
func TestIssuingTwiceIsRefused(t *testing.T) {
	inv := issued(t, true)
	if err := inv.Issue(invID, invWS, invOrg, invSub, invIdx, inviter,
		contract.RoleMember, true, expiry, issuedAt); err == nil {
		t.Fatal("a second issue landed on an invitation that already exists; a replay would " +
			"rebuild one aggregate that had been through the lifecycle twice")
	}
}

// ---------------------------------------------------------------------------
// accept
// ---------------------------------------------------------------------------

// A LINK CLICKED AFTER THE WINDOW IS REFUSED, even before the workflow has
// written the expiry.
//
// The workflow owns the seat release and may be seconds behind. The aggregate is
// the only place that cannot be bypassed, so it checks the deadline itself
// rather than trusting that Pending means live.
func TestAcceptingAfterExpiryIsRefused(t *testing.T) {
	inv := issued(t, true)

	if err := inv.Accept(invSub, expiry); err == nil {
		t.Fatal("an invitation was accepted at the instant it expired; the window is " +
			"half-open, and a link that arrives exactly on the deadline is late")
	}
	if err := inv.Accept(invSub, expiry.Add(time.Second)); err == nil {
		t.Fatal("an invitation was accepted after it expired. Pending only means no " +
			"settlement has been recorded — the workflow that records one may be seconds " +
			"behind, and that gap is exactly when a stale link is clicked")
	}
	if inv.Status() != domain.InvitationPending {
		t.Errorf("a refused acceptance changed the status to %s", inv.Status())
	}
}

// ACCEPTANCE RECORDS WHO ACTUALLY REDEEMED IT, which may not be who was invited.
//
// An address that later merged accounts follows the SURVIVING pseudonym
// (identity §7.5). Assuming the accepting subject equals the invited one would
// create the membership for an account that no longer exists.
func TestAcceptanceRecordsTheAcceptingAccount(t *testing.T) {
	const survivor = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAZ"
	inv := issued(t, true)

	if err := inv.Accept(survivor, issuedAt.Add(time.Hour)); err != nil {
		t.Fatalf("accepting: %v", err)
	}

	events := inv.Uncommitted()
	if len(events) != 1 {
		t.Fatalf("recorded %d events, want 1", len(events))
	}
	accepted, ok := events[0].(*contract.InvitationAccepted)
	if !ok {
		t.Fatalf("recorded %T, want InvitationAccepted", events[0])
	}
	if accepted.AcceptedBy != survivor {
		t.Errorf("recorded AcceptedBy=%s, want %s", accepted.AcceptedBy, survivor)
	}
	if accepted.SubjectID != invSub {
		t.Errorf("recorded SubjectID=%s, want the INVITED subject %s; the invitation was "+
			"issued to that address and the vault entry hangs off it",
			accepted.SubjectID, invSub)
	}
	if accepted.Role != contract.RoleMember {
		t.Errorf("recorded role %q; the role comes from the invitation, not from the "+
			"acceptance, or an invitee could choose their own", accepted.Role)
	}
}

// Acceptance needs an accepting account.
func TestAcceptingWithNoSubjectIsRefused(t *testing.T) {
	if err := issued(t, true).Accept("", issuedAt); err == nil {
		t.Fatal("an invitation was accepted by nobody, so the membership would be created " +
			"for the empty subject")
	}
}

// ---------------------------------------------------------------------------
// settlement records the seat it is giving back
// ---------------------------------------------------------------------------

// EVERY SETTLEMENT RECORDS THE SEAT IT RETURNS, from what ISSUE recorded.
//
// Not recomputed from present state: "was this invitation holding a seat" is a
// question about the past, and present state answers it wrongly the moment two
// invitations for one person are settled out of order.
func TestSettlementReleasesOnlyASeatThatWasTaken(t *testing.T) {
	for _, seatTaken := range []bool{true, false} {
		for name, settle := range map[string]func(*domain.Invitation) error{
			"revoke":  func(i *domain.Invitation) error { return i.Revoke(inviter, issuedAt) },
			"decline": func(i *domain.Invitation) error { return i.Decline(issuedAt) },
			"expire":  func(i *domain.Invitation) error { return i.Expire(expiry) },
			"bounce": func(i *domain.Invitation) error {
				return i.MarkUndeliverable("hard_bounce", issuedAt)
			},
		} {
			t.Run(name, func(t *testing.T) {
				inv := issued(t, seatTaken)
				if err := settle(inv); err != nil {
					t.Fatalf("%s: %v", name, err)
				}
				events := inv.Uncommitted()
				if len(events) != 1 {
					t.Fatalf("recorded %d events, want 1", len(events))
				}

				var released bool
				switch e := events[0].(type) {
				case *contract.InvitationRevoked:
					released = e.SeatReleased
				case *contract.InvitationDeclined:
					released = e.SeatReleased
				case *contract.InvitationExpired:
					released = e.SeatReleased
				case *contract.InvitationUndeliverable:
					released = e.SeatReleased
				default:
					t.Fatalf("recorded %T", events[0])
				}

				if released != seatTaken {
					t.Errorf("%s recorded SeatReleased=%v for an invitation that took "+
						"seat=%v; releasing one that was never taken inflates the "+
						"allowance every time it happens, and failing to release one "+
						"that was leaks it", name, released, seatTaken)
				}
			})
		}
	}
}

// ACCEPTANCE RELEASES NOTHING, whatever the invitation took.
func TestAcceptanceNeverReleasesASeat(t *testing.T) {
	inv := issued(t, true)
	if err := inv.Accept(invSub, issuedAt.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if _, isRelease := inv.Uncommitted()[0].(*contract.InvitationRevoked); isRelease {
		t.Fatal("acceptance recorded a revocation")
	}
	if inv.Status().ReleasesSeat() {
		t.Fatal("the accepted state releases a seat; the person is now a member and is " +
			"holding it, so the pool would grow by one for everybody who joins")
	}
}

// ---------------------------------------------------------------------------
// expire
// ---------------------------------------------------------------------------

// EXPIRY REFUSES TO RUN EARLY.
//
// The workflow owns the timer, and a workflow that fires on a replay or a clock
// skew would release a seat and kill a live token for an invitation somebody is
// about to accept.
func TestExpiringEarlyIsRefused(t *testing.T) {
	inv := issued(t, true)
	if err := inv.Expire(expiry.Add(-time.Second)); err == nil {
		t.Fatal("an invitation expired a second before its deadline; a replayed workflow " +
			"or a skewed clock would kill a live token and return a held seat")
	}
	if err := inv.Expire(expiry); err != nil {
		t.Fatalf("an invitation did not expire AT its deadline: %v", err)
	}
}

// ---------------------------------------------------------------------------
// resend
// ---------------------------------------------------------------------------

// A RESEND EXTENDS THE WINDOW AND NEVER SHORTENS IT.
func TestResendExtendsTheWindow(t *testing.T) {
	inv := issued(t, true)
	later := expiry.Add(24 * time.Hour)

	if err := inv.RotateToken(later, issuedAt.Add(time.Hour)); err != nil {
		t.Fatalf("resending: %v", err)
	}
	if inv.ExpiresAt() != later {
		t.Errorf("the window is %s after a resend, want %s; a link that arrived after the "+
			"original window closed is useless", inv.ExpiresAt(), later)
	}

	inv.ClearUncommitted()
	if err := inv.RotateToken(later.Add(-time.Hour), issuedAt.Add(2*time.Hour)); err == nil {
		t.Fatal("a resend SHORTENED the window; that is a support request nobody can " +
			"explain, and it can only come from computing the new expiry from the wrong base")
	}
}

// A resend cannot produce an already-dead token.
func TestResendRefusesAnExpiryInThePast(t *testing.T) {
	inv := issued(t, true)
	if err := inv.RotateToken(issuedAt.Add(-time.Hour), issuedAt); err == nil {
		t.Fatal("a resend minted a token that had already expired")
	}
}

// ---------------------------------------------------------------------------
// bounce
// ---------------------------------------------------------------------------

// A BOUNCE REASON IS REQUIRED AND BOUNDED.
//
// Required, because an inviter who is not told why will resend forever. Bounded,
// because a provider's raw bounce message routinely quotes the recipient's
// address back — and an unbounded field is exactly how personal data reaches the
// event log (ADR-002).
func TestABounceCarriesAClassificationAndNotAMessage(t *testing.T) {
	if err := issued(t, true).MarkUndeliverable("", issuedAt); err == nil {
		t.Error("a bounce with no reason was accepted; the inviter is told nothing and " +
			"will resend forever")
	}

	raw := "550 5.1.1 <alice@example.com>: Recipient address rejected: User unknown in " +
		"local recipient table"
	if len(raw) <= domain.MaxBounceReasonLen {
		t.Fatalf("precondition: the sample provider message is %d bytes, which is within "+
			"the bound, so this proves nothing", len(raw))
	}
	if err := issued(t, true).MarkUndeliverable(raw, issuedAt); err == nil {
		t.Error("a provider's raw bounce message was accepted into an event; it quotes the " +
			"recipient's address, which is personal data (ADR-002)")
	}
	if err := issued(t, true).MarkUndeliverable("hard_bounce", issuedAt); err != nil {
		t.Errorf("a classification was refused: %v", err)
	}
}

// ---------------------------------------------------------------------------
// replay
// ---------------------------------------------------------------------------

// THE AGGREGATE REBUILDS FROM ITS OWN EVENTS.
//
// Every field a later command reads has to survive a replay, and the one that
// bites is seatConsumed: a rebuild that lost it would settle every invitation as
// though it had never taken a seat, and the allowance would shrink by one for
// every invitation ever issued.
func TestAnInvitationRebuildsFromItsLog(t *testing.T) {
	later := expiry.Add(24 * time.Hour)
	events := []eventsourcing.Event{
		&contract.InvitationIssued{
			InvitationID: invID, WorkspaceID: invWS, OrgID: invOrg, SubjectID: invSub,
			EmailIndex: invIdx, InvitedBy: inviter, Role: contract.RoleGuest,
			SeatConsumed: true, ExpiresAt: expiry, IssuedAt: issuedAt,
		},
		&contract.InvitationTokenRotated{
			InvitationID: invID, WorkspaceID: invWS, OrgID: invOrg, SubjectID: invSub,
			ExpiresAt: later, RotatedAt: issuedAt.Add(time.Hour),
		},
	}

	inv := domain.NewInvitation()
	for _, e := range events {
		inv.Apply(e)
	}

	switch {
	case inv.InvitationID() != invID:
		t.Errorf("id is %q", inv.InvitationID())
	case inv.WorkspaceID() != invWS:
		t.Errorf("workspace is %q", inv.WorkspaceID())
	case inv.OrgID() != invOrg:
		t.Errorf("organization is %q", inv.OrgID())
	case inv.SubjectID() != invSub:
		t.Errorf("subject is %q", inv.SubjectID())
	case inv.EmailIndex() != invIdx:
		t.Errorf("blind index is %q", inv.EmailIndex())
	case inv.InvitedBy() != inviter:
		t.Errorf("inviter is %q", inv.InvitedBy())
	case inv.Role() != contract.RoleGuest:
		t.Errorf("role is %q; a rebuild that lost it would create the membership with the "+
			"wrong permissions and draw on the wrong seat pool", inv.Role())
	case !inv.SeatConsumed():
		t.Error("seatConsumed was lost in the replay; every settlement would then report " +
			"releasing nothing, and the allowance shrinks by one per invitation ever issued")
	case inv.ExpiresAt() != later:
		t.Errorf("the window is %s, want the ROTATED one %s", inv.ExpiresAt(), later)
	case inv.Status() != domain.InvitationPending:
		t.Errorf("status is %s", inv.Status())
	}
}

// AN UNLOADED INVITATION GRANTS NOTHING.
//
// The zero value must not be redeemable. This is the same fail-closed property
// authz.Decision's zero value has: a forgotten load, a mistyped id and an empty
// stream all have to refuse.
func TestTheZeroInvitationIsUnusable(t *testing.T) {
	inv := domain.NewInvitation()

	if inv.Exists() || inv.Pending() {
		t.Fatal("a never-loaded invitation reports itself as usable")
	}
	if inv.Status().HoldsSeat() || inv.Status().ReleasesSeat() {
		t.Error("the zero status touches the seat pool")
	}

	for name, cmd := range map[string]func() error{
		"accept":  func() error { return inv.Accept(invSub, issuedAt) },
		"revoke":  func() error { return inv.Revoke(inviter, issuedAt) },
		"decline": func() error { return inv.Decline(issuedAt) },
		"expire":  func() error { return inv.Expire(expiry) },
		"bounce":  func() error { return inv.MarkUndeliverable("x", issuedAt) },
		"resend":  func() error { return inv.RotateToken(expiry, issuedAt) },
	} {
		t.Run(name, func(t *testing.T) {
			err := cmd()
			if err == nil {
				t.Fatal("succeeded on an invitation that does not exist")
			}
			if !strings.Contains(err.Error(), "no such invitation") {
				t.Errorf("refused with %q; a mistyped id should read as not found rather "+
					"than as a state problem", err)
			}
		})
	}
}
