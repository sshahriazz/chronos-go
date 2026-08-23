package reactor

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// stubPurposeIssuer answers with a distinct token per call and records which
// PURPOSE was asked for — which is one of the properties under test.
type stubPurposeIssuer struct {
	purposes []app.TokenPurpose
	err      error
}

func (s *stubPurposeIssuer) IssueFor(
	_ context.Context, purpose app.TokenPurpose, _ string,
) (Verification, error) {
	s.purposes = append(s.purposes, purpose)
	if s.err != nil {
		return Verification{}, s.err
	}
	return Verification{
		Plaintext:   fmt.Sprintf("token-%d", len(s.purposes)),
		ExpiresAt:   testNow.Add(24 * time.Hour),
		TTL:         24 * time.Hour,
		Fingerprint: fmt.Sprintf("fpr%d", len(s.purposes)),
	}, nil
}

func changeEnvelope(t *testing.T, e eventsourcing.Event) eventsourcing.Envelope {
	t.Helper()
	payload, err := identityCodec().Marshal(e)
	if err != nil {
		t.Fatalf("encoding %s: %v", e.EventType(), err)
	}
	return eventsourcing.Envelope{
		ID:      ids.MustParse[ids.Event](testEventID),
		Type:    e.EventType(),
		Stream:  "identity-usr_1",
		Payload: payload,
		Meta:    eventsourcing.Metadata{OccurredAt: testNow},
	}
}

func newChangeMail(t *testing.T) (*EmailChangeMail, *stubPurposeIssuer, *recordingDispatcher) {
	t.Helper()
	issuer := &stubPurposeIssuer{}
	dispatch := &recordingDispatcher{}
	r, err := NewEmailChangeMail(issuer, identityCodec(), dispatch)
	if err != nil {
		t.Fatalf("NewEmailChangeMail: %v", err)
	}
	return r, issuer, dispatch
}

func sentWithTemplate(sent []notify.Notification, template string) (notify.Notification, bool) {
	for _, n := range sent {
		if n.Template == template {
			return n, true
		}
	}
	return notify.Notification{}, false
}

// THE REVERT LINK GOES TO THE PREVIOUS ADDRESS.
//
// # This is the single most dangerous line in the flow
//
// The dispatcher resolves the recipient from the vault at SEND time and
// overwrites Recipient.Address with what it finds. By the time this notification
// is delivered the vault holds the NEW address — which, in the case the revert
// window exists for, is the attacker's. So AddressPrimary here would deliver
// "your address was changed, click here to undo it", with a live single-use
// credential attached, to the party the undo is aimed at.
//
// Nothing else in the system catches that. The mail sends, the dispatcher
// reports success, the metric goes up, and the person whose account was taken
// never hears anything.
func TestTheRevertLinkGoesToThePreviousAddress(t *testing.T) {
	r, _, dispatch := newChangeMail(t)

	if err := r.React(context.Background(), changeEnvelope(t, &contract.EmailChanged{
		SubjectID:       testSubject,
		FromIndex:       "idx_old",
		ToIndex:         "idx_new",
		RevertibleUntil: testNow.Add(72 * time.Hour),
		ChangedAt:       testNow,
	})); err != nil {
		t.Fatalf("React: %v", err)
	}

	n, ok := sentWithTemplate(dispatch.sent, ChangeRevertTemplate)
	if !ok {
		t.Fatalf("a completed change dispatched %d notifications and none was the revert "+
			"link. An account moved by somebody else can never be recovered",
			len(dispatch.sent))
	}
	if n.Address != notify.AddressPrevious {
		t.Fatalf("the revert link resolves the %s address. The dispatcher reads the "+
			"vault at send time and it now holds the address the account was moved TO — "+
			"so this mails the undo link, with its live token, to whoever performed the "+
			"change", n.Address)
	}
	if n.Class != notify.Security {
		t.Errorf("the revert link is class %v; a preference could switch off the message "+
			"that says an account was taken", n.Class)
	}
	if n.Data["Token"] == nil || n.Data["Token"] == "" {
		t.Error("the revert mail carries no token, so its link redeems nothing")
	}
}

// THE PROOF LINK GOES TO THE PENDING ADDRESS, AND THE WARNING TO THE CURRENT ONE.
//
// Two messages, two different addresses, one event. Sending the proof link to
// the primary would mail the proof of a new address to the old one, which proves
// nothing and hands a live change token to whoever already reads that mailbox.
// Sending the warning to the pending address would warn the person doing the
// changing.
func TestARequestMailsTheLinkAndTheWarningToDifferentAddresses(t *testing.T) {
	r, issuer, dispatch := newChangeMail(t)

	if err := r.React(context.Background(), changeEnvelope(t, &contract.EmailChangeRequested{
		SubjectID:   testSubject,
		FromIndex:   "idx_old",
		ToIndex:     "idx_new",
		ExpiresAt:   testNow.Add(24 * time.Hour),
		RequestedAt: testNow,
	})); err != nil {
		t.Fatalf("React: %v", err)
	}

	if len(dispatch.sent) != 2 {
		t.Fatalf("a request dispatched %d notifications, want 2 — the proof link and "+
			"the warning", len(dispatch.sent))
	}

	link, ok := sentWithTemplate(dispatch.sent, ChangeConfirmTemplate)
	if !ok {
		t.Fatal("no proof link was sent, so no change can ever complete")
	}
	if link.Address != notify.AddressPending {
		t.Fatalf("the proof link resolves the %s address; it proves the NEW address, so "+
			"sending it to the old one proves nothing and hands a live change token to "+
			"whoever already reads that mailbox", link.Address)
	}

	warning, ok := sentWithTemplate(dispatch.sent, ChangeNoticeTemplate)
	if !ok {
		t.Fatal("no warning was sent to the address the account uses today. An attacker " +
			"holding a session moves the account in silence, and the person it belongs " +
			"to first learns when they can no longer sign in — which identity.md §12 " +
			"names as the reason this flow needs a warning at all")
	}
	if warning.Address != notify.AddressPrimary {
		t.Fatalf("the warning resolves the %s address, which is the address being moved "+
			"TO — so the person doing the changing is warned and the account holder is "+
			"not", warning.Address)
	}
	if warning.Class != notify.Security {
		t.Errorf("the warning is class %v; a person who muted account mail has not "+
			"consented to being kept unaware that somebody is moving their address",
			warning.Class)
	}

	// THE WARNING CARRIES NO CREDENTIAL. It goes to a mailbox an attacker may
	// already be reading, so a token in it would make the warning itself the
	// attack.
	if _, carries := warning.Data["Token"]; carries {
		t.Fatalf("the warning carries a token. It is mailed to the address the change is " +
			"moving AWAY from — exactly the mailbox that may already be compromised — " +
			"so the credential in it hands the attacker the thing they need")
	}

	if len(issuer.purposes) != 1 || issuer.purposes[0] != app.PurposeEmailChange {
		t.Errorf("the reactor minted %v; a token of the wrong purpose is refused at "+
			"redemption and every link is dead on arrival", issuer.purposes)
	}
}

// THE TWO EVENTS MINT DIFFERENT PURPOSES.
//
// The purpose is mixed into the digest, so a change token presented to the
// revert endpoint hashes to nothing it can find. Minting one purpose for both
// would make one of the two links permanently unredeemable.
func TestEachEventMintsItsOwnPurpose(t *testing.T) {
	r, issuer, _ := newChangeMail(t)
	ctx := context.Background()

	if err := r.React(ctx, changeEnvelope(t, &contract.EmailChangeRequested{
		SubjectID: testSubject, FromIndex: "idx_old", ToIndex: "idx_new",
		ExpiresAt: testNow.Add(time.Hour), RequestedAt: testNow,
	})); err != nil {
		t.Fatal(err)
	}
	if err := r.React(ctx, changeEnvelope(t, &contract.EmailChanged{
		SubjectID: testSubject, FromIndex: "idx_old", ToIndex: "idx_new",
		RevertibleUntil: testNow.Add(72 * time.Hour), ChangedAt: testNow,
	})); err != nil {
		t.Fatal(err)
	}

	want := []app.TokenPurpose{app.PurposeEmailChange, app.PurposeEmailChangeRevert}
	if len(issuer.purposes) != 2 ||
		issuer.purposes[0] != want[0] || issuer.purposes[1] != want[1] {
		t.Fatalf("the reactor minted %v, want %v. A link minted under the wrong purpose "+
			"digests to a value its own endpoint cannot find, so it is dead on arrival "+
			"with nothing to say so", issuer.purposes, want)
	}
}

// A FAILED WARNING IS NOT ACKED AWAY.
//
// The link is sent first because it is what the holder is waiting for; the
// warning is what reaches somebody whose session was hijacked. If a failure of
// the second were swallowed, an attacker's change would be silent to the victim
// for exactly the deliveries that failed — and nothing would retry.
func TestAFailedDeliveryIsReturnedSoTheEventIsRedelivered(t *testing.T) {
	issuer := &stubPurposeIssuer{}
	dispatch := &recordingDispatcher{err: fmt.Errorf("smtp is down")}
	r, err := NewEmailChangeMail(issuer, identityCodec(), dispatch)
	if err != nil {
		t.Fatal(err)
	}

	if err := r.React(context.Background(), changeEnvelope(t, &contract.EmailChangeRequested{
		SubjectID: testSubject, FromIndex: "idx_old", ToIndex: "idx_new",
		ExpiresAt: testNow.Add(time.Hour), RequestedAt: testNow,
	})); err == nil {
		t.Fatal("a failed delivery was acked. The event is never redelivered, so the " +
			"link and the warning are both lost with no error anywhere")
	}
}

// THE FILTER COVERS BOTH EVENTS.
//
// Asserted separately from the handlers because it fails INDEPENDENTLY of them:
// every handler above can be correct and never run, and a reactor that matches
// nothing is indistinguishable from a quiet system.
func TestTheChangeFilterCoversBothEvents(t *testing.T) {
	r, _, _ := newChangeMail(t)
	got := r.Filter().EventTypePrefixes

	for _, want := range []string{
		"identity.EmailChangeRequested.v1",
		"identity.EmailChanged.v1",
	} {
		var found bool
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the filter is %v and omits %q, so that event is delivered to "+
				"nothing", got, want)
		}
	}
}

// AN EVENT THE FILTER SHOULD NOT HAVE DELIVERED MINTS NOTHING.
//
// Reacting to whatever arrives would turn a filter change into an email — and
// into a token.
func TestAnUnrelatedEventMintsNothing(t *testing.T) {
	r, issuer, dispatch := newChangeMail(t)

	if err := r.React(context.Background(), eventsourcing.Envelope{
		ID: ids.MustParse[ids.Event](testEventID), Type: "identity.EmailVerified.v1",
	}); err != nil {
		t.Fatalf("an unrelated event was treated as a failure: %v", err)
	}
	if len(issuer.purposes) != 0 || len(dispatch.sent) != 0 {
		t.Errorf("an unrelated event minted %v and sent %d notifications",
			issuer.purposes, len(dispatch.sent))
	}
}

// A CHANGE WITH NO PREVIOUS ADDRESS SENDS NOTHING AND DOES NOT PARK.
//
// There is nobody to warn and no revert to offer. Parking would be a reactor
// that stops on a SHAPE of history rather than on a fault.
func TestAChangeFromNoAddressIsSilentAndNotPoison(t *testing.T) {
	r, issuer, dispatch := newChangeMail(t)

	if err := r.React(context.Background(), changeEnvelope(t, &contract.EmailChanged{
		SubjectID: testSubject, FromIndex: "", ToIndex: "idx_new",
		RevertibleUntil: testNow.Add(72 * time.Hour), ChangedAt: testNow,
	})); err != nil {
		t.Fatalf("a change with no previous address parked the group: %v", err)
	}
	if len(dispatch.sent) != 0 || len(issuer.purposes) != 0 {
		t.Errorf("a change from no address still minted %v and sent %d notifications",
			issuer.purposes, len(dispatch.sent))
	}
}
