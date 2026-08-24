package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

const (
	google = contract.Issuer("https://accounts.google.com")
	github = contract.Issuer("https://github.com")
)

// linked returns a verified account holding one link.
func linked(t *testing.T, auto bool) *domain.User {
	t.Helper()
	u := verified(t)
	if err := u.LinkFederatedIdentity(google, "sub-1",
		contract.VerificationVerified, auto, at); err != nil {
		t.Fatalf("link: %v", err)
	}
	u.ClearUncommitted()
	return u
}

// A LINK NEEDS BOTH HALVES OF THE IDENTITY.
//
// A `sub` is unique within an issuer and nowhere else, so a link keyed on the
// subject alone lets two providers' identifiers collide into one — silently,
// because neither provider can see the other's namespace.
func TestALinkNeedsAnIssuerAndASubject(t *testing.T) {
	for name, link := range map[string]func(*domain.User) error{
		"no issuer": func(u *domain.User) error {
			return u.LinkFederatedIdentity("", "sub-1", contract.VerificationVerified, false, at)
		},
		"no subject": func(u *domain.User) error {
			return u.LinkFederatedIdentity(google, "", contract.VerificationVerified, false, at)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := link(verified(t)); err == nil {
				t.Fatalf("a link with %s was accepted", name)
			}
		})
	}
}

// THE SAME PAIR LINKS ONCE.
//
// A retried callback must not fail, and must not record a second link that a
// later unlink would only half remove.
func TestLinkingTheSamePairTwiceRecordsOnce(t *testing.T) {
	u := verified(t)
	for range 2 {
		if err := u.LinkFederatedIdentity(google, "sub-1",
			contract.VerificationVerified, false, at); err != nil {
			t.Fatal(err)
		}
	}
	if got := recorded(u); len(got) != 1 {
		t.Fatalf("recorded %v for two identical links", got)
	}
	if u.FederatedLinks() != 1 {
		t.Fatalf("the account holds %d links", u.FederatedLinks())
	}
}

// TWO PROVIDERS WITH THE SAME SUBJECT ARE TWO LINKS.
//
// The collision the key exists to prevent, from the other side.
func TestTheSameSubjectAtTwoProvidersIsTwoLinks(t *testing.T) {
	u := verified(t)
	for _, issuer := range []contract.Issuer{google, github} {
		if err := u.LinkFederatedIdentity(issuer, "12345",
			contract.VerificationVerified, false, at); err != nil {
			t.Fatal(err)
		}
	}
	if u.FederatedLinks() != 2 {
		t.Fatalf("two providers sharing a subject collapsed into %d link(s); one "+
			"provider's identifier now signs in as another's", u.FederatedLinks())
	}
}

// §7: REMOVING THE LAST WAY IN IS REFUSED.
//
// A person who signed up with Google has no password by design — §7 calls that a
// first-class state — so removing their only link leaves them with nothing, and
// an endpoint that allowed it would be account loss dressed as a settings
// toggle.
func TestRemovingTheLastLinkFromAPasswordlessAccountIsRefused(t *testing.T) {
	u := linked(t, false)

	err := u.UnlinkFederatedIdentity(google, "sub-1", u.SubjectID(), at)
	if err == nil {
		t.Fatal("the only way into a passwordless account was removed; the holder is " +
			"locked out by a settings toggle")
	}
	if !u.HasFederatedLink(google, "sub-1") {
		t.Error("the refused removal deleted the link anyway")
	}
}

// AND ALLOWED WHEN SOMETHING ELSE CAN SIGN IN.
func TestRemovingALinkIsAllowedWhenAnotherMethodRemains(t *testing.T) {
	u := linked(t, false)
	if err := u.LinkFederatedIdentity(github, "99",
		contract.VerificationVerified, false, at); err != nil {
		t.Fatal(err)
	}
	u.ClearUncommitted()

	if err := u.UnlinkFederatedIdentity(google, "sub-1", u.SubjectID(), at); err != nil {
		t.Fatalf("unlink: %v", err)
	}
	if u.HasFederatedLink(google, "sub-1") {
		t.Error("the link survived its own removal")
	}
	if u.FederatedLinks() != 1 {
		t.Errorf("the account holds %d links, want 1", u.FederatedLinks())
	}
}

// UNLINKING SOMETHING THAT IS NOT LINKED IS NOT FOUND.
func TestUnlinkingAnAbsentLinkIsNotFound(t *testing.T) {
	if err := verified(t).UnlinkFederatedIdentity(google, "sub-1", "actor", at); err == nil {
		t.Fatal("an absent link was unlinked")
	}
}

// §4.4 — THE TROJAN IDENTIFIER.
//
// # The attack, in full
//
// An attacker attaches a provider identity they control to the victim's account
// and waits. The victim resets their password, believes they have taken the
// account back, and the attacker signs straight back in — because a reset
// changes a credential and leaves a link alone.
//
// This is the third of Sudhodanan & Paverd's variants and the last one this
// module had unreachable. Building federated linking is what makes it reachable,
// so it is closed in the same slice.
func TestARecoveryVoidsAnAutoLinkedIdentity(t *testing.T) {
	u := linked(t, true) // auto-linked: created on a provider's claim

	if err := u.VoidUnprovenFederatedLinks(at.Add(time.Hour)); err != nil {
		t.Fatalf("voiding: %v", err)
	}
	got := recorded(u)
	if len(got) != 1 || got[0] != "identity.FederatedIdentityUnlinked.v1" {
		t.Fatalf("a recovery recorded %v; the attacker's link survives and they sign "+
			"straight back into an account the victim believes they just secured", got)
	}
	if u.HasFederatedLink(google, "sub-1") {
		t.Fatal("the auto-linked identity survived the recovery")
	}
	ev := u.Uncommitted()[0].(*contract.FederatedIdentityUnlinked)
	if ev.Reason != contract.UnlinkPasswordReset {
		t.Errorf("the unlink reason is %q; an operator asking whether a recovery killed "+
			"this link cannot tell", ev.Reason)
	}
	if ev.ActorID != "" {
		t.Errorf("the void names actor %q; nobody chose it, a rule did", ev.ActorID)
	}
}

// AND LEAVES THE ONES THE HOLDER PROVED.
//
// §4.4 voids what the acting party did NOT prove. A link somebody created
// deliberately from an authenticated session was proven by them, and voiding it
// would sign people out of their own providers every time they forgot a
// password.
func TestARecoveryKeepsADeliberatelyLinkedIdentity(t *testing.T) {
	u := linked(t, false) // the holder linked it themselves

	if err := u.VoidUnprovenFederatedLinks(at.Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if got := recorded(u); len(got) != 0 {
		t.Fatalf("a recovery recorded %v for a link the holder proved; they are signed "+
			"out of their own provider for forgetting a password", got)
	}
	if !u.HasFederatedLink(google, "sub-1") {
		t.Fatal("a deliberately created link was voided by a recovery")
	}
}

// VOIDING RECORDS NOTHING WHEN THERE IS NOTHING TO VOID.
//
// The reset calls this on EVERY run. An unconditional event would put an unlink
// on the stream of every account that ever reset a password.
func TestVoidingWithNoLinksIsSilent(t *testing.T) {
	u := verified(t)
	if err := u.VoidUnprovenFederatedLinks(at); err != nil {
		t.Fatal(err)
	}
	if got := recorded(u); len(got) != 0 {
		t.Fatalf("voiding nothing recorded %v", got)
	}
}

// THE VOID IS DETERMINISTIC.
//
// Map order is randomised in Go, and a retried reset that recorded two events in
// two different orders would derive different event ids for the same command —
// which is a retry that appends a second set instead of collapsing.
func TestVoidingIsOrderedDeterministically(t *testing.T) {
	build := func() *domain.User {
		u := verified(t)
		for _, pair := range []struct {
			issuer  contract.Issuer
			subject string
		}{{github, "zzz"}, {google, "aaa"}, {google, "bbb"}} {
			if err := u.LinkFederatedIdentity(pair.issuer, pair.subject,
				contract.VerificationVerified, true, at); err != nil {
				t.Fatal(err)
			}
		}
		u.ClearUncommitted()
		return u
	}

	var first []string
	for run := range 8 {
		u := build()
		if err := u.VoidUnprovenFederatedLinks(at); err != nil {
			t.Fatal(err)
		}
		var order []string
		for _, e := range u.Uncommitted() {
			ev := e.(*contract.FederatedIdentityUnlinked)
			order = append(order, string(ev.Issuer)+"|"+ev.ProviderSubject)
		}
		if run == 0 {
			first = order
			continue
		}
		if len(order) != len(first) {
			t.Fatalf("run %d recorded %d events, run 0 recorded %d", run, len(order), len(first))
		}
		for i := range order {
			if order[i] != first[i] {
				t.Fatalf("run %d ordered links %v and run 0 ordered them %v; a retried "+
					"reset derives different event ids for the same command, so it "+
					"appends a second set instead of collapsing", run, order, first)
			}
		}
	}
}

// A SUSPENDED ACCOUNT LINKS NOTHING.
func TestASuspendedAccountCannotLink(t *testing.T) {
	u := verified(t)
	if err := u.Suspend("op_1", "abuse", at); err != nil {
		t.Fatal(err)
	}
	if err := u.LinkFederatedIdentity(google, "sub-1",
		contract.VerificationVerified, false, at); err == nil {
		t.Error("a suspended account gained a way to sign in")
	}
}

// VERIFICATION IS TRI-STATE, AND ITS ZERO VALUE GRANTS NOTHING.
//
// §7 rule 6: `verified`, `unverified`, or NOT ASSERTED — and the third is not
// the second. A build that forgets to set it must land on the answer that grants
// nothing, because the alternative is Entra's silence reading as a verified
// address, which is nOAuth.
func TestNotAssertedIsTheZeroValue(t *testing.T) {
	var zero contract.ProviderVerification
	if zero != contract.VerificationNotAsserted {
		t.Fatalf("the zero verification is %q; a forgotten field must mean 'the provider "+
			"did not say', never 'the provider said yes'", zero)
	}
	if contract.VerificationNotAsserted == contract.VerificationUnverified {
		t.Fatal("'not asserted' and 'unverified' are the same value; the difference " +
			"between a provider staying silent and a provider saying no is the " +
			"difference between refusing an auto-link and refusing to consider one")
	}
}
