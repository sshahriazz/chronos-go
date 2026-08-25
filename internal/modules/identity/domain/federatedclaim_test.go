package domain_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

func claim(t *testing.T) *domain.FederatedClaim {
	t.Helper()
	return eventsourcing.NewAggregate(domain.NewFederatedClaim)
}

// §7 RULE 4: ONE PROVIDER IDENTITY, AT MOST ONE ACCOUNT.
//
// The uniqueness this aggregate exists for. Two accounts linking one Google
// identity contend on the SAME STREAM, so one of them loses the append —
// checking a projection first cannot work, because it is behind the log by
// construction and under concurrency both reads say "free".
func TestOneProviderIdentityLinksToOneAccount(t *testing.T) {
	c := claim(t)
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_first", at); err != nil {
		t.Fatalf("first claim: %v", err)
	}
	c.ClearUncommitted()

	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_second", at); err == nil {
		t.Fatal("a second account claimed a provider identity the first already holds; " +
			"one Google login now signs into two accounts")
	}
	if c.SubjectID() != "subj_first" {
		t.Fatalf("the claim moved to %q", c.SubjectID())
	}
}

// AND THE REFUSAL DISCLOSES NOTHING.
//
// Telling a caller that a provider identity is already linked says that some
// account here is associated with that Google login — an account-existence
// oracle keyed on a third party, which is exactly what §7's other rules refuse
// to provide.
func TestTheRefusalDoesNotSayItIsAlreadyLinked(t *testing.T) {
	c := claim(t)
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_first", at); err != nil {
		t.Fatal(err)
	}
	err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_second", at)
	if err == nil {
		t.Fatal("the second claim succeeded")
	}
	for _, leak := range []string{"already", "linked to", "another account", "exists"} {
		if contains(err.Error(), leak) {
			t.Errorf("the refusal says %q (%q), which confirms that some account here "+
				"is associated with that provider login", leak, err)
		}
	}
}

// RE-CLAIMING BY THE SAME ACCOUNT IS SILENT.
//
// A retried callback must not fail, and must not record a second claim that a
// later release would only half remove.
func TestReclaimingByTheSameAccountRecordsNothing(t *testing.T) {
	c := claim(t)
	for range 2 {
		if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_1", at); err != nil {
			t.Fatal(err)
		}
	}
	if got := len(c.Uncommitted()); got != 1 {
		t.Fatalf("two identical claims recorded %d events", got)
	}
}

// RELEASING FREES IT FOR THE SAME PERSON TO LINK AGAIN.
//
// Without this a provider identity is held forever by an account that removed
// the link — or was erased — and the same person could never re-link.
func TestAReleasedIdentityCanBeClaimedAgain(t *testing.T) {
	c := claim(t)
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_1", at); err != nil {
		t.Fatal(err)
	}
	if err := c.Release("subj_1", "unlinked_by_holder", at); err != nil {
		t.Fatalf("release: %v", err)
	}
	if c.Held() {
		t.Fatal("the identity is still held after being released")
	}
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_2", at); err != nil {
		t.Fatalf("a released identity could not be claimed: %v", err)
	}
}

// ONE ACCOUNT CANNOT RELEASE ANOTHER'S CLAIM.
func TestReleasingAnotherAccountsClaimIsRefused(t *testing.T) {
	c := claim(t)
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_1", at); err != nil {
		t.Fatal(err)
	}
	if err := c.Release("subj_other", "unlinked_by_holder", at); err == nil {
		t.Fatal("one account released another's provider identity, freeing it to be " +
			"claimed by anybody")
	}
	if !c.Held() {
		t.Error("the refused release freed the claim anyway")
	}
}

// A RELEASE MUST STATE A KNOWN REASON.
func TestAReleaseNeedsAKnownReason(t *testing.T) {
	c := claim(t)
	if err := c.Claim(domain.IssuerGoogle, "sub-1", "subj_1", at); err != nil {
		t.Fatal(err)
	}
	if err := c.Release("subj_1", "because", at); err == nil {
		t.Fatal("an unnamed reason was accepted; the log entry cannot be interpreted later")
	}
}

// BOTH HALVES OF THE IDENTITY ARE REQUIRED.
func TestAClaimNeedsEveryPart(t *testing.T) {
	for name, f := range map[string]func(*domain.FederatedClaim) error{
		"no issuer":  func(c *domain.FederatedClaim) error { return c.Claim("", "s", "subj", at) },
		"no subject": func(c *domain.FederatedClaim) error { return c.Claim(domain.IssuerGoogle, "", "subj", at) },
		"no account": func(c *domain.FederatedClaim) error { return c.Claim(domain.IssuerGoogle, "s", "", at) },
	} {
		t.Run(name, func(t *testing.T) {
			if err := f(claim(t)); err == nil {
				t.Fatalf("a claim with %s was accepted", name)
			}
		})
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		func() bool {
			for i := 0; i+len(needle) <= len(haystack); i++ {
				if haystack[i:i+len(needle)] == needle {
					return true
				}
			}
			return false
		}()
}
