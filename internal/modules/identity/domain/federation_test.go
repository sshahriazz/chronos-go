package domain_test

import (
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// verifiedLocal is an account that proved its own address.
var verifiedLocal = domain.LocalAccount{Exists: true, EmailVerified: true}

// googleVerified is the one shape that auto-links.
func googleVerified() domain.ProviderIdentity {
	return domain.ProviderIdentity{
		Issuer:            domain.IssuerGoogle,
		Subject:           "1234567890",
		EmailIndex:        "idx_1",
		EmailVerification: contract.VerificationVerified,
	}
}

// THE ONE SHAPE THAT AUTO-LINKS.
//
// Asserted first so every refusal below is discriminating rather than blanket —
// a DecideAutoLink that returned LinkRefused unconditionally would pass every
// other test in this file.
func TestGoogleWithBothSidesVerifiedAutoLinks(t *testing.T) {
	if got := domain.DecideAutoLink(googleVerified(), verifiedLocal); got != domain.LinkAuto {
		t.Fatalf("a Google identity with a verified address, matching a verified local "+
			"account, was refused (%v). Nothing would ever auto-link", got)
	}
}

// nOAuth: ENTRA WITHOUT xms_edov IS AN ACCOUNT TAKEOVER.
//
// # The attack, in full
//
// Entra's `email` claim is not verified and Entra emits no trustworthy
// `email_verified`. Anyone can create a free Entra tenant, set `mail` on a user
// they control to the victim's address, and sign in. If the relying party
// auto-links on that claim, they are handed the victim's account — and the
// victim's MFA, conditional access and Zero Trust policies are all irrelevant,
// because the attack never touches their tenant.
//
// Disclosed June 2023. Still found in 9 of 104 Entra Gallery applications in
// 2025, which is why this test names the CVE class rather than describing a
// generic rule.
func TestEntraWithoutTheDomainOwnerClaimIsRefused(t *testing.T) {
	attacker := domain.ProviderIdentity{
		Issuer:     contract.Issuer(domain.IssuerEntraPrefix + "attacker-tenant/v2.0"),
		Subject:    domain.EntraSubject("attacker-tenant", "attacker-object"),
		EmailIndex: "idx_1",
		// The attacker's tenant asserts the victim's address as verified. It can
		// say anything it likes; that is the point.
		EmailVerification: contract.VerificationVerified,
		// And does NOT emit xms_edov, which is the only signal that would mean
		// anything.
		EntraEmailDomainOwnerVerified: false,
	}

	if got := domain.DecideAutoLink(attacker, verifiedLocal); got != domain.LinkRefused {
		t.Fatal("an Entra tenant the attacker created was auto-linked to the victim's " +
			"account on a claim it made about an address it does not own. This is " +
			"nOAuth: the victim's MFA and conditional access never come into it, " +
			"because the attack never touches their tenant")
	}
}

// AND WITH IT, ENTRA IS TRUSTED.
//
// The exception has to work, or the rule is "never Entra" written in a way that
// pretends otherwise.
func TestEntraWithTheDomainOwnerClaimAutoLinks(t *testing.T) {
	ok := domain.ProviderIdentity{
		Issuer:                        contract.Issuer(domain.IssuerEntraPrefix + "real-tenant/v2.0"),
		Subject:                       domain.EntraSubject("real-tenant", "obj"),
		EmailIndex:                    "idx_1",
		EmailVerification:             contract.VerificationVerified,
		EntraEmailDomainOwnerVerified: true,
	}
	if got := domain.DecideAutoLink(ok, verifiedLocal); got != domain.LinkAuto {
		t.Fatalf("Entra with xms_edov was refused (%v); the only verification signal "+
			"Entra offers buys nothing", got)
	}
}

// APPLE AND GITHUB ARE NOT ON THE LIST.
//
// Not because they are untrustworthy providers, but because neither offers a
// verification claim this system can rely on for LINKING — which is a narrower
// question than whether the sign-in is genuine.
func TestAppleAndGitHubNeverAutoLink(t *testing.T) {
	for name, issuer := range map[string]contract.Issuer{
		"apple":  domain.IssuerApple,
		"github": domain.IssuerGitHub,
	} {
		t.Run(name, func(t *testing.T) {
			p := googleVerified()
			p.Issuer = issuer
			if got := domain.DecideAutoLink(p, verifiedLocal); got != domain.LinkRefused {
				t.Fatalf("%s auto-linked (%v); it is not on the trusted-verification "+
					"list and the person must link explicitly instead", name, got)
			}
		})
	}
}

// A GITHUB NOREPLY ADDRESS IS VERIFIED AND USELESS.
//
// GitHub marks `@users.noreply.github.com` as verified: true, and it is not
// deliverable mail. The verification claim alone would say yes and be wrong in
// the way that matters.
func TestAGitHubNoreplyAddressNeverAutoLinks(t *testing.T) {
	p := googleVerified()
	p.Issuer = domain.IssuerGitHub
	p.GitHubNoreply = true
	if got := domain.DecideAutoLink(p, verifiedLocal); got != domain.LinkRefused {
		t.Fatalf("a noreply address auto-linked (%v)", got)
	}
}

// AN APPLE PRIVATE RELAY IS REVOCABLE, SO IT IS NEVER A CONTACT ADDRESS.
//
// The person can revoke it, after which mail bounces permanently — an account
// whose only address is a relay is one we can eventually no longer reach.
//
// Asserted with the relay on a TRUSTED issuer, so the refusal is the relay's and
// not the issuer's.
func TestAnApplePrivateRelayNeverAutoLinks(t *testing.T) {
	p := googleVerified()
	p.AppleUsesPrivateRelay = true
	if got := domain.DecideAutoLink(p, verifiedLocal); got != domain.LinkRefused {
		t.Fatalf("a private-relay address auto-linked (%v) on a trusted issuer", got)
	}
}

// EVERY OTHER CONDITION IS INDIVIDUALLY NECESSARY.
//
// Rule 1 requires all three, so each is removed alone from the one shape that
// works. A test that only checked them together would pass against an
// implementation that required any ONE of them.
func TestEachConditionIsIndividuallyRequired(t *testing.T) {
	for name, tc := range map[string]struct {
		mutate func(*domain.ProviderIdentity, *domain.LocalAccount)
		why    string
	}{
		"no account claims the address": {
			mutate: func(_ *domain.ProviderIdentity, l *domain.LocalAccount) { l.Exists = false },
			why:    "there is nothing to link to; the caller creates an account instead",
		},
		"the local address was never proven": {
			mutate: func(_ *domain.ProviderIdentity, l *domain.LocalAccount) { l.EmailVerified = false },
			why:    "two unverified claims do not make a verified one",
		},
		"the provider says unverified": {
			mutate: func(p *domain.ProviderIdentity, _ *domain.LocalAccount) {
				p.EmailVerification = contract.VerificationUnverified
			},
			why: "the provider itself says it did not check",
		},
		"the provider asserts nothing": {
			mutate: func(p *domain.ProviderIdentity, _ *domain.LocalAccount) {
				p.EmailVerification = contract.VerificationNotAsserted
			},
			why: "silence is not a yes, and rule 6 keeps it distinct from a no",
		},
		"the provider asserts no address": {
			mutate: func(p *domain.ProviderIdentity, _ *domain.LocalAccount) { p.EmailIndex = "" },
			why:    "nothing to match on, and matching on anything else is what rule 5 forbids",
		},
	} {
		t.Run(name, func(t *testing.T) {
			p, l := googleVerified(), verifiedLocal
			tc.mutate(&p, &l)
			if got := domain.DecideAutoLink(p, l); got != domain.LinkRefused {
				t.Fatalf("auto-linked with %s (%v) — %s", name, got, tc.why)
			}
		})
	}
}

// REFUSED IS THE ZERO VALUE.
//
// So a forgotten branch, an unhandled provider or a zero struct all refuse. The
// property authz.Decision has, for the same reason: the safe answer must be the
// one you get by accident.
func TestTheZeroDecisionRefuses(t *testing.T) {
	var zero domain.LinkDecision
	if zero != domain.LinkRefused {
		t.Fatal("the zero LinkDecision is not LinkRefused; a forgotten branch links")
	}
	if got := domain.DecideAutoLink(domain.ProviderIdentity{}, domain.LocalAccount{}); got != domain.LinkRefused {
		t.Fatalf("a zero identity against a zero account returned %v", got)
	}
}

// AN UNKNOWN ISSUER IS NOT TRUSTED.
//
// A provider nobody has assessed is not a provider to trust, and the default has
// to be refusal or the list is advisory.
func TestAnUnknownIssuerIsNeverTrusted(t *testing.T) {
	p := googleVerified()
	p.Issuer = "https://idp.example.test"
	if got := domain.DecideAutoLink(p, verifiedLocal); got != domain.LinkRefused {
		t.Fatalf("an unassessed issuer auto-linked (%v)", got)
	}
}

// ENTRA IS IDENTIFIED BY tid AND oid, NEVER sub.
//
// `sub` is pairwise per application, so the same person is a different `sub` to
// every app and no link would survive. `upn` and `email` are user-mutable and
// reassignable. §7 rule 5.
func TestTheEntraSubjectJoinsTenantAndObject(t *testing.T) {
	if got := domain.EntraSubject("tid-1", "oid-1"); got != "tid-1:oid-1" {
		t.Fatalf("EntraSubject produced %q", got)
	}
	// A missing half produces NOTHING rather than a half-identity that would
	// collide with every other identity missing the same half.
	for _, tc := range [][2]string{{"", "oid"}, {"tid", ""}, {"", ""}} {
		if got := domain.EntraSubject(tc[0], tc[1]); got != "" {
			t.Errorf("EntraSubject(%q,%q) produced %q; a half identity collides with "+
				"every other half identity", tc[0], tc[1], got)
		}
	}
}
