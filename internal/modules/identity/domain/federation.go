package domain

import (
	"strings"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
)

// ---------------------------------------------------------------------------
// The auto-link decision (identity.md §7)
// ---------------------------------------------------------------------------

// Known issuers. Constants rather than configuration, because the trusted list
// below is keyed on them and a deployment that could rename an issuer could
// move a provider onto that list.
const (
	// IssuerGoogle is Google's OIDC issuer, as it appears in every ID token.
	IssuerGoogle contract.Issuer = "https://accounts.google.com"

	// IssuerApple is Apple's.
	IssuerApple contract.Issuer = "https://appleid.apple.com"

	// IssuerGitHub is a CONSTANT, not a URL from a discovery document: GitHub
	// issues no ID token and has no OIDC issuer at all. It is written here so a
	// GitHub identity still has both halves of the pair every link is keyed on.
	IssuerGitHub contract.Issuer = "https://github.com"

	// IssuerEntraPrefix begins every Microsoft Entra issuer, which carries the
	// tenant id: `https://login.microsoftonline.com/{tid}/v2.0`.
	IssuerEntraPrefix = "https://login.microsoftonline.com/"
)

// LinkReason names WHY a link was refused.
//
// # Why the decision carries a reason at all
//
// The caller must not be told which condition failed — that is an oracle about
// somebody else's account and about a third party's claims. The OPERATOR must,
// because "why can nobody sign in with Google" is otherwise unanswerable, and a
// refusal that records only "refused" is the same defect this repository has now
// found three times: a check whose reason is destroyed at the moment it is
// produced.
//
// So it is returned alongside the decision, logged, and never serialised onto
// the wire.
type LinkReason string

const (
	// ReasonLinked is not a refusal.
	ReasonLinked LinkReason = "linked"

	// ReasonNoAccount means nothing claims the address, so there was nothing to
	// link to. The caller creates a new account instead.
	ReasonNoAccount LinkReason = "no_account_claims_the_address"

	// ReasonNoProviderEmail means the provider asserted no address at all.
	ReasonNoProviderEmail LinkReason = "provider_asserted_no_address"

	// ReasonLocalUnverified means the account never proved its own address, so
	// linking would trust a provider's claim about something this system has
	// itself never confirmed.
	ReasonLocalUnverified LinkReason = "local_address_not_verified"

	// ReasonProviderUnverified means the provider said it did not verify.
	ReasonProviderUnverified LinkReason = "provider_says_unverified"

	// ReasonProviderSilent means the provider asserted NOTHING, which is not the
	// same as saying no (§7 rule 6).
	ReasonProviderSilent LinkReason = "provider_asserted_nothing"

	// ReasonUndeliverable means a GitHub noreply or an Apple private relay:
	// verified by the provider and useless as a contact address.
	ReasonUndeliverable LinkReason = "address_is_not_deliverable_mail"

	// ReasonIssuerNotTrusted means the provider is not on §7's
	// trusted-verification list — or is Entra without xms_edov, which is nOAuth.
	ReasonIssuerNotTrusted LinkReason = "issuer_not_trusted_for_verification"
)

// LinkDecision is what a provider response permits.
type LinkDecision int

const (
	// LinkRefused means no link may be created without the person proving the
	// account by some other means first. It is the ZERO VALUE, so a forgotten
	// branch refuses rather than links.
	LinkRefused LinkDecision = iota

	// LinkAuto means the identity may be attached to the matching account
	// without further proof.
	LinkAuto
)

// ProviderIdentity is what a federated sign-in produced.
//
// No email address: the ADDRESS is not carried into this decision as a string
// because §7 rule 5 forbids matching on it, and a struct that held one would
// invite exactly that. What the decision needs is the blind INDEX — which
// account claims this address — and the provider's claim ABOUT the address.
type ProviderIdentity struct {
	Issuer contract.Issuer

	// Subject is the provider's immutable identifier. `sub` for Google and
	// Apple, the numeric id for GitHub, and `tid`+`oid` joined for Entra.
	Subject string

	// EmailIndex is the blind index of the address the provider asserted, or
	// empty when it asserted none.
	EmailIndex contract.EmailIndex

	// EmailVerification is the provider's claim, TRI-STATE (§7 rule 6).
	EmailVerification contract.ProviderVerification

	// EntraEmailDomainOwnerVerified is Entra's `xms_edov` claim.
	//
	// It exists as its own field rather than being folded into the verification
	// above because it is the ONLY verification signal Entra offers, it must be
	// configured on the app registration to be emitted at all, and its absence
	// is not `false` — it is "not asserted", which is the distinction rule 6
	// exists to preserve.
	EntraEmailDomainOwnerVerified bool

	// AppleUsesPrivateRelay reports an `@privaterelay.appleid.com` address.
	//
	// Never a contact address and never auto-linkable: the person can revoke it,
	// after which mail to it bounces permanently — so an account whose only
	// address is a relay is an account we can eventually no longer reach.
	AppleUsesPrivateRelay bool

	// GitHubNoreply reports an `@users.noreply.github.com` address.
	//
	// GitHub marks these `verified: true` and they are not deliverable mail, so
	// the flag is true and the address is useless. Carried separately because
	// the verification claim alone would say "verified" and be wrong in the way
	// that matters.
	GitHubNoreply bool
}

// LocalAccount is what this system already knows about the address.
type LocalAccount struct {
	// Exists reports that some account claims the index.
	Exists bool

	// EmailVerified reports that the account PROVED the address itself.
	EmailVerified bool
}

// DecideAutoLink answers whether a federated sign-in may attach itself to an
// existing account without further proof.
//
// # This is the most dangerous decision in the domain
//
// identity.md §7: "Never auto-link a federated identity to an existing account
// on email match alone." The attack is one sentence — an attacker registers at a
// provider using the victim's email address, the provider does not verify it,
// the attacker signs in, and naive matching hands them the victim's account.
//
// # The three conditions, all required
//
// Rule 1: the provider asserts `email_verified = true`, AND the local account's
// address is already verified, AND the provider is on the trusted-verification
// list. Any one missing refuses.
//
// # The trusted list is Google, and Entra only with xms_edov
//
// Nothing else, and the exclusions are specific rather than conservative:
//
//   - MICROSOFT does not qualify on its standard claims. Entra's `email` claim
//     is not verified and it emits no trustworthy `email_verified`. Anyone can
//     create a free Entra tenant, set `mail` on a user they control to the
//     victim's address, and be handed the victim's account. That is nOAuth,
//     disclosed June 2023 and still found in 9 of 104 Entra Gallery applications
//     in 2025 — and the victim's MFA and conditional access are irrelevant,
//     because the attack never touches their tenant. `xms_edov` is the only
//     verification signal Entra offers and must be configured to be emitted at
//     all, so its ABSENCE is "not asserted" rather than false.
//   - GITHUB's unverified addresses never qualify, and neither do its
//     `@users.noreply.github.com` ones — those are `verified: true` and are not
//     deliverable mail.
//   - APPLE private-relay addresses never qualify as a contact address, because
//     the person can revoke them and mail then bounces permanently.
//
// # What a refusal means
//
// Not a failure. Rule 2: sign-in creates NO link, and the person authenticates
// with an existing method and links explicitly from settings. That path is
// always available, so refusing costs a few clicks and never an account.
func DecideAutoLink(p ProviderIdentity, local LocalAccount) LinkDecision {
	decision, _ := DecideAutoLinkWithReason(p, local)
	return decision
}

// DecideAutoLinkWithReason is DecideAutoLink, saying which condition decided.
//
// The reason is for the OPERATOR and never for the caller. See LinkReason.
func DecideAutoLinkWithReason(p ProviderIdentity, local LocalAccount) (LinkDecision, LinkReason) {
	// No account claims the address, so there is nothing to link TO. The caller
	// creates a new account instead, which is a different decision entirely.
	if !local.Exists {
		return LinkRefused, ReasonNoAccount
	}

	switch {
	case p.EmailIndex == "":
		// The provider asserted no address. Nothing to match on, and matching on
		// anything else is what rule 5 forbids.
		return LinkRefused, ReasonNoProviderEmail
	case !local.EmailVerified:
		// The local account never proved its own address. Linking here would
		// trust a provider's claim about an address this system has itself never
		// confirmed — two unverified claims do not make a verified one.
		return LinkRefused, ReasonLocalUnverified
	case p.EmailVerification == contract.VerificationUnverified:
		return LinkRefused, ReasonProviderUnverified
	case p.EmailVerification != contract.VerificationVerified:
		// NOT ASSERTED. Kept distinct from "said no" because rule 6 requires it:
		// a provider staying silent is not a provider saying no, and only one of
		// those could ever become a yes.
		return LinkRefused, ReasonProviderSilent
	case p.GitHubNoreply, p.AppleUsesPrivateRelay:
		// Verified by the provider and useless as an address. See the doc.
		return LinkRefused, ReasonUndeliverable
	}

	if !trustedForVerification(p) {
		return LinkRefused, ReasonIssuerNotTrusted
	}
	return LinkAuto, ReasonLinked
}

// trustedForVerification implements the trusted list, and nothing else may.
//
// A function rather than a set literal so the Entra condition — which is not
// "is this issuer present" but "is this issuer present AND did it emit
// xms_edov" — cannot be expressed as membership and then quietly widened to it.
func trustedForVerification(p ProviderIdentity) bool {
	switch {
	case p.Issuer == IssuerGoogle:
		// `email_verified` is reliable for consumer accounts, and for Workspace
		// it means "the domain admin says so" — which is a real assertion by a
		// party with authority over the domain.
		return true
	case strings.HasPrefix(string(p.Issuer), IssuerEntraPrefix):
		// ONLY with xms_edov. See DecideAutoLink's doc: without it this is
		// nOAuth.
		return p.EntraEmailDomainOwnerVerified
	default:
		// Apple and GitHub are deliberately absent, as is anything unrecognised.
		// A provider nobody has assessed is not a provider to trust.
		return false
	}
}

// EntraSubject joins the tuple that identifies a person in Entra.
//
// `tid` AND `oid`, never `sub` — which is pairwise per application, so the same
// person is a different `sub` to every app and no link would survive — and never
// `upn` or `email`, which are user-mutable and reassignable. §7 rule 5.
func EntraSubject(tenantID, objectID string) string {
	if tenantID == "" || objectID == "" {
		return ""
	}
	return tenantID + ":" + objectID
}
