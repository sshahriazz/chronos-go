package app

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// InvitationIssuer mints the emailed link, off the request path.
//
// # Why this exists at all
//
// The plaintext cannot travel in an event. An event is permanent and replicated,
// so a token in one is a live credential in the log (ADR-002), and only the
// digest — one-way by construction — ever reaches storage. So whoever SENDS the
// invitation must hold the plaintext at the moment it is minted; nothing that
// survives the request can recover it afterwards.
//
// The first version of this slice minted in the HANDLER and returned the
// plaintext up through the use case, where the API layer dropped it. That works
// right up until something has to actually send the mail: the reactor consumes
// InvitationIssued, and there is no way back from a digest — so the link existed
// for exactly one function call and then became unreachable forever.
//
// This is identity's VerificationIssuer, for invitations, and it is here for the
// same three reasons that one gives. It keeps a slow, failure-prone step off the
// request, so a mail outage costs a redelivery rather than a failed invitation.
// It gives the plaintext ONE holder for its whole life, rather than threading it
// through a use case that is also performing an atomic append it must not carry.
// And the rule it enforces — at most one live link per invitation — is workspace
// policy, so a reactor that inlined "RevokeAll, then Issue" would be a second
// place for that ordering to be remembered or forgotten.
//
// # Why RevokeAll comes first, always
//
// A reactor's delivery is at-least-once, and a retry that issued a second link
// without voiding the first would leave TWO live credentials for one invitation.
// Either could be redeemed, and redeeming one would leave the other usable —
// which is what "the old token stays dead" (workspace.md §5) forbids, and what
// anybody who has seen one copy of the mail wants.
//
// Revoking first makes that a property of this call rather than of how carefully
// its callers retry: after Issue returns, the link it returned is the ONLY
// redeemable one and every link mailed earlier is already dead.
//
// The order also decides which failure is survivable. Revoke-then-issue can fail
// between the two and leave an invitation with no live link — recoverable,
// because the caller reports it, the event is redelivered, and the next attempt
// issues a fresh one. Issue-then-revoke cannot fail safely: the revoke would void
// the link just issued, so a crash between them leaves the caller holding a
// plaintext that redeems nothing, and mailing it produces a link that is dead on
// arrival with nothing to say so.
type InvitationIssuer struct {
	clock  clock.Clock
	tokens InvitationTokenStore
	minter *secret.Minter
}

// InvitationIssuerDeps is what the issuer needs.
type InvitationIssuerDeps struct {
	// Clock stamps the expiry. The minter is handed this instant rather than
	// reading its own, so the deadline stored is the one the caller can report.
	Clock clock.Clock

	// Tokens holds the digests. The issuer never reads one back — only Issue and
	// RevokeAll are used here; Lookup and Consume belong to redemption.
	Tokens InvitationTokenStore

	// Minter produces the plaintext and its digest together. One component, so
	// the two forms cannot be derived by two pieces of code that disagree.
	Minter *secret.Minter
}

// InvitationLink is one freshly issued link.
type InvitationLink struct {
	// Plaintext is the secret the emailed link carries. It is returned exactly
	// once and must never be logged, stored, or put in an event.
	Plaintext string

	// ExpiresAt is when it stops working, UTC.
	ExpiresAt time.Time

	// Fingerprint identifies WHICH link this is, without being one.
	//
	// The reactor keys its delivery on it: a rerun mints a second link and kills
	// the first, so the two runs are not the same delivery. Keying on the event
	// id alone would make the second run a duplicate, refused as already done —
	// and the only mail ever sent would be the one carrying the revoked link.
	Fingerprint string
}

func NewInvitationIssuer(d InvitationIssuerDeps) (*InvitationIssuer, error) {
	switch {
	case d.Clock == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	case d.Tokens == nil:
		return nil, fmt.Errorf("workspace: a token store is required; without one the link " +
			"is minted, mailed and redeemable by nothing")
	case d.Minter == nil:
		return nil, fmt.Errorf("workspace: a minter is required")
	}
	return &InvitationIssuer{clock: d.Clock, tokens: d.Tokens, minter: d.Minter}, nil
}

// Issue voids every outstanding link for an invitation and mints one.
func (i *InvitationIssuer) Issue(
	ctx context.Context, invitationID, orgID string,
) (InvitationLink, error) {
	if invitationID == "" || orgID == "" {
		return InvitationLink{}, errs.Internalf("issuing a link needs an invitation and an " +
			"organization")
	}

	// FIRST. See the type comment: this is what makes "one live link" a property
	// of this call rather than of how carefully every caller retries.
	if _, err := i.tokens.RevokeAll(ctx, invitationID); err != nil {
		return InvitationLink{}, errs.Internalf("voiding the previous link").Wrap(err)
	}

	now := i.clock.Now().UTC()
	minted, err := i.minter.Mint(PurposeInvitation, now)
	if err != nil {
		return InvitationLink{}, errs.Internalf("minting an invitation link").Wrap(err)
	}
	if err := i.tokens.Issue(ctx, minted.Digest, invitationID, orgID, minted.ExpiresAt); err != nil {
		return InvitationLink{}, errs.Internalf("storing the invitation link").Wrap(err)
	}

	return InvitationLink{
		Plaintext:   minted.Plaintext,
		ExpiresAt:   minted.ExpiresAt,
		Fingerprint: Fingerprint(minted.Digest),
	}, nil
}

// Fingerprint names a link without being one.
//
// The first 8 bytes of the digest, hex-encoded. It is derived from a value that
// is already one-way, so it identifies the link while carrying nothing that
// could redeem it — which is what makes it safe in a workflow id and a
// Message-ID, where the plaintext would be a credential in durable, replicated
// history.
func Fingerprint(digest []byte) string {
	const n = 8
	if len(digest) < n {
		return ""
	}
	return fmt.Sprintf("%x", digest[:n])
}
