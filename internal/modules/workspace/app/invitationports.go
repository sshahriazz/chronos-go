package app

import (
	"context"
	"errors"
	"time"

	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// PurposeInvitation scopes an invitation token to redemption.
//
// Mixed into the digest by platform/secret rather than stored beside it, so an
// invitation token cannot be redeemed as a verification link or a password reset
// even by a query that forgot to filter — and the reverse, which matters more: a
// verification link is far easier to obtain than an invitation, and without the
// scoping one could be presented here to join a workspace.
const PurposeInvitation secret.Purpose = "workspace_invitation"

// InvitationTTL is how long an invitation link lives.
//
// Seven days, from workspace.md §5. Long enough to survive a holiday and a spam
// folder; short enough that a seat is not held indefinitely by somebody who has
// changed jobs. It is declared HERE and not in platform/secret because a token's
// window is a decision about this flow (see that package).
const InvitationTTL = 7 * 24 * time.Hour

// ErrInvitationTokenNotFound is a digest that is unknown, already spent, or
// expired.
//
// One error for all three, deliberately. Distinguishing them tells an attacker
// holding a guessed token that they guessed a real one, and tells anyone with an
// old mail whether the organization still exists.
var ErrInvitationTokenNotFound = errors.New("workspace: no such invitation token")

// InvitationTokenStore holds invitation link credentials, as digests.
//
// Consume is the whole interface's reason for existing, and it must be ATOMIC. A
// read-then-delete races two clicks of the same link and both win, which turns a
// single-use invitation into a multi-use one — two people joining on one seat.
type InvitationTokenStore interface {
	// Issue records a digest against an invitation, until expiresAt.
	Issue(ctx context.Context, digest []byte, invitationID, orgID string, expiresAt time.Time) error

	// Lookup reads a digest WITHOUT spending it, so the checks that can fail
	// transiently run before the link is burned.
	Lookup(ctx context.Context, digest []byte, now time.Time) (invitationID, orgID string, err error)

	// Consume redeems a digest exactly once and reports which invitation it
	// names. Returns ErrInvitationTokenNotFound for unknown, spent or expired.
	Consume(ctx context.Context, digest []byte, now time.Time) (invitationID, orgID string, err error)

	// RevokeAll drops every outstanding digest for one invitation, reporting how
	// many there were.
	//
	// A resend calls it so exactly one link is live afterwards; a settlement
	// calls it so none is. The count matters to the first: a resend that revoked
	// nothing has just created a second live link.
	RevokeAll(ctx context.Context, invitationID string) (int64, error)
}

// EmailIndexer derives the keyed lookup value for an address.
//
// Declared here and satisfied at the composition root by identity's blind-index
// adapter. Workspace may import `identity/contract` and nothing else of
// identity's (CONVENTIONS §2), and `EmailIndex` is in that contract precisely so
// two modules can agree an address is the same address without either holding
// the address or the key.
//
// The value it returns is what the invitation event carries. It answers "is this
// the same address?" and nothing else: it cannot be rendered to a human, and no
// mail may be addressed from it (ADR-002).
type EmailIndexer interface {
	// Of returns the blind index for an address, or a validation error when the
	// address is not one this system will accept.
	Of(email string) (identitycontract.EmailIndex, error)
}

// Directory resolves an address to the pseudonym the system already knows it by.
//
// A READ-ONLY cross-module query, which is the only shape CONVENTIONS §2 permits
// between modules: workspace never commands identity, it asks.
//
// # Why the answer matters
//
// An invitation to somebody who already has an account must name THEIR
// pseudonym, so that accepting it makes them a member rather than creating a
// second identity for the same person. An invitation to somebody who does not
// gets a fresh pseudonym, which exists only to hang the vault entry holding
// their address off — see Invitations.Issue.
type Directory interface {
	// SubjectFor returns the pseudonym claiming an index.
	//
	// known=false is a normal answer, not an error: most invitations go to
	// people who have never used this system, and treating that as a failure
	// would make inviting a new colleague impossible.
	SubjectFor(ctx context.Context, index identitycontract.EmailIndex) (subjectID string, known bool, err error)

	// IsAccount reports whether a pseudonym names a real account.
	//
	// # What acceptance does with the answer, and why it is not a comparison of
	// addresses
	//
	// workspace.md §5 wants a caller signed in as a DIFFERENT user to be told so
	// explicitly rather than have the invitation silently bound to the wrong
	// account. The obvious implementation compares the caller's address to the
	// invited one — and it cannot be built, because identity deliberately drops
	// the blind index at its read boundary: it is a re-identification handle
	// over an address, and letting one out of a result whose whole design is
	// that it carries a pseudonym is the thing that comment exists to prevent.
	//
	// This answers the same question without one. An invitation to somebody who
	// ALREADY had an account names that account's pseudonym, so a different
	// caller is detectable by comparing pseudonyms. An invitation to somebody
	// who did not names a minted pseudonym that is not an account at all — and
	// there is nothing to compare, nor anything to gain: holding the link is
	// proof of control over the mailbox it was sent to, which is the entire
	// reason the token is a credential.
	IsAccount(ctx context.Context, subjectID string) (bool, error)
}

// Subscriptions is gate 3, asked about an organization the CALLER did not name.
//
// Every other org-scoped RPC gets this from the interceptor, which reads the
// tenant scope gate 1 resolved. Acceptance cannot: the person clicking the link
// may not be in the organization yet, so there is no membership to resolve a
// scope from — the TOKEN is what names the organization, and it names it only
// after the handler has looked it up.
//
// So the check moves into the handler and takes an explicit id. That is safe
// here for the reason it is unsafe everywhere else: the id did not come from the
// caller, it came from a 256-bit capability this system issued and stored.
type Subscriptions interface {
	// PermitJoin refuses an acceptance the organization's subscription does not
	// allow. workspace.md §5 wants ORG_SUSPENDED here, which is what makes a
	// suspended tenant unable to grow while its existing members keep working.
	PermitJoin(ctx context.Context, orgID string) error
}

// Addresses is the vault, narrowed to the one field an invitation needs.
//
// Narrow on purpose. A use case holding the whole vault could read any field of
// any subject, and the only thing this flow legitimately does is record the
// address it is about to send to — so that the mail activity can resolve it at
// send time and erasure can destroy it with one key (ADR-002).
type Addresses interface {
	// PutEmail records an address under a pseudonym.
	PutEmail(ctx context.Context, subjectID, email string) error
}

// SubjectMinter creates a fresh pseudonym for an address nobody knows yet.
//
// A port rather than a call to ids.New, so the test that proves an invitation to
// a KNOWN address reuses the existing pseudonym can tell the two paths apart —
// otherwise both produce a valid-looking id and the test passes either way.
type SubjectMinter interface {
	NewSubject() string
}

// PendingInvitation names one outstanding invitation.
//
// Ids only. It crosses into a reactor and into workflow-adjacent code, so it
// carries nothing personal — the address it was sent to is in the vault, and the
// blind index that recognised it stays in the query.
type PendingInvitation struct {
	InvitationID string
	WorkspaceID  string
}

// AddressInvitations answers "is there already an invitation to this address
// here?".
//
// It exists for workspace.md §5's supersession rule: a second invitation to one
// address supersedes the first rather than taking a SECOND SEAT. Scoped by
// organization rather than workspace, because the seat is per organization —
// two invitations to one address in two workspaces of one tenant are exactly the
// double charge the rule prevents.
type AddressInvitations interface {
	PendingForAddress(ctx context.Context, orgID, emailIndex string) (PendingInvitation, bool, error)
}

// OutstandingInvitations lists what one person has issued and nobody has settled.
//
// For the reactor that revokes a departing inviter's invitations
// (workspace.md §5): the authorisation to join came from somebody who is no
// longer there, and an invitation nobody can vouch for should not still be
// redeemable.
type OutstandingInvitations interface {
	ListPendingBy(ctx context.Context, orgID, subjectID string) ([]PendingInvitation, error)
}
