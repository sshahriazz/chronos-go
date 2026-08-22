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
