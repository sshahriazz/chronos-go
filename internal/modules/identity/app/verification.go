package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

// VerificationIssuer mints the emailed proof-of-control token, off the
// registration path.
//
// # Why this exists at all
//
// The plaintext token cannot travel in an event. An event is permanent and
// replicated, so a token in one is a live credential in the log (ADR-002), and
// only the digest — one-way by construction — ever reaches storage. So whoever
// SENDS the verification mail must hold the plaintext at the moment it is
// minted; nothing that survives the request can recover it afterwards.
//
// There are exactly two coherent places to mint it: the registration handler,
// which then has to hand the plaintext to a delivery step, or the reactor that
// consumes EmailVerificationRequested, which mints its own. This type is the
// second, and it is deliberately a use case rather than reactor code: the rule
// it enforces — at most ONE outstanding verification token per subject
// (identity.md §7 rule 7) — is identity policy, and a reactor that inlined
// "RevokeAll, then Issue" would be a second place for that ordering to be
// remembered or forgotten.
//
// # Why RevokeAll comes first, always
//
// A verification token is at-least-once by nature: the reactor's delivery is
// retried, and a retry that issued a second token without voiding the first
// would leave TWO live links for one address. Consuming one of them would leave
// the other usable, which is exactly what the rule forbids — and exactly what an
// attacker who has seen one mail wants. Revoking first makes the invariant a
// property of this call rather than of how carefully its callers retry: after
// IssueVerification returns, the token it returned is the ONLY redeemable one,
// and every link mailed earlier is already dead.
//
// The order also decides which failure is survivable. Revoke-then-issue can fail
// between the two and leave a subject with no live token — recoverable, because
// the caller reports the failure, the event is redelivered and the next attempt
// issues a fresh one. Issue-then-revoke cannot fail safely: the revoke would
// void the token just issued, so a crash between them leaves the caller holding
// a plaintext that redeems nothing, and mailing it produces a link that is dead
// on arrival with nothing to say so.
type VerificationIssuer struct {
	clock  clock.Clock
	tokens TokenStore
	minter TokenMinter
}

// VerificationIssuerDeps is what the issuer needs.
type VerificationIssuerDeps struct {
	// Clock stamps the token's expiry. The minter is handed this instant rather
	// than reading its own, so the deadline recorded in the store is the one the
	// caller can also report.
	Clock clock.Clock

	// Tokens holds the digests. The issuer never reads one back — only Issue and
	// RevokeAll are used here; Consume belongs to redemption.
	Tokens TokenStore

	// Minter produces the plaintext and its digest together. One component, so
	// the two forms cannot be derived by two pieces of code that disagree.
	Minter TokenMinter
}

// NewVerificationIssuer builds the issuer.
//
// Every dependency is required and none has a safe stand-in. A nil token store
// would make an issued link unredeemable; a nil minter would make it
// unissuable. Both failures are silent at the point they happen and only visible
// to the person who clicked the link, so they are refused at wiring time.
func NewVerificationIssuer(deps VerificationIssuerDeps) (*VerificationIssuer, error) {
	switch {
	case deps.Clock == nil:
		return nil, fmt.Errorf("identity/app: the verification issuer needs a clock")
	case deps.Tokens == nil:
		return nil, fmt.Errorf("identity/app: the verification issuer needs a token store; " +
			"without one nothing records the digest and every emailed link is refused")
	case deps.Minter == nil:
		return nil, fmt.Errorf("identity/app: the verification issuer needs a token minter")
	}
	return &VerificationIssuer{clock: deps.Clock, tokens: deps.Tokens, minter: deps.Minter}, nil
}

// Verification is one freshly issued link's ingredients.
//
// It exists for exactly one hop — from this call into the delivery step that
// renders the mail — and must not be stored, logged or put into an event.
type Verification struct {
	// Plaintext is the secret the link carries. Produced once, and the only copy
	// in the system: the store holds a one-way digest, so this value cannot be
	// recovered from anything after this call returns.
	Plaintext string

	// ExpiresAt is when the link stops working, UTC.
	ExpiresAt time.Time

	// TTL is how long the link lives, so a template can say "this link expires
	// in 24 hours" without subtracting two instants and without needing a clock
	// of its own.
	TTL time.Duration

	// Fingerprint names THIS issuance without being a credential: it is a hash
	// of the digest, so knowing it reveals nothing that could be redeemed.
	//
	// It exists so a delivery can be identified by the token it carries. A
	// delivery keyed only by the event that asked for it is deduplicated across
	// retries — and a retry here carries a DIFFERENT token, because the previous
	// one was revoked, so deduplicating it would send the older, now-dead link
	// and call the job done.
	Fingerprint string
}

// IssueVerification voids every outstanding verification token for the subject
// and issues exactly one new one.
//
// The plaintext is returned and nothing else keeps it: it is not logged here and
// must not be logged by the caller, since a log line outlives the token it
// exposes by months.
func (v *VerificationIssuer) IssueVerification(
	ctx context.Context, subjectID string,
) (Verification, error) {
	if subjectID == "" {
		// Refused rather than defaulted. RevokeAll with an empty subject is a
		// query that matches nothing in one store and everything in another, and
		// Issue would bind a live token to a pseudonym no account resolves from.
		return Verification{}, errs.ValidationFailedf("a subject id is required to issue a verification")
	}

	now := v.clock.Now().UTC()
	token, err := v.minter(PurposeEmailVerification, now)
	if err != nil {
		return Verification{}, fmt.Errorf("minting a verification token: %w", err)
	}
	if err := v.tokens.RevokeAll(ctx, PurposeEmailVerification, subjectID); err != nil {
		// Before Issue, so a failure here leaves the PREVIOUS token live and this
		// one unissued — one live token, and the link already in the mailbox still
		// works. The redelivery that follows tries the whole sequence again.
		return Verification{}, fmt.Errorf("voiding outstanding verification tokens: %w", err)
	}
	if err := v.tokens.Issue(
		ctx, PurposeEmailVerification, subjectID, token.Digest, token.ExpiresAt,
	); err != nil {
		return Verification{}, fmt.Errorf("storing the verification token: %w", err)
	}

	return Verification{
		Plaintext:   token.Plaintext,
		ExpiresAt:   token.ExpiresAt,
		TTL:         token.ExpiresAt.Sub(now),
		Fingerprint: fingerprint(token.Digest),
	}, nil
}

// fingerprint reduces a digest to a short, non-redeemable label.
//
// Hashed again rather than truncated: a prefix of the stored digest would put
// part of a lookup key into a workflow id and a Message-ID header, and while 64
// bits of a SHA-256 preimage-resistant value is not an attack today, "part of
// the secret material is fine in the clear" is not a property worth depending
// on when a second hash costs nothing.
func fingerprint(digest []byte) string {
	sum := sha256.Sum256(digest)
	return hex.EncodeToString(sum[:8])
}
