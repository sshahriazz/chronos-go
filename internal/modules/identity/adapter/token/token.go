// Package token mints and checks identity's single-use secrets: verification
// links and password resets.
//
// # What is here and what is not
//
// The construction — 256 bits of crypto/rand, SHA-256 with a length-prefixed
// purpose, constant-time comparison — is `platform/secret`, and the reasoning
// behind every part of it is documented there. What is here is IDENTITY'S
// POLICY: which purposes exist and how long each one lives.
//
// The split is not tidiness. An invitation token is the same construction with a
// different purpose and a different lifetime, and it belongs to the workspace
// module, which may import `identity/contract` and nothing else of identity's
// (CONVENTIONS §2). Leaving the primitive here would have forced a second copy
// of credential hashing into that module, and two implementations of that drift
// silently.
package token

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// Bytes is the token's entropy, in bytes.
const Bytes = secret.Bytes

const (
	// VerificationTTL bounds an email-verification link.
	//
	// Long enough to survive a mail queue, a spam folder and a night's sleep;
	// short enough that an old message in a compromised mailbox is not a live
	// credential.
	VerificationTTL = 24 * time.Hour

	// ResetTTL bounds a password-reset link, and is deliberately much shorter.
	//
	// A reset token is strictly more dangerous than a verification token — it
	// grants account access rather than confirming an address — so it gets the
	// tighter window. Treating the two the same is the common shortcut, and it
	// leaves account-takeover credentials sitting in inboxes for a day.
	ResetTTL = time.Hour

	// ChangeTTL bounds the link that proves an address an account is MOVING TO.
	//
	// The same window as a verification, because it is the same act: somebody
	// proving they can read mail at an address. It also bounds how long the
	// claimed address is held away from anyone else who might want it, so it is
	// not a number to lengthen casually.
	ChangeTTL = 24 * time.Hour

	// RevertTTL bounds the link that UNDOES a completed change.
	//
	// Deliberately the longest of the four, and the only one whose length is a
	// safety property rather than a cost. The person who needs it did not ask for
	// the change and is reading an unexpected mail — possibly after a weekend —
	// and every hour shaved off is an hour in which an account taken over stays
	// taken over. It must match app.DefaultEmailRevertWindow: the token dying
	// before the aggregate's window closes would leave a window nothing can act
	// on, and outliving it would leave a link that redeems into a refusal.
	RevertTTL = 72 * time.Hour
)

// Token is a freshly minted secret and its stored digest.
type Token = secret.Token

// Minter creates and checks identity's tokens.
type Minter struct{ inner *secret.Minter }

// New builds a minter over identity's lifetime table.
//
// It cannot fail: the table is a compile-time constant of this package, so the
// only errors secret.New reports — an empty table, an empty purpose, a
// non-positive lifetime — are unreachable here. Returning no error keeps the
// call sites unchanged, and a panic would be reached at init or never.
func New() *Minter {
	inner, err := secret.New(map[secret.Purpose]time.Duration{
		secret.Purpose(app.PurposeEmailVerification): VerificationTTL,
		secret.Purpose(app.PurposePasswordReset):     ResetTTL,
		secret.Purpose(app.PurposeEmailChange):       ChangeTTL,
		secret.Purpose(app.PurposeEmailChangeRevert): RevertTTL,
	})
	if err != nil {
		// Unreachable: the table above is a constant of this package. Panicking
		// rather than returning a zero minter, because a minter that cannot mint
		// would otherwise surface as a failed registration at request time.
		panic("token: identity's own lifetime table was rejected: " + err.Error())
	}
	return &Minter{inner: inner}
}

// Mint creates a token for a purpose.
func (m *Minter) Mint(purpose app.TokenPurpose, now time.Time) (Token, error) {
	return m.inner.Mint(secret.Purpose(purpose), now)
}

// Digest is what gets stored and what a presented token is hashed to.
func Digest(purpose app.TokenPurpose, plaintext string) []byte {
	return secret.Digest(secret.Purpose(purpose), plaintext)
}

// Equal compares two digests in constant time.
func Equal(a, b []byte) bool { return secret.Equal(a, b) }

// TTLFor reports how long a purpose's tokens live.
func TTLFor(purpose app.TokenPurpose) (time.Duration, error) {
	return New().inner.TTLFor(secret.Purpose(purpose))
}
