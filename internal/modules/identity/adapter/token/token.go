// Package token mints and checks the single-use secrets sent by email:
// verification links and password resets.
//
// # Why SHA-256 and not Argon2id
//
// Password verifiers get Argon2id because a password is low-entropy — a human
// chose it, and an attacker with the digest guesses candidates until one
// matches. A slow hash is what makes that expensive.
//
// A token here is 256 bits from crypto/rand. There is no candidate list, no
// dictionary, and no structure to exploit: an attacker holding the digest has
// nothing better than enumerating 2^256 values. Argon2id would add ~50 ms to
// every click of every verification link and buy nothing, while making the
// endpoint a memory amplification vector for anyone who can send it garbage.
//
// The reasoning turns entirely on WHERE THE ENTROPY COMES FROM. Use a slow hash
// when a human chose the secret; a fast one when crypto/rand did. Applying
// either rule in the wrong place is a real mistake in both directions.
//
// # What is stored
//
// Only the digest. A stolen database yields digests, and a digest cannot be
// presented — the endpoint hashes what it receives and compares. This is the
// same reason session tokens are stored hashed.
package token

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

const (
	// Bytes is the token's entropy. 256 bits.
	//
	// Well above the 128-bit floor NIST SP 800-63B-4 §5.1.1 sets for a
	// single-use secret sent out of band, because there is no cost to it: the
	// token is machine-generated, machine-checked, and only ever travels inside a
	// URL.
	Bytes = 32

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
)

// Token is a freshly minted secret and its stored digest.
type Token struct {
	// Plaintext goes into the emailed URL. It is returned exactly once and must
	// never be logged, stored, or included in an event — a token in a log line is
	// a live credential in a system whose logs are retained far longer than the
	// token's TTL.
	Plaintext string

	// Digest is what the store holds.
	Digest []byte

	ExpiresAt time.Time
}

// Minter creates and checks tokens.
type Minter struct {
	// rand is injectable ONLY so a test can drive the short-read branch.
	// Production always uses crypto/rand.
	rand io.Reader
}

// New builds a minter.
func New() *Minter { return &Minter{rand: rand.Reader} }

// Mint creates a token for a purpose.
//
// The purpose is mixed into the DIGEST, not merely stored beside it. A token
// issued to verify an address then hashes to a value that no reset lookup can
// match — so even a store that forgot to filter by purpose cannot cross-redeem
// one for the other. Defence at the layer that cannot be forgotten, rather than
// at the query.
func (m *Minter) Mint(purpose app.TokenPurpose, now time.Time) (Token, error) {
	if purpose == "" {
		return Token{}, fmt.Errorf("token: a purpose is required; an unscoped token can be " +
			"redeemed in a flow it was never issued for")
	}
	ttl, err := ttlFor(purpose)
	if err != nil {
		return Token{}, err
	}

	raw := make([]byte, Bytes)
	if _, err := io.ReadFull(m.rand, raw); err != nil {
		// Refused, never degraded. A short read leaves trailing zero bytes, and
		// a token whose tail is predictable is one an attacker can search.
		return Token{}, fmt.Errorf("token: generating a token: %w", err)
	}

	// base64url without padding: it goes in a URL, so '+' and '/' would need
	// escaping and '=' is commonly mangled by mail clients rewriting links.
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	return Token{
		Plaintext: plaintext,
		Digest:    Digest(purpose, plaintext),
		ExpiresAt: now.Add(ttl).UTC(),
	}, nil
}

// Digest is what gets stored and what a presented token is hashed to.
//
// The purpose is a length-prefixed prefix rather than a plain concatenation.
// With plain concatenation, ("ab", "cd") and ("a", "bcd") hash identically — and
// while no current purpose can collide that way, the property holds because of
// the constant values chosen today, not because of anything this function does.
func Digest(purpose app.TokenPurpose, plaintext string) []byte {
	h := sha256.New()
	// Fixed-width length prefix, so the boundary between purpose and token
	// cannot be moved by choosing a clever purpose string.
	var n [8]byte
	binary.BigEndian.PutUint64(n[:], uint64(len(purpose)))
	_, _ = h.Write(n[:])
	_, _ = h.Write([]byte(purpose))
	_, _ = h.Write([]byte(plaintext))
	return h.Sum(nil)
}

// Equal compares two digests in constant time.
//
// Used where a caller holds both — the store's comparison is a lookup, not a
// comparison, so it is already immune. This exists so no caller reaches for
// bytes.Equal on a security-relevant value.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }

// TTLFor reports how long a purpose's tokens live.
func TTLFor(purpose app.TokenPurpose) (time.Duration, error) { return ttlFor(purpose) }

func ttlFor(purpose app.TokenPurpose) (time.Duration, error) {
	switch purpose {
	case app.PurposeEmailVerification:
		return VerificationTTL, nil
	case app.PurposePasswordReset:
		return ResetTTL, nil
	default:
		// An unknown purpose gets no default TTL. A fallback here would give a
		// newly added flow whichever window happened to be first in the switch,
		// silently — and the dangerous direction is the long one.
		return 0, fmt.Errorf("token: unknown purpose %q; every purpose must declare its own "+
			"lifetime", purpose)
	}
}
