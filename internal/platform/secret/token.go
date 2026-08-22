// Package secret mints and checks the single-use secrets this system sends to
// people: verification links, password resets, invitations.
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
// every click of every emailed link and buy nothing, while making the endpoint a
// memory amplification vector for anyone who can send it garbage.
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
//
// # Why it lives in platform and not in identity
//
// It began as identity's, because verification links were the first thing that
// needed it. An invitation token is the same construction with a different
// purpose and a different lifetime, and it belongs to workspace — which may
// import `identity/contract` and nothing else of identity's (CONVENTIONS §2).
//
// The alternatives were both worse than moving it. Copying it gives two
// implementations of credential hashing that will drift, and the drift is
// silent. Widening the import contract to let one module reach into another's
// adapters gives up the property the contract exists for. So the primitive is
// here, holding no policy: every LIFETIME is declared by the module that owns
// the flow, because a token's window is a decision about that flow and not about
// hashing.
package secret

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"fmt"
	"io"
	"maps"
	"time"
)

// Bytes is the token's entropy. 256 bits.
//
// Well above the 128-bit floor NIST SP 800-63B-4 §5.1.1 sets for a single-use
// secret sent out of band, because there is no cost to it: the token is
// machine-generated, machine-checked, and only ever travels inside a URL.
const Bytes = 32

// Purpose scopes a single-use token to one flow.
//
// It is mixed into the DIGEST rather than stored beside it, so a token issued
// for one flow hashes to a value no other flow's lookup can match — see Digest.
type Purpose string

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

// Minter creates tokens for the purposes it was given lifetimes for.
type Minter struct {
	// rand is injectable ONLY so a test can drive the short-read branch.
	// Production always uses crypto/rand.
	rand io.Reader

	ttls map[Purpose]time.Duration
}

// New builds a minter over a lifetime table.
//
// The table is REQUIRED and is the whole configuration surface. A minter with a
// default TTL would give a newly added flow whichever window happened to be the
// fallback, silently — and the dangerous direction is the long one. Refusing at
// construction turns that into a boot failure instead.
//
// A non-positive lifetime is refused for the same reason `platform/cache`
// refuses one: it reads as "forever", and forever is exactly what a single-use
// credential must not be.
func New(ttls map[Purpose]time.Duration) (*Minter, error) {
	if len(ttls) == 0 {
		return nil, fmt.Errorf("secret: at least one purpose and its lifetime are required")
	}
	for purpose, ttl := range ttls {
		if purpose == "" {
			return nil, fmt.Errorf("secret: the empty purpose has no meaning; an unscoped " +
				"token can be redeemed in a flow it was never issued for")
		}
		if ttl <= 0 {
			return nil, fmt.Errorf("secret: %q declares a lifetime of %s; a token that never "+
				"expires is a permanent credential in somebody's inbox", purpose, ttl)
		}
	}
	return &Minter{rand: rand.Reader, ttls: maps.Clone(ttls)}, nil
}

// Mint creates a token for a purpose.
func (m *Minter) Mint(purpose Purpose, now time.Time) (Token, error) {
	// The empty purpose is reported as MISSING rather than as unknown, and the
	// distinction is worth a branch: "unknown purpose" sends a reader looking for
	// a typo in a constant, while the actual fault is a caller that passed
	// nothing — most often a zero-valued variable that was never set.
	if purpose == "" {
		return Token{}, fmt.Errorf("secret: a purpose is required; an unscoped token can be " +
			"redeemed in a flow it was never issued for")
	}
	ttl, err := m.TTLFor(purpose)
	if err != nil {
		return Token{}, err
	}

	raw := make([]byte, Bytes)
	if _, err := io.ReadFull(m.rand, raw); err != nil {
		// Refused, never degraded. A short read leaves trailing zero bytes, and
		// a token whose tail is predictable is one an attacker can search.
		return Token{}, fmt.Errorf("secret: generating a token: %w", err)
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

// TTLFor reports how long a purpose's tokens live.
func (m *Minter) TTLFor(purpose Purpose) (time.Duration, error) {
	ttl, ok := m.ttls[purpose]
	if !ok {
		return 0, fmt.Errorf("secret: unknown purpose %q; every purpose must declare its own "+
			"lifetime", purpose)
	}
	return ttl, nil
}

// Digest is what gets stored and what a presented token is hashed to.
//
// The purpose is a length-prefixed prefix rather than a plain concatenation.
// With plain concatenation, ("ab", "cd") and ("a", "bcd") hash identically — and
// while no current purpose can collide that way, the property would hold because
// of the constant values chosen today rather than because of anything this
// function does.
//
// A package-level function, not a method: verifying a presented token needs the
// same derivation and has no reason to hold a minter.
func Digest(purpose Purpose, plaintext string) []byte {
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
// Used where a caller holds both — a store's comparison is a lookup rather than
// a comparison, so it is already immune. This exists so no caller reaches for
// bytes.Equal on a security-relevant value.
func Equal(a, b []byte) bool { return subtle.ConstantTimeCompare(a, b) == 1 }
