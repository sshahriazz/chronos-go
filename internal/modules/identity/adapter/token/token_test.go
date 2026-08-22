package token_test

import (
	"encoding/base64"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

var at = time.Date(2026, 8, 12, 12, 0, 0, 0, time.UTC)

// A token round-trips: its plaintext hashes to the digest that was stored.
func TestAMintedTokenHashesToItsStoredDigest(t *testing.T) {
	m := token.New()
	tok, err := m.Mint(app.PurposeEmailVerification, at)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	got := token.Digest(app.PurposeEmailVerification, tok.Plaintext)
	if !token.Equal(got, tok.Digest) {
		t.Fatal("a token does not hash to its own stored digest: every emailed link is dead " +
			"on arrival")
	}
}

// THE ONE THAT MATTERS: a verification token cannot be redeemed as a reset.
//
// Without the purpose binding, an attacker who can cause a verification mail to
// be sent — by registering, or by triggering a resend — holds a password-reset
// token for an account they do not own.
func TestAVerificationTokenCannotBeRedeemedAsAReset(t *testing.T) {
	m := token.New()
	tok, err := m.Mint(app.PurposeEmailVerification, at)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	asReset := token.Digest(app.PurposePasswordReset, tok.Plaintext)
	if token.Equal(asReset, tok.Digest) {
		t.Fatal("a verification token hashes to the same digest as a reset token: anyone who " +
			"can trigger a verification mail obtains a password-reset credential")
	}
}

// The purpose boundary cannot be shifted by a crafted purpose string.
//
// Plain concatenation would let ("ab", "cd") and ("a", "bcd") collide. No
// current pair of purposes can, which is exactly why it is worth asserting: the
// property holds today because of the constants chosen, not because of anything
// the hashing does.
func TestThePurposeBoundaryCannotBeShifted(t *testing.T) {
	a := token.Digest("ab", "cdEFGH")
	b := token.Digest("a", "bcdEFGH")
	if token.Equal(a, b) {
		t.Fatal("the purpose and the token are concatenated without a boundary: a purpose " +
			"chosen to end where the token begins produces a colliding digest")
	}
}

// Every token is different.
func TestEveryTokenIsUnique(t *testing.T) {
	m := token.New()
	seen := map[string]bool{}
	for range 200 {
		tok, err := m.Mint(app.PurposeEmailVerification, at)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if seen[tok.Plaintext] {
			t.Fatal("two tokens collided: the generator is not random, and one person's " +
				"verification link works for another's account")
		}
		seen[tok.Plaintext] = true
	}
}

// A token carries the full 256 bits.
func TestATokenCarriesFullEntropy(t *testing.T) {
	m := token.New()
	tok, err := m.Mint(app.PurposeEmailVerification, at)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	raw, err := base64.RawURLEncoding.DecodeString(tok.Plaintext)
	if err != nil {
		t.Fatalf("the token is not base64url: %v", err)
	}
	if len(raw) != token.Bytes {
		t.Fatalf("the token carries %d bytes, want %d (%d bits)",
			len(raw), token.Bytes, token.Bytes*8)
	}
	// An ABSOLUTE floor, not one derived from the constant. The assertion above
	// follows token.Bytes wherever it goes, so halving the constant satisfies it
	// perfectly — verified by mutation: dropping to 16 bytes passed.
	if token.Bytes < 32 {
		t.Fatalf("tokens carry %d bytes (%d bits); NIST SP 800-63B-4 §5.1.1 sets 128 bits as "+
			"the floor for an out-of-band secret and this system uses 256", token.Bytes, token.Bytes*8)
	}
	if len(raw) < 32 {
		t.Fatalf("a minted token carries only %d bits of entropy", len(raw)*8)
	}
}

// The plaintext is URL-safe and unpadded.
//
// It travels in an emailed link. '+' and '/' need escaping, and '=' is routinely
// mangled by mail clients that rewrite URLs — producing a link that looks right
// and does not work.
func TestTheTokenIsSafeInAURL(t *testing.T) {
	m := token.New()
	for range 50 {
		tok, err := m.Mint(app.PurposePasswordReset, at)
		if err != nil {
			t.Fatalf("mint: %v", err)
		}
		if strings.ContainsAny(tok.Plaintext, "+/=") {
			t.Fatalf("the token %q contains a character that breaks in an emailed link",
				tok.Plaintext)
		}
	}
}

// A reset token expires much sooner than a verification token.
//
// A reset grants account access; a verification confirms an address. Treating
// them the same is the common shortcut, and it leaves account-takeover
// credentials sitting in inboxes for a day.
func TestAResetTokenExpiresSoonerThanAVerificationToken(t *testing.T) {
	m := token.New()

	verification, err := m.Mint(app.PurposeEmailVerification, at)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	reset, err := m.Mint(app.PurposePasswordReset, at)
	if err != nil {
		t.Fatalf("mint: %v", err)
	}

	if !reset.ExpiresAt.Before(verification.ExpiresAt) {
		t.Fatalf("a reset token lives until %v and a verification token until %v: the more "+
			"dangerous credential has the longer window", reset.ExpiresAt, verification.ExpiresAt)
	}
	if got := reset.ExpiresAt.Sub(at); got != token.ResetTTL {
		t.Errorf("reset TTL is %v, want %v", got, token.ResetTTL)
	}
	if got := verification.ExpiresAt.Sub(at); got != token.VerificationTTL {
		t.Errorf("verification TTL is %v, want %v", got, token.VerificationTTL)
	}
	if token.ResetTTL > time.Hour {
		t.Errorf("the reset window is %v; an account-takeover credential should not sit in a "+
			"mailbox that long", token.ResetTTL)
	}
}

// An unknown purpose is refused, and gets no default lifetime.
//
// A fallback would give a newly added flow whichever window happens to be first
// in the switch — silently, and the dangerous direction is the long one.
func TestAnUnknownPurposeIsRefused(t *testing.T) {
	m := token.New()
	for _, purpose := range []app.TokenPurpose{"invite", "magic_link", "EMAIL_VERIFICATION"} {
		if _, err := m.Mint(purpose, at); err == nil {
			t.Errorf("a token was minted for purpose %q with no declared lifetime", purpose)
		}
		if _, err := token.TTLFor(purpose); err == nil {
			t.Errorf("purpose %q resolved to a TTL", purpose)
		}
	}

	// The EMPTY purpose is refused by name. The check is redundant for safety —
	// ttlFor rejects it too — and not redundant for the caller: "a purpose is
	// required" says what to fix, where "unknown purpose \"\"" describes a lookup
	// that failed for a value nobody meant to supply.
	_, err := m.Mint("", at)
	if err == nil {
		t.Fatal("a token was minted with no purpose: it can be redeemed in any flow")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("an empty purpose produced %q; it should be reported as a missing value "+
			"rather than as an unknown one", err)
	}
}

// The entropy source's failure path is asserted in platform/secret, which is
// where the read now happens. A copy here could only reach it through a
// test-only export of another package's unexported field, which does not exist
// across package boundaries — and the branch is the primitive's, not this
// package's policy.

// Digesting is deterministic and order-independent across calls.
func TestDigestingIsDeterministic(t *testing.T) {
	first := token.Digest(app.PurposePasswordReset, "a-fixed-token-value")
	for range 10 {
		again := token.Digest(app.PurposePasswordReset, "a-fixed-token-value")
		if !token.Equal(first, again) {
			t.Fatal("the same token digests differently across calls: a link stops matching " +
				"the digest that was stored for it")
		}
	}
}

// Equal is a comparison, not an identity check.
func TestEqualComparesContent(t *testing.T) {
	a := token.Digest(app.PurposePasswordReset, "x-token-value")
	b := token.Digest(app.PurposePasswordReset, "x-token-value")
	c := token.Digest(app.PurposePasswordReset, "y-token-value")

	if !token.Equal(a, b) {
		t.Error("two digests of the same token compared unequal")
	}
	if token.Equal(a, c) {
		t.Error("digests of different tokens compared equal")
	}
	if token.Equal(a, nil) || token.Equal(a, a[:16]) {
		t.Error("a digest compared equal to a truncated or absent one")
	}
}
