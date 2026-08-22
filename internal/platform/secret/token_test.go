package secret

import (
	"crypto/rand"
	"encoding/base64"
	"io"
	"strings"
	"testing"
	"time"
)

const (
	verify Purpose = "email_verification"
	reset  Purpose = "password_reset"
	invite Purpose = "workspace_invitation"
)

var at = time.Date(2026, 8, 22, 12, 0, 0, 0, time.UTC)

func minter(t *testing.T) *Minter {
	t.Helper()
	m, err := New(map[Purpose]time.Duration{
		verify: 24 * time.Hour,
		reset:  time.Hour,
		invite: 7 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return m
}

// A FAILING ENTROPY SOURCE FAILS THE MINT rather than producing a weak token.
//
// A short read leaves trailing zeroes, and a token whose tail is predictable is
// one an attacker can search. This test moved here with the read itself: the
// branch is the primitive's, and reaching it needs the unexported entropy field,
// which only this package's own tests can touch.
func TestAFailingEntropySourceFailsTheMint(t *testing.T) {
	m := minter(t)
	m.rand = io.LimitReader(rand.Reader, 4)

	if _, err := m.Mint(verify, at); err == nil {
		t.Fatal("a token was minted from a short entropy read: its tail is zeroes, and every " +
			"token minted while the source is degraded shares that structure")
	}
}

// A TOKEN CANNOT BE REDEEMED IN A FLOW IT WAS NOT ISSUED FOR.
//
// The purpose is mixed into the digest rather than stored beside it, so this
// holds even for a store that forgot to filter by purpose — defence at the layer
// that cannot be forgotten.
func TestATokenCannotCrossPurposes(t *testing.T) {
	m := minter(t)
	minted, err := m.Mint(verify, at)
	if err != nil {
		t.Fatal(err)
	}

	for _, other := range []Purpose{reset, invite} {
		if Equal(minted.Digest, Digest(other, minted.Plaintext)) {
			t.Fatalf("a %s token hashes to the same value as a %s one, so a store that did "+
				"not filter by purpose would redeem it in the wrong flow", verify, other)
		}
	}
	if !Equal(minted.Digest, Digest(verify, minted.Plaintext)) {
		t.Fatal("the minted digest does not match its own purpose, so nothing can be redeemed")
	}
}

// THE PURPOSE BOUNDARY CANNOT BE SHIFTED.
//
// Without the fixed-width length prefix, ("ab", "cd") and ("a", "bcd") hash
// identically. No purpose in use today can collide that way, which is exactly
// why this is asserted: the property would otherwise hold because of the
// constants chosen today rather than because of the construction.
func TestThePurposeBoundaryCannotBeShifted(t *testing.T) {
	if Equal(Digest("ab", "cd"), Digest("a", "bcd")) {
		t.Fatal("the purpose and the token are concatenated without a length prefix, so a " +
			"purpose chosen to end where another begins produces the same digest")
	}
}

// EVERY LIFETIME IS DECLARED. There is no default.
//
// A fallback would give a newly added flow whichever window happened to be the
// default, silently, and the dangerous direction is the long one.
func TestAnUndeclaredPurposeCannotMint(t *testing.T) {
	m := minter(t)
	if _, err := m.Mint("some_new_flow", at); err == nil {
		t.Fatal("a purpose with no declared lifetime minted a token, so a flow added without " +
			"a lifetime silently inherits one")
	}
}

// An EMPTY purpose is reported as missing, not as unknown.
//
// "Unknown purpose" sends a reader looking for a typo in a constant; the actual
// fault is a caller that passed nothing.
func TestAnEmptyPurposeIsReportedAsMissing(t *testing.T) {
	m := minter(t)
	_, err := m.Mint("", at)
	if err == nil {
		t.Fatal("the empty purpose minted a token")
	}
	if !strings.Contains(err.Error(), "required") {
		t.Errorf("reported %q; an empty purpose is a missing value rather than an unknown "+
			"one, and the message is what sends somebody to the right place", err)
	}
}

// THE LIFETIME TABLE IS VALIDATED AT CONSTRUCTION, so a bad one is a boot
// failure rather than a token that never expires.
func TestNewRefusesAnUnusableTable(t *testing.T) {
	tests := []struct {
		name string
		ttls map[Purpose]time.Duration
		why  string
	}{
		{
			name: "empty", ttls: map[Purpose]time.Duration{},
			why: "a minter that can mint nothing is a wiring fault, not a configuration",
		},
		{
			name: "empty purpose", ttls: map[Purpose]time.Duration{"": time.Hour},
			why: "an unscoped token can be redeemed in a flow it was never issued for",
		},
		{
			name: "zero lifetime", ttls: map[Purpose]time.Duration{verify: 0},
			why: "zero reads as forever, and forever is what a single-use secret must not be",
		},
		{
			name: "negative lifetime", ttls: map[Purpose]time.Duration{verify: -time.Hour},
			why: "a token that is already expired can never be redeemed at all",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := New(tt.ttls); err == nil {
				t.Fatalf("accepted it: %s", tt.why)
			}
		})
	}
}

// The table is COPIED, so a caller mutating the map afterwards cannot change a
// token's lifetime out from under the minter.
func TestTheLifetimeTableIsCopied(t *testing.T) {
	ttls := map[Purpose]time.Duration{verify: time.Hour}
	m, err := New(ttls)
	if err != nil {
		t.Fatal(err)
	}
	ttls[verify] = 100 * 24 * time.Hour
	delete(ttls, verify)

	got, err := m.TTLFor(verify)
	if err != nil {
		t.Fatalf("the minter lost a purpose when the caller's map changed: %v", err)
	}
	if got != time.Hour {
		t.Errorf("the lifetime became %s after the caller mutated their map, want 1h", got)
	}
}

// A token carries its FULL entropy and survives a URL unescaped.
func TestATokenIsFullEntropyAndURLSafe(t *testing.T) {
	m := minter(t)
	minted, err := m.Mint(invite, at)
	if err != nil {
		t.Fatal(err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(minted.Plaintext)
	if err != nil {
		t.Fatalf("the token is not base64url, so a mail client rewriting the link may mangle "+
			"it: %v", err)
	}
	if len(raw) != Bytes {
		t.Errorf("the token carries %d bytes, want %d", len(raw), Bytes)
	}
	if strings.ContainsAny(minted.Plaintext, "+/=") {
		t.Errorf("the token contains a character that needs escaping in a URL: %q",
			minted.Plaintext)
	}
	if len(minted.Digest) != 32 {
		t.Errorf("the digest is %d bytes, want 32", len(minted.Digest))
	}
}

// Expiry comes from the purpose's own lifetime, measured from the caller's
// clock, so a test clock and a leap second both behave.
func TestExpiryFollowsThePurpose(t *testing.T) {
	m := minter(t)
	for purpose, want := range map[Purpose]time.Duration{
		verify: 24 * time.Hour,
		reset:  time.Hour,
		invite: 7 * 24 * time.Hour,
	} {
		minted, err := m.Mint(purpose, at)
		if err != nil {
			t.Fatal(err)
		}
		if got := minted.ExpiresAt.Sub(at); got != want {
			t.Errorf("%s expires in %s, want %s", purpose, got, want)
		}
		if minted.ExpiresAt.Location() != time.UTC {
			t.Errorf("%s expires in %s, not UTC", purpose, minted.ExpiresAt.Location())
		}
	}
}

// Two mints never collide.
func TestEveryTokenIsUnique(t *testing.T) {
	m := minter(t)
	seen := map[string]bool{}
	for range 1000 {
		minted, err := m.Mint(verify, at)
		if err != nil {
			t.Fatal(err)
		}
		if seen[minted.Plaintext] {
			t.Fatal("two mints produced the same token, so the entropy source is not random")
		}
		seen[minted.Plaintext] = true
	}
}

// Equal compares CONTENT, not identity.
func TestEqualComparesContent(t *testing.T) {
	a := Digest(verify, "token")
	b := Digest(verify, "token")
	if !Equal(a, b) {
		t.Error("two digests of the same input compared unequal")
	}
	if Equal(a, Digest(verify, "tokeo")) {
		t.Error("digests of different inputs compared equal")
	}
	if Equal(a, nil) || Equal(a, a[:31]) {
		t.Error("a digest compared equal to something of a different length")
	}
}
