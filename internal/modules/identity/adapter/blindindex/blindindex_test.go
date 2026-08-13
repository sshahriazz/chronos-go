package blindindex_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

func newIndex(t *testing.T) *blindindex.Index {
	t.Helper()
	key := make([]byte, blindindex.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	idx, err := blindindex.New(key)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	return idx
}

// Addresses that are the same mailbox produce the same index.
//
// Each pair here is a distinct normalization rule. If any one stops being
// applied, the user registers, cannot sign in, and registers AGAIN — so the
// failure is a duplicate account holding half their data, not a login error
// anyone would report as a bug.
func TestEquivalentAddressesShareAnIndex(t *testing.T) {
	idx := newIndex(t)
	for _, tc := range []struct{ name, a, b string }{
		{"domain case", "user@example.com", "user@EXAMPLE.COM"},
		{"local case", "User@example.com", "user@example.com"},
		// A quoted local part may legitimately contain '@'. Splitting on the
		// FIRST one takes the domain to be b"@example.com, which idna rejects —
		// so the address stops resolving entirely rather than indexing wrongly.
		{"quoted local part containing an at sign",
			`"a@b"@example.com`, `"a@b"@EXAMPLE.com`},
		{"surrounding space", "  user@example.com  ", "user@example.com"},
		{"unicode domain to punycode", "user@münchen.de", "user@xn--mnchen-3ya.de"},
		{"mixed case unicode domain", "user@MÜNCHEN.de", "user@xn--mnchen-3ya.de"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := idx.Of(tc.a)
			if err != nil {
				t.Fatalf("%q: %v", tc.a, err)
			}
			b, err := idx.Of(tc.b)
			if err != nil {
				t.Fatalf("%q: %v", tc.b, err)
			}
			if a != b {
				t.Fatalf("%q and %q index differently: the same person registers twice and "+
					"ends up with two accounts", tc.a, tc.b)
			}
		})
	}
}

// Addresses that are genuinely different must NOT collide.
//
// Dots and +tags are the ones that matter. Stripping them is a common
// "normalization" that merges addresses which are separate mailboxes at most
// providers — and merging means delivering one person's password reset to
// another's inbox.
func TestGenuinelyDifferentAddressesDoNotShareAnIndex(t *testing.T) {
	idx := newIndex(t)
	for _, tc := range []struct{ name, a, b string }{
		{"plus tag", "user+tag@example.com", "user@example.com"},
		{"dots in local part", "u.ser@example.com", "user@example.com"},
		{"different domain", "user@example.com", "user@example.org"},
		{"different local part", "user@example.com", "usar@example.com"},
		{"subdomain", "user@mail.example.com", "user@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := idx.Of(tc.a)
			if err != nil {
				t.Fatalf("%q: %v", tc.a, err)
			}
			b, err := idx.Of(tc.b)
			if err != nil {
				t.Fatalf("%q: %v", tc.b, err)
			}
			if a == b {
				t.Fatalf("%q and %q share an index: two separate mailboxes are treated as "+
					"one account, so a password reset can reach the wrong person", tc.a, tc.b)
			}
		})
	}
}

// The index is FULL WIDTH — 32 bytes, 64 hex characters.
//
// The truncation IDENTITY-REVIEW C7 named. A shortened index collides, and under
// the UNIQUE constraint that enforces address uniqueness a collision means one
// person's registration fails because an unrelated stranger's address shares a
// prefix — unreproducible, unexplainable, and an oracle for the attacker who
// engineered it.
func TestTheIndexIsFullWidth(t *testing.T) {
	idx := newIndex(t)
	got, err := idx.Of("user@example.com")
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	if len(got) != 64 {
		t.Fatalf("the index is %d hex characters (%d bytes); it must be the full 32-byte "+
			"HMAC output, or collisions make an unrelated stranger's address block a "+
			"registration", len(got), len(got)/2)
	}
}

// The key actually keys the index.
//
// A plain hash would pass every test above. What separates it from a blind index
// is that a different key gives a different value — which is what makes the
// database alone useless for enumerating addresses.
func TestADifferentKeyGivesADifferentIndex(t *testing.T) {
	a := newIndex(t)

	otherKey := make([]byte, blindindex.KeySize)
	for i := range otherKey {
		otherKey[i] = byte(255 - i)
	}
	b, err := blindindex.New(otherKey)
	if err != nil {
		t.Fatalf("index: %v", err)
	}

	x, err := a.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	y, err := b.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if x == y {
		t.Fatal("the index does not depend on the key: it is a plain hash, and the space of " +
			"real email addresses is small enough to enumerate offline from a database dump")
	}
}

// The deriver copies its key.
//
// A caller that zeroes its own buffer after wiring — the correct thing to do —
// must not silently turn every future index into HMAC-under-a-zero-key. That
// failure is invisible: indexes still derive, they are just all derived under a
// key an attacker can guess.
func TestTheKeyIsCopiedNotRetained(t *testing.T) {
	key := make([]byte, blindindex.KeySize)
	for i := range key {
		key[i] = byte(i)
	}
	idx, err := blindindex.New(key)
	if err != nil {
		t.Fatalf("index: %v", err)
	}
	before, err := idx.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	for i := range key { // caller wipes its buffer
		key[i] = 0
	}

	after, err := idx.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	if before != after {
		t.Fatal("zeroing the caller's key buffer changed the index: the deriver aliases the " +
			"caller's slice, so every index after a well-behaved wipe is keyed with zeroes")
	}
}

// The stream key composes into a valid KurrentDB stream id.
//
// Hex cannot contain a dash, so this always holds — but it is asserted rather
// than assumed, because a change to the encoding (base64, say) would silently
// produce keys containing '+' and '/' and, worse, a category split at the wrong
// place.
func TestTheStreamKeyComposesIntoAValidStreamID(t *testing.T) {
	idx := newIndex(t)
	key, err := idx.StreamKey("user@example.com")
	if err != nil {
		t.Fatalf("stream key: %v", err)
	}
	stream, err := eventsourcing.NewStreamID(blindindex.Category, key)
	if err != nil {
		t.Fatalf("the derived key is not a valid stream key: %v", err)
	}
	if got := string(stream.Category()); got != blindindex.Category {
		t.Fatalf("the stream files under category %q, not %q: every prefix-filtered "+
			"subscription misses it", got, blindindex.Category)
	}
	if stream.Key() != key {
		t.Errorf("the stream key round-trips to %q, not %q", stream.Key(), key)
	}
}

// The stream key and the lookup index are the same value.
//
// Two derivations for one address would let the stream that ENFORCES uniqueness
// and the column that REPORTS it disagree — and the disagreement would look
// exactly like ordinary projection lag, which is the one thing nobody
// investigates.
func TestTheStreamKeyAndTheLookupIndexAgree(t *testing.T) {
	idx := newIndex(t)
	const addr = "user@example.com"

	index, err := idx.Of(addr)
	if err != nil {
		t.Fatal(err)
	}
	key, err := idx.StreamKey(addr)
	if err != nil {
		t.Fatal(err)
	}
	if string(index) != key {
		t.Fatalf("the lookup index (%s) and the stream key (%s) differ: uniqueness is "+
			"enforced against one value and reported against another", index, key)
	}
}

// Matches is equivalent to comparing indexes, and tolerates a bad address.
func TestMatchesAgreesWithDerivation(t *testing.T) {
	idx := newIndex(t)
	index, err := idx.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}

	if !idx.Matches("USER@Example.COM", index) {
		t.Error("Matches rejected an address that derives to the same index")
	}
	if idx.Matches("other@example.com", index) {
		t.Error("Matches accepted an address that derives to a different index")
	}
	if idx.Matches("not an address", index) {
		t.Error("Matches accepted an unparseable address")
	}
	if idx.Matches("user@example.com", "") {
		t.Error("Matches accepted an empty index")
	}
}

// A malformed key is refused.
func TestAMalformedKeyIsRefused(t *testing.T) {
	for _, n := range []int{0, 16, 31, 33, 64} {
		if _, err := blindindex.New(make([]byte, n)); err == nil {
			t.Errorf("a %d-byte key was accepted; HMAC-SHA256 keying here requires exactly %d",
				n, blindindex.KeySize)
		}
	}
}

// Addresses that cannot be normalized are refused rather than indexed.
//
// Indexing an unparseable address would reserve a stream nobody can ever receive
// mail at, and the reservation is permanent.
func TestUnusableAddressesAreRefused(t *testing.T) {
	idx := newIndex(t)
	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"only space", "   "},
		{"no at sign", "userexample.com"},
		{"no local part", "@example.com"},
		{"no domain", "user@"},
		{"dotless domain", "user@localhost"},
		{"control character", "user\x00name@example.com"},
		{"newline in local part", "user\nname@example.com"},
		{"local part too long", strings.Repeat("a", 65) + "@example.com"},
		// Over the TOTAL limit while the local part is legal, so the whole-address
		// cap is what has to reject it. The obvious fixture — 250 a's before the
		// '@' — is caught by the 64-byte local-part rule instead, and passes
		// happily with the total cap deleted.
		{"over the total length limit",
			strings.Repeat("a", 64) + "@" + strings.Repeat("b", 63) + "." +
				strings.Repeat("c", 63) + "." + strings.Repeat("d", 63) + ".com"},
		{"invalid utf-8", "user\xff@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := idx.Of(tc.in); err == nil {
				t.Fatalf("%q was accepted and indexed", tc.in)
			}
		})
	}
}

// Deriving is deterministic across calls.
func TestDerivationIsStable(t *testing.T) {
	idx := newIndex(t)
	first, err := idx.Of("user@example.com")
	if err != nil {
		t.Fatal(err)
	}
	for range 10 {
		again, err := idx.Of("user@example.com")
		if err != nil {
			t.Fatal(err)
		}
		if again != first {
			t.Fatal("the index is not stable across calls: a reservation written on one " +
				"request cannot be found by the next")
		}
	}
}
