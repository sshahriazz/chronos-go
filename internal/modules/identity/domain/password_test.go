package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// The same password typed on two operating systems must produce the same
// normalized string.
//
// This is the failure NFC exists to prevent, and it is invisible without a test
// like this one: an ASCII password normalizes to itself, so a build with no
// normalization at all passes every test written with ASCII fixtures. The user
// who set their password on macOS and cannot sign in on Linux discovers it
// instead.
func TestTheSamePasswordInTwoEncodingsNormalizesIdentically(t *testing.T) {
	for _, tc := range []struct {
		name       string
		composed   string // single code point
		decomposed string // base + combining mark
	}{
		{"e acute", "café-longer", "café-longer"},
		{"a ring", "ångstrom1", "ångstrom1"},
		{"o umlaut", "schönespw", "schönespw"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := domain.NormalizePassword(tc.composed)
			if err != nil {
				t.Fatalf("composed form rejected: %v", err)
			}
			b, err := domain.NormalizePassword(tc.decomposed)
			if err != nil {
				t.Fatalf("decomposed form rejected: %v", err)
			}
			if a != b {
				t.Fatalf("the same password normalizes to two different strings (%q vs %q): "+
					"a user who sets it on one platform cannot sign in on another",
					a, b)
			}
		})
	}
}

// Compatibility-equivalent strings must stay DISTINCT.
//
// NFKC would fold these together, which looks like more normalization and is
// actually entropy loss: two passwords the user chose to be different become the
// same one. The distinction between NFC and NFKC is a single identifier in the
// source, so this is the test that stops a well-meaning change.
func TestCompatibilityEquivalentPasswordsStayDifferent(t *testing.T) {
	for _, tc := range []struct{ a, b string }{
		{"ﬁreproofing", "fireproofing"}, // U+FB01 LATIN SMALL LIGATURE FI
		{"squared²pw", "squared2pw"},    // U+00B2 SUPERSCRIPT TWO
	} {
		got, err := domain.NormalizePassword(tc.a)
		if err != nil {
			t.Fatalf("%q rejected: %v", tc.a, err)
		}
		other, err := domain.NormalizePassword(tc.b)
		if err != nil {
			t.Fatalf("%q rejected: %v", tc.b, err)
		}
		if got == other {
			t.Errorf("%q and %q normalized to the same string: NFKC is being applied where "+
				"NFC is required, and two deliberately different passwords collide",
				tc.a, tc.b)
		}
	}
}

// Every kind of Unicode space becomes an ordinary one.
//
// Mobile keyboards insert U+00A0 after certain autocorrections. Without this
// mapping, the password set on a phone cannot be typed on a laptop.
func TestExoticSpacesMapToAnOrdinarySpace(t *testing.T) {
	base := "two words here"
	want, err := domain.NormalizePassword(base)
	if err != nil {
		t.Fatalf("baseline rejected: %v", err)
	}
	for _, space := range []string{" ", " ", "　", " "} {
		got, err := domain.NormalizePassword(strings.ReplaceAll(base, " ", space))
		if err != nil {
			t.Errorf("password containing %q rejected: %v", space, err)
			continue
		}
		if got != want {
			t.Errorf("a password using %q did not normalize to the plain-space form", space)
		}
	}
}

// Case and width are NOT folded. Both would discard entropy the user chose.
func TestCaseAndWidthAreNotFolded(t *testing.T) {
	lower, err := domain.NormalizePassword("correcthorse")
	if err != nil {
		t.Fatal(err)
	}
	upper, err := domain.NormalizePassword("CORRECTHORSE")
	if err != nil {
		t.Fatal(err)
	}
	if lower == upper {
		t.Fatal("case was folded: every password loses roughly one bit per letter, and " +
			"\"password\" and \"PASSWORD\" become the same secret")
	}
}

// Invisible and structural characters are refused rather than silently stripped.
//
// Stripping is the tempting option and the wrong one: it stores a hash for a
// password that differs from what the user typed, so the next login — which
// strips identically — works, and any other client does not.
func TestInvisibleCharactersAreRefused(t *testing.T) {
	for _, tc := range []struct{ name, in string }{
		{"newline", "pass\nword1"},
		{"carriage return", "pass\rword1"},
		{"tab", "pass\tword1"},
		{"null", "pass\x00word1"},
		{"zero-width joiner", "pass\u200dword1"},
		{"left-to-right mark", "pass\u200eword1"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := domain.NormalizePassword(tc.in); err == nil {
				t.Fatalf("a password containing a %s was accepted", tc.name)
			}
		})
	}
}

// Invalid UTF-8 is refused up front.
//
// Ranging over invalid UTF-8 yields U+FFFD silently, so without the explicit
// check the mangled input would be normalized and hashed — and the correct
// password would never reproduce that hash.
func TestInvalidUTF8IsRefused(t *testing.T) {
	if _, err := domain.NormalizePassword("valid\xffinput"); err == nil {
		t.Fatal("invalid UTF-8 was accepted: the stored hash is of mojibake that the real " +
			"password never reproduces")
	}
}

// The length floor is counted in CHARACTERS, not bytes.
//
// Eight 3-byte runes is 24 bytes. A byte-counted minimum would accept a
// three-character password made of CJK ideographs, and reject an eight-character
// one that happens to be accented.
func TestTheMinimumIsCountedInCharacters(t *testing.T) {
	if _, err := domain.NormalizePassword("短短短"); err == nil {
		t.Error("a three-character password was accepted: the minimum is being counted in " +
			"bytes, so any short non-ASCII password passes")
	}
	if _, err := domain.NormalizePassword("日本語のパスワード"); err != nil {
		t.Errorf("a nine-character password was rejected: %v", err)
	}
	if _, err := domain.NormalizePassword("1234567"); err == nil {
		t.Error("a seven-character password was accepted")
	}
	if _, err := domain.NormalizePassword("12345678"); err != nil {
		t.Errorf("an eight-character password was rejected: %v", err)
	}
}

// A long passphrase is accepted. NIST requires at least 64 characters.
func TestALongPassphraseIsAccepted(t *testing.T) {
	long := strings.Repeat("correct horse battery staple ", 4) // 116 characters
	if _, err := domain.NormalizePassword(long); err != nil {
		t.Fatalf("a %d-character passphrase was rejected: %v", len([]rune(long)), err)
	}
}

// The byte cap bounds the work one request can cause.
func TestAnAbsurdlyLongInputIsRefused(t *testing.T) {
	if _, err := domain.NormalizePassword(strings.Repeat("a", domain.MaxPasswordBytes+1)); err == nil {
		t.Fatal("an oversized password was accepted: normalization cost is unbounded per request")
	}
}

// Normalization is idempotent. Applying it twice must not change the result, or
// a rehash on login would produce a different verifier from the one stored.
func TestNormalizationIsIdempotent(t *testing.T) {
	once, err := domain.NormalizePassword("café naıve pw")
	if err != nil {
		t.Fatal(err)
	}
	twice, err := domain.NormalizePassword(once)
	if err != nil {
		t.Fatal(err)
	}
	if once != twice {
		t.Fatalf("normalizing twice changed the result (%q -> %q): a transparent rehash on "+
			"login would store a verifier the same password no longer matches", once, twice)
	}
}
