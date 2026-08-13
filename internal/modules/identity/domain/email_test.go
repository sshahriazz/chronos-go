package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
)

// The LOCAL part is NFC-normalized.
//
// Asserted separately from the domain because nothing else normalizes it. The
// domain gets NFC for free from idna.Lookup.ToASCII; the local part passes
// through untouched unless this code does it, so a missing norm.NFC there is a
// silent duplicate-account bug for anyone whose address contains an accent.
func TestTheLocalPartIsNFCNormalized(t *testing.T) {
	for _, tc := range []struct {
		name       string
		composed   string
		decomposed string
	}{
		// Written with explicit escapes for the decomposed side. Typing both
		// forms as literals looks right and produces IDENTICAL bytes — the
		// editor normalizes as you type — so the test passes against a build
		// with no normalization at all.
		{"e acute", "caf\u00e9@example.com", "cafe\u0301@example.com"},
		{"o umlaut", "sch\u00f6n@example.com", "scho\u0308n@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := domain.NormalizeEmail(tc.composed)
			if err != nil {
				t.Fatalf("composed: %v", err)
			}
			b, err := domain.NormalizeEmail(tc.decomposed)
			if err != nil {
				t.Fatalf("decomposed: %v", err)
			}
			if a != b {
				t.Fatalf("the same local part in two encodings normalized to %q and %q: the "+
					"person registers, cannot sign in, registers again, and now holds two "+
					"accounts", a, b)
			}
		})
	}
}

// NFC, not NFKC — the local part keeps compatibility-distinct characters
// distinct.
//
// NFKC would fold "ﬁre@x.com" onto "fire@x.com". Those are different mailboxes
// at every provider, so folding them means one person's password reset is
// delivered to another person's inbox.
func TestTheLocalPartIsNotNFKCFolded(t *testing.T) {
	for _, tc := range []struct{ name, a, b string }{
		{"fi ligature", "ﬁre@example.com", "fire@example.com"},
		{"superscript two", "user²@example.com", "user2@example.com"},
		{"fullwidth latin", "ｕser@example.com", "user@example.com"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, err := domain.NormalizeEmail(tc.a)
			if err != nil {
				t.Fatalf("%q: %v", tc.a, err)
			}
			b, err := domain.NormalizeEmail(tc.b)
			if err != nil {
				t.Fatalf("%q: %v", tc.b, err)
			}
			if a == b {
				t.Errorf("%q and %q normalized to the same address (%q): NFKC is being applied "+
					"where NFC is required, and mail for one reaches the other", tc.a, tc.b, a)
			}
		})
	}
}

// An empty address is refused by name, not by falling through to a structural
// complaint.
//
// The check is redundant for SAFETY — an empty string has no '@', so the
// structural check below refuses it anyway — and it is not redundant for the
// person reading the message. "An email address is required" tells them what to
// do; "must contain a local part and a domain" describes a grammar they did not
// attempt to write.
func TestAnEmptyAddressIsRefusedByName(t *testing.T) {
	for _, in := range []string{"", "   ", "\t\n"} {
		_, err := domain.NormalizeEmail(in)
		if err == nil {
			t.Fatalf("%q was accepted", in)
		}
		if !strings.Contains(err.Error(), "required") {
			t.Errorf("%q produced %q; an absent address should be reported as required rather "+
				"than as a malformed one", in, err)
		}
	}
}

// Normalization is idempotent.
//
// The stored form is re-normalized on every comparison, so a second pass that
// changed anything would mean an address stops matching itself.
func TestEmailNormalizationIsIdempotent(t *testing.T) {
	for _, in := range []string{
		"User@Example.COM",
		"café@münchen.de",
		`"a@b"@example.com`,
		"user+tag@sub.example.co.uk",
	} {
		once, err := domain.NormalizeEmail(in)
		if err != nil {
			t.Fatalf("%q: %v", in, err)
		}
		twice, err := domain.NormalizeEmail(once)
		if err != nil {
			t.Fatalf("%q re-normalized: %v", once, err)
		}
		if once != twice {
			t.Errorf("%q normalized to %q then %q: an address stops matching itself on the "+
				"second pass", in, once, twice)
		}
	}
}
