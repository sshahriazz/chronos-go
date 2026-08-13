package domain

import (
	"unicode"
	"unicode/utf8"

	"github.com/chronos/chronos-go/internal/platform/errs"
	"golang.org/x/text/unicode/norm"
)

// Password policy, in one place, applied identically at set and at verify
// (identity.md §4).
//
// "Identically" is the load-bearing word. A normalization applied when a
// password is set but not when it is checked locks the user out with a password
// they typed correctly — and the failure is invisible in testing, because
// ASCII-only passwords normalize to themselves. Every entry point calls
// NormalizePassword; nothing hashes a raw input.
const (
	// MinPasswordRunes is NIST SP 800-63B-4's floor for a memorized secret used
	// WITH another factor. A second factor is mandatory here before an account
	// becomes active (identity.md §2), so eight is the correct number rather
	// than a lenient one.
	MinPasswordRunes = 8

	// MaxPasswordBytes bounds the input, and is a denial-of-service control
	// rather than a policy. Argon2id's cost is independent of password length,
	// but normalization and copying are not, and an unbounded field is a free
	// way to make one request expensive.
	//
	// Well above the 64-character minimum acceptance NIST requires: a 64-rune
	// password of 4-byte runes is 256 bytes, so this accepts sixteen times the
	// longest password anyone will type.
	MaxPasswordBytes = 4096
)

// NormalizePassword prepares a password for hashing or comparison.
//
// This is RFC 8265's OpaqueString profile, and each step is there for a reason
// that has bitten real systems:
//
//   - Non-ASCII spaces map to U+0020. A password typed on a mobile keyboard that
//     inserts U+00A0 must match the same password typed on a desktop one.
//   - NFC normalization, NOT NFKC. NFC makes "é" as one code point equal to "é"
//     as e + combining acute, which is the same password typed on two operating
//     systems. NFKC would additionally fold compatibility characters, mapping
//     distinct strings — "ﬁ" and "fi" — onto each other and REDUCING entropy.
//   - No case folding and no width folding. Both would discard entropy the user
//     chose deliberately.
//
// Order matters: space mapping happens before normalization, because NFC can
// itself produce characters the mapping would otherwise have caught.
func NormalizePassword(raw string) (string, error) {
	if raw == "" {
		return "", errs.ValidationFailedf("a password is required")
	}
	if len(raw) > MaxPasswordBytes {
		return "", errs.ValidationFailedf(
			"a password may not exceed %d bytes", MaxPasswordBytes)
	}
	if !utf8.ValidString(raw) {
		// Checked up front rather than inferred from U+FFFD during the loop.
		// Ranging over invalid UTF-8 silently yields RuneError, so a mangled
		// input would otherwise be normalized and hashed — producing a stored
		// verifier that the correct password never reproduces.
		return "", errs.ValidationFailedf("a password must be valid UTF-8")
	}

	mapped := make([]rune, 0, len(raw))
	for _, r := range raw {
		switch {
		case unicode.Is(unicode.Zs, r):
			// Every space-separator becomes an ordinary space. U+0020 itself
			// falls in this category and maps to itself.
			mapped = append(mapped, ' ')
		case r == '\t', r == '\n', r == '\r':
			// Whitespace controls are refused rather than mapped. A password
			// containing a newline is almost always a paste artefact, and
			// silently stripping it produces a stored hash for a password the
			// user cannot retype.
			return "", errs.ValidationFailedf("a password may not contain line breaks or tabs")
		case unicode.Is(unicode.Cc, r), unicode.Is(unicode.Cf, r):
			// Control and format characters are disallowed by RFC 8264 §7.5.
			// They are invisible, so a password containing one cannot be
			// reproduced by a human reading it off a screen.
			return "", errs.ValidationFailedf("a password may not contain control characters")
		default:
			mapped = append(mapped, r)
		}
	}

	normalized := norm.NFC.String(string(mapped))
	if utf8.RuneCountInString(normalized) < MinPasswordRunes {
		// The message names the minimum and nothing else. No composition rules
		// exist to report, and none will be added: NIST SP 800-63B-4 removed
		// them because they push users toward predictable substitutions.
		return "", errs.ValidationFailedf(
			"a password must be at least %d characters", MinPasswordRunes)
	}
	return normalized, nil
}
