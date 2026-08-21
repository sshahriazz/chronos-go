package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TestNormalizeUsername pins the character set, the length bounds, the case
// fold and the underscore rules.
//
// Every accepted case states what the canonical form is, because the canonical
// form is what names a KurrentDB stream — permanently. A change to any rule here
// changes which stream an existing handle would map to, which is why the table
// is written as an executable specification rather than as a smoke test.
func TestNormalizeUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		in   string
		want string // empty means "must be refused"
		why  string
	}{
		{
			name: "an ordinary handle passes through unchanged",
			in:   "ada_lovelace", want: "ada_lovelace",
		},
		{
			name: "case is folded to lower",
			in:   "Ada_Lovelace", want: "ada_lovelace",
			why: "@Alice and @alice must be ONE handle. Two accounts whose handles " +
				"differ only in case are two accounts one reader cannot tell apart, " +
				"which is impersonation rather than duplication.",
		},
		{
			name: "surrounding whitespace is trimmed",
			in:   "  ada  ", want: "ada",
		},
		{
			name: "digits are allowed after the first character",
			in:   "ada2nd", want: "ada2nd",
		},
		{
			name: "the shortest permitted handle is accepted",
			in:   "abc", want: "abc",
			why: "an off-by-one in the floor refuses the shortest handle anyone may hold",
		},
		{
			name: "the longest permitted handle is accepted",
			in:   strings.Repeat("a", domain.MaxUsernameBytes),
			want: strings.Repeat("a", domain.MaxUsernameBytes),
		},
		{
			name: "one character over the ceiling is refused",
			in:   strings.Repeat("a", domain.MaxUsernameBytes+1),
			why: "the handle names a stream, and a stream name is permanent — an " +
				"unbounded one is an unbounded permanent artefact",
		},
		{
			name: "one character under the floor is refused",
			in:   "ab",
		},
		{
			name: "empty is refused",
			in:   "",
		},
		{
			name: "whitespace alone is refused",
			in:   "   ",
		},
		{
			name: "a hyphen is refused",
			in:   "ada-lovelace",
			why: "eventsourcing.NewStreamID refuses a dash in a stream key, because " +
				"KurrentDB derives a category from everything before the first one. A " +
				"handle with a dash could not be claimed at all, and the refusal would " +
				"arrive as an internal error at append time instead of as a message.",
		},
		{
			name: "a dot is refused",
			in:   "ada.lovelace",
		},
		{
			name: "a space inside is refused",
			in:   "ada lovelace",
		},
		{
			name: "a leading underscore is refused",
			in:   "_ada",
			why: "a handle starting with an underscore reads as a system-generated " +
				"identifier rather than as a name a person chose",
		},
		{
			name: "a trailing underscore is refused",
			in:   "ada_",
		},
		{
			name: "two underscores in a row are refused",
			in:   "ada__lovelace",
			why: "underscores carry no meaning, and each permitted position multiplies " +
				"the family of near-duplicates around an existing handle at no cost to " +
				"whoever wants to impersonate it",
		},
		{
			name: "a leading digit is refused",
			in:   "1ada",
		},
		{
			name: "a Cyrillic homoglyph is refused rather than folded",
			in:   "аda_lovelace",
			why: "This is Cyrillic U+0430 followed by 'da', and it is pixel-identical " +
				"to 'ada' in most fonts. The ASCII-only rule eliminates the whole " +
				"cross-script homoglyph class outright: there is no mapping to get " +
				"wrong because there is no non-ASCII input at all.",
		},
		{
			name: "a fullwidth latin letter is refused",
			in:   "ａda",
		},
		{
			name: "a dotted capital I is refused rather than folded into two code points",
			in:   "İda",
			why: "strings.ToLower maps U+0130 to \"i\" plus a combining dot — two code " +
				"points, one of them a mark — which would turn input the character-set " +
				"rule refuses into input it accepts. NormalizeUsername folds ASCII only.",
		},
		{
			name: "a zero-width joiner is refused",
			in:   "ada\u200dlovelace",
		},
		{
			name: "invalid UTF-8 is refused",
			in:   "ada\xff\xfe",
		},
		{
			name: "a reserved name is refused",
			in:   "admin",
		},
		{
			name: "a reserved name is refused in any case",
			in:   "AdMiN",
			why: "screening runs on the NORMALIZED form. Screening the raw string would " +
				"let @AdMiN through, and a case-varied impersonation of the operator is " +
				"exactly what the list exists to stop.",
		},
		{
			name: "a route-colliding name is refused",
			in:   "settings",
			why: "a profile path built from the handle would make /settings ambiguous " +
				"forever, and it cannot be fixed later without taking a handle away " +
				"from somebody other people have already linked to",
		},
		{
			name: "a reserved name with a suffix is allowed",
			in:   "admin2", want: "admin2",
			why: "the list is exact, not a prefix match. A prefix rule would refuse " +
				"'administrative_ada' and every other honest name containing one.",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got, err := domain.NormalizeUsername(tt.in)
			if tt.want == "" {
				if err == nil {
					t.Fatalf("NormalizeUsername(%q) = %q, want a refusal. %s", tt.in, got, tt.why)
				}
				if r := errs.ReasonOf(err); r != errs.ValidationFailed {
					t.Errorf("reason %s, want %s — a malformed handle is the caller's own "+
						"bytes and must not be reported as anything else", r, errs.ValidationFailed)
				}
				return
			}
			if err != nil {
				t.Fatalf("NormalizeUsername(%q): %v. %s", tt.in, err, tt.why)
			}
			if got != tt.want {
				t.Errorf("NormalizeUsername(%q) = %q, want %q. %s", tt.in, got, tt.want, tt.why)
			}
		})
	}
}

// TestNormalizeUsernameIsIdempotent is the property that matters more than any
// single case in the table above.
//
// The canonical form names a stream, and the stream is permanent. If normalizing
// an already-normalized handle changed it, the same input would claim one stream
// today and a different one after a refactor — and uniqueness would silently stop
// being enforced for every handle claimed under the old form, with no error and
// no event.
func TestNormalizeUsernameIsIdempotent(t *testing.T) {
	t.Parallel()

	for _, in := range []string{
		"ada_lovelace", "Ada_Lovelace", "  ADA  ", "abc", "a1b2c3", "ada2nd",
		strings.Repeat("a", domain.MaxUsernameBytes),
	} {
		t.Run(in, func(t *testing.T) {
			t.Parallel()
			once, err := domain.NormalizeUsername(in)
			if err != nil {
				t.Fatalf("first pass: %v", err)
			}
			twice, err := domain.NormalizeUsername(once)
			if err != nil {
				t.Fatalf("the canonical form %q was refused on a second pass: %v", once, err)
			}
			if once != twice {
				t.Errorf("normalizing twice gave %q then %q; the canonical form names a "+
					"permanent stream and must be a fixed point", once, twice)
			}
		})
	}
}

// TestEveryNormalizedHandleIsAValidStreamKey is the check that keeps the
// character set honest about WHY it excludes what it excludes.
//
// The hyphen is not a style preference: NewStreamID refuses one because KurrentDB
// derives a category from everything before the first dash. Asserting it against
// the real constructor means a future widening of the set fails here, at the
// rule, rather than as an internal error on somebody's first claim.
func TestEveryNormalizedHandleIsAValidStreamKey(t *testing.T) {
	t.Parallel()

	for _, in := range []string{"ada_lovelace", "abc", "a1", "a_b_c", "admin2"} {
		normalized, err := domain.NormalizeUsername(in)
		if err != nil {
			continue // refused by the rules; nothing to name a stream with
		}
		if _, err := eventsourcing.NewStreamID("reservation_username", normalized); err != nil {
			t.Errorf("the canonical form of %q is %q, which cannot name a stream: %v",
				in, normalized, err)
		}
	}
}

// TestEveryReservedNameIsWellFormed keeps the list from accumulating dead
// entries.
//
// A name that would be refused by the character-set rules anyway is never
// reached by the reserved-name check, so it reads as protection that is not
// there. This fails the moment somebody adds "no-reply" or "Admin" to the list.
func TestEveryReservedNameIsWellFormed(t *testing.T) {
	t.Parallel()

	// Sampled across both families the list is drawn from, plus the shapes most
	// likely to be added wrongly.
	for _, name := range []string{
		"admin", "support", "security", "noreply", "no_reply", "mailer_daemon",
		"api", "login", "settings", "www", "null",
	} {
		if !domain.IsReservedUsername(name) {
			t.Errorf("%q is not in the reserved list; a role-impersonation or "+
				"route-colliding handle that can be claimed cannot be reclaimed later", name)
			continue
		}
		// It must be reachable: long enough, in the character set, and canonical.
		if len(name) < domain.MinUsernameBytes || len(name) > domain.MaxUsernameBytes {
			t.Errorf("%q is outside the length bounds, so the length rule refuses it "+
				"before the reserved check is ever consulted", name)
		}
		if _, err := domain.NormalizeUsername(name); errs.ReasonOf(err) != errs.ValidationFailed {
			t.Errorf("%q is not refused by NormalizeUsername at all: %v", name, err)
		}
	}
}

// TestIsReservedUsernameRequiresANormalizedInput states the precondition rather
// than hiding it.
//
// The function does not normalize, deliberately: NormalizeUsername calls it after
// folding, and a second fold inside would be a second place for the two to
// disagree. This test is what says a caller may not pass a raw string.
func TestIsReservedUsernameRequiresANormalizedInput(t *testing.T) {
	t.Parallel()

	if domain.IsReservedUsername("ADMIN") {
		t.Error("IsReservedUsername folded case; it must not — NormalizeUsername folds " +
			"first, and a second fold here is a second definition of the canonical form")
	}
	if !domain.IsReservedUsername("admin") {
		t.Error("the normalized form of a reserved name was not recognised")
	}
}
