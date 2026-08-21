package ids_test

import (
	"crypto/rand"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// TestThePatternAgreesWithParse is the assertion the whole of PatternFor exists
// for: the published grammar and the parser must accept exactly the same
// strings.
//
// They are two implementations of one rule, and they run in different places —
// the pattern in the validation interceptor, before any handler; Parse inside
// it. When they disagree the interceptor wins, and it wins silently. Both
// directions of disagreement were live in this repository until this test was
// written:
//
//   - the hand-written .proto patterns were uppercase-only while ParseStrict
//     accepts lowercase, so every lowercase identifier was refused at the
//     boundary and no test noticed. Resolved by making PARSE the strict half —
//     see TestOneIdentifierHasOneSpelling for why that direction, not the other;
//   - they allowed any Crockford character first while ParseStrict rejects a
//     leading '8' or above as a timestamp overflow, so the document described
//     identifiers that cannot exist.
//
// The generated half is the load-bearing half: a table of hand-picked strings
// only ever tests the cases somebody thought of, and neither of those two was.
func TestThePatternAgreesWithParse(t *testing.T) {
	t.Parallel()

	re := regexp.MustCompile(ids.Pattern[ids.Session]())

	t.Run("every minted identifier matches", func(t *testing.T) {
		t.Parallel()
		for i := range 2000 {
			// Spread across the whole timestamp range rather than clustering on
			// "now": the leading character is a function of the timestamp, and
			// an hour's worth of identifiers all start with the same one.
			at := time.UnixMilli(int64(i) * 1_000_000_000).UTC()
			got := ids.New[ids.Session](at, rand.Reader).String()
			if !re.MatchString(got) {
				t.Fatalf("PatternFor rejects a freshly minted identifier: %s", got)
			}
		}
	})

	t.Run("the pattern and Parse never disagree", func(t *testing.T) {
		t.Parallel()

		valid := ids.New[ids.Session](time.UnixMilli(1_700_000_000_000).UTC(), rand.Reader).String()
		body := strings.TrimPrefix(valid, "sess_")

		cases := []string{
			valid,
			strings.ToLower(valid),            // non-canonical: refused by both
			strings.ToUpper(valid),            // the canonical rendering
			"sess_" + strings.Repeat("Z", 26), // leading overflow
			"sess_8" + body[1:],               // leading overflow, minimally
			"sess_7" + body[1:],               // the highest leading character
			"sess_" + body[:25] + "I",         // I is not in Crockford
			"sess_" + body[:25] + "L",         // nor L
			"sess_" + body[:25] + "O",         // nor O
			"sess_" + body[:25] + "U",         // nor U
			"sess_" + body[:25],               // one short
			"sess_" + body + "A",              // one long
			"sess_",                           // no body
			body,                              // no prefix
			"usr_" + body,                     // another kind's prefix
			" sess_" + body,                   // leading space
			"sess_" + body + "\n",             // trailing newline
			"prefix_sess_" + body,             // the valid form as a substring
			"sess_" + body + " sess_" + body,  // twice
			"sess_" + strings.ToLower(body[:13]) + strings.ToUpper(body[13:]), // mixed case
			"",
		}

		for _, s := range cases {
			_, err := ids.Parse[ids.Session](s)
			parses := err == nil
			matches := re.MatchString(s)
			if parses != matches {
				t.Errorf("%q: Parse accepts=%v, PatternFor matches=%v — the interceptor and "+
					"the handler disagree about this value", s, parses, matches)
			}
		}
	})
}

// TestOneIdentifierHasOneSpelling pins the decision Parse documents, in the one
// way TestThePatternAgreesWithParse cannot.
//
// That test asserts the pattern and the parser AGREE. Both agreeing to accept
// lowercase would satisfy it perfectly — and would restore the aliasing the
// strictness exists to remove: two strings naming one entity, compared textually
// in OpenFGA tuples, cache keys, channel names and stream names. So the verdict
// itself is asserted here, separately.
//
// If this test is ever in the way, the question to answer first is what happens
// to a tuple written `user:usr_01ARZ…` and checked as `user:usr_01arz…`.
func TestOneIdentifierHasOneSpelling(t *testing.T) {
	t.Parallel()

	canonical := ids.New[ids.User](at, ent).String()

	// The PREFIX is lower case and stays that way — it is a type tag, not part of
	// the base32 body. Only the body is asserted canonical, which is also the only
	// part the case check in Parse looks at.
	body := strings.TrimPrefix(canonical, "usr_")
	if body == canonical {
		t.Fatalf("a minted user identifier is %q, which does not carry the usr_ prefix", canonical)
	}
	if body != strings.ToUpper(body) {
		t.Fatalf("a minted identifier's body is not upper case: %q — the rest of this test is "+
			"asserting the wrong thing", canonical)
	}

	if _, err := ids.Parse[ids.User](canonical); err != nil {
		t.Fatalf("the canonical rendering does not parse: %v", err)
	}

	lower := "usr_" + strings.ToLower(body)
	if _, err := ids.Parse[ids.User](lower); err == nil {
		t.Errorf("Parse accepted %q as well as %q — one identifier now has two spellings, "+
			"and every textual comparison of one (OpenFGA tuples, cache keys, stream names) "+
			"can now miss", lower, canonical)
	}

	if regexp.MustCompile(ids.Pattern[ids.User]()).MatchString(lower) {
		t.Errorf("PatternFor admits %q; the published grammar and Parse have diverged", lower)
	}
}

// TestRenderedLenIsExact keeps `max_len` honest.
//
// A `max_len` above the rendered length admits a string no identifier can be,
// which makes the published bound a suggestion; below it, the interceptor refuses
// every identifier of that kind and the endpoint is simply broken.
func TestRenderedLenIsExact(t *testing.T) {
	t.Parallel()

	for name, prefix := range ids.Registry() {
		want := ids.RenderedLen(prefix)
		got := len(prefix) + 1 + 26
		if want != got {
			t.Errorf("%s: RenderedLen(%q) = %d, want %d", name, prefix, want, got)
		}
	}

	minted := ids.New[ids.Notification](at, ent).String()
	if len(minted) != ids.RenderedLen("notif") {
		t.Errorf("a minted identifier is %d characters, RenderedLen says %d",
			len(minted), ids.RenderedLen("notif"))
	}
}

// TestEveryRegisteredPrefixProducesAUsablePattern walks the whole registry, so a
// kind added later cannot arrive with a grammar nothing checks.
func TestEveryRegisteredPrefixProducesAUsablePattern(t *testing.T) {
	t.Parallel()

	for name, prefix := range ids.Registry() {
		re, err := regexp.Compile(ids.PatternFor(prefix))
		if err != nil {
			t.Errorf("%s: PatternFor(%q) does not compile: %v", name, prefix, err)
			continue
		}
		if !re.MatchString(prefix + "_01ARZ3NDEKTSV4RRFFQ69G5FAV") {
			t.Errorf("%s: PatternFor(%q) rejects a well-formed identifier", name, prefix)
		}
		if re.MatchString(prefix + "_01ARZ3NDEKTSV4RRFFQ69G5FAI") {
			t.Errorf("%s: PatternFor(%q) admits 'I', which Crockford excludes", name, prefix)
		}

		opt := regexp.MustCompile(ids.OptionalPatternFor(prefix))
		if !opt.MatchString("") {
			t.Errorf("%s: OptionalPatternFor(%q) rejects the empty string", name, prefix)
		}
		if opt.MatchString("nonsense") {
			t.Errorf("%s: OptionalPatternFor(%q) admits anything", name, prefix)
		}
	}
}
