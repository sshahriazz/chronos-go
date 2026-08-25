package oidc

import (
	"testing"
)

// TRI-STATE `email_verified`, INCLUDING APPLE'S STRING FORM.
//
// # Why the string case is not defensive coding
//
// Apple serialises `email_verified` as a STRING or a BOOLEAN depending on the
// flow. A reader that only accepted a bool would treat Apple's `"true"` as
// ABSENT — the safe direction, and wrong: it makes Apple permanently unlinkable
// for a reason nobody could find, because "not asserted" and "asserted true"
// look identical from every log line.
//
// And absent must stay ABSENT rather than becoming false. identity.md §7 rule 6:
// a provider staying silent is not a provider saying no, and only one of those
// could ever become a yes.
func TestEmailVerifiedIsTriState(t *testing.T) {
	tr, fa := true, false
	for name, tc := range map[string]struct {
		claims map[string]any
		want   *bool
	}{
		"boolean true":       {map[string]any{"email_verified": true}, &tr},
		"boolean false":      {map[string]any{"email_verified": false}, &fa},
		"apple string true":  {map[string]any{"email_verified": "true"}, &tr},
		"apple string false": {map[string]any{"email_verified": "false"}, &fa},
		"apple string TRUE":  {map[string]any{"email_verified": "TRUE"}, &tr},
		"absent":             {map[string]any{}, nil},
		"null":               {map[string]any{"email_verified": nil}, nil},
		"nonsense":           {map[string]any{"email_verified": "yes"}, nil},
		"a number":           {map[string]any{"email_verified": 1}, nil},
	} {
		t.Run(name, func(t *testing.T) {
			got := boolClaim(tc.claims, "email_verified")
			switch {
			case tc.want == nil && got != nil:
				t.Fatalf("%s parsed as %v; absent must stay absent, because 'the "+
					"provider did not say' and 'the provider said no' are different "+
					"answers and only one could ever become a yes", name, *got)
			case tc.want != nil && got == nil:
				t.Fatalf("%s parsed as ABSENT; Apple sends this form and would be "+
					"permanently unlinkable", name)
			case tc.want != nil && *got != *tc.want:
				t.Fatalf("%s parsed as %v, want %v", name, *got, *tc.want)
			}
		})
	}
}

// A CEREMONY'S THREE SECRETS ARE ALL DISTINCT AND ALL UNGUESSABLE.
//
// They defend different attacks and sharing one value between them would make
// any single leak defeat all three.
func TestEachCeremonyValueIsIndependentAndRandom(t *testing.T) {
	seen := map[string]bool{}
	for range 32 {
		state, err := randomToken()
		if err != nil {
			t.Fatal(err)
		}
		nonce, err := randomToken()
		if err != nil {
			t.Fatal(err)
		}
		verifier, err := randomToken()
		if err != nil {
			t.Fatal(err)
		}
		if state == nonce || state == verifier || nonce == verifier {
			t.Fatal("two ceremony values collided in one request; they defend different " +
				"attacks and one leak would defeat all three")
		}
		for _, v := range []string{state, nonce, verifier} {
			if len(v) < 43 {
				t.Fatalf("a ceremony value is %d characters, which is under 256 bits", len(v))
			}
			if seen[v] {
				t.Fatal("a ceremony value repeated across requests")
			}
			seen[v] = true
		}
	}
}

// THE REDIRECT ALLOWLIST MATCHES WHOLE STRINGS.
//
// identity.md §7 requires exact matching, and the reason is the cases below: a
// prefix rule admits an attacker's domain that merely starts the same way, and a
// suffix rule admits one that merely ends the same way.
func TestTheRedirectAllowlistIsExact(t *testing.T) {
	allowed := []string{"https://chronos.example/callback"}

	for name, candidate := range map[string]string{
		"an attacker's domain sharing the prefix": "https://chronos.example.evil.test/callback",
		"a path appended":                         "https://chronos.example/callback/../evil",
		"a query appended":                        "https://chronos.example/callback?next=evil",
		"a different scheme":                      "http://chronos.example/callback",
		"a trailing slash":                        "https://chronos.example/callback/",
		"a different host entirely":               "https://evil.test/callback",
	} {
		t.Run(name, func(t *testing.T) {
			if AllowedRedirect(candidate, allowed) {
				t.Fatalf("%q was allowed by an allowlist holding only %q", candidate, allowed[0])
			}
		})
	}

	if !AllowedRedirect(allowed[0], allowed) {
		t.Fatal("the exact registered value was refused, so nothing would ever work")
	}
}

// AN ISSUER MUST BE AN HTTPS URL.
func TestAnIssuerMustBeHTTPS(t *testing.T) {
	for name, raw := range map[string]string{
		"plain http": "http://accounts.google.com",
		"no scheme":  "accounts.google.com",
		"no host":    "https://",
		"nonsense":   "://",
		"empty":      "",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := MustParseIssuer(raw); err == nil {
				t.Fatalf("%q was accepted as an issuer", raw)
			}
		})
	}
	got, err := MustParseIssuer("https://accounts.google.com/")
	if err != nil {
		t.Fatal(err)
	}
	// The trailing slash is trimmed, because the issuer is compared to the ID
	// token's `iss` as a whole string and the token carries no slash.
	if got != "https://accounts.google.com" {
		t.Fatalf("issuer normalised to %q", got)
	}
}

// STATE IS COMPARED WITHOUT SHORT-CIRCUITING ON CONTENT.
func TestStateComparisonIsConstantTime(t *testing.T) {
	if !constantTimeEqual("abc", "abc") {
		t.Fatal("equal values compared unequal")
	}
	for _, tc := range [][2]string{{"abc", "abd"}, {"abc", "ab"}, {"", "a"}, {"abc", ""}} {
		if constantTimeEqual(tc[0], tc[1]) {
			t.Fatalf("%q and %q compared equal", tc[0], tc[1])
		}
	}
}

// A PROVIDER REFUSES TO BE BUILT WITHOUT WHAT IT CANNOT DEFAULT.
func TestNewRefusesAnIncompleteConfiguration(t *testing.T) {
	for name, cfg := range map[string]Config{
		"no issuer":    {ClientID: "id", RedirectURL: "https://x/callback"},
		"no client id": {Issuer: "https://accounts.google.com", RedirectURL: "https://x/callback"},
		// A redirect URI assembled from anything the caller controls is an open
		// redirect with extra steps, so it has no default at all.
		"no redirect": {Issuer: "https://accounts.google.com", ClientID: "id"},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := New(t.Context(), cfg); err == nil {
				t.Fatalf("a provider was built with %s", name)
			}
		})
	}
}
