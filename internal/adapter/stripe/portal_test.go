package stripe

import "testing"

// THE RETURN URL IS AN OPEN-REDIRECT SURFACE.
//
// Stripe redirects a BROWSER to whatever this value says, after a session that
// began on our domain. An attacker-chosen value therefore borrows our
// credibility for the landing — the classic phishing primitive — and the person
// following it has just been thinking about their payment details.
//
// protovalidate refuses most of these at the edge already. This is the second
// enforcement, and it is not redundant: this method is reachable from any future
// caller, and a bound published in one place and enforced in another is a bound
// that ends one refactor away from being neither.
func TestAReturnURLIsRefusedUnlessItIsSafeToRedirectTo(t *testing.T) {
	tests := map[string]struct {
		url  string
		want bool // true = accepted
	}{
		"an ordinary https url":    {"https://app.example.com/settings/billing", true},
		"https with a port":        {"https://app.example.com:8443/billing", true},
		"https with a query":       {"https://app.example.com/b?tab=invoices", true},
		"plain http":               {"http://app.example.com/billing", false},
		"javascript":               {"javascript:alert(document.cookie)", false},
		"data":                     {"data:text/html,<script>fetch('//evil')</script>", false},
		"a scheme-relative url":    {"//evil.example/billing", false},
		"a relative path":          {"/settings/billing", false},
		"no host at all":           {"https:///settings/billing", false},
		"userinfo before the host": {"https://app.example.com@evil.example/", false},
		"uppercase HTTPS":          {"HTTPS://app.example.com/billing", true},
		"empty":                    {"", false},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			err := checkReturnURL(tt.url)
			if tt.want && err != nil {
				t.Errorf("%q was refused: %v", tt.url, err)
			}
			if !tt.want && err == nil {
				t.Errorf("%q was ACCEPTED. Stripe redirects a browser there after a billing "+
					"session that started on our domain, so this is an open redirect wearing "+
					"our name", tt.url)
			}
		})
	}
}

// A PORTAL NEEDS A KEY.
//
// Constructed without one it would fail per call, at the moment a customer is
// trying to pay, rather than at startup where somebody is watching.
func TestAPortalNeedsAnAPIKey(t *testing.T) {
	if _, err := NewPortal(PortalConfig{}); err == nil {
		t.Error("a portal with no API key was accepted")
	}
	if _, err := NewPortal(PortalConfig{SecretKey: "sk_test_x"}); err != nil {
		t.Errorf("a configured portal was refused: %v", err)
	}
}

// THE ARGUMENTS ARE CHECKED BEFORE STRIPE IS CALLED.
//
// An empty customer id sent to Stripe is a 400 from their API with a message
// about a missing parameter — which surfaces as an internal error at the moment
// somebody is trying to pay, rather than as the wiring bug it is.
func TestASessionNeedsACustomerAndAReturnURL(t *testing.T) {
	portal, err := NewPortal(PortalConfig{SecretKey: "sk_test_x"})
	if err != nil {
		t.Fatal(err)
	}
	ctx := t.Context()

	if _, err := portal.Session(ctx, "", "https://app.example.com/b"); err == nil {
		t.Error("a session with no customer was attempted")
	}
	if _, err := portal.Session(ctx, "cus_x", ""); err == nil {
		t.Error("a session with no return url was attempted")
	}
	// The one that matters: a bad URL must not reach Stripe, because Stripe
	// accepts plenty of URLs this refuses.
	//
	// Compared against checkReturnURL's OWN error rather than merely asserting
	// that something failed. Without that this passes even with the validation
	// removed: the call would fall through to Stripe, Stripe would reject the
	// test key, and "an error came back" would look identical to "the URL was
	// refused here". The distinction is the whole property — Stripe accepts
	// return URLs this must not.
	want := checkReturnURL("http://evil.example/")
	if want == nil {
		t.Fatal("checkReturnURL accepts http; this test proves nothing")
	}
	_, err = portal.Session(ctx, "cus_x", "http://evil.example/")
	if err == nil || err.Error() != want.Error() {
		t.Errorf("returned %v, want the local refusal %q — anything else means the URL "+
			"reached Stripe", err, want)
	}
}
