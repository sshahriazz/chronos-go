package webauthn_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/webauthn"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

func ceremony(t *testing.T) *webauthn.Ceremony {
	t.Helper()
	c, err := webauthn.New(webauthn.Config{
		RPID:          "chronos.test",
		RPDisplayName: "Chronos",
		Origins:       []string{"https://chronos.test"},
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return c
}

// A CEREMONY WITHOUT AN ORIGIN IS REFUSED.
//
// The origin check is what makes a passkey unusable from an attacker's page even
// if the person is fooled into visiting it. Defaulting it — to "any", or to the
// RPID with a guessed scheme — would remove the phishing resistance that is the
// entire reason to prefer passkeys over password plus TOTP.
func TestACeremonyNeedsAnExplicitOrigin(t *testing.T) {
	if _, err := webauthn.New(webauthn.Config{RPID: "chronos.test"}); err == nil {
		t.Fatal("a ceremony was built with no permitted origin; a credential could then " +
			"be used from any page, which is the property passkeys exist to have")
	}
}

// AND WITHOUT A RELYING-PARTY ID.
func TestACeremonyNeedsARelyingPartyID(t *testing.T) {
	if _, err := webauthn.New(webauthn.Config{
		Origins: []string{"https://chronos.test"},
	}); err == nil {
		t.Fatal("a ceremony was built with no RPID; it is bound into every credential at " +
			"registration and cannot be changed afterwards")
	}
}

// THE OPTIONS AND THE STATE ARE SEPARATE, AND THE STATE CARRIES THE CHALLENGE.
//
// They must not travel to the same place. If a caller handed the state to the
// browser, the challenge that makes a replay impossible would be in the
// attacker's hands along with everything they need to answer it.
func TestARegistrationSplitsWhatTheBrowserGetsFromWhatTheServerKeeps(t *testing.T) {
	got, err := ceremony(t).BeginRegistration(webauthn.Account{
		SubjectID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "ada",
	})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	if len(got.Options) == 0 || len(got.State) == 0 {
		t.Fatal("a ceremony produced no options or no state")
	}
	if got.ExpiresAt.IsZero() {
		t.Error("the ceremony has no deadline, so an abandoned challenge stays redeemable")
	}
	if !got.ExpiresAt.After(time.Now()) {
		t.Error("the ceremony is already expired")
	}

	// The STATE holds the challenge; the OPTIONS hold it too, because the browser
	// must sign it — what matters is that they are separate values the caller
	// cannot confuse.
	state, err := codec.Tolerant[struct {
		Challenge string `json:"challenge"`
	}](got.State)
	if err != nil {
		t.Fatalf("the stored state does not decode: %v", err)
	}
	if state.Challenge == "" {
		t.Fatal("the stored state carries no challenge, so nothing prevents a replay")
	}
}

// THE REGISTRATION ASKS FOR A DISCOVERABLE CREDENTIAL AND NO ATTESTATION.
//
// Discoverable, because identity.md §5 wants usernameless login — the
// authenticator offers the account without the person typing an identifier.
//
// Attestation NONE, because Apple and Google return no attestation statement for
// synced passkeys, so requesting `direct` silently no-ops on the two platforms
// most people are on. Storing an attestation this system cannot act on would
// imply a capability it does not have (ADR-057, IDENTITY-REVIEW C4).
func TestTheRegistrationAsksForADiscoverableCredentialWithoutAttestation(t *testing.T) {
	got, err := ceremony(t).BeginRegistration(webauthn.Account{
		SubjectID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "ada",
	})
	if err != nil {
		t.Fatal(err)
	}
	options := string(got.Options)

	if !strings.Contains(options, `"residentKey":"required"`) {
		t.Errorf("the ceremony does not require a discoverable credential, so usernameless "+
			"login is impossible: %s", options)
	}
	if !strings.Contains(options, `"userVerification":"preferred"`) {
		t.Errorf("user verification is not `preferred`. `required` refuses security keys "+
			"with no PIN, and `discouraged` gives up the AAL2 that makes a passkey worth "+
			"preferring: %s", options)
	}
	if !strings.Contains(options, `"attestation":"none"`) {
		t.Errorf("the ceremony requests attestation, which the two platforms most people "+
			"use do not provide for synced passkeys: %s", options)
	}
}

// THE USER HANDLE IS THE PSEUDONYM, NEVER AN ADDRESS.
//
// It travels to the authenticator and is stored there PERMANENTLY — synced to a
// cloud backup, shown on a lock screen. That is the same store identity.md §5
// refuses to put an email into via a TOTP label, and for the same reason: it is
// the one place ADR-002 can never reach to erase.
func TestTheUserHandleIsAPseudonym(t *testing.T) {
	const subject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	got, err := ceremony(t).BeginRegistration(webauthn.Account{
		SubjectID: subject, Username: "ada",
	})
	if err != nil {
		t.Fatal(err)
	}
	options := string(got.Options)
	if strings.Contains(options, "@") {
		t.Fatalf("the ceremony options contain an address. It would be stored by the "+
			"authenticator permanently, in the one place erasure cannot reach: %s", options)
	}
	// The handle is base64url in the payload, so its presence is asserted by the
	// public handle appearing as the NAME and no address appearing at all.
	if !strings.Contains(options, `"name":"ada"`) {
		t.Errorf("the public handle is not what the authenticator will show: %s", options)
	}
}

// A REGISTRATION EXCLUDES CREDENTIALS THE ACCOUNT ALREADY HOLDS.
//
// Without it an authenticator that already holds a passkey for this account
// creates a second, and the person ends up with two credentials for one device
// and no way to tell which is which.
func TestARegistrationExcludesExistingCredentials(t *testing.T) {
	got, err := ceremony(t).BeginRegistration(webauthn.Account{
		SubjectID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "ada",
		Existing: [][]byte{[]byte("credential-one"), []byte("credential-two")},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got.Options), "excludeCredentials") {
		t.Fatalf("the ceremony does not exclude the account's existing credentials: %s",
			got.Options)
	}
}

// A LOGIN WITH NO CREDENTIALS IS REFUSED, NAMED.
//
// Distinct from a failed ceremony: there is nothing to attempt, and the caller
// needs to tell the person to use another method rather than that their passkey
// did not verify.
func TestALoginWithNoCredentialsIsRefused(t *testing.T) {
	_, err := ceremony(t).BeginLogin(webauthn.Account{
		SubjectID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "ada",
	}, nil)
	if !errors.Is(err, webauthn.ErrNoCredentials) {
		t.Fatalf("BeginLogin with no credentials returned %v, want ErrNoCredentials", err)
	}
}

// EVERY UNVERIFIABLE ANSWER IS ONE REFUSAL.
//
// A bad signature, a wrong origin, an expired challenge and a replayed one are
// deliberately indistinguishable. Telling a caller which check failed tells an
// attacker which one to work on.
func TestEveryUnverifiableAnswerIsTheSameRefusal(t *testing.T) {
	c := ceremony(t)
	account := webauthn.Account{SubjectID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV", Username: "ada"}
	fresh, err := c.BeginRegistration(account)
	if err != nil {
		t.Fatal(err)
	}

	for name, tc := range map[string]struct{ state, response []byte }{
		"no state at all":     {nil, []byte(`{}`)},
		"corrupt state":       {[]byte("not json"), []byte(`{}`)},
		"unparseable answer":  {fresh.State, []byte("not json")},
		"well-formed rubbish": {fresh.State, []byte(`{"id":"x","type":"public-key"}`)},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := c.FinishRegistration(account, tc.state, tc.response)
			if !errors.Is(err, webauthn.ErrCeremonyRefused) {
				t.Fatalf("returned %v, want ErrCeremonyRefused — a distinguishable "+
					"failure tells an attacker which check to work on", err)
			}
		})
	}
}
