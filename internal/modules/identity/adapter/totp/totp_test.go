package totp_test

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totp"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
	pquerna "github.com/pquerna/otp/totp"
)

// guard is an in-memory replay guard.
//
// In-memory is fine HERE and wrong in production, for the reason the port
// comment gives: a per-process map lets an attacker replay against another
// instance. The real one is a UNIQUE constraint (S1-16).
type guard struct {
	mu     sync.Mutex
	seen   map[string]bool
	fail   error
	claims int
}

func newGuard() *guard { return &guard{seen: map[string]bool{}} }

func (g *guard) Claim(_ context.Context, cred ids.CredentialID, step int64, _ time.Time) error {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.claims++
	if g.fail != nil {
		return g.fail
	}
	key := fmt.Sprintf("%s:%d", cred, step)
	if g.seen[key] {
		return app.ErrCodeReplayed
	}
	g.seen[key] = true
	return nil
}

func newAuth(t *testing.T) (*totp.Authenticator, *guard) {
	t.Helper()
	g := newGuard()
	a, err := totp.New("Chronos", g)
	if err != nil {
		t.Fatalf("authenticator: %v", err)
	}
	return a, g
}

func newCred(t *testing.T) ids.CredentialID {
	t.Helper()
	return ids.New[ids.Credential](time.Now(), rand.Reader)
}

// code returns the valid code for a secret at an instant.
func code(t *testing.T, secret string, at time.Time) string {
	t.Helper()
	c, err := pquerna.GenerateCode(secret, at)
	if err != nil {
		t.Fatalf("generate code: %v", err)
	}
	return c
}

// A freshly enrolled secret validates the code an authenticator app would show.
func TestAnEnrolledSecretValidatesItsOwnCode(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	cred := newCred(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()

	ok, err := a.Verify(ctx, e.Secret, code(t, e.Secret, now), cred, now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("the code an authenticator app would show did not validate")
	}
}

// THE ONE THAT MATTERS: a valid code cannot be used twice.
//
// RFC 6238 §5.2. Without it an observed code — a shoulder-surf, a screenshot, a
// log line, a phishing relay — is presentable again for the whole 90-second
// window, and the second factor stops being one.
func TestAValidCodeCannotBeUsedTwice(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	cred := newCred(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()
	c := code(t, e.Secret, now)

	ok, err := a.Verify(ctx, e.Secret, c, cred, now)
	if err != nil || !ok {
		t.Fatalf("first use: ok=%v err=%v", ok, err)
	}

	ok, err = a.Verify(ctx, e.Secret, c, cred, now.Add(time.Second))
	if ok {
		t.Fatal("a code validated a second time: anyone who observes a code can use it for " +
			"the rest of the acceptance window")
	}
	if !errors.Is(err, app.ErrCodeReplayed) {
		t.Fatalf("error is %v, want app.ErrCodeReplayed; a replay is a different signal from "+
			"a typo — it means somebody has seen a genuine code", err)
	}
}

// The replay guard is keyed per CREDENTIAL, so one user's use does not consume
// another's step.
func TestOneUsersCodeDoesNotConsumeAnothersStep(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()
	c := code(t, e.Secret, now)

	first, second := newCred(t), newCred(t)
	if ok, err := a.Verify(ctx, e.Secret, c, first, now); !ok || err != nil {
		t.Fatalf("first credential: ok=%v err=%v", ok, err)
	}
	// Same secret and code, different credential. Contrived — two credentials do
	// not share a secret in practice — and it is what proves the guard key
	// includes the credential rather than only the step.
	if ok, err := a.Verify(ctx, e.Secret, c, second, now); !ok || err != nil {
		t.Fatalf("a second credential was refused because an unrelated one used the same "+
			"step: ok=%v err=%v", ok, err)
	}
}

// A code from the adjacent steps is accepted; one from further out is not.
func TestTheAcceptanceWindowIsExactlyOneStepEitherSide(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()

	for _, tc := range []struct {
		name   string
		offset time.Duration
		want   bool
	}{
		{"one step behind", -totp.Period * time.Second, true},
		{"current step", 0, true},
		{"one step ahead", +totp.Period * time.Second, true},
		{"two steps behind", -2 * totp.Period * time.Second, false},
		{"two steps ahead", +2 * totp.Period * time.Second, false},
		{"an hour behind", -time.Hour, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			// A fresh credential per case, so the replay guard does not confuse
			// "outside the window" with "already used".
			cred := newCred(t)
			c := code(t, e.Secret, now.Add(tc.offset))
			ok, err := a.Verify(ctx, e.Secret, c, cred, now)
			if err != nil {
				t.Fatalf("verify: %v", err)
			}
			if ok != tc.want {
				t.Fatalf("a code %s was accepted=%v, want %v: the acceptance window is not "+
					"one step either side, so an observed code stays usable for longer than "+
					"the replay guard covers", tc.name, ok, tc.want)
			}
		})
	}
}

// A wrong code does NOT consume the step.
//
// Claiming before validating would let an attacker burn the legitimate user's
// step with garbage — a denial of service that needs no credential at all.
func TestAWrongCodeDoesNotConsumeTheStep(t *testing.T) {
	ctx := context.Background()
	a, g := newAuth(t)
	cred := newCred(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()

	for range 5 {
		if ok, err := a.Verify(ctx, e.Secret, "000000", cred, now); ok || err != nil {
			t.Fatalf("a wrong code returned ok=%v err=%v", ok, err)
		}
	}
	if g.claims != 0 {
		t.Fatalf("a wrong code claimed a step %d times: an attacker burns the user's step "+
			"with garbage and denies them their own second factor", g.claims)
	}

	// And the real code still works.
	if ok, err := a.Verify(ctx, e.Secret, code(t, e.Secret, now), cred, now); !ok || err != nil {
		t.Fatalf("the correct code was refused after wrong attempts: ok=%v err=%v", ok, err)
	}
}

// An unavailable replay guard REFUSES the code.
//
// Failing open here means that during an outage of the replay store every
// observed code becomes replayable — so an attacker who can cause the outage has
// switched the second factor off. A failed login is the cheaper failure.
func TestAnUnavailableReplayGuardRefusesTheCode(t *testing.T) {
	ctx := context.Background()
	a, g := newAuth(t)
	cred := newCred(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()
	g.fail = errors.New("the store is unreachable")

	ok, err := a.Verify(ctx, e.Secret, code(t, e.Secret, now), cred, now)
	if ok {
		t.Fatal("a code was accepted while the replay guard was unavailable: an attacker who " +
			"can take the store down has turned replay protection off")
	}
	if err == nil {
		t.Fatal("an unavailable guard was reported as a wrong code, so the outage is invisible")
	}
	if errors.Is(err, app.ErrCodeReplayed) {
		t.Error("an unavailable guard was reported as a replay")
	}
}

// An authenticator cannot be built without a replay guard.
func TestAnAuthenticatorWithoutAReplayGuardIsRefused(t *testing.T) {
	if _, err := totp.New("Chronos", nil); err == nil {
		t.Error("an authenticator was built with no replay guard: every observed code is " +
			"replayable for the whole window, and nothing about it looks wrong")
	}
	if _, err := totp.New("", newGuard()); err == nil {
		t.Error("an authenticator was built with no issuer: the user sees an unlabelled " +
			"entry in their app")
	}
	if _, err := totp.New("   ", newGuard()); err == nil {
		t.Error("a blank issuer was accepted")
	}
}

// The provisioning URI carries the parameters every authenticator app assumes.
//
// Most apps IGNORE these fields and hard-code SHA-1 / 6 digits / 30 seconds. So
// emitting anything else does not produce a stronger factor — it produces an app
// showing codes that never validate, with no error to explain why.
func TestTheProvisioningURIMatchesWhatAuthenticatorAppsAssume(t *testing.T) {
	a, _ := newAuth(t)
	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}

	for _, want := range []string{
		"otpauth://totp/",
		"algorithm=SHA1",
		"digits=6",
		"period=30",
		"issuer=Chronos",
	} {
		if !strings.Contains(e.URI, want) {
			t.Errorf("the provisioning URI does not contain %q: %s", want, e.URI)
		}
	}

	secret, err := totp.SecretFromURI(e.URI)
	if err != nil {
		t.Fatalf("the URI's secret could not be read back: %v", err)
	}
	if secret != e.Secret {
		t.Errorf("the URI carries a different secret from the one returned")
	}
}

// Every enrolment produces a different secret.
func TestEachEnrolmentGetsItsOwnSecret(t *testing.T) {
	a, _ := newAuth(t)
	seen := map[string]bool{}
	for range 20 {
		e, err := a.Enroll("user@example.com")
		if err != nil {
			t.Fatalf("enroll: %v", err)
		}
		if seen[e.Secret] {
			t.Fatal("two enrolments produced the same secret: the generator is not random, " +
				"and one user's codes validate for another")
		}
		seen[e.Secret] = true
		// 160 bits of base32 is 32 characters.
		if len(e.Secret) != 32 {
			t.Errorf("the secret is %d base32 characters, want 32 (160 bits)", len(e.Secret))
		}
	}
}

// Empty and malformed inputs are refused rather than validated.
func TestMalformedInputsAreRefused(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	cred := newCred(t)

	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()

	for _, tc := range []struct{ name, secret, code string }{
		{"empty code", e.Secret, ""},
		{"empty secret", "", "123456"},
		{"both empty", "", ""},
		{"non-numeric code", e.Secret, "abcdef"},
		{"short code", e.Secret, "123"},
		{"long code", e.Secret, "12345678"},
		{"malformed secret", "not-base32!", "123456"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := a.Verify(ctx, tc.secret, tc.code, cred, now)
			if ok {
				t.Fatalf("%s validated", tc.name)
			}
			if err != nil {
				t.Errorf("%s produced an error rather than a plain mismatch: %v", tc.name, err)
			}
		})
	}

	if _, err := a.Verify(ctx, e.Secret, "123456", ids.CredentialID{}, now); err == nil {
		t.Error("a verification with no credential id was allowed: nothing keys the replay " +
			"guard, so replay protection silently does not apply")
	}
	if _, err := a.Enroll(""); err == nil {
		t.Error("an enrolment with no account name was allowed")
	}
}

// Codes are surrounded by whitespace when pasted. Trim, do not reject.
func TestAPastedCodeWithWhitespaceIsAccepted(t *testing.T) {
	ctx := context.Background()
	a, _ := newAuth(t)
	e, err := a.Enroll("user@example.com")
	if err != nil {
		t.Fatalf("enroll: %v", err)
	}
	now := time.Now()

	ok, err := a.Verify(ctx, e.Secret, "  "+code(t, e.Secret, now)+" ", newCred(t), now)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Error("a pasted code with surrounding whitespace was refused")
	}
}
