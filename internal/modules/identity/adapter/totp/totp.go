// Package totp implements the RFC 6238 second factor.
//
// # The three choices that are not free
//
// SHA-1, 6 digits, 30-second period. All three look like weak defaults and all
// three are forced by interoperability: Google Authenticator, and most of the
// apps that copied it, ignore the algorithm, digits and period fields in the
// provisioning URI and assume exactly these values. Choosing SHA-256 does not
// produce a stronger second factor — it produces an authenticator app showing
// codes that never validate, with no error anywhere to explain why.
//
// SHA-1's weaknesses are collision attacks. HMAC-SHA1 is unaffected by them, and
// the output is truncated to six digits regardless, so the security of a TOTP
// code rests on the secret's entropy and the replay guard, not on the hash.
//
// # What is NOT here
//
// The secret never touches this package's storage, because this package has
// none. It is generated here, handed to the caller once, and sealed in the vault
// under the subject's key — it is the one credential that must be recoverable in
// plaintext to verify a code, which is exactly why it lives in the vault rather
// than beside the account row.
package totp

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

const (
	// Period is the time step in seconds. RFC 6238 §5.2's recommended default,
	// and what every authenticator app assumes.
	Period = 30

	// Digits is the code length.
	Digits = otp.DigitsSix

	// Algorithm is HMAC-SHA1 — see the package comment.
	Algorithm = otp.AlgorithmSHA1

	// SecretBytes is the shared secret's length. 160 bits, RFC 4226 §4 R6's
	// recommendation.
	//
	// Not longer, and that is deliberate rather than lazy: HMAC-SHA1's key is
	// folded to 64 bytes anyway, so beyond 160 bits there is no strength to gain,
	// and several widely used authenticator apps mis-handle longer base32
	// secrets — producing an enrolment the user completes successfully and can
	// never use.
	SecretBytes = 20

	// Skew is how many steps either side of the current one are accepted.
	//
	// One step, so the accepted window is 90 seconds: the current step plus one
	// behind and one ahead. That covers ordinary clock drift and a user who
	// starts typing at second 29.
	//
	// Widening it is the tempting fix for "users complain codes are rejected",
	// and each extra step lengthens the window in which an OBSERVED code can be
	// replayed — which is the window the replay guard has to cover.
	Skew = 1
)

// Enrollment is what a user needs to add the account to their authenticator.
type Enrollment struct {
	// Secret is base32, to be sealed in the vault. It is returned exactly once
	// and must never be logged, echoed back, or stored anywhere else.
	Secret string

	// URI is the otpauth:// provisioning URI the QR code encodes.
	//
	// It CONTAINS THE SECRET and the account label, which is personal data. It is
	// rendered to the enrolling user's own screen and nowhere else: not in a log
	// line, not in an event, not in an error message.
	URI string
}

// Authenticator generates and verifies TOTP codes.
type Authenticator struct {
	issuer string
	guard  app.TOTPReplayGuard
}

// New builds the authenticator.
//
// The replay guard is REQUIRED, not optional. An authenticator without one
// accepts an observed code for the whole 90-second window, which makes the
// second factor replayable by anyone who saw it — and the failure is invisible,
// because every code still validates exactly as expected.
func New(issuer string, guard app.TOTPReplayGuard) (*Authenticator, error) {
	if strings.TrimSpace(issuer) == "" {
		// The issuer is what the user sees in their authenticator app. An empty
		// one produces an unlabelled entry, which is how people end up deleting
		// the wrong credential.
		return nil, fmt.Errorf("totp: an issuer is required; it is the label the user sees " +
			"in their authenticator app")
	}
	if guard == nil {
		return nil, fmt.Errorf("totp: a replay guard is required; without one an observed " +
			"code can be presented again for the whole acceptance window (RFC 6238 §5.2)")
	}
	return &Authenticator{issuer: issuer, guard: guard}, nil
}

// Enroll generates a new secret and its provisioning URI.
//
// accountName is what the user sees under the issuer in their app — normally
// their email address. It is personal data, it appears in the URI, and it goes
// no further than the enrolling user's screen.
func (a *Authenticator) Enroll(accountName string) (Enrollment, error) {
	if strings.TrimSpace(accountName) == "" {
		return Enrollment{}, fmt.Errorf("totp: an account name is required")
	}
	key, err := totp.Generate(totp.GenerateOpts{
		Issuer:      a.issuer,
		AccountName: accountName,
		Period:      Period,
		SecretSize:  SecretBytes,
		Digits:      Digits,
		Algorithm:   Algorithm,
	})
	if err != nil {
		return Enrollment{}, fmt.Errorf("totp: generating a secret: %w", err)
	}
	return Enrollment{Secret: key.Secret(), URI: key.URL()}, nil
}

// Verify checks a code and consumes its time step.
//
// Two things happen, in this order, and the order is the security property:
// the code is validated, and THEN its step is claimed. Claiming first would
// let an attacker burn a step with a wrong code, denying the legitimate user
// their next 30 seconds.
//
// Returns:
//
//	(true,  nil)                 the code is valid and now spent
//	(false, nil)                 wrong code
//	(false, app.ErrCodeReplayed) valid, but already used — somebody observed it
//	(false, other)               the check could not be performed
func (a *Authenticator) Verify(
	ctx context.Context, secret, code string, cred ids.CredentialID, now time.Time,
) (bool, error) {
	if cred.IsZero() {
		return false, fmt.Errorf("totp: a credential id is required to guard against replay")
	}
	code = strings.TrimSpace(code)
	if secret == "" || code == "" {
		return false, nil
	}

	// Find WHICH step matched, rather than asking "is this valid anywhere in the
	// window". The step is what the replay guard is keyed on, so a validator that
	// only returns a boolean cannot prevent replay at all — it can only tell you
	// the code was good, not which of the three acceptable codes it was.
	step, ok := a.matchingStep(secret, code, now)
	if !ok {
		return false, nil
	}

	// The claim expires once the code can no longer be presented: the end of the
	// last step that would accept it. Keeping it longer stores nothing useful;
	// keeping it shorter reopens the replay window it exists to close.
	expiresAt := time.Unix((step+Skew+1)*Period, 0).UTC()
	if err := a.guard.Claim(ctx, cred, step, expiresAt); err != nil {
		if errors.Is(err, app.ErrCodeReplayed) {
			return false, err
		}
		// The guard could not be consulted. REFUSED, not allowed: accepting here
		// means that during an outage of the replay store, every observed code
		// becomes replayable — and an attacker who can cause that outage has
		// turned the second factor off. A failed login is the cheaper failure.
		return false, fmt.Errorf("totp: the replay guard is unavailable: %w", err)
	}
	return true, nil
}

// matchingStep returns the time step whose code equals the one presented.
//
// The candidate order is current, then behind, then ahead. It does not affect
// correctness — at most one step in the window can produce a given code, since
// two steps producing the same six digits is a 1-in-a-million coincidence that
// would still be caught by the guard — but checking the current step first means
// the common case does one HMAC rather than three.
func (a *Authenticator) matchingStep(secret, code string, now time.Time) (int64, bool) {
	current := now.UTC().Unix() / Period
	for _, offset := range []int64{0, -Skew, +Skew} {
		step := current + offset
		// No Skew field. It is part of ValidateOpts but is only consulted when
		// VALIDATING; generating a code at an instant has no window to widen.
		// Setting it here reads as "the window is pinned" and pins nothing —
		// verified by mutation: changing it to 3 altered no behaviour at all.
		// The window is walked by this loop, and only by this loop.
		want, err := totp.GenerateCodeCustom(secret, time.Unix(step*Period, 0).UTC(), totp.ValidateOpts{
			Period:    Period,
			Digits:    Digits,
			Algorithm: Algorithm,
		})
		if err != nil {
			// A malformed secret. Reported as "no match" rather than an error,
			// because the caller cannot act on it differently and the alternative
			// leaks which stored secrets are corrupt.
			return 0, false
		}
		// Constant time. A byte-wise == leaks how many leading digits were right,
		// and with six digits that is enough to recover a code in a handful of
		// attempts.
		if subtle.ConstantTimeCompare([]byte(want), []byte(code)) == 1 {
			return step, true
		}
	}
	return 0, false
}

// SecretFromURI extracts the shared secret from a provisioning URI.
//
// For tests and for support tooling that must confirm what was issued. It exists
// here rather than being re-derived by every caller because parsing an otpauth
// URI by hand is how a secret ends up in a log line.
func SecretFromURI(uri string) (string, error) {
	u, err := url.Parse(uri)
	if err != nil {
		return "", errs.ValidationFailedf("not a valid provisioning URI")
	}
	if u.Scheme != "otpauth" || u.Host != "totp" {
		return "", errs.ValidationFailedf("not a TOTP provisioning URI")
	}
	secret := u.Query().Get("secret")
	if secret == "" {
		return "", errs.ValidationFailedf("the provisioning URI carries no secret")
	}
	return secret, nil
}
