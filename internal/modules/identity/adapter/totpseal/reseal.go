package totpseal

import (
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Reseal moves a stored secret from an older sealing key version to the current
// one.
//
// The TOTP case is the one that makes a batch re-seal ESSENTIAL rather than
// merely convenient. A password verifier has a second repair path — the
// login-time rehash, which upgrades a row while the plaintext is briefly in
// memory — so a pepper rotation eventually reaches every account that signs in.
// A shared secret has no equivalent: verification opens the secret and derives a
// code from it, and nothing about that exchange produces an opportunity to
// re-seal, so before this job a rotated totpseal key could NEVER retire. The old
// key had to be kept for the life of the deployment, including after a leak.
//
// It lives here rather than in the rotation job even though Seal and Open are
// both exported and composing them upstream would work. The reason is that the
// composition hands the caller the PLAINTEXT SHARED SECRET — the one value in
// this package that must not travel — and a secret in a variable in a
// composition root is a secret one careless log line away from being permanent.
// Keeping the round trip inside this function bounds its lifetime to a few
// statements and lets it be zeroed on the way out.
//
// A secret it cannot open is returned as an error, never as a new secret. A job
// that "repaired" an unopenable row by enrolling fresh material would silently
// disconnect an authenticator the user still holds, and would do it under the new
// key, so the row would look perfectly healthy afterwards.
func (s *Sealer) Reseal(sealed, subjectID string, cred ids.CredentialID) (string, error) {
	if subjectID == "" || cred.IsZero() {
		// Both are the AES-GCM additional data. Re-sealing under a different
		// binding produces a row that can never be opened again, and the failure
		// surfaces at the user's next sign-in rather than here.
		return "", fmt.Errorf("%w: re-sealing needs both the subject id and the credential "+
			"id the secret was bound to", app.ErrSecretUnreadable)
	}

	version, body, err := decode(sealed)
	if err != nil {
		return "", err
	}

	current := s.keys.Current()
	if version == current {
		// Already there. Re-sealing anyway would emit new ciphertext under a
		// fresh GCM nonce at an unchanged version, so the done check would never
		// fall and the pass would repeat forever.
		return "", fmt.Errorf("%w: v%d", app.ErrAlreadyCurrent, current)
	}

	oldKey, err := s.keys.key(version)
	if err != nil {
		// This row names a key that is not loaded. It cannot be carried forward,
		// and destroying that key takes the account's second factor with it.
		// Reported as ErrSecretUnreadable so the job counts it apart from a
		// transient fault, with ErrNoKey still wrapped underneath.
		return "", fmt.Errorf("%w: %w", app.ErrSecretUnreadable, err)
	}
	// Checked BEFORE the secret is opened, and the ordering is the point: there
	// is no reason to bring a plaintext shared secret into memory when the key
	// that would re-seal it is not loaded. Left unwrapped by ErrSecretUnreadable
	// so the job counts it as an ordinary failure and retries, rather than
	// declaring every second factor in the system lost — a missing CURRENT key
	// breaks every row equally and is not a fact about this one.
	if _, err := s.keys.key(current); err != nil {
		return "", fmt.Errorf("totpseal: re-sealing under the current key: %w", err)
	}

	binding := aad(subjectID, cred)
	secret, err := crypto.Open(oldKey, body, binding)
	if err != nil {
		return "", fmt.Errorf("%w: opening under key v%d", app.ErrSecretUnreadable, version)
	}
	// Zeroed on every path. This is the plaintext shared secret; anyone holding
	// it can generate valid codes for the account indefinitely.
	defer crypto.Zero(secret)

	// The SAME binding, and the same encoding Seal produces — reached through
	// Seal itself rather than reassembled here, so there is exactly one place
	// that knows the stored form.
	return s.Seal(string(secret), subjectID, cred)
}

// TOTPResealer presents the sealer as identity's re-sealing port.
//
// A separate type rather than methods on Sealer, because app.Resealer's Kind and
// CurrentVersion would be meaningless on a sealer — it has no opinion about the
// `kind` column — and because the port takes an app.SealedCredential, a use-case
// type this package has no reason to know.
type TOTPResealer struct{ s *Sealer }

var _ app.Resealer = TOTPResealer{}

// NewTOTPResealer builds the port implementation.
func NewTOTPResealer(s *Sealer) (TOTPResealer, error) {
	if s == nil {
		return TOTPResealer{}, fmt.Errorf("totpseal: a TOTP resealer needs a sealer; without " +
			"one the rotation job would scan TOTP rows and move none, while reporting a " +
			"clean pass — and TOTP has no second repair path to fall back on")
	}
	return TOTPResealer{s: s}, nil
}

// Kind is the credential kind these secrets live under.
func (TOTPResealer) Kind() string { return app.KindTOTP }

// CurrentVersion is the sealing key version Reseal produces.
func (r TOTPResealer) CurrentVersion() int32 { return r.s.KeyVersion() }

// Reseal adapts the port's row shape to the sealer's binding.
//
// The SUBJECT id, not the user id: this is the value the credential row is keyed
// by and the value Seal authenticated into the ciphertext.
func (r TOTPResealer) Reseal(sealed string, cred app.SealedCredential) (string, error) {
	return r.s.Reseal(sealed, cred.SubjectID, cred.ID)
}
