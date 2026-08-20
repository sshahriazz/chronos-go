package argon2id

import (
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Reseal moves a stored verifier from an older pepper version to the current
// one, WITHOUT the password.
//
// This is the operation that makes a pepper rotation completable, and it is
// possible only because of the design choice the package comment argues for: the
// verifier is Argon2id(password, salt) ENCRYPTED under the pepper, not
// Argon2id(password ‖ pepper). The digest is therefore recoverable with the old
// key and re-encryptable under the new one, and the password is never involved.
// The concatenated-pepper design cannot be rotated at all — every stored digest
// is bound to the pepper that produced it, and changing it requires exactly the
// plaintext nobody has.
//
// It lives beside Hash and Verify rather than in the rotation job because the
// pepper keys are unexported and must stay that way: a caller holding raw key
// bytes is a second place the pepper can leak from, and a caller that re-derived
// the PHC encoding would be a second parser for a format with one authority. The
// job upstream sees a string in and a string out.
//
// # What is preserved, and what is not
//
// The salt, the cost parameters and the digest are carried across UNCHANGED. Only
// the encryption of the digest changes. That means a re-seal does NOT upgrade a
// verifier's Argon2id cost — raising Memory or Time still requires the plaintext,
// so it still happens at login through NeedsRehash and Hash. The two mechanisms
// are complementary rather than overlapping: this one reaches every account and
// fixes only the key version, the login path reaches only accounts that sign in
// and fixes everything.
//
// # What it refuses
//
// A verifier it cannot open is returned as an error, never as a fresh value. A
// job that "repaired" an unopenable row by hashing something new would silently
// replace a password the user knows with one nobody does, and the row would then
// look perfectly healthy under the new key.
func (h *Hasher) Reseal(verifier string, user ids.UserID, cred ids.CredentialID) (string, error) {
	if user.IsZero() || cred.IsZero() {
		// Both ids are the AES-GCM additional data. Without them the open cannot
		// authenticate, and re-sealing under a DIFFERENT binding would produce a
		// row that no login can ever verify — a silent, permanent lockout written
		// by the job that was supposed to protect against one.
		return "", fmt.Errorf("%w: re-sealing needs both the user id and the credential id "+
			"the verifier was bound to", app.ErrVerifierUnreadable)
	}

	stored, err := decode(verifier)
	if err != nil {
		return "", err
	}

	current := h.pepper.Current()
	if stored.version == current {
		// Already there. Re-sealing anyway would emit new ciphertext under a
		// fresh GCM nonce at an unchanged version, so the rotation's done check
		// would never fall and the pass would repeat forever.
		return "", fmt.Errorf("%w: v%d", app.ErrAlreadyCurrent, current)
	}

	oldKey, err := h.pepper.key(stored.version)
	if err != nil {
		// The operationally serious case: this row names a key that is not
		// loaded, so it cannot be carried forward and will stop verifying the
		// moment that key is destroyed. Reported as ErrVerifierUnreadable so the
		// job counts it apart from a transient fault, with ErrNoPepperKey still
		// wrapped underneath for whoever reads the log.
		return "", fmt.Errorf("%w: %w", app.ErrVerifierUnreadable, err)
	}
	newKey, err := h.pepper.key(current)
	if err != nil {
		// Not an unopenable ROW — the current key is missing, which breaks every
		// row equally. Left unwrapped so the job counts it as an ordinary failure
		// and retries rather than declaring every account lost.
		return "", fmt.Errorf("argon2id: re-sealing under the current pepper: %w", err)
	}

	binding := aad(user, cred)
	digest, err := crypto.Open(oldKey, stored.sealed, binding)
	if err != nil {
		// The row does not authenticate under its own binding: tampering, or a
		// verifier copied from another account. Same category as a missing key
		// from the job's point of view — it cannot be carried forward — and the
		// same category Verify puts it in.
		return "", fmt.Errorf("%w: opening under pepper v%d: %w",
			app.ErrVerifierUnreadable, stored.version, err)
	}
	// Zeroed on every path. The digest is the value an offline attack wants, and
	// it exists in this process only for the length of this function.
	defer crypto.Zero(digest)

	// The SAME binding. Re-deriving it from different ids would produce a row
	// that cannot be opened again — the failure would appear at the user's next
	// login, long after the old key was destroyed.
	sealed, err := crypto.Seal(newKey, digest, binding)
	if err != nil {
		return "", fmt.Errorf("argon2id: sealing a re-sealed digest: %w", err)
	}
	return encode(stored.params, current, stored.salt, sealed), nil
}

// PasswordResealer presents the hasher as identity's re-sealing port.
//
// A separate type rather than methods on Hasher, because app.Resealer's Kind and
// CurrentVersion would be meaningless on a hasher — a hasher has no opinion about
// the `kind` column — and because the port takes an app.SealedCredential, which
// is a use-case type the hasher itself has no reason to know.
type PasswordResealer struct{ h *Hasher }

var _ app.Resealer = PasswordResealer{}

// NewPasswordResealer builds the port implementation.
func NewPasswordResealer(h *Hasher) (PasswordResealer, error) {
	if h == nil {
		return PasswordResealer{}, fmt.Errorf("argon2id: a password resealer needs a hasher; " +
			"without one the rotation job would scan password rows and move none, while " +
			"reporting a clean pass")
	}
	return PasswordResealer{h: h}, nil
}

// Kind is the credential kind these verifiers live under.
func (PasswordResealer) Kind() string { return app.KindPassword }

// CurrentVersion is the pepper version Reseal produces.
func (r PasswordResealer) CurrentVersion() int32 { return r.h.PepperVersion() }

// Reseal adapts the port's row shape to the hasher's binding.
func (r PasswordResealer) Reseal(sealed string, cred app.SealedCredential) (string, error) {
	return r.h.Reseal(sealed, cred.UserID, cred.ID)
}
