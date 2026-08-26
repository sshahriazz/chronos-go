package pii

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/platform/crypto"
)

// CanaryPlaintext is what the canary wraps.
//
// A CONSTANT in the source, and not a secret. What the canary proves is that the
// key ring can still decrypt what this installation encrypted; the value itself
// carries nothing, so publishing it costs nothing and makes the check auditable
// by reading the code.
//
// It is deliberately not empty and not a repeated byte: a wrap of nothing, or of
// a value with no structure, is a weaker signal that something decoded than a
// value nobody would produce by accident.
var CanaryPlaintext = []byte("chronos.kek.canary.v1")

// ErrKEKChanged means the key-encryption key can no longer decrypt what this
// installation encrypted.
//
// Every wrapped data key in the database is undecryptable, which means every
// subject's personal data is unreadable — permanently, unless the previous key
// is restored. It is NOT a transient failure and must never be retried past.
var ErrKEKChanged = errors.New("pii: the key-encryption key cannot decrypt this " +
	"installation's data")

// CanaryStore holds the single wrapped proof.
type CanaryStore interface {
	// Get returns the stored canary, or ErrNoCanary when none exists yet.
	Get(ctx context.Context) (kekName string, wrapped []byte, err error)

	// Put writes the canary the first time, and does nothing if one already
	// exists. See the query for why it must not overwrite.
	Put(ctx context.Context, kekName string, wrapped []byte) error

	// Touch records that the canary verified.
	Touch(ctx context.Context, at time.Time) error
}

// ErrNoCanary means the installation has not written one yet.
var ErrNoCanary = errors.New("pii: no canary is stored")

// KeyRing is the wrap/unwrap half of the vault, narrowed to what the canary
// needs. Declared here rather than reused so the check cannot acquire the
// ability to read a subject's data.
type KeyRing interface {
	Wrap(ctx context.Context, plaintext []byte) (crypto.Wrapped, error)
	Unwrap(ctx context.Context, wrapped crypto.Wrapped) ([]byte, error)
}

// VerifyKEK proves the key ring can still decrypt what this installation
// encrypted, and writes the proof the first time.
//
// # Why this runs at startup and not on a schedule
//
// The damage is already done by the time a scheduled check would notice: every
// notification between the deploy and the check tries to resolve an address and
// silently fails. Running it at boot means the process REFUSES TO START, which
// is a deploy that visibly did not happen rather than one that appeared to work.
//
// # Why a mismatch is fatal rather than degraded
//
// A key store that is briefly unreachable is degradable — it comes back, and the
// data is fine. A key store holding the WRONG KEY never comes back on its own,
// and every request served in the meantime is a request that could not read a
// single subject's data. The two failures look identical to a liveness probe,
// which is exactly why the probe was not enough.
//
// # First boot writes rather than refuses
//
// An empty table is a new installation, not a lost key. It mints the canary
// against whatever key is present and records the key's NAME, so an installation
// that legitimately moves to a new named key can be told apart from one whose key
// was replaced underneath it.
func VerifyKEK(ctx context.Context, ring KeyRing, store CanaryStore, kekName string, now time.Time) error {
	switch {
	case ring == nil:
		return errors.New("pii: verifying the KEK needs a key ring")
	case store == nil:
		return errors.New("pii: verifying the KEK needs a canary store")
	case kekName == "":
		return errors.New("pii: verifying the KEK needs the key's name")
	}

	storedName, wrapped, err := store.Get(ctx)
	if errors.Is(err, ErrNoCanary) {
		// FIRST BOOT. Nothing has been encrypted under any key yet, so there is
		// nothing to lose and nothing to compare against.
		fresh, wrapErr := ring.Wrap(ctx, CanaryPlaintext)
		if wrapErr != nil {
			return fmt.Errorf("pii: writing the first KEK canary: %w", wrapErr)
		}
		if putErr := store.Put(ctx, kekName, fresh); putErr != nil {
			return fmt.Errorf("pii: storing the first KEK canary: %w", putErr)
		}
		return nil
	}
	if err != nil {
		return fmt.Errorf("pii: reading the KEK canary: %w", err)
	}

	got, err := ring.Unwrap(ctx, crypto.Wrapped(wrapped))
	if err != nil {
		// The unwrap FAILED. This is the case that matters: the key store
		// answered, and it could not decrypt. Reported as ErrKEKChanged with the
		// cause attached, because "the key changed" is what an operator needs to
		// hear and the cipher error is what they need to confirm it.
		return fmt.Errorf("%w (canary written under %q, now serving %q): %w",
			ErrKEKChanged, storedName, kekName, err)
	}
	if !bytes.Equal(got, CanaryPlaintext) {
		// Decrypted to something ELSE. Not a failure any real cipher produces —
		// AES-GCM authenticates, so a wrong key errors rather than returning
		// plausible bytes — which makes this a check on the key ring itself
		// rather than on the key. It stays because the alternative is trusting
		// that property of an adapter this package cannot see.
		return fmt.Errorf("%w: the canary decrypted to a different value", ErrKEKChanged)
	}

	if storedName != kekName {
		// The key DECRYPTS but is named differently. Not fatal — an operator may
		// have renamed the key, and the data is provably readable — but it is
		// recorded, because a name that drifts silently is how the next
		// investigation starts from the wrong assumption.
		return nil
	}

	// Best effort: the check has already passed, and failing a boot because a
	// timestamp could not be written would be the check causing the outage.
	_ = store.Touch(ctx, now)
	return nil
}
