package pii_test

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"io"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// realRing is AES-256-GCM under a key held in memory.
//
// A REAL cipher rather than a fake that compares strings, because the property
// under test is "a different key cannot decrypt this" — and a fake would decide
// that for itself. Swapping the key here is exactly what happens when a KEK is
// replaced.
type realRing struct{ key []byte }

func newRing(t *testing.T) *realRing {
	t.Helper()
	k := make([]byte, 32)
	if _, err := io.ReadFull(rand.Reader, k); err != nil {
		t.Fatal(err)
	}
	return &realRing{key: k}
}

func (r *realRing) Wrap(_ context.Context, plaintext []byte) (crypto.Wrapped, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, a.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return a.Seal(nonce, nonce, plaintext, nil), nil
}

func (r *realRing) Unwrap(_ context.Context, wrapped crypto.Wrapped) ([]byte, error) {
	block, err := aes.NewCipher(r.key)
	if err != nil {
		return nil, err
	}
	a, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(wrapped) < a.NonceSize() {
		return nil, errors.New("short ciphertext")
	}
	return a.Open(nil, wrapped[:a.NonceSize()], wrapped[a.NonceSize():], nil)
}

// memStore is the canary table.
type memStore struct {
	name    string
	wrapped []byte
	written int
	touched int
	getErr  error
}

func (m *memStore) Get(context.Context) (string, []byte, error) {
	if m.getErr != nil {
		return "", nil, m.getErr
	}
	if m.wrapped == nil {
		return "", nil, pii.ErrNoCanary
	}
	return m.name, m.wrapped, nil
}

func (m *memStore) Put(_ context.Context, name string, wrapped []byte) error {
	m.written++
	// DO NOTHING on conflict, like the real statement: a second writer must not
	// replace the proof.
	if m.wrapped == nil {
		m.name, m.wrapped = name, wrapped
	}
	return nil
}

func (m *memStore) Touch(context.Context, time.Time) error { m.touched++; return nil }

const kek = "chronos-kek"

// A FIRST BOOT WRITES THE CANARY AND PASSES.
//
// An empty table is a new installation, not a lost key: nothing has been
// encrypted under any key yet, so there is nothing to lose and nothing to
// compare against.
func TestAFirstBootWritesTheCanary(t *testing.T) {
	ring, store := newRing(t), &memStore{}

	if err := pii.VerifyKEK(t.Context(), ring, store, kek, time.Now()); err != nil {
		t.Fatalf("a first boot refused to start: %v", err)
	}
	if store.written != 1 || store.wrapped == nil {
		t.Fatalf("the canary was not written (writes=%d)", store.written)
	}
	// And it is a WRAP, not the plaintext filed away.
	if bytes.Equal(store.wrapped, pii.CanaryPlaintext) {
		t.Fatal("the canary was stored in the clear, so it proves nothing about the key")
	}
}

// THE SAME KEY PASSES ON EVERY SUBSEQUENT BOOT.
func TestTheSameKeyVerifies(t *testing.T) {
	ring, store := newRing(t), &memStore{}
	ctx := t.Context()

	if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
			t.Fatalf("boot %d refused with the same key: %v", i+2, err)
		}
	}
	if store.written != 1 {
		t.Errorf("the canary was rewritten %d times; only the first boot may write it",
			store.written)
	}
	if store.touched == 0 {
		t.Error("a passing check recorded nothing, so an operator cannot tell it ran")
	}
}

// A REPLACED KEY REFUSES THE BOOT.
//
// # The whole reason this exists
//
// Every subject's data key is wrapped by the KEK. Replace the KEK — restore a
// backup that predates it, migrate without the key material, recreate it by
// hand, or lose an in-memory instance — and every wrapped data key in the
// database is undecryptable. Permanently.
//
// Nothing else notices: the key store answers healthy because it IS healthy, it
// simply holds a different key. Accounts authenticate normally, because
// authentication touches no personal data. What fails is every notification, one
// at a time, as each tries to turn a pseudonym into an address.
//
// This is that failure arriving once, at boot, where somebody is watching.
func TestAReplacedKeyRefusesToStart(t *testing.T) {
	ring, store := newRing(t), &memStore{}
	ctx := t.Context()

	if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
		t.Fatal(err)
	}

	// The key is REPLACED, exactly as recreating a transit key does.
	replaced := newRing(t)

	err := pii.VerifyKEK(ctx, replaced, store, kek, time.Now())
	if err == nil {
		t.Fatal("a process whose KEK cannot decrypt this installation's data started " +
			"successfully. Every subject's personal data is unreadable, every " +
			"notification will silently fail to resolve an address, and nothing " +
			"anywhere reports it")
	}
	if !errors.Is(err, pii.ErrKEKChanged) {
		t.Fatalf("a replaced key reported %v, which callers cannot distinguish from a "+
			"transient key-store failure — and one of those is retryable while the "+
			"other never recovers", err)
	}
	if store.touched != 0 {
		t.Errorf("a REFUSED check recorded a verification (touches=%d); the timestamp "+
			"would then say the KEK was last verified at the moment it was proven "+
			"wrong", store.touched)
	}
}

// THE CANARY IS NEVER OVERWRITTEN BY A PROCESS HOLDING THE WRONG KEY.
//
// The defeat this forecloses: if a mismatched boot rewrote the canary against
// its own key, the next boot would pass and the check would have destroyed the
// only evidence of the thing it exists to catch.
func TestAMismatchedBootDoesNotRewriteTheCanary(t *testing.T) {
	ring, store := newRing(t), &memStore{}
	ctx := t.Context()

	if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
		t.Fatal(err)
	}
	original := append([]byte(nil), store.wrapped...)

	_ = pii.VerifyKEK(ctx, newRing(t), store, kek, time.Now())

	if !bytes.Equal(store.wrapped, original) {
		t.Fatal("a process holding the wrong key replaced the canary. The next boot " +
			"would pass, and the check would have destroyed the evidence of the " +
			"thing it exists to catch")
	}
	// And the ORIGINAL key still verifies, so the refusal cost nothing.
	if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
		t.Fatalf("the correct key stopped verifying after a mismatched boot: %v", err)
	}
}

// A RENAMED KEY THAT STILL DECRYPTS IS NOT FATAL.
//
// The data is provably readable, which is the only question that matters. An
// operator may legitimately rename or re-point a key, and refusing there would
// make the check a liability rather than a guard.
func TestARenamedKeyThatDecryptsStillStarts(t *testing.T) {
	ring, store := newRing(t), &memStore{}
	ctx := t.Context()

	if err := pii.VerifyKEK(ctx, ring, store, "old-name", time.Now()); err != nil {
		t.Fatal(err)
	}
	if err := pii.VerifyKEK(ctx, ring, store, "new-name", time.Now()); err != nil {
		t.Fatalf("a renamed key that still decrypts refused the boot: %v", err)
	}
}

// A KEY RING THAT LIES IS CAUGHT TOO.
//
// AES-GCM authenticates, so a wrong key errors rather than returning plausible
// bytes — which makes this a check on the key RING rather than on the key. It
// stays because the alternative is trusting that property of an adapter this
// package cannot see.
func TestADecryptionToTheWrongValueIsCaught(t *testing.T) {
	store := &memStore{}
	ctx := t.Context()

	ring := newRing(t)
	if err := pii.VerifyKEK(ctx, ring, store, kek, time.Now()); err != nil {
		t.Fatal(err)
	}

	err := pii.VerifyKEK(ctx, liarRing{}, store, kek, time.Now())
	if !errors.Is(err, pii.ErrKEKChanged) {
		t.Fatalf("a key ring that decrypted to the wrong value reported %v", err)
	}
}

// liarRing unwraps to something that is not the canary.
type liarRing struct{}

func (liarRing) Wrap(context.Context, []byte) (crypto.Wrapped, error) {
	return crypto.Wrapped("wrapped"), nil
}

func (liarRing) Unwrap(context.Context, crypto.Wrapped) ([]byte, error) {
	return []byte("not the canary"), nil
}

// EVERY COLLABORATOR IS REQUIRED.
func TestVerifyKEKRefusesAPartialWiring(t *testing.T) {
	for name, run := range map[string]func() error{
		"no ring": func() error {
			return pii.VerifyKEK(t.Context(), nil, &memStore{}, kek, time.Now())
		},
		"no store": func() error {
			return pii.VerifyKEK(t.Context(), newRing(t), nil, kek, time.Now())
		},
		"no key name": func() error {
			return pii.VerifyKEK(t.Context(), newRing(t), &memStore{}, "", time.Now())
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := run(); err == nil {
				t.Fatalf("the check ran with %s", name)
			}
		})
	}
}

// A KEY STORE THAT IS DOWN IS NOT A CHANGED KEY.
//
// The distinction the health probe could not make, from the other side: an
// unreachable store is transient and retryable, a replaced key never recovers.
// Reporting them alike would make an operator restore a key that was never lost.
func TestAnUnreadableStoreIsNotReportedAsAChangedKey(t *testing.T) {
	store := &memStore{getErr: errors.New("postgres is down")}
	err := pii.VerifyKEK(t.Context(), newRing(t), store, kek, time.Now())
	if err == nil {
		t.Fatal("an unreadable canary store was treated as a pass")
	}
	if errors.Is(err, pii.ErrKEKChanged) {
		t.Fatal("a store that is merely down was reported as a CHANGED KEY. One of " +
			"those is retryable and the other means restoring key material; an " +
			"operator told the wrong one acts on the wrong thing")
	}
}
