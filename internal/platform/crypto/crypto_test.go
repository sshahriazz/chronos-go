package crypto_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/crypto"
)

func TestSealOpenRoundTrip(t *testing.T) {
	dek, err := crypto.NewDEK()
	if err != nil {
		t.Fatal(err)
	}
	const secret = "sam.larsson@example.test"

	sealed, err := crypto.Seal(dek, []byte(secret), []byte("sub_1"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(sealed, []byte(secret)) {
		t.Fatal("the plaintext appears in the ciphertext")
	}

	opened, err := crypto.Open(dek, sealed, []byte("sub_1"))
	if err != nil {
		t.Fatal(err)
	}
	if string(opened) != secret {
		t.Fatalf("got %q, want %q", opened, secret)
	}
}

// THE property. Without the key, the ciphertext is unreadable — which is what
// makes erasure a key deletion rather than a migration (ADR-002).
func TestWithoutTheKeyThereIsNothing(t *testing.T) {
	dek, _ := crypto.NewDEK()
	sealed, _ := crypto.Seal(dek, []byte("sam@example.test"), []byte("sub_1"))

	other, _ := crypto.NewDEK()
	if _, err := crypto.Open(other, sealed, []byte("sub_1")); !errors.Is(err, crypto.ErrUnopenable) {
		t.Fatalf("a different key opened the ciphertext: %v", err)
	}
}

// The subject id is authenticated, so a row copied into another subject fails
// to open rather than decrypting into the wrong person's profile.
func TestCiphertextIsBoundToItsSubject(t *testing.T) {
	dek, _ := crypto.NewDEK()
	sealed, _ := crypto.Seal(dek, []byte("sam@example.test"), []byte("sub_victim"))

	if _, err := crypto.Open(dek, sealed, []byte("sub_attacker")); !errors.Is(err, crypto.ErrUnopenable) {
		t.Fatal("a ciphertext moved to another subject id still decrypted — " +
			"one row copied between subjects would leak a real address")
	}
}

// GCM authenticates, so a modified ciphertext fails rather than producing
// plausible garbage that gets stored or displayed.
func TestTamperingIsDetected(t *testing.T) {
	dek, _ := crypto.NewDEK()
	sealed, _ := crypto.Seal(dek, []byte("sam@example.test"), []byte("sub_1"))

	for i := range sealed {
		altered := bytes.Clone(sealed)
		altered[i] ^= 0x01
		if _, err := crypto.Open(dek, altered, []byte("sub_1")); err == nil {
			t.Fatalf("flipping byte %d produced a value that still opened", i)
		}
	}
}

// Nonce reuse under one key is the catastrophic mistake with GCM. Generating it
// inside Seal removes the chance of a caller managing it badly, and this checks
// two encryptions of the same value differ.
func TestNoncesAreNotReused(t *testing.T) {
	dek, _ := crypto.NewDEK()
	seen := map[string]struct{}{}
	for range 1000 {
		sealed, err := crypto.Seal(dek, []byte("same value every time"), []byte("sub_1"))
		if err != nil {
			t.Fatal(err)
		}
		nonce := string(sealed[:12])
		if _, dup := seen[nonce]; dup {
			t.Fatal("a nonce repeated under one key; GCM offers no confidentiality after that")
		}
		seen[nonce] = struct{}{}
	}
}

func TestKeysAreDistinct(t *testing.T) {
	seen := map[string]struct{}{}
	for range 1000 {
		k, err := crypto.NewDEK()
		if err != nil {
			t.Fatal(err)
		}
		if len(k) != crypto.DEKSize {
			t.Fatalf("key is %d bytes, want %d", len(k), crypto.DEKSize)
		}
		if _, dup := seen[string(k)]; dup {
			t.Fatal("generated the same data key twice")
		}
		seen[string(k)] = struct{}{}
	}
}

func TestShortCiphertextIsRejected(t *testing.T) {
	dek, _ := crypto.NewDEK()
	if _, err := crypto.Open(dek, []byte{1, 2, 3}, nil); !errors.Is(err, crypto.ErrUnopenable) {
		t.Fatalf("a truncated ciphertext must be refused, got %v", err)
	}
}

func TestZero(t *testing.T) {
	k, _ := crypto.NewDEK()
	crypto.Zero(k)
	for i, b := range k {
		if b != 0 {
			t.Fatalf("byte %d survived zeroing", i)
		}
	}
}
