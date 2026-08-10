// Package crypto is the envelope-encryption kernel behind crypto-shredding.
//
// The shape, and why it is this shape:
//
//	KEK   one key-encryption key, held in OpenBao, NEVER leaves it (ADR-028)
//	DEK   one data-encryption key PER SUBJECT, generated here, used here
//	      and stored only in its wrapped form
//
// Personal data is sealed with the subject's DEK. The DEK is stored wrapped by
// the KEK, and nothing else. ERASURE IS DESTROYING THE WRAPPED DEK: every value
// that subject ever had becomes ciphertext nobody can open, without touching the
// rows that hold it (ADR-002).
//
// A per-subject key in OpenBao would be simpler and does not scale — millions of
// users means millions of transit keys, and listing or rotating them becomes an
// operation nobody can run. Envelope encryption keeps OpenBao holding exactly
// one key and puts the per-subject material in Postgres, where it is cheap and
// where deleting one row is an ordinary operation.
package crypto

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
)

// DEKSize is the data-encryption key length. AES-256.
const DEKSize = 32

// KeyRing wraps and unwraps data keys using a key that never leaves custody.
//
// Wrap and Unwrap are the ONLY operations. There is deliberately no Export: a
// key that can be exported can be copied, and a copied key means destroying the
// original erases nothing.
type KeyRing interface {
	// Wrap encrypts a data key with the key-encryption key.
	Wrap(ctx context.Context, dek []byte) (Wrapped, error)

	// Unwrap recovers a data key.
	Unwrap(ctx context.Context, w Wrapped) ([]byte, error)
}

// Wrapped is a data key encrypted by the KEK.
//
// Opaque bytes: the format belongs to whatever holds the KEK, and reading it
// here would tie the vault to one provider.
type Wrapped []byte

// NewDEK generates a data-encryption key.
//
// From crypto/rand only. A key derived from anything predictable — a subject id,
// a timestamp — is a key an attacker can regenerate, and then erasure erases
// nothing.
func NewDEK() ([]byte, error) {
	dek := make([]byte, DEKSize)
	if _, err := io.ReadFull(rand.Reader, dek); err != nil {
		return nil, fmt.Errorf("crypto: generating data key: %w", err)
	}
	return dek, nil
}

// Seal encrypts a value with a data key.
//
// AES-256-GCM: authenticated, so a modified ciphertext fails to open rather than
// producing plausible garbage. The nonce is random per call and prefixed to the
// output — reusing a nonce under one key is the catastrophic mistake with GCM,
// and generating it fresh here removes the chance of a caller managing it badly.
//
// additionalData is authenticated but NOT encrypted. Pass the subject id: a
// ciphertext then cannot be moved from one subject's row to another's, because
// it will not open under a different subject.
func Seal(dek, plaintext, additionalData []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, fmt.Errorf("crypto: generating nonce: %w", err)
	}
	// Seal appends to its first argument, so the nonce leads the ciphertext and
	// Open can recover it without a second column.
	return gcm.Seal(nonce, nonce, plaintext, additionalData), nil
}

// Open decrypts a value.
//
// Returns ErrUnopenable for anything that does not authenticate. That is the
// expected outcome after erasure — the DEK is gone — and it is deliberately not
// distinguishable from tampering: both mean "this cannot be read", and treating
// them differently would let a caller act on the difference.
func Open(dek, ciphertext, additionalData []byte) ([]byte, error) {
	gcm, err := newGCM(dek)
	if err != nil {
		return nil, err
	}
	if len(ciphertext) < gcm.NonceSize() {
		return nil, ErrUnopenable
	}
	nonce, body := ciphertext[:gcm.NonceSize()], ciphertext[gcm.NonceSize():]
	out, err := gcm.Open(nil, nonce, body, additionalData)
	if err != nil {
		return nil, ErrUnopenable
	}
	return out, nil
}

func newGCM(dek []byte) (cipher.AEAD, error) {
	if len(dek) != DEKSize {
		return nil, fmt.Errorf("crypto: data key is %d bytes, want %d", len(dek), DEKSize)
	}
	block, err := aes.NewCipher(dek)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, fmt.Errorf("crypto: %w", err)
	}
	return gcm, nil
}

// Zero overwrites a key in memory.
//
// Best effort, and worth doing anyway: it shortens the window in which a heap
// dump or a swapped page contains usable key material. It is not a guarantee —
// Go may have copied the slice — which is why the durable protection is that the
// key only ever exists unwrapped for the length of one operation.
func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

var (
	// ErrUnopenable means the ciphertext did not authenticate: the key is gone,
	// the data was altered, or it belongs to a different subject. All three
	// mean the same thing to a caller — it cannot be read.
	ErrUnopenable = errors.New("crypto: ciphertext cannot be opened")

	// ErrKeyDestroyed means the wrapping key itself is gone, so no data key
	// under it can ever be recovered.
	ErrKeyDestroyed = errors.New("crypto: key-encryption key has been destroyed")
)
