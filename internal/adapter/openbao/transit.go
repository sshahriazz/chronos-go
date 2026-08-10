package openbao

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"github.com/chronos/chronos-go/internal/platform/crypto"
	openbao "github.com/openbao/openbao/api/v2"
)

// KeyRing wraps per-subject data keys with a KEK that never leaves OpenBao.
//
// The transit engine encrypts and decrypts on our behalf; the key material is
// created non-exportable, so it cannot be read out even by us. That is what
// makes destroying a wrapped data key a real erasure rather than a filing
// change — there is no second copy of the KEK anywhere to recover it with
// (ADR-028).
type KeyRing struct {
	client *openbao.Client
	kek    string
}

var _ crypto.KeyRing = (*KeyRing)(nil)

func NewKeyRing(client *openbao.Client, kekName string) *KeyRing {
	return &KeyRing{client: client, kek: kekName}
}

// Wrap encrypts a data key with the KEK.
func (k *KeyRing) Wrap(ctx context.Context, dek []byte) (crypto.Wrapped, error) {
	if k.client == nil {
		return nil, errors.New("openbao: client not initialised")
	}
	secret, err := k.client.Logical().WriteWithContext(ctx, "transit/encrypt/"+k.kek,
		map[string]any{"plaintext": base64.StdEncoding.EncodeToString(dek)})
	if err != nil {
		return nil, fmt.Errorf("openbao: wrapping data key: %w", err)
	}
	ct, ok := secret.Data["ciphertext"].(string)
	if !ok || ct == "" {
		return nil, errors.New("openbao: transit returned no ciphertext")
	}
	// "vault:v1:…" — the version prefix is what lets the KEK be rotated without
	// rewrapping every key at once, so it is kept verbatim.
	return crypto.Wrapped(ct), nil
}

// Unwrap recovers a data key.
//
// A destroyed KEK surfaces here, and is reported as ErrKeyDestroyed rather than
// a generic failure: it is the difference between "OpenBao is down, retry" and
// "this data is gone forever, stop asking".
func (k *KeyRing) Unwrap(ctx context.Context, w crypto.Wrapped) ([]byte, error) {
	if k.client == nil {
		return nil, errors.New("openbao: client not initialised")
	}
	secret, err := k.client.Logical().WriteWithContext(ctx, "transit/decrypt/"+k.kek,
		map[string]any{"ciphertext": string(w)})
	if err != nil {
		if isKeyGone(err) {
			return nil, fmt.Errorf("%w: %s", crypto.ErrKeyDestroyed, k.kek)
		}
		return nil, fmt.Errorf("openbao: unwrapping data key: %w", err)
	}
	encoded, ok := secret.Data["plaintext"].(string)
	if !ok {
		return nil, errors.New("openbao: transit returned no plaintext")
	}
	dek, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, fmt.Errorf("openbao: decoding data key: %w", err)
	}
	return dek, nil
}

// isKeyGone distinguishes a destroyed or missing KEK from an unreachable server.
func isKeyGone(err error) bool {
	var respErr *openbao.ResponseError
	if errors.As(err, &respErr) && respErr.StatusCode == 400 {
		for _, e := range respErr.Errors {
			if strings.Contains(e, "encryption key not found") ||
				strings.Contains(e, "no such key") {
				return true
			}
		}
	}
	return false
}
