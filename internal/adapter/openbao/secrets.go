package openbao

import (
	"context"
	"errors"
	"fmt"

	openbao "github.com/openbao/openbao/api/v2"
)

// Secrets reads application secrets out of OpenBao's KV v2 engine.
//
// # A different job from KeyRing, in the same server
//
// The transit engine above holds a key that NEVER LEAVES OpenBao — that is what
// makes erasure a key destruction. This reads values that MUST leave it: a
// Stripe API key is useless unless the process can send it to Stripe.
//
// So this is CUSTODY, not secrecy-in-use. The value is fetched once at startup
// over an authenticated channel instead of sitting in every process's
// environment, where it appears in `docker inspect`, in a crash dump, in
// `/proc/<pid>/environ`, and in the shell history of whoever last deployed
// (BILLING-PLAN.md §7).
type Secrets struct {
	client *openbao.Client
	mount  string
}

// ErrNoSecret reports that a path holds nothing.
//
// Its own error because the caller's response differs: a MISSING path during
// startup means custody was never populated, which is a deployment step nobody
// ran — distinguishable from OpenBao being unreachable, which is a retry.
var ErrNoSecret = errors.New("openbao: no secret at that path")

// NewSecrets builds a reader over one KV mount.
func NewSecrets(client *openbao.Client, mount string) (*Secrets, error) {
	switch {
	case client == nil:
		return nil, errors.New("openbao: a client is required")
	case mount == "":
		return nil, errors.New("openbao: a KV mount is required")
	}
	return &Secrets{client: client, mount: mount}, nil
}

// Values reads every key at one path.
//
// # Why a map and not a single value
//
// One read per secret would be one round trip per secret, and — worse — would
// let a partially-populated path start the process: the API key present, the
// webhook secret missing, and the failure discovered when Stripe first posts an
// event nobody can verify. Reading the whole path makes "is this fully
// configured" answerable in one place.
//
// Non-string values are DROPPED rather than coerced. KV v2 stores JSON, so a
// number or a nested object can be written there by hand; rendering one with
// %v would put `map[...]` into an API key and produce an authentication failure
// that reads like a revoked credential.
func (s *Secrets) Values(ctx context.Context, path string) (map[string]string, error) {
	if path == "" {
		return nil, errors.New("openbao: a secret path is required")
	}
	// KV v2 nests the payload under data/data and puts the mount's own `data`
	// segment in the URL. Reading `<mount>/<path>` instead silently returns
	// nothing on v2, which looks exactly like an empty secret.
	secret, err := s.client.Logical().ReadWithContext(ctx, s.mount+"/data/"+path)
	if err != nil {
		return nil, fmt.Errorf("openbao: reading %s: %w", path, err)
	}
	if secret == nil || secret.Data == nil {
		return nil, fmt.Errorf("%w: %s/%s", ErrNoSecret, s.mount, path)
	}
	raw, ok := secret.Data["data"].(map[string]any)
	if !ok {
		// A v1 mount answers without the nested `data`. Reported rather than
		// worked around: silently accepting both would mean a v1 mount passes
		// startup and then loses the version history that makes a secret
		// rotation auditable.
		return nil, fmt.Errorf("openbao: %s/%s is not a KV v2 secret; mount it with "+
			"options.version=2", s.mount, path)
	}
	if len(raw) == 0 {
		return nil, fmt.Errorf("%w: %s/%s", ErrNoSecret, s.mount, path)
	}

	out := make(map[string]string, len(raw))
	for k, v := range raw {
		if str, ok := v.(string); ok {
			out[k] = str
		}
	}
	return out, nil
}
