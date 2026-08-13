// Package argon2id is the password hasher: Argon2id, then a peppered seal.
//
// # Why a pepper at all
//
// A salt stops one precomputed table covering every user. It does nothing once
// the database is stolen, because the salt is stolen with it — the attacker
// simply runs Argon2id per candidate per user, which is expensive but entirely
// possible for the accounts they care about.
//
// A pepper is a key that is NOT in the database. With it, a stolen dump alone is
// useless: every candidate check needs a key the attacker does not have. The
// whole value rests on the pepper living somewhere the database does not, which
// is why it is wrapped by the KEK in OpenBao and never written to Postgres in the
// clear (ADR-028).
//
// # Why encryption rather than concatenation
//
// The obvious pepper is Argon2id(password ‖ pepper). It cannot be rotated: every
// stored digest is bound to the pepper that produced it, and changing the pepper
// requires the plaintext passwords, which is exactly what nobody has. Systems
// that do this have a pepper they can never change, including after it leaks.
//
// Encrypting the digest under the pepper key is reversible with the key, so
// rotation is a batch job that opens each verifier under the old key and re-seals
// it under the new one — no plaintext involved (identity.md §4).
//
// # Why the AAD
//
// AES-256-GCM authenticates additional data without encrypting it. The user id
// and credential id go there, so a verifier row lifted from one account into
// another fails to OPEN rather than validating. Without it, an attacker with a
// single write to the credential table — a SQL injection, a compromised admin
// path — copies their own known-password verifier onto any account they choose,
// and every subsequent login succeeds with a password they know.
package argon2id

import (
	"errors"
	"fmt"
	"math"
	"sync"

	"github.com/chronos/chronos-go/internal/platform/crypto"
)

// PepperKeys holds the unwrapped pepper keys, by version.
//
// Plural, and that is the operational requirement rather than a nicety: rotation
// is not instantaneous, so during a rotation the current key seals new verifiers
// while older ones must still open. A single-key design forces a flag day, and a
// flag day for password verification means every user is locked out for the
// duration.
//
// The keys are held UNWRAPPED in memory, deliberately. The alternative — a
// transit round trip to OpenBao per login — would keep the pepper out of this
// process entirely, which is stronger, but the KeyRing port offers no way to
// authenticate additional data, so it cannot carry the AAD binding above. Given
// the choice between "pepper never in our memory" and "a stolen verifier cannot
// be replayed onto another account", the second prevents a live account takeover
// and the first only raises the cost of an offline attack that already requires
// the database.
type PepperKeys struct {
	mu      sync.RWMutex
	keys    map[int][]byte
	current int
}

var (
	// ErrNoPepperKey means the version a verifier names is not loaded.
	//
	// Almost always operational: a key was destroyed while rows still referenced
	// it. It must NOT be reported as a wrong password — see app.ErrVerifierUnreadable.
	ErrNoPepperKey = errors.New("argon2id: no pepper key for that version")

	// ErrNoCurrentKey means nothing can be hashed at all.
	ErrNoCurrentKey = errors.New("argon2id: no current pepper key is loaded")
)

// NewPepperKeys builds the set. current must be present in keys.
func NewPepperKeys(keys map[int][]byte, current int) (*PepperKeys, error) {
	if len(keys) == 0 {
		return nil, ErrNoCurrentKey
	}
	held := make(map[int][]byte, len(keys))
	for version, key := range keys {
		if err := validVersion(version); err != nil {
			return nil, err
		}
		if len(key) != crypto.DEKSize {
			return nil, fmt.Errorf("argon2id: pepper key v%d is %d bytes, want %d",
				version, len(key), crypto.DEKSize)
		}
		held[version] = key
	}
	if _, ok := held[current]; !ok {
		return nil, fmt.Errorf("%w: v%d is not among the %d loaded keys",
			ErrNoCurrentKey, current, len(held))
	}
	return &PepperKeys{keys: held, current: current}, nil
}

// validVersion bounds a pepper key version at both ends.
//
// The lower bound: version zero is the zero value of an int column. Allowing it
// would make "no version recorded" indistinguishable from "version zero", and a
// verifier written before the column existed would silently resolve to a real
// key.
//
// The upper bound exists so `PepperVersion` can narrow to the int32 the
// `pepper_version` column holds without a range check at the point of
// conversion — and therefore without a //nolint, which is a promise a reader has
// to take on trust. Refusing the value where it ENTERS the system is what makes
// the narrowing provably safe everywhere it is read. No deployment will have two
// billion pepper versions; the point is that the guarantee is structural rather
// than assumed.
func validVersion(version int) error {
	if version < 1 {
		return fmt.Errorf("argon2id: pepper key version %d is not positive", version)
	}
	if version > math.MaxInt32 {
		return fmt.Errorf("argon2id: pepper key version %d exceeds %d, the width of the "+
			"pepper_version column", version, math.MaxInt32)
	}
	return nil
}

// Current returns the version new verifiers are sealed under.
func (p *PepperKeys) Current() int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	return p.current
}

// key returns the key for a version.
func (p *PepperKeys) key(version int) ([]byte, error) {
	p.mu.RLock()
	defer p.mu.RUnlock()
	k, ok := p.keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: v%d", ErrNoPepperKey, version)
	}
	return k, nil
}

// Rotate installs a new current key, KEEPING the old ones openable.
//
// Retiring the old key here would be the bug: verifiers still reference it, and
// they only stop doing so when the rotation batch job has re-sealed every row.
// The operational rule that goes with this — do not destroy the old transit key
// until that job reports zero rows at the old version — is in identity.md §4,
// because nothing in code can enforce it.
func (p *PepperKeys) Rotate(version int, key []byte) error {
	if err := validVersion(version); err != nil {
		return err
	}
	if len(key) != crypto.DEKSize {
		return fmt.Errorf("argon2id: pepper key is %d bytes, want %d", len(key), crypto.DEKSize)
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if existing, ok := p.keys[version]; ok && string(existing) != string(key) {
		// A version is immutable once loaded. Silently replacing it would make
		// every verifier sealed under the old material unopenable, with no event
		// and no error until users start failing to sign in.
		return fmt.Errorf("argon2id: pepper key v%d is already loaded with different material", version)
	}
	p.keys[version] = key
	p.current = version
	return nil
}

// Versions reports every loaded version. For the rotation job's progress check.
func (p *PepperKeys) Versions() []int {
	p.mu.RLock()
	defer p.mu.RUnlock()
	out := make([]int, 0, len(p.keys))
	for v := range p.keys {
		out = append(out, v)
	}
	return out
}
