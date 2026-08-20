// Package totpseal seals and opens the TOTP shared secret.
//
// # Why sealing and not hashing
//
// Every other authentication secret this system stores is one-way: a password
// verifier, a token digest, a recovery-code digest. Verification hashes what was
// presented and compares. A TOTP secret cannot work that way — RFC 6238 derives
// the code FROM the secret, so the secret has to be recoverable in plaintext at
// every verification. Hashing it would produce a credential nothing can ever
// check.
//
// That makes it the one identity secret that must be encrypted rather than
// digested, and encryption brings the two obligations a digest does not have: a
// key that is not in the database, and a binding to the row it belongs to.
//
// # Where it is stored, and where it is NOT
//
// In `credential.verifier`, with `kind = 'totp'`, beside the password verifier
// that shares the column (migration 00008). NOT in the PII vault: the vault is
// for PERSONAL DATA under a per-subject key that erasure destroys, and a TOTP
// secret is key material. Putting it there would tie the ability to complete an
// authentication to the erasure key, so a subject's crypto-shredding would take
// their second factor with it — correct for an address, incoherent for a
// credential the account still needs while it exists.
//
// It cannot go in an event either, for the reason every verifier cannot: an
// event is permanent and replicated, so a secret in one survives the factor being
// removed, survives erasure, and stays usable forever (identity.md §4, ADR-002).
//
// # Why the AAD
//
// AES-256-GCM authenticates additional data without encrypting it. The subject
// pseudonym and the credential id go there, so a `verifier` value lifted from one
// account's row into another's fails to OPEN rather than producing a working
// second factor for an attacker who chose the secret. Without it, a single write
// to the credential table — a SQL injection, a compromised admin path — installs
// an authenticator the attacker controls on any account they name, and every
// subsequent login succeeds with codes they can generate.
//
// This mirrors the argon2id hasher's binding exactly, and deliberately: two
// secrets living in one column with two different binding rules is how one of
// them ends up unbound.
package totpseal

import (
	"encoding/base64"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"sync"

	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Keys holds the unwrapped sealing keys, by version.
//
// A sibling of argon2id.PepperKeys rather than a reuse of it, and the shape is
// copied on purpose: one versioning scheme for both secrets in the `credential`
// table, one `pepper_version` column recording which key opened a row, one rule
// that version 0 does not exist. The hasher's type could not simply be shared —
// its key accessor is unexported, and widening it to serve a second consumer
// would mean the password pepper and this key are one key, which is the opposite
// of what separate versions buy.
//
// Plural because rotation is not instantaneous: while a batch job re-seals rows,
// the current key seals new enrollments and every older key must still open. A
// single-key design forces a flag day, and a flag day for a second factor locks
// every user out of their own account for its duration.
//
// The keys are held UNWRAPPED in memory, for the same reason the pepper is: the
// crypto.KeyRing port is Wrap/Unwrap with no additional-data parameter, so a
// transit round trip per verification could not carry the AAD binding above.
// Given the choice, "a stolen row cannot be replayed onto another account"
// prevents a live account takeover and "the key is never in our memory" only
// raises the cost of an offline attack that already requires the database.
type Keys struct {
	mu      sync.RWMutex
	keys    map[int][]byte
	current int
}

var (
	// ErrNoKey means the version a sealed secret names is not loaded.
	//
	// Almost always operational: a key was destroyed while rows still referenced
	// it. It must never be reported to a caller as a wrong code — see
	// app.ErrSecretUnreadable.
	ErrNoKey = errors.New("totpseal: no sealing key for that version")

	// ErrNoCurrentKey means nothing can be sealed at all.
	ErrNoCurrentKey = errors.New("totpseal: no current sealing key is loaded")
)

// NewKeys builds the set. current must be present in keys.
func NewKeys(keys map[int][]byte, current int) (*Keys, error) {
	if len(keys) == 0 {
		return nil, ErrNoCurrentKey
	}
	held := make(map[int][]byte, len(keys))
	for version, key := range keys {
		if err := validVersion(version); err != nil {
			return nil, err
		}
		if len(key) != crypto.DEKSize {
			return nil, fmt.Errorf("totpseal: sealing key v%d is %d bytes, want %d",
				version, len(key), crypto.DEKSize)
		}
		held[version] = key
	}
	if _, ok := held[current]; !ok {
		return nil, fmt.Errorf("%w: v%d is not among the %d loaded keys",
			ErrNoCurrentKey, current, len(held))
	}
	return &Keys{keys: held, current: current}, nil
}

// validVersion bounds a key version at both ends.
//
// The lower bound: zero is the zero value of an int column, so allowing it makes
// "no version recorded" indistinguishable from "version zero", and a row written
// before the column meant anything would silently resolve to a real key.
//
// The upper bound is what lets KeyVersion narrow to the int32 the
// `pepper_version` column holds without a range check at the conversion — and so
// without a //nolint, which is a promise the reader has to take on trust.
// Refusing the value where it ENTERS the system is what makes the narrowing
// provably safe everywhere it is read.
func validVersion(version int) error {
	if version < 1 {
		return fmt.Errorf("totpseal: sealing key version %d is not positive", version)
	}
	if version > math.MaxInt32 {
		return fmt.Errorf("totpseal: sealing key version %d exceeds %d, the width of the "+
			"pepper_version column", version, math.MaxInt32)
	}
	return nil
}

// Current returns the version new secrets are sealed under.
func (k *Keys) Current() int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	return k.current
}

// key returns the key for a version.
func (k *Keys) key(version int) ([]byte, error) {
	k.mu.RLock()
	defer k.mu.RUnlock()
	held, ok := k.keys[version]
	if !ok {
		return nil, fmt.Errorf("%w: v%d", ErrNoKey, version)
	}
	return held, nil
}

// Rotate installs a new current key, KEEPING the old ones openable.
//
// Retiring the old key here would be the bug: rows still reference it, and they
// stop only when the re-sealing batch job has visited every one. The operational
// rule that goes with it — do not destroy the old transit key until that job
// reports zero rows at the old version — cannot be enforced in code, which is why
// Versions exists for the job to check against.
func (k *Keys) Rotate(version int, key []byte) error {
	if err := validVersion(version); err != nil {
		return err
	}
	if len(key) != crypto.DEKSize {
		return fmt.Errorf("totpseal: sealing key is %d bytes, want %d", len(key), crypto.DEKSize)
	}
	k.mu.Lock()
	defer k.mu.Unlock()
	if existing, ok := k.keys[version]; ok && string(existing) != string(key) {
		// A version is immutable once loaded. Silently replacing it would make
		// every secret sealed under the old material unopenable, with no event and
		// no error until users start failing their second factor.
		return fmt.Errorf("totpseal: sealing key v%d is already loaded with different material",
			version)
	}
	k.keys[version] = key
	k.current = version
	return nil
}

// Versions reports every loaded version, for the re-sealing job's progress check.
func (k *Keys) Versions() []int {
	k.mu.RLock()
	defer k.mu.RUnlock()
	out := make([]int, 0, len(k.keys))
	for v := range k.keys {
		out = append(out, v)
	}
	return out
}

// Sealer implements app.TotpSealer.
type Sealer struct{ keys *Keys }

var _ app.TotpSealer = (*Sealer)(nil)

// New builds the sealer.
func New(keys *Keys) (*Sealer, error) {
	if keys == nil {
		return nil, errors.New("totpseal: a key set is required; without one a shared secret " +
			"would have to be stored in the clear, and the credential table is exactly the " +
			"thing an attacker who reaches the database already has")
	}
	return &Sealer{keys: keys}, nil
}

// prefix identifies this encoding in the shared `verifier` column.
//
// The column holds Argon2id verifiers too, which begin "$argon2id$". A distinct
// leading token means a value handed to the wrong opener is refused by its shape
// rather than by a decryption failure several layers in.
const prefix = "totp"

// Seal encrypts a shared secret for one credential on one subject.
//
// The output is `totp$v<version>$<base64url ciphertext>`. The version is OUTSIDE
// the ciphertext because it selects the key needed to open it; putting it inside
// would be a chicken-and-egg. It is not authenticated, and does not need to be:
// naming a different version yields a key that cannot open the body, which GCM
// rejects. The worst an attacker who can rewrite it achieves is a failed open.
func (s *Sealer) Seal(secret, subjectID string, cred ids.CredentialID) (string, error) {
	switch {
	case secret == "":
		return "", errors.New("totpseal: an empty shared secret seals to a credential that " +
			"can never produce a code")
	case subjectID == "":
		return "", errors.New("totpseal: a subject id is required; it is half the binding that " +
			"stops a row being moved between accounts")
	case cred.IsZero():
		return "", errors.New("totpseal: a credential id is required; it is half the binding " +
			"that stops a row being moved between accounts")
	}

	version := s.keys.Current()
	key, err := s.keys.key(version)
	if err != nil {
		return "", err
	}
	ciphertext, err := crypto.Seal(key, []byte(secret), aad(subjectID, cred))
	if err != nil {
		return "", fmt.Errorf("totpseal: sealing a shared secret: %w", err)
	}
	return prefix + "$v" + strconv.Itoa(version) + "$" +
		base64.RawURLEncoding.EncodeToString(ciphertext), nil
}

// Open recovers a shared secret.
//
// Every failure is app.ErrSecretUnreadable except a missing key version, which is
// ErrNoKey. The split is the same one the password hasher draws: "this cannot be
// read" is a fact about one row, while "the key for v2 is gone" is an outage
// affecting every row sealed under it, and the two need different people woken
// up. Neither is ever a wrong code — reporting them as one would make a destroyed
// key look like every user suddenly typing badly.
func (s *Sealer) Open(sealed, subjectID string, cred ids.CredentialID) (string, error) {
	if subjectID == "" || cred.IsZero() {
		return "", app.ErrSecretUnreadable
	}
	version, body, err := decode(sealed)
	if err != nil {
		return "", err
	}
	key, err := s.keys.key(version)
	if err != nil {
		return "", err
	}
	plaintext, err := crypto.Open(key, body, aad(subjectID, cred))
	if err != nil {
		// A wrong subject, a wrong credential, a tampered ciphertext and a key
		// that no longer opens it are ONE outcome here, because crypto.Open does
		// not distinguish them either and a caller could do nothing different with
		// the distinction.
		return "", app.ErrSecretUnreadable
	}
	return string(plaintext), nil
}

// KeyVersion reports the version Seal is currently sealing under.
//
// It is on the port because a sealed secret is useless without it: the version is
// duplicated into the `pepper_version` column so a re-sealing job can find rows
// at an old version with `pepper_version < n` rather than parsing every row.
//
// The value must be >= 1 and the floor is not decoration. A row written at 0 is
// invisible to that query, so the job skips it silently and the account loses its
// second factor the moment the old key is destroyed — months after the mistake,
// with nothing left to reconstruct the secret from. validVersion makes 0
// unreachable; this returns it only if that guarantee has been broken, so a
// caller checking for it is checking something real.
func (s *Sealer) KeyVersion() int32 {
	v := s.keys.Current()
	if v < 1 || v > math.MaxInt32 {
		return 0
	}
	return int32(v)
}

// decode splits a sealed value into its version and its ciphertext.
func decode(sealed string) (int, []byte, error) {
	parts := strings.Split(sealed, "$")
	if len(parts) != 3 || parts[0] != prefix || !strings.HasPrefix(parts[1], "v") {
		return 0, nil, app.ErrSecretUnreadable
	}
	version, err := strconv.Atoi(parts[1][1:])
	if err != nil || validVersion(version) != nil {
		return 0, nil, app.ErrSecretUnreadable
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return 0, nil, app.ErrSecretUnreadable
	}
	return version, body, nil
}

// aad binds a sealed secret to the row that holds it.
//
// subject id, a colon, credential id — the same construction the password hasher
// uses, and unambiguous for the same reason: a colon cannot appear in a prefixed
// ULID (ADR-030), so the boundary between the two cannot be forged by choosing a
// clever identifier.
//
// The SUBJECT rather than the user id, because subject_id is the column this row
// is actually keyed by; binding to a value the row does not carry would let a row
// be moved to another subject and still open.
func aad(subjectID string, cred ids.CredentialID) []byte {
	b := make([]byte, 0, 64)
	b = append(b, subjectID...)
	b = append(b, ':')
	b = cred.AppendTo(b)
	return b
}
