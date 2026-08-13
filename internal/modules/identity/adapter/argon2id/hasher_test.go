package argon2id_test

import (
	"context"
	"crypto/rand"
	"errors"
	"io"
	"math"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Cheap parameters. The algorithm's behaviour is identical at any cost, and the
// default cost would make this suite take minutes.
var testParams = argon2id.Params{
	Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
}

func keyBytes(t *testing.T, fill byte) []byte {
	t.Helper()
	k := make([]byte, crypto.DEKSize)
	for i := range k {
		k[i] = fill
	}
	return k
}

func newHasher(t *testing.T) (*argon2id.Hasher, *argon2id.PepperKeys) {
	t.Helper()
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	return h, pepper
}

// withParams copies base and raises exactly one dimension.
func withParams(base argon2id.Params, raise func(*argon2id.Params)) argon2id.Params {
	raise(&base)
	return base
}

func newIDs(t *testing.T) (ids.UserID, ids.CredentialID) {
	t.Helper()
	now := time.Now()
	return ids.New[ids.User](now, rand.Reader), ids.New[ids.Credential](now, rand.Reader)
}

// The round trip works, and the wrong password does not.
func TestAPasswordVerifiesAgainstItsOwnHash(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	v, err := h.Hash(ctx, "correct horse battery", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	ok, err := h.Verify(ctx, "correct horse battery", v, user, cred)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("the correct password did not verify against its own hash")
	}

	ok, err = h.Verify(ctx, "correct horse batterz", v, user, cred)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if ok {
		t.Fatal("a wrong password verified")
	}
}

// THE ONE THAT MATTERS: a verifier cannot be moved to another account.
//
// Without the AAD binding, an attacker with a single write to the credential
// table — SQL injection, a compromised admin path, a restored backup with an
// edit — copies their own known-password verifier onto any account they choose,
// and every subsequent login succeeds with a password they know. Nothing about
// the row looks wrong afterwards.
func TestAVerifierCopiedToAnotherAccountDoesNotValidate(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	attacker, attackerCred := newIDs(t)
	victim, victimCred := newIDs(t)

	v, err := h.Hash(ctx, "attackers own password", attacker, attackerCred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// The attacker's verifier, pasted onto the victim's row.
	ok, err := h.Verify(ctx, "attackers own password", v, victim, victimCred)
	if ok {
		t.Fatal("a verifier copied onto another account validated: one write to the " +
			"credential table takes over any account, with a password the attacker chose")
	}
	if err == nil {
		t.Fatal("a copied verifier was reported as an ordinary wrong password: the tampering " +
			"is indistinguishable from a user mistyping, so nothing surfaces it")
	}
	if !errors.Is(err, app.ErrVerifierUnreadable) {
		t.Errorf("error is %v, want app.ErrVerifierUnreadable", err)
	}
}

// Changing EITHER id breaks the binding, not just the pair together.
func TestBothIdentifiersAreBoundIndependently(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)
	otherUser, otherCred := newIDs(t)

	v, err := h.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if ok, _ := h.Verify(ctx, "a fine password", v, otherUser, cred); ok {
		t.Error("the verifier validated under a different user id: the user is not bound")
	}
	if ok, _ := h.Verify(ctx, "a fine password", v, user, otherCred); ok {
		t.Error("the verifier validated under a different credential id: the credential is " +
			"not bound, so a verifier moves freely between one user's own methods")
	}
}

// Every hash of the same password is different.
//
// If two are equal, the salt is not being used — and a single precomputed table
// then covers every user who chose that password.
func TestTheSamePasswordHashesDifferentlyEveryTime(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	seen := make(map[string]bool)
	for range 5 {
		v, err := h.Hash(ctx, "same password twice", user, cred)
		if err != nil {
			t.Fatalf("hash: %v", err)
		}
		if seen[v] {
			t.Fatal("two hashes of the same password are identical: the salt is not random, " +
				"so one precomputed table covers every user who chose this password")
		}
		seen[v] = true
	}
}

// The stored form contains no recoverable digest.
//
// This is what the pepper buys. A dump of the credential table must be useless
// without a key that is not in the dump — so the final field must NOT be a bare
// Argon2id output.
func TestTheStoredFormRevealsNoUsableDigest(t *testing.T) {
	ctx := context.Background()
	h, pepper := newHasher(t)
	user, cred := newIDs(t)

	v, err := h.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// An attacker holding the dump but not the pepper key: a hasher with the
	// right parameters and the wrong key must not verify the correct password.
	wrongKey, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0x99)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	attacker, err := argon2id.New(wrongKey, testParams)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	if ok, _ := attacker.Verify(ctx, "a fine password", v, user, cred); ok {
		t.Fatal("the correct password verified WITHOUT the pepper key: the stored digest is " +
			"crackable from a database dump alone, which is the whole thing the pepper prevents")
	}

	// And the same hasher with the right key still works, so the test above is
	// not passing for some unrelated reason.
	right, err := argon2id.New(pepper, testParams)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	if ok, err := right.Verify(ctx, "a fine password", v, user, cred); !ok || err != nil {
		t.Fatalf("the correct key failed to verify (ok=%v err=%v), so the previous assertion "+
			"proves nothing", ok, err)
	}
}

// An old pepper version still opens after rotation, and new hashes use the new
// key.
//
// Retiring the old key at rotation time is the tempting bug: verifiers still
// reference it until the batch job has re-sealed every row, and the failure is
// every user locked out at once.
func TestRotationKeepsOlderVerifiersOpenable(t *testing.T) {
	ctx := context.Background()
	h, pepper := newHasher(t)
	user, cred := newIDs(t)

	old, err := h.Hash(ctx, "set before rotation", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if err := pepper.Rotate(2, keyBytes(t, 0xB2)); err != nil {
		t.Fatalf("rotate: %v", err)
	}

	ok, err := h.Verify(ctx, "set before rotation", old, user, cred)
	if err != nil {
		t.Fatalf("a verifier from before the rotation could not be read: %v", err)
	}
	if !ok {
		t.Fatal("a verifier sealed under the previous pepper key stopped validating after " +
			"rotation: every user is locked out until the batch job finishes")
	}

	if !h.NeedsRehash(old) {
		t.Error("a verifier at the old pepper version was not flagged for rehash, so the " +
			"rotation never completes and the old key can never be destroyed")
	}

	fresh, err := h.Hash(ctx, "set after rotation", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h.NeedsRehash(fresh) {
		t.Error("a freshly written verifier was immediately flagged for rehash: every " +
			"successful login rehashes, and the flag stops meaning anything")
	}
}

// A version already loaded cannot be silently replaced with different material.
func TestAPepperVersionIsImmutableOnceLoaded(t *testing.T) {
	_, pepper := newHasher(t)
	if err := pepper.Rotate(1, keyBytes(t, 0xEE)); err == nil {
		t.Fatal("pepper key v1 was replaced with different material: every verifier sealed " +
			"under the original becomes unopenable, with no error until users cannot sign in")
	}
	// Re-installing the SAME material is fine — a reload is not a mistake.
	if err := pepper.Rotate(1, keyBytes(t, 0xA1)); err != nil {
		t.Errorf("reloading identical key material failed: %v", err)
	}
}

// A missing pepper version is an ERROR, never a wrong password.
//
// A key destroyed while rows still reference it looks exactly like every user
// mistyping at once. Reporting it as a mismatch means the support tickets say
// "wrong password" and nobody looks at the operational cause.
func TestAMissingPepperVersionIsNotReportedAsAWrongPassword(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	v, err := h.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	// A hasher that has never loaded v1.
	other, err := argon2id.NewPepperKeys(map[int][]byte{7: keyBytes(t, 0x77)}, 7)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	stranded, err := argon2id.New(other, testParams)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}

	ok, err := stranded.Verify(ctx, "a fine password", v, user, cred)
	if ok {
		t.Fatal("a verifier validated under a hasher lacking its pepper key")
	}
	if !errors.Is(err, app.ErrVerifierUnreadable) {
		t.Fatalf("error is %v; a destroyed pepper key must not be indistinguishable from a "+
			"wrong password", err)
	}
}

// Weaker parameters are flagged; equal or stronger ones are not.
func TestOnlyUnderpoweredVerifiersAreFlaggedForRehash(t *testing.T) {
	ctx := context.Background()
	h, pepper := newHasher(t)
	user, cred := newIDs(t)

	weak, err := argon2id.New(pepper, argon2id.Params{
		Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	v, err := weak.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}

	if h.NeedsRehash(v) {
		t.Error("a verifier at the current parameters was flagged for rehash")
	}

	// Each dimension raised ALONE. Raising several at once means a single
	// surviving comparison catches every case, and dropping any one of the others
	// goes unnoticed — which is exactly what happened here: a test that raised
	// memory and time together still passed with the memory comparison deleted.
	base := argon2id.Params{Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}
	for _, tc := range []struct {
		dimension string
		params    argon2id.Params
	}{
		{"memory", withParams(base, func(p *argon2id.Params) { p.Memory = 16 * 1024 })},
		{"time", withParams(base, func(p *argon2id.Params) { p.Time = 2 })},
		{"parallelism", withParams(base, func(p *argon2id.Params) { p.Parallelism = 2 })},
		{"salt length", withParams(base, func(p *argon2id.Params) { p.SaltLen = 32 })},
		{"key length", withParams(base, func(p *argon2id.Params) { p.KeyLen = 64 })},
	} {
		t.Run("raised "+tc.dimension, func(t *testing.T) {
			stronger, err := argon2id.New(pepper, tc.params)
			if err != nil {
				t.Fatalf("hasher: %v", err)
			}
			if !stronger.NeedsRehash(v) {
				t.Errorf("a verifier below the current %s was not flagged: raising that "+
					"parameter has no effect on any existing password, ever", tc.dimension)
			}
		})
	}

	stronger, err := argon2id.New(pepper, argon2id.Params{
		Memory: 16 * 1024, Time: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32,
	})
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}

	// And a verifier from the STRONGER hasher is not downgraded by the weaker
	// one — a rehash must never reduce cost.
	sv, err := stronger.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	if h.NeedsRehash(sv) {
		t.Error("a stronger verifier was flagged for rehash by a weaker hasher: a rolling " +
			"deploy would downgrade every password the newer instances had upgraded")
	}
}

// Malformed stored values are rejected, never treated as a match.
func TestMalformedVerifiersAreRejected(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	valid, err := h.Hash(ctx, "a fine password", user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	parts := strings.Split(valid, "$")

	for _, tc := range []struct{ name, in string }{
		{"empty", ""},
		{"not a verifier", "hunter2"},
		{"too few fields", "$argon2id$v=19$m=8192,t=1,p=1$c2FsdA"},
		{"wrong algorithm", strings.Replace(valid, "argon2id", "argon2i", 1)},
		{"wrong argon version", strings.Replace(valid, "v=19", "v=16", 1)},
		{"unparseable cost", strings.Replace(valid, parts[3], "m=x,t=1,p=1", 1)},
		{"zero memory", strings.Replace(valid, parts[3], "m=0,t=1,p=1", 1)},
		{"pepper version zero", strings.Replace(valid, "$k=1$", "$k=0$", 1)},
		{"pepper version missing", strings.Replace(valid, "$k=1$", "$1$", 1)},
		{"salt not base64", strings.Replace(valid, parts[4], "!!!!", 1)},
		{"sealed digest truncated", strings.Replace(valid, parts[6], "AAAA", 1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ok, err := h.Verify(ctx, "a fine password", tc.in, user, cred)
			if ok {
				t.Fatal("a malformed verifier validated a password")
			}
			if err == nil {
				t.Fatal("a malformed verifier was reported as an ordinary wrong password")
			}
			if !errors.Is(err, app.ErrVerifierUnreadable) {
				t.Errorf("error is %v, want app.ErrVerifierUnreadable", err)
			}
		})
	}
}

// A hasher cannot be built without a pepper, or below the cost floors.
func TestAMisconfiguredHasherRefusesToBuild(t *testing.T) {
	if _, err := argon2id.New(nil, testParams); err == nil {
		t.Error("a hasher was built with no pepper keys: every verifier is a bare Argon2id " +
			"digest and a database dump is crackable offline")
	}
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	for _, tc := range []struct {
		name string
		p    argon2id.Params
	}{
		{"memory below the floor", argon2id.Params{Memory: 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32}},
		{"no iterations", argon2id.Params{Memory: 8192, Time: 0, Parallelism: 1, SaltLen: 16, KeyLen: 32}},
		{"no lanes", argon2id.Params{Memory: 8192, Time: 1, Parallelism: 0, SaltLen: 16, KeyLen: 32}},
		{"short salt", argon2id.Params{Memory: 8192, Time: 1, Parallelism: 1, SaltLen: 8, KeyLen: 32}},
		{"short key", argon2id.Params{Memory: 8192, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 16}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := argon2id.New(pepper, tc.p); err == nil {
				t.Errorf("a hasher was built with %s", tc.name)
			}
		})
	}
}

// A pepper key set must be well formed.
func TestAMalformedPepperKeySetIsRefused(t *testing.T) {
	for _, tc := range []struct {
		name    string
		keys    map[int][]byte
		current int
	}{
		{"empty", map[int][]byte{}, 1},
		{"current not present", map[int][]byte{1: make([]byte, crypto.DEKSize)}, 2},
		{"version zero", map[int][]byte{0: make([]byte, crypto.DEKSize)}, 0},
		{"negative version", map[int][]byte{-1: make([]byte, crypto.DEKSize)}, -1},
		{"short key", map[int][]byte{1: make([]byte, 16)}, 1},
		// The upper bound is what makes PepperVersion's narrowing to int32 safe
		// without a range check at the conversion. Refusing the value where it
		// ENTERS the key set is the whole argument; without this case the
		// conversion is merely untested rather than provably in range.
		{"version wider than the column",
			map[int][]byte{math.MaxInt32 + 1: make([]byte, crypto.DEKSize)}, math.MaxInt32 + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := argon2id.NewPepperKeys(tc.keys, tc.current); err == nil {
				t.Errorf("a pepper key set was accepted with %s", tc.name)
			}
		})
	}
}

// Hashing needs both identifiers, or the AAD binding silently degrades.
func TestHashingWithoutIdentifiersIsRefused(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	if _, err := h.Hash(ctx, "a fine password", ids.UserID{}, cred); err == nil {
		t.Error("a verifier was produced with no user id: it is bound to nothing and can be " +
			"copied onto any account")
	}
	if _, err := h.Hash(ctx, "a fine password", user, ids.CredentialID{}); err == nil {
		t.Error("a verifier was produced with no credential id")
	}
}

// The password policy applies at HASH time too, not only at the API boundary.
func TestAPasswordBelowPolicyIsNotHashed(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	if _, err := h.Hash(ctx, "short", user, cred); err == nil {
		t.Error("a five-character password was hashed: the policy is enforced only at the " +
			"boundary, so any other caller bypasses it")
	}
}

// Normalization applies at BOTH ends.
//
// The same password in two Unicode encodings must verify. This is the lockout
// that ASCII fixtures never reproduce: set on one platform, refused on another.
func TestAPasswordVerifiesAcrossUnicodeEncodings(t *testing.T) {
	ctx := context.Background()
	h, _ := newHasher(t)
	user, cred := newIDs(t)

	composed := "café password"    // é as one code point
	decomposed := "café password" // e + combining acute

	v, err := h.Hash(ctx, composed, user, cred)
	if err != nil {
		t.Fatalf("hash: %v", err)
	}
	ok, err := h.Verify(ctx, decomposed, v, user, cred)
	if err != nil {
		t.Fatalf("verify: %v", err)
	}
	if !ok {
		t.Fatal("a password set in one Unicode encoding did not verify in the other: " +
			"normalization is applied at only one of hash and verify, and the user is locked " +
			"out of the account they just created")
	}
}

// A failing entropy source must fail the hash, not produce a weak salt.
func TestAFailingEntropySourceFailsTheHash(t *testing.T) {
	ctx := context.Background()
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: keyBytes(t, 0xA1)}, 1)
	if err != nil {
		t.Fatalf("pepper: %v", err)
	}
	h, err := argon2id.New(pepper, testParams)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	argon2id.SetRandForTest(h, io.LimitReader(rand.Reader, 4)) // short read

	user, cred := newIDs(t)
	if _, err := h.Hash(ctx, "a fine password", user, cred); err == nil {
		t.Fatal("a hash was produced from a short entropy read: the salt is partly zeroes " +
			"and every user who hits this shares it")
	}
}

// BenchmarkHash is the tuning instrument. Run it on the target hardware and
// raise Memory until the latency budget is reached — memory first, not time.
func BenchmarkHash(b *testing.B) {
	ctx := context.Background()
	pepper, err := argon2id.NewPepperKeys(map[int][]byte{1: make([]byte, crypto.DEKSize)}, 1)
	if err != nil {
		b.Fatal(err)
	}
	h, err := argon2id.New(pepper, argon2id.DefaultParams)
	if err != nil {
		b.Fatal(err)
	}
	now := time.Now()
	user := ids.New[ids.User](now, rand.Reader)
	cred := ids.New[ids.Credential](now, rand.Reader)

	b.ResetTimer()
	for b.Loop() {
		if _, err := h.Hash(ctx, "correct horse battery staple", user, cred); err != nil {
			b.Fatal(err)
		}
	}
}
