package argon2id_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

func resealKey(b byte) []byte {
	k := make([]byte, 32)
	for i := range k {
		k[i] = b
	}
	return k
}

// floorParams are the cheapest parameters the hasher accepts.
//
// The floor, not DefaultParams: these tests run Argon2id for real and the cost is
// the whole runtime. Reseal never re-derives a digest, so the only thing that
// matters here is which parameters it PRESERVES.
var floorParams = argon2id.Params{
	Memory: 8 * 1024, Time: 1, Parallelism: 1, SaltLen: 16, KeyLen: 32,
}

// raisedParams are strictly stronger, and exist so a test can make the hasher's
// CURRENT policy differ from the policy a stored verifier was produced under.
//
// That difference is not decoration. Reseal must carry each verifier's OWN
// parameters across, because it has no plaintext to re-derive a digest from; a
// version that substituted the hasher's current parameters would write a verifier
// claiming costs its digest was never computed at, and Verify would then derive
// the candidate with the wrong m and t and never match again. With one set of
// parameters everywhere in the test, that substitution is invisible.
var raisedParams = argon2id.Params{
	Memory: 16 * 1024, Time: 2, Parallelism: 1, SaltLen: 16, KeyLen: 32,
}

func newResealHasher(t *testing.T, keys map[int][]byte, current int) *argon2id.Hasher {
	t.Helper()
	return newResealHasherWith(t, keys, current, floorParams)
}

func newResealHasherWith(
	t *testing.T, keys map[int][]byte, current int, params argon2id.Params,
) *argon2id.Hasher {
	t.Helper()
	pepper, err := argon2id.NewPepperKeys(keys, current)
	if err != nil {
		t.Fatalf("pepper keys: %v", err)
	}
	h, err := argon2id.New(pepper, params)
	if err != nil {
		t.Fatalf("hasher: %v", err)
	}
	return h
}

func resealIDs(t *testing.T) (ids.UserID, ids.CredentialID) {
	t.Helper()
	return ids.New[ids.User](time.Now(), ids.Entropy()),
		ids.New[ids.Credential](time.Now(), ids.Entropy())
}

// The property the whole rotation rests on: a verifier sealed under v1 can be
// carried to v2 WITHOUT the password, and still verifies that password
// afterwards.
//
// If this ever stops holding, a rotation silently converts every account into a
// permanent lockout — the row looks healthy, the version is current, and the
// password nobody can change is the one that no longer works.
func TestReseal_CarriesAVerifierToTheNewKeyAndItStillVerifies(t *testing.T) {
	t.Parallel()

	const password = "correct horse battery staple"
	user, cred := resealIDs(t)

	v1 := newResealHasher(t, map[int][]byte{1: resealKey(1)}, 1)
	verifier, err := v1.Hash(t.Context(), password, user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	// Both keys loaded, current is v2 — the state a rotation puts the process in.
	rotated := newResealHasher(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)
	resealed, err := rotated.Reseal(verifier, user, cred)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if resealed == verifier {
		t.Fatal("the re-sealed verifier is byte-identical to the original; GCM's nonce is " +
			"random per call, so this means nothing was actually re-sealed")
	}
	if !strings.Contains(resealed, "$k=2$") {
		t.Errorf("the re-sealed verifier does not name key version 2: %q", resealed)
	}

	// The password still verifies, and it was never involved in the re-seal.
	ok, err := rotated.Verify(t.Context(), password, resealed, user, cred)
	if err != nil {
		t.Fatalf("verifying the re-sealed verifier: %v", err)
	}
	if !ok {
		t.Fatal("the password no longer verifies after a re-seal: every account that was " +
			"re-sealed is now permanently locked out")
	}

	// And a process holding ONLY the new key can still verify it, which is the
	// entire point — that is what makes destroying v1 safe.
	only2 := newResealHasher(t, map[int][]byte{2: resealKey(2)}, 2)
	ok, err = only2.Verify(t.Context(), password, resealed, user, cred)
	if err != nil || !ok {
		t.Fatalf("the re-sealed verifier does not open under the new key alone: ok=%v err=%v",
			ok, err)
	}
}

// The Argon2id cost parameters and the salt survive the round trip.
//
// They must: there is no plaintext to re-derive a digest from, so a re-seal that
// changed either would produce a verifier that can never match again.
func TestReseal_PreservesTheSaltAndTheCostParameters(t *testing.T) {
	t.Parallel()

	const password = "a password worth keeping"
	user, cred := resealIDs(t)

	// The stored verifier is produced at the FLOOR parameters.
	v1 := newResealHasherWith(t, map[int][]byte{1: resealKey(1)}, 1, floorParams)
	verifier, err := v1.Hash(t.Context(), password, user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	// The re-sealing process runs at RAISED parameters — the ordinary situation
	// after somebody tunes the cost, and the only configuration in which
	// "preserves the stored parameters" and "writes the current parameters" are
	// distinguishable at all.
	rotated := newResealHasherWith(t,
		map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2, raisedParams)
	resealed, err := rotated.Reseal(verifier, user, cred)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}

	// $argon2id$v=19$m=..,t=..,p=..$<salt>$k=N$<sealed>
	before, after := strings.Split(verifier, "$"), strings.Split(resealed, "$")
	if before[3] != after[3] {
		t.Errorf("cost parameters changed from %q to %q; a re-seal has no plaintext and "+
			"cannot re-derive a digest, so parameters it did not compute under would make "+
			"the verifier permanently unmatchable", before[3], after[3])
	}
	if before[4] != after[4] {
		t.Error("the salt changed; the digest it produced would no longer match")
	}
	if before[6] == after[6] {
		t.Error("the sealed digest is unchanged, so nothing was re-encrypted")
	}

	// The assertion that actually bites: the password must still verify THROUGH
	// the raised-parameter hasher. Verify reads the parameters out of the stored
	// verifier, so a re-seal that stamped the current ones on an old digest fails
	// here even if nobody notices the string comparison above.
	ok, err := rotated.Verify(t.Context(), password, resealed, user, cred)
	if err != nil {
		t.Fatalf("verifying a verifier re-sealed under a raised-cost hasher: %v", err)
	}
	if !ok {
		t.Fatal("the password no longer verifies after being re-sealed by a hasher whose " +
			"current cost differs from the stored one: every re-sealed account is locked out")
	}
}

// A verifier already at the current version is refused as ErrAlreadyCurrent, not
// rewritten. Rewriting it would emit fresh ciphertext at an unchanged version on
// every pass, forever, and the rotation's done check would never fall.
func TestReseal_RefusesAVerifierAlreadyAtTheCurrentVersion(t *testing.T) {
	t.Parallel()

	user, cred := resealIDs(t)
	h := newResealHasher(t, map[int][]byte{1: resealKey(1)}, 1)
	verifier, err := h.Hash(t.Context(), "already current", user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	if _, err := h.Reseal(verifier, user, cred); !errors.Is(err, app.ErrAlreadyCurrent) {
		t.Fatalf("re-sealing a current verifier gave %v, want ErrAlreadyCurrent", err)
	}
}

// A verifier naming a key that is NOT loaded is ErrVerifierUnreadable, so the
// job counts it apart from a transient fault and says so loudly. It is the case
// that means an account is about to lose its password.
func TestReseal_AVerifierNamingAMissingKeyIsUnreadable(t *testing.T) {
	t.Parallel()

	user, cred := resealIDs(t)
	v1 := newResealHasher(t, map[int][]byte{1: resealKey(1)}, 1)
	verifier, err := v1.Hash(t.Context(), "stranded", user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	// Only v2 loaded — the state a deployment is in when it has rotated without
	// carrying the previous key forward.
	only2 := newResealHasher(t, map[int][]byte{2: resealKey(2)}, 2)
	got, err := only2.Reseal(verifier, user, cred)
	if !errors.Is(err, app.ErrVerifierUnreadable) {
		t.Fatalf("re-sealing under a missing key gave %v, want ErrVerifierUnreadable", err)
	}
	if !errors.Is(err, argon2id.ErrNoPepperKey) {
		t.Error("the underlying cause is not wrapped, so the log cannot say WHICH key is missing")
	}
	if got != "" {
		t.Fatal("a value was returned for a verifier that could not be opened; the row " +
			"must be left exactly as it was")
	}
}

// The AAD binding is enforced on the way OUT as well as the way in: re-sealing
// against the wrong ids must fail rather than produce a row that can never be
// opened again.
func TestReseal_RefusesTheWrongBinding(t *testing.T) {
	t.Parallel()

	user, cred := resealIDs(t)
	other, otherCred := resealIDs(t)

	v1 := newResealHasher(t, map[int][]byte{1: resealKey(1)}, 1)
	verifier, err := v1.Hash(t.Context(), "bound to one row", user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}
	rotated := newResealHasher(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)

	tests := []struct {
		name string
		user ids.UserID
		cred ids.CredentialID
	}{
		{"another account's user id", other, cred},
		{"another row's credential id", user, otherCred},
		{"no user id at all", ids.UserID{}, cred},
		{"no credential id at all", user, ids.CredentialID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := rotated.Reseal(verifier, tt.user, tt.cred); !errors.Is(
				err, app.ErrVerifierUnreadable,
			) {
				t.Fatalf("re-sealing with the wrong binding gave %v; it must refuse, or the "+
					"row is rewritten into one no login can ever verify", err)
			}
		})
	}
}

// The port shim: kind, version, and the row shape the job hands it.
func TestPasswordResealer_SpeaksThePortAndBindsWithTheUserID(t *testing.T) {
	t.Parallel()

	user, cred := resealIDs(t)
	v1 := newResealHasher(t, map[int][]byte{1: resealKey(1)}, 1)
	verifier, err := v1.Hash(t.Context(), "through the port", user, cred)
	if err != nil {
		t.Fatalf("hashing: %v", err)
	}

	rotated := newResealHasher(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)
	r, err := argon2id.NewPasswordResealer(rotated)
	if err != nil {
		t.Fatalf("resealer: %v", err)
	}
	if r.Kind() != app.KindPassword {
		t.Errorf("kind %q; a resealer under the wrong kind selects the wrong work list", r.Kind())
	}
	if r.CurrentVersion() != 2 {
		t.Errorf("current version %d, want 2", r.CurrentVersion())
	}

	got, err := r.Reseal(verifier, app.SealedCredential{ID: cred, UserID: user, Sealed: verifier})
	if err != nil {
		t.Fatalf("re-sealing through the port: %v", err)
	}
	if !strings.Contains(got, "$k=2$") {
		t.Errorf("the port produced %q, which is not at the current version", got)
	}
}

func TestNewPasswordResealer_RefusesANilHasher(t *testing.T) {
	t.Parallel()
	if _, err := argon2id.NewPasswordResealer(nil); err == nil {
		t.Fatal("a resealer was built around no hasher; the job would scan password rows " +
			"and move none while reporting a clean pass")
	}
}
