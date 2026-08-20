package totpseal_test

import (
	"crypto/rand"
	"encoding/base64"
	"errors"
	"io"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totp"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totpseal"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/crypto"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// The real TOTP adapter must satisfy the app's verifier port.
//
// Asserted HERE rather than beside the port, because app's own tests are
// in-package and this package imports app — so a test there importing the
// authenticator would be an import cycle. Without the assertion the port could
// drift into a shape only the fakes implement, which is how a use case ends up
// passing every test and wiring into nothing.
var _ app.TotpVerifier = (*totp.Authenticator)(nil)

const (
	// testSharedValue is a base32 TOTP shared value used as a fixture. It is not a
	// credential for anything: no account, test or otherwise, is enrolled with it.
	testSharedValue = "JBSWY3DPEHPK3PXPJBSWY3DP"
	testSubject     = "subj_01JQ0000000000000000000001"
)

func testCred(t *testing.T) ids.CredentialID {
	t.Helper()
	return ids.New[ids.Credential](time.Now(), rand.Reader)
}

func newSealer(t *testing.T, versions ...int) *totpseal.Sealer {
	t.Helper()
	if len(versions) == 0 {
		versions = []int{1}
	}
	keys := make(map[int][]byte, len(versions))
	for _, v := range versions {
		key := make([]byte, crypto.DEKSize)
		if _, err := io.ReadFull(rand.Reader, key); err != nil {
			t.Fatalf("entropy: %v", err)
		}
		keys[v] = key
	}
	set, err := totpseal.NewKeys(keys, versions[len(versions)-1])
	if err != nil {
		t.Fatalf("building the key set: %v", err)
	}
	sealer, err := totpseal.New(set)
	if err != nil {
		t.Fatalf("building the sealer: %v", err)
	}
	return sealer
}

func TestASealedSecretOpensUnderItsOwnRow(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)

	sealed, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if strings.Contains(sealed, testSharedValue) {
		t.Fatalf("the sealed value %q contains the secret in the clear; the column it "+
			"goes in is exactly what an attacker who reaches the database already has", sealed)
	}
	got, err := sealer.Open(sealed, testSubject, cred)
	if err != nil {
		t.Fatalf("opening: %v", err)
	}
	if got != testSharedValue {
		t.Errorf("opened %q, want %q", got, testSharedValue)
	}
}

// The property the AAD exists for. Without it, one write to the credential table
// installs an authenticator the attacker holds the secret for on any account they
// name, and every subsequent login succeeds.
func TestASecretSealedForOneRowCannotBeOpenedUnderAnother(t *testing.T) {
	sealer := newSealer(t)
	cred, other := testCred(t), testCred(t)
	if cred == other {
		t.Fatal("the two credential ids are equal, so this test would pass vacuously")
	}

	sealed, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	tests := map[string]struct {
		subject string
		cred    ids.CredentialID
	}{
		"another credential": {testSubject, other},
		"another subject":    {"subj_01JQ0000000000000000000002", cred},
		"both moved":         {"subj_01JQ0000000000000000000002", other},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			got, err := sealer.Open(sealed, tt.subject, tt.cred)
			if !errors.Is(err, app.ErrSecretUnreadable) {
				t.Fatalf("opening under %s gave (%q, %v), want ErrSecretUnreadable",
					name, got, err)
			}
		})
	}
}

func TestATamperedCiphertextDoesNotOpen(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)
	sealed, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	// Flip one bit of the CIPHERTEXT, not of its encoding. Flipping the last
	// base64 character is the obvious version and is wrong: Go's non-strict
	// decoder ignores unused trailing bits, so that edit can decode to identical
	// bytes and the test passes without having tampered with anything.
	parts := strings.Split(sealed, "$")
	body, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decoding the fixture: %v", err)
	}
	body[len(body)-1] ^= 0x01
	tampered := parts[0] + "$" + parts[1] + "$" + base64.RawURLEncoding.EncodeToString(body)
	if tampered == sealed {
		t.Fatal("the fixture was not actually altered")
	}
	if _, err := sealer.Open(tampered, testSubject, cred); !errors.Is(err, app.ErrSecretUnreadable) {
		t.Fatalf("a tampered ciphertext gave %v, want ErrSecretUnreadable; GCM authenticates, "+
			"so a modified ciphertext must fail to open rather than producing plausible garbage", err)
	}
}

func TestTwoSealsOfOneSecretDiffer(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)
	first, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	second, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if first == second {
		t.Fatal("two seals of one secret are byte-identical, so the nonce is not fresh — " +
			"reusing a nonce under one key is the catastrophic mistake with GCM")
	}
}

func TestTheKeyVersionIsRecordedAndSelectsTheKey(t *testing.T) {
	sealer := newSealer(t, 1, 2)
	cred := testCred(t)
	sealed, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if !strings.HasPrefix(sealed, "totp$v2$") {
		t.Fatalf("the sealed value is %q; it must carry the version outside the "+
			"ciphertext, or nothing can choose the key that opens it", sealed)
	}
	if sealer.KeyVersion() != 2 {
		t.Errorf("KeyVersion reports %d, want 2: the column is what the re-sealing job "+
			"selects on", sealer.KeyVersion())
	}

	// A sealer that does not hold that version must say so, and must NOT report it
	// as an unreadable row: one is an outage across every row at that version, the
	// other is a fact about one row, and they need different people woken up.
	narrow := newSealer(t, 5)
	if _, err := narrow.Open(sealed, testSubject, cred); !errors.Is(err, totpseal.ErrNoKey) {
		t.Fatalf("opening under a sealer without v2 gave %v, want ErrNoKey", err)
	}
}

func TestRotationKeepsOlderSecretsOpenable(t *testing.T) {
	key1 := make([]byte, crypto.DEKSize)
	key2 := make([]byte, crypto.DEKSize)
	if _, err := io.ReadFull(rand.Reader, key1); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	if _, err := io.ReadFull(rand.Reader, key2); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	keys, err := totpseal.NewKeys(map[int][]byte{1: key1}, 1)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	sealer, err := totpseal.New(keys)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}

	cred := testCred(t)
	old, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	if err := keys.Rotate(2, key2); err != nil {
		t.Fatalf("rotating: %v", err)
	}
	if got, err := sealer.Open(old, testSubject, cred); err != nil || got != testSharedValue {
		t.Fatalf("a secret sealed before the rotation gave (%q, %v); retiring the old key "+
			"at rotation locks out every account whose row has not been re-sealed yet",
			got, err)
	}
	fresh, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing after rotation: %v", err)
	}
	if !strings.HasPrefix(fresh, "totp$v2$") {
		t.Errorf("after rotation a new secret is sealed as %q, want v2", fresh)
	}
	if err := keys.Rotate(1, key2); err == nil {
		t.Error("a loaded version was silently redefined with different material; every " +
			"secret sealed under the old material becomes unopenable with no error until " +
			"users start failing their second factor")
	}
}

func TestAKeySetIsValidatedWhereItEnters(t *testing.T) {
	good := make([]byte, crypto.DEKSize)
	if _, err := io.ReadFull(rand.Reader, good); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	tests := map[string]struct {
		keys    map[int][]byte
		current int
	}{
		"no keys at all":      {map[int][]byte{}, 1},
		"version zero":        {map[int][]byte{0: good}, 0},
		"negative version":    {map[int][]byte{-1: good}, -1},
		"short key":           {map[int][]byte{1: good[:16]}, 1},
		"current not present": {map[int][]byte{1: good}, 2},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := totpseal.NewKeys(tt.keys, tt.current); err == nil {
				t.Errorf("%s was accepted; a row written at a version the rotation query "+
					"cannot see is skipped silently and locked out for good when the old "+
					"key is destroyed", name)
			}
		})
	}
}

func TestAMalformedSealedValueIsRefusedRatherThanParsedLoosely(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)
	tests := map[string]string{
		"empty":               "",
		"no version":          "totp$$AAAA",
		"wrong prefix":        "$argon2id$v=19$m=32768,t=3,p=1$c2FsdA$aGFzaA",
		"too few parts":       "totp$v1",
		"too many parts":      "totp$v1$AAAA$extra",
		"version zero":        "totp$v0$AAAA",
		"unparseable version": "totp$vX$AAAA",
		"not base64":          "totp$v1$!!!!",
		"shorter than nonce":  "totp$v1$AAAA",
	}
	for name, sealed := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := sealer.Open(sealed, testSubject, cred); !errors.Is(err, app.ErrSecretUnreadable) {
				t.Errorf("opening %q gave %v, want ErrSecretUnreadable", sealed, err)
			}
		})
	}
}

func TestSealingRefusesAnIncompleteBinding(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)
	tests := map[string]struct {
		secret  string
		subject string
		cred    ids.CredentialID
	}{
		"no secret":     {"", testSubject, cred},
		"no subject":    {testSharedValue, "", cred},
		"no credential": {testSharedValue, testSubject, ids.CredentialID{}},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			if _, err := sealer.Seal(tt.secret, tt.subject, tt.cred); err == nil {
				t.Errorf("sealing with %s succeeded; half a binding binds nothing", name)
			}
		})
	}
}

func TestOpeningWithoutABindingIsUnreadable(t *testing.T) {
	sealer := newSealer(t)
	cred := testCred(t)
	sealed, err := sealer.Seal(testSharedValue, testSubject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if _, err := sealer.Open(sealed, "", cred); !errors.Is(err, app.ErrSecretUnreadable) {
		t.Errorf("opening with no subject gave %v, want ErrSecretUnreadable", err)
	}
	if _, err := sealer.Open(sealed, testSubject, ids.CredentialID{}); !errors.Is(err, app.ErrSecretUnreadable) {
		t.Errorf("opening with no credential gave %v, want ErrSecretUnreadable", err)
	}
}

func TestASealerNeedsAKeySet(t *testing.T) {
	if _, err := totpseal.New(nil); err == nil {
		t.Fatal("a sealer built with no keys would have to store secrets in the clear")
	}
}

func TestVersionsReportsWhatIsLoaded(t *testing.T) {
	key := make([]byte, crypto.DEKSize)
	if _, err := io.ReadFull(rand.Reader, key); err != nil {
		t.Fatalf("entropy: %v", err)
	}
	keys, err := totpseal.NewKeys(map[int][]byte{3: key}, 3)
	if err != nil {
		t.Fatalf("keys: %v", err)
	}
	got := keys.Versions()
	if len(got) != 1 || got[0] != 3 {
		t.Fatalf("Versions reports %v, want [3]; the re-sealing job checks its progress "+
			"against this", got)
	}
	if keys.Current() != 3 {
		t.Errorf("Current is %d, want 3", keys.Current())
	}
}
