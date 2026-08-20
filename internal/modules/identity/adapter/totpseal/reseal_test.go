package totpseal_test

import (
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totpseal"
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

func newResealSealer(t *testing.T, keys map[int][]byte, current int) *totpseal.Sealer {
	t.Helper()
	set, err := totpseal.NewKeys(keys, current)
	if err != nil {
		t.Fatalf("sealing keys: %v", err)
	}
	s, err := totpseal.New(set)
	if err != nil {
		t.Fatalf("sealer: %v", err)
	}
	return s
}

func resealCred(t *testing.T) ids.CredentialID {
	t.Helper()
	return ids.New[ids.Credential](time.Now(), ids.Entropy())
}

// The property the TOTP half of a rotation rests on, and the one with no
// fallback: a secret sealed under v1 can be carried to v2 and still opens.
//
// Passwords have a second repair path — the login-time rehash — so a broken
// pepper rotation degrades. A TOTP secret has none: verification derives a code
// from the secret and never produces an opportunity to re-seal it, so if this
// stops holding, a rotated key can never retire.
func TestReseal_CarriesASecretToTheNewKeyAndItStillOpens(t *testing.T) {
	t.Parallel()

	const plaintext = "JBSWY3DPEHPK3PXP"
	subject, cred := "sub_01", resealCred(t)

	v1 := newResealSealer(t, map[int][]byte{1: resealKey(1)}, 1)
	sealed, err := v1.Seal(plaintext, subject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	rotated := newResealSealer(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)
	resealed, err := rotated.Reseal(sealed, subject, cred)
	if err != nil {
		t.Fatalf("re-sealing: %v", err)
	}
	if resealed == sealed {
		t.Fatal("the re-sealed value is byte-identical to the original; GCM's nonce is " +
			"random per call, so nothing was actually re-sealed")
	}
	if !strings.HasPrefix(resealed, "totp$v2$") {
		t.Errorf("the re-sealed value does not name key version 2: %q", resealed)
	}

	// The whole point: a process holding ONLY the new key can still open it,
	// which is what makes destroying v1 safe.
	only2 := newResealSealer(t, map[int][]byte{2: resealKey(2)}, 2)
	got, err := only2.Open(resealed, subject, cred)
	if err != nil {
		t.Fatalf("opening under the new key alone: %v", err)
	}
	if got != plaintext {
		t.Fatal("the re-sealed secret does not match the original: every re-sealed account " +
			"has silently lost its second factor")
	}
}

// A secret already at the current version is refused, not rewritten. Rewriting
// would emit fresh ciphertext at an unchanged version on every pass forever.
func TestReseal_RefusesASecretAlreadyAtTheCurrentVersion(t *testing.T) {
	t.Parallel()

	subject, cred := "sub_01", resealCred(t)
	s := newResealSealer(t, map[int][]byte{1: resealKey(1)}, 1)
	sealed, err := s.Seal("JBSWY3DPEHPK3PXP", subject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	if _, err := s.Reseal(sealed, subject, cred); !errors.Is(err, app.ErrAlreadyCurrent) {
		t.Fatalf("re-sealing a current secret gave %v, want ErrAlreadyCurrent", err)
	}
}

// A secret naming a key that is not loaded is ErrSecretUnreadable, so the job
// counts it apart from a transient fault. The row is left untouched.
func TestReseal_ASecretNamingAMissingKeyIsUnreadable(t *testing.T) {
	t.Parallel()

	subject, cred := "sub_01", resealCred(t)
	v1 := newResealSealer(t, map[int][]byte{1: resealKey(1)}, 1)
	sealed, err := v1.Seal("JBSWY3DPEHPK3PXP", subject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	only2 := newResealSealer(t, map[int][]byte{2: resealKey(2)}, 2)
	got, err := only2.Reseal(sealed, subject, cred)
	if !errors.Is(err, app.ErrSecretUnreadable) {
		t.Fatalf("re-sealing under a missing key gave %v, want ErrSecretUnreadable", err)
	}
	if !errors.Is(err, totpseal.ErrNoKey) {
		t.Error("the underlying cause is not wrapped, so the log cannot say WHICH key is missing")
	}
	if got != "" {
		t.Fatal("a value was returned for a secret that could not be opened; the row must " +
			"be left exactly as it was")
	}
}

// The AAD binding is enforced on the way out too: re-sealing against the wrong
// ids must fail rather than produce a row that can never be opened again.
func TestReseal_RefusesTheWrongBinding(t *testing.T) {
	t.Parallel()

	subject, cred := "sub_01", resealCred(t)
	otherCred := resealCred(t)

	v1 := newResealSealer(t, map[int][]byte{1: resealKey(1)}, 1)
	sealed, err := v1.Seal("JBSWY3DPEHPK3PXP", subject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}
	rotated := newResealSealer(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)

	tests := []struct {
		name    string
		subject string
		cred    ids.CredentialID
	}{
		{"another account's subject", "sub_02", cred},
		{"another row's credential id", subject, otherCred},
		{"no subject at all", "", cred},
		{"no credential id at all", subject, ids.CredentialID{}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := rotated.Reseal(sealed, tt.subject, tt.cred); !errors.Is(
				err, app.ErrSecretUnreadable,
			) {
				t.Fatalf("re-sealing with the wrong binding gave %v; it must refuse, or the "+
					"row is rewritten into one no verification can ever open", err)
			}
		})
	}
}

// The port shim: kind, version, and the SUBJECT binding — not the user id, which
// is what the password half binds with and what this row does not carry.
func TestTOTPResealer_SpeaksThePortAndBindsWithTheSubject(t *testing.T) {
	t.Parallel()

	subject, cred := "sub_01", resealCred(t)
	v1 := newResealSealer(t, map[int][]byte{1: resealKey(1)}, 1)
	sealed, err := v1.Seal("JBSWY3DPEHPK3PXP", subject, cred)
	if err != nil {
		t.Fatalf("sealing: %v", err)
	}

	rotated := newResealSealer(t, map[int][]byte{1: resealKey(1), 2: resealKey(2)}, 2)
	r, err := totpseal.NewTOTPResealer(rotated)
	if err != nil {
		t.Fatalf("resealer: %v", err)
	}
	if r.Kind() != app.KindTOTP {
		t.Errorf("kind %q; a resealer under the wrong kind selects the wrong work list", r.Kind())
	}
	if r.CurrentVersion() != 2 {
		t.Errorf("current version %d, want 2", r.CurrentVersion())
	}

	// No UserID on the row, deliberately: a TOTP re-seal must not need one.
	got, err := r.Reseal(sealed, app.SealedCredential{ID: cred, SubjectID: subject, Sealed: sealed})
	if err != nil {
		t.Fatalf("re-sealing through the port: %v", err)
	}
	if !strings.HasPrefix(got, "totp$v2$") {
		t.Errorf("the port produced %q, which is not at the current version", got)
	}
}

func TestNewTOTPResealer_RefusesANilSealer(t *testing.T) {
	t.Parallel()
	if _, err := totpseal.NewTOTPResealer(nil); err == nil {
		t.Fatal("a resealer was built around no sealer; the job would scan TOTP rows and " +
			"move none while reporting a clean pass")
	}
}
