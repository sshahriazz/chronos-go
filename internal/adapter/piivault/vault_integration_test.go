//go:build integration

package piivault_test

import (
	"context"
	"errors"
	"fmt"
	"os"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/openbao"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/google/uuid"
	"github.com/jackc/pgx/v5/pgxpool"
)

func newVault(t testing.TB) (*piivault.Vault, *pgxpool.Pool) {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	client, err := openbao.Dial(envOr("OPENBAO_ADDR", "http://localhost:8200"), os.Getenv("OPENBAO_DEV_TOKEN"))
	if err != nil {
		t.Fatalf("openbao: %v", err)
	}
	ring := openbao.NewKeyRing(client, envOr("OPENBAO_KEK_NAME", "chronos-kek"))
	return piivault.New(pgadapter.New(pool), ring), pool
}

func subject(t testing.TB) pii.SubjectID {
	t.Helper()
	return pii.SubjectID("sub_" + uuid.NewString()[:12])
}

// The whole point of the design: after erasure the data is UNREADABLE, and the
// rows are still there to prove the records existed (ADR-002).
func TestErasureMakesDataUnreadableForever(t *testing.T) {
	v, pool := newVault(t)
	ctx := context.Background()
	id := subject(t)

	if err := v.PutAll(ctx, id, map[pii.Field]string{
		pii.FieldEmail: "sam.larsson@example.test",
		pii.FieldName:  "Sam Larsson",
	}); err != nil {
		t.Fatalf("put: %v", err)
	}

	got, err := v.Get(ctx, id, pii.FieldEmail)
	if err != nil || got != "sam.larsson@example.test" {
		t.Fatalf("before erasure: got %q err %v", got, err)
	}

	if err := v.Erase(ctx, id); err != nil {
		t.Fatalf("erase: %v", err)
	}

	if _, err := v.Get(ctx, id, pii.FieldEmail); !errors.Is(err, pii.ErrErased) {
		t.Fatalf("after erasure the address must be unreadable, got %v", err)
	}
	if _, err := v.Profile(ctx, id); !errors.Is(err, pii.ErrErased) {
		t.Fatalf("the profile must be unreadable too, got %v", err)
	}

	// The ciphertext is STILL THERE — deleting it would leave nothing to show
	// the records existed and were erased.
	var rows int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pii_value WHERE subject_id = $1`, string(id)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 2 {
		t.Errorf("expected the ciphertext rows to remain as evidence, found %d", rows)
	}

	// And the key is genuinely gone, not merely flagged.
	var wrapped []byte
	if err := pool.QueryRow(ctx,
		`SELECT wrapped_dek FROM pii_key WHERE subject_id = $1`, string(id)).Scan(&wrapped); err != nil {
		t.Fatal(err)
	}
	if wrapped != nil {
		t.Fatal("the wrapped data key survived erasure; the data is still recoverable")
	}
}

// A subject may exercise the right twice, and the second request must not fail.
func TestErasureIsIdempotent(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()
	id := subject(t)

	if err := v.Put(ctx, id, pii.FieldEmail, "a@example.test"); err != nil {
		t.Fatal(err)
	}
	for i := range 3 {
		if err := v.Erase(ctx, id); err != nil {
			t.Fatalf("erase %d: %v", i, err)
		}
	}
	erased, err := v.Erased(ctx, id)
	if err != nil || !erased {
		t.Fatalf("erased=%v err=%v", erased, err)
	}
}

// Writing to an erased subject would resurrect them under a fresh key, quietly
// undoing the erasure.
func TestWritingToAnErasedSubjectIsRefused(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()
	id := subject(t)

	if err := v.Put(ctx, id, pii.FieldEmail, "a@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := v.Erase(ctx, id); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, id, pii.FieldEmail, "resurrected@example.test"); !errors.Is(err, pii.ErrErased) {
		t.Fatalf("an erased subject must not be writable again, got %v", err)
	}
}

// Nothing readable may sit in the database. A copy of the schema without
// OpenBao must be worthless.
func TestNothingReadableIsStored(t *testing.T) {
	v, pool := newVault(t)
	ctx := context.Background()
	id := subject(t)
	const address = "unmistakable.address@example.test"

	if err := v.Put(ctx, id, pii.FieldEmail, address); err != nil {
		t.Fatal(err)
	}

	var found int
	if err := pool.QueryRow(ctx,
		`SELECT count(*) FROM pii_value WHERE position($1::bytea in ciphertext) > 0`,
		[]byte(address)).Scan(&found); err != nil {
		t.Fatal(err)
	}
	if found != 0 {
		t.Fatal("the plaintext address is present in the database; the vault stores readable personal data")
	}
}

// Two subjects must not share a key, or erasing one would erase the other — or
// worse, leave the other readable by the wrong key.
func TestSubjectsHaveSeparateKeys(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()
	a, b := subject(t), subject(t)

	if err := v.Put(ctx, a, pii.FieldEmail, "a@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := v.Put(ctx, b, pii.FieldEmail, "b@example.test"); err != nil {
		t.Fatal(err)
	}
	if err := v.Erase(ctx, a); err != nil {
		t.Fatal(err)
	}

	got, err := v.Get(ctx, b, pii.FieldEmail)
	if err != nil {
		t.Fatalf("erasing one subject broke another: %v", err)
	}
	if got != "b@example.test" {
		t.Fatalf("got %q", got)
	}
}

func TestProfileReturnsEverything(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()
	id := subject(t)

	want := map[pii.Field]string{
		pii.FieldEmail:    "sam@example.test",
		pii.FieldName:     "Sam Larsson",
		pii.FieldLocale:   "en-GB",
		pii.FieldTimezone: "Europe/Berlin",
	}
	if err := v.PutAll(ctx, id, want); err != nil {
		t.Fatal(err)
	}

	profile, err := v.Profile(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	for field, expected := range want {
		if got := profile.Get(field); got != expected {
			t.Errorf("%s: got %q want %q", field, got, expected)
		}
	}
}

func TestUnknownSubjectAndField(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()

	if _, err := v.Get(ctx, subject(t), pii.FieldEmail); !errors.Is(err, pii.ErrNoSubject) {
		t.Errorf("an unknown subject should report ErrNoSubject, got %v", err)
	}

	id := subject(t)
	if err := v.Put(ctx, id, pii.FieldEmail, "a@example.test"); err != nil {
		t.Fatal(err)
	}
	if _, err := v.Get(ctx, id, pii.FieldPhone); !errors.Is(err, pii.ErrNoValue) {
		t.Errorf("an unset field should report ErrNoValue, got %v", err)
	}
	if _, err := v.Get(ctx, id, pii.Field("shoe_size")); !errors.Is(err, pii.ErrInvalidField) {
		t.Errorf("an unknown field must be refused, got %v", err)
	}
}

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	return fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		envOr("POSTGRES_APP_USER", "chronos_app"), os.Getenv("POSTGRES_APP_PASSWORD"),
		envOr("POSTGRES_HOST", "localhost"), envOr("POSTGRES_PORT", "5432"),
		envOr("POSTGRES_DB", "chronos"))
}

func envOr(k, d string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return d
}

// The complete outbound path: a pseudonym becomes an address only at the last
// moment, and an erased subject stops the notification without failing it.
func TestNotifyVaultResolvesAndRespectsErasure(t *testing.T) {
	v, _ := newVault(t)
	ctx := context.Background()
	id := subject(t)

	if err := v.PutAll(ctx, id, map[pii.Field]string{
		pii.FieldEmail:    "sam.larsson@example.test",
		pii.FieldName:     "Sam Larsson",
		pii.FieldTimezone: "Asia/Tokyo",
	}); err != nil {
		t.Fatal(err)
	}

	nv := piivault.NewNotifyVault(v, "en", "UTC")
	r, err := nv.Resolve(ctx, string(id))
	if err != nil {
		t.Fatalf("resolve: %v", err)
	}
	if r.Address != "sam.larsson@example.test" || r.Name != "Sam Larsson" {
		t.Fatalf("resolved %+v", r)
	}
	if r.Timezone != "Asia/Tokyo" {
		t.Errorf("timezone %q — the recipient's own zone must reach the renderer", r.Timezone)
	}
	if r.Locale != "en" {
		t.Errorf("locale %q — an unset locale should take the default", r.Locale)
	}

	if err := v.Erase(ctx, id); err != nil {
		t.Fatal(err)
	}
	_, err = nv.Resolve(ctx, string(id))
	if !errors.Is(err, notify.ErrSubjectErased) {
		t.Fatalf("an erased subject must report ErrSubjectErased so the send is "+
			"SKIPPED rather than retried forever, got %v", err)
	}
}

// A subject with no record is NOT the same as an erased one: nobody asked to be
// forgotten, so it is a data fault worth seeing.
func TestNotifyVaultDistinguishesMissingFromErased(t *testing.T) {
	v, _ := newVault(t)
	nv := piivault.NewNotifyVault(v, "en", "UTC")

	_, err := nv.Resolve(context.Background(), string(subject(t)))
	if errors.Is(err, notify.ErrSubjectErased) {
		t.Fatal("a subject that never existed was reported as erased")
	}
	if !errors.Is(err, notify.ErrNoAddress) {
		t.Fatalf("expected ErrNoAddress, got %v", err)
	}
}
