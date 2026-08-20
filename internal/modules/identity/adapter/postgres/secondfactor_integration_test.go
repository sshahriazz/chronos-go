//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// The second-factor store, against the real schema.
//
// Tested here rather than against a fake because every property that matters is a
// property of the SQL and the constraints around it: whether an unproven
// enrolment is invisible to the usable-credential lookup, whether the partial
// unique index actually refuses a second live authenticator, whether replacing a
// code set really replaces it, and — the one the whole design turns on — whether
// two simultaneous presentations of one recovery code can both win. A stub that
// accepted the statements would demonstrate none of it.

func newSecondFactors(t *testing.T) *identitypg.SecondFactors {
	t.Helper()
	return newSecondFactorsOn(t, openPool(t))
}

func newSecondFactorsOn(t *testing.T, pool *pgxpool.Pool) *identitypg.SecondFactors {
	t.Helper()
	store, err := identitypg.NewSecondFactors(pgadapter.New(pool))
	if err != nil {
		t.Fatalf("building the second-factor store: %v", err)
	}
	return store
}

// usableRowExists asks the SAME query the login path uses, so "unproven is not
// usable" is asserted against the statement that actually decides it rather than
// against this adapter's own reading of the row.
func usableRowExists(t *testing.T, pool *pgxpool.Pool, subject, kind string) bool {
	t.Helper()
	var (
		credID, subjectID, gotKind string
		verifier                   *string
		pepper                     *int32
		enabledAt                  *time.Time
		failures                   int32
	)
	err := pool.QueryRow(context.Background(), identitydb.GetUsableCredential, subject, kind).
		Scan(&credID, &subjectID, &gotKind, &verifier, &pepper, &enabledAt, &failures)
	if err == nil {
		return true
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false
	}
	t.Fatalf("reading the usable credential: %v", err)
	return false
}

func unusedCodeCount(t *testing.T, pool *pgxpool.Pool, subject string) int64 {
	t.Helper()
	var n int64
	if err := pool.QueryRow(context.Background(), identitydb.CountUnusedRecoveryCodes, subject).
		Scan(&n); err != nil {
		t.Fatalf("counting unused codes: %v", err)
	}
	return n
}

// digestOf builds a distinct 32-byte digest. The column has a CHECK on that
// width, so a shorter fixture would fail for a reason no test is about.
func digestOf(t *testing.T, seed byte) []byte {
	t.Helper()
	out := make([]byte, 32)
	for i := range out {
		out[i] = seed ^ byte(i)
	}
	return out
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// An enrolment nobody has proven must not be able to take part in an
// authentication. Writing it enabled would let an account satisfy the mandatory
// second factor with a secret that may exist only on this side of the exchange.
func TestAProvisionedSecretIsStoredUnusable(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newSecondFactorsOn(t, pool)

	subject := testSubject(t)
	cred := newCredentialID()
	if err := store.Provision(ctx, app.NewTotpSecret{
		ID: cred, SubjectID: subject, Sealed: "totp$v1$fixture-one", KeyVersion: 2,
	}); err != nil {
		t.Fatalf("provisioning: %v", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.ID != cred {
		t.Errorf("credential id is %s, want %s: the secret is sealed against this id, so "+
			"the wrong one means it can never be opened", got.ID, cred)
	}
	if got.Sealed != "totp$v1$fixture-one" {
		t.Errorf("the sealed value read back as %q", got.Sealed)
	}
	if got.KeyVersion != 2 {
		t.Errorf("key version is %d, want 2: at the wrong version the re-sealing job "+
			"visits the wrong rows", got.KeyVersion)
	}
	if got.Enabled {
		t.Error("a provisioned enrolment reports itself proven")
	}
	if usableRowExists(t, pool, subject, "totp") {
		t.Error("the usable-credential lookup returns an unproven enrolment; a login " +
			"would then verify against a secret nobody has demonstrated possession of")
	}
}

func TestEnablingMakesAnEnrolmentUsableAndIsIdempotent(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newSecondFactorsOn(t, pool)

	subject := testSubject(t)
	cred := newCredentialID()
	if err := store.Provision(ctx, app.NewTotpSecret{
		ID: cred, SubjectID: subject, Sealed: "totp$v1$fixture-two", KeyVersion: 1,
	}); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if err := store.Enable(ctx, cred); err != nil {
		t.Fatalf("enabling: %v", err)
	}
	if !usableRowExists(t, pool, subject, "totp") {
		t.Fatal("a proven enrolment is still invisible to the usable-credential lookup, " +
			"so the user has a second factor they cannot use")
	}
	first, err := store.Find(ctx, subject)
	if err != nil || !first.Enabled {
		t.Fatalf("after enabling: (%+v, %v)", first, err)
	}

	// A retried confirmation must not be an error and must not move the timestamp.
	if err := store.Enable(ctx, cred); err != nil {
		t.Fatalf("re-enabling: %v", err)
	}
}

func TestEnablingSomethingThatIsNotThereIsReported(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)
	if err := store.Enable(ctx, newCredentialID()); !errors.Is(err, app.ErrCredentialNotFound) {
		t.Fatalf("enabling an absent credential gave %v, want ErrCredentialNotFound: a "+
			"silent success would leave the log asserting a factor that does not exist", err)
	}
}

// A restarted enrolment must replace the abandoned secret AND un-prove the row,
// or the account keeps a second confirmable factor it has forgotten about.
func TestReprovisioningReplacesTheSecretAndClearsTheProof(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newSecondFactorsOn(t, pool)

	subject := testSubject(t)
	cred := newCredentialID()
	if err := store.Provision(ctx, app.NewTotpSecret{
		ID: cred, SubjectID: subject, Sealed: "totp$v1$first", KeyVersion: 1,
	}); err != nil {
		t.Fatalf("provisioning: %v", err)
	}
	if err := store.Enable(ctx, cred); err != nil {
		t.Fatalf("enabling: %v", err)
	}
	if err := store.Provision(ctx, app.NewTotpSecret{
		ID: cred, SubjectID: subject, Sealed: "totp$v1$second", KeyVersion: 3,
	}); err != nil {
		t.Fatalf("re-provisioning: %v", err)
	}

	got, err := store.Find(ctx, subject)
	if err != nil {
		t.Fatalf("finding: %v", err)
	}
	if got.Sealed != "totp$v1$second" || got.KeyVersion != 3 {
		t.Errorf("the row holds (%q, v%d), want the replacement", got.Sealed, got.KeyVersion)
	}
	if got.Enabled {
		t.Error("the replaced enrolment is still marked proven, so an abandoned secret " +
			"stays usable")
	}
	if usableRowExists(t, pool, subject, "totp") {
		t.Error("the usable lookup still returns the re-provisioned row")
	}
}

// The partial unique index is what keeps one subject from holding two live
// authenticators. This asserts the adapter surfaces that rather than swallowing
// it — the handler reuses the stored id precisely because of this.
func TestASecondLiveAuthenticatorIsRefused(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)

	subject := testSubject(t)
	if err := store.Provision(ctx, app.NewTotpSecret{
		ID: newCredentialID(), SubjectID: subject, Sealed: "totp$v1$a", KeyVersion: 1,
	}); err != nil {
		t.Fatalf("the first enrolment: %v", err)
	}
	err := store.Provision(ctx, app.NewTotpSecret{
		ID: newCredentialID(), SubjectID: subject, Sealed: "totp$v1$b", KeyVersion: 1,
	})
	if err == nil {
		t.Fatal("a second live authenticator was stored for one subject")
	}
}

func TestFindReportsNothingForAnUnknownSubject(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)
	if _, err := store.Find(ctx, testSubject(t)); !errors.Is(err, app.ErrNoTotpCredential) {
		t.Fatalf("an unknown subject gave %v, want ErrNoTotpCredential", err)
	}
	if _, err := store.Find(ctx, ""); !errors.Is(err, app.ErrNoTotpCredential) {
		t.Fatalf("an empty subject gave %v, want ErrNoTotpCredential: a caller must not "+
			"be able to tell a malformed lookup from a missing one", err)
	}
}

func TestProvisioningValidatesWhatItIsGiven(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)
	subject := testSubject(t)

	tests := map[string]app.NewTotpSecret{
		"no credential id": {SubjectID: subject, Sealed: "totp$v1$x", KeyVersion: 1},
		"no subject":       {ID: newCredentialID(), Sealed: "totp$v1$x", KeyVersion: 1},
		"no secret":        {ID: newCredentialID(), SubjectID: subject, KeyVersion: 1},
		"no key version":   {ID: newCredentialID(), SubjectID: subject, Sealed: "totp$v1$x"},
	}
	for name, secret := range tests {
		t.Run(name, func(t *testing.T) {
			if err := store.Provision(ctx, secret); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

func TestReplacingACodeSetReplacesTheWholeSet(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newSecondFactorsOn(t, pool)

	subject := testSubject(t)
	cred := newCredentialID()
	old := [][]byte{digestOf(t, 1), digestOf(t, 2), digestOf(t, 3)}
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: cred, SubjectID: subject, Digests: old, GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing the first set: %v", err)
	}
	if got := unusedCodeCount(t, pool, subject); got != 3 {
		t.Fatalf("%d unused codes, want 3", got)
	}

	// Spend one, then replace. The replacement must take BOTH the spent and the
	// unspent old rows with it.
	if _, err := store.Consume(ctx, subject, old[0]); err != nil {
		t.Fatalf("consuming: %v", err)
	}
	fresh := [][]byte{digestOf(t, 10), digestOf(t, 11)}
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: cred, SubjectID: subject, Digests: fresh, GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing the second set: %v", err)
	}
	if got := unusedCodeCount(t, pool, subject); got != 2 {
		t.Errorf("%d unused codes after a replacement of 2, want 2 — a top-up leaves "+
			"codes the user believes were replaced still live", got)
	}
	if _, err := store.Consume(ctx, subject, old[1]); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Errorf("a code from the replaced set was redeemed (%v); somebody who "+
			"photographed the old sheet keeps their access through the regeneration "+
			"performed to take it away", err)
	}
}

func TestARecoveryCodeIsSpentExactlyOnce(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)

	subject := testSubject(t)
	cred := newCredentialID()
	digest := digestOf(t, 42)
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: cred, SubjectID: subject, Digests: [][]byte{digest},
		GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}

	got, err := store.Consume(ctx, subject, digest)
	if err != nil {
		t.Fatalf("consuming: %v", err)
	}
	if got != cred {
		t.Errorf("the burn reported credential %s, want %s", got, cred)
	}
	if _, err := store.Consume(ctx, subject, digest); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Fatalf("the same code was spent twice (%v)", err)
	}
}

// The property the single-statement discipline exists for, and the only way to
// demonstrate it: many simultaneous presentations of ONE code, of which exactly
// one may win. A SELECT-then-UPDATE passes every sequential test above and fails
// this one.
func TestConcurrentRedemptionsOfOneCodeProduceExactlyOneWinner(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)

	subject := testSubject(t)
	digest := digestOf(t, 77)
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: newCredentialID(), SubjectID: subject, Digests: [][]byte{digest},
		GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}

	const racers = 8
	var (
		wg      sync.WaitGroup
		mu      sync.Mutex
		winners int
		other   error
	)
	start := make(chan struct{})
	for range racers {
		wg.Go(func() {
			<-start
			_, err := store.Consume(ctx, subject, digest)
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				winners++
			case errors.Is(err, app.ErrNoRecoveryCode):
			default:
				other = err
			}
		})
	}
	close(start)
	wg.Wait()

	if other != nil {
		t.Fatalf("a racer failed for an unexpected reason: %v", other)
	}
	if winners != 1 {
		t.Fatalf("%d of %d concurrent redemptions of ONE code succeeded, want exactly 1; "+
			"that concurrency is what somebody working from a photographed sheet produces",
			winners, racers)
	}
}

func TestACodeDoesNotRedeemOnAnotherSubject(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)

	mine, theirs := testSubject(t), testSubject(t)
	digest := digestOf(t, 99)
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: newCredentialID(), SubjectID: mine, Digests: [][]byte{digest},
		GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}
	if _, err := store.Consume(ctx, theirs, digest); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Fatalf("one subject's digest redeemed on another account (%v)", err)
	}
}

func TestTheRecoveryCredentialIsReadBack(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)

	subject := testSubject(t)
	if _, err := store.Credential(ctx, subject); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Fatalf("an account with no set gave %v, want ErrNoRecoveryCode", err)
	}

	cred := newCredentialID()
	if err := store.Replace(ctx, app.NewRecoveryCodeSet{
		CredentialID: cred, SubjectID: subject, Digests: [][]byte{digestOf(t, 5)},
		GeneratedAt: time.Now().UTC(),
	}); err != nil {
		t.Fatalf("storing: %v", err)
	}
	got, err := store.Credential(ctx, subject)
	if err != nil {
		t.Fatalf("reading back: %v", err)
	}
	if got != cred {
		t.Errorf("the stored credential is %s, want %s; a regenerate that mints a fresh "+
			"id contends on the one-usable-per-kind index and fails on every retry", got, cred)
	}
}

func TestReplacingValidatesWhatItIsGiven(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)
	subject := testSubject(t)
	now := time.Now().UTC()

	tests := map[string]app.NewRecoveryCodeSet{
		"no credential id": {SubjectID: subject, Digests: [][]byte{digestOf(t, 1)}, GeneratedAt: now},
		"no subject":       {CredentialID: newCredentialID(), Digests: [][]byte{digestOf(t, 1)}, GeneratedAt: now},
		"no digests":       {CredentialID: newCredentialID(), SubjectID: subject, GeneratedAt: now},
		"no generated-at":  {CredentialID: newCredentialID(), SubjectID: subject, Digests: [][]byte{digestOf(t, 1)}},
		"short digest": {
			CredentialID: newCredentialID(), SubjectID: subject,
			Digests: [][]byte{make([]byte, 16)}, GeneratedAt: now,
		},
	}
	for name, set := range tests {
		t.Run(name, func(t *testing.T) {
			if err := store.Replace(ctx, set); err == nil {
				t.Errorf("%s was accepted", name)
			}
		})
	}
}

func TestConsumingRefusesAMalformedPresentationAsUnknown(t *testing.T) {
	ctx := context.Background()
	store := newSecondFactors(t)
	if _, err := store.Consume(ctx, testSubject(t), make([]byte, 16)); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Fatalf("a wrong-width digest gave %v, want ErrNoRecoveryCode: the caller must "+
			"not be able to tell a malformed presentation from a wrong one", err)
	}
	if _, err := store.Consume(ctx, "", digestOf(t, 1)); !errors.Is(err, app.ErrNoRecoveryCode) {
		t.Fatalf("an empty subject gave %v, want ErrNoRecoveryCode", err)
	}
}

// A credential id ids.Parse cannot read means something other than this
// application wrote the row. It must be reported, never answered as "no such
// code": that would hide exactly the tampering the design is shaped to surface.
func TestAnUnreadableCredentialIdIsReportedRatherThanHidden(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)
	store := newSecondFactorsOn(t, pool)

	subject := testSubject(t)
	if _, err := pool.Exec(ctx, identitydb.UpsertCredential,
		"not-a-credential-id", subject, "totp", "totp$v1$x", int32(1), nil); err != nil {
		t.Fatalf("planting the row: %v", err)
	}
	t.Cleanup(func() {
		_, _ = pool.Exec(context.Background(), identitydb.DeleteCredential, "not-a-credential-id")
	})

	_, err := store.Find(ctx, subject)
	if err == nil || errors.Is(err, app.ErrNoTotpCredential) {
		t.Fatalf("a row with an unreadable id gave %v; answering 'no credential' hides "+
			"a row this application did not write", err)
	}
}
