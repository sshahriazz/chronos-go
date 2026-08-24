//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"testing"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

func newPasskeysOn(t *testing.T) *identitypg.Passkeys {
	t.Helper()
	store, err := identitypg.NewPasskeys(pgadapter.New(openPool(t)))
	if err != nil {
		t.Fatalf("NewPasskeys: %v", err)
	}
	return store
}

func newPasskey(t *testing.T, subject, credentialID string) app.NewPasskey {
	t.Helper()
	return app.NewPasskey{
		CredentialID: credentialID,
		SubjectID:    subject,
		PublicKey:    []byte("cose-public-key-bytes"),
		SignCount:    0,
		UserVerified: true,
		Label:        "MacBook",
		RegisteredAt: time.Now().UTC().Truncate(time.Microsecond),
	}
}

// C3: A CREDENTIAL ID IS UNIQUE ACROSS EVERY ACCOUNT, AND THE INDEX IS WHAT
// SAYS SO.
//
// # Why this test is here and not a unit test
//
// ADR-057 says it directly: "IDENTITY-REVIEW C3 requires a negative test that
// constructs the collision, and it belongs in the integration suite rather than
// a unit test, because what is being asserted is the INDEX." A fake store can be
// written to refuse a duplicate and would prove only that the fake refuses one.
// This asserts the constraint the database actually holds — and a mutation of
// the use case's refusal survived the unit suite for exactly that reason.
//
// # The attack it forecloses
//
// WebAuthn L3 §7.1 step 27. An attacker obtains a victim's credential ID and
// public key — neither is secret, both travel in an `allowCredentials` list —
// and registers them as their own. If the relying party REPLACES the victim's
// registration and the credentials are discoverable, the VICTIM IS SIGNED INTO
// THE ATTACKER'S ACCOUNT at their next attempt, and everything they do there is
// the attacker's.
//
// So the collision is constructed here across TWO SUBJECTS, which is the shape a
// per-subject unique index would not catch.
func TestACredentialIDCannotBeRegisteredTwiceAcrossAccounts(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	victim := testSubject(t)
	attacker := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)

	if err := store.Register(ctx, newPasskey(t, victim, credentialID)); err != nil {
		t.Fatalf("registering the victim's passkey: %v", err)
	}
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), victim) })

	err := store.Register(ctx, newPasskey(t, attacker, credentialID))
	if !errors.Is(err, app.ErrPasskeyAlreadyRegistered) {
		t.Fatalf("registering a credential id another account already holds returned %v, "+
			"want ErrPasskeyAlreadyRegistered. If it SUCCEEDED, the victim signs into "+
			"the attacker's account at their next attempt", err)
	}

	// And the victim still owns it. A refusal that had somehow moved the row
	// would be the takeover with an error message attached.
	got, err := store.Find(ctx, credentialID)
	if err != nil {
		t.Fatalf("the credential vanished: %v", err)
	}
	if got.SubjectID != victim {
		t.Fatalf("the credential now belongs to %q, want the victim %q. The registration "+
			"was refused and the row moved anyway", got.SubjectID, victim)
	}
}

// THE SAME ACCOUNT CANNOT REGISTER ONE CREDENTIAL TWICE EITHER.
//
// The milder half of the same constraint, and worth asserting separately: a
// per-subject index would catch this one and miss the takeover above, so a test
// that only covered this would pass against the wrong index.
func TestACredentialIDCannotBeRegisteredTwiceByOneAccount(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	subject := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), subject) })

	if err := store.Register(ctx, newPasskey(t, subject, credentialID)); err != nil {
		t.Fatal(err)
	}
	if err := store.Register(ctx, newPasskey(t, subject, credentialID)); !errors.Is(
		err, app.ErrPasskeyAlreadyRegistered,
	) {
		t.Fatalf("re-registering returned %v, want ErrPasskeyAlreadyRegistered", err)
	}
}

// A PASSKEY IS NOT COUPLED TO THE ACCOUNT PROJECTION.
//
// # The disaster this forecloses, which was shipped and then removed
//
// 00031 gave this table a foreign key to `user_view` with ON DELETE CASCADE, and
// 00033 dropped it. `user_view` is a PROJECTION: a rebuild truncates it and
// replays the log. With that key in place, a rebuild — a routine, supposedly
// safe act — would delete every passkey in the installation, and ADR-057 is
// explicit that none of them is rebuildable because a public key never enters an
// event. The rebuild would report success.
//
// It is the same key migration 00009 removed from `credential`, for the same
// reason, reintroduced within one session of that reasoning being written down.
// This test is what stops the third time.
//
// Asserted by registering a passkey for a subject that has NO projected account,
// which is exactly what the world looks like mid-rebuild.
func TestAPasskeyIsNotCoupledToTheAccountProjection(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	// A subject with no user_view row: the projection is empty while this table
	// is untouched.
	subject := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), subject) })

	if err := store.Register(ctx, newPasskey(t, subject, credentialID)); err != nil {
		t.Fatalf("a passkey could not be stored for an unprojected account: %v.\n\n"+
			"That is the foreign key to user_view. It means a projection REBUILD "+
			"cascades into every passkey in the system, and no replay restores them "+
			"because a public key is in no event (ADR-057)", err)
	}
	if _, err := store.Find(ctx, credentialID); err != nil {
		t.Fatalf("the passkey did not survive: %v", err)
	}
}

// THE SIGN COUNT ONLY EVER GOES FORWARD, ATOMICALLY.
//
// The whole clone check is `UPDATE … WHERE sign_count < $new`. In Go it would be
// a read-modify-write two concurrent logins can both win.
func TestTheSignCountAdvancesOnlyForwards(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	subject := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), subject) })

	c := newPasskey(t, subject, credentialID)
	c.SignCount = 5
	if err := store.Register(ctx, c); err != nil {
		t.Fatal(err)
	}
	now := time.Now().UTC()

	// FORWARD: accepted.
	got, err := store.Advance(ctx, credentialID, 9, now)
	if err != nil {
		t.Fatal(err)
	}
	if !got.Advanced || got.Regressed {
		t.Fatalf("advancing 5 → 9 reported %+v", got)
	}

	// BACKWARD: refused as a regression, and the stored value is unchanged.
	got, err = store.Advance(ctx, credentialID, 6, now)
	if err != nil {
		t.Fatal(err)
	}
	if got.Advanced {
		t.Fatal("the counter went BACKWARDS. A cloned authenticator replaying an old " +
			"counter would be indistinguishable from a legitimate login")
	}
	if !got.Regressed {
		t.Fatalf("a regression from 9 to 6 was not reported: %+v", got)
	}
	if got.Stored != 9 {
		t.Errorf("the stored counter is %d, want 9 — the difference is what separates a "+
			"race from a clone", got.Stored)
	}

	after, err := store.Find(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if after.SignCount != 9 {
		t.Fatalf("the stored counter moved to %d on a regression", after.SignCount)
	}
	if after.CloneWarnedAt.IsZero() {
		t.Error("a regression left no record; an operator cannot ask whether this " +
			"credential has ever gone backwards")
	}
}

// 0 → 0 IS NORMAL AND MUST NOT READ AS A REGRESSION.
//
// Synced passkey providers report signCount = 0 permanently, because there is no
// coherent place to keep a monotonic counter across N devices. Treating that as
// a clone would flag most of the passkeys in existence on every single login.
func TestAZeroCounterIsNotARegression(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	subject := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), subject) })

	if err := store.Register(ctx, newPasskey(t, subject, credentialID)); err != nil {
		t.Fatal(err)
	}
	got, err := store.Advance(ctx, credentialID, 0, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if got.Regressed {
		t.Fatal("0 → 0 was reported as a clone. Synced passkeys report 0 permanently, so " +
			"this would flag most of the passkeys in existence on every login")
	}
	if got.Advanced {
		t.Error("0 → 0 was reported as an advance; nothing moved")
	}

	// The USE still happened, so it is recorded.
	after, err := store.Find(ctx, credentialID)
	if err != nil {
		t.Fatal(err)
	}
	if after.LastUsedAt.IsZero() {
		t.Error("a synced passkey's login left no last-used timestamp, so a security " +
			"screen cannot say when it was last used")
	}
	if !after.CloneWarnedAt.IsZero() {
		t.Error("0 → 0 stamped a clone warning")
	}
}

// A REMOVAL IS SCOPED TO ITS OWNER.
//
// Find is deliberately not scoped — a ceremony asks whose a credential is — so
// the scoping has to be here, or naming somebody else's credential id deletes
// their passkey.
func TestARemovalCannotTakeAnotherAccountsPasskey(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	owner := testSubject(t)
	stranger := testSubject(t)
	credentialID := "cred_" + randomHex(t, 16)
	t.Cleanup(func() { _, _ = store.Erase(context.Background(), owner) })

	if err := store.Register(ctx, newPasskey(t, owner, credentialID)); err != nil {
		t.Fatal(err)
	}
	if err := store.Remove(ctx, credentialID, stranger); !errors.Is(err, app.ErrNoSuchPasskey) {
		t.Fatalf("a stranger's removal returned %v, want ErrNoSuchPasskey", err)
	}
	if _, err := store.Find(ctx, credentialID); err != nil {
		t.Fatalf("the owner's passkey was deleted by somebody else: %v", err)
	}
}

// ERASURE DELETES THE ROWS.
//
// The one erasure path that removes rows rather than destroying a key: this
// material is not encrypted under a subject key, so there is nothing to shred.
func TestErasureDeletesEveryPasskey(t *testing.T) {
	ctx := context.Background()
	store := newPasskeysOn(t)

	subject := testSubject(t)
	for range 3 {
		if err := store.Register(ctx, newPasskey(t, subject, "cred_"+randomHex(t, 16))); err != nil {
			t.Fatal(err)
		}
	}
	removed, err := store.Erase(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if removed != 3 {
		t.Fatalf("erasure removed %d passkeys, want 3", removed)
	}
	left, err := store.List(ctx, subject)
	if err != nil {
		t.Fatal(err)
	}
	if len(left) != 0 {
		t.Fatalf("%d passkeys survived erasure. Unlike vault data there is no key to "+
			"destroy, so a row that survives is readable material about an erased "+
			"person", len(left))
	}
}

// NOTHING AUTHORITATIVE REFERENCES user_view.
//
// # The rule, and why the blanket version is wrong
//
// `session_view` references `user_view` and that is FINE: both are projections,
// `TruncateIdentityProjections` names them in one statement, and TRUNCATE
// permits a referenced table when the referencing one is truncated with it. The
// first version of this test forbade every key and failed on that legitimate
// one.
//
// The real rule is narrower and is the one the truncate statement already
// states: a table that is NOT rebuildable from the log may not reference a table
// that is. Those tables hold verifiers, secrets and public keys that no replay
// restores, so a foreign key to a projection either cascades — destroying them
// on a rebuild — or blocks the truncate and makes the projection impossible to
// rebuild at all.
//
// # Why it is a schema query and not a per-table assertion
//
// The same defect has been introduced three times: 00008 gave `credential` the
// key and 00009 removed it; 00031 gave one to `passkey_credential` and 00033
// removed it; 00032 gave one to `webauthn_challenge` and 00034 removed it. Each
// time the reasoning was already written down. A per-table test catches the
// table it was written for; this catches the next one.
func TestNoAuthoritativeTableReferencesTheAccountProjection(t *testing.T) {
	ctx := context.Background()
	pool := openPool(t)

	// Every identity table whose contents no replay can restore. Listed by name
	// rather than inferred, because "is this rebuildable" is a design fact about
	// each table and not something the schema records.
	authoritative := map[string]bool{
		"credential":         true,
		"recovery_code":      true,
		"identity_token":     true,
		"passkey_credential": true,
		"webauthn_challenge": true,
	}

	rows, err := pool.Query(ctx, `
		SELECT c.conrelid::regclass::text, c.conname
		FROM pg_constraint c
		WHERE c.contype = 'f'
		  AND c.confrelid = 'user_view'::regclass`)
	if err != nil {
		t.Fatalf("reading foreign keys: %v", err)
	}
	defer rows.Close()

	var offenders []string
	for rows.Next() {
		var table, constraint string
		if err := rows.Scan(&table, &constraint); err != nil {
			t.Fatal(err)
		}
		if authoritative[table] {
			offenders = append(offenders, table+"."+constraint)
		}
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}

	if len(offenders) > 0 {
		t.Fatalf("%d authoritative table(s) reference user_view: %v.\n\n"+
			"user_view is a PROJECTION: a rebuild truncates it. These tables hold "+
			"material no replay can restore, so the key either cascades and destroys "+
			"them or blocks the truncate and makes the projection impossible to "+
			"rebuild. This has been introduced three times already — add the column "+
			"without the key, and delete explicitly where erasure needs it",
			len(offenders), offenders)
	}
}
