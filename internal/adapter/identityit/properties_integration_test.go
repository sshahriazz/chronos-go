//go:build integration

package identityit_test

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// TestConcurrentRegistrationsForOneAddress is the property the reservation
// stream exists for (ADR-044), and it had never been demonstrated.
//
// Address uniqueness in this system is not a UNIQUE constraint. It is an
// optimistic append to a stream named by the address's blind index, with an
// expected revision — so two registrations racing for one address contend
// inside KurrentDB, one gets ErrWrongExpectedRevision, and the loser's ENTIRE
// registration is discarded because the append that would have created the
// account is the same atomic multi-append that claims the name.
//
// Nothing below the integration level can show this. A unit test with a fake
// store proves the handler's branch is written; it cannot prove that KurrentDB
// actually refuses the second append, and that is where the guarantee lives. It
// is driven with real goroutines against the real server for the same reason:
// serialized calls take the "already claimed" branch, which is a different code
// path from the one that loses the append race.
func TestConcurrentRegistrationsForOneAddress(t *testing.T) {
	const racers = 8
	ctx := context.Background()
	email := h.freshEmail("race")

	// A distinct idempotency key per goroutine, deliberately. A shared key would
	// let gate 5 collapse seven of the eight requests before any of them reached
	// the event store, and the test would pass while proving only that the
	// idempotency gate works.
	start := make(chan struct{})
	var wg sync.WaitGroup
	errs := make([]error, racers)
	for i := range racers {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			_, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
				Email: email,
			}))
			errs[i] = err
		}(i)
	}
	close(start)
	wg.Wait()

	// Every outcome is indistinguishable on the wire BY DESIGN: winning, losing
	// the reservation and losing the append all return an empty
	// RegisterResponse, because a distinguishable loss is an account-existence
	// oracle (RegisterResponse's own doc, identity.md §11). So a non-nil error
	// here is not "you lost" — it is the oracle being reintroduced.
	failed := 0
	for i, err := range errs {
		if err != nil {
			failed++
			t.Errorf("BUG: racer %d was refused with %v. Registration must answer identically "+
				"whether or not the address was free; an error that only losers receive tells "+
				"the caller that the address is taken.", i, err)
		}
	}
	t.Logf("racers=%d refused=%d", racers, failed)

	index := h.emailIndex(t, email)
	account := h.awaitAccount(t, index)

	// The assertions that matter. All three are absolute rather than delta-based
	// and that is safe: the blind-index key is unique to this run, so no other
	// test and no earlier run can have written a row under this index.
	var accounts, reservations int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM user_view WHERE email_index = $1`, index).Scan(&accounts); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(*) FROM email_reservation_view WHERE email_index = $1`,
			index).Scan(&reservations)
	})
	if accounts != 1 {
		t.Errorf("%d concurrent registrations produced %d accounts, want exactly 1", racers, accounts)
	}
	if reservations != 1 {
		t.Errorf("%d concurrent registrations produced %d reservations, want exactly 1",
			racers, reservations)
	}

	// And the reservation stream itself, read back from KurrentDB rather than
	// from its projection. The projection is derived; the stream is the truth,
	// and a single claim there is what makes the uniqueness real.
	stream, err := eventsourcing.NewStreamID("reservation_email", index)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := h.store.ReadStream(context.Background(), stream, 0)
	if err != nil {
		t.Fatalf("reading the reservation stream: %v", err)
	}
	claims := 0
	types := make([]string, 0, len(events))
	for _, e := range events {
		types = append(types, e.Type)
		if strings.Contains(e.Type, "Reserved") {
			claims++
		}
	}
	if claims != 1 {
		t.Errorf("the reservation stream holds %d claims, want 1: %v", claims, types)
	}
	t.Logf("racers=%d accounts=%d reservations=%d stream=%v winner=%s",
		racers, accounts, reservations, types, account.subjectID)

	// The winner is a whole account, not a half-built one: the losers must have
	// left NOTHING behind. That is what makes the append atomic rather than
	// merely ordered — a loser that had already written its vault entry would
	// leave seven orphaned subjects per contested address.
	//
	// The CREDENTIAL count is now zero for the winner too, and that is the
	// stronger statement: registration creates no credential at all
	// (IDENTITY-REVIEW C8), so eight racing registrations for one address produce
	// eight opportunities to write a verifier and take none of them. A non-zero
	// count here means a password exists for an address nobody has proven, which
	// is the pre-hijacking premise.
	//
	// Checked by counting, per subject, rather than by logging in. Logging in
	// would be the stronger check and is not available: `Authenticate` loads the
	// User aggregate, which currently fails for every account (see
	// TestIdentityEventsCarryTheirSchemaVersion), so an assertion on its refusal
	// would pass for the wrong reason.
	var credentials, vaultSubjects int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM credential WHERE subject_id = $1`,
			account.subjectID).Scan(&credentials); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(DISTINCT subject_id) FROM pii_key WHERE subject_id IN (
			     SELECT subject_id FROM user_view WHERE email_index = $1)`,
			index).Scan(&vaultSubjects)
	})
	if credentials != 0 {
		t.Errorf("the surviving account holds %d credential rows, want 0: a registration "+
			"creates no credential, and one that exists before the address is proven is "+
			"activated by the mailbox owner's own verification click", credentials)
	}
	if vaultSubjects != 1 {
		t.Errorf("%d subjects hold a vault key for this address, want 1", vaultSubjects)
	}
	t.Logf("winner: %d credential rows, %d vault subject", credentials, vaultSubjects)
}

// TestASecondRegistrationIsIndistinguishable is the deterministic form of the
// same property, and it is here because a race is a bad place to first learn
// about a defect: this one fails the same way every time.
//
// Registering an address that is already claimed must produce a response
// identical to registering a free one: same shape, same absence of detail. It is
// one of the four flows identity.md §11 names as leaking account existence when
// written naively.
//
// The COST is a weaker claim than it used to be, and it is worth being honest
// about here rather than repeating a comment that was never quite true. The
// handler once paid an Argon2id hash on both paths and called that its timing
// defence; the hash was a constant added to both, while the free path also
// writes the vault, issues a token digest and appends. The difference between
// the two paths is unchanged by the hash's removal, and it is stated on
// app.RegisterResult rather than closed. What this test asserts is the half that
// is absolute: the CONTENT is identical, and no error distinguishes them.
func TestASecondRegistrationIsIndistinguishable(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("dup")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("first Register: %v\n%s", err, h.serverLogs())
	}
	h.awaitAccount(t, h.emailIndex(t, email))

	_, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	}))
	if err != nil {
		t.Errorf("BUG: registering an already-claimed address was refused with %v, while "+
			"registering a free one succeeds. That difference IS the account-existence "+
			"oracle the empty RegisterResponse exists to close: a caller learns whether an "+
			"address has an account by trying to register it.", err)
	}

	// And exactly one account still holds the address, whichever answer came back.
	var accounts int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `SELECT count(*) FROM user_view WHERE email_index = $1`,
			h.emailIndex(t, email)).Scan(&accounts)
	})
	if accounts != 1 {
		t.Errorf("after a duplicate registration %d accounts hold the address, want 1", accounts)
	}
}

// TestRebuildPreservesCredentials is migration 00009's reason for existing.
//
// `credential` is authoritative, not projected: a password verifier and a
// sealed TOTP secret can never enter the event log, because an event is
// permanent and a verifier in one stays offline-crackable forever. So a
// projection rebuild — the routine recovery for a projector bug — must truncate
// and replay user_view, session_view and login_history_view WITHOUT touching
// it. 00008 wired foreign keys from credential to user_view, which would have
// made every rebuild cascade every password in the system into oblivion; 00009
// dropped them.
//
// This test asserts the property end to end: rebuild all three identity
// projections from position zero and check that the account is reconstructed
// identically while its credential row is untouched — and then log in with it.
func TestRebuildPreservesCredentials(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("rebuild")
	const password = "correct-horse-battery-staple-58"

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	registered := h.awaitAccount(t, index)

	// The account must be VERIFIED before it has a credential to preserve.
	// Registration no longer writes one (IDENTITY-REVIEW C8), so a rebuild test
	// that stopped at Register would truncate and replay a projection while the
	// authoritative table it must not touch was empty — and would pass whatever
	// migration 00009 had done.
	if _, err := h.client.VerifyEmail(ctx, write(&identityv1.VerifyEmailRequest{
		Token:    h.mintVerificationToken(t, registered.subjectID),
		Password: password,
	})); err != nil {
		t.Fatalf("VerifyEmail: %v\n%s", err, h.serverLogs())
	}

	before := h.awaitVerified(t, index)
	beforeCred := h.credentialFingerprints(t, before.subjectID)
	if len(beforeCred) == 0 {
		t.Fatal("the verification wrote no credential row, so this test would prove nothing")
	}

	// The live projectors hold the advisory lease each projection is guarded by,
	// and Rebuild takes the same one. Stopping them is what production would do
	// too — a rebuild is an operator action against a stopped projector.
	//
	// Restarted from a defer, not from the happy path. Every later test in this
	// package needs a running projector to see its own registration, so a
	// t.Fatal inside the rebuild must not take the rest of the package down with
	// it — which is exactly what happened the first time this ran.
	h.cancelProjectors()
	<-h.projectorsDone
	defer h.startProjectors()

	// identity_user and identity_reservation only. `identity_session.Reset`
	// deliberately refuses: session_view and user_view are tied by a foreign key
	// and Postgres will not truncate either alone, so `identity_user` truncates
	// all three projections together and rebuilding the session projection by
	// name is an error rather than a second, partial reset.
	for _, view := range []projection.Projection{
		identityprojection.NewUser(h.codec),
		identityprojection.NewReservation(h.codec),
	} {
		h.rebuild(t, view, index)
	}

	after := h.awaitAccount(t, index)
	if after != before {
		t.Errorf("the rebuild produced a different account row:\n  before %+v\n  after  %+v",
			before, after)
	}

	afterCred := h.credentialFingerprints(t, before.subjectID)
	if len(afterCred) != len(beforeCred) {
		t.Fatalf("BUG: a projection rebuild changed the credential count for subject %s "+
			"from %d to %d; the verifier is not recoverable from the log",
			before.subjectID, len(beforeCred), len(afterCred))
	}
	for id, fp := range beforeCred {
		if afterCred[id] != fp {
			t.Errorf("credential %s changed across the rebuild:\n  before %s\n  after  %s",
				id, fp, afterCred[id])
		}
	}
	t.Logf("rebuild: user_view row identical, %d credential row(s) preserved byte for byte",
		len(afterCred))

	// The stronger check — present the password to the real server and see it
	// verify — is deliberately NOT made here. `Authenticate` loads the User
	// aggregate before it ever reaches the verifier, and that load currently
	// fails for every account in the system (see
	// TestIdentityEventsCarryTheirSchemaVersion), so the call would refuse
	// without having touched the credential row and the assertion would pass
	// while proving nothing. The byte-for-byte comparison above is what carries
	// the property until that defect is fixed.
}

// TestTheAddressIsNeverStoredInTheClear is ADR-002 checked against the bytes
// rather than against the design.
//
// Personal data never enters an event or a log; only SubjectID pseudonyms do,
// and erasure works by destroying a key. That is only true if it is true of
// every byte actually written, so this reads the streams the flow produced back
// out of KurrentDB and searches the raw payloads and metadata, and does the same
// across every identity table in Postgres.
//
// The `pii_value` row is the ONE place the address is allowed to exist, and it
// must be there as ciphertext. Asserting that the row exists is as important as
// asserting the address is absent from it: without it, "the address is nowhere"
// would also be satisfied by a registration that never stored it at all.
func TestTheAddressIsNeverStoredInTheClear(t *testing.T) {
	ctx := context.Background()
	email := h.freshEmail("plaintext")

	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: email,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	index := h.emailIndex(t, email)
	account := h.awaitAccount(t, index)

	// --- KurrentDB ---------------------------------------------------------
	needles := []string{email, strings.ToLower(email), strings.Split(email, "@")[0]}
	streams := []struct{ category, key string }{
		{"user", account.userID},
		{"reservation_email", index},
	}
	scanned := 0
	for _, s := range streams {
		id, err := eventsourcing.NewStreamID(eventsourcing.Category(s.category), s.key)
		if err != nil {
			t.Fatalf("stream id: %v", err)
		}
		events, err := h.store.ReadStream(ctx, id, 0)
		if err != nil {
			t.Fatalf("reading %s: %v", id, err)
		}
		if len(events) == 0 {
			t.Fatalf("stream %s is empty; there is nothing to search and the property is unproven", id)
		}
		for _, e := range events {
			scanned++
			for _, needle := range needles {
				if strings.Contains(string(e.Payload), needle) {
					t.Errorf("BUG: event %s on %s carries the address in its PAYLOAD: %s",
						e.Type, id, e.Payload)
				}
				if strings.Contains(string(e.Metadata), needle) {
					t.Errorf("BUG: event %s on %s carries the address in its METADATA: %s",
						e.Type, id, e.Metadata)
				}
			}
		}
	}
	t.Logf("scanned %d events across %d streams; no payload or metadata contains the address",
		scanned, len(streams))

	// --- Postgres ----------------------------------------------------------
	//
	// Whole-row casts rather than a column list. A column added later is covered
	// by construction, which a list would not be — and the failure this guards
	// against is exactly somebody adding an `email` column to a projection.
	tables := []string{
		"user_view", "email_reservation_view", "session_view", "login_history_view",
		"credential", "recovery_code", "identity_token", "session_token", "pii_value",
	}
	for _, table := range tables {
		var hits int
		h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM `+table+` t WHERE t::text LIKE '%' || $1 || '%'`,
				email).Scan(&hits)
		})
		if hits != 0 {
			t.Errorf("BUG: %s holds %d row(s) containing the address in the clear", table, hits)
		}
	}
	t.Logf("no row in %d identity tables contains the address in the clear", len(tables))

	// --- and it IS in the vault, encrypted ---------------------------------
	var vaultRows, keyRows int
	h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		if err := q.QueryRow(ctx,
			`SELECT count(*) FROM pii_value WHERE subject_id = $1`, account.subjectID).
			Scan(&vaultRows); err != nil {
			return err
		}
		return q.QueryRow(ctx,
			`SELECT count(*) FROM pii_key WHERE subject_id = $1`, account.subjectID).Scan(&keyRows)
	})
	if vaultRows == 0 {
		t.Errorf("the vault holds no value for subject %s, so 'the address is nowhere' is "+
			"satisfied trivially and proves nothing", account.subjectID)
	}
	if keyRows == 0 {
		t.Errorf("the vault holds no wrapped key for subject %s; erasure would have nothing "+
			"to destroy", account.subjectID)
	}
	t.Logf("vault: %d value row(s) and %d wrapped key(s) for the subject", vaultRows, keyRows)

	// The blind index is a keyed hash and is what makes the login lookup possible
	// without an address column. It must not be derivable by anyone without the
	// key, so the stored value must not be the address in any encoding.
	if strings.Contains(index, "@") || strings.Contains(index, strings.Split(email, "@")[0]) {
		t.Errorf("the stored email index looks like the address itself: %q", index)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// credentialFingerprints reads every credential row for a subject as an opaque
// string, so a change of ANY column — verifier, pepper version, key version,
// enabled_at — is caught, not just a deleted row.
func (hh *harness) credentialFingerprints(t *testing.T, subjectID string) map[string]string {
	t.Helper()
	out := map[string]string{}
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx,
			`SELECT credential_id, c::text FROM credential c WHERE subject_id = $1
			 ORDER BY credential_id`, subjectID)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var id, whole string
			if err := rows.Scan(&id, &whole); err != nil {
				return err
			}
			out[id] = whole
		}
		return rows.Err()
	})
	return out
}

// rebuild replays one projection from position zero and stops it once the row
// this test cares about is back.
//
// "Caught up" is judged by the ROW rather than by the checkpoint, and that
// matters: a filtered subscription persists the server's CheckPointReached for
// spans that matched nothing (ADR-042), so the stored position advances long
// before any identity event has been applied. A settle heuristic on the
// checkpoint reports "rebuilt, 0 events" while the read model is still empty —
// which it did, the first time this was written.
func (hh *harness) rebuild(t *testing.T, view projection.Projection, index string) {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	done := make(chan error, 1)
	go func() { done <- projection.NewRunner(view, hh.projectionDeps()).Rebuild(ctx) }()

	deadline := time.After(5 * time.Minute)
	for {
		select {
		case err := <-done:
			t.Fatalf("the rebuild of %s stopped early: %v", view.Name(), err)
		case <-deadline:
			t.Fatalf("the rebuild of %s never restored the row for this run", view.Name())
		case <-time.After(500 * time.Millisecond):
			if !hh.rowRestored(t, view.Name(), index) {
				continue
			}
			cp := hh.checkpoint(t, view.Name())
			cancel()
			select {
			case <-done:
			case <-time.After(60 * time.Second):
				t.Fatalf("the rebuild of %s did not stop when cancelled", view.Name())
			}
			t.Logf("rebuilt %s: %d events applied, checkpoint at commit %d",
				view.Name(), cp.EventsProcessed, cp.Position.Commit)
			return
		}
	}
}

// rowRestored asks the projection's own table whether this run's registration
// has been replayed yet.
func (hh *harness) rowRestored(t *testing.T, projectionName, index string) bool {
	t.Helper()
	table := "user_view"
	if projectionName == identityprojection.ReservationName {
		table = "email_reservation_view"
	}
	var n int
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM `+table+` WHERE email_index = $1`, index).Scan(&n)
	})
	return n > 0
}

func (hh *harness) checkpoint(t *testing.T, name string) projection.Checkpoint {
	t.Helper()
	var cp projection.Checkpoint
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		got, err := pgadapter.Checkpoints{}.Load(ctx, q, name)
		if err != nil {
			if strings.Contains(err.Error(), "no checkpoint") {
				return nil
			}
			return err
		}
		cp = got
		return nil
	})
	return cp
}
