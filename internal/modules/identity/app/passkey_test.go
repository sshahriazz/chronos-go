package app

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

type fakeCeremonies struct {
	credential CeremonyCredential
	assertion  CeremonyAssertion
	beginErr   error
	finishErr  error

	begun int
}

func (f *fakeCeremonies) BeginRegistration(CeremonyAccount) (CeremonyChallenge, error) {
	f.begun++
	if f.beginErr != nil {
		return CeremonyChallenge{}, f.beginErr
	}
	return CeremonyChallenge{Options: []byte(`{}`), State: []byte(`{"challenge":"x"}`)}, nil
}

func (f *fakeCeremonies) FinishRegistration(
	CeremonyAccount, []byte, []byte,
) (CeremonyCredential, error) {
	if f.finishErr != nil {
		return CeremonyCredential{}, f.finishErr
	}
	return f.credential, nil
}

func (f *fakeCeremonies) BeginLogin(CeremonyAccount, []CeremonyStored) (CeremonyChallenge, error) {
	f.begun++
	if f.beginErr != nil {
		return CeremonyChallenge{}, f.beginErr
	}
	return CeremonyChallenge{Options: []byte(`{}`), State: []byte(`{"challenge":"x"}`)}, nil
}

func (f *fakeCeremonies) FinishLogin(
	CeremonyAccount, []CeremonyStored, []byte, []byte,
) (CeremonyAssertion, error) {
	if f.finishErr != nil {
		return CeremonyAssertion{}, f.finishErr
	}
	return f.assertion, nil
}

// fakePasskeyStore records what was written and can be made to collide.
type fakePasskeyStore struct {
	rows        map[string]StoredPasskey
	outcome     SignCountOutcome
	registerErr error

	advanced []uint32
	removed  []string
	warned   int
}

func newFakePasskeyStore() *fakePasskeyStore {
	return &fakePasskeyStore{rows: map[string]StoredPasskey{}}
}

func (f *fakePasskeyStore) Register(_ context.Context, c NewPasskey) error {
	if f.registerErr != nil {
		return f.registerErr
	}
	if _, taken := f.rows[c.CredentialID]; taken {
		return ErrPasskeyAlreadyRegistered
	}
	f.rows[c.CredentialID] = StoredPasskey{
		CredentialID: c.CredentialID, SubjectID: c.SubjectID, PublicKey: c.PublicKey,
		SignCount: c.SignCount, UserVerified: c.UserVerified, Label: c.Label,
	}
	return nil
}

func (f *fakePasskeyStore) Find(_ context.Context, id string) (StoredPasskey, error) {
	row, ok := f.rows[id]
	if !ok {
		return StoredPasskey{}, ErrNoSuchPasskey
	}
	return row, nil
}

func (f *fakePasskeyStore) List(_ context.Context, subjectID string) ([]StoredPasskey, error) {
	var out []StoredPasskey
	for _, r := range f.rows {
		if r.SubjectID == subjectID {
			out = append(out, r)
		}
	}
	return out, nil
}

func (f *fakePasskeyStore) Advance(
	_ context.Context, _ string, presented uint32, _ time.Time,
) (SignCountOutcome, error) {
	f.advanced = append(f.advanced, presented)
	if f.outcome.Regressed {
		f.warned++
	}
	return f.outcome, nil
}

func (f *fakePasskeyStore) Remove(_ context.Context, id, _ string) error {
	if _, ok := f.rows[id]; !ok {
		return ErrNoSuchPasskey
	}
	delete(f.rows, id)
	f.removed = append(f.removed, id)
	return nil
}

func (f *fakePasskeyStore) Erase(_ context.Context, subjectID string) (int, error) {
	var n int
	for id, r := range f.rows {
		if r.SubjectID == subjectID {
			delete(f.rows, id)
			n++
		}
	}
	return n, nil
}

// fakeChallenges is single-use, like the real one.
type fakeChallenges struct {
	rows map[string]Challenge
}

func newFakeChallenges() *fakeChallenges {
	return &fakeChallenges{rows: map[string]Challenge{}}
}

func (f *fakeChallenges) Issue(_ context.Context, c Challenge) error {
	f.rows[c.ID] = c
	return nil
}

func (f *fakeChallenges) Consume(
	_ context.Context, id string, purpose CeremonyPurpose, now time.Time,
) (Challenge, error) {
	c, ok := f.rows[id]
	if !ok || c.Purpose != purpose || !c.ExpiresAt.After(now) {
		return Challenge{}, ErrNoSuchChallenge
	}
	// SINGLE USE, as the statement is. A fake that let a challenge be redeemed
	// twice would make every replay test pass for the wrong reason.
	delete(f.rows, id)
	return c, nil
}

func (f *fakeChallenges) Sweep(context.Context, time.Time) (int, error) { return 0, nil }

type fakePasskeyRecovery struct {
	codes  []string
	err    error
	issued int
}

func (f *fakePasskeyRecovery) Issue(context.Context, ids.UserID, string) ([]string, error) {
	f.issued++
	if f.err != nil {
		return nil, f.err
	}
	return f.codes, nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const passkeySubject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

type passkeyHarness struct {
	flow       *Passkeys
	user       *domain.User
	ceremonies *fakeCeremonies
	store      *fakePasskeyStore
	challenges *fakeChallenges
	recovery   *fakePasskeyRecovery
	appender   *fakeAppender
	now        time.Time
}

func newPasskeyHarness(t *testing.T) *passkeyHarness {
	t.Helper()

	now := time.Date(2026, 8, 23, 12, 0, 0, 0, time.UTC)
	userID := ids.New[ids.User](now, &fixedEntropy{})

	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, passkeySubject, "idx_1", now); err != nil {
		t.Fatal(err)
	}
	if err := user.VerifyEmail("idx_1", now); err != nil {
		t.Fatal(err)
	}
	if err := user.AssignUsername("ada", now); err != nil {
		t.Fatal(err)
	}
	user.ClearUncommitted()

	h := &passkeyHarness{
		user: user,
		ceremonies: &fakeCeremonies{credential: CeremonyCredential{
			ID: "Y3JlZC1vbmU", PublicKey: []byte("key"), UserVerified: true,
		}},
		store:      newFakePasskeyStore(),
		challenges: newFakeChallenges(),
		recovery:   &fakePasskeyRecovery{codes: []string{"aaaa-bbbb", "cccc-dddd"}},
		appender:   &fakeAppender{},
		now:        now,
	}

	flow, err := NewPasskeys(PasskeysDeps{
		Clock:      clock.NewFixed(now),
		Entropy:    &fixedEntropy{},
		Users:      staticLoader[*domain.User](user, nil),
		Subjects:   fakeDirectory{user: userID},
		Appender:   h.appender,
		Schemas:    eventsourcing.NewUpcasterRegistry(),
		Ceremonies: h.ceremonies,
		Store:      h.store,
		Challenges: h.challenges,
		Recovery:   h.recovery,
	})
	if err != nil {
		t.Fatalf("NewPasskeys: %v", err)
	}
	h.flow = flow
	return h
}

func (h *passkeyHarness) register(t *testing.T) FinishRegistrationResult {
	t.Helper()
	ctx := context.Background()
	begun, err := h.flow.BeginRegistration(ctx, BeginRegistrationCommand{SubjectID: passkeySubject})
	if err != nil {
		t.Fatalf("BeginRegistration: %v", err)
	}
	got, err := h.flow.FinishRegistration(ctx, FinishRegistrationCommand{
		SubjectID: passkeySubject, ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"Y3JlZC1vbmU"}`), Label: "MacBook",
		IdempotencyKey: "k-register",
	})
	if err != nil {
		t.Fatalf("FinishRegistration: %v", err)
	}
	return got
}

// ---------------------------------------------------------------------------
// The properties
// ---------------------------------------------------------------------------

// A CEREMONY IS SINGLE-USE.
//
// Replaying one is how a single signature becomes two credentials, or two
// sessions. The store enforces it with DELETE … RETURNING; this asserts the flow
// actually relies on that rather than looking the challenge up and leaving it.
func TestARegistrationCeremonyCannotBeReplayed(t *testing.T) {
	h := newPasskeyHarness(t)
	ctx := context.Background()

	begun, err := h.flow.BeginRegistration(ctx, BeginRegistrationCommand{SubjectID: passkeySubject})
	if err != nil {
		t.Fatal(err)
	}
	cmd := FinishRegistrationCommand{
		SubjectID: passkeySubject, ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"Y3JlZC1vbmU"}`), Label: "MacBook",
		IdempotencyKey: "k-1",
	}
	if _, err := h.flow.FinishRegistration(ctx, cmd); err != nil {
		t.Fatalf("first finish: %v", err)
	}
	if _, err := h.flow.FinishRegistration(ctx, cmd); err == nil {
		t.Fatal("a ceremony was redeemed twice; one signature can mint two credentials")
	}
}

// ANOTHER SUBJECT'S CEREMONY IS CONSUMED AND THEN REFUSED.
//
// Consumed FIRST, deliberately: refusing without consuming would let a caller
// who can guess a ceremony id probe for one by trying it repeatedly.
func TestAnotherSubjectsCeremonyIsSpentAndRefused(t *testing.T) {
	h := newPasskeyHarness(t)
	ctx := context.Background()

	begun, err := h.flow.BeginRegistration(ctx, BeginRegistrationCommand{SubjectID: passkeySubject})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := h.flow.FinishRegistration(ctx, FinishRegistrationCommand{
		SubjectID: "subj_someone_else", ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"x"}`), IdempotencyKey: "k-1",
	}); err == nil {
		t.Fatal("one subject completed another's ceremony")
	}
	// SPENT: the rightful owner cannot use it either, which is the cost of not
	// being a probe oracle.
	if _, err := h.flow.FinishRegistration(ctx, FinishRegistrationCommand{
		SubjectID: passkeySubject, ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"Y3JlZC1vbmU"}`), IdempotencyKey: "k-2",
	}); err == nil {
		t.Fatal("the ceremony survived being tried by another subject, so it can be " +
			"probed until it is guessed")
	}
}

// A DUPLICATE CREDENTIAL ID IS REFUSED, NOT REPLACED.
//
// WebAuthn L3 §7.1 step 27. Replacing a victim's registration with an attacker's
// signs the VICTIM into the ATTACKER'S account at their next attempt.
func TestADuplicateCredentialIsRefusedRatherThanReplacing(t *testing.T) {
	h := newPasskeyHarness(t)
	h.register(t)

	ctx := context.Background()
	begun, err := h.flow.BeginRegistration(ctx, BeginRegistrationCommand{SubjectID: passkeySubject})
	if err != nil {
		t.Fatal(err)
	}
	_, err = h.flow.FinishRegistration(ctx, FinishRegistrationCommand{
		SubjectID: passkeySubject, ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"Y3JlZC1vbmU"}`), IdempotencyKey: "k-dup",
	})
	if err == nil {
		t.Fatal("a credential id already in this installation was registered again. " +
			"Replacing a registration is the WebAuthn L3 §7.1 step 27 takeover")
	}
}

// RECOVERY CODES ARE ISSUED AT THE FIRST PASSKEY AND NOT THE SECOND.
//
// identity.md §5 calls lockout "the real design problem": a person whose only
// method is a passkey on a lost device must still get back in, and an
// afterthought is a path most people never take.
func TestRecoveryCodesAreIssuedAtTheFirstPasskeyOnly(t *testing.T) {
	h := newPasskeyHarness(t)

	first := h.register(t)
	if len(first.RecoveryCodes) == 0 {
		t.Fatal("a first passkey was registered with no recovery codes; the account has " +
			"one way in and no way back")
	}
	if h.recovery.issued != 1 {
		t.Fatalf("the issuer was called %d times for one registration", h.recovery.issued)
	}

	// A SECOND passkey issues none — re-issuing would invalidate the sheet the
	// person already printed.
	ctx := context.Background()
	h.ceremonies.credential.ID = "Y3JlZC10d28"
	begun, err := h.flow.BeginRegistration(ctx, BeginRegistrationCommand{SubjectID: passkeySubject})
	if err != nil {
		t.Fatal(err)
	}
	second, err := h.flow.FinishRegistration(ctx, FinishRegistrationCommand{
		SubjectID: passkeySubject, ChallengeID: begun.ChallengeID,
		Response: []byte(`{"id":"Y3JlZC10d28"}`), IdempotencyKey: "k-2",
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(second.RecoveryCodes) != 0 {
		t.Error("a second passkey re-issued recovery codes, invalidating the sheet the " +
			"person already has")
	}
	if h.recovery.issued != 1 {
		t.Errorf("the issuer was called %d times across two registrations", h.recovery.issued)
	}
}

// A FAILURE TO MINT CODES DOES NOT UNDO THE PASSKEY.
//
// Losing a working credential to a code-minting error is worse than having no
// codes. It is loud instead — the log line is the remedy.
func TestAFailedRecoveryIssueDoesNotUndoTheRegistration(t *testing.T) {
	h := newPasskeyHarness(t)
	h.recovery.err = errors.New("valkey is down")

	got := h.register(t)
	if got.CredentialID == "" {
		t.Fatal("the registration was rolled back because recovery codes could not be minted")
	}
	if len(got.RecoveryCodes) != 0 {
		t.Error("codes were reported despite the issuer failing")
	}
}

// A USER-VERIFIED PASSKEY AUTHENTICATES AT AAL2.
//
// identity.md §2: one gesture, two factors. Treating it as AAL1 would force a
// redundant TOTP prompt on the strongest method available.
func TestAUserVerifiedPasskeyReachesAAL2(t *testing.T) {
	h := newPasskeyHarness(t)
	h.register(t)
	h.ceremonies.assertion = CeremonyAssertion{
		ID: "Y3JlZC1vbmU", SignCount: 5, UserVerified: true,
	}
	h.store.outcome = SignCountOutcome{Advanced: true}

	got := h.login(t)
	if got.Proof.AAL() != contract.AAL2 {
		t.Fatalf("a user-verified passkey authenticated at %v, want AAL2", got.Proof.AAL())
	}
	if got.CloneWarned {
		t.Error("an advancing counter reported a clone warning")
	}
}

// AND WITHOUT USER VERIFICATION IT IS AAL1.
func TestAPasskeyWithoutUserVerificationIsAAL1(t *testing.T) {
	h := newPasskeyHarness(t)
	h.register(t)
	h.ceremonies.assertion = CeremonyAssertion{ID: "Y3JlZC1vbmU", SignCount: 5}
	h.store.outcome = SignCountOutcome{Advanced: true}

	if got := h.login(t); got.Proof.AAL() != contract.AAL1 {
		t.Fatalf("a passkey with no user verification authenticated at %v, want AAL1",
			got.Proof.AAL())
	}
}

// T1: A CLONE WARNING IS READ, AND IT CAPS THE SESSION RATHER THAN DENYING IT.
//
// # This is the test ADR-057 exists for
//
// `go-webauthn` sets CloneWarning and returns NO ERROR, so FinishLogin succeeds.
// An application that never inspects the flag has clone detection that does
// nothing while every test passes — the exact failure this repository shipped
// three times in notification adapters.
//
// And it must NOT deny: identity.md §5 says the counter is "not treated as
// mandatory, because most synced passkeys never increment it. A regression here
// locks out legitimate users." So the session is capped at AAL1, which makes
// anything sensitive ask for step-up while ordinary reads keep working.
func TestACloneWarningCapsTheSessionAndIsRecorded(t *testing.T) {
	for name, tc := range map[string]struct {
		assertion CeremonyAssertion
		outcome   SignCountOutcome
	}{
		"the library flagged it": {
			assertion: CeremonyAssertion{ID: "Y3JlZC1vbmU", SignCount: 3, UserVerified: true, CloneWarning: true},
			outcome:   SignCountOutcome{Advanced: true},
		},
		"the store saw the regression": {
			assertion: CeremonyAssertion{ID: "Y3JlZC1vbmU", SignCount: 3, UserVerified: true},
			outcome:   SignCountOutcome{Regressed: true, Stored: 9},
		},
	} {
		t.Run(name, func(t *testing.T) {
			h := newPasskeyHarness(t)
			h.register(t)
			h.ceremonies.assertion = tc.assertion
			h.store.outcome = tc.outcome
			h.appender.calls = nil

			got := h.login(t)

			// NOT denied. A denial signs people out for using two devices at once.
			if got.Proof.SubjectID() == "" {
				t.Fatal("a counter regression DENIED the sign-in. identity.md §5: a " +
					"regression here locks out legitimate users, and most synced " +
					"passkeys never increment the counter at all")
			}
			// CAPPED, so anything sensitive asks for step-up.
			if got.Proof.AAL() != contract.AAL1 {
				t.Fatalf("a clone warning left the session at %v; a possibly-cloned "+
					"authenticator would then change a password without stepping up",
					got.Proof.AAL())
			}
			if !got.CloneWarned {
				t.Error("the caller was not told why the session is reduced")
			}

			// RECORDED. Without the event the check is invisible: the library
			// returns no error, so nothing else marks that it happened.
			var found bool
			for _, call := range h.appender.calls {
				for _, a := range call {
					for _, e := range a.Events {
						if e.Event.EventType() == "identity.PasskeyCloneWarning.v1" {
							found = true
						}
					}
				}
			}
			if !found {
				t.Fatalf("no PasskeyCloneWarning was appended. go-webauthn sets the flag "+
					"and returns no error, so without this event the detection is "+
					"silent and every test still passes — appended: %v",
					passkeyAppended(h.appender))
			}
		})
	}
}

// AN UNKNOWN CREDENTIAL ANSWERS EXACTLY AS A BAD SIGNATURE DOES.
//
// A credential id is not secret — it travels in every allowCredentials list — so
// the answer must not tell a caller which ids are registered.
func TestAnUnknownCredentialIsIndistinguishableFromABadSignature(t *testing.T) {
	h := newPasskeyHarness(t)
	h.register(t)
	ctx := context.Background()

	unknown := h.beginLogin(t)
	_, unknownErr := h.flow.FinishLogin(ctx, FinishLoginCommand{
		ChallengeID: unknown, Response: []byte(`{"id":"bm90LXJlZ2lzdGVyZWQ"}`),
		IdempotencyKey: "k-1",
	})

	h.ceremonies.finishErr = errors.New("signature does not verify")
	bad := h.beginLogin(t)
	_, badErr := h.flow.FinishLogin(ctx, FinishLoginCommand{
		ChallengeID: bad, Response: []byte(`{"id":"Y3JlZC1vbmU"}`),
		IdempotencyKey: "k-2",
	})

	if unknownErr == nil || badErr == nil {
		t.Fatal("an unusable assertion was accepted")
	}
	if unknownErr.Error() != badErr.Error() {
		t.Fatalf("an unknown credential answers %q and a bad signature answers %q; the "+
			"difference tells a caller which credential ids are registered",
			unknownErr, badErr)
	}
}

// REMOVING THE ONLY PASSKEY ON A PASSKEY-ONLY ACCOUNT IS REFUSED.
func TestRemovingTheOnlyWayInIsRefused(t *testing.T) {
	h := newPasskeyHarness(t)
	h.register(t)

	err := h.flow.RemovePasskey(context.Background(), RemovePasskeyCommand{
		SubjectID: passkeySubject, CredentialID: "Y3JlZC1vbmU", IdempotencyKey: "k-rm",
	})
	if err == nil {
		t.Fatal("the account's only way to sign in was removed; the person is locked out " +
			"by an endpoint that was supposed to help them")
	}
	if _, still := h.store.rows["Y3JlZC1vbmU"]; !still {
		t.Error("the refused removal still deleted the row")
	}
}

// EVERY DEPENDENCY IS REQUIRED.
func TestNewPasskeysRefusesAPartialWiring(t *testing.T) {
	full := func() PasskeysDeps {
		return PasskeysDeps{
			Clock: clock.System{}, Entropy: &fixedEntropy{},
			Users: staticLoader[*domain.User](nil, nil), Subjects: fakeDirectory{},
			Appender: &fakeAppender{}, Schemas: eventsourcing.NewUpcasterRegistry(),
			Ceremonies: &fakeCeremonies{}, Store: newFakePasskeyStore(),
			Challenges: newFakeChallenges(), Recovery: &fakePasskeyRecovery{},
		}
	}
	for name, breakIt := range map[string]func(*PasskeysDeps){
		"no clock":      func(d *PasskeysDeps) { d.Clock = nil },
		"no entropy":    func(d *PasskeysDeps) { d.Entropy = nil },
		"no users":      func(d *PasskeysDeps) { d.Users = nil },
		"no subjects":   func(d *PasskeysDeps) { d.Subjects = nil },
		"no appender":   func(d *PasskeysDeps) { d.Appender = nil },
		"no schemas":    func(d *PasskeysDeps) { d.Schemas = nil },
		"no ceremonies": func(d *PasskeysDeps) { d.Ceremonies = nil },
		"no store":      func(d *PasskeysDeps) { d.Store = nil },
		// Without it nothing makes a ceremony single-use, and one signature mints
		// two sessions.
		"no challenges": func(d *PasskeysDeps) { d.Challenges = nil },
		// Without it a passkey-only account has one way in and no way back.
		"no recovery": func(d *PasskeysDeps) { d.Recovery = nil },
	} {
		t.Run(name, func(t *testing.T) {
			deps := full()
			breakIt(&deps)
			if _, err := NewPasskeys(deps); err == nil {
				t.Fatalf("a passkey flow was built with %s", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func (h *passkeyHarness) beginLogin(t *testing.T) string {
	t.Helper()
	got, err := h.flow.BeginLogin(context.Background(), BeginLoginCommand{})
	if err != nil {
		t.Fatalf("BeginLogin: %v", err)
	}
	return got.ChallengeID
}

func (h *passkeyHarness) login(t *testing.T) FinishLoginResult {
	t.Helper()
	got, err := h.flow.FinishLogin(context.Background(), FinishLoginCommand{
		ChallengeID: h.beginLogin(t), Response: []byte(`{"id":"Y3JlZC1vbmU"}`),
		IdempotencyKey: "k-login",
	})
	if err != nil {
		t.Fatalf("FinishLogin: %v", err)
	}
	return got
}

// passkeyAppended names every event this harness's appender received.
func passkeyAppended(a *fakeAppender) []string {
	var out []string
	for _, call := range a.calls {
		for _, s := range call {
			for _, e := range s.Events {
				out = append(out, e.Event.EventType())
			}
		}
	}
	return out
}
