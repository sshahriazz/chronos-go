package domain_test

import (
	"errors"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// A fixed instant. The domain has no clock, so every test supplies one and
// nothing here depends on when it runs.
var at = time.Date(2026, 8, 11, 12, 0, 0, 0, time.UTC)

func newID[K ids.Kind](t *testing.T) ids.ID[K] {
	t.Helper()
	return ids.New[K](at, ids.Entropy())
}

// registered returns a Pending account with nothing enrolled.
func registered(t *testing.T) *domain.User {
	t.Helper()
	u := eventsourcing.NewAggregate(domain.New)
	if err := u.Register(newID[ids.User](t), "subj_1", "idx_1", at); err != nil {
		t.Fatalf("register: %v", err)
	}
	return u
}

// legacyPassword puts a password on an account whose address is UNPROVEN.
//
// It applies the event directly rather than taking the decision, because the
// decision is refused: SetPassword requires a verified address (IDENTITY-REVIEW
// C8). The STATE is still reachable — every account registered before that rule
// existed has exactly this shape in its stream, and Apply must never reject a
// recorded fact — so tests about how such an account behaves need a way to build
// one. Using it anywhere the rule itself is under test would defeat the rule.
func legacyPassword(u *domain.User, cred ids.CredentialID) *domain.User {
	u.Apply(&contract.PasswordSet{
		SubjectID:    u.SubjectID(),
		CredentialID: cred.String(),
		SetAt:        at,
	})
	return u
}

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

// A password may not be set before the address it belongs to is proven.
//
// This is the aggregate's half of the pre-hijacking defence (IDENTITY-REVIEW
// C8). Without it, a stranger registers somebody else's address with a password
// of their own, the mailbox owner follows the verification link believing they
// are finishing their own signup, and that click — which proves control of the
// MAILBOX and nothing more — switches the stranger's credential on.
//
// The rule is stated as a refusal in the aggregate rather than as an ordering in
// the use case, so a second path to a first password inherits it instead of
// having to remember it.
func TestAPasswordCannotBeSetBeforeTheAddressIsProven(t *testing.T) {
	u := registered(t)
	before := len(u.Uncommitted())

	err := u.SetPassword(newID[ids.Credential](t), at)
	if err == nil {
		t.Fatal("an unverified account accepted a password: whoever registered the address " +
			"can now set the credential that the real mailbox owner's click will activate, " +
			"which is the pre-hijacking attack in full")
	}
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Errorf("reason is %s, want %s", got, errs.Conflict)
	}
	if got := len(u.Uncommitted()); got != before {
		t.Errorf("the refusal still recorded %d event(s)", got-before)
	}

	// And it is accepted the moment the address IS proven, so the rule is an
	// ordering rather than a prohibition — without this half the test would also
	// pass against a SetPassword that refused unconditionally.
	mustNil(t, u.VerifyEmail("idx_1", at))
	mustNil(t, u.SetPassword(newID[ids.Credential](t), at))
}

// A registered account is Pending and can do nothing.
//
// The assertion that matters is the SECOND one. "Pending" as a label is
// cosmetic; what makes it real is that CanAuthenticate refuses.
func TestRegistrationLeavesTheAccountUnusable(t *testing.T) {
	u := registered(t)

	if got := u.State(); got != domain.StatePending {
		t.Errorf("state is %s, want pending", got)
	}
	reason, ok := u.CanAuthenticate()
	if ok {
		t.Fatal("a freshly registered account was allowed to authenticate before verifying " +
			"its address or enrolling a second factor")
	}
	if reason != contract.ReasonUnverifiedEmail {
		t.Errorf("refusal reason is %q, want %q", reason, contract.ReasonUnverifiedEmail)
	}
}

// Activation needs email verification AND a primary AND a real second factor.
//
// Each subtest stops one step short, so a rule that stopped being enforced shows
// up as exactly one failure naming the missing piece — rather than as a single
// "not active" that could mean any of them.
func TestActivationRequiresEveryPrecondition(t *testing.T) {
	cred := newID[ids.Credential](t)
	totp := newID[ids.Credential](t)

	t.Run("verified and password, but no second factor", func(t *testing.T) {
		u := registered(t)
		mustNil(t, u.VerifyEmail("idx_1", at))
		mustNil(t, u.SetPassword(cred, at))

		if u.State() == domain.StateActive {
			t.Fatal("the account activated with no second factor: the mandatory-second-factor " +
				"policy (identity.md §2) is not enforced, and password-alone is an auth path")
		}
	})

	t.Run("verified and TOTP, but nothing primary", func(t *testing.T) {
		u := registered(t)
		mustNil(t, u.VerifyEmail("idx_1", at))
		mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
		mustNil(t, u.EnableTotp(totp, at))

		if u.State() == domain.StateActive {
			t.Fatal("the account activated with only a second factor: nothing it holds can " +
				"begin an authentication")
		}
	})

	t.Run("password and TOTP, but unverified", func(t *testing.T) {
		// The password is APPLIED rather than decided: an unverified account
		// cannot be given one any more. The state is still reachable by replay,
		// and this subtest is about what activation does with it.
		u := legacyPassword(registered(t), cred)
		mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
		mustNil(t, u.EnableTotp(totp, at))

		if u.State() == domain.StateActive {
			t.Fatal("the account activated without a verified address: anyone can register " +
				"someone else's address and reach a usable account")
		}
	})
}

// The order in which the preconditions are met must not matter.
//
// maybeActivate is called from three different decide methods, and it is easy
// for one of them to be the only one that works. Verifying last and enrolling
// last are genuinely different code paths.
func TestActivationHappensWhicheverStepIsLast(t *testing.T) {
	for _, tc := range []struct {
		name string
		run  func(t *testing.T, u *domain.User, pw, totp ids.CredentialID)
	}{
		// Verification last is now reachable only from a stream written before
		// SetPassword required a proven address, so the password is applied as a
		// recorded fact. The path still has to activate: a rebuild of such an
		// account must reach Active exactly as it did, or every pre-existing
		// account silently stops being usable.
		{"verification last", func(t *testing.T, u *domain.User, pw, totp ids.CredentialID) {
			legacyPassword(u, pw)
			mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
			mustNil(t, u.EnableTotp(totp, at))
			mustNil(t, u.VerifyEmail("idx_1", at))
		}},
		{"second factor last", func(t *testing.T, u *domain.User, pw, totp ids.CredentialID) {
			mustNil(t, u.VerifyEmail("idx_1", at))
			mustNil(t, u.SetPassword(pw, at))
			mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
			mustNil(t, u.EnableTotp(totp, at))
		}},
		{"password last", func(t *testing.T, u *domain.User, pw, totp ids.CredentialID) {
			mustNil(t, u.VerifyEmail("idx_1", at))
			mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
			mustNil(t, u.EnableTotp(totp, at))
			mustNil(t, u.SetPassword(pw, at))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := registered(t)
			tc.run(t, u, newID[ids.Credential](t), newID[ids.Credential](t))

			if got := u.State(); got != domain.StateActive {
				t.Fatalf("state is %s after every precondition was met: the account is stuck "+
					"Pending and the user has no remaining action that would fix it", got)
			}
			if _, ok := u.CanAuthenticate(); !ok {
				t.Error("an active account still cannot authenticate")
			}
			if n := countEvents[*contract.UserActivated](u); n != 1 {
				t.Errorf("recorded %d UserActivated events, want exactly 1", n)
			}
		})
	}
}

// Recovery codes must NOT satisfy the second-factor requirement.
//
// They are RoleSecondFactor and Usable, so without the explicit exclusion an
// account with a password and a printed code sheet activates — which lets a user
// answer "set up a second factor" by generating recovery codes, and leaves the
// policy satisfied by the one method whose entire purpose is to work after the
// real ones have failed.
func TestRecoveryCodesAloneDoNotActivateAnAccount(t *testing.T) {
	u := registered(t)
	mustNil(t, u.VerifyEmail("idx_1", at))
	mustNil(t, u.SetPassword(newID[ids.Credential](t), at))
	mustNil(t, u.GenerateRecoveryCodes(newID[ids.Credential](t), 10, at))

	if u.State() == domain.StateActive {
		t.Fatal("a password plus recovery codes activated the account: the mandatory second " +
			"factor can be satisfied by printing a sheet of paper")
	}
}

// ---------------------------------------------------------------------------
// AtLeastOneUsableMethod
// ---------------------------------------------------------------------------

// Removing the only second factor from an active account is refused.
func TestDisablingTheOnlySecondFactorIsRefused(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)

	err := u.DisableTotp(totp, "subj_1", at)
	if err == nil {
		t.Fatal("the last second factor was removed from an active account, leaving it below " +
			"its own policy with no error and no record")
	}
	if !errors.Is(err, errs.Conflictf("")) {
		t.Errorf("error is %v, want a CONFLICT the client can act on", err)
	}
	if u.State() != domain.StateActive {
		t.Error("the refused removal changed the account state")
	}
}

// Recovery codes do not count as the replacement second factor either.
//
// This is the removal-side twin of the activation rule. Counting them would let
// an account with TOTP plus a code sheet drop the TOTP and keep only the sheet.
func TestRecoveryCodesDoNotPermitRemovingTheRealSecondFactor(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	mustNil(t, u.GenerateRecoveryCodes(newID[ids.Credential](t), 10, at))

	if err := u.DisableTotp(totp, "subj_1", at); err == nil {
		t.Fatal("TOTP was removed because recovery codes were counted as a second factor: " +
			"the account's only remaining factor is a printed sheet")
	}
}

// A Pending account may remove its unproven enrollment and start over.
//
// The invariant protects ACTIVE accounts. Applying it to Pending ones would trap
// a user who scanned the QR code into the wrong authenticator app with no way
// out.
func TestAPendingAccountMayAbandonItsEnrollment(t *testing.T) {
	u := registered(t)
	totp := newID[ids.Credential](t)
	mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
	mustNil(t, u.EnableTotp(totp, at))

	if err := u.DisableTotp(totp, "subj_1", at); err != nil {
		t.Fatalf("a pending account could not abandon its enrollment: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Lifecycle
// ---------------------------------------------------------------------------

// Suspension is not reversible by the holder; deactivation is.
//
// The two states are indistinguishable from outside, so the only thing that
// makes suspension mean anything is this asymmetry.
func TestOnlyDeactivationIsReversibleByTheHolder(t *testing.T) {
	t.Run("deactivated", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.Deactivate("subj_1", at))
		if err := u.Reactivate("subj_1", at); err != nil {
			t.Fatalf("the holder could not undo their own deactivation: %v", err)
		}
		if u.State() != domain.StateActive {
			t.Errorf("state is %s after reactivation", u.State())
		}
	})

	t.Run("suspended", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.Suspend("op_1", "abuse", at))

		err := u.Reactivate("subj_1", at)
		if err == nil {
			t.Fatal("a suspended account reactivated itself: suspension is decorative")
		}
		// The REASON, not merely that it failed.
		//
		// Deleting the explicit suspended branch still refuses — the state is not
		// Deactivated, so the fallback catches it — and an assertion on `err !=
		// nil` alone cannot tell the two apart. What is lost is the identity:
		// ACCESS_DENIED ("you are not allowed to do this") degrades to CONFLICT
		// ("this account is not deactivated"), which describes the state machine
		// rather than the decision, and reads in a log as a client bug rather
		// than as someone probing a suspension.
		if !errors.Is(err, errs.AccessDeniedf("")) {
			t.Errorf("error is %v; a suspended account must be refused as ACCESS_DENIED, "+
				"not as a state-machine CONFLICT", err)
		}
		if u.State() != domain.StateSuspended {
			t.Errorf("state is %s, want suspended", u.State())
		}
	})
}

// A suspended account accepts no credential changes.
func TestASuspendedAccountAcceptsNoChanges(t *testing.T) {
	u := active(t)
	mustNil(t, u.Suspend("op_1", "abuse", at))

	if err := u.SetPassword(newID[ids.Credential](t), at); err == nil {
		t.Error("a suspended account set a password")
	}
	if err := u.StartTotpEnrollment(newID[ids.Credential](t), at.Add(time.Hour), at); err == nil {
		t.Error("a suspended account enrolled an authenticator")
	}
}

// Each refusal reason is distinct, and none of them reaches the caller.
//
// The reasons exist for the LOG. The test asserts the mapping is complete —
// a state that fell through to a zero reason would produce a log line saying
// nothing about why the login failed.
func TestEveryUnusableStateHasItsOwnRefusalReason(t *testing.T) {
	unverified := registered(t)

	// Pending, verified, and NOT the bootstrap case: this account has already
	// proven a second factor and is unfinished for a different reason — it has no
	// primary method, so there is nothing for a login to start with. It is the
	// case ReasonIncomplete continues to describe now that a Pending account
	// which has never held a factor is admitted (NeedsFirstSecondFactor).
	incomplete := registered(t)
	mustNil(t, incomplete.VerifyEmail("idx_1", at))
	incompleteTotp := newID[ids.Credential](t)
	mustNil(t, incomplete.StartTotpEnrollment(incompleteTotp, at.Add(time.Hour), at))
	mustNil(t, incomplete.EnableTotp(incompleteTotp, at))
	if incomplete.State() != domain.StatePending {
		t.Fatalf("the incomplete fixture is %s, not pending", incomplete.State())
	}

	// Deactivated AND UNVERIFIED. A deactivated account whose address IS proven is
	// admitted now — the login is how identity.md §1's holder-reversible promise is
	// kept, and NeedsReactivation is what says so (see
	// TestAVerifiedDeactivatedAccountMayAuthenticateToReactivate). This fixture is
	// the case ReasonDeactivated continues to describe: an account switched off
	// before it ever proved a mailbox, so there is nobody a reactivation could be
	// attributed to.
	deactivated := registered(t)
	mustNil(t, deactivated.Deactivate("subj_1", at))
	if deactivated.EmailVerified() {
		t.Fatal("the deactivated fixture proved its address; it must not, or this case " +
			"is testing the reactivation path instead of the refusal")
	}

	suspended := active(t)
	mustNil(t, suspended.Suspend("op_1", "abuse", at))

	for _, tc := range []struct {
		name string
		user *domain.User
		want contract.FailureReason
	}{
		{"nonexistent", eventsourcing.NewAggregate(domain.New), contract.ReasonNoSuchIdentifier},
		{"unverified", unverified, contract.ReasonUnverifiedEmail},
		{"no second factor", incomplete, contract.ReasonIncomplete},
		{"deactivated", deactivated, contract.ReasonDeactivated},
		{"suspended", suspended, contract.ReasonSuspended},
	} {
		t.Run(tc.name, func(t *testing.T) {
			reason, ok := tc.user.CanAuthenticate()
			if ok {
				t.Fatalf("a %s account was allowed to authenticate", tc.name)
			}
			if reason != tc.want {
				t.Errorf("reason is %q, want %q", reason, tc.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Deactivation, and the way back
// ---------------------------------------------------------------------------

// A verified deactivated account may authenticate, and that is the only way it
// can ever come back.
//
// This is the property the whole reactivation design exists for, and it is the
// one that would silently not exist. identity.md §1 says deactivation is
// reversible by the holder; CanAuthenticate refused a deactivated account, every
// authenticated RPC needs a session, and a session needs an authentication — so
// "reversible" was a word with no code behind it, exactly as the first-enrolment
// deadlock was before NeedsFirstSecondFactor.
//
// Ask what this test would do if the feature were deleted: restore the blanket
// `return ReasonDeactivated, false` and it fails on the first assertion.
func TestAVerifiedDeactivatedAccountMayAuthenticateToReactivate(t *testing.T) {
	u := active(t)
	mustNil(t, u.Deactivate("subj_1", at))

	if !u.NeedsReactivation() {
		t.Fatal("a verified deactivated account does not report that it needs reactivation")
	}
	reason, ok := u.CanAuthenticate()
	if !ok {
		t.Fatalf("a verified deactivated account was refused authentication with %q; there is "+
			"then no route back into it, and deactivation is permanent rather than "+
			"reversible", reason)
	}

	// And the reversal itself is the decision the login is required to record in
	// the same append. Without it the ceremony would end in a session for an
	// account the log still says is off.
	mustNil(t, u.Reactivate("subj_1", at.Add(time.Minute)))
	if u.State() != domain.StateActive {
		t.Fatalf("state after reactivation is %s, want active", u.State())
	}
	if u.NeedsReactivation() {
		t.Error("an account still reports that it needs reactivation after being reactivated")
	}
}

// A SUSPENDED account is not admitted, and the holder cannot undo one.
//
// The whole difference between the two states. If the carve-out above ever
// widens to "not active", this fails.
func TestASuspendedAccountIsNeitherAdmittedNorReversibleByItsHolder(t *testing.T) {
	u := active(t)
	mustNil(t, u.Suspend("op_1", "abuse", at))

	if u.NeedsReactivation() {
		t.Fatal("a suspended account reports that it needs reactivation; the holder would " +
			"then undo an administrative suspension by signing in")
	}
	if reason, ok := u.CanAuthenticate(); ok || reason != contract.ReasonSuspended {
		t.Fatalf("a suspended account authenticates (%v) or refuses with %q, want a refusal "+
			"with %q", ok, reason, contract.ReasonSuspended)
	}
	if err := u.Reactivate("subj_1", at); err == nil {
		t.Fatal("the holder reactivated a suspended account")
	}
}

// A deactivated account that never proved its address stays refused.
//
// The carve-out is keyed on a PROVEN mailbox, for NeedsFirstSecondFactor's
// reason: nothing otherwise establishes that the person signing in is the person
// the address belongs to.
func TestADeactivatedAccountWithAnUnprovenAddressStaysRefused(t *testing.T) {
	u := registered(t)
	mustNil(t, u.Deactivate("subj_1", at))

	if u.NeedsReactivation() {
		t.Fatal("a deactivated account with an unproven address reports that it needs " +
			"reactivation")
	}
	if _, ok := u.CanAuthenticate(); ok {
		t.Fatal("a deactivated account with an unproven address was allowed to authenticate")
	}
}

// ---------------------------------------------------------------------------
// The deletion request
// ---------------------------------------------------------------------------

// A deletion request records one event, changes no state, and is idempotent.
func TestRequestDeletion(t *testing.T) {
	due := at.Add(30 * 24 * time.Hour)

	t.Run("it records the request and leaves the account alone", func(t *testing.T) {
		u := active(t)
		u.ClearUncommitted()
		mustNil(t, u.RequestDeletion("subj_1", due, at))

		events := u.Uncommitted()
		if len(events) != 1 {
			t.Fatalf("a deletion request recorded %d events, want exactly 1: %#v", len(events), events)
		}
		e, ok := events[0].(*contract.UserDeletionRequested)
		if !ok {
			t.Fatalf("a deletion request recorded %T", events[0])
		}
		if !e.ScheduledFor.Equal(due) {
			t.Errorf("the deadline is %s, want %s", e.ScheduledFor, due)
		}
		if e.ActorID != "subj_1" || e.SubjectID != u.SubjectID() {
			t.Errorf("actor=%q subject=%q, want subj_1 / %q", e.ActorID, e.SubjectID, u.SubjectID())
		}

		// The state does NOT move. Nothing consumes the request yet, so an account
		// that stopped working here would be broken by a request nobody is going to
		// act on.
		if u.State() != domain.StateActive {
			t.Errorf("state after a deletion request is %s, want active — the account still "+
				"works, because nothing has erased it", u.State())
		}
		if scheduled, requested := u.DeletionRequested(); !requested || !scheduled.Equal(due) {
			t.Errorf("DeletionRequested() = (%s, %v), want (%s, true)", scheduled, requested, due)
		}
	})

	t.Run("a second request records nothing and keeps the first deadline", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.RequestDeletion("subj_1", due, at))
		u.ClearUncommitted()

		later := due.Add(365 * 24 * time.Hour)
		mustNil(t, u.RequestDeletion("subj_1", later, at.Add(time.Hour)))
		if got := u.Uncommitted(); len(got) != 0 {
			t.Fatalf("a repeated deletion request recorded %d event(s); anyone holding the "+
				"session could then push the deadline out forever, and every mail naming a "+
				"date would be contradicted by the next", len(got))
		}
		if scheduled, _ := u.DeletionRequested(); !scheduled.Equal(due) {
			t.Errorf("the deadline moved to %s; the first one (%s) is the date the holder "+
				"was mailed", scheduled, due)
		}
	})

	t.Run("a suspended account may not start the clock", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.Suspend("op_1", "abuse", at))
		if err := u.RequestDeletion("subj_1", due, at); err == nil {
			t.Fatal("a suspended account requested its own erasure; the subject of a " +
				"suspension would then destroy the evidence it exists to preserve")
		}
	})

	t.Run("a deadline in the past is refused", func(t *testing.T) {
		u := active(t)
		if err := u.RequestDeletion("subj_1", at.Add(-time.Second), at); err == nil {
			t.Fatal("a deletion deadline already in the past was accepted")
		}
	})

	t.Run("a rebuild reaches the same answer", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.RequestDeletion("subj_1", due, at))

		rebuilt := eventsourcing.NewAggregate(domain.New)
		rebuilt.Apply(&contract.UserDeletionRequested{
			SubjectID: "subj_1", ActorID: "subj_1", ScheduledFor: due, RequestedAt: at,
		})
		scheduled, requested := rebuilt.DeletionRequested()
		if !requested || !scheduled.Equal(due) {
			t.Fatalf("replaying the event gives (%s, %v), want (%s, true) — the projection "+
				"and the aggregate would then disagree after a rebuild", scheduled, requested, due)
		}
	})
}

// ---------------------------------------------------------------------------
// The first enrolment
// ---------------------------------------------------------------------------

// A verified account with no second factor may authenticate, and that is the
// only way it can ever get one.
//
// Without this the account is deadlocked: enrolling a factor needs a session, a
// session needs AAL2, and AAL2 needs the factor. The refusal that used to sit
// here made every account registered through the public API permanently Pending.
func TestAVerifiedAccountWithNoFactorMayAuthenticateToEnrolItsFirst(t *testing.T) {
	u := registered(t)
	mustNil(t, u.VerifyEmail("idx_1", at))
	mustNil(t, u.SetPassword(newID[ids.Credential](t), at))

	if u.State() != domain.StatePending {
		t.Fatalf("the fixture is %s, not pending", u.State())
	}
	if !u.NeedsFirstSecondFactor() {
		t.Fatal("an account that has never held a second factor does not report that it " +
			"needs its first")
	}
	reason, ok := u.CanAuthenticate()
	if !ok {
		t.Fatalf("a verified account with no second factor was refused (%q), so it can never "+
			"enrol one and can never leave pending", reason)
	}
	if reason != "" {
		t.Errorf("an allowed authentication carries the refusal reason %q", reason)
	}
}

// Nothing but that one state reports it.
//
// The table is the security statement: NeedsFirstSecondFactor is what admits a
// password-only login and what the AAL1 session is justified by, so any state
// reaching it that should not is a route to a session without a second factor.
func TestOnlyANeverEnrolledVerifiedAccountNeedsAFirstFactor(t *testing.T) {
	// Pending, verified, and already holding a proven factor — it has no primary
	// method, which is why it has not activated.
	pendingWithFactor := registered(t)
	mustNil(t, pendingWithFactor.VerifyEmail("idx_1", at))
	pwfTotp := newID[ids.Credential](t)
	mustNil(t, pendingWithFactor.StartTotpEnrollment(pwfTotp, at.Add(time.Hour), at))
	mustNil(t, pendingWithFactor.EnableTotp(pwfTotp, at))

	// Pending, verified, mid-enrolment: the secret is provisioned and no code has
	// proven it. A provisioned-but-unproven factor must NOT end the exemption, or
	// the account is locked out one step further along than before — it can start
	// an enrolment and never confirm it.
	midEnrolment := registered(t)
	mustNil(t, midEnrolment.VerifyEmail("idx_1", at))
	mustNil(t, midEnrolment.SetPassword(newID[ids.Credential](t), at))
	mustNil(t, midEnrolment.StartTotpEnrollment(newID[ids.Credential](t), at.Add(time.Hour), at))

	unverified := legacyPassword(registered(t), newID[ids.Credential](t))

	deactivated := active(t)
	mustNil(t, deactivated.Deactivate("subj_1", at))

	suspended := active(t)
	mustNil(t, suspended.Suspend("op_1", "abuse", at))

	for _, tc := range []struct {
		name string
		user *domain.User
		want bool
	}{
		{"nonexistent", eventsourcing.NewAggregate(domain.New), false},
		{"registered but unverified", unverified, false},
		{"verified, never enrolled", midEnrolment, true},
		{"verified, already proven a factor", pendingWithFactor, false},
		{"active", active(t), false},
		{"deactivated", deactivated, false},
		{"suspended", suspended, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.user.NeedsFirstSecondFactor(); got != tc.want {
				t.Fatalf("NeedsFirstSecondFactor is %v, want %v", got, tc.want)
			}
			if !tc.want {
				return
			}
			if _, ok := tc.user.CanAuthenticate(); !ok {
				t.Fatal("an account that needs its first factor may not authenticate, so it " +
					"cannot get one")
			}
		})
	}
}

// An unverified address never earns a session, whatever else is enrolled.
//
// The exemption is what makes a password-only session possible, so the address
// check is the whole thing standing between "somebody registered your address"
// and "somebody holds a session on your account". It is asserted separately from
// the table above because it is the conjunct an optimisation is most likely to
// drop.
func TestAnUnverifiedAccountIsRefusedHoweverFarItsEnrolmentGot(t *testing.T) {
	u := legacyPassword(registered(t), newID[ids.Credential](t))

	if u.NeedsFirstSecondFactor() {
		t.Error("an account whose address nobody proved reports that it may enrol a factor")
	}
	reason, ok := u.CanAuthenticate()
	if ok {
		t.Fatal("an account whose address nobody proved was allowed to authenticate; " +
			"registering somebody else's address would hand over a session on it")
	}
	if reason != contract.ReasonUnverifiedEmail {
		t.Errorf("refusal reason is %q, want %q", reason, contract.ReasonUnverifiedEmail)
	}
}

// Having held a second factor is PERMANENT, and no route walks it back.
//
// This is the stolen-password attack, stated as a property. An attacker who
// knows the password of an account that already has a factor cannot enrol their
// own — the exemption is keyed on "has ever had", so the only way back to it
// would be an event that clears the fact. Each subtest is one candidate for such
// an event.
func TestHavingHeldASecondFactorIsPermanent(t *testing.T) {
	t.Run("the factor is removed", func(t *testing.T) {
		// Removal is possible here because the account never activated (no primary
		// method), which is exactly the account an attacker would want to walk back:
		// an active one cannot remove its last factor at all.
		u := registered(t)
		mustNil(t, u.VerifyEmail("idx_1", at))
		totp := newID[ids.Credential](t)
		mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
		mustNil(t, u.EnableTotp(totp, at))
		mustNil(t, u.DisableTotp(totp, "subj_1", at))

		if len(u.UsableMethods()) != 0 {
			t.Fatalf("the fixture still holds %d usable methods", len(u.UsableMethods()))
		}
		assertEstablished(t, u)
	})

	t.Run("the factor is locked out", func(t *testing.T) {
		u := active(t)
		totp := totpCredential(t, u)
		locked, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at)
		mustNil(t, err)
		if !locked {
			t.Fatal("the fixture did not lock the authenticator out")
		}
		assertEstablished(t, u)
	})

	t.Run("the account is deactivated and reactivated", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.Deactivate("subj_1", at))
		assertEstablished(t, u)
		mustNil(t, u.Reactivate("subj_1", at))
		assertEstablished(t, u)
	})

	t.Run("the account is suspended", func(t *testing.T) {
		u := active(t)
		mustNil(t, u.Suspend("op_1", "abuse", at))
		assertEstablished(t, u)
	})

	t.Run("the account is rebuilt from its log", func(t *testing.T) {
		// Locked out rather than removed: an active account may not remove its last
		// factor at all, and a lockout is the way its only factor really does stop
		// being usable — so the rebuilt aggregate holds no usable second factor and
		// must still report that it once did.
		live := active(t)
		if _, err := live.RecordAuthenticatorFailure(
			totpCredential(t, live), domain.LockoutThreshold, at,
		); err != nil {
			t.Fatalf("locking the authenticator out: %v", err)
		}

		rebuilt := eventsourcing.NewAggregate(domain.New)
		for _, e := range live.Uncommitted() {
			rebuilt.Apply(e)
		}
		if !rebuilt.HasEverHadSecondFactor() {
			t.Fatal("an account rebuilt from a log containing TotpEnabled reports that it has " +
				"never held a second factor; a projection rebuild would hand the first-enrolment " +
				"exemption to every account in the system")
		}
		assertEstablished(t, rebuilt)
	})

	t.Run("activation alone is enough to establish it", func(t *testing.T) {
		// A stream whose factor was proven by an event this build does not
		// recognise still reaches Active, so activation is read as evidence in its
		// own right rather than depending on the list of enabling events being
		// exhaustive.
		u := eventsourcing.NewAggregate(domain.New)
		u.Apply(&contract.UserRegistered{
			UserID: newID[ids.User](t).String(), SubjectID: "subj_1",
			EmailIndex: "idx_1", RegisteredAt: at,
		})
		u.Apply(&contract.EmailVerified{SubjectID: "subj_1", Index: "idx_1", VerifiedAt: at})
		u.Apply(&contract.UserActivated{SubjectID: "subj_1", ActivatedAt: at})
		assertEstablished(t, u)
	})
}

// assertEstablished states the two halves of "this account may not bootstrap".
func assertEstablished(t *testing.T, u *domain.User) {
	t.Helper()
	if !u.HasEverHadSecondFactor() {
		t.Error("the account reports that it has never held a second factor")
	}
	if u.NeedsFirstSecondFactor() {
		t.Error("an account that has held a second factor reports that it needs its first; " +
			"anyone holding its password could enrol one of their own")
	}
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// Consuming the last code records exhaustion as its own event.
func TestConsumingTheLastRecoveryCodeRecordsExhaustion(t *testing.T) {
	u := active(t)
	mustNil(t, u.GenerateRecoveryCodes(newID[ids.Credential](t), 2, at))

	mustNil(t, u.ConsumeRecoveryCode(at))
	if n := countEvents[*contract.RecoveryCodesExhausted](u); n != 0 {
		t.Fatal("exhaustion was recorded while codes remained")
	}
	if got := u.RecoveryCodesRemaining(); got != 1 {
		t.Fatalf("remaining is %d, want 1", got)
	}

	mustNil(t, u.ConsumeRecoveryCode(at))
	if n := countEvents[*contract.RecoveryCodesExhausted](u); n != 1 {
		t.Fatal("the last code was consumed without recording exhaustion: nothing forces the " +
			"re-issue interstitial and the account silently loses its fallback")
	}
	if err := u.ConsumeRecoveryCode(at); err == nil {
		t.Fatal("a code was consumed from an exhausted set")
	}
}

// ---------------------------------------------------------------------------
// NoSilentDowngrade
// ---------------------------------------------------------------------------

// A normal login on an account whose best door IS the one used is not a
// downgrade.
//
// Slice 1 enrols exactly one primary method, so this is the only end-to-end
// case the rule can reach today — and it is the false-positive side, which is
// the side that decides whether the signal survives contact with production.
// The true-positive case needs a second primary method and lands with passkeys
// in slice 2. Nothing here should be read as covering it.
func TestAnOrdinaryLoginIsNotADowngrade(t *testing.T) {
	u := active(t) // password + TOTP

	if u.IsDowngrade([]contract.MethodKind{contract.MethodPassword}) {
		t.Error("a password attempt on an account whose only door is a password was called " +
			"a downgrade")
	}
	if u.IsDowngrade([]contract.MethodKind{contract.MethodPassword, contract.MethodTOTP}) {
		t.Error("a normal password+TOTP login was flagged as a downgrade: the rule is " +
			"comparing the primary factor against a second factor, so it fires on every " +
			"login and the signal is noise within a week")
	}
}

// The strength ordering is what makes NoSilentDowngrade able to fire at all.
//
// Asserted directly rather than through an account, because the ordering is the
// part that must already be right before the method that would exercise it
// exists. A password ranking at or above a passkey is not a test failure in
// slice 2 — it is a rule that silently never fires.
func TestTheStrengthOrderingCanExpressADowngrade(t *testing.T) {
	if domain.StrengthOf(contract.MethodPassword) >= domain.StrengthOf(contract.MethodPasskey) {
		t.Error("a password ranks at or above a passkey: an attacker who cannot beat a " +
			"passkey simply asks for the password form, and nothing records it")
	}
	if domain.StrengthOf(contract.MethodRecoveryCode) >= domain.StrengthOf(contract.MethodPassword) {
		t.Error("a recovery code ranks at or above a password: the method whose purpose is " +
			"to work after everything else has failed is not treated as a fallback")
	}
	// An unclassified kind must sort BELOW everything real, not above it. A kind
	// added to the contract without being classified here would otherwise be
	// treated as the strongest thing the account holds.
	if domain.StrengthOf("not_a_real_method") >= domain.StrengthOf(contract.MethodRecoveryCode) {
		t.Error("an unrecognised method kind outranks a recovery code: adding a kind to the " +
			"contract without classifying it makes it the account's strongest method")
	}
	if domain.RoleOf("not_a_real_method") != domain.RoleSecondFactor {
		t.Error("an unrecognised method kind can begin an authentication")
	}
}

// ---------------------------------------------------------------------------
// Rebuild
// ---------------------------------------------------------------------------

// Replaying an account's own events reproduces its state exactly.
//
// This is the property the whole design rests on: if Apply and the decide
// methods ever disagree, the aggregate loaded from the log behaves differently
// from the one that just wrote it, and the divergence is invisible until a
// restart.
func TestReplayingTheEventsReproducesTheState(t *testing.T) {
	live := active(t)
	mustNil(t, live.GenerateRecoveryCodes(newID[ids.Credential](t), 5, at))
	mustNil(t, live.ConsumeRecoveryCode(at))

	rebuilt := eventsourcing.NewAggregate(domain.New)
	for _, e := range live.Uncommitted() {
		rebuilt.Apply(e)
	}

	if live.State() != rebuilt.State() {
		t.Errorf("state: live %s, rebuilt %s", live.State(), rebuilt.State())
	}
	if live.EmailVerified() != rebuilt.EmailVerified() {
		t.Errorf("emailVerified: live %v, rebuilt %v", live.EmailVerified(), rebuilt.EmailVerified())
	}
	if live.SubjectID() != rebuilt.SubjectID() {
		t.Errorf("subject: live %q, rebuilt %q", live.SubjectID(), rebuilt.SubjectID())
	}
	if live.RecoveryCodesRemaining() != rebuilt.RecoveryCodesRemaining() {
		t.Errorf("recovery codes: live %d, rebuilt %d",
			live.RecoveryCodesRemaining(), rebuilt.RecoveryCodesRemaining())
	}
	if len(live.UsableMethods()) != len(rebuilt.UsableMethods()) {
		t.Errorf("usable methods: live %d, rebuilt %d",
			len(live.UsableMethods()), len(rebuilt.UsableMethods()))
	}
	if live.StrongestUsablePrimary() != rebuilt.StrongestUsablePrimary() {
		t.Errorf("strongest: live %v, rebuilt %v", live.StrongestUsablePrimary(), rebuilt.StrongestUsablePrimary())
	}
}

// A retried verification records nothing and does not fail.
//
// Mail clients prefetch links. A second click must not produce an error page for
// having succeeded, and must not produce a second event either — every
// EmailVerified voids sessions (identity.md §7 rule 7), so a duplicate would
// sign the user out immediately after they signed in.
func TestVerifyingTwiceRecordsNothingTheSecondTime(t *testing.T) {
	u := registered(t)
	mustNil(t, u.VerifyEmail("idx_1", at))
	before := countEvents[*contract.EmailVerified](u)

	mustNil(t, u.VerifyEmail("idx_1", at))
	if after := countEvents[*contract.EmailVerified](u); after != before {
		t.Fatalf("a repeated verification recorded another event (%d -> %d): every one of "+
			"them voids the user's sessions", before, after)
	}
}

// ---------------------------------------------------------------------------
// Authenticator lockout
// ---------------------------------------------------------------------------

// Consecutive failures against a second factor disable it, and only at the
// threshold.
//
// The subtest one short of the threshold is the one that matters. A rule that
// disabled on the first failure would pass any test that only checked "ten
// failures lock it out", and would lock out every user who mistyped a code once.
func TestAnAuthenticatorLocksOutOnlyAtTheThreshold(t *testing.T) {
	for _, tc := range []struct {
		name     string
		failures int
		want     bool
	}{
		{"first failure", 1, false},
		{"one short", domain.LockoutThreshold - 1, false},
		{"at the threshold", domain.LockoutThreshold, true},
		{"beyond it", domain.LockoutThreshold + 4, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := active(t)
			totp := totpCredential(t, u)
			u.ClearUncommitted()

			locked, err := u.RecordAuthenticatorFailure(totp, tc.failures, at)
			mustNil(t, err)
			if locked != tc.want {
				t.Fatalf("%d failures reported locked=%v, want %v", tc.failures, locked, tc.want)
			}
			if got := countEvents[*contract.AuthenticatorDisabled](u); got != boolToInt(tc.want) {
				t.Errorf("recorded %d AuthenticatorDisabled events, want %d",
					got, boolToInt(tc.want))
			}
			m, ok := u.Method(totp)
			if !ok {
				t.Fatal("the authenticator vanished from the account")
			}
			if m.Usable() == tc.want {
				t.Errorf("the authenticator's usability is %v after %d failures",
					m.Usable(), tc.failures)
			}
		})
	}
}

// The event names the credential and the count, and carries nothing else.
func TestALockoutRecordsTheCredentialAndTheCount(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	u.ClearUncommitted()

	if _, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at); err != nil {
		t.Fatalf("recording a lockout: %v", err)
	}
	pending := u.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("recorded %d events, want 1", len(pending))
	}
	disabled, ok := pending[0].(*contract.AuthenticatorDisabled)
	if !ok {
		t.Fatalf("recorded %T, want *contract.AuthenticatorDisabled", pending[0])
	}
	switch {
	case disabled.CredentialID != totp.String():
		t.Errorf("the event names credential %q, want %q", disabled.CredentialID, totp)
	case disabled.SubjectID != "subj_1":
		t.Errorf("the event names subject %q, want the account's pseudonym", disabled.SubjectID)
	case disabled.Failures != domain.LockoutThreshold:
		t.Errorf("the event records %d failures, want %d",
			disabled.Failures, domain.LockoutThreshold)
	case !disabled.DisabledAt.Equal(at.UTC()) || disabled.DisabledAt.Location() != time.UTC:
		t.Errorf("the event is stamped %s, want %s in UTC", disabled.DisabledAt, at.UTC())
	}
}

// A PRIMARY factor is never disabled by failures, however many there are.
//
// This is the denial-of-service refusal, and it is the property most likely to be
// "simplified" into a uniform rule: anyone who knows an address can produce
// failures against that account's password, so a password that could be locked out
// is a password anybody can lock out. The assertion is not only that no event is
// recorded — it is that the account can still authenticate afterwards, which is
// what "a lockout cannot strand an account" means operationally.
func TestAPrimaryFactorIsNeverLockedOutByFailures(t *testing.T) {
	u := active(t)
	password := passwordCredential(t, u)
	u.ClearUncommitted()

	for i := 1; i <= domain.LockoutThreshold*5; i++ {
		locked, err := u.RecordAuthenticatorFailure(password, i, at)
		mustNil(t, err)
		if locked {
			t.Fatalf("the password credential was disabled after %d failures; an attacker who "+
				"knows an address can produce those at will, so this locks out any account "+
				"they can name", i)
		}
	}
	if got := countEvents[*contract.AuthenticatorDisabled](u); got != 0 {
		t.Errorf("recorded %d lockouts against a primary factor, want 0", got)
	}
	m, ok := u.Method(password)
	if !ok || !m.Usable() {
		t.Fatal("the password credential is no longer usable")
	}
	if reason, ok := u.CanAuthenticate(); !ok {
		t.Errorf("the account can no longer authenticate (%q); repeated failures must not be "+
			"able to strand it with no usable primary method", reason)
	}
}

// A locked-out authenticator stops satisfying every rule that reads usability.
func TestALockedOutAuthenticatorCountsForNothing(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	u.ClearUncommitted()

	if _, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at); err != nil {
		t.Fatalf("recording a lockout: %v", err)
	}
	for _, m := range u.UsableMethods() {
		if m.ID == totp {
			t.Fatal("a locked-out authenticator is still listed as usable")
		}
	}
	// The account keeps a usable primary, so it still passes the state gate — the
	// login then finds no second factor to offer. That asymmetry is deliberate:
	// removing the way IN would be the denial of service; removing a second factor
	// that is being ground is the whole point.
	if _, ok := u.CanAuthenticate(); !ok {
		t.Error("locking out a second factor also closed the account's primary door")
	}
	if len(secondFactorsOf(u)) != 0 {
		t.Error("a locked-out authenticator is still offered as a second factor")
	}
}

// Failing again after a lockout records nothing more.
//
// Without this the account stream grows one AuthenticatorDisabled per subsequent
// attempt against a credential that is already disabled — an unbounded write
// driven by whoever is still guessing.
func TestFailingAgainstADisabledAuthenticatorRecordsNothing(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	u.ClearUncommitted()

	if _, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at); err != nil {
		t.Fatalf("recording a lockout: %v", err)
	}
	locked, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold+1, at)
	mustNil(t, err)
	if locked {
		t.Error("an already-disabled authenticator reported a second lockout")
	}
	if got := countEvents[*contract.AuthenticatorDisabled](u); got != 1 {
		t.Errorf("recorded %d lockouts for one lockout, want 1", got)
	}
}

// An unproven enrolment cannot be locked out, because it was never usable.
func TestAnUnprovenAuthenticatorIsNotLockedOut(t *testing.T) {
	u := registered(t)
	mustNil(t, u.VerifyEmail("idx_1", at))
	pending := newID[ids.Credential](t)
	mustNil(t, u.StartTotpEnrollment(pending, at.Add(time.Hour), at))
	u.ClearUncommitted()

	locked, err := u.RecordAuthenticatorFailure(pending, domain.LockoutThreshold, at)
	mustNil(t, err)
	if locked || countEvents[*contract.AuthenticatorDisabled](u) != 0 {
		t.Error("a provisioned but unproven enrolment was locked out")
	}
}

// A suspended account can still lock out an authenticator.
//
// mutable() refuses a suspended account every change, and a lockout deliberately
// does not go through it: a lockout only ever REMOVES a capability, so refusing it
// here would leave a grindable authenticator alive on the account most likely to
// be under attack.
func TestALockoutIsNotBlockedByAccountState(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	mustNil(t, u.Suspend("op_1", "abuse", at))
	u.ClearUncommitted()

	locked, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at)
	mustNil(t, err)
	if !locked {
		t.Fatal("a suspended account refused to lock out an authenticator being ground")
	}
}

// A credential the account's own log does not have is refused, not invented.
func TestALockoutRefusesAnUnknownCredential(t *testing.T) {
	u := active(t)
	u.ClearUncommitted()

	for _, tc := range []struct {
		name string
		cred ids.CredentialID
		want errs.Reason
	}{
		{"a credential from another account", newID[ids.Credential](t), errs.NotFound},
		{"no credential at all", ids.CredentialID{}, errs.ValidationFailed},
	} {
		t.Run(tc.name, func(t *testing.T) {
			locked, err := u.RecordAuthenticatorFailure(tc.cred, domain.LockoutThreshold, at)
			if err == nil {
				t.Fatal("the failure was accepted against a credential this account does not have")
			}
			if errs.ReasonOf(err) != tc.want {
				t.Errorf("reason is %s, want %s", errs.ReasonOf(err), tc.want)
			}
			if locked {
				t.Error("an unknown credential reported a lockout")
			}
		})
	}
	if got := countEvents[*contract.AuthenticatorDisabled](u); got != 0 {
		t.Errorf("recorded %d lockouts, want 0", got)
	}
}

// A nonexistent account records nothing.
func TestALockoutAgainstNoAccountIsRefused(t *testing.T) {
	u := eventsourcing.NewAggregate(domain.New)

	_, err := u.RecordAuthenticatorFailure(newID[ids.Credential](t), domain.LockoutThreshold, at)
	if err == nil || errs.ReasonOf(err) != errs.NotFound {
		t.Fatalf("a lockout against no account returned %v, want a not-found", err)
	}
	if len(u.Uncommitted()) != 0 {
		t.Error("a lockout against no account recorded an event")
	}
}

// A lockout survives a rebuild: it is applied from the event, not held in memory.
func TestALockoutIsRebuiltFromItsEvent(t *testing.T) {
	u := active(t)
	totp := totpCredential(t, u)
	if _, err := u.RecordAuthenticatorFailure(totp, domain.LockoutThreshold, at); err != nil {
		t.Fatalf("recording a lockout: %v", err)
	}

	rebuilt := eventsourcing.NewAggregate(domain.New)
	for _, e := range u.Uncommitted() {
		rebuilt.Apply(e)
	}
	m, ok := rebuilt.Method(totp)
	if !ok {
		t.Fatal("the rebuilt account has no such method")
	}
	if m.Usable() {
		t.Error("a rebuilt account considers a locked-out authenticator usable; the lockout " +
			"would then last only until the next process restart")
	}
}

// ---------------------------------------------------------------------------
// Password rehash
// ---------------------------------------------------------------------------

// A rehash is recorded against the password credential and nothing else changes.
func TestARehashIsRecordedAndChangesNoState(t *testing.T) {
	u := active(t)
	password := passwordCredential(t, u)
	u.ClearUncommitted()

	mustNil(t, u.RecordPasswordRehash(password, at))
	pending := u.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("recorded %d events, want 1", len(pending))
	}
	rehashed, ok := pending[0].(*contract.PasswordRehashed)
	if !ok {
		t.Fatalf("recorded %T, want *contract.PasswordRehashed", pending[0])
	}
	if rehashed.CredentialID != password.String() || rehashed.SubjectID != "subj_1" {
		t.Errorf("the event is %+v", rehashed)
	}
	if !rehashed.RehashedAt.Equal(at.UTC()) || rehashed.RehashedAt.Location() != time.UTC {
		t.Errorf("the event is stamped %s, want %s in UTC", rehashed.RehashedAt, at.UTC())
	}

	// Applying it must leave the credential exactly as it was. A rehashed verifier
	// is the same credential under a new encoding, so any state change here would
	// be a rebuild diverging from the live aggregate.
	u.Apply(rehashed)
	m, ok := u.Method(password)
	if !ok || !m.Usable() {
		t.Error("applying a rehash changed the credential's usability")
	}
	if reason, ok := u.CanAuthenticate(); !ok {
		t.Errorf("applying a rehash made the account unauthenticable (%q)", reason)
	}
}

// A rehash may only name a usable password on THIS account.
func TestARehashRefusesACredentialThatIsNotAUsablePasswordHere(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*testing.T, *domain.User) ids.CredentialID
		want    errs.Reason
	}{
		{
			name: "a credential from another account",
			arrange: func(t *testing.T, _ *domain.User) ids.CredentialID {
				return newID[ids.Credential](t)
			},
			want: errs.NotFound,
		},
		{
			name: "the account's own second factor",
			arrange: func(t *testing.T, u *domain.User) ids.CredentialID {
				return totpCredential(t, u)
			},
			want: errs.NotFound,
		},
		{
			name: "a suspended account",
			arrange: func(t *testing.T, u *domain.User) ids.CredentialID {
				cred := passwordCredential(t, u)
				mustNil(t, u.Suspend("op_1", "abuse", at))
				u.ClearUncommitted()
				return cred
			},
			want: errs.AccessDenied,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			u := active(t)
			u.ClearUncommitted()
			cred := tc.arrange(t, u)

			err := u.RecordPasswordRehash(cred, at)
			if err == nil {
				t.Fatal("the rehash was recorded")
			}
			if errs.ReasonOf(err) != tc.want {
				t.Errorf("reason is %s, want %s", errs.ReasonOf(err), tc.want)
			}
			if got := countEvents[*contract.PasswordRehashed](u); got != 0 {
				t.Errorf("recorded %d rehash events, want 0", got)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

// secondFactorsOf lists the usable second factors, recovery codes included.
func secondFactorsOf(u *domain.User) []domain.Method {
	var out []domain.Method
	for _, m := range u.UsableMethods() {
		if domain.RoleOf(m.Kind) == domain.RoleSecondFactor {
			out = append(out, m)
		}
	}
	return out
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// passwordCredential finds the account's usable password credential id.
func passwordCredential(t *testing.T, u *domain.User) ids.CredentialID {
	t.Helper()
	for _, m := range u.UsableMethods() {
		if m.Kind == contract.MethodPassword {
			return m.ID
		}
	}
	t.Fatal("the account has no usable password method")
	return ids.CredentialID{}
}

// active returns a fully enrolled, active account: verified, password, TOTP.
func active(t *testing.T) *domain.User {
	t.Helper()
	u := registered(t)
	mustNil(t, u.VerifyEmail("idx_1", at))
	mustNil(t, u.SetPassword(newID[ids.Credential](t), at))
	totp := newID[ids.Credential](t)
	mustNil(t, u.StartTotpEnrollment(totp, at.Add(time.Hour), at))
	mustNil(t, u.EnableTotp(totp, at))
	if u.State() != domain.StateActive {
		t.Fatalf("helper produced a %s account, not an active one", u.State())
	}
	return u
}

// totpCredential finds the account's TOTP credential id.
func totpCredential(t *testing.T, u *domain.User) ids.CredentialID {
	t.Helper()
	for _, m := range u.UsableMethods() {
		if m.Kind == contract.MethodTOTP {
			return m.ID
		}
	}
	t.Fatal("the account has no usable TOTP method")
	return ids.CredentialID{}
}

func countEvents[T eventsourcing.Event](u *domain.User) int {
	var n int
	for _, e := range u.Uncommitted() {
		if _, ok := e.(T); ok {
			n++
		}
	}
	return n
}

func mustNil(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
}

// ---------------------------------------------------------------------------
// The public handle
// ---------------------------------------------------------------------------

// A handle may not be claimed before the address it belongs to is proven.
//
// This is the aggregate's half of the squatting defence, and it is written under
// the same rule SetPassword is: the use case is one call site, the aggregate is
// the boundary, and a second route to a first handle — an import, an admin tool,
// a future federated link — inherits the rule by construction rather than by
// somebody remembering it.
//
// Why it matters more here than for an address. An unverified ADDRESS claim
// lapses after 48 hours, so squatting one is a bounded denial of service. A
// handle is claimed PERMANENTLY and, once tombstoned, can never be reissued even
// in principle — so a handle claimed by whoever typed an address they do not
// control is gone for good.
func TestAUsernameMayNotBeClaimedBeforeTheAddressIsProven(t *testing.T) {
	t.Parallel()
	u := registered(t)

	err := u.AssignUsername("ada_lovelace", at)
	if errs.ReasonOf(err) != errs.Conflict {
		t.Fatalf("reason %s, want %s (%v)", errs.ReasonOf(err), errs.Conflict, err)
	}
	if n := countEvents[*contract.UsernameAssigned](u); n != 0 {
		t.Errorf("%d handles recorded on an unproven account", n)
	}
	if got := u.Username(); got != "" {
		t.Errorf("the account reports handle %q", got)
	}
}

// TestAssignUsername covers the rules that apply once the address IS proven.
func TestAssignUsername(t *testing.T) {
	t.Parallel()

	verified := func(t *testing.T) *domain.User {
		t.Helper()
		u := registered(t)
		mustNil(t, u.VerifyEmail("idx_1", at))
		return u
	}

	t.Run("a proven account claims its handle", func(t *testing.T) {
		t.Parallel()
		u := verified(t)
		mustNil(t, u.AssignUsername("ada_lovelace", at))
		if got := u.Username(); got != "ada_lovelace" {
			t.Fatalf("handle %q, want ada_lovelace", got)
		}
		if n := countEvents[*contract.UsernameAssigned](u); n != 1 {
			t.Errorf("%d UsernameAssigned events, want 1", n)
		}
	})

	t.Run("re-assigning the same handle records nothing", func(t *testing.T) {
		t.Parallel()
		u := verified(t)
		mustNil(t, u.AssignUsername("ada_lovelace", at))
		mustNil(t, u.AssignUsername("ada_lovelace", at))
		if n := countEvents[*contract.UsernameAssigned](u); n != 1 {
			t.Errorf("%d UsernameAssigned events for one handle, want 1 — a link "+
				"followed twice must not append a second assignment", n)
		}
	})

	t.Run("a second, different handle is refused", func(t *testing.T) {
		t.Parallel()
		u := verified(t)
		mustNil(t, u.AssignUsername("ada_lovelace", at))

		err := u.AssignUsername("grace_hopper", at)
		if errs.ReasonOf(err) != errs.Conflict {
			t.Fatalf("reason %s, want %s (%v)", errs.ReasonOf(err), errs.Conflict, err)
		}
		// There is no username-change flow, and a change is not merely
		// unimplemented: releasing a handle back into circulation is the failure
		// ADR-051's tombstone exists to prevent. A second assignment recorded here
		// would strand the FIRST handle claimed on its own stream by an account
		// that no longer answers to it, with nothing able to reconcile the two.
		if got := u.Username(); got != "ada_lovelace" {
			t.Errorf("handle %q, want the original ada_lovelace", got)
		}
	})

	t.Run("an empty handle is refused", func(t *testing.T) {
		t.Parallel()
		u := verified(t)
		if got := errs.ReasonOf(u.AssignUsername("", at)); got != errs.ValidationFailed {
			t.Fatalf("reason %s, want %s", got, errs.ValidationFailed)
		}
	})

	t.Run("a suspended account may not claim one", func(t *testing.T) {
		t.Parallel()
		u := verified(t)
		mustNil(t, u.Suspend("op_1", "fraud", at))
		if got := errs.ReasonOf(u.AssignUsername("ada_lovelace", at)); got != errs.AccessDenied {
			t.Fatalf("reason %s, want %s", got, errs.AccessDenied)
		}
	})

	t.Run("replaying the assignment reproduces the handle", func(t *testing.T) {
		t.Parallel()
		live := verified(t)
		mustNil(t, live.AssignUsername("ada_lovelace", at))

		rebuilt := eventsourcing.NewAggregate(domain.New)
		for _, e := range live.Uncommitted() {
			rebuilt.Apply(e)
		}
		if live.Username() != rebuilt.Username() {
			t.Errorf("username: live %q, rebuilt %q", live.Username(), rebuilt.Username())
		}
		// The property the whole design rests on, stated for this field: erasure
		// tombstones the handle the AGGREGATE reports, so an Apply that disagreed
		// with the decide method would tombstone the wrong name — permanently, and
		// for somebody else.
		if rebuilt.Username() != "ada_lovelace" {
			t.Errorf("the rebuilt account reports handle %q", rebuilt.Username())
		}
	})
}
