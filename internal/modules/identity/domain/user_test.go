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

// ---------------------------------------------------------------------------
// Activation
// ---------------------------------------------------------------------------

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
		u := registered(t)
		mustNil(t, u.SetPassword(cred, at))
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
		{"verification last", func(t *testing.T, u *domain.User, pw, totp ids.CredentialID) {
			mustNil(t, u.SetPassword(pw, at))
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

	incomplete := registered(t)
	mustNil(t, incomplete.VerifyEmail("idx_1", at))

	deactivated := active(t)
	mustNil(t, deactivated.Deactivate("subj_1", at))

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
// Helpers
// ---------------------------------------------------------------------------

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
