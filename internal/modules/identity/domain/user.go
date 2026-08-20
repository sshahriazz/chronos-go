// Package domain holds identity's aggregates and invariants. It is PURE: no
// I/O, no clock, no crypto, no transport (CONVENTIONS §2).
//
// Purity is what makes the rules here testable without a running stack, and it
// is also what keeps them honest. A hash cannot be computed in this package, so
// no rule can accidentally come to depend on one; time is always a parameter, so
// "the token has expired" is a decision about an instant the caller supplied
// rather than about whichever moment the test happened to run.
package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// State is the account lifecycle (identity.md §1).
type State int

const (
	// StateNone is an account that does not exist. It is the zero value so that
	// a User nobody loaded cannot be mistaken for a usable one.
	StateNone State = iota

	// StatePending is registered but not yet usable. It can hold no session and
	// authenticate nothing. Two things must happen to leave it: the address must
	// be verified, and a second factor must be enrolled and proven.
	StatePending

	// StateActive is usable.
	StateActive

	// StateDeactivated is switched off by the holder, and reversible by them.
	StateDeactivated

	// StateSuspended is switched off administratively, and NOT reversible by the
	// holder. Kept distinct from Deactivated because they look identical from
	// outside and must never be confused inside — a suspended account that could
	// reactivate itself would make suspension decorative.
	StateSuspended
)

func (s State) String() string {
	switch s {
	case StatePending:
		return "pending"
	case StateActive:
		return "active"
	case StateDeactivated:
		return "deactivated"
	case StateSuspended:
		return "suspended"
	default:
		return "none"
	}
}

// User is the account aggregate. One stream per user.
//
// The consistency boundary is deliberately the ACCOUNT and not the credential:
// "at least one usable method remains" cannot be enforced if each method is its
// own aggregate, because two concurrent removals would each see the other's
// method still present and both would succeed.
type User struct {
	eventsourcing.Base

	id         ids.UserID
	subjectID  string
	emailIndex contract.EmailIndex

	state         State
	emailVerified bool

	// everSecondFactor records that this account has, at some point in its
	// history, held a PROVEN second factor. It is set by Apply and never cleared
	// by anything, which is the whole property: `methods` is a picture of the
	// account NOW — TotpDisabled deletes from it, a lockout makes an entry
	// unusable — and a rule that keyed off "has" rather than "has ever had" would
	// hand an attacker who knows the password a route back to the first-enrolment
	// exemption by removing the factor they cannot pass (policy.Enrolment).
	//
	// Monotone by construction rather than by care taken at each call site: no
	// case in Apply assigns false, so a rebuild from position zero reaches the
	// same answer as the live aggregate however the events are ordered, and a
	// future event that takes a factor away cannot flip it back without somebody
	// writing that line deliberately.
	everSecondFactor bool

	methods map[ids.CredentialID]Method

	// recoveryRemaining is the count of unused recovery codes. Held here rather
	// than read from a projection because "using the last one" is a decision,
	// and a decision made from an eventually-consistent read can be made twice.
	recoveryRemaining  int
	recoveryCredential ids.CredentialID
}

// New returns an empty User for the repository to rebuild into.
func New() *User { return &User{methods: make(map[ids.CredentialID]Method)} }

func (u *User) ID() ids.UserID                  { return u.id }
func (u *User) SubjectID() string               { return u.subjectID }
func (u *User) EmailIndex() contract.EmailIndex { return u.emailIndex }
func (u *User) State() State                    { return u.state }
func (u *User) EmailVerified() bool             { return u.emailVerified }
func (u *User) RecoveryCodesRemaining() int     { return u.recoveryRemaining }

// Method returns one enrolled method.
func (u *User) Method(id ids.CredentialID) (Method, bool) {
	m, ok := u.methods[id]
	return m, ok
}

// UsableMethods lists the methods that can take part in an authentication now,
// in no particular order.
func (u *User) UsableMethods() []Method {
	out := make([]Method, 0, len(u.methods))
	for _, m := range u.methods {
		if m.Usable() {
			out = append(out, m)
		}
	}
	return out
}

// StrongestUsablePrimary reports the strength of the best method the account
// can START an authentication with.
//
// PRIMARY only, and that restriction is the whole correctness of the rule. The
// obvious version — strongest of every usable method — compares a password
// against the account's TOTP, finds it weaker, and reports a downgrade on every
// ordinary password+TOTP login. The signal is then noise within a week, which is
// indistinguishable from not having the rule at all.
//
// A downgrade is a question about which DOOR was used. Second factors are not
// doors; they are what stands behind one.
func (u *User) StrongestUsablePrimary() Strength {
	best := StrengthUnknown
	for _, m := range u.methods {
		if m.Usable() && RoleOf(m.Kind) == RolePrimary {
			if s := StrengthOf(m.Kind); s > best {
				best = s
			}
		}
	}
	return best
}

func (u *User) hasUsable(role Role) bool {
	for _, m := range u.methods {
		if m.Usable() && RoleOf(m.Kind) == role {
			return true
		}
	}
	return false
}

// hasRealSecondFactor reports a usable second factor that is not a recovery
// code.
//
// The exclusion is the point. A recovery code set is a legitimate second factor
// for AUTHENTICATING — that is what it is for — but it must never be the one
// that satisfies the enrolment requirement, or "you must set up a second factor"
// is answered by printing a sheet of paper and the account is left one lost
// sheet away from having no second factor at all.
func (u *User) hasRealSecondFactor() bool { return u.countRealSecondFactors() > 0 }

// countRealSecondFactors counts usable second factors excluding recovery codes.
func (u *User) countRealSecondFactors() int {
	var n int
	for _, m := range u.methods {
		if m.Usable() && RoleOf(m.Kind) == RoleSecondFactor &&
			StrengthOf(m.Kind) > StrengthRecoveryCode {
			n++
		}
	}
	return n
}

// ---------------------------------------------------------------------------
// Apply — pure state transition, runs during rebuild
// ---------------------------------------------------------------------------

// Apply mutates state from an event and must never reject one: every event here
// is already a fact, and refusing one during rebuild makes the stream
// unloadable.
func (u *User) Apply(e eventsourcing.Event) {
	if u.methods == nil {
		// A repository may rebuild into a zero User rather than one from New.
		u.methods = make(map[ids.CredentialID]Method)
	}
	switch ev := e.(type) {
	case *contract.UserRegistered:
		u.id, _ = ids.Parse[ids.User](ev.UserID)
		u.subjectID = ev.SubjectID
		u.emailIndex = ev.EmailIndex
		u.state = StatePending

	case *contract.EmailVerified:
		u.emailVerified = true
		u.emailIndex = ev.Index

	case *contract.UserActivated:
		u.state = StateActive
		// Activation is only ever recorded once a real second factor is proven
		// (maybeActivate), so this is the same fact arriving a second way. It is
		// set here as well as on TotpEnabled so the property survives a stream
		// whose factor was proven by some event this build does not know about —
		// an older enrolment path, or a second-factor kind added later — rather
		// than depending on the list of enabling events staying exhaustive.
		u.everSecondFactor = true

	case *contract.UserDeactivated:
		u.state = StateDeactivated

	case *contract.UserReactivated:
		u.state = StateActive

	case *contract.UserSuspended:
		u.state = StateSuspended

	case *contract.PasswordSet:
		u.enable(ev.CredentialID, contract.MethodPassword, ev.SetAt)

	case *contract.TotpEnrollmentStarted:
		// Recorded as PENDING, not usable. This is the distinction the two-step
		// enrollment exists for.
		if id, err := ids.Parse[ids.Credential](ev.CredentialID); err == nil {
			u.methods[id] = Method{ID: id, Kind: contract.MethodTOTP}
		}

	case *contract.TotpEnabled:
		u.enable(ev.CredentialID, contract.MethodTOTP, ev.EnabledAt)
		// A code verified against a secret this account provisioned. That is the
		// moment a second factor becomes PROVEN, and it is recorded permanently:
		// TotpDisabled below removes the method and deliberately does not touch
		// this.
		u.everSecondFactor = true

	case *contract.TotpDisabled:
		if id, err := ids.Parse[ids.Credential](ev.CredentialID); err == nil {
			delete(u.methods, id)
		}

	case *contract.AuthenticatorDisabled:
		if id, err := ids.Parse[ids.Credential](ev.CredentialID); err == nil {
			if m, ok := u.methods[id]; ok {
				m.DisabledAt = ev.DisabledAt
				u.methods[id] = m
			}
		}

	case *contract.RecoveryCodesGenerated:
		u.enable(ev.CredentialID, contract.MethodRecoveryCode, ev.GeneratedAt)
		u.recoveryRemaining = ev.Count
		u.recoveryCredential, _ = ids.Parse[ids.Credential](ev.CredentialID)

	case *contract.RecoveryCodeConsumed:
		// Taken from the event rather than decremented locally: the event is the
		// authority, and a local decrement would drift if one were ever replayed
		// out of order during a partial rebuild.
		u.recoveryRemaining = ev.Remaining

	case *contract.RecoveryCodesExhausted:
		u.recoveryRemaining = 0
		if id, err := ids.Parse[ids.Credential](ev.CredentialID); err == nil {
			delete(u.methods, id)
		}
	}
}

func (u *User) enable(credentialID string, kind contract.MethodKind, at time.Time) {
	id, err := ids.Parse[ids.Credential](credentialID)
	if err != nil {
		return
	}
	m := u.methods[id]
	m.ID = id
	m.Kind = kind
	m.EnabledAt = at
	m.DisabledAt = time.Time{}
	u.methods[id] = m
}

// ---------------------------------------------------------------------------
// Decisions
// ---------------------------------------------------------------------------

// Register creates the account, in Pending.
//
// It takes the already-derived EmailIndex rather than the address itself. The
// domain never sees an email: it cannot compute the index (that needs a key it
// must not hold) and it has nothing to do with one it could read.
func (u *User) Register(
	id ids.UserID, subjectID string, index contract.EmailIndex, at time.Time,
) error {
	if u.state != StateNone {
		return errs.Conflictf("this account already exists")
	}
	switch {
	case id.IsZero():
		return errs.ValidationFailedf("a user id is required")
	case subjectID == "":
		return errs.ValidationFailedf("a subject id is required")
	case index == "":
		return errs.ValidationFailedf("an email index is required")
	}
	eventsourcing.Record(u, &contract.UserRegistered{
		UserID:       id.String(),
		SubjectID:    subjectID,
		EmailIndex:   index,
		RegisteredAt: at.UTC(),
	})
	return nil
}

// VerifyEmail proves control of the address.
//
// Idempotent by design: a user who clicks the link twice, or whose mail client
// prefetches it, must not get an error page for having succeeded. The second
// call records nothing.
func (u *User) VerifyEmail(index contract.EmailIndex, at time.Time) error {
	if u.state == StateNone {
		return errs.NotFoundf("no such account")
	}
	if u.emailVerified && u.emailIndex == index {
		return nil
	}
	if index == "" {
		return errs.ValidationFailedf("an email index is required")
	}
	eventsourcing.Record(u, &contract.EmailVerified{
		SubjectID:  u.subjectID,
		Index:      index,
		VerifiedAt: at.UTC(),
	})
	u.maybeActivate(at)
	return nil
}

// SetPassword enrolls the account's first password.
//
// # The address must be PROVEN first, and that ordering is a security control
//
// This is the aggregate's half of the pre-hijacking defence (Sudhodanan &
// Paverd, USENIX Security 2022; IDENTITY-REVIEW C8). The attack is: a stranger
// registers somebody else's address with a password of their own, the mailbox
// owner receives a genuine-looking verification mail and follows it, and that
// click — which proves control of the MAILBOX and nothing else — activates the
// stranger's credential. The stranger then signs in.
//
// The premise is a credential that exists BEFORE the proof. Refusing to record
// one on an unverified account removes the premise rather than mitigating its
// consequences: there is no attacker-set password for the victim's proof to
// switch on, because a password can only be recorded in the same breath as the
// proof itself (Registration.VerifyEmail records EmailVerified first, then
// this).
//
// It is stated HERE, in the aggregate, rather than only in the use case,
// because the use case is one call site and the aggregate is the boundary. A
// second path to a first password — an admin tool, a migration, a future
// federated link — inherits the rule by construction instead of having to
// remember it.
func (u *User) SetPassword(credentialID ids.CredentialID, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if !u.emailVerified {
		return errs.Conflictf(
			"this account has not proven its address; a password may not be set before verification")
	}
	if credentialID.IsZero() {
		return errs.ValidationFailedf("a credential id is required")
	}
	for _, m := range u.methods {
		if m.Kind == contract.MethodPassword && m.Usable() {
			return errs.Conflictf("this account already has a password; change it instead")
		}
	}
	eventsourcing.Record(u, &contract.PasswordSet{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		SetAt:        at.UTC(),
	})
	u.maybeActivate(at)
	return nil
}

// ChangePassword replaces an existing one.
//
// viaReset carries into the event because it decides what else happens: a reset
// invalidates every session, a change made by someone who knew the current
// password does not have to.
func (u *User) ChangePassword(credentialID ids.CredentialID, viaReset bool, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodPassword {
		return errs.NotFoundf("no such password credential")
	}
	eventsourcing.Record(u, &contract.PasswordChanged{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		ViaReset:     viaReset,
		ChangedAt:    at.UTC(),
	})
	return nil
}

// UsablePasswordCredential names the password this account can authenticate
// with, if it has one.
//
// USABLE, not merely enrolled, and the distinction is what makes this safe to
// drive a password reset from. A credential that was never enabled belongs to a
// half-finished enrolment, and one that was disabled belongs to an authenticator
// this account has locked out; writing a fresh verifier onto either produces a
// row that looks maintained and that nothing will ever accept, with the reset
// reported to the user as done.
//
// It exists as a method on the aggregate rather than as a lookup in the
// credential table because the LOG is the authority on which methods an account
// has (identity.md §4.2): a row the log does not account for was written outside
// the application, and a reset that took its target from the table would happily
// rewrite it.
func (u *User) UsablePasswordCredential() (ids.CredentialID, bool) {
	for id, m := range u.methods {
		if m.Kind == contract.MethodPassword && m.Usable() {
			return id, true
		}
	}
	return ids.CredentialID{}, false
}

// HasUsablePassword reports whether a password reset could do anything for this
// account.
//
// A passwordless account is a first-class state here (identity.md §4, §5, §7),
// and the way into one is the verification link, never a reset: VerifyEmail is
// the only call that can give an account its first password, and
// domain.User.SetPassword refuses one on an unproven address. So a reset link
// mailed to a passwordless account would lead to a page that cannot succeed.
func (u *User) HasUsablePassword() bool {
	_, ok := u.UsablePasswordCredential()
	return ok
}

// VoidPendingIdentifierChange cancels an identifier change this account has
// started but not completed.
//
// # What it does today, stated plainly: nothing
//
// There is no email-change flow in this module — no RPC, no use case, no event —
// so no account can be holding a pending change and there is nothing here to
// record. The method is written anyway, and it is called by the password reset
// on every run, for exactly the reason Registration.VerifyEmail calls
// RevokeAllSessions on a subject that provably has none:
//
//	the rule is free while it is a no-op and expensive to retrofit once it is not.
//
// # The rule it carries
//
// identity.md §4.4 and §4.5, from Sudhodanan & Paverd (USENIX Security 2022).
// The "unexpired email change" variant is an attacker queueing a change to an
// address they control and letting the victim's own recovery survive it: the
// victim resets their password, believes they have taken the account back, and
// the pending change completes minutes later and hands it straight back. Voiding
// the change is what closes it, and it has to happen in the same command as the
// reset — a reactor on PasswordChanged would leave a window, and the window is
// the attack.
//
// # Where the enforcement actually lives today
//
// Not here, and saying so is the point of this comment. A pending change cannot
// be COMPLETED without the live email-verification token that was mailed for it,
// and the reset voids every outstanding token of every purpose for the subject
// (app.TokenStore.RevokeAllPurposes). That is the half of the rule that is real
// today. This method is the half that will matter the moment a pending change
// becomes a fact the AGGREGATE holds rather than only a token in a table — and
// when it does, the recording goes here and every existing caller inherits it
// without being changed.
//
// It returns an error rather than nothing so that the day it can refuse — an
// account suspended mid-flight, a change already completed — the callers already
// handle the refusal instead of acquiring a new error path.
func (u *User) VoidPendingIdentifierChange(at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	// No branch, and no `if u.pendingIndex != ""`: the aggregate has no such
	// field, because no event can set one. Adding a field for a state nothing
	// produces would be a state nothing can test.
	_ = at
	return nil
}

// StartTotpEnrollment provisions a secret that is not yet proven.
func (u *User) StartTotpEnrollment(
	credentialID ids.CredentialID, expiresAt, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if credentialID.IsZero() {
		return errs.ValidationFailedf("a credential id is required")
	}
	for _, m := range u.methods {
		if m.Kind == contract.MethodTOTP && m.Usable() {
			return errs.Conflictf("this account already has an authenticator app enrolled")
		}
	}
	if !expiresAt.After(at) {
		return errs.ValidationFailedf("an enrollment must expire in the future")
	}
	eventsourcing.Record(u, &contract.TotpEnrollmentStarted{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		ExpiresAt:    expiresAt.UTC(),
		StartedAt:    at.UTC(),
	})
	return nil
}

// EnableTotp completes enrollment, after a live code has verified.
//
// The code is checked by the caller — verifying one needs the secret, which
// lives in the vault, which this package cannot reach. What is enforced HERE is
// that a code was checked against a secret this account actually provisioned:
// an unknown credential id is refused rather than enrolled.
func (u *User) EnableTotp(credentialID ids.CredentialID, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodTOTP {
		return errs.NotFoundf("no such enrollment")
	}
	if m.Usable() {
		return nil // already enabled; a retried confirmation is not an error
	}
	eventsourcing.Record(u, &contract.TotpEnabled{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		EnabledAt:    at.UTC(),
	})
	u.maybeActivate(at)
	return nil
}

// DisableTotp removes the authenticator.
//
// This is where AtLeastOneUsableMethod bites hardest. An active account must
// keep a second factor, so removing the only one is refused — with a named
// error the client can act on, never a silent success that leaves the account
// weaker than its own policy allows.
func (u *User) DisableTotp(credentialID ids.CredentialID, actorID string, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodTOTP {
		return errs.NotFoundf("no such authenticator")
	}
	// countRealSecondFactors, not countUsable(RoleSecondFactor): the latter
	// counts the recovery-code set, so an account with TOTP plus recovery codes
	// would pass the check and end up with the code sheet as its only second
	// factor — the same hole maybeActivate closes on the way in.
	if u.state == StateActive && m.Usable() && u.countRealSecondFactors() <= 1 {
		return errs.Conflictf(
			"removing this would leave the account with no second factor; enrol another first")
	}
	eventsourcing.Record(u, &contract.TotpDisabled{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		ActorID:      actorID,
		DisabledAt:   at.UTC(),
	})
	return nil
}

// GenerateRecoveryCodes replaces the whole set.
func (u *User) GenerateRecoveryCodes(
	credentialID ids.CredentialID, count int, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if count <= 0 {
		return errs.ValidationFailedf("a recovery code set must contain at least one code")
	}
	if credentialID.IsZero() {
		return errs.ValidationFailedf("a credential id is required")
	}
	eventsourcing.Record(u, &contract.RecoveryCodesGenerated{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		Count:        count,
		GeneratedAt:  at.UTC(),
	})
	return nil
}

// ConsumeRecoveryCode burns one.
//
// The code itself is matched by the caller against digests in the read model;
// what this enforces is that there was one left to burn. Exhaustion is recorded
// as its own event so a reactor can force the re-issue interstitial without
// having to distinguish "Remaining hit zero" from "a regenerate happened".
func (u *User) ConsumeRecoveryCode(at time.Time) error {
	if u.state != StateActive {
		return errs.Unauthenticatedf("this account cannot authenticate")
	}
	if u.recoveryRemaining <= 0 {
		return errs.Conflictf("no recovery codes remain")
	}
	remaining := u.recoveryRemaining - 1
	eventsourcing.Record(u, &contract.RecoveryCodeConsumed{
		SubjectID:    u.subjectID,
		CredentialID: u.recoveryCredential.String(),
		Remaining:    remaining,
		ConsumedAt:   at.UTC(),
	})
	if remaining == 0 {
		eventsourcing.Record(u, &contract.RecoveryCodesExhausted{
			SubjectID:    u.subjectID,
			CredentialID: u.recoveryCredential.String(),
			ExhaustedAt:  at.UTC(),
		})
	}
	return nil
}

// Deactivate switches the account off at the holder's request.
func (u *User) Deactivate(actorID string, at time.Time) error {
	switch u.state {
	case StateActive, StatePending:
	case StateDeactivated:
		return nil
	default:
		return errs.Conflictf("a %s account cannot be deactivated", u.state)
	}
	eventsourcing.Record(u, &contract.UserDeactivated{
		SubjectID:     u.subjectID,
		ActorID:       actorID,
		DeactivatedAt: at.UTC(),
	})
	return nil
}

// Reactivate restores a deactivated account.
//
// Explicitly NOT reachable from Suspended. That is the entire difference between
// the two states, and it is enforced here rather than at the API, because an
// administrative suspension a user can undo is not a suspension.
func (u *User) Reactivate(actorID string, at time.Time) error {
	if u.state == StateSuspended {
		return errs.AccessDeniedf("this account is suspended and cannot be reactivated by its holder")
	}
	if u.state != StateDeactivated {
		return errs.Conflictf("this account is not deactivated")
	}
	eventsourcing.Record(u, &contract.UserReactivated{
		SubjectID:     u.subjectID,
		ActorID:       actorID,
		ReactivatedAt: at.UTC(),
	})
	return nil
}

// Suspend switches the account off administratively.
func (u *User) Suspend(actorID, reason string, at time.Time) error {
	if u.state == StateNone {
		return errs.NotFoundf("no such account")
	}
	if u.state == StateSuspended {
		return nil
	}
	eventsourcing.Record(u, &contract.UserSuspended{
		SubjectID:   u.subjectID,
		ActorID:     actorID,
		Reason:      reason,
		SuspendedAt: at.UTC(),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// HasEverHadSecondFactor reports whether this account has, at any point, held a
// proven second factor.
//
// One-way: nothing in this aggregate sets it back to false. Removing a factor,
// losing one to a lockout, deactivating and suspending all leave it true, and a
// rebuild recomputes the same answer from the log. That is what makes it safe to
// key an exemption off — see NeedsFirstSecondFactor.
func (u *User) HasEverHadSecondFactor() bool { return u.everSecondFactor }

// NeedsFirstSecondFactor reports that this account is in the ONE state a
// password-only authentication may be honoured in: registered, address proven,
// and no second factor ever held.
//
// # Why the state exists at all
//
// A second factor is mandatory before an account activates (identity.md §2), and
// enrolling one requires a session, and a session requires the factor. Read
// literally that is a deadlock and no account registered through the public API
// could ever become Active. The way out is a session whose AUTHORITY is bounded
// rather than a rule that is quietly dropped: this predicate admits a
// password-only authentication, the resulting session records AAL1 honestly, and
// what AAL1 can reach is decided by the declared policy — only EnrollTotp and
// ConfirmTotp carry a bootstrap assurance floor, and every other method still
// compares against its ordinary min_aal (policy.Policy.AALFloor).
//
// # Why each conjunct is here
//
//   - Pending only. An Active, Deactivated or Suspended account is not enrolling
//     its first factor; the first has one, and the other two may not authenticate
//     at all.
//   - The address must be VERIFIED. Without it, anyone who registers an address
//     they do not control holds a session on it, which turns registration itself
//     into an account-takeover primitive against a person who has not signed up
//     yet.
//   - Never held a factor, and does not hold one now. The first is the property
//     that closes "remove the factor, then enrol my own"; the second is a
//     belt-and-braces reading of the same state that costs nothing and does not
//     depend on the history flag having been maintained correctly.
//
// It says nothing about a PRIMARY factor, because the caller has to have passed
// one to be asking: the login path reaches this only after a password verified.
func (u *User) NeedsFirstSecondFactor() bool {
	return u.state == StatePending &&
		u.emailVerified &&
		!u.everSecondFactor &&
		!u.hasRealSecondFactor()
}

// CanAuthenticate reports why an authentication may not proceed, before any
// credential is examined.
//
// The reason returned here is for the LOG, not for the caller. Every one of
// these produces the same undifferentiated refusal on the wire: telling an
// attacker that the account exists but is unverified is an account-existence
// oracle, and telling them it is suspended is worse (identity.md §7).
//
// # The one Pending account that may authenticate
//
// A Pending account whose address is proven and which has never held a second
// factor is admitted, because it has to be: it is the state every new account
// passes through, and the session it earns is what carries the first enrolment
// (NeedsFirstSecondFactor). Every other Pending account is still refused with
// ReasonIncomplete, which is what that reason continues to mean — an account
// that is unfinished in a way authenticating cannot fix. The unverified,
// deactivated and suspended refusals are untouched.
//
// Note what admitting it does NOT decide. This says the ceremony may proceed; it
// does not say what the resulting session may do. The assurance level such a
// login reaches is AAL1 (domain.AALFor over a password alone), and the gate
// compares that against each method's declared floor.
func (u *User) CanAuthenticate() (contract.FailureReason, bool) {
	switch u.state {
	case StateNone:
		return contract.ReasonNoSuchIdentifier, false
	case StatePending:
		if !u.emailVerified {
			return contract.ReasonUnverifiedEmail, false
		}
		if u.NeedsFirstSecondFactor() {
			return "", true
		}
		return contract.ReasonIncomplete, false
	case StateDeactivated:
		return contract.ReasonDeactivated, false
	case StateSuspended:
		return contract.ReasonSuspended, false
	}
	if !u.hasUsable(RolePrimary) {
		// Every primary method locked out. Not an authentication failure — there
		// is nothing left to fail against.
		return contract.ReasonIncomplete, false
	}
	return "", true
}

// IsDowngrade reports whether authenticating with these methods would use
// something weaker than the account's strongest available method.
//
// It answers a question; it does not refuse. A downgrade is permitted when the
// user has deliberately elected the fallback — they may genuinely have lost the
// passkey — but it is rate-limited, notified and recorded as a risk signal
// (identity.md §2). Silently allowing it is what lets an attacker who cannot
// beat a passkey simply ask for the password form instead.
func (u *User) IsDowngrade(used []contract.MethodKind) bool {
	best := u.StrongestUsablePrimary()
	if best == StrengthUnknown {
		return false
	}
	for _, k := range used {
		if RoleOf(k) == RolePrimary && StrengthOf(k) < best {
			return true
		}
	}
	return false
}

// LockoutThreshold is how many CONSECUTIVE failures against ONE authenticator
// disable it.
//
// # What is being counted
//
// The signal is `credential.failures`, which is incremented on every failed
// presentation and set to zero by any success (TouchCredential). It is therefore
// a consecutive count and not a lifetime one, which is what makes a threshold
// safe to state as an absolute number: a person who fumbles a code and then gets
// one right is back at zero, so reaching ten means ten in a row with no working
// presentation in between.
//
// # Why there is no time window
//
// A window — "ten failures in an hour" — is the textbook shape and this table
// cannot express it: there is no per-failure timestamp, only a counter and a
// `last_used_at` that moves on SUCCESS. Adding one is a migration, and it would
// buy less here than it looks. A window exists to stop a legitimate user's
// scattered mistakes from accumulating into a lockout over months; a
// consecutive-since-last-success counter already does that for anyone whose
// authenticator works, because using it successfully clears it. The residual case
// is a user who fails ten times in a row over a long period and never once
// succeeds — and an authenticator that has not produced a working code in ten
// consecutive tries is already broken from that user's point of view. The
// recovery they need is the same one the lockout sends them to.
//
// # Why ten
//
// The search space this is defending is a six-digit TOTP code with a small
// acceptance window: on the order of 10^6 candidates, of which a handful verify
// at any instant. Ten consecutive guesses is a chance in the region of 10^-5 of
// landing one before the authenticator is taken away, and it is more fumbles in a
// row than a working authenticator produces. Lower would start locking real
// people out during a clock-skew episode; much higher starts to matter against an
// attacker who already holds the password and is grinding the second factor
// slowly enough to stay under the attempt ceiling — which is precisely the attack
// this layer exists for, since that ceiling FAILS OPEN (ratelimit.Limiter.Allow)
// and can therefore be absent without anything refusing.
const LockoutThreshold = 10

// RecordAuthenticatorFailure counts one failed presentation against one
// authenticator and disables it once the ceiling is crossed.
//
// failures is the NEW total reported by the store's own increment, not a value
// this aggregate maintains: the count is per credential and lives in the one
// identity table that is not rebuildable from the log (identity.md §4), so the
// aggregate is the authority on the RULE and the row is the authority on the
// COUNT. Reading it back separately would be a second transaction's view, and two
// concurrent failures could then both observe a pre-increment total and neither
// would see the ceiling crossed — which is exactly the concurrency an online
// guessing attack produces.
//
// # A PRIMARY method is never disabled here, and that is the whole safety case
//
// Anyone who knows an address can produce failures against that account's
// password: the identifier is the address, and reaching the password check needs
// no secret at all. So a lockout that could disable a password would let an
// attacker lock any account they can name, and therefore every account they can
// enumerate — a denial of service that is cheaper to mount than the online
// guessing attack the lockout is defending against, and one whose damage is
// permanent rather than bounded (the recovery is a password reset per victim).
// That trade is refused outright rather than tuned, which is why the rule is
// expressed as a property of the method's ROLE rather than as a threshold that
// could be raised until the DoS "stopped mattering".
//
// A second factor is different in the one way that decides this: reaching it
// requires having already passed a primary factor. An attacker can only grind an
// authenticator on an account whose password they already hold, so the lockout
// cannot be aimed at a stranger, and the person it inconveniences is one an
// attacker is already most of the way to compromising. Locking it is the safer
// side of that trade, because the alternative is letting the grind continue until
// a six-digit code eventually verifies.
//
// The same rule is what keeps a lockout from stranding an account: refusing to
// disable a primary method means hasUsable(RolePrimary) — the condition
// CanAuthenticate checks last — cannot be falsified by this path at all. An
// account cannot be locked into a state where it has no way to start an
// authentication, because the only methods this removes are ones that could never
// have started one.
//
// # Recovery is by rebinding, not by waiting
//
// There is no expiry on the lockout and no unlock timer, which is the decision
// Method.DisabledAt and contract.AuthenticatorDisabled already record. A timer is
// something the attacker waits out as easily as the user does: a grind that
// resumes every fifteen minutes forever is slower than an unthrottled one and is
// otherwise the same attack. The user re-enrols the authenticator through the
// second-factor flow, which is a ceremony that proves possession again.
//
// Returns true when this call disabled the authenticator. Every other outcome is
// (false, nil) — below the threshold, already disabled, or a primary method —
// because none of them is an error the login path could act on differently.
func (u *User) RecordAuthenticatorFailure(
	credentialID ids.CredentialID, failures int, at time.Time,
) (bool, error) {
	if u.state == StateNone {
		return false, errs.NotFoundf("no such account")
	}
	if credentialID.IsZero() {
		return false, errs.ValidationFailedf("a credential id is required")
	}
	// Deliberately NOT gated on mutable(): a lockout only ever REMOVES a
	// capability, so refusing it for a suspended account would keep a grindable
	// authenticator alive on the account most likely to be under attack. Only a
	// nonexistent account is refused, because there is nothing to record against.
	m, ok := u.methods[credentialID]
	if !ok {
		// The credential store named a method this account's own log does not
		// have. Reported rather than ignored: it means the row and the stream
		// disagree, which is the tampering the AAD binding makes expensive rather
		// than impossible.
		return false, errs.NotFoundf("no such authenticator")
	}
	if !m.Usable() {
		// Already disabled, or never proven. Not an error — the caller wants the
		// authenticator unusable and it is — and recording a second
		// AuthenticatorDisabled would put a second lockout in the log for one
		// lockout that happened.
		return false, nil
	}
	if RoleOf(m.Kind) == RolePrimary {
		return false, nil
	}
	if failures < LockoutThreshold {
		return false, nil
	}
	eventsourcing.Record(u, &contract.AuthenticatorDisabled{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		Failures:     failures,
		DisabledAt:   at.UTC(),
	})
	return true, nil
}

// RecordPasswordRehash records that a stored verifier was re-derived under
// current policy, after a login proved the plaintext.
//
// The rehash itself is not a domain operation — it needs the plaintext, an
// algorithm and a key, none of which this package may hold — so what is enforced
// here is the part the aggregate is the authority on: that the credential being
// re-sealed is a password this account's own log records as usable. Without that
// check the event would be appended from whatever the credential table happened to
// return, and a row moved between accounts would produce a rehash recorded against
// the wrong person's stream.
//
// Nothing about the verifier, the parameters or the pepper reaches the event.
// PasswordRehashed says only THAT a credential was upgraded and when, which is the
// evidence a parameter bump or a pepper rotation is actually progressing — a
// rotation that quietly rehashes nothing is indistinguishable from one that
// worked, and that ambiguity is what makes an operator destroy the old key too
// early.
//
// The state changes nothing: a rehashed verifier is the same credential, still
// usable, still bound to the same ids, so Apply has no case for this event and
// must not grow one.
func (u *User) RecordPasswordRehash(credentialID ids.CredentialID, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodPassword {
		return errs.NotFoundf("no such password credential")
	}
	if !m.Usable() {
		// Disabled or never enabled. Recording an upgrade to a credential that
		// cannot authenticate would report progress for a row the rotation job is
		// entitled to consider dead.
		return errs.Conflictf("this password credential is not usable")
	}
	eventsourcing.Record(u, &contract.PasswordRehashed{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		RehashedAt:   at.UTC(),
	})
	return nil
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// mutable refuses changes to an account that should not be accepting them.
//
// Pending is deliberately mutable: enrolling the password and the second factor
// is exactly what a Pending account is FOR. Suspended is not, and neither is a
// nonexistent one.
func (u *User) mutable() error {
	switch u.state {
	case StateNone:
		return errs.NotFoundf("no such account")
	case StateSuspended:
		return errs.AccessDeniedf("this account is suspended")
	default:
		return nil
	}
}

// maybeActivate records the transition into Active when, and only when, both
// preconditions hold.
//
// It is called after every event that could satisfy one of them, rather than
// being inferred by a projector, because the two conditions are established by
// different events and neither knows about the other's completion. The check is
// cheap and idempotent; missing it leaves an account permanently Pending after
// the user has done everything asked of them.
func (u *User) maybeActivate(at time.Time) {
	if u.state != StatePending {
		return
	}
	if !u.emailVerified {
		return
	}
	// BOTH roles, not just a second factor: an account whose only method is a
	// TOTP secret has nothing that can start an authentication.
	//
	// And the second factor may NOT be a recovery-code set. Recovery codes are
	// RoleSecondFactor and usable, so without this an account with a password and
	// a printed code sheet would activate — which lets a user skip enrolling a
	// real second factor entirely by generating recovery codes instead, and
	// leaves the mandatory-second-factor policy satisfied by the one method whose
	// whole purpose is to work when the real ones have failed.
	if !u.hasUsable(RolePrimary) || !u.hasRealSecondFactor() {
		return
	}
	eventsourcing.Record(u, &contract.UserActivated{
		SubjectID:   u.subjectID,
		ActivatedAt: at.UTC(),
	})
}
