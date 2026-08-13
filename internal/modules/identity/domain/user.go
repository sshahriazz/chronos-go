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
func (u *User) SetPassword(credentialID ids.CredentialID, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
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

// CanAuthenticate reports why an authentication may not proceed, before any
// credential is examined.
//
// The reason returned here is for the LOG, not for the caller. Every one of
// these produces the same undifferentiated refusal on the wire: telling an
// attacker that the account exists but is unverified is an account-existence
// oracle, and telling them it is suspended is worse (identity.md §7).
func (u *User) CanAuthenticate() (contract.FailureReason, bool) {
	switch u.state {
	case StateNone:
		return contract.ReasonNoSuchIdentifier, false
	case StatePending:
		if !u.emailVerified {
			return contract.ReasonUnverifiedEmail, false
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
