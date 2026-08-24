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
	"sort"
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

	// StateErased is TERMINAL. The subject key is destroyed, so nothing can read
	// the person's address or name again — not this system, and not anybody who
	// takes a copy of the database.
	//
	// It is a state rather than a deleted row because the events remain and must
	// keep replaying (compliance.md §4): a projector that met a missing account
	// and panicked would make the log unreplayable and take the rebuild
	// capability down with it. So the account exists, and is inert.
	StateErased
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
	case StateErased:
		return "erased"
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

	// pendingIndex is the address an email change is claiming but has not yet
	// proven, and pendingUntil is when that claim lapses.
	//
	// Both are blind indexes and instants — no address (ADR-002). They exist so
	// VoidPendingIdentifierChange can record something: identity.md §4.4 requires
	// a password reset to kill a pending change, and a reset cannot kill a state
	// the aggregate does not hold.
	pendingIndex contract.EmailIndex
	pendingUntil time.Time

	// revertIndex is the address this account moved AWAY from, and revertUntil is
	// when the window to move back closes (identity.md §12).
	revertIndex contract.EmailIndex
	revertUntil time.Time

	// links are the federated identities that can sign this account in, keyed by
	// issuer and provider subject (identity.md §7).
	//
	// A map rather than a slice because rule 4 — a provider identity links to at
	// most one user — makes the pair a key, and because §4.4's void has to
	// distinguish links the acting party PROVED from ones they did not.
	links map[federatedKey]federatedLink

	// username is the account's public handle (ADR-051), in the clear.
	//
	// It is held on the AGGREGATE and not read from user_view when a decision
	// needs it, for the reason every other decision in this module is taken from
	// the log: erasure must tombstone the handle it destroys, that is a write, and
	// a write decided from an eventually consistent read can be decided twice with
	// two different answers — here, twice with two different handles.
	//
	// Empty until the address is proven. A handle is claimed in the same request
	// as the verification and the first password (identity.md §4.6), so an account
	// carrying no handle is exactly an account nobody can sign into.
	username string

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

	// deletionRequested records that an erasure request is outstanding. Held so
	// RequestDeletion is idempotent — a person who clicks the button twice must
	// not put two deadlines in the log, because the mail NOTIFICATIONS §4 sends
	// names a date and two dates for one account is a support ticket.
	//
	// It is deliberately NOT a State. The lifecycle in identity.md §1 is
	// pending -> active -> deactivated -> suspended -> erased, and a request is
	// none of those: the account keeps every capability it had until compliance
	// acts on it, so a state that read "deleted" would make every gate in the
	// system disagree with what the account can actually do.
	deletionRequested   bool
	deletionScheduledAt time.Time
}

// New returns an empty User for the repository to rebuild into.
func New() *User { return &User{methods: make(map[ids.CredentialID]Method)} }

func (u *User) ID() ids.UserID                  { return u.id }
func (u *User) SubjectID() string               { return u.subjectID }
func (u *User) EmailIndex() contract.EmailIndex { return u.emailIndex }
func (u *User) State() State                    { return u.state }
func (u *User) EmailVerified() bool             { return u.emailVerified }

func (u *User) RecoveryCodesRemaining() int { return u.recoveryRemaining }

// Username is the account's public handle, empty until the address is proven.
func (u *User) Username() string { return u.username }

// DeletionRequested reports whether an erasure request is outstanding, and when
// it falls due. A zero time with a true flag is impossible: both are set by the
// one event.
func (u *User) DeletionRequested() (time.Time, bool) {
	return u.deletionScheduledAt, u.deletionRequested
}

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

func (u *User) hasUsable(role Role) bool { return u.countUsable(role) > 0 }

// countUsable counts the usable methods in one role.
//
// A COUNT rather than a boolean, because the removal paths need to know whether
// this is the LAST one — "does the account have a primary method" and "would
// removing this leave it with none" are different questions, and answering the
// second with the first is how an account ends up with nothing that can sign in.
func (u *User) countUsable(role Role) int {
	var n int
	for _, m := range u.methods {
		if m.Usable() && RoleOf(m.Kind) == role {
			n++
		}
	}
	return n
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

// countRealSecondFactors counts what satisfies the mandatory-second-factor
// policy: usable second factors excluding recovery codes, PLUS user-verified
// passkeys.
//
// # Why a passkey counts here despite being RolePrimary
//
// identity.md §2: a passkey with user verification is AAL2 ON ITS OWN, because
// the authenticator is the possession factor and the PIN or biometric that
// unlocked it is the second. It is one gesture that is stronger than password
// plus TOTP and phishing-resistant, which is why §5 calls passkeys the preferred
// path.
//
// Without this an account whose only method is a passkey could never activate —
// maybeActivate would demand a second factor the person already has, expressed
// differently — and the strongest available method would be the one that leaves
// you stuck. The policy is "two independent factors", not "an entry in the
// second-factor column".
//
// A passkey WITHOUT user verification does not count, and that is the same rule
// from the other side: no PIN and no biometric means one factor, so it is a
// primary and nothing more.
func (u *User) countRealSecondFactors() int {
	var n int
	for _, m := range u.methods {
		if !m.Usable() {
			continue
		}
		switch {
		case RoleOf(m.Kind) == RoleSecondFactor && StrengthOf(m.Kind) > StrengthRecoveryCode:
			n++
		case m.Kind == contract.MethodPasskey && m.UserVerified:
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
		// A verification CLEARS any pending change, which is identity.md §4.4
		// applied in the transition rather than remembered by a caller: proving
		// an identifier voids every pending identifier change, and the rule holds
		// however the event got here — including on a replay of a log written by
		// a build that enforced it somewhere else.
		u.pendingIndex, u.pendingUntil = "", time.Time{}

	case *contract.EmailChangeRequested:
		u.pendingIndex = ev.ToIndex
		u.pendingUntil = ev.ExpiresAt

	case *contract.EmailChangeCancelled:
		u.pendingIndex, u.pendingUntil = "", time.Time{}

	case *contract.EmailChanged:
		u.emailIndex = ev.ToIndex
		u.emailVerified = true
		u.pendingIndex, u.pendingUntil = "", time.Time{}
		u.revertIndex, u.revertUntil = ev.FromIndex, ev.RevertibleUntil

	case *contract.EmailChangeReverted:
		u.emailIndex = ev.ToIndex
		u.emailVerified = true
		u.pendingIndex, u.pendingUntil = "", time.Time{}
		// The window is spent. Reverting a revert would need its own window and
		// its own proof, and offering one would let the two addresses be swapped
		// back and forth indefinitely from whichever mailbox answered last.
		u.revertIndex, u.revertUntil = "", time.Time{}

	case *contract.UsernameAssigned:
		u.username = ev.Username

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

	case *contract.UserDeletionCancelled:
		u.deletionRequested = false
		u.deletionScheduledAt = time.Time{}
	case *contract.UserErased:
		u.state = StateErased
	case *contract.UserDeletionRequested:
		// No state change, deliberately — see the field's comment. A rebuild that
		// replays this reaches the same answer as the live aggregate because
		// nothing else writes either field.
		u.deletionRequested = true
		u.deletionScheduledAt = ev.ScheduledFor

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

	case *contract.FederatedIdentityLinked:
		if u.links == nil {
			u.links = make(map[federatedKey]federatedLink)
		}
		u.links[federatedKey{Issuer: ev.Issuer, Subject: ev.ProviderSubject}] = federatedLink{
			// AutoLinked is what §4.4's void turns on: a link the holder created
			// deliberately from an authenticated session was proven by THEM, and
			// one the system made on a provider's claim was not.
			AutoLinked: ev.AutoLinked,
			LinkedAt:   ev.LinkedAt,
		}

	case *contract.FederatedIdentityUnlinked:
		delete(u.links, federatedKey{Issuer: ev.Issuer, Subject: ev.ProviderSubject})

	case *contract.PasskeyRegistered:
		// ENABLED immediately, unlike a TOTP secret. There is no provisioned-but-
		// unproven state for a passkey: the registration ceremony IS the proof —
		// the authenticator signed the challenge — so a credential that exists has
		// already demonstrated itself. A pending state here would be a method that
		// only exists on the server's side of an exchange that already completed.
		u.enablePasskey(ev.CredentialID, ev.UserVerified, ev.RegisteredAt)
		if ev.UserVerified {
			// A user-verified passkey is AAL2 on its own (identity.md §2), so it
			// is a second factor being PROVEN — recorded permanently, exactly as
			// TotpEnabled does, and deliberately not undone by PasskeyRemoved.
			u.everSecondFactor = true
		}

	case *contract.PasskeyRemoved:
		// DELETED from the set, as TotpDisabled does. A removed passkey is not a
		// disabled one: the credential is gone from `passkey_credential` too, so
		// leaving a lingering method would describe an authenticator nothing can
		// verify against.
		if id, err := ids.Parse[ids.Credential](ev.CredentialID); err == nil {
			delete(u.methods, id)
		}

	case *contract.PasskeyCloneWarning:
		// No state. The warning is a fact about a ceremony, recorded so it is
		// observable; what it CHANGES — the reduced assurance and the required
		// step-up — belongs to the session that ceremony produced, not to the
		// account. Folding it in here would make a transient signal permanent.

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

// enablePasskey is enable, carrying the credential's user-verification state.
//
// UV is a property of the CREDENTIAL rather than of a ceremony: an authenticator
// registered without user verification cannot start producing it. Storing it on
// the method is what lets activation and the removal invariant be decided from
// the enrolled set instead of from whatever the last login happened to report.
func (u *User) enablePasskey(credentialID string, userVerified bool, at time.Time) {
	u.enable(credentialID, contract.MethodPasskey, at)
	id, err := ids.Parse[ids.Credential](credentialID)
	if err != nil {
		return
	}
	if m, ok := u.methods[id]; ok {
		m.UserVerified = userVerified
		u.methods[id] = m
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

// AssignUsername records the account's public handle.
//
// # The address must be PROVEN first, and the ordering is the same control
// SetPassword is written under
//
// A handle is claimed in the same request as the verification and the first
// password (identity.md §4.6). Refusing one on an unverified account is what
// makes that true of every route rather than of one call site: a handle claimed
// by whoever typed an address they may not control is a squat that costs an
// attacker nothing, and the 48h reservation lease that bounds an address squat
// does not exist for handles — a handle is claimed permanently.
//
// Stated in the AGGREGATE and not only in the use case, for the reason
// SetPassword is: the use case is one call site, and a second path to a first
// handle — an import, an admin tool, a future federated link — inherits the rule
// by construction instead of having to remember it.
//
// # One handle per account, forever
//
// A second, DIFFERENT handle is refused rather than recorded. There is no
// username-change flow (identity.md §4.6), and a change is not merely an
// unimplemented feature here: releasing a handle back into circulation is the
// failure ADR-051's tombstone exists to prevent, so a change must burn the old
// handle rather than free it. Recording a second assignment without that would
// leave the first handle claimed on its own stream by an account that no longer
// answers to it, and the two would disagree with nothing to reconcile them.
//
// Re-assigning the SAME handle records nothing and is not an error: a
// verification link clicked twice must not fail.
//
// # The value is taken as given
//
// Normalization and reserved-name screening are NormalizeUsername's, and they
// are not repeated here. What is checked is that the value is non-empty — a
// handle is mandatory, and an empty one recorded on the account would satisfy
// "has a username" while naming nobody.
func (u *User) AssignUsername(username string, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if !u.emailVerified {
		return errs.Conflictf(
			"this account has not proven its address; a username may not be claimed before verification")
	}
	if username == "" {
		return errs.ValidationFailedf("a username is required")
	}
	if u.username == username {
		return nil // already ours; records nothing
	}
	if u.username != "" {
		return errs.Conflictf("this account already has a username")
	}
	eventsourcing.Record(u, &contract.UsernameAssigned{
		SubjectID:  u.subjectID,
		Username:   username,
		AssignedAt: at.UTC(),
	})
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

// PendingEmailIndex is the address an unproven email change is claiming, and
// whether there is one at all.
func (u *User) PendingEmailIndex() (contract.EmailIndex, bool) {
	return u.pendingIndex, u.pendingIndex != ""
}

// RevertibleEmailIndex is the address this account moved away from and can still
// move back to, and whether that window is open at `at`.
func (u *User) RevertibleEmailIndex(at time.Time) (contract.EmailIndex, bool) {
	if u.revertIndex == "" {
		return "", false
	}
	return u.revertIndex, at.Before(u.revertUntil)
}

// RequestEmailChange claims a new address without switching to it.
//
// Nothing about the account moves here. It still answers to the old address,
// still signs in with it, and still receives its mail there — identity.md §12
// requires the NEW address to be proven first, because an attacker holding a
// session would otherwise take ownership by naming an address they do not
// control.
//
// A second request SUPERSEDES the first, recording the cancellation before the
// new claim so the log says what happened to the address that is no longer being
// claimed. That matters beyond tidiness: the reservation on the superseded
// address is released off the back of that event, and without it a person who
// mistyped an address once would hold it away from its real owner until the
// lease ran out.
func (u *User) RequestEmailChange(
	to contract.EmailIndex, expiresAt, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	switch {
	case !u.emailVerified:
		// An account that has not proven the address it HAS cannot ask to move.
		// The route out of an unverified address is the verification link, or a
		// fresh registration once the claim lapses — not a change that would let
		// somebody chain unproven addresses indefinitely.
		return errs.Conflictf("verify this account's current address first")
	case to == "":
		return errs.ValidationFailedf("an email index is required")
	case to == u.emailIndex:
		return errs.ValidationFailedf("that is already this account's address")
	case !expiresAt.After(at):
		return errs.ValidationFailedf("a pending change must expire in the future")
	}

	if u.pendingIndex == to {
		// The same change, again. Records nothing rather than moving the
		// deadline: extending on repeat would let one request hold an address
		// indefinitely by being replayed, which is the renewal
		// EmailReservation.Reserve refuses for the same reason.
		return nil
	}
	if u.pendingIndex != "" {
		eventsourcing.Record(u, &contract.EmailChangeCancelled{
			SubjectID:   u.subjectID,
			ToIndex:     u.pendingIndex,
			Reason:      contract.CancelSuperseded,
			CancelledAt: at.UTC(),
		})
	}
	eventsourcing.Record(u, &contract.EmailChangeRequested{
		SubjectID:   u.subjectID,
		FromIndex:   u.emailIndex,
		ToIndex:     to,
		ExpiresAt:   expiresAt.UTC(),
		RequestedAt: at.UTC(),
	})
	return nil
}

// CompleteEmailChange switches the account to the address it proved.
//
// Refused for anything but the pending index, and that refusal is what makes the
// mailed token specific: a token proving address A must not be able to complete
// a change to address B, however the two came to be outstanding at once.
//
// Refused once the pending change has LAPSED, for the reason
// EmailReservation.Confirm refuses a lapsed claim: the address is available to
// anybody after that, so completing would take it from whoever claimed it since.
func (u *User) CompleteEmailChange(
	to contract.EmailIndex, revertibleUntil, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if u.emailIndex == to && u.pendingIndex == "" {
		// Already done. A second click of one link is not a failure.
		return nil
	}
	switch {
	case u.pendingIndex == "":
		return errs.Conflictf("this account has no pending address change")
	case u.pendingIndex != to:
		return errs.Conflictf("this link is for a different address")
	case !at.Before(u.pendingUntil):
		return errs.Conflictf("this change request has expired; start again")
	case !revertibleUntil.After(at):
		return errs.ValidationFailedf("a revert window must end in the future")
	}

	eventsourcing.Record(u, &contract.EmailChanged{
		SubjectID:       u.subjectID,
		FromIndex:       u.emailIndex,
		ToIndex:         to,
		RevertibleUntil: revertibleUntil.UTC(),
		ChangedAt:       at.UTC(),
	})
	return nil
}

// RevertEmailChange puts the previous address back.
//
// Reached from a link mailed to the OLD address, so whoever calls it has proven
// control of the address the account had BEFORE the change. That is the whole
// remedy: an attacker holding a session can move the address, and cannot stop
// the real owner being told and undoing it.
func (u *User) RevertEmailChange(at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if u.revertIndex == "" {
		if u.emailVerified {
			// Either it was never changed, or the revert already happened and
			// cleared the window. A repeated click of one link is not a failure,
			// so the second case answers success — but only when the account is
			// in the state a completed revert leaves it in.
			return nil
		}
		return errs.Conflictf("this account has no address change to undo")
	}
	if !at.Before(u.revertUntil) {
		// The window is the security boundary and it has closed. After it the old
		// address is available to anybody, so undoing would take it back from
		// whoever claimed it since.
		return errs.Conflictf("the window to undo this address change has closed")
	}

	eventsourcing.Record(u, &contract.EmailChangeReverted{
		SubjectID:  u.subjectID,
		FromIndex:  u.emailIndex,
		ToIndex:    u.revertIndex,
		RevertedAt: at.UTC(),
	})
	return nil
}

// VoidPendingIdentifierChange cancels an identifier change this account has
// started but not completed.
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
// # It used to record nothing, and now it does
//
// This method was written before the email-change flow existed and was called by
// the password reset on every run while provably doing nothing, on the argument
// that the rule is free while it is a no-op and expensive to retrofit once it is
// not. The flow now exists, `pendingIndex` is now a state an event can set, and
// every existing caller inherited the enforcement without being changed. That is
// the argument paying out; it is recorded here because the next such no-op is
// easier to justify with a case that actually landed.
//
// # The other half of the rule, which was always real
//
// A pending change cannot be COMPLETED without the live token mailed for it, and
// the reset voids every outstanding token of every purpose for the subject
// (app.TokenStore.RevokeAllPurposes). So the flow was never exploitable in the
// window between the two. This closes it in the aggregate as well, which is what
// makes the state visible in the log rather than merely unreachable.
func (u *User) VoidPendingIdentifierChange(at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if u.pendingIndex == "" {
		return nil
	}
	eventsourcing.Record(u, &contract.EmailChangeCancelled{
		SubjectID:   u.subjectID,
		ToIndex:     u.pendingIndex,
		Reason:      contract.CancelPasswordReset,
		CancelledAt: at.UTC(),
	})
	return nil
}

// CancelEmailChange is the holder calling their own pending change off.
func (u *User) CancelEmailChange(at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if u.pendingIndex == "" {
		return nil
	}
	eventsourcing.Record(u, &contract.EmailChangeCancelled{
		SubjectID:   u.subjectID,
		ToIndex:     u.pendingIndex,
		Reason:      contract.CancelByHolder,
		CancelledAt: at.UTC(),
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

// RegisterPasskey records a WebAuthn credential the account just proved.
//
// # There is no pending state, unlike TOTP
//
// A TOTP secret is provisioned and then proven by a code, so it has a moment of
// existing-but-unusable. A passkey's registration ceremony IS the proof: the
// authenticator signed the challenge before this is ever called. A credential
// that exists has already demonstrated itself, and a pending state would
// describe a method that only exists on the server's side of an exchange that
// already completed.
//
// # It can complete activation, and only when user-verified
//
// identity.md §2 puts a passkey on both rows: with user verification it is AAL2
// on its own — the authenticator is the possession factor and the PIN or
// biometric that unlocked it is the second — and without, it is one factor and
// nothing more. maybeActivate therefore accepts the first and not the second,
// which is why the flag is a parameter here rather than an assumption made
// later.
//
// The LABEL is the one caller-chosen string. It is bounded on the wire and
// checked again here, because it lands in a permanent log nobody can edit and is
// rendered on a security screen beside other people's devices.
func (u *User) RegisterPasskey(
	credentialID ids.CredentialID, label string,
	backupEligible, backupState, userVerified bool, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if credentialID.IsZero() {
		return errs.ValidationFailedf("a credential id is required")
	}
	if !u.emailVerified {
		// The same ordering SetPassword enforces, and for the same reason: a
		// method enrolled on an unproven address is a method a stranger who typed
		// somebody else's address can attach to the account they are hijacking.
		return errs.Conflictf("verify this account's address before registering a passkey")
	}
	if len(label) > MaxPasskeyLabel {
		return errs.ValidationFailedf(
			"a passkey label may not exceed %d characters", MaxPasskeyLabel)
	}
	if m, ok := u.methods[credentialID]; ok && m.Usable() {
		// Already registered. A retried ceremony is not an error — and this is a
		// no-op rather than a second event, because the credential id is the
		// authenticator's own and a duplicate would describe one key twice.
		return nil
	}

	eventsourcing.Record(u, &contract.PasskeyRegistered{
		SubjectID:      u.subjectID,
		CredentialID:   credentialID.String(),
		Label:          label,
		BackupEligible: backupEligible,
		BackupState:    backupState,
		UserVerified:   userVerified,
		RegisteredAt:   at.UTC(),
	})
	u.maybeActivate(at)
	return nil
}

// MaxPasskeyLabel bounds the name a person gives their own device.
//
// Generous, because it is a human label and the alternative is somebody unable
// to tell two work laptops apart. Bounded at all, because it is permanent: an
// event cannot be edited, and an unbounded string in one is an unbounded row in
// every replica of the log forever.
const MaxPasskeyLabel = 64

// RemovePasskey deletes a credential.
//
// # Guarded by the same invariant that protects the last TOTP factor
//
// identity.md §5 says removal is guarded by AtLeastOneUsableMethod and requires
// step-up. Both halves matter and they guard different things: the step-up is
// the transport's (the RPC declares it), and this is the one that stops an
// account being left with nothing that can authenticate.
//
// Two checks rather than one, because a passkey occupies two roles at once. It
// is a PRIMARY method, so removing the last one can leave an account unable to
// start an authentication at all; and a user-verified one also satisfies the
// mandatory-second-factor policy, so removing it can leave an Active account
// below the policy even though a password remains. A single count would miss
// whichever case it was not written for.
func (u *User) RemovePasskey(
	credentialID ids.CredentialID, actorID string, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodPasskey {
		return errs.NotFoundf("no such passkey")
	}
	if actorID == "" {
		return errs.Internalf("no actor reached the passkey removal")
	}

	if m.Usable() {
		if u.countUsable(RolePrimary) <= 1 {
			return errs.Conflictf("removing this would leave the account with no way to " +
				"sign in; set a password or register another passkey first")
		}
		if u.state == StateActive && m.UserVerified && u.countRealSecondFactors() <= 1 {
			return errs.Conflictf("removing this would leave the account with no second " +
				"factor; enrol another first")
		}
	}

	eventsourcing.Record(u, &contract.PasskeyRemoved{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		ActorID:      actorID,
		RemovedAt:    at.UTC(),
	})
	return nil
}

// NoteCloneWarning records that an authenticator's counter went backwards.
//
// # It records and refuses nothing
//
// The WebAuthn spec lists an out-of-order race as a benign cause, and this
// system treats concurrent sessions as ordinary (identity.md §6, §9), so denying
// would sign people out for using two devices at once. §5 says the counter is
// "not treated as mandatory, because most synced passkeys never increment it. A
// regression here locks out legitimate users."
//
// What it buys is OBSERVABILITY. `go-webauthn` sets CloneWarning and returns no
// error, so an application that never inspects the flag has clone detection that
// does nothing while every test passes — the exact failure this repository
// shipped three times in notification adapters. The consequence for the session
// is the caller's: reduced assurance and a required step-up.
func (u *User) NoteCloneWarning(
	credentialID ids.CredentialID, stored, presented uint32, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	m, ok := u.methods[credentialID]
	if !ok || m.Kind != contract.MethodPasskey {
		return errs.NotFoundf("no such passkey")
	}
	eventsourcing.Record(u, &contract.PasskeyCloneWarning{
		SubjectID:    u.subjectID,
		CredentialID: credentialID.String(),
		Stored:       stored,
		Presented:    presented,
		DetectedAt:   at.UTC(),
	})
	return nil
}

// Passkeys returns the account's usable WebAuthn credentials.
func (u *User) Passkeys() []Method {
	var out []Method
	for _, m := range u.methods {
		if m.Kind == contract.MethodPasskey && m.Usable() {
			out = append(out, m)
		}
	}
	return out
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
	case StateErased:
		// Explicit, because the fallback below would answer CONFLICT and NAME
		// THE STATE — "a erased account cannot be deactivated" both confirms to
		// anybody who can guess an identifier that a particular person once held
		// this account, and reads as a typo while doing it.
		return errs.NotFoundf("no such account")
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
	if u.state == StateErased {
		// Before the suspended branch, and NOT_FOUND for the same reason
		// Deactivate gives: an erased account must not be distinguishable from
		// one that never existed.
		return errs.NotFoundf("no such account")
	}
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

// RequestDeletion records that the holder has asked for the account to be
// erased, and when that becomes due.
//
// # It changes nothing else, and that is the point
//
// The account keeps its state, its credentials and its sessions. Erasure is
// `compliance`'s work and that module does not exist; an aggregate that switched
// the account off here would be asserting that a handoff happened when the other
// side of it has never been built, and the person would be locked out of an
// account nothing is going to delete.
//
// Deactivating first is a product decision that belongs to whoever calls this,
// not to the aggregate: `Deactivate` is a separate command and can be issued in
// the same append.
//
// # Idempotent, because the deadline is communicated
//
// A second request records nothing and keeps the FIRST deadline. The alternative
// lets anyone holding the session push the deadline out indefinitely, and it
// makes the mail NOTIFICATIONS §4 sends ("deletion scheduled for <date>") name a
// date that a later mail contradicts.
//
// A suspended account is refused by mutable(): a suspension is administrative,
// and letting its subject start a clock that ends in erasure would let them
// destroy the evidence the suspension exists to preserve.
func (u *User) RequestDeletion(actorID string, scheduledFor, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if u.deletionRequested {
		return nil
	}
	switch {
	case actorID == "":
		return errs.ValidationFailedf("an actor id is required")
	case scheduledFor.Before(at):
		// A deadline already in the past would be due the moment it was written.
		// Refused here rather than clamped, because a clamp hides a caller whose
		// grace period is misconfigured to zero.
		return errs.ValidationFailedf("a deletion deadline may not be in the past")
	}
	eventsourcing.Record(u, &contract.UserDeletionRequested{
		SubjectID:    u.subjectID,
		ActorID:      actorID,
		ScheduledFor: scheduledFor.UTC(),
		RequestedAt:  at.UTC(),
	})
	return nil
}

// CancelDeletion withdraws an outstanding erasure request.
//
// # Idempotent in the direction that matters
//
// Cancelling when nothing is outstanding records nothing and succeeds. The
// alternative — an error — makes the cancel link in the "deletion scheduled"
// mail fail for anybody who clicks it twice, or who clicks it after an operator
// already withdrew the request on their behalf. Neither person did anything
// wrong, and both would be told they had.
//
// It is refused for an ERASED account by mutable(), which is the important
// direction: once the key is destroyed there is nothing to come back to, and a
// cancel that appeared to succeed would tell somebody their account was saved
// when it is unreadable.
func (u *User) CancelDeletion(actorID string, at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}
	if !u.deletionRequested {
		return nil
	}
	if actorID == "" {
		return errs.ValidationFailedf("an actor id is required")
	}
	eventsourcing.Record(u, &contract.UserDeletionCancelled{
		SubjectID:   u.subjectID,
		ActorID:     actorID,
		CancelledAt: at.UTC(),
	})
	return nil
}

// Erase records that the subject key has been destroyed.
//
// # Called AFTER the destruction, never before
//
// This is the fact, not the instruction. compliance.md §4 makes step 5 — the
// destroy — the point of no return, and everything before it reversible; an
// event appended first would assert an irreversible thing that had not happened
// yet, and a failure between the two would leave a log saying the account is
// unreadable while every address in the vault still resolves.
//
// # Only with a request outstanding
//
// Erasure follows a request and a grace period. Refusing without one is what
// stops a bug in the orchestration — a workflow started for the wrong subject,
// a replayed activity carrying a stale id — from destroying an account nobody
// asked to erase. That mistake has no undo.
//
// Idempotent, because the workflow that calls it retries: a second call on an
// already-erased account records nothing and succeeds, so a redelivery does not
// park forever on a step that is genuinely done.
func (u *User) Erase(at time.Time) error {
	if u.state == StateErased {
		return nil
	}
	if u.state == StateNone {
		return errs.NotFoundf("no such account")
	}
	if !u.deletionRequested {
		return errs.Conflictf("this account has no outstanding erasure request; erasure " +
			"follows a request and a grace period, and there is no undo for it")
	}
	eventsourcing.Record(u, &contract.UserErased{
		SubjectID: u.subjectID,
		ErasedAt:  at.UTC(),
	})
	return nil
}

// NeedsReactivation reports that this account is deactivated and that a
// completed authentication is entitled to switch it back on.
//
// # Why reactivation is not an RPC
//
// Deactivation is holder-reversible by design (identity.md §1). CanAuthenticate
// refuses a deactivated account, and every authenticated RPC needs a session, so
// a `Reactivate` RPC would have exactly one precondition — a session — that its
// own subject cannot obtain. "Reversible" would be a word in a document with no
// code behind it. That is the same shape as the first-enrolment deadlock
// (NeedsFirstSecondFactor), and it is closed the same way: by admitting ONE more
// state into the authentication, narrowly, rather than by relaxing a rule.
//
// # Why the account is not left holding a bounded session instead
//
// The enrolment carve-out mints an AAL1 session whose authority is bounded by
// the declared assurance floors. That mechanism cannot be reused here, because
// the bound it provides is a level and this account's problem is a STATE — an
// AAL2 session on a deactivated account passes every floor in the system.
// Nothing in the request pipeline reads the account's state (the authenticator's
// query joins user_view only to read the enrolment column), so a deactivated
// account holding any session is a deactivated account with full API access.
//
// So the reactivation happens INSIDE the ceremony, in the same atomic append
// that records the successful authentication, and no session for a deactivated
// account is ever minted. The window in which the two disagree does not exist
// rather than being small.
//
// # What it does not relax
//
// The account must present every factor it has, exactly as an active account
// must: this predicate is consulted after the credentials verified, not instead
// of verifying them. So an attacker holding only the password cannot reactivate
// an account any more than they could sign into it — and the reversal is mailed
// to the holder as a Security-class alert (NOTIFICATIONS §4,
// `identity.account_reactivated`), which is the control that makes a reversal
// the holder did not perform visible to them.
//
// The address must be proven, for NeedsFirstSecondFactor's reason: an account
// that deactivated before proving its address has nothing establishing that the
// person signing in reads that mailbox.
//
// Suspended is not here and must never be. Suspension is administrative and
// identity.md §1 says the holder may never reverse it; Reactivate refuses it
// again, so a caller that reached this predicate wrongly still cannot undo one.
func (u *User) NeedsReactivation() bool {
	return u.state == StateDeactivated && u.emailVerified
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
		if u.NeedsReactivation() {
			// Admitted so the ceremony can RUN, not so it can end in a session for
			// a deactivated account. Every factor the account holds is still
			// demanded below, and the caller that admits this state is required to
			// record UserReactivated in the same atomic append as the successful
			// authentication — see NeedsReactivation for why the reversal cannot be
			// an RPC and cannot be a bounded session.
			return "", true
		}
		// Deactivated with an unproven address. There is no mailbox this account
		// has ever demonstrated control of, so there is nobody a reactivation could
		// be attributed to.
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
	case StateErased:
		// TERMINAL, and refused here so every command inherits it rather than
		// each one remembering. There is nothing left to act on: the key that
		// made the personal data readable is destroyed, so a command that
		// "succeeded" here would record a change to an account nobody can ever
		// resolve again.
		//
		// NOT_FOUND rather than a specific refusal, and it is the one place in
		// this switch where the wording is a privacy decision: telling a caller
		// "this account was erased" confirms that a particular person once held
		// it, to anybody who can guess an identifier.
		return errs.NotFoundf("no such account")
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

// ---------------------------------------------------------------------------
// Federated identity (identity.md §7)
// ---------------------------------------------------------------------------

// federatedKey is the pair that identifies a person at a provider.
//
// Both halves, always. A `sub` is unique within an issuer and nowhere else, so
// keying on the subject alone would let two providers' identifiers collide into
// one link — and the collision would be silent, because neither provider can see
// the other's namespace.
type federatedKey struct {
	Issuer  contract.Issuer
	Subject string
}

// federatedLink is what the account remembers about one link.
type federatedLink struct {
	// AutoLinked records that the SYSTEM created this on a verified-email match
	// rather than the holder creating it deliberately.
	//
	// It is the whole of what §4.4's void turns on. A link somebody made from an
	// authenticated session was proven by them; one made automatically was proven
	// by a provider's claim about an address, and a recovery exists precisely
	// because claims about that account may no longer be trustworthy.
	AutoLinked bool

	LinkedAt time.Time
}

// FederatedLinks reports how many provider identities can sign this account in.
func (u *User) FederatedLinks() int { return len(u.links) }

// HasFederatedLink reports whether one specific provider identity is linked.
func (u *User) HasFederatedLink(issuer contract.Issuer, subject string) bool {
	_, ok := u.links[federatedKey{Issuer: issuer, Subject: subject}]
	return ok
}

// LinkFederatedIdentity attaches a provider identity to this account.
//
// # What this method does NOT decide
//
// Whether the link is ALLOWED. identity.md §7's auto-link rules — the provider's
// verification claim, the trusted-verification list, whether the local address
// is verified — are decided by the caller against a provider's response, which
// is not something an aggregate can see. What lives here is what the ACCOUNT
// knows: that a pair may link once, that it may not link twice, and that a
// suspended or erased account links nothing.
//
// `autoLinked` is carried rather than judged, for the same reason: this records
// HOW the link came about so §4.4 can act on it later, and the judgement about
// whether it should have happened belongs where the provider's claims are.
func (u *User) LinkFederatedIdentity(
	issuer contract.Issuer, subject string, verification contract.ProviderVerification,
	autoLinked bool, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	switch {
	case issuer == "":
		return errs.ValidationFailedf("an issuer is required")
	case subject == "":
		// A link with no provider subject matches nothing and would be matched by
		// anything else with no subject — which across accounts is one identity
		// signing into all of them.
		return errs.ValidationFailedf("a provider subject is required")
	}

	if _, already := u.links[federatedKey{Issuer: issuer, Subject: subject}]; already {
		// Idempotent for the SAME pair. A retried callback must not fail, and must
		// not record a second link that a later unlink would only half remove.
		return nil
	}

	eventsourcing.Record(u, &contract.FederatedIdentityLinked{
		SubjectID:         u.subjectID,
		Issuer:            issuer,
		ProviderSubject:   subject,
		EmailVerification: verification,
		AutoLinked:        autoLinked,
		LinkedAt:          at.UTC(),
	})
	return nil
}

// UnlinkFederatedIdentity removes a provider identity.
//
// # The refusal identity.md §7 names precisely
//
// "Removing the last federated link from a passwordless account is refused with
// an actionable error telling the user to set a password or register a passkey
// first." A person who signed up with Google has no password by design — §7
// calls that a first-class state, not a degraded one — so removing their only
// link leaves them with nothing at all, and an endpoint that allowed it would be
// the account-loss path dressed as a settings toggle.
//
// The check is AtLeastOneUsableMethod expressed for this method: what matters is
// not that a link is going, but that something can still start an
// authentication afterwards.
func (u *User) UnlinkFederatedIdentity(
	issuer contract.Issuer, subject, actorID string, at time.Time,
) error {
	if err := u.mutable(); err != nil {
		return err
	}
	key := federatedKey{Issuer: issuer, Subject: subject}
	if _, ok := u.links[key]; !ok {
		return errs.NotFoundf("no such linked account")
	}

	// The account's OTHER ways in, counted after this link is gone.
	if len(u.links) == 1 && !u.hasUsable(RolePrimary) {
		return errs.Conflictf("removing this would leave the account with no way to sign " +
			"in; set a password or register a passkey first")
	}

	eventsourcing.Record(u, &contract.FederatedIdentityUnlinked{
		SubjectID:       u.subjectID,
		Issuer:          issuer,
		ProviderSubject: subject,
		Reason:          contract.UnlinkByHolder,
		ActorID:         actorID,
		UnlinkedAt:      at.UTC(),
	})
	return nil
}

// VoidUnprovenFederatedLinks removes every link the acting party did not prove.
//
// # The variant this closes
//
// identity.md §4.4 and §7 rule 7, from Sudhodanan & Paverd: the TROJAN
// IDENTIFIER. An attacker attaches a provider identity they control to the
// victim's account and waits. The victim resets their password, believes they
// have taken the account back, and the attacker signs straight back in — because
// a reset changes a credential and leaves a link alone.
//
// # Which links go, and which stay
//
// AUTO-LINKED ones go. They were created on a provider's claim about an email
// address, and a recovery exists precisely because claims about this account may
// no longer be trustworthy — the address may be the attacker's, which is how the
// link got there.
//
// Links the HOLDER created deliberately stay. Those were made from a session
// that had already proven the account, which is what "proven by the acting
// party" means in §4.4's wording, and voiding them would sign people out of
// their own legitimately linked providers every time they forgot a password.
//
// # It records nothing when there is nothing to void
//
// Called by the password reset on EVERY run, so an unconditional event would put
// an unlink on the stream of every account that ever reset a password.
func (u *User) VoidUnprovenFederatedLinks(at time.Time) error {
	if err := u.mutable(); err != nil {
		return err
	}

	// Sorted, so a replay records the same events in the same order. Map order
	// is randomised in Go, and two runs of one command producing two different
	// event sequences would make a retried reset non-idempotent.
	var unproven []federatedKey
	for key, link := range u.links {
		if link.AutoLinked {
			unproven = append(unproven, key)
		}
	}
	sort.Slice(unproven, func(i, j int) bool {
		if unproven[i].Issuer != unproven[j].Issuer {
			return unproven[i].Issuer < unproven[j].Issuer
		}
		return unproven[i].Subject < unproven[j].Subject
	})

	for _, key := range unproven {
		eventsourcing.Record(u, &contract.FederatedIdentityUnlinked{
			SubjectID:       u.subjectID,
			Issuer:          key.Issuer,
			ProviderSubject: key.Subject,
			Reason:          contract.UnlinkPasswordReset,
			// No actor: nobody chose this, a rule did.
			UnlinkedAt: at.UTC(),
		})
	}
	return nil
}
