package domain

import (
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Role says whether a method can start an authentication or only complete one.
//
// The distinction is not cosmetic. A TOTP code proves possession of a device but
// says nothing about WHO is holding it, so a system that accepts one as a first
// factor has an authentication scheme where the only secret is a six-digit
// number with a thirty-second lifetime.
type Role int

const (
	// RolePrimary can begin an authentication: it establishes which account is
	// being claimed and offers evidence for the claim.
	RolePrimary Role = iota

	// RoleSecondFactor can only complete one. It is meaningless without a
	// primary factor having already identified the account.
	RoleSecondFactor
)

// Strength orders methods so that "weaker than" is a comparison rather than a
// scattered set of if-statements.
//
// Ordered by what an attacker must defeat, not by how modern the method is:
//
//   - A password is a shared secret. Phishable, replayable, reusable across
//     sites, and breachable in bulk somewhere else entirely.
//   - A TOTP code is a shared secret with a thirty-second life. Still phishable
//     in real time — an attacker relaying the code to us while the user types it
//     succeeds — but not replayable afterwards and not breachable in bulk.
//   - A passkey is an origin-bound private key that never leaves the
//     authenticator. Not phishable: the signature is over our origin, so a proxy
//     site cannot obtain one that verifies here.
//
// A recovery code sits at the bottom deliberately. It is a long shared secret
// with no expiry, written down somewhere, and its whole purpose is to work when
// everything stronger has failed — which is exactly the situation an attacker
// engineers.
type Strength int

const (
	StrengthUnknown Strength = iota
	StrengthRecoveryCode
	StrengthPassword
	StrengthTOTP
	StrengthFederated
	StrengthPasskey
)

// StrengthOf reports a method kind's position in the ordering.
//
// An unrecognised kind is StrengthUnknown, which is BELOW every real method — so
// a kind added to the contract without being classified here is treated as the
// weakest thing available rather than silently as the strongest. The zero value
// denies, in the same sense authz.Decision's does.
func StrengthOf(k contract.MethodKind) Strength {
	switch k {
	case contract.MethodRecoveryCode:
		return StrengthRecoveryCode
	case contract.MethodPassword:
		return StrengthPassword
	case contract.MethodTOTP:
		return StrengthTOTP
	case contract.MethodFederated:
		return StrengthFederated
	case contract.MethodPasskey:
		return StrengthPasskey
	default:
		return StrengthUnknown
	}
}

// RoleOf reports whether a kind can start an authentication.
//
// Unrecognised kinds are RoleSecondFactor: an unclassified method must not be
// able to begin one.
func RoleOf(k contract.MethodKind) Role {
	switch k {
	case contract.MethodPassword, contract.MethodPasskey, contract.MethodFederated:
		return RolePrimary
	default:
		return RoleSecondFactor
	}
}

// Method is one enrolled authentication method on a user.
type Method struct {
	ID   ids.CredentialID
	Kind contract.MethodKind

	// EnabledAt is zero while a method is provisioned but unproven — a TOTP
	// secret the user has scanned but never produced a code from.
	//
	// A pending method is NOT usable and does NOT satisfy any invariant. Treating
	// provisioning as completion is how an account ends up with a second factor
	// that only exists on the server's side of the exchange.
	EnabledAt time.Time

	// DisabledAt is non-zero once the method is locked out after repeated
	// failures. Recovery is by rebinding the method, not by waiting: a
	// time-based unlock is a timer an attacker can also wait out.
	DisabledAt time.Time

	// UserVerified is meaningful for a PASSKEY and false for everything else.
	//
	// It is the difference between AAL1 and AAL2 for that method (identity.md
	// §2), and it is a property of the CREDENTIAL rather than of a ceremony: an
	// authenticator registered without user verification cannot start producing
	// it, so the account's activation and its removal invariants can be decided
	// from the enrolled set rather than from whatever the last login reported.
	UserVerified bool
}

// Usable reports whether this method can take part in an authentication now.
func (m Method) Usable() bool { return !m.EnabledAt.IsZero() && m.DisabledAt.IsZero() }

// Pending reports a method that is provisioned but not yet proven.
func (m Method) Pending() bool { return m.EnabledAt.IsZero() && m.DisabledAt.IsZero() }

// AALFor reports the assurance level a set of satisfied methods establishes.
//
// The rule is about INDEPENDENCE, not count. Two knowledge factors are still one
// thing an attacker steals once, so what counts is whether the set spans a
// primary factor and something the primary factor's compromise would not also
// yield.
//
// A passkey listed here is treated as NOT user-verified. Use AALForVerified when
// the ceremony reported UV — see there for why the distinction is a parameter
// rather than an assumption.
func AALFor(used []contract.MethodKind) contract.AssuranceLevel {
	return AALForVerified(used, false)
}

// AALForVerified is AALFor with the passkey's user-verification state supplied.
//
// # Why UV is a parameter and not an assumption
//
// identity.md §2 puts a passkey on BOTH rows of the table: `UV=false` is AAL1,
// and `UV=true` is AAL2 on its own, because the authenticator is the possession
// factor and the PIN or biometric that unlocked it is the second. NIST SP
// 800-63B-4 recognises that pairing.
//
// The previous signature could not express it, and its comment said so: it
// treated any passkey as AAL2 and left the caller "responsible for not listing a
// passkey it accepted without UV". That is a rule enforced by a sentence, on the
// one input that decides whether a session is trusted for a password change.
// Passing the flag makes the strong answer unreachable without the evidence for
// it — a caller that forgets now gets AAL1, which is the safe direction.
func AALForVerified(used []contract.MethodKind, userVerified bool) contract.AssuranceLevel {
	var primary, second bool
	for _, k := range used {
		switch RoleOf(k) {
		case RolePrimary:
			primary = true
		case RoleSecondFactor:
			second = true
		}
	}
	switch {
	case !primary:
		// No primary factor means nothing identified the account. This is not a
		// weak authentication; it is not an authentication.
		return contract.AAL0
	case second:
		return contract.AAL2
	case len(used) == 1 && used[0] == contract.MethodPasskey && userVerified:
		// One gesture, two factors. Treating it as AAL1 would force a redundant
		// TOTP prompt on the strongest method available and push users back to
		// passwords.
		return contract.AAL2
	default:
		// This is where a passkey with UV=false lands: AAL1, exactly as §2's
		// table says, rather than AAL0 — the credential did identify the account.
		return contract.AAL1
	}
}
