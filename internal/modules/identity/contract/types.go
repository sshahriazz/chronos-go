// Package contract is the identity module's published surface — the only
// package another module may import (CONVENTIONS §1).
//
// Plain structs, no wire tags: serialization is the codec's job (ADR-001).
//
// # What is NOT here
//
// No email, no name, no IP address, no user agent, no device name, no secret,
// no hash. Identity is the module with the most personal data in the system and
// the least of it in the log: every event below carries a SubjectID pseudonym,
// and the vault resolves it at read time (ADR-002, compliance.md §1). Erasure is
// a key destruction, so an event that carried an address directly would be the
// one record erasure could not reach.
package contract

// MethodKind labels an authentication method.
//
// The label is wire-visible and permanent — it appears in stored events forever
// — so it is a string constant rather than an integer whose meaning depends on a
// Go source file that can be reordered.
//
// The ORDERING of these by strength is deliberately NOT here. Strength is a
// business rule that decides whether an attempt is a downgrade, and rules live
// in domain/ (CONVENTIONS §2). A consumer of this contract can read the label; it
// has no business deciding what the label is worth.
type MethodKind string

const (
	// MethodPassword is a knowledge factor. Never sufficient alone in this
	// system: an account does not become active until a second factor exists
	// (identity.md §2).
	MethodPassword MethodKind = "password"

	// MethodTOTP is RFC 6238, second factor only.
	MethodTOTP MethodKind = "totp"

	// MethodRecoveryCode is the single-use fallback for a lost second factor.
	// Second factor only, and every use is a risk signal.
	MethodRecoveryCode MethodKind = "recovery_code"

	// MethodPasskey is WebAuthn. Arrives in slice 2; the constant exists now so
	// the event schema does not change when it does.
	MethodPasskey MethodKind = "passkey"

	// MethodFederated is an external identity provider. Slice 4.
	MethodFederated MethodKind = "federated"
)

// EmailIndex is a keyed HMAC of a normalized email address.
//
// It exists because the log must be able to say "this account claims that
// address" without containing the address. Two properties make that safe:
//
//   - It is not reversible. Recovering the address needs the key, which lives in
//     OpenBao and never reaches a projector or a log line.
//   - It is not a global identifier for the person. Different keys produce
//     different indexes, so the value cannot be correlated against any other
//     system's records.
//
// It is NOT a substitute for the vault. It answers "is this the same address?"
// and nothing else — it cannot render an address to a human, and no notification
// may be addressed from it.
//
// The same construction already names the reservation stream (ADR-044), so the
// key is the same key, and the same rule applies: it is never rotated, because a
// stream name is immutable and rotating would orphan every reservation ever
// written. That is the deliberate, narrow exception to erasure-by-key-destruction
// documented in EVENT-SOURCING §5.
type EmailIndex string

// AssuranceLevel is the authentication strength a session was established with.
//
// Mirrors chronos.options.v1.AssuranceLevel, which is what an RPC declares it
// requires. Duplicated as a domain-side type rather than imported because
// contract may not import gen/proto (CONVENTIONS §2) — and because the wire enum
// is free to gain values this module has no implementation for.
type AssuranceLevel int

const (
	// AAL0 is an unauthenticated request. Never stored on a session; it exists
	// so the zero value is not silently AAL1.
	AAL0 AssuranceLevel = 0

	// AAL1 is a single factor.
	AAL1 AssuranceLevel = 1

	// AAL2 is two factors, or one passkey with user verification.
	AAL2 AssuranceLevel = 2

	// AAL3 is a hardware-bound authenticator with verifier impersonation
	// resistance.
	//
	// Declared, and deliberately not yet reachable: nothing in slice 1 can
	// establish it, and IDENTITY-REVIEW C4 records that the definition as
	// written is not deliverable with the authenticators this system accepts. A
	// method that claimed to produce AAL3 before that is resolved would be a
	// policy lie enforced by a comparison operator.
	AAL3 AssuranceLevel = 3
)

// Valid reports whether the level is one this system can actually establish.
func (a AssuranceLevel) Valid() bool { return a == AAL1 || a == AAL2 }

// FailureReason classifies a failed authentication attempt.
//
// Recorded in the log and never returned to the caller. The caller gets one
// undifferentiated refusal — telling an attacker whether the password or the
// second factor was wrong hands them a working oracle for one of the two
// (ADR-036, identity.md §7).
type FailureReason string

const (
	// ReasonNoSuchIdentifier is a login for an address with no account. Recorded
	// so credential stuffing is visible; the response is identical to a wrong
	// password, down to the timing.
	ReasonNoSuchIdentifier FailureReason = "no_such_identifier"

	ReasonWrongPassword     FailureReason = "wrong_password"
	ReasonWrongSecondFactor FailureReason = "wrong_second_factor"

	// ReasonReplayedCode is a TOTP code that verified arithmetically but was
	// already used. Distinct from a wrong code because it means an attacker has
	// observed a real one.
	ReasonReplayedCode FailureReason = "replayed_code"

	// ReasonUnverifiedEmail is a correct credential on an account that never
	// completed verification.
	ReasonUnverifiedEmail FailureReason = "unverified_email"

	// ReasonIncomplete is a correct credential on an account still in Pending —
	// registered, verified, but with no second factor yet, so not authenticable.
	ReasonIncomplete FailureReason = "incomplete_enrollment"

	ReasonDeactivated FailureReason = "deactivated"
	ReasonSuspended   FailureReason = "suspended"

	// ReasonRateLimited is an attempt refused before any credential was checked.
	ReasonRateLimited FailureReason = "rate_limited"
)
