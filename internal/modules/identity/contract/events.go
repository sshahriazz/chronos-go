package contract

import "time"

// The event type discriminator is permanent: it appears in every stored event
// forever (CONVENTIONS §3). Format is "identity.<Name>.v<N>".
//
// Slice 1 publishes the account lifecycle, the password and TOTP methods,
// recovery codes, authentication outcomes and sessions. Passkeys, federation and
// API keys arrive in later slices and add types here; they do not change these.

// ---------------------------------------------------------------------------
// Email reservation
// ---------------------------------------------------------------------------

// EmailReserved claims an address for an account.
//
// This is the uniqueness mechanism, and it is an APPEND rather than a unique
// index because uniqueness has to hold at the moment of the write, in the log,
// not eventually in a projection. The reservation lives on its own stream named
// from the address — see ADR-044 — so two concurrent registrations for the same
// address contend on the same stream and exactly one append succeeds.
//
// A projection-based check cannot do this: it answers from data that is, by
// definition, behind the log, so both registrations read "free" and both
// succeed.
//
// INTERNAL to identity. No other module subscribes to it; there is nothing here
// another module could act on that is not better expressed by UserRegistered.
type EmailReserved struct {
	// Index is the keyed HMAC of the address. It is also what names the stream,
	// so it is present here for the projector, which does not parse stream names.
	Index EmailIndex

	// SubjectID is the account that now holds the claim.
	SubjectID string

	// ExpiresAt is when an UNVERIFIED claim lapses, and is the whole reason the
	// two-state design exists.
	//
	// Without it, registering with an address you do not control holds it
	// forever: the real owner can never register, and there is no one to appeal
	// to because no account was ever proven. With it, the squatter's claim is a
	// short lease and the owner simply registers after it runs out.
	//
	// Stored rather than derived from ReservedAt plus a policy constant, because
	// the constant will change and every reservation written under the old one
	// would silently change its deadline — including retroactively extending
	// claims that had already lapsed.
	ExpiresAt time.Time

	ReservedAt time.Time
}

func (*EmailReserved) EventType() string { return "identity.EmailReserved.v1" }

// EmailReservationConfirmed makes a claim permanent.
//
// Recorded when the address is proven, and separate from EmailVerified because
// the two live on DIFFERENT STREAMS: verification is a fact about the account,
// confirmation is a fact about the address claim. One event cannot be appended
// to two streams atomically, so collapsing them would mean the account believes
// it is verified while the reservation still lapses on schedule — and the
// address becomes available to a stranger under an active account.
type EmailReservationConfirmed struct {
	Index       EmailIndex
	SubjectID   string
	ConfirmedAt time.Time
}

func (*EmailReservationConfirmed) EventType() string {
	return "identity.EmailReservationConfirmed.v1"
}

// EmailReleased frees a claim.
//
// Three causes, and the distinction matters to the projector: an unverified
// reservation that expired, an address the owner changed away from, or an
// erasure. Only the first is routine.
type EmailReleased struct {
	Index      EmailIndex
	SubjectID  string
	Reason     string
	ReleasedAt time.Time
}

func (*EmailReleased) EventType() string { return "identity.EmailReleased.v1" }

// ---------------------------------------------------------------------------
// Account lifecycle
// ---------------------------------------------------------------------------

// UserRegistered creates the account, in state Pending.
//
// Pending is not a formality. An account here can do exactly nothing: it cannot
// authenticate, hold a session, or be invited anywhere. It becomes Active only
// once the address is verified AND a second factor is enrolled — see
// UserActivated.
type UserRegistered struct {
	UserID string

	// SubjectID is the pseudonym under which the vault holds this person's
	// address and name. It is what every other event and every projection
	// carries; the UserID and it are minted together and never diverge.
	SubjectID string

	// EmailIndex lets a projector build the lookup column for "is there an
	// account for this address?" without the vault, and without the address.
	EmailIndex EmailIndex

	RegisteredAt time.Time
}

func (*UserRegistered) EventType() string { return "identity.UserRegistered.v1" }

// EmailVerificationRequested records that a token was issued.
//
// The token itself is NOT here. Only its digest reaches storage at all, and even
// the digest stays out of the log: an event is permanent and readable by anyone
// who can replay, so a token digest in it would be an offline attack surface
// that outlives the token by years. The log records that a verification was
// requested; the short-lived digest lives in the read model and is deleted on
// use (identity.md §4).
type EmailVerificationRequested struct {
	SubjectID string

	// Index is the address being proven. Present because a verification can be
	// outstanding for a NEW address during an email change, and the projector
	// must know which claim the token would prove.
	Index EmailIndex

	// ExpiresAt bounds the token. Short, and enforced at use.
	ExpiresAt time.Time

	RequestedAt time.Time
}

func (*EmailVerificationRequested) EventType() string {
	return "identity.EmailVerificationRequested.v1"
}

// EmailVerified proves control of the address.
//
// Per identity.md §7 rule 7, verification VOIDS: every existing session, every
// other outstanding verification token, and any pending address change. That is
// what closes the pre-account-takeover window in which an attacker registers
// with a victim's address, waits for the victim to verify, and keeps a session
// established before the verification.
type EmailVerified struct {
	SubjectID  string
	Index      EmailIndex
	VerifiedAt time.Time
}

func (*EmailVerified) EventType() string { return "identity.EmailVerified.v1" }

// UserActivated is the transition into a usable account.
//
// It is a separate fact from EmailVerified and from the second factor being
// enrolled, because the account becomes usable only when BOTH hold, and neither
// event alone can know about the other's completion. A projector that inferred
// activation from either one would open the account early.
type UserActivated struct {
	SubjectID   string
	ActivatedAt time.Time
}

func (*UserActivated) EventType() string { return "identity.UserActivated.v1" }

// UserDeactivated is self-service: the account holder switching their own
// account off. Reversible by the holder.
type UserDeactivated struct {
	SubjectID string

	// ActorID is who did it, and is normally the SubjectID. It differs when an
	// operator deactivates on request, and the difference is the whole reason
	// the field exists — "notify the actor" and "notify the subject" are
	// different audiences (NOTIFICATIONS §4).
	ActorID       string
	DeactivatedAt time.Time
}

func (*UserDeactivated) EventType() string { return "identity.UserDeactivated.v1" }

// UserReactivated restores a deactivated account.
type UserReactivated struct {
	SubjectID     string
	ActorID       string
	ReactivatedAt time.Time
}

func (*UserReactivated) EventType() string { return "identity.UserReactivated.v1" }

// UserSuspended is administrative and is NOT reversible by the holder.
//
// Distinct from deactivation because the two look identical from outside and
// must never be confused inside: a suspended account that could reactivate
// itself would make suspension decorative.
type UserSuspended struct {
	SubjectID   string
	ActorID     string
	Reason      string
	SuspendedAt time.Time
}

func (*UserSuspended) EventType() string { return "identity.UserSuspended.v1" }

// ---------------------------------------------------------------------------
// Password
// ---------------------------------------------------------------------------

// PasswordResetRequested records that a password-reset link was asked for.
//
// The token is NOT here, and neither is its digest — the same rule
// EmailVerificationRequested is written under, and it bites harder here: a reset
// token grants account access rather than confirming an address, so a digest in
// a permanent, replicated log would be an offline attack surface against the
// credential itself. The log records that a reset was ASKED FOR; the digest
// lives in identity_token, is deleted on use, and expires in an hour.
//
// It is recorded on the ACCOUNT's stream rather than on a stream of its own,
// because that is where the outcome lands too — PasswordChanged with ViaReset —
// so a reader can see a request and its result in order without joining two
// streams.
//
// # Why this event exists at all, rather than the handler mailing directly
//
// Three reasons, all of them ResendVerification's (identity/app,
// ResendVerification's package comment) applied unchanged: the mail system's
// availability must not decide whether a reset can be REQUESTED, there must be
// exactly one place a reset link is minted, and a reset that left no trace in the
// account's own log would make "somebody asked to reset my password" invisible to
// the person it happened to.
type PasswordResetRequested struct {
	SubjectID string

	// Index is the address the link will be sent to, as a blind index. Present
	// for the same reason EmailVerificationRequested carries one: it says WHICH
	// claim the request was made against, and it is the only form of the address
	// that may appear in an event (ADR-002).
	//
	// It is advisory to delivery. The mail goes to the address the VAULT holds
	// for the subject — never to one a request supplied — which is what makes
	// this event unable to redirect a reset link (identity.md §4.5).
	Index EmailIndex

	// ExpiresAt is the deadline the link will carry. Advisory: the token the
	// issuer mints carries its own, and the store enforces that one.
	ExpiresAt time.Time

	RequestedAt time.Time
}

func (*PasswordResetRequested) EventType() string {
	return "identity.PasswordResetRequested.v1"
}

// PasswordSet records the FIRST password on an account.
//
// No hash, no salt, no parameters, no pepper version. The verifier lives in the
// read model, which is derived and rebuildable — but not from this event, and
// deliberately so. A hash in the log is a hash that can never be un-published:
// it survives the user changing their password, survives erasure of everything
// else, and is offline-crackable by anyone who can replay the stream. The
// verifier is written by the command handler to the system-scoped credential
// table and is the one piece of identity state that is NOT reconstructable by
// replay (identity.md §4).
type PasswordSet struct {
	SubjectID    string
	CredentialID string
	SetAt        time.Time
}

func (*PasswordSet) EventType() string { return "identity.PasswordSet.v1" }

// PasswordChanged records a replacement. Distinct from PasswordSet because the
// notification and the risk weighting differ: setting a first password on a
// passwordless account is an escalation, replacing one is routine.
type PasswordChanged struct {
	SubjectID    string
	CredentialID string

	// ViaReset is true when the change came from a reset flow rather than from a
	// caller who knew the old password. A reset invalidates every session; a
	// change made with the current password does not have to.
	ViaReset  bool
	ChangedAt time.Time
}

func (*PasswordChanged) EventType() string { return "identity.PasswordChanged.v1" }

// PasswordRehashed records a transparent upgrade on successful login, when the
// stored verifier's algorithm, parameters or pepper key version fall below
// current policy.
//
// An event rather than a silent write because it is the only evidence that the
// rehash job is actually running. A parameter bump that quietly rehashes nothing
// is indistinguishable from one that worked.
type PasswordRehashed struct {
	SubjectID    string
	CredentialID string
	RehashedAt   time.Time
}

func (*PasswordRehashed) EventType() string { return "identity.PasswordRehashed.v1" }

// CredentialCompromiseDetected records that a password appeared in a known
// breach corpus.
//
// It does NOT block the login. Blocking would lock a person out of the only
// place they can fix the problem, using information they cannot act on from the
// login screen. The session is instead marked RequiresCredentialRotation and
// restricted to profile and credential endpoints (identity.md §4).
type CredentialCompromiseDetected struct {
	SubjectID    string
	CredentialID string

	// Source names the corpus. Present so a false positive from one provider can
	// be traced without re-querying.
	Source     string
	DetectedAt time.Time
}

func (*CredentialCompromiseDetected) EventType() string {
	return "identity.CredentialCompromiseDetected.v1"
}

// ---------------------------------------------------------------------------
// Second factors
// ---------------------------------------------------------------------------

// TotpEnrollmentStarted records that a secret was provisioned but NOT yet
// proven.
//
// The two-step shape is the whole point: a secret the user has scanned but never
// produced a code from is a secret that may exist only on our side. Treating
// enrollment as complete at provisioning time is how accounts end up with a
// second factor nobody can satisfy.
//
// The secret is not here, and it is not in the PII vault either — an earlier
// version of this comment said it was. It is sealed with AES-256-GCM under a key
// wrapped by the OpenBao KEK (ADR-028) and stored in `credential.verifier` with
// `kind = 'totp'`, beside the password verifier that shares the column
// (migration 00008), bound by AAD to `subject:credential` so a row moved between
// accounts fails to open.
//
// The vault is for PERSONAL DATA, under a per-subject key that erasure destroys.
// A TOTP secret is key material: filing it there would make crypto-shredding a
// subject silently take their second factor with it. What the two share is only
// the rule that neither may enter an event.
type TotpEnrollmentStarted struct {
	SubjectID    string
	CredentialID string
	ExpiresAt    time.Time
	StartedAt    time.Time
}

func (*TotpEnrollmentStarted) EventType() string { return "identity.TotpEnrollmentStarted.v1" }

// TotpEnabled records a live code verified against the provisioned secret. This
// is the event that makes the method usable and can complete activation.
type TotpEnabled struct {
	SubjectID    string
	CredentialID string
	EnabledAt    time.Time
}

func (*TotpEnabled) EventType() string { return "identity.TotpEnabled.v1" }

// TotpDisabled removes the method. Requires step-up, and is refused outright if
// it would leave the account with no second factor while it is Active.
type TotpDisabled struct {
	SubjectID    string
	CredentialID string
	ActorID      string
	DisabledAt   time.Time
}

func (*TotpDisabled) EventType() string { return "identity.TotpDisabled.v1" }

// RecoveryCodesGenerated replaces the whole set atomically.
//
// Whole-set replacement, never incremental top-up: a set with a mix of old and
// new codes makes "how many do I have left" unanswerable, and leaves codes the
// user believes were replaced still live.
//
// The codes are not here. Their digests are in the read model.
type RecoveryCodesGenerated struct {
	SubjectID    string
	CredentialID string

	// Count is how many were issued. It is the denominator for the
	// low-codes-remaining warning, and carries no secret.
	Count       int
	GeneratedAt time.Time
}

func (*RecoveryCodesGenerated) EventType() string { return "identity.RecoveryCodesGenerated.v1" }

// RecoveryCodeConsumed burns one code. Single use, enforced by the projection's
// unique constraint rather than by a read-then-write in the handler.
type RecoveryCodeConsumed struct {
	SubjectID    string
	CredentialID string

	// Remaining is the count AFTER this consumption, so a projector does not
	// have to hold a running total to decide whether to warn.
	Remaining  int
	ConsumedAt time.Time
}

func (*RecoveryCodeConsumed) EventType() string { return "identity.RecoveryCodeConsumed.v1" }

// RecoveryCodesExhausted records that the last code was used.
//
// Its own event because it forces an interstitial — a new set is issued and an
// additional credential is encouraged — and a reactor cannot reliably detect
// "Remaining == 0" as a special case without also firing on a regenerate.
type RecoveryCodesExhausted struct {
	SubjectID    string
	CredentialID string
	ExhaustedAt  time.Time
}

func (*RecoveryCodesExhausted) EventType() string { return "identity.RecoveryCodesExhausted.v1" }

// ---------------------------------------------------------------------------
// Authentication outcomes
// ---------------------------------------------------------------------------

// AuthenticationSucceeded records a completed authentication, all factors
// satisfied. It is emitted once per successful login, not once per factor.
type AuthenticationSucceeded struct {
	SubjectID string

	// Methods are the kinds actually used, in the order they were satisfied.
	// Recorded rather than derived because "password then totp" and "passkey
	// alone" both reach AAL2 and must be distinguishable afterwards.
	Methods []MethodKind

	AAL AssuranceLevel

	// DeviceID is a pseudonym for the client. The device NAME, platform, user
	// agent and address are personal data and live in the vault under it.
	DeviceID string

	SucceededAt time.Time
}

func (*AuthenticationSucceeded) EventType() string { return "identity.AuthenticationSucceeded.v1" }

// AuthenticationFailed records a refusal.
//
// SubjectID is EMPTY when the identifier matched no account. That is not an
// omission to tidy up later: inventing a subject for an address nobody
// registered would create a permanent log record keyed to a person who does not
// exist here, and the attempt still needs to be counted for stuffing detection —
// which is what Index is for.
type AuthenticationFailed struct {
	SubjectID string
	Index     EmailIndex
	Reason    FailureReason
	DeviceID  string
	FailedAt  time.Time
}

func (*AuthenticationFailed) EventType() string { return "identity.AuthenticationFailed.v1" }

// SecondFactorChallenged records that the first factor passed and a second was
// demanded. Emitted so an abandoned login — first factor correct, second never
// supplied — is visible as the strong stuffing signal it is.
type SecondFactorChallenged struct {
	SubjectID    string
	Offered      []MethodKind
	DeviceID     string
	ChallengedAt time.Time
}

func (*SecondFactorChallenged) EventType() string { return "identity.SecondFactorChallenged.v1" }

// AuthenticatorDisabled records an authenticator locked out after too many
// failures against it.
//
// Per-authenticator, never per-account: locking the ACCOUNT on failed attempts
// hands any attacker a denial-of-service against any address they can guess.
// Recovery is by rebinding that authenticator, not by waiting.
type AuthenticatorDisabled struct {
	SubjectID    string
	CredentialID string
	Failures     int
	DisabledAt   time.Time
}

func (*AuthenticatorDisabled) EventType() string { return "identity.AuthenticatorDisabled.v1" }

// ---------------------------------------------------------------------------
// Sessions
// ---------------------------------------------------------------------------

// SessionCreated opens a session.
//
// The token is not here, and neither is its digest — same reasoning as the
// verification token. A session token digest in the log would outlive the
// session permanently.
type SessionCreated struct {
	SessionID string
	SubjectID string
	DeviceID  string

	AAL AssuranceLevel

	// IdleExpiresAt and AbsoluteExpiresAt are BOTH stored, and both are
	// enforced. The idle deadline moves on use; the absolute one never does, and
	// is what bounds a stolen token held by an attacker who keeps it warm.
	IdleExpiresAt     time.Time
	AbsoluteExpiresAt time.Time

	// RequiresCredentialRotation restricts the session to profile and credential
	// endpoints. Set when the password used to establish it was found in a
	// breach corpus.
	RequiresCredentialRotation bool

	CreatedAt time.Time
}

func (*SessionCreated) EventType() string { return "identity.SessionCreated.v1" }

// SessionElevated raises a session's assurance for a bounded window, after a
// step-up ceremony.
//
// Scoped and time-boxed: ElevatedUntil is short, and Scope names the ceremony it
// was granted for. An elevation that outlived its purpose would turn one
// re-authentication into a standing key to every dangerous operation.
type SessionElevated struct {
	SessionID     string
	SubjectID     string
	AAL           AssuranceLevel
	Scope         string
	ElevatedUntil time.Time
	ElevatedAt    time.Time
}

func (*SessionElevated) EventType() string { return "identity.SessionElevated.v1" }

// SessionRevoked ends a session deliberately.
//
// This is the event the access projector turns into a revocation tombstone
// (ADR-045). The tombstone is cleared by the projector CONFIRMING the removal,
// never by a timer.
type SessionRevoked struct {
	SessionID string
	SubjectID string

	// ActorID is who revoked it. Differs from SubjectID when an operator or a
	// password reset did it, and that difference decides who gets notified.
	ActorID string

	// Reason distinguishes routine sign-out from the ones that matter: a reset,
	// a compromise, an operator action.
	Reason    string
	RevokedAt time.Time
}

func (*SessionRevoked) EventType() string { return "identity.SessionRevoked.v1" }

// SessionExpired records a deadline being reached.
//
// Separate from SessionRevoked because expiry is not a security signal and
// revocation usually is. Collapsing them would bury every real revocation in
// routine noise.
type SessionExpired struct {
	SessionID string
	SubjectID string

	// Absolute distinguishes the two deadlines. An absolute expiry on a session
	// in active use is worth surfacing; an idle expiry is not.
	Absolute  bool
	ExpiredAt time.Time
}

func (*SessionExpired) EventType() string { return "identity.SessionExpired.v1" }

// DeviceRegistered records a client seen for the first time under this account.
//
// The device's NAME, platform and address are personal data and go to the vault
// under DeviceID. What is here is only the pseudonym and the fact.
type DeviceRegistered struct {
	SubjectID    string
	DeviceID     string
	RegisteredAt time.Time
}

func (*DeviceRegistered) EventType() string { return "identity.DeviceRegistered.v1" }
