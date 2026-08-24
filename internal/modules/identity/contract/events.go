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

// DuplicateRegistrationAttempted records that somebody tried to register with an
// address a VERIFIED account already holds.
//
// # Why this event exists at all
//
// Register is deliberately indistinguishable: the already-claimed branch and the
// success branch return the same empty response, because a CONFLICT on the wire
// answers "does an account exist for this address?" exactly (identity.md §11,
// ADR-036). That property is correct and this event does not weaken it — nothing
// here reaches the caller.
//
// What it fixes is the other half. Until this event, the taken branch sent
// NOTHING anywhere: the screen said "check your email", no mail was ever sent,
// and the person who actually owns the mailbox — the returning user, who is who
// hits that branch most often — was left at a dead end with no way to learn that
// the account they were trying to create already exists. The answer cannot go on
// the wire, so it goes to the MAILBOX, which is the one channel that proves
// ownership of the address before disclosing anything about it.
//
// # Only for a VERIFIED claim
//
// The reservation aggregate refuses to record this while the claim is unverified
// (domain.EmailReservation.NoticeDuplicateRegistration). Mailing an address whose
// claim nobody has proven is unsolicited mail to a person who never asked for it
// and never proved they can read it (NOTIFICATIONS §5) — and the pending
// registrant already holds a verification link and a resend path.
//
// # What it carries, and what it must never carry
//
// The pseudonym of the account that HOLDS the address, so the notification
// kernel resolves the mailbox from the vault at delivery time (ADR-002). Not the
// address. Not the caller's IP, not their user agent, and nothing else about
// whoever typed the address: an event is permanent and replicated, and the party
// this records is by definition unauthenticated, so anything attributed to them
// would be attacker-controlled text living forever in the log.
//
// AttemptedAt is load-bearing rather than decorative — it is what the reservation
// aggregate counts to bound how often one address can be made to receive this
// message. See domain.EmailReservation.NoticesSince.
type DuplicateRegistrationAttempted struct {
	// Index is the keyed HMAC of the address, and also names the stream this
	// lands on. Present for the same reason EmailReserved carries it: a reader
	// does not parse stream names.
	Index EmailIndex

	// SubjectID is the account that holds the claim — the person who is told.
	// It is NOT whoever made the attempt, who is unauthenticated and unnamed.
	SubjectID string

	// AttemptedAt is when the refused registration arrived, UTC. The per-address
	// ceiling is computed from these, so it is state rather than commentary.
	AttemptedAt time.Time
}

func (*DuplicateRegistrationAttempted) EventType() string {
	return "identity.DuplicateRegistrationAttempted.v1"
}

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

// UserDeletionRequested records that the account holder has asked for the
// account to be erased.
//
// It is a REQUEST and nothing more. Erasure is `compliance`'s work (ADR-002:
// destroy the key), and that module does not exist yet — so nothing consumes
// this event today and the account keeps working until something does. Saying
// so in the type is deliberate: an event named `UserDeleted` would read as a
// completed fact, and a projection built against that reading would hide an
// account that is still fully usable.
//
// # Why the deadline is in the event
//
// `ScheduledFor` is the end of the grace period, computed by the application
// layer from its own policy and frozen here. A consumer that recomputed it from
// `RequestedAt` plus whatever the grace period is TODAY would move every
// outstanding deadline whenever the policy changed — including backwards, past
// deadlines that have already been communicated to the person by mail
// (NOTIFICATIONS.md §4: "Deletion scheduled for *date* — cancel").
//
// # No personal data, as everywhere else
//
// A pseudonym, an actor and two timestamps. Nothing here says which address is
// being deleted, and nothing needs to: the vault resolves the subject at send
// time (ADR-002).
type UserDeletionRequested struct {
	SubjectID string

	// ActorID is who asked, and is normally the SubjectID. It differs when an
	// operator raises a deletion on the holder's behalf — a DSAR arriving by
	// post, for instance — and the difference decides who the mail goes to
	// (NOTIFICATIONS §4).
	ActorID string

	// ScheduledFor is when erasure becomes due: the end of the grace period
	// during which the request can still be withdrawn.
	ScheduledFor time.Time

	RequestedAt time.Time
}

func (*UserDeletionRequested) EventType() string { return "identity.UserDeletionRequested.v1" }

// UserDeletionCancelled records that an outstanding erasure request was
// withdrawn before its deadline.
//
// # The grace period only means something if it can be used
//
// A request that could not be withdrawn would make the waiting period
// decoration: the point of it is that somebody who clicked in anger, or whose
// session was taken, can stop what they started. The window is also exactly when
// a stolen session is most dangerous, which is why the "deletion scheduled"
// mail carries a way to cancel and why cancelling is a mutation like any other.
//
// After this the account is ordinary again. There is no residue: the next
// request computes a fresh deadline, because a stale one would be a date nobody
// was ever told.
type UserDeletionCancelled struct {
	SubjectID string

	// ActorID is who withdrew it. Normally the holder; an operator when the
	// original request arrived out of band and was retracted the same way.
	ActorID string

	CancelledAt time.Time
}

func (*UserDeletionCancelled) EventType() string { return "identity.UserDeletionCancelled.v1" }

// UserErased records that the account's key has been destroyed.
//
// # This is the completed fact UserDeletionRequested deliberately is not
//
// The request is a clock; this is the point of no return, appended AFTER
// OpenBao has destroyed the subject key (compliance.md §4 step 5). Every event
// referencing this subject still exists and still replays — that is what makes
// erasure a key destruction rather than a rewrite — and from here the vault
// answers a tombstone for them, so projections render "Deleted user" instead of
// a name nobody can read.
//
// # What it does NOT mean
//
// Not "every trace is gone". Invoices and tax records are retained under Article
// 17(3)(b) with the personal data minimised to what the obligation requires, and
// operator audit keeps the pseudonym while the key that resolves it is destroyed
// (compliance.md §7). The mail that precedes this event says so explicitly: a
// confirmation implying total deletion when tax records survive is a misleading
// statement about processing.
//
// # No personal data, and less than usual
//
// A pseudonym and a timestamp. There is no actor: by the time this is appended
// the request that caused it is minutes-to-days old and already recorded, and an
// actor here would be a second copy of a fact whose subject can no longer be
// resolved anyway.
type UserErased struct {
	SubjectID string

	ErasedAt time.Time
}

func (*UserErased) EventType() string { return "identity.UserErased.v1" }

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

// ---------------------------------------------------------------------------
// Username reservation
//
// The public handle (ADR-051). Three events, and the split mirrors the email
// trio one section above for the same reason: the CLAIM is a fact about a handle
// and lives on the handle's own stream, while the ASSIGNMENT is a fact about an
// account and lives on the account's stream. One event cannot be appended to two
// streams, and collapsing them would leave an account believing it holds a
// handle no reservation records, or a reservation held by an account that does
// not know it.
//
// Unlike the email trio there is no lease, no expiry and no release. A handle is
// claimed by an account that has just PROVEN its address (identity.md §4.6), so
// there is no unverified claim to lapse — and the one terminal transition,
// UsernameTombstoned, is permanent by design.
//
// These are the first events in this module whose payload is CLEARTEXT text a
// person chose. That is the deliberate exception ADR-051 records: a handle is
// published by design, so a vault that could shred it would protect nothing
// while every copy that matters sits in somebody else's inbox.
// ---------------------------------------------------------------------------

// UsernameReserved claims a public handle for an account.
//
// This is the uniqueness mechanism, and it is an APPEND rather than a unique
// index for exactly the reason EmailReserved is: uniqueness has to hold at the
// moment of the write, in the log, not eventually in a projection. Two
// simultaneous claims for one handle contend on one stream and one of them loses
// its ENTIRE append.
//
// The stream is named by the handle ITSELF, not by a keyed HMAC. ADR-048 hides
// an email because an email is secret and a stream name is unshreddable; hiding
// a handle would buy nothing — it is published on purpose — and would cost the
// ability to read the log while debugging.
type UsernameReserved struct {
	// Username is the normalized handle. It is also what names the stream, so it
	// is present here for the projector, which does not parse stream names.
	Username string

	// SubjectID is the account that now holds the handle. Permanently: nothing
	// releases a handle back into circulation.
	SubjectID string

	ReservedAt time.Time
}

func (*UsernameReserved) EventType() string { return "identity.UsernameReserved.v1" }

// UsernameAssigned records that an ACCOUNT has a handle.
//
// Separate from UsernameReserved because the two live on different streams, and
// present at all because the aggregate that decides an account's future must be
// able to answer "what is this account's handle?" from the account's OWN log. A
// projection cannot serve that: erasure must tombstone the handle it is
// destroying, that decision is a write, and a write decided from an eventually
// consistent read can be decided twice with two different answers.
type UsernameAssigned struct {
	SubjectID string

	// Username is the normalized handle, in the clear. See the section comment.
	Username string

	AssignedAt time.Time
}

func (*UsernameAssigned) EventType() string { return "identity.UsernameAssigned.v1" }

// UsernameTombstoned burns a handle forever.
//
// Recorded when an account is erased. Erasure elsewhere in this system is the
// destruction of a key (ADR-002), and key destruction does nothing to a value
// that was published — so a handle has to be DELETED from the projection, and
// deletion alone is not enough.
//
// # Why the handle may never be reissued
//
// Because every old mention, link and cached reference would silently re-point
// at a stranger. An erasure request is a privacy action taken to protect
// somebody; reissuing their handle would turn it into an impersonation vector
// aimed at that same person, arriving through the control they used to defend
// themselves.
//
// # Why retaining it after an erasure is lawful, and how that is made true
//
// It is data kept after an erasure request, so it needs a justification rather
// than a convention. Two: it protects THIRD PARTIES — readers of old content,
// who would otherwise be deceived — rather than the controller, and it retains
// NO PERSONAL DATA.
//
// The second half is carried by the type. There is no SubjectID field, no actor
// and no field naming the account, and the absence is the enforcement: a
// tombstone is a reservation with no owner, and nothing here can be joined back
// to the person who held it.
type UsernameTombstoned struct {
	// Username is the handle being burned. Cleartext, and the only field that
	// could be: it is what the reservation stream is named after, so hiding it
	// here would hide it from the projector and from nobody else.
	Username string

	TombstonedAt time.Time
}

func (*UsernameTombstoned) EventType() string { return "identity.UsernameTombstoned.v1" }

// ---------------------------------------------------------------------------
// Email change (identity.md §12)
// ---------------------------------------------------------------------------

// Cancellation reasons for a pending email change. Stored in the event, so they
// are permanent strings rather than an enum whose meaning depends on ordering in
// a Go file.
const (
	// CancelSuperseded is a second change request replacing the first. Routine.
	CancelSuperseded = "superseded"

	// CancelPasswordReset is identity.md §4.4 being enforced.
	//
	// The variant it closes is Sudhodanan & Paverd's "unexpired email change":
	// an attacker queues a change to their own address, the victim recovers the
	// account believing they have secured it, and the queued change completes
	// afterwards and hands it straight back.
	CancelPasswordReset = "password_reset"

	// CancelByHolder is the account holder calling it off from a session.
	CancelByHolder = "cancelled_by_holder"
)

// EmailChangeRequested records that an account asked to move to a new address.
//
// # Nothing has changed yet, and that is the whole design
//
// The account still answers to the old address, still signs in with it, and
// still receives its mail there. What this records is a CLAIM on the new address
// plus a deadline: identity.md §12 requires the new address to be proven before
// the switch, so an attacker with a hijacked session cannot silently take
// ownership by asserting an address they do not control.
//
// # Indexes, never addresses
//
// Both are blind indexes (ADR-002). The addresses themselves are in the vault,
// and the token proving the new one is mailed by the reactor, which resolves it
// there — no handler in this module ever holds either address.
type EmailChangeRequested struct {
	SubjectID string

	// FromIndex is the address in force. Recorded so a reader of the log can see
	// what the change was FROM without replaying the whole account.
	FromIndex EmailIndex

	// ToIndex is the address being claimed. The reservation on it is a separate
	// fact on a different stream, for the same reason EmailVerified and
	// EmailReservationConfirmed are separate.
	ToIndex EmailIndex

	// ExpiresAt is when the pending change lapses if it is never confirmed.
	//
	// It bounds the reservation on the new address as much as the change: a
	// claim nobody proves must not hold an address away from its real owner
	// forever, which is the same rule an unverified registration obeys.
	ExpiresAt time.Time

	RequestedAt time.Time
}

func (*EmailChangeRequested) EventType() string { return "identity.EmailChangeRequested.v1" }

// EmailChangeCancelled ends a pending change without completing it.
//
// The reason is load-bearing rather than descriptive: `password_reset` is
// identity.md §4.4 being enforced, and an operator asking "was this account's
// pending change killed by a recovery" is asking a security question the log has
// to answer.
type EmailChangeCancelled struct {
	SubjectID string

	// ToIndex is the address that was being claimed and now is not. The
	// reservation on it is released by its own event on its own stream.
	ToIndex EmailIndex

	Reason      string
	CancelledAt time.Time
}

func (*EmailChangeCancelled) EventType() string { return "identity.EmailChangeCancelled.v1" }

// EmailChanged is the switch itself.
//
// Appended only after the new address is proven by a token mailed to it, and in
// the same atomic append as the reservation events for both addresses — the
// account's identifier and the two claims backing it cannot disagree, so they
// cannot be written separately.
//
// Per identity.md §4.4 this voids every session for the subject, with no
// exception for the one that asked. The re-verification IS the trigger, so the
// "unexpired session" variant is closed at the instant the identifier changes.
type EmailChanged struct {
	SubjectID string

	FromIndex EmailIndex
	ToIndex   EmailIndex

	// RevertibleUntil is the end of the window in which the OLD address can undo
	// this (identity.md §12).
	//
	// The old address is not released at this point; it is demoted to an
	// unverified claim expiring here, so it stays unavailable to everybody else
	// for the window and frees itself afterwards with no sweep. Releasing it
	// outright would let whoever performed the change immediately re-register it
	// and make the revert impossible — which is the attack the window exists to
	// defeat.
	RevertibleUntil time.Time

	ChangedAt time.Time
}

func (*EmailChanged) EventType() string { return "identity.EmailChanged.v1" }

// EmailChangeReverted puts the previous address back.
//
// Reached from a link mailed to the OLD address, so the party undoing the change
// has proven control of the address the account had before it. That is the
// remedy identity.md §12 asks for: an attacker holding a session can change the
// address, but cannot stop the real owner being told and undoing it.
//
// It voids every session exactly as the change did, for the same reason — the
// party who performed the change may still be holding one.
type EmailChangeReverted struct {
	SubjectID string

	// FromIndex is the address being abandoned, which is the one the change
	// moved TO. ToIndex is the address being restored.
	FromIndex EmailIndex
	ToIndex   EmailIndex

	RevertedAt time.Time
}

func (*EmailChangeReverted) EventType() string { return "identity.EmailChangeReverted.v1" }

// EmailReservationDemoted turns a VERIFIED claim back into a leased one.
//
// One producer: the old address during an email change's revert window. The
// address stays held by the same subject, so nobody else can take it, but it now
// carries a deadline — and `EmailReservation.Reserve` already releases a lapsed
// unverified claim before granting a new one, so the address frees itself when
// the window closes and no sweep has to remember it.
//
// It is a distinct event rather than a second EmailReserved because the log
// should say what happened. "Reserved" for an address that was confirmed years
// ago reads as a new registration; this reads as what it is.
type EmailReservationDemoted struct {
	Index     EmailIndex
	SubjectID string

	// ExpiresAt is when the claim lapses. For a revert window it is the same
	// instant as EmailChanged.RevertibleUntil, so the address stops being
	// reclaimable at exactly the moment the revert stops being possible.
	ExpiresAt time.Time

	Reason    string
	DemotedAt time.Time
}

func (*EmailReservationDemoted) EventType() string { return "identity.EmailReservationDemoted.v1" }

// ---------------------------------------------------------------------------
// Passkeys (WebAuthn) — identity slice 2, ADR-057
// ---------------------------------------------------------------------------

// PasskeyRegistered records that an account gained a WebAuthn credential.
//
// # What is here, and what may never be
//
// The credential's ID and nothing else that identifies the key. The PUBLIC KEY
// is deliberately absent, and its absence is a security control rather than
// economy: the log is permanent and replicated, and a credential ID plus a
// public key is exactly the pair WebAuthn L3 §7.1 step 27's takeover needs — an
// attacker registers a victim's pair as their own and the victim signs into the
// attacker's account. Keeping the key out of the log means a replica, a backup
// or a rebuild never hands anybody half of that.
//
// So this event says a passkey EXISTS. `passkey_credential` says what it is, is
// not rebuildable from the log, and is deleted rather than crypto-shredded on
// erasure — there is no subject key to destroy (ADR-057).
type PasskeyRegistered struct {
	SubjectID string

	// CredentialID is the WebAuthn credential id, base64url. It appears in every
	// `allowCredentials` list a browser is handed, so it is not secret — which is
	// precisely why the uniqueness constraint, and not obscurity, is the control.
	CredentialID string

	// Label is what the PERSON called the device. Free text they wrote about
	// their own hardware.
	//
	// It is the one string here a caller chooses, and it is bounded on the wire
	// rather than trusted: a label is rendered on a security screen beside other
	// people's sessions, and an unbounded one is a permanent entry in a log
	// nobody can edit.
	Label string

	// BackupEligible reports whether the authenticator may sync this credential
	// to other devices, and BackupState whether it currently is.
	//
	// Recorded because they change what the credential MEANS: a synced passkey is
	// present on every device the person's account touches, which is why SP
	// 800-63B-4 Appendix B forbids one at AAL3 (IDENTITY-REVIEW C4). Neither is
	// personal data; both are properties of the key.
	BackupEligible bool
	BackupState    bool

	// UserVerified reports whether the registration ceremony proved a PIN or a
	// biometric, not merely possession of the authenticator.
	//
	// It is the difference between AAL1 and AAL2 for this credential
	// (identity.md §2), and it belongs in the event because it is a property of
	// the CREDENTIAL: an authenticator registered without user verification
	// cannot start producing it. Recording it here is what lets the account's
	// activation rule and its removal invariant be decided by replaying the log,
	// rather than by reading a table that is not rebuildable from it.
	UserVerified bool

	RegisteredAt time.Time
}

func (*PasskeyRegistered) EventType() string { return "identity.PasskeyRegistered.v1" }

// PasskeyRemoved records that a credential no longer authenticates.
//
// Refused by the aggregate when it would leave an Active account with no usable
// method, which is the same rule that stops the last TOTP factor being removed.
// A person who deletes their only passkey from a device they no longer have is
// not helped by an endpoint that lets them.
type PasskeyRemoved struct {
	SubjectID    string
	CredentialID string

	// ActorID is who removed it. Normally the holder; recorded separately
	// because a removal is a security-relevant act and "who did this" is the
	// first question asked about one.
	ActorID string

	RemovedAt time.Time
}

func (*PasskeyRemoved) EventType() string { return "identity.PasskeyRemoved.v1" }

// PasskeyCloneWarning records that an authenticator's signature counter went
// BACKWARDS.
//
// # It is a warning and not a denial, deliberately
//
// The WebAuthn spec lists an out-of-order race as a benign cause, and this
// system treats concurrent sessions as ordinary rather than theoretical
// (identity.md §6, §9). Denying on it would sign people out for using two
// devices at once. So the authentication SUCCEEDS at a reduced assurance and the
// caller is required to step up.
//
// # Why it is an event rather than a log line
//
// `go-webauthn` sets `CloneWarning` on the credential and returns NO ERROR, so
// `FinishLogin` succeeds and an application that never inspects the flag has
// clone detection that does nothing while every test passes. That is the exact
// failure this repository has shipped before — three notification adapters,
// fully built and constructed by no binary. An event is what makes the check
// observable: it is asserted by a test, it reaches the security stream, and its
// absence over a fleet is a measurable fact rather than an assumption.
type PasskeyCloneWarning struct {
	SubjectID    string
	CredentialID string

	// Stored and Presented are the counters, in that order. Both are recorded
	// because the DIFFERENCE is what distinguishes a race — which lands one or
	// two behind — from a cloned authenticator replaying an old counter, which
	// can land arbitrarily far back.
	Stored    uint32
	Presented uint32

	DetectedAt time.Time
}

func (*PasskeyCloneWarning) EventType() string { return "identity.PasskeyCloneWarning.v1" }

// ---------------------------------------------------------------------------
// Federated identity (identity.md §7)
// ---------------------------------------------------------------------------

// Issuer identifies an identity provider.
//
// The OIDC issuer URL for Google, Apple and Entra; a constant for GitHub, which
// issues no ID token and therefore has no issuer of its own. It is half of the
// pair that identifies a person at a provider, and it is stored so a `sub` that
// collides across two providers cannot be one identity.
type Issuer string

// ProviderVerification is what a provider says about an address, and it is
// TRI-STATE.
//
// identity.md §7 rule 6: `verified`, `unverified`, or NOT ASSERTED — and the
// third is not the second. Entra emits no trustworthy signal at all and GitHub's
// noreply addresses assert verification for something that is not deliverable
// mail; collapsing either into `false` loses the distinction between "the
// provider says no" and "the provider did not say", which is the difference
// between refusing an auto-link and refusing to consider one.
type ProviderVerification string

const (
	// VerificationNotAsserted is the DEFAULT, and the zero value deliberately:
	// a build that forgets to set this gets the answer that grants nothing.
	VerificationNotAsserted ProviderVerification = ""

	// VerificationVerified means the provider asserts it verified the address.
	VerificationVerified ProviderVerification = "verified"

	// VerificationUnverified means the provider asserts it did NOT.
	VerificationUnverified ProviderVerification = "unverified"
)

// FederatedIdentityLinked records that an account gained a provider identity.
//
// # What is here, and what may never be
//
// The issuer and the provider's IMMUTABLE subject identifier, and nothing else.
// No email, no display name, no profile picture URL — all of them are personal
// data and belong in the vault (ADR-002), and the address in particular must
// never be the thing a link is matched on (§7 rule 5).
//
// # The rule this event's existence makes reachable
//
// A link attached to an account the linking party has not proven control of is a
// TROJAN IDENTIFIER: the attacker attaches their own provider identity to the
// victim's account and it survives every later recovery, because a reset changes
// the password and leaves the link alone. So a link may only be created by a
// session that has proven the account, and §4.4 requires a reset to void every
// link the acting party did not prove.
type FederatedIdentityLinked struct {
	SubjectID string

	Issuer Issuer

	// ProviderSubject is the provider's own immutable identifier — `sub` for
	// Google and Apple, the numeric id for GitHub, and the `tid`+`oid` tuple for
	// Entra, joined.
	//
	// NEVER an email address. §7 rule 5: matching on email is the takeover this
	// whole section exists to prevent, and an identifier that can change is not
	// an identity.
	ProviderSubject string

	// EmailVerification is what the provider claimed about the address at the
	// moment of linking, kept because the auto-link decision turns on it and an
	// auditor asking "why was this allowed" needs the answer the code saw.
	EmailVerification ProviderVerification

	// AutoLinked distinguishes a link the SYSTEM made on a verified-email match
	// from one a person made deliberately from settings.
	//
	// Recorded because the two carry different risk and §4.4 treats them
	// differently on recovery: a link somebody explicitly created while
	// authenticated was proven by them, and one made automatically was proven by
	// a provider's claim.
	AutoLinked bool

	LinkedAt time.Time
}

func (*FederatedIdentityLinked) EventType() string {
	return "identity.FederatedIdentityLinked.v1"
}

// FederatedIdentityUnlinked records that a provider identity no longer signs in.
//
// Refused by the aggregate when it would leave the account with no usable way to
// authenticate — identity.md §7's de-linking rule, which names the case
// precisely: removing the last federated link from a PASSWORDLESS account, whose
// holder would then have nothing at all.
type FederatedIdentityUnlinked struct {
	SubjectID string

	Issuer          Issuer
	ProviderSubject string

	// Reason distinguishes a person removing a link from §4.4 voiding one.
	//
	// Load-bearing rather than descriptive: "was this link killed by a recovery"
	// is a security question, and the log has to answer it.
	Reason string

	// ActorID is who did it. Empty for a system-initiated void, which is itself
	// the answer: nobody chose it.
	ActorID string

	UnlinkedAt time.Time
}

func (*FederatedIdentityUnlinked) EventType() string {
	return "identity.FederatedIdentityUnlinked.v1"
}

// Reasons a federated link ends.
const (
	// UnlinkByHolder is the account holder removing it from settings.
	UnlinkByHolder = "unlinked_by_holder"

	// UnlinkPasswordReset is identity.md §4.4 being enforced.
	//
	// The variant it closes is Sudhodanan & Paverd's TROJAN IDENTIFIER: an
	// attacker pre-attaches a provider identity they control, the victim
	// recovers the account believing they have secured it, and the attacker
	// signs straight back in through a link the reset never touched.
	UnlinkPasswordReset = "password_reset"

	// UnlinkErased is the account being erased.
	UnlinkErased = "erased"
)
