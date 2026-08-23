// Package app holds identity's use cases and the ports they need.
//
// Ports are declared HERE, by the consumer, and satisfied in adapter/
// (CONVENTIONS §1.1). That direction is what keeps every use case testable with
// a fake and stops an adapter's shape leaking into a business rule.
package app

import (
	"context"
	"errors"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// PasswordHasher turns a password into a stored verifier, and checks one.
//
// The port deliberately has no "compare these two hashes" method. Comparison is
// the hasher's job because only it knows the parameters, the pepper version and
// the constant-time discipline — a caller handed two byte slices will eventually
// compare them with ==, and the timing side channel that opens is invisible in
// every test.
type PasswordHasher interface {
	// Hash produces a verifier bound to this user and credential.
	//
	// Both ids are authenticated into the ciphertext, so a verifier row copied
	// from one account to another fails to open rather than validating the
	// attacker's own password against the victim's account.
	Hash(ctx context.Context, password string, user ids.UserID, cred ids.CredentialID) (string, error)

	// Verify reports whether the password matches the stored verifier.
	//
	// A mismatch is (false, nil) — an ordinary outcome, not an error. An error
	// means the check could not be PERFORMED: the pepper key is unreachable, the
	// stored value is corrupt. The distinction decides whether the caller
	// records a failed attempt against the user or an outage against itself.
	Verify(ctx context.Context, password, verifier string, user ids.UserID, cred ids.CredentialID) (bool, error)

	// NeedsRehash reports whether a verifier was produced below current policy —
	// weaker parameters, an older pepper key version, an older algorithm.
	//
	// Called after a SUCCESSFUL verify, which is the only moment the plaintext
	// exists and a rehash is possible.
	NeedsRehash(verifier string) bool

	// PepperVersion reports the transit key version Hash is currently sealing
	// verifiers under.
	//
	// It is on the hasher because the hasher is the only component that knows it,
	// and it is on the PORT because a stored verifier is useless without it: the
	// version is duplicated into its own column so the rotation job can find rows
	// sealed under an old key with `pepper_version < n` rather than parsing every
	// verifier in the table.
	//
	// The value must be >= 1, and the floor is not decoration. A row written at 0
	// is invisible to that query, so the rotation job skips it silently and the
	// account is locked out permanently the moment the old transit key is
	// destroyed — a failure that appears months after the mistake, with nothing
	// left to reconstruct the password from.
	PepperVersion() int32
}

// ErrVerifierUnreadable means a stored verifier could not be parsed or opened.
//
// It is NOT a wrong password. Treating it as one would mean a pepper key rotated
// out of existence looks exactly like every user suddenly typing wrongly — the
// support tickets say "wrong password" and the cause is an operational mistake
// nobody is looking for.
var ErrVerifierUnreadable = errors.New("identity: stored password verifier cannot be read")

// TotpSealer encrypts the TOTP shared secret for storage, and recovers it.
//
// It is the one authentication secret in this system that is SEALED rather than
// digested, and the reason is structural: RFC 6238 derives the code from the
// secret, so verification needs the plaintext back. A one-way function — the
// treatment every password verifier, token and recovery code gets — would produce
// a credential nothing could ever check.
//
// The port has no Compare method for the same reason PasswordHasher has none:
// only the implementation knows the encoding, the key version and the binding,
// and a caller handed two strings will eventually compare them with ==.
//
// There is no context parameter. The keys are held in memory (see the totpseal
// package), so there is no round trip to cancel, and an unused ctx on a port is a
// promise of cancellability that nothing behind it honours.
type TotpSealer interface {
	// Seal encrypts a shared secret, bound to this subject and credential.
	//
	// Both ids are authenticated into the ciphertext, so a row copied from one
	// account to another fails to open rather than handing the attacker a working
	// second factor on an account they chose.
	Seal(secret, subjectID string, cred ids.CredentialID) (string, error)

	// Open recovers a shared secret.
	//
	// Returns ErrSecretUnreadable when the value does not authenticate. It is
	// never "the code was wrong" — see that error's doc.
	Open(sealed, subjectID string, cred ids.CredentialID) (string, error)

	// KeyVersion reports the key version Seal is currently sealing under, for the
	// `pepper_version` column. It must be >= 1: a row at 0 is invisible to the
	// re-sealing job's `pepper_version < n` query, so it is skipped silently and
	// the account loses its second factor when the old key is destroyed.
	KeyVersion() int32
}

// ErrSecretUnreadable means a stored TOTP secret could not be parsed or opened.
//
// It is NOT a wrong code, and conflating the two is how a key destroyed too early
// looks exactly like every user suddenly mistyping: the tickets say "my
// authenticator stopped working" and the cause is an operational mistake nobody
// is looking for. The caller still answers the WIRE identically for both — a
// distinguishable response would say which accounts have a second factor
// enrolled — and distinguishes them in the log.
var ErrSecretUnreadable = errors.New("identity: stored TOTP secret cannot be read")

// TotpSecrets stores the sealed TOTP shared secret.
//
// It is the second consumer of the `credential` table and the second port that is
// NOT a projection: like a password verifier, a shared secret may never enter an
// event (identity.md §4, ADR-002), so these rows are authoritative and a
// projection rebuild must not be able to reach them.
//
// The sealed value is OPAQUE here. This port does not open it, does not know its
// encoding and does not hold a key — that belongs to TotpSealer. A store that
// peeked inside would be a second parser for a format with exactly one authority.
type TotpSecrets interface {
	// Provision records a secret that is not yet proven.
	//
	// The row is written UNUSABLE: enrollment is two-step, and a secret the user
	// scanned but never produced a code from may exist only on this side of the
	// exchange. Writing it enabled would let an account satisfy the
	// mandatory-second-factor rule with a factor nobody has ever demonstrated.
	//
	// Idempotent for the same credential id, so a handler that crashed between
	// writing the row and appending its event can retry the whole command.
	Provision(ctx context.Context, secret NewTotpSecret) error

	// Find returns the subject's TOTP credential, PROVEN OR NOT.
	//
	// Deliberately unlike PasswordCredentials.Find, which returns only usable
	// rows: confirmation has to open a secret that is by definition not yet
	// usable. Disabled rows are still excluded — a locked-out authenticator must
	// not be resurrected by a confirmation.
	//
	// Returns ErrNoTotpCredential when there is none. An unknown subject and an
	// account with no authenticator land there together, and the caller must
	// answer both exactly as it answers a wrong code.
	Find(ctx context.Context, subjectID string) (TotpSecret, error)

	// Enable makes a provisioned credential usable, after a live code has proven
	// it.
	//
	// Idempotent: confirming twice is not an error, because the caller wants the
	// credential usable and it is. Returns ErrCredentialNotFound when the row is
	// gone or disabled — which means something removed the authenticator between
	// the verification and this write, and enabling it anyway would restore a
	// factor that was deliberately taken away.
	Enable(ctx context.Context, cred ids.CredentialID) error
}

// NewTotpSecret is everything needed to provision an enrollment.
//
// A struct rather than positional arguments because two of the fields are strings
// that must not be swapped — a pseudonym and an opaque ciphertext — and the
// compiler cannot tell them apart.
type NewTotpSecret struct {
	// ID is minted by the handler and authenticated INTO the sealed secret.
	// Storing it under any other id produces a row that can never be opened, and
	// the failure surfaces when the user next presents a code rather than here.
	ID ids.CredentialID

	// SubjectID is the pseudonym, never an address. It is the other half of the
	// seal's binding.
	SubjectID string

	// Sealed is opaque to this layer. See the interface doc.
	Sealed string

	// KeyVersion duplicates the version encoded inside Sealed so the re-sealing
	// job can select rows without parsing them.
	KeyVersion int32
}

// TotpSecret is a stored enrollment.
//
// Deliberately not the whole row: no created_at, no failure count and no
// disabled_at, because a caller that can see them will eventually make an
// authentication decision from them, and the only decisions this port supports
// are the two it already made — this row exists, and this is whether it is proven.
type TotpSecret struct {
	ID        ids.CredentialID
	SubjectID string

	// Sealed is opaque. Hand it to TotpSealer.Open; never compare it.
	Sealed string

	KeyVersion int32

	// Enabled reports whether the enrollment has been proven. It is reported
	// rather than filtered on so a confirmation can find its own pending row.
	Enabled bool
}

// ErrNoTotpCredential means the subject has no authenticator enrolled.
//
// Unknown subject, never-enrolled account and disabled authenticator all land
// here and cannot be told apart: a caller that could distinguish them would be an
// oracle for which accounts have a second factor, which is precisely the list an
// attacker choosing targets wants.
var ErrNoTotpCredential = errors.New("identity: no TOTP credential")

// RecoveryCodes stores recovery-code digests and spends them.
//
// Digests, never codes. A recovery code is a user-presented secret checked for
// equality, so the same rule as an emailed token applies — store what a
// presentation hashes to, and a stolen database yields nothing presentable.
type RecoveryCodes interface {
	// Credential returns the recovery-code credential this subject's digests hang
	// from, spent or not.
	//
	// It exists so a regenerated set reuses the id the store already holds. The
	// alternative — mint a fresh id every time — collides with the partial unique
	// index that allows one usable credential per kind, and it collides for good:
	// a handler that crashed after writing rows and before appending its event
	// would then fail on every retry, leaving the account unable to generate codes
	// at all.
	//
	// Returns ErrNoRecoveryCode when there is none.
	Credential(ctx context.Context, subjectID string) (ids.CredentialID, error)

	// Replace swaps the WHOLE set atomically, and creates the credential row the
	// digests hang from.
	//
	// Whole-set replacement, never incremental top-up: a mix of old and new codes
	// makes "how many do I have left" unanswerable and leaves codes the user
	// believes were replaced still live. The delete and the inserts are one
	// transaction, so there is no instant at which the account has no codes while
	// believing it has ten.
	Replace(ctx context.Context, set NewRecoveryCodeSet) error

	// Consume redeems one digest exactly once and returns which credential owned
	// it.
	//
	// Must be ATOMIC, in ONE statement. A read-then-write races two presentations
	// of the same code and both win, which is exactly what an attacker holding a
	// photographed sheet produces on purpose.
	//
	// Returns ErrNoRecoveryCode for a digest that is unknown, already spent, or
	// belongs to another subject. The three are deliberately one answer.
	Consume(ctx context.Context, subjectID string, digest []byte) (ids.CredentialID, error)
}

// NewRecoveryCodeSet is a freshly minted set, ready to store.
type NewRecoveryCodeSet struct {
	// CredentialID is the recovery-code credential the digests belong to. The
	// digest rows carry a foreign key to it, so it is created by the same
	// transaction rather than assumed to exist.
	CredentialID ids.CredentialID

	SubjectID string

	// Digests are 32 bytes each — the column has a CHECK to that effect — and are
	// all this system ever learns about the codes it issued.
	Digests [][]byte

	// GeneratedAt is when the set became usable, UTC.
	GeneratedAt time.Time
}

// ErrNoRecoveryCode means the presented code matched no unspent digest.
var ErrNoRecoveryCode = errors.New("identity: no such recovery code")

// TotpVerifier checks a code and claims its time step.
//
// Satisfied directly by the totp adapter's Authenticator. The claim is part of
// the same call rather than a second one the caller could forget: a verifier that
// only returned "valid" would leave replay protection optional, and optional
// replay protection is absent replay protection for the one caller that forgets
// (ADR-049).
type TotpVerifier interface {
	// Verify reports whether the code is valid, and spends its step.
	//
	// (false, nil) is a wrong code. (false, ErrCodeReplayed) is a VALID code
	// presented a second time — a different fact, worth alerting on, and still the
	// same refusal on the wire.
	Verify(ctx context.Context, secret, code string, cred ids.CredentialID, now time.Time) (bool, error)
}

// TotpEnrollment is a freshly minted shared secret and its provisioning URI.
type TotpEnrollment struct {
	// Secret is base32. It is returned to the enrolling user exactly once and must
	// never be logged, echoed back, or placed in an event.
	Secret string

	// URI is the otpauth:// value the QR code encodes. It CONTAINS THE SECRET and
	// the account label, which is personal data, so it goes to the enrolling
	// user's own screen and nowhere else.
	URI string
}

// TotpEnroller mints a shared secret and its provisioning URI.
//
// A FUNCTION type rather than an interface, for the same structural reason
// TokenDigest is one: the adapter that generates these imports this package for
// TOTPReplayGuard, so this package cannot import it back to name its return type.
// A func type is satisfied by a three-line adapter at the composition root
// without either side gaining a dependency on the other.
type TotpEnroller func(accountName string) (TotpEnrollment, error)

// TOTPReplayGuard records that a time step has been used, and refuses a repeat.
//
// RFC 6238 §5.2 requires it: a code stays valid for its whole time step, and for
// the skew window either side of it, so without this an observed code — from a
// shoulder-surf, a screenshot, a log line, a phishing relay — can be presented
// again inside that window and will validate.
//
// It is a PORT rather than an in-process map because the check has to hold
// across every instance. A per-process map means an attacker replays the code
// against a different pod and it works, which is worse than no protection at all
// because the tests all pass.
//
// The implementation is a UNIQUE constraint, not a cache: this is a security
// control, and "the entry was evicted under memory pressure" is not an
// acceptable reason to accept a replayed code.
type TOTPReplayGuard interface {
	// Claim records (credential, step) as used, or returns ErrCodeReplayed if it
	// already was.
	//
	// Must be ATOMIC. A read-then-write races two simultaneous presentations of
	// the same code, and both win — which is exactly the situation an attacker
	// relaying a code engineers.
	Claim(ctx context.Context, cred ids.CredentialID, step int64, expiresAt time.Time) error
}

// ErrCodeReplayed means a valid code was presented a second time.
//
// Distinct from a wrong code, and the distinction is a real signal: a wrong code
// is a typo, a replayed one means somebody has OBSERVED a genuine code. It is
// recorded as contract.ReasonReplayedCode and is worth alerting on.
var ErrCodeReplayed = errors.New("identity: this code has already been used")

// TokenPurpose scopes a single-use token to one flow.
//
// It is part of the stored digest's identity, not a label beside it. Without
// that binding, a token issued to VERIFY an address can be presented to RESET a
// password — and an attacker who can cause a verification mail to be sent (by
// registering, or by triggering a resend) obtains a password-reset token for an
// account they do not own.
type TokenPurpose string

const (
	// PurposeEmailVerification proves control of an address.
	PurposeEmailVerification TokenPurpose = "email_verification"

	// PurposePasswordReset authorises setting a new password.
	PurposePasswordReset TokenPurpose = "password_reset"

	// PurposeEmailChange proves control of an address an account is MOVING TO.
	//
	// Distinct from PurposeEmailVerification, and the separation is the control
	// this type exists for. A verification token is issued to anybody who
	// registers or asks for a resend; if a change accepted one, an attacker who
	// can cause a verification mail for an address they own — by registering it —
	// would hold a token that completes a change on somebody else's account.
	PurposeEmailChange TokenPurpose = "email_change"

	// PurposeEmailChangeRevert authorises undoing a completed change.
	//
	// Mailed to the address the account moved AWAY from, so whoever redeems it
	// has proven control of the address the account had before. That is the whole
	// remedy identity.md §12 asks for: an attacker holding a session can move the
	// address and cannot stop the real owner undoing it.
	PurposeEmailChangeRevert TokenPurpose = "email_change_revert"
)

// TokenStore holds single-use token digests.
//
// Consume is the whole interface's reason for existing, and it must be ATOMIC.
// A read-then-delete races two presentations of the same token and both win,
// which turns a single-use reset link into a multi-use one — exactly what an
// attacker who intercepted the mail wants.
type TokenStore interface {
	// Issue records a digest against a subject, until expiresAt.
	Issue(ctx context.Context, purpose TokenPurpose, subjectID string, digest []byte, expiresAt time.Time) error

	// Consume redeems a digest exactly once and returns whose it was.
	//
	// Returns ErrTokenNotFound for a digest that is unknown, already spent, or
	// expired. The three are deliberately indistinguishable: telling a caller
	// that a token WAS valid but is expired confirms that the address it was
	// sent to has an account.
	Consume(ctx context.Context, purpose TokenPurpose, digest []byte, now time.Time) (subjectID string, err error)

	// RevokeAll drops every outstanding token of a purpose for a subject.
	//
	// Required by identity.md §7 rule 7: verification, reset and recovery void
	// every other outstanding token. Without it, two reset links can be live at
	// once and using one leaves the other usable.
	RevokeAll(ctx context.Context, purpose TokenPurpose, subjectID string) error

	// RevokeAllPurposes drops every outstanding token for a subject, whatever it
	// was issued for.
	//
	// identity.md §4.5 requires a completed reset to void every outstanding token
	// of EVERY purpose, not only reset tokens, and this is the method that
	// obeys it. The variant it closes is the "trojan token": an attacker who
	// triggered a verification mail — by registering, or through
	// ResendEmailVerification — holds a live link that the victim's recovery does
	// not touch, and redeems it afterwards.
	//
	// It is a separate method rather than a loop over TokenPurpose in the caller
	// for a reason that only shows up later: a loop is correct exactly until
	// somebody adds a purpose and forgets the loop, and the symptom is a token
	// that survives a reset with nothing anywhere to say so. One statement
	// scoped by the subject cannot acquire that gap.
	//
	// Returns how many were dropped, so a caller can record the fact rather than
	// assume it. Zero is an ordinary outcome — the reset token that was just
	// consumed is already gone.
	RevokeAllPurposes(ctx context.Context, subjectID string) (int, error)
}

// ErrTokenNotFound covers unknown, spent and expired digests alike.
var ErrTokenNotFound = errors.New("identity: no such token")

// MintedToken is a freshly generated single-use secret, in the two forms the
// system needs it in and the one deadline that bounds it.
//
// The two forms are deliberately produced together and by ONE component. A
// caller that received only the plaintext would have to derive the digest
// itself, and the moment two places derive it, one of them can derive it
// differently — a purpose left out, a separator changed — and every redemption
// then looks up a row that was never written. That failure is silent on both
// sides: the issue succeeds, the mail is sent, and the link is simply refused.
type MintedToken struct {
	// Plaintext is the secret that goes into the emailed URL. It is produced
	// exactly once and must never be stored, logged, returned to an API caller,
	// or placed in an event — a token in any of those is a live credential
	// sitting in a medium that outlives it by months.
	Plaintext string

	// Digest is the only form that reaches storage. See TokenDigest: the purpose
	// is mixed INTO it, so this value is meaningless to a lookup made under any
	// other purpose.
	Digest []byte

	// ExpiresAt is when the token stops being redeemable, UTC. It comes from the
	// minter rather than from the caller because the lifetime is a property of
	// the PURPOSE — a reset link is far more dangerous than a verification link
	// and gets a much shorter window — and a caller free to choose it will
	// eventually choose the long one for both.
	ExpiresAt time.Time
}

// TokenMinter produces a single-use token for a purpose.
//
// A FUNCTION type rather than an interface, for the same structural reason
// TokenDigest and TotpEnroller are function types: the adapter that generates
// these imports this package for TokenPurpose, so this package cannot import it
// back to name its return type. A three-line closure at the composition root
// satisfies this without either side gaining a dependency on the other.
//
// It takes `now` rather than reading a clock, so the token's expiry is stamped
// from the SAME instant as the events of the command that issued it. A minter
// with its own clock would put the expiry a few microseconds after the event
// that announces it, which is harmless until a test or an auditor compares the
// two and finds the log disagreeing with the row.
//
// An unknown purpose must be an ERROR, never a default lifetime. A fallback
// hands a newly added flow whichever window happened to be first in a switch,
// and the dangerous direction is the long one.
type TokenMinter func(purpose TokenPurpose, now time.Time) (MintedToken, error)

// BreachChecker reports whether a password appears in a known breach corpus.
//
// The port takes the PASSWORD, not a hash, because the k-anonymity protocol
// needs to compute its own prefix — and because a port that took a hash would
// fix the algorithm here rather than in the adapter.
type BreachChecker interface {
	// Breached reports whether the password is known-compromised.
	//
	// The second return is the corpus name, for the event. An implementation that
	// cannot reach its corpus returns (false, "", err): the caller ALLOWS the
	// login and records that the check did not run. Blocking on an unreachable
	// third party would let an outage at that third party lock every user out.
	Breached(ctx context.Context, password string) (bool, string, error)
}

// EmailIndexer derives the keyed lookup value for an email address.
//
// Two things depend on it and they must agree exactly: the column a projection
// answers "is there an account for this address?" from, and the NAME of the
// stream that enforces uniqueness for it (ADR-044). The port exists because
// deriving the value needs a key, and a key is the one thing domain/ may never
// hold — so the derivation happens here, at the edge of the use case, and the
// domain is handed the result.
//
// The implementation normalizes the address itself, so a caller that has already
// normalized loses nothing by passing the canonical form: the derivation is
// idempotent under normalization by construction.
type EmailIndexer interface {
	// Of returns the blind index for an address, or a validation error when the
	// address is not one this system will accept.
	Of(email string) (contract.EmailIndex, error)
}

// AggregateLoader rebuilds one aggregate from its stream.
//
// It is the READ half of eventsourcing.Repository, and only the read half. A use
// case that writes to two streams at once cannot use Repository.Save — Save
// appends to a single stream, and two sequential single-stream appends are
// exactly the non-atomic pattern the multi-stream append exists to remove. So
// the write side is eventsourcing.MultiAppender, taken directly, and this port
// covers the load.
//
// Declaring it as an interface rather than depending on *eventsourcing.Repository
// is what lets a use-case test drive the "this address is already claimed" and
// "the previous claim has lapsed" branches from a fake, with no store at all.
type AggregateLoader[T eventsourcing.Root] interface {
	// Load returns the aggregate for a stream key. A stream that does not exist
	// is NOT an error: it returns a new aggregate positioned before its first
	// event, so the caller relies on the append precondition to decide rather
	// than on a check that could race.
	Load(ctx context.Context, key string) (T, error)
}

// SubjectVault stores personal data under a pseudonym.
//
// Deliberately narrower than pii.Vault, which it is satisfied by: the whole
// surface here is WRITE. A registration puts an address into the vault and never
// reads one back, and a port that could read is a port through which an address
// can reach a log line, an error message or an event — the three places ADR-002
// exists to keep it out of.
type SubjectVault interface {
	// PutAll stores several fields for one subject in one operation, so a failure
	// cannot leave a half-populated profile behind.
	PutAll(ctx context.Context, id pii.SubjectID, values map[pii.Field]string) error
}

// SubjectAddresses moves a subject's addresses between the vault's slots.
//
// # Why every method is a MOVE and none of them is a read
//
// SubjectVault above is deliberately write-only, and the reason it gives holds
// here just as hard: a port that could read an address is a port through which
// an address reaches a log line, an error message or an event. An email change
// nevertheless has to move addresses around — the new one becomes primary, the
// old one becomes the previous, the revert puts them back — and every one of
// those needs the CURRENT value.
//
// So the moves happen inside the vault adapter and the values never cross this
// boundary. The use case says which transition happened; the adapter is the only
// code that sees an address. That is the same shape as the blind index: identity
// works in pseudonyms and something else does the one operation that cannot.
//
// Each method is IDEMPOTENT, because each is called from a handler whose append
// may be retried. Promoting when there is nothing pending, or restoring when
// there is no previous address, changes nothing and is not an error — the
// aggregate has already decided whether the transition is legal, and this must
// not fail a retry that the aggregate correctly treats as a no-op.
type SubjectAddresses interface {
	// StagePending records the address an email change is claiming.
	//
	// The verification link for a change is mailed HERE and nowhere else: sending
	// it to the primary would mail the proof of a new address to the old one,
	// which proves nothing.
	StagePending(ctx context.Context, id pii.SubjectID, address string) error

	// PromotePending makes the pending address primary and the primary previous.
	//
	// The previous is kept because a revert has to put it back and the event log
	// cannot hold it (ADR-002). identity.md §12 requires the revert window, and
	// the window is worthless if the address it would restore is unrecoverable.
	PromotePending(ctx context.Context, id pii.SubjectID) error

	// DiscardPending forgets a claimed address that was never proven.
	//
	// Called when a change is cancelled or superseded. Without it, an address
	// somebody typed by mistake stays in their vault record and in every subject
	// access request that follows.
	DiscardPending(ctx context.Context, id pii.SubjectID) error

	// RestorePrevious undoes a completed change: the previous address becomes
	// primary again.
	RestorePrevious(ctx context.Context, id pii.SubjectID) error
}

// TokenDigest reduces a presented token to the value the store holds.
//
// A FUNCTION type rather than an interface, for a structural reason rather than
// a stylistic one: the adapter that mints these tokens imports this package for
// TokenPurpose, so this package cannot import it back. A func type is satisfied
// by the adapter's package-level Digest without either side gaining a dependency
// on the other.
//
// The purpose is an argument rather than something the caller prepends, because
// it must be mixed into the digest itself. A token issued to verify an address
// then hashes to a value no reset lookup can match, even if the store forgot to
// filter by purpose.
type TokenDigest func(purpose TokenPurpose, plaintext string) []byte

// UserDirectory resolves a subject pseudonym to the account it names.
//
// This is the one question in the verification flow that the log cannot answer
// cheaply. A verification token is issued against a SubjectID — the pseudonym is
// what travels, by ADR-002 — while the account's events live on a stream named
// from its UserID, and nothing maps one to the other without either this lookup
// or a scan of every user stream in the system.
//
// It reads a PROJECTION and is therefore eventually consistent, which is safe
// here and would not be everywhere: the answer is only used to NAME a stream,
// and every decision made afterwards is made against that stream's events under
// an expected-revision precondition. A stale or missing row costs a failed
// verification the user can retry, never a wrong decision.
type UserDirectory interface {
	// UserBySubject returns the account id for a subject.
	//
	// Returns ErrNoSuchSubject when nothing is known. That is deliberately the
	// same outcome the caller produces for an unknown token: telling anyone
	// which of the two happened is an account-existence oracle.
	UserBySubject(ctx context.Context, subjectID string) (ids.UserID, error)
}

// ErrNoSuchSubject means the directory holds no account for a pseudonym.
var ErrNoSuchSubject = errors.New("identity: no account for that subject")

// AccountDirectory resolves an email blind index to the account claiming it.
//
// This is the LOGIN lookup, and it is a separate port from UserDirectory rather
// than a second method on it because the two are asked in opposite directions: a
// verification knows a pseudonym and needs the account, an authentication knows
// an identifier and needs the pseudonym. Keeping them apart is what lets the
// verification flow stay unable to turn an address into an account.
//
// It reads a PROJECTION, so it is eventually consistent, and that is safe for
// exactly the reason it is safe in UserDirectory: the answer only NAMES a stream,
// and every decision afterwards is taken against that stream's events. A row that
// has not arrived yet costs one failed login the user can retry — never a wrong
// decision — and a row that is stale names an account whose own log then refuses.
type AccountDirectory interface {
	// AccountByEmailIndex returns the account that claims an index.
	//
	// Returns ErrNoSuchAccount when nothing claims it. The caller must answer
	// that identically to a wrong password, down to the cost of the answer: this
	// is the one lookup in the system whose miss is cheap and whose hit is not,
	// which is precisely the shape of an enumeration oracle.
	AccountByEmailIndex(ctx context.Context, index contract.EmailIndex) (Account, error)
}

// Account is the pair of identifiers an authentication needs, and nothing else.
//
// No state, no email index echoed back, no verification flag. A caller holding
// those would eventually decide an authentication from them, and that decision
// belongs to the aggregate rebuilt from the account's own events — the projection
// is behind the log by construction, so a decision taken from it can be taken
// twice with two different answers.
type Account struct {
	UserID    ids.UserID
	SubjectID string
}

// ErrNoSuchAccount means no account claims that identifier.
var ErrNoSuchAccount = errors.New("identity: no account for that identifier")

// AttemptLimiter is the attempt ceiling consulted before any credential work.
//
// Declared as a port over *ratelimit.Limiter so a use-case test can drive both
// the refusal and the DEGRADED branch, which is the one that matters: the limiter
// fails open, and a ceiling that has silently stopped counting is
// indistinguishable from one that is never reached unless the caller surfaces it.
type AttemptLimiter interface {
	// Allow records an attempt against a scope and reports whether it may
	// proceed. Every attempt is counted, allowed or not.
	Allow(ctx context.Context, scope string) (ratelimit.Decision, error)
}

// SessionTokens stores the bearer-token digest that resolves a session.
//
// It is the third identity port that is NOT a projection, and it is authoritative
// for the same reason the other two are: a session token is a secret, so it may
// never enter an event (ADR-002), so no replay can restore it. The projected half
// of a session — who it belongs to, its assurance level, its absolute deadline —
// is written by the session projector from SessionCreated, and a session resolves
// only when BOTH halves exist (migration 00010).
//
// There is no lookup method here. Resolving a token is the authenticator's
// question and lives with the authenticator (S1-25); a login only ever ISSUES.
type SessionTokens interface {
	// Issue records the digest of a freshly minted bearer token.
	//
	// Called AFTER SessionCreated has been appended. Both orders lose something if
	// the process dies between them, and this is the recoverable one — see
	// Authentication.CreateSession, where the reasoning belongs.
	Issue(ctx context.Context, token NewSessionToken) error
}

// NewSessionToken is everything the authoritative half of a session needs.
//
// A struct rather than three positional arguments because the digest and the
// session id are both opaque and the compiler cannot tell a swapped pair apart.
type NewSessionToken struct {
	// Digest is SHA-256 over the token under its own domain separator. The token
	// itself is returned to the caller once and stored nowhere.
	Digest []byte

	SessionID ids.SessionID

	// IdleExpiresAt is the deadline that MOVES. It lives here rather than in the
	// projection because recording each refresh as an event would make every
	// authenticated read a write to the log.
	IdleExpiresAt time.Time
}

// LiveSessions lists the sessions a subject can still use.
//
// The work list for "sign out everywhere". It is READ-ONLY, deliberately: the
// revocation itself is a SessionRevoked event on each session's own stream, and
// the projector clears revoked_at from it. A port that could also write the view
// would be able to end a session with no event saying so, and session_view would
// stop being reconstructable by replaying the log (ADR-019).
//
// A stale list is therefore harmless in one direction and visible in the other: a
// session that has since been revoked is reloaded, found revoked, and skipped,
// while a session created after the list was taken is simply not in it — which is
// why the caller states the instant it asked.
type LiveSessions interface {
	// List returns the unrevoked sessions whose absolute deadline is still ahead
	// of now, newest first.
	List(ctx context.Context, subjectID string, now time.Time) ([]ids.SessionID, error)
}

// PasskeyStore is the system of record for WebAuthn material (ADR-057).
//
// # It is not a projection, and that is the whole shape of it
//
// Nothing here is rebuildable from the event log. A public key never enters an
// event, for the reason a password verifier does not: the log is permanent and
// replicated, and a credential ID plus a public key is exactly the pair WebAuthn
// L3 §7.1 step 27's takeover needs. So this port sits beside PasswordCredentials
// in the one category of identity state written by the code that verifies rather
// than by a projector.
type PasskeyStore interface {
	// Register stores a new credential, or reports ErrPasskeyAlreadyRegistered.
	//
	// The refusal is a SECURITY outcome and not a duplicate-key inconvenience:
	// the credential id is unique across every account, so a collision means
	// somebody is registering an id that already exists in this installation.
	Register(ctx context.Context, c NewPasskey) error

	// Find returns one credential by id, whoever owns it.
	//
	// Deliberately not scoped by subject: an assertion names the credential and
	// the relying party looks it up to learn WHOSE it is. Scoping by a subject
	// the caller supplied would trust the caller's claim about their own
	// identity, which is what the ceremony exists to establish.
	Find(ctx context.Context, credentialID string) (StoredPasskey, error)

	// List returns every passkey an account holds, newest first.
	List(ctx context.Context, subjectID string) ([]StoredPasskey, error)

	// Advance moves the signature counter forward and reports what happened.
	//
	// The monotonic comparison belongs HERE rather than in a use case, because
	// it is an atomic `UPDATE … WHERE sign_count < $new`. In Go it would be a
	// read-modify-write that two concurrent logins can both win.
	Advance(ctx context.Context, credentialID string, presented uint32, at time.Time) (SignCountOutcome, error)

	// Remove deletes one credential, scoped to its owner.
	Remove(ctx context.Context, credentialID, subjectID string) error

	// Erase deletes every credential an account holds, returning how many.
	//
	// DELETED rather than crypto-shredded: this material is not encrypted under
	// a subject key, so there is nothing to destroy that would make it
	// unreadable. It is the one erasure path that removes rows.
	Erase(ctx context.Context, subjectID string) (int, error)
}

// NewPasskey is a credential a completed registration ceremony produced.
type NewPasskey struct {
	CredentialID string
	SubjectID    string

	// PublicKey is the COSE key. Verification material: stored, never displayed,
	// never logged, never placed in an event.
	PublicKey []byte

	SignCount uint32
	AAGUID    []byte

	// Transports are the authenticator's own hints — "usb", "internal",
	// "hybrid" — so a browser can prompt for the right thing.
	Transports []string

	// UserVerified decides AAL2 versus AAL1 for this credential (identity.md
	// §2), and BackupEligible/BackupState describe whether it syncs.
	UserVerified   bool
	BackupEligible bool
	BackupState    bool

	// Label is the person's own name for the device. Bounded before it gets
	// here; it reaches a permanent event and a shared screen.
	Label string

	RegisteredAt time.Time
}

// StoredPasskey is one credential as the store holds it.
type StoredPasskey struct {
	CredentialID string
	SubjectID    string
	PublicKey    []byte
	SignCount    uint32
	AAGUID       []byte
	Transports   []string

	UserVerified   bool
	BackupEligible bool
	BackupState    bool

	Label        string
	RegisteredAt time.Time
	LastUsedAt   time.Time

	// CloneWarnedAt is non-zero once this credential's counter went backwards.
	// Surfaced so a security screen can say so and an operator can ask when.
	CloneWarnedAt time.Time
}

// SignCountOutcome is what an Advance did, and it has three shapes because the
// counter has three meanings.
//
// Separated here rather than collapsed into an error, because two of the three
// are entirely normal and the third is a warning rather than a denial. A caller
// handed a bare error would have to guess which.
type SignCountOutcome struct {
	// Advanced is the ordinary case: the authenticator counted up.
	Advanced bool

	// Regressed means the presented counter was BELOW the stored one. It is a
	// warning and a step-up, never a denial: the spec lists an out-of-order race
	// as a benign cause, and this system treats concurrent sessions as ordinary
	// (identity.md §6, §9). Denying would sign people out for using two devices.
	Regressed bool

	// Stored is the counter the row held, meaningful when Regressed. Reported
	// because the DIFFERENCE is what separates a race — one or two behind — from
	// a cloned authenticator replaying an old value.
	Stored uint32
}

var (
	// ErrPasskeyAlreadyRegistered means the credential id already exists in this
	// installation, for this account or another.
	//
	// WebAuthn L3 §7.1 step 27. Its own error because the caller's response is
	// specific and must never be "replace it": replacing a victim's registration
	// with an attacker's is the takeover the uniqueness exists to prevent.
	ErrPasskeyAlreadyRegistered = errors.New("identity: this passkey is already registered")

	// ErrNoSuchPasskey means no credential is known by that id — or, for a
	// removal, none by that id belonging to that account. One error for both, so
	// a caller cannot use a removal to discover which ids exist.
	ErrNoSuchPasskey = errors.New("identity: no such passkey")
)

// RevocationEpochs invalidates the authorization decisions cached for a
// principal (ADR-045).
//
// # Why a session revocation touches the authorization cache at all
//
// A revoked session stops resolving once the session projection applies
// SessionRevoked, so the bearer token dies on its own. The decision cache does
// not: the kernel keys a cached permit on
// `(principal kind, principal id, relation, resource, epoch)` — see the Valkey
// adapter's decisionKey — and on NOTHING about the session that produced it. No
// session id, no assurance level, no device trust. A permit computed while a
// session was elevated is therefore served to any request that resolves to the
// same principal, for as long as the entry lives (up to authz.MaxDecisionTTL,
// fifteen minutes).
//
// That is the gap this port closes. Bumping the epoch invalidates every decision
// cached for the principal at once, which is the only invalidation available: a
// session revocation is not about one resource, so there is no key to evict and
// no authz.Query to build a tombstone from.
//
// # Why this is an epoch bump and not a tombstone
//
// A tombstone is keyed by an authz.Query — a principal, a relation and a
// resource — and it is cleared by the access projector CONFIRMING that it removed
// the corresponding OpenFGA tuple. A session revocation removes no tuple, so
// nothing would ever confirm one written here: it would sit until its garbage-
// collection TTL, which ADR-045 defines as an alert meaning the access projector
// is broken. Writing a tombstone no projector can answer for would manufacture
// that alert on every sign-out, and an alert that fires routinely is an alert
// nobody reads.
//
// The epoch has the opposite lifecycle and needs no confirmation: it is a
// monotonic counter with no expiry, and bumping it can only ever cause a cache
// MISS, which is answered by asking OpenFGA. Nothing here can grant anything —
// the worst outcome of a spurious bump is one round trip.
//
// # Satisfied by the same adapter the Guard holds
//
// The signature is exactly (*valkey.Authz).BumpEpoch, so the composition root
// passes the object it already built for authz.Decisions rather than
// constructing a second client with its own view of the epoch.
type RevocationEpochs interface {
	// BumpEpoch invalidates every decision cached for the principal.
	//
	// An error means the invalidation did not happen, and it must be reported
	// rather than logged: the caller decides whether a revocation whose cache
	// invalidation failed may be reported as done. It may not — see
	// Authentication.invalidateAuthorization.
	BumpEpoch(ctx context.Context, p authz.Principal) error
}

// SessionRevoker ends every live session for a subject.
//
// Satisfied by *Authentication, whose RevokeAllSessions this is the exact
// signature of. It is declared as a port rather than taken as the concrete type
// so the dependency reads in one direction — registration asks for "something
// that can void sessions", not for the authentication handlers — and so a use
// case that needs the rule can be driven in a test without an event store, a
// session projection and a Valkey client.
//
// # Why registration holds this at all (IDENTITY-REVIEW C8)
//
// Sudhodanan & Paverd, "Pre-hijacked accounts" (USENIX Security 2022), closes
// its five variants with ONE rule: when an identifier becomes verified — and on
// any password reset or recovery — void every session, every pending identifier
// change, and every identifier not proven by the acting party. Verification is
// the moment the system learns WHO it has been talking to, and everything
// established before that moment was established by somebody unproven.
//
// The session half of that rule is the half that is enforceable today, and
// Registration.VerifyEmail is where it is enforced.
type SessionRevoker interface {
	// RevokeAllSessions ends every live session for the subject, sparing only
	// cmd.Except. A verification passes a zero Except: it spares nothing,
	// because it is not performed from a session at all.
	RevokeAllSessions(
		ctx context.Context, cmd RevokeAllSessionsCommand,
	) (RevokeAllSessionsResult, error)
}
