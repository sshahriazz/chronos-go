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
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
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
}

// ErrTokenNotFound covers unknown, spent and expired digests alike.
var ErrTokenNotFound = errors.New("identity: no such token")

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
