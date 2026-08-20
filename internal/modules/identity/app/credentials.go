package app

import (
	"context"
	"errors"
	"time"

	"github.com/chronos/chronos-go/internal/platform/ids"
)

// PasswordCredentials stores and maintains password verifiers.
//
// This port exists as a separate thing from every other identity store because
// what it holds is the one piece of identity state that is NOT derived. Every
// other table under this module is a projection: emptied and replayed from
// position zero, and correct afterwards. A verifier cannot be, because it may
// never enter an event — an event is permanent and replicated, so a verifier in
// one would survive the password being changed, survive the erasure of
// everything else about the person, and stay offline-crackable forever
// (identity.md §4, ADR-002). The log records THAT a password was set; this port
// holds what actually verifies it.
//
// The consequence runs the other way too, and it is the reason migration 00009
// dropped the credential table's foreign key: a projection rebuild must not be
// able to reach these rows. Losing them means every user resets their password,
// which is recoverable. Putting them in the log is not.
//
// Everything here is therefore written by a COMMAND HANDLER, in a system
// transaction, never by a projector.
//
// The verifier is an opaque string throughout. This port does not parse it, does
// not compare it, and does not know what algorithm produced it — that belongs to
// PasswordHasher, which is the only component that knows the parameters, the
// pepper version and the constant-time discipline. A store that peeked inside
// would be a second parser for a format with exactly one authority, and the two
// would eventually disagree about what is current.
type PasswordCredentials interface {
	// Store records the verifier for a newly set password.
	//
	// Idempotent for the same credential id, so a handler that crashed between
	// appending PasswordSet and writing the verifier can retry the whole command
	// and land in the same state rather than colliding with its own half-finished
	// work.
	//
	// Storing a SECOND usable password for a subject returns
	// ErrPasswordAlreadySet. That is a real answer, not a storage failure: the
	// database holds at most one usable credential per subject per kind, and a
	// handler that hits it is either retrying with a freshly minted credential id
	// or racing another registration. Both want to stop, and neither wants the
	// existing verifier replaced by one bound to a different row.
	Store(ctx context.Context, cred NewPasswordCredential) error

	// StoreFirst records the account's FIRST password verifier, replacing any row
	// left behind by an attempt that failed before it could append.
	//
	// # Why this is not Store
	//
	// Store refuses a second usable password under a new credential id, and that
	// refusal is right for every caller that has one: it is the database saying
	// "this account already has a password", and replacing it would be a silent
	// credential swap.
	//
	// It is wrong for exactly one caller. Setting the first password
	// (Registration.VerifyEmail) writes this row and THEN appends PasswordSet. A
	// crash in between leaves a verifier that no event refers to: the aggregate
	// rebuilt from the log has no password method, so nothing can authenticate
	// against the row and nothing will ever clean it up. The user's recovery is a
	// resend and a second verification — which mints a NEW credential id, hits
	// the partial unique index, and fails. Forever. The account would be
	// permanently unable to acquire the password it never got, and the only
	// evidence would be a constraint name in a log line.
	//
	// So this call replaces instead of refusing, and it is safe to do so for a
	// reason the caller must establish first: the LOG is the authority on whether
	// an account has a password, and domain.User.SetPassword has already refused
	// if it thinks one exists. A row present when the log says there is none can
	// only be that orphan.
	//
	// # The contract on the caller
	//
	// It MUST have taken a successful domain.User.SetPassword decision on the
	// aggregate it loaded, in the same command. Calling this on an account whose
	// log records a usable password destroys a working credential. There is no
	// way for the store to check that itself — it cannot see the stream — which
	// is why it is written here as a precondition rather than implied by the name.
	StoreFirst(ctx context.Context, cred NewPasswordCredential) error

	// Find returns the usable password credential for a subject.
	//
	// "Usable" excludes a disabled credential and one that was never enabled. The
	// filter is here rather than at the call site because a caller handed a
	// disabled row will verify against it and succeed — the lockout then exists
	// in the table and nowhere in the behaviour.
	//
	// Returns ErrNoPasswordCredential when the subject has no usable password.
	// That is an ordinary outcome, not a failure: a passwordless account is a
	// first-class state here (identity.md §4), and it is also what an
	// authentication attempt against an unknown subject looks like. Any other
	// error means the lookup could not be PERFORMED, and the caller must not
	// treat it as "wrong password" — doing so turns a database outage into a
	// global wave of authentication failures that look like user error and are
	// investigated as such.
	Find(ctx context.Context, subjectID string) (PasswordCredential, error)

	// Rehash replaces a verifier with one produced under current policy, but only
	// if the row still holds the verifier that was just verified.
	//
	// The guard is the point. A rehash is computed from the plaintext a login
	// verified, and it is written after that login has returned. If the password
	// was changed in between, an unconditional write would replace the new
	// verifier with a re-encoding of the OLD password — quietly restoring a
	// password the user may have replaced precisely because it was compromised.
	//
	// Returns ErrCredentialMoved when the row no longer matches: changed,
	// disabled, or gone. The caller must DROP the rehash rather than retry it —
	// the verifier it holds is stale by definition, and the next successful login
	// will re-derive a current one. It is not a login failure; the login already
	// succeeded.
	//
	// pepperVersion is passed rather than read out of the verifier: it is a
	// duplicate of a value encoded inside the string, kept as a column so the
	// pepper-rotation job can find rows at an old version without parsing every
	// row, and parsing it here would put a second decoder for the verifier format
	// in the storage layer. It must be a real version (>= 1) — a NULL or zero
	// column is invisible to `pepper_version < n`, so such a row is skipped
	// silently by the rotation job and locked out permanently when the old
	// transit key is destroyed (identity.md §4).
	Rehash(ctx context.Context, cred ids.CredentialID, expected, replacement string, pepperVersion int32) error

	// Replace swaps the verifier of an EXISTING password credential, but only if
	// the row still holds the one the caller decided against.
	//
	// This is the password-reset write, and the compare-and-set is the whole
	// reason it is a distinct method rather than a call to Store.
	//
	// # It is the reset flow's only serialization point
	//
	// Two reset links for one account can be redeemed simultaneously, and both
	// succeed at the token store, because they are different digests in different
	// rows — that concurrency is not exotic, it is what an attacker who triggered
	// a reset and a victim who triggered another produce between them. Both
	// callers then hold a verifier computed from the same expected value. An
	// unconditional write would let both land, and the account would end up with
	// whichever password committed last: one the user may never have typed, with
	// no error raised anywhere. Requiring the row to still hold `expected` makes
	// exactly one of them win, and the loser stops before it appends anything.
	//
	// # The failure count is cleared, and Rehash's is not
	//
	// A consecutive-failure count describes attempts against a password that no
	// longer exists once this returns. Carrying it forward would let a run of
	// guesses against the OLD password lock out the new one, locking out the
	// person who has just proven control of the mailbox. Rehash must not do the
	// same: it runs after a login that already cleared the count, so zeroing it
	// there would erase a run still accumulating against a credential nobody has
	// used successfully.
	//
	// # The contract on the caller
	//
	// `cred` MUST be the credential the ACCOUNT'S OWN EVENT STREAM names as its
	// usable password (domain.User.UsablePasswordCredential), never one read from
	// this table. The log is the authority on which credentials an account has
	// (identity.md §4.2): a row the log cannot account for was written outside
	// the application, and a reset driven from the table would rewrite it as if
	// it were legitimate.
	//
	// Returns ErrCredentialMoved when the row no longer matches — changed,
	// disabled, or gone. That is an ordinary outcome under contention and the
	// caller must ABORT rather than retry: retrying would recompute `expected`
	// from a verifier somebody else just chose, which is a second reset nobody
	// asked for.
	Replace(ctx context.Context, cred ids.CredentialID, expected, replacement string, pepperVersion int32) error

	// RecordSuccess stamps the credential as used and clears its failure count.
	//
	// Clearing on success is what makes the count consecutive rather than
	// lifetime. Without it, an account that has ever accumulated enough failures
	// is locked out for good, however many successful logins came after.
	//
	// Called AFTER the login has been decided, so an error here is bookkeeping
	// that did not happen, not a reason to reject the caller. Returns
	// ErrCredentialNotFound if the row has since vanished.
	RecordSuccess(ctx context.Context, cred ids.CredentialID) error

	// RecordFailure counts one failed attempt and returns the new total.
	//
	// The total comes back from the same statement that wrote it. A second read
	// would be a different transaction's view, so two concurrent failures could
	// both read the pre-increment count and neither would observe the ceiling
	// being crossed — which is exactly the concurrency an online guessing attack
	// produces.
	//
	// Returns ErrCredentialNotFound when there is nothing to count against. The
	// caller must not invent a credential to count on: an attempt against an
	// identifier with no account has no credential, and recording one would
	// create a row that reveals the account does not exist.
	RecordFailure(ctx context.Context, cred ids.CredentialID) (int32, error)

	// Disable locks out ONE authenticator.
	//
	// Per authenticator, never per account. Locking the account on failed
	// attempts hands any attacker a denial of service against every address they
	// can guess, which is a cheaper attack than the one the lockout defends
	// against.
	//
	// Idempotent: disabling an already-disabled credential succeeds. The caller
	// wants the credential unusable, and it is. Reporting an error for a state
	// that is already correct invites a retry loop around a lockout.
	Disable(ctx context.Context, cred ids.CredentialID) error
}

// NewPasswordCredential is everything needed to store a first verifier.
//
// A struct rather than six positional arguments because two of the fields are
// strings that must not be swapped — an id and an opaque verifier — and the
// compiler cannot tell them apart.
type NewPasswordCredential struct {
	// ID is minted by the handler and is authenticated INTO the verifier by the
	// hasher, together with the user id. Storing the verifier under a different
	// id than it was sealed with produces a row that can never be opened, and the
	// failure surfaces at the user's next login rather than here.
	ID ids.CredentialID

	// SubjectID is the pseudonym, never an address or a name. No column in this
	// table holds personal data; the vault resolves the pseudonym at read time
	// (compliance.md §1).
	SubjectID string

	// Verifier is opaque to this layer. See the interface doc.
	Verifier string

	// PepperVersion duplicates the version encoded inside Verifier so the
	// rotation job can select rows without parsing them.
	PepperVersion int32

	// EnabledAt is when the credential became usable. It is required, and it is
	// required for a reason that is invisible until it bites: an unset value
	// leaves enabled_at NULL, the usable-credential lookup filters on
	// `enabled_at IS NOT NULL`, and the account is passwordless with a password
	// row sitting in the table.
	EnabledAt time.Time
}

// PasswordCredential is a stored verifier and the state around it.
//
// Deliberately not the whole row: there is no created_at, no disabled_at and no
// last_used_at here, because a caller that can see them will eventually make an
// authentication decision from them, and the only decision this port supports is
// the one Find already made — this credential is usable.
type PasswordCredential struct {
	ID        ids.CredentialID
	SubjectID string

	// Verifier is opaque. Hand it to PasswordHasher.Verify; never compare it.
	Verifier string

	PepperVersion int32

	// Failures is the CONSECUTIVE failed-attempt count, zero after any success.
	Failures int32

	// EnabledAt is UTC, like every stored time here (ADR-008).
	EnabledAt time.Time
}

var (
	// ErrNoPasswordCredential means the subject has no usable password.
	//
	// Unknown subject, passwordless account and disabled credential all land
	// here, and deliberately cannot be told apart: a caller that could
	// distinguish them would be an oracle for which addresses have accounts and
	// which of those are locked out.
	ErrNoPasswordCredential = errors.New("identity: no usable password credential")

	// ErrPasswordAlreadySet means the subject already has a usable password.
	//
	// Distinct from a storage failure, and the distinction is what lets a
	// registration retry stop cleanly instead of replacing a verifier that
	// already works.
	ErrPasswordAlreadySet = errors.New("identity: the subject already has a usable password")

	// ErrCredentialMoved means a compare-and-set found the row changed.
	//
	// The verifier was replaced, the credential was disabled, or it is gone. The
	// three are one error because the caller's response is the same for all of
	// them — discard the rehash — and because distinguishing them would need a
	// second read whose answer could already be stale again.
	ErrCredentialMoved = errors.New("identity: the credential changed under the write")

	// ErrCredentialNotFound means the named credential does not exist.
	//
	// Used only by the bookkeeping calls, which name a credential the caller has
	// already read. It means something deleted the row underneath a live login,
	// which is worth a log line rather than a retry.
	ErrCredentialNotFound = errors.New("identity: no such credential")
)
