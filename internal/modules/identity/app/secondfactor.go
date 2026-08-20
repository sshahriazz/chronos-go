package app

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// DefaultEnrollmentWindow is how long a provisioned-but-unproven TOTP secret
// stays confirmable.
//
// Short, because the window is the time in which a secret exists that nobody has
// demonstrated possession of. It only has to cover scanning a QR code and typing
// six digits, and a user who takes longer starts again at no cost. The mistake in
// the other direction is expensive and quiet: a long window leaves half-finished
// enrollments confirmable for hours, so a secret captured from a screen — a
// screenshot, a shoulder-surf, a shared screen — remains usable long after the
// user gave up on it.
const DefaultEnrollmentWindow = 15 * time.Minute

const (
	// DefaultRecoveryCodeCount is how many codes a set holds when the caller does
	// not say.
	//
	// Ten is the number the user has to keep somewhere physical, so it trades
	// against being copied down wrongly rather than against entropy — each code
	// carries its own 50 bits, and the set size does not weaken any of them.
	DefaultRecoveryCodeCount = 10

	// MaxRecoveryCodeCount bounds a caller-chosen set.
	//
	// The bound exists because the count is caller-supplied and every code is a
	// row plus a hash: without it, one request asks for a million codes and the
	// handler obliges inside a single transaction. It is a resource bound, not a
	// security one.
	MaxRecoveryCodeCount = 20

	// recoveryCodeBytes is the entropy per code. 80 bits.
	//
	// Well above what an online guessing attack can reach, and it is the ONLY
	// thing standing behind a recovery code — unlike a password there is no second
	// factor after it, because this IS the fallback for when the second factor is
	// gone. Encoded as base32 it produces 16 characters, which is short enough to
	// be written on paper and read back without transcription errors.
	recoveryCodeBytes = 10

	// recoveryCodeGroup is how many characters go between hyphens when a code is
	// shown. Presentation only: hyphens are stripped before hashing, so a user who
	// types them, omits them, or uses spaces gets the same digest.
	recoveryCodeGroup = 4

	// recoveryDigestDomain separates recovery-code digests from every other
	// SHA-256 this system computes.
	//
	// Length-prefixed into the hash below rather than concatenated, so no choice
	// of subject id can shift the boundary and make two different (domain,
	// subject, code) triples collide.
	recoveryDigestDomain = "chronos/identity/recovery_code/v1"
)

// recoveryCodeAlphabet is base32 without padding: A-Z and 2-7.
//
// Chosen for what it EXCLUDES. There is no 0/O, no 1/I/l and no 8/B pair to
// confuse when a code is read off paper, which is the entire failure mode of a
// credential whose storage medium is a printout.
var recoveryCodeAlphabet = base32.StdEncoding.WithPadding(base32.NoPadding)

// SecondFactor is the four commands that give an account something beyond a
// password: enrol an authenticator, prove it, mint recovery codes, and spend one.
//
// # Why the TOTP secret is sealed rather than hashed, and where it lives
//
// It lives in `credential.verifier` with `kind = 'totp'`, encrypted, beside the
// Argon2id password verifier that shares the column. Two properties force that
// and they pull in opposite directions from everything else here:
//
// It cannot be HASHED, because RFC 6238 derives the code from the secret, so
// verification needs the plaintext back. Every other secret this system stores —
// passwords, emailed tokens, the recovery codes below — is one-way precisely
// because nothing ever needs to recover them.
//
// It cannot go in the PII VAULT either, though an earlier comment said it did.
// The vault holds personal data under a per-subject key that erasure destroys
// (ADR-002); a TOTP secret is key material, and filing it there would make a
// subject's crypto-shredding silently take their second factor with it. What the
// vault and this share is only the rule that neither may enter an event.
//
// The seal is AES-256-GCM under a key wrapped by the OpenBao KEK (ADR-028), and
// it is AAD-bound to `subject:credential` exactly as the password hasher binds
// its verifier. That binding is what makes a single write to the credential table
// insufficient for a takeover: a row moved to another account fails to OPEN
// rather than becoming an authenticator the attacker holds the secret for.
//
// # Why recovery codes are hashed and not sealed
//
// The opposite reasoning applies to them, and getting the two backwards is the
// easy mistake. A recovery code is a user-presented secret checked for equality,
// so nothing ever needs it back: store the digest, compare what arrives. They
// come from crypto/rand, so SHA-256 rather than Argon2id — there is no candidate
// list to search, and a slow hash would buy nothing while making the endpoint a
// memory-amplification vector (see adapter/token for the same argument).
//
// # Why recovery codes do not satisfy the second-factor requirement
//
// domain.User.hasRealSecondFactor excludes them deliberately, and this handler
// relies on that rather than re-checking it: an account must not be able to
// answer "enrol a second factor" by printing a sheet of paper. Activation
// happens on TotpEnabled and never on RecoveryCodesGenerated, which is visible
// here as the fact that only ConfirmTotp reports Activated.
type SecondFactor struct {
	clock    clock.Clock
	entropy  io.Reader
	users    AggregateLoader[*domain.User]
	appender eventsourcing.MultiAppender
	enroll   TotpEnroller
	sealer   TotpSealer
	secrets  TotpSecrets
	verifier TotpVerifier
	recovery RecoveryCodes
	window   time.Duration
	count    int
	log      *slog.Logger

	// codeEntropy is the source recovery codes are drawn from, and it is NOT a
	// dependency: it is crypto/rand, always, and is a field only so an in-package
	// test can drive the short-read branch. Exposing it on SecondFactorDeps would
	// make "which entropy source mints the codes" a wiring decision, and the one
	// wrong answer to that question is unrecoverable — codes minted from a
	// predictable source are guessable for as long as the user keeps the sheet.
	codeEntropy io.Reader
	schemas     eventsourcing.SchemaVersions
}

// SecondFactorDeps is everything the four handlers need.
//
// A struct rather than a positional constructor because several of these are
// interfaces over the same machinery, and two transposed arguments of compatible
// shape compile cleanly and fail in production.
type SecondFactorDeps struct {
	Clock    clock.Clock
	Entropy  io.Reader
	Users    AggregateLoader[*domain.User]
	Appender eventsourcing.MultiAppender
	Enroll   TotpEnroller
	Sealer   TotpSealer
	Secrets  TotpSecrets
	Verifier TotpVerifier
	Recovery RecoveryCodes

	// Window overrides DefaultEnrollmentWindow. Zero means the default.
	Window time.Duration

	// RecoveryCodeCount overrides DefaultRecoveryCodeCount. Zero means the
	// default.
	RecoveryCodeCount int

	// Log is optional and defaults to slog.Default(). Nothing here logs a secret,
	// a code or a digest: the only identifiers that reach it are pseudonyms and
	// credential ids.
	Log *slog.Logger
	// Schemas stamps each appended event with its current schema version.
	//
	// Repository.Save does this for single-stream appends; these handlers use
	// MultiAppender and therefore must do it themselves. Without it every event is
	// stored at version 0 while the registry declares 1, so loading the aggregate
	// back demands a 0->1 upcaster that should never exist — the account is
	// writable exactly once and unreadable thereafter, while every projection and
	// dashboard stays green because the read path does not upcast.
	Schemas eventsourcing.SchemaVersions
}

// NewSecondFactor validates the wiring and returns the handlers.
//
// Every dependency is checked. This repository has already shipped three adapters
// that were built, tested and constructed by no binary, so a nil port here would
// surface as a panic during somebody's enrolment rather than as a refusal to
// start.
func NewSecondFactor(deps SecondFactorDeps) (*SecondFactor, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: second factors need %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Entropy == nil:
		return nil, missing("an entropy source")
	case deps.Users == nil:
		return nil, missing("a user loader")
	case deps.Appender == nil:
		return nil, missing("a multi-stream appender")
	case deps.Enroll == nil:
		return nil, missing("a TOTP enroller")
	case deps.Sealer == nil:
		return nil, missing("a sealer; a shared secret stored in the clear is a second " +
			"factor anyone who reaches the database already holds")
	case deps.Secrets == nil:
		return nil, missing("a TOTP secret store")
	case deps.Verifier == nil:
		return nil, missing("a TOTP verifier")
	case deps.Recovery == nil:
		return nil, missing("a recovery-code store")
	case deps.Window < 0:
		return nil, fmt.Errorf("identity/app: an enrollment window may not be negative")
	case deps.RecoveryCodeCount < 0 || deps.RecoveryCodeCount > MaxRecoveryCodeCount:
		return nil, fmt.Errorf("identity/app: a recovery-code set of %d is outside 1..%d",
			deps.RecoveryCodeCount, MaxRecoveryCodeCount)
	case deps.Sealer.KeyVersion() < 1:
		// Checked at wiring time because the consequence is invisible until it is
		// unrecoverable: a row written at version 0 is skipped by the
		// `pepper_version < n` re-sealing query, and the account silently loses its
		// second factor when the old key is destroyed.
		return nil, fmt.Errorf("identity/app: the sealer reports key version %d; a secret "+
			"stored below version 1 is invisible to key rotation", deps.Sealer.KeyVersion())
	}

	window := deps.Window
	if window == 0 {
		window = DefaultEnrollmentWindow
	}
	count := deps.RecoveryCodeCount
	if count == 0 {
		count = DefaultRecoveryCodeCount
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &SecondFactor{
		clock: deps.Clock, entropy: deps.Entropy, users: deps.Users,
		appender: deps.Appender, enroll: deps.Enroll, sealer: deps.Sealer,
		secrets: deps.Secrets, verifier: deps.Verifier, recovery: deps.Recovery,
		window: window, count: count, log: log,
		codeEntropy: rand.Reader,
		schemas:     deps.Schemas,
	}, nil
}

// ---------------------------------------------------------------------------
// TOTP enrolment
// ---------------------------------------------------------------------------

// EnrollTotpCommand asks for a new authenticator secret.
type EnrollTotpCommand struct {
	UserID ids.UserID

	// AccountName is what the user sees under the issuer in their authenticator
	// app, normally their own address. It is PERSONAL DATA: it is placed in the
	// provisioning URI, which is rendered to the enrolling user's screen, and it
	// reaches no event, no log line and no error message from here.
	//
	// It is supplied by the caller rather than read from the vault because the
	// vault port is write-only by design (see SubjectVault) — a port that could
	// read is a port through which an address reaches a log.
	AccountName string

	// IdempotencyKey makes a retried request derive the same event ids, which the
	// store collapses instead of duplicating.
	IdempotencyKey string
}

// EnrollTotpResult carries the provisioning material back to the caller ONCE.
//
// Secret and URI are returned by this call and are then unrecoverable: nothing
// stores them in the clear, and the sealed copy is opened only to check a code.
// A caller that loses them starts the enrolment again, which is the correct
// outcome — the alternative is an endpoint that re-displays a shared secret to
// anyone holding a session, turning a stolen session into a permanent second
// factor.
type EnrollTotpResult struct {
	CredentialID ids.CredentialID

	// Secret is base32, for manual entry. Never log it.
	Secret string

	// URI is the otpauth:// value behind the QR code. It CONTAINS the secret and
	// the account label. Never log it.
	URI string

	ExpiresAt time.Time
	Position  eventsourcing.Position
}

// EnrollTotp provisions a shared secret that is not yet proven.
//
// # Order of operations
//
//  1. load the account and take its pseudonym from its own events
//  2. decide the credential id — reusing an existing enrolment's, see below
//  3. generate the secret and seal it against subject and credential
//  4. let the aggregate decide: a proven authenticator already present is a
//     conflict, and this is where that is refused
//  5. write the sealed row, UNPROVEN
//  6. append TotpEnrollmentStarted
//
// Steps 5 and 6 in that order are the same trade registration makes. A crash
// between them leaves a sealed row nothing references — garbage bound to a
// credential id no event names, unusable by construction because the aggregate
// has no method for it — and the retry succeeds completely. The reverse order
// leaves the log asserting an enrolment whose secret does not exist, which no
// retry repairs because the aggregate then refuses to start another.
//
// # Why an existing row's credential id is reused
//
// The credential table permits one usable credential per kind per subject, so a
// second enrolment under a fresh id collides with the first. Reusing the id the
// store already holds makes a restarted enrolment converge: the upsert replaces
// the secret AND clears enabled_at, so the abandoned secret stops existing at the
// moment the new one is written rather than lingering as a second confirmable
// factor.
func (s *SecondFactor) EnrollTotp(
	ctx context.Context, cmd EnrollTotpCommand,
) (EnrollTotpResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return EnrollTotpResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.UserID.IsZero():
		return EnrollTotpResult{}, errs.ValidationFailedf("a user id is required")
	case strings.TrimSpace(cmd.AccountName) == "":
		// The authenticator app shows this under the issuer. An empty one produces
		// an unlabelled entry, which is how people delete the wrong credential.
		return EnrollTotpResult{}, errs.ValidationFailedf("an account name is required")
	}

	user, err := s.users.Load(ctx, cmd.UserID.String())
	if err != nil {
		return EnrollTotpResult{}, fmt.Errorf("loading the account for an enrolment: %w", err)
	}
	subjectID := user.SubjectID()
	if subjectID == "" {
		return EnrollTotpResult{}, errs.NotFoundf("no such account")
	}

	now := s.clock.Now().UTC()
	credentialID, err := s.enrollmentCredential(ctx, subjectID, now)
	if err != nil {
		return EnrollTotpResult{}, err
	}

	enrollment, err := s.enroll(cmd.AccountName)
	if err != nil {
		return EnrollTotpResult{}, fmt.Errorf("generating a shared secret: %w", err)
	}
	sealed, err := s.sealer.Seal(enrollment.Secret, subjectID, credentialID)
	if err != nil {
		// Refused, never degraded. Storing the secret unsealed because sealing
		// failed would put a working second factor in the clear in the one table an
		// attacker who reaches the database already has.
		return EnrollTotpResult{}, fmt.Errorf("sealing a shared secret: %w", err)
	}

	expiresAt := now.Add(s.window)
	if err := user.StartTotpEnrollment(credentialID, expiresAt, now); err != nil {
		return EnrollTotpResult{}, err
	}

	if err := s.secrets.Provision(ctx, NewTotpSecret{
		ID:         credentialID,
		SubjectID:  subjectID,
		Sealed:     sealed,
		KeyVersion: s.sealer.KeyVersion(),
	}); err != nil {
		return EnrollTotpResult{}, fmt.Errorf("storing a shared secret: %w", err)
	}

	position, err := s.appendUser(ctx, cmd.IdempotencyKey, subjectID, cmd.UserID, user)
	if err != nil {
		return EnrollTotpResult{}, conflictOnRace(err)
	}
	return EnrollTotpResult{
		CredentialID: credentialID,
		Secret:       enrollment.Secret,
		URI:          enrollment.URI,
		ExpiresAt:    expiresAt,
		Position:     position,
	}, nil
}

// enrollmentCredential picks the id a new enrolment is written under.
//
// The store is asked rather than the aggregate, and that is deliberate: the row
// is what the unique index constrains, and a crash between writing it and
// appending its event leaves a row the aggregate knows nothing about. Minting a
// fresh id in that state would collide on every retry, leaving the account unable
// to enrol at all — a self-inflicted lockout with no error a user could act on.
func (s *SecondFactor) enrollmentCredential(
	ctx context.Context, subjectID string, now time.Time,
) (ids.CredentialID, error) {
	existing, err := s.secrets.Find(ctx, subjectID)
	switch {
	case err == nil:
		return existing.ID, nil
	case errors.Is(err, ErrNoTotpCredential):
		return ids.New[ids.Credential](now, s.entropy), nil
	default:
		return ids.CredentialID{}, fmt.Errorf("looking up an existing enrolment: %w", err)
	}
}

// ConfirmTotpCommand presents a live code against a provisioned secret.
type ConfirmTotpCommand struct {
	UserID ids.UserID

	// Code is the six digits from the authenticator. It is never logged, stored,
	// or placed in an event.
	Code string

	IdempotencyKey string
}

// ConfirmTotpResult reports what the confirmation produced.
type ConfirmTotpResult struct {
	CredentialID ids.CredentialID

	// Activated is true when this confirmation was the event that completed the
	// account: a verified address plus a REAL second factor. It is reported here
	// and by no other handler in this file, because a recovery-code set must never
	// be what activates an account.
	Activated bool

	// Changed is false when the authenticator was already proven — a retried
	// confirmation. Nothing was appended, and it is not an error.
	Changed bool

	Position eventsourcing.Position
}

// ConfirmTotp proves an enrolment with a live code and makes it usable.
//
// # Every failure looks the same from outside
//
// A wrong code, an account with no enrolment, a secret that will not open, a
// code that was already spent and an enrolment removed mid-ceremony all produce
// ONE refusal on the wire. The
// alternative is an oracle: an endpoint that answers "you have no authenticator"
// differently from "wrong code" tells an attacker holding a session which
// accounts have a second factor, and that is the list they need to choose targets
// from. The distinctions are made in the LOG, where they belong — a replayed code
// in particular is not user error, it means somebody has OBSERVED a genuine code.
//
// # The replay claim is not made here
//
// TotpVerifier.Verify validates the code and claims its time step in one call,
// atomically and in that order (ADR-049). Claiming first would let a wrong code
// burn the step and deny the legitimate user their next thirty seconds; claiming
// separately would make the claim something a caller could forget.
func (s *SecondFactor) ConfirmTotp(
	ctx context.Context, cmd ConfirmTotpCommand,
) (ConfirmTotpResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return ConfirmTotpResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.UserID.IsZero():
		return ConfirmTotpResult{}, errs.ValidationFailedf("a user id is required")
	case strings.TrimSpace(cmd.Code) == "":
		return ConfirmTotpResult{}, errWrongCode()
	}

	user, err := s.users.Load(ctx, cmd.UserID.String())
	if err != nil {
		return ConfirmTotpResult{}, fmt.Errorf("loading the account for a confirmation: %w", err)
	}
	subjectID := user.SubjectID()
	if subjectID == "" {
		return ConfirmTotpResult{}, errs.NotFoundf("no such account")
	}

	stored, err := s.secrets.Find(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoTotpCredential) {
			s.refused(ctx, subjectID, "no_enrollment")
			return ConfirmTotpResult{}, errWrongCode()
		}
		return ConfirmTotpResult{}, fmt.Errorf("reading an enrolment: %w", err)
	}

	secret, err := s.sealer.Open(stored.Sealed, subjectID, stored.ID)
	if err != nil {
		// An unreadable secret is an OUTAGE, not user error — a key destroyed too
		// early, or a row that was tampered with. It still produces the ordinary
		// refusal, because an internal error here would answer "this account has an
		// enrolment" to anyone who asked. The log is where the two part company.
		s.log.ErrorContext(ctx, "a stored TOTP secret could not be opened",
			"module", "identity", "subject_id", subjectID,
			"credential_id", stored.ID.String(), "key_version", stored.KeyVersion,
			"error", err)
		return ConfirmTotpResult{}, errWrongCode()
	}

	valid, err := s.verifier.Verify(ctx, secret, cmd.Code, stored.ID, s.clock.Now().UTC())
	switch {
	case errors.Is(err, ErrCodeReplayed):
		// A VALID code, presented twice. Not a typo: somebody has seen a real code.
		s.log.WarnContext(ctx, "a TOTP code was replayed",
			"module", "identity", "subject_id", subjectID,
			"credential_id", stored.ID.String(),
			"reason", string(contract.ReasonReplayedCode))
		return ConfirmTotpResult{}, errWrongCode()
	case err != nil:
		// The replay guard could not be consulted. Surfaced rather than refused
		// quietly: it fails closed by construction, and an outage that looks like a
		// wave of wrong codes is an outage nobody investigates. It discloses
		// nothing about the account — every account gets it.
		return ConfirmTotpResult{}, fmt.Errorf("verifying a TOTP code: %w", err)
	case !valid:
		s.refused(ctx, subjectID, "wrong_code")
		return ConfirmTotpResult{}, errWrongCode()
	}

	now := s.clock.Now().UTC()
	if err := user.EnableTotp(stored.ID, now); err != nil {
		if errs.ReasonOf(err) == errs.NotFound {
			// The code checked out against a secret this account's own log does not
			// name — a row written by something other than this handler. Refused as
			// an ordinary wrong code, and recorded loudly, because it is the exact
			// tampering the AAD binding exists to make expensive.
			s.log.ErrorContext(ctx, "a TOTP secret was verified against an enrolment the "+
				"account's own log does not record",
				"module", "identity", "subject_id", subjectID,
				"credential_id", stored.ID.String())
			return ConfirmTotpResult{}, errWrongCode()
		}
		return ConfirmTotpResult{}, err
	}

	// Enabled BEFORE the append, for the same reason the sealed row is written
	// before its event. A crash here leaves a usable row whose event never landed:
	// the aggregate still considers the factor unproven, so nothing authenticates
	// with it, and a retried confirmation converges. The reverse order leaves the
	// log saying the factor is proven while the usable-credential lookup skips the
	// row, which is a second factor the user has enrolled and cannot use.
	if err := s.secrets.Enable(ctx, stored.ID); err != nil {
		if errors.Is(err, ErrCredentialNotFound) {
			// The row was read a few lines above and is gone now: the enrolment was
			// removed between the two calls, so the code that just verified belongs
			// to a secret that no longer exists.
			//
			// This is the account's own state, not an outage, and it is the "no
			// enrolment" case arriving one step later than usual — so it gets the
			// same refusal every other one gets. INTERNAL would be the wrong answer
			// twice over: it tells the caller to retry a code that can never work
			// again, when what they must do is enrol and scan the new QR, and it
			// answers differently from the branches above, which is the oracle this
			// function's uniformity exists to deny.
			s.refused(ctx, subjectID, "enrollment_removed")
			return ConfirmTotpResult{}, errWrongCode()
		}
		return ConfirmTotpResult{}, fmt.Errorf("enabling an authenticator: %w", err)
	}

	result := ConfirmTotpResult{CredentialID: stored.ID}
	pending := user.Uncommitted()
	if len(pending) == 0 {
		// Already proven. A retried confirmation appends nothing and is not an
		// error: the user did what was asked and has no failure to be told about.
		return result, nil
	}
	for _, e := range pending {
		if _, ok := e.(*contract.UserActivated); ok {
			result.Activated = true
		}
	}

	position, err := s.appendUser(ctx, cmd.IdempotencyKey, subjectID, cmd.UserID, user)
	if err != nil {
		return ConfirmTotpResult{}, conflictOnRace(err)
	}
	result.Changed = true
	result.Position = position
	return result, nil
}

// ---------------------------------------------------------------------------
// Recovery codes
// ---------------------------------------------------------------------------

// GenerateRecoveryCodesCommand asks for a fresh set.
type GenerateRecoveryCodesCommand struct {
	UserID ids.UserID

	// Count is how many codes to mint. Zero means the configured default.
	Count int

	IdempotencyKey string
}

// GenerateRecoveryCodesResult carries the plaintext codes back ONCE.
//
// Only digests are stored, so this is the only moment the codes exist anywhere
// this system can reach. A caller that loses them generates a new set, which
// invalidates the old one — that is the correct outcome, and an endpoint that
// could re-display them would turn a stolen session into a permanent bypass of
// every factor on the account.
type GenerateRecoveryCodesResult struct {
	CredentialID ids.CredentialID

	// Codes are plaintext, shown once. Never log them.
	Codes []string

	Position eventsourcing.Position
}

// GenerateRecoveryCodes replaces the whole set.
//
// # Whole-set replacement, never a top-up
//
// The old digests are deleted and the new ones written in ONE transaction. A
// top-up leaves a mix of old and new codes, which makes "how many do I have left"
// unanswerable and — the part that matters — leaves codes the user believes were
// replaced still live. Somebody who photographed the old sheet keeps their access
// through a regeneration the user performed precisely to take it away.
//
// # These codes do not activate the account
//
// The aggregate records them as a RoleSecondFactor method whose strength is below
// every real one, and its activation rule excludes exactly that. So a Pending
// account that generates codes stays Pending, and this result reports no
// activation. That is not an omission; it is the rule that stops "you must enrol
// a second factor" being answered with a printout.
func (s *SecondFactor) GenerateRecoveryCodes(
	ctx context.Context, cmd GenerateRecoveryCodesCommand,
) (GenerateRecoveryCodesResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return GenerateRecoveryCodesResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.UserID.IsZero():
		return GenerateRecoveryCodesResult{}, errs.ValidationFailedf("a user id is required")
	case cmd.Count < 0 || cmd.Count > MaxRecoveryCodeCount:
		// REDUNDANT with the identical bound in mintRecoveryCodes, and kept
		// deliberately. A mutation removing this one survives the whole suite,
		// because mint refuses the same values a few lines later — recorded here so
		// the next reader does not take the survival as proof that the bound is
		// unnecessary. The one in mint is load-bearing; this one refuses before any
		// store is touched, and a caller-supplied count reaching a loop that
		// allocates per iteration is worth stopping at the edge.
		return GenerateRecoveryCodesResult{}, errs.ValidationFailedf(
			"a recovery-code set holds between 1 and %d codes", MaxRecoveryCodeCount)
	}
	count := cmd.Count
	if count == 0 {
		count = s.count
	}

	user, err := s.users.Load(ctx, cmd.UserID.String())
	if err != nil {
		return GenerateRecoveryCodesResult{}, fmt.Errorf("loading the account for a code set: %w", err)
	}
	subjectID := user.SubjectID()
	if subjectID == "" {
		return GenerateRecoveryCodesResult{}, errs.NotFoundf("no such account")
	}

	now := s.clock.Now().UTC()
	credentialID, err := s.recoveryCredential(ctx, subjectID, now)
	if err != nil {
		return GenerateRecoveryCodesResult{}, err
	}

	codes, digests, err := s.mintRecoveryCodes(subjectID, count)
	if err != nil {
		return GenerateRecoveryCodesResult{}, err
	}

	if err := user.GenerateRecoveryCodes(credentialID, count, now); err != nil {
		return GenerateRecoveryCodesResult{}, err
	}

	// Stored before the append, and atomically. A crash after this leaves a set
	// the log does not name — unusable, because ConsumeRecoveryCode checks the
	// burned digest against the credential the aggregate knows — and the retry
	// replaces it wholesale.
	if err := s.recovery.Replace(ctx, NewRecoveryCodeSet{
		CredentialID: credentialID,
		SubjectID:    subjectID,
		Digests:      digests,
		GeneratedAt:  now,
	}); err != nil {
		return GenerateRecoveryCodesResult{}, fmt.Errorf("storing a recovery-code set: %w", err)
	}

	position, err := s.appendUser(ctx, cmd.IdempotencyKey, subjectID, cmd.UserID, user)
	if err != nil {
		return GenerateRecoveryCodesResult{}, conflictOnRace(err)
	}
	return GenerateRecoveryCodesResult{
		CredentialID: credentialID,
		Codes:        codes,
		Position:     position,
	}, nil
}

// recoveryCredential picks the id a new set is written under.
//
// The store is asked for the same reason enrollmentCredential asks it: the
// partial unique index constrains the ROW, so a crash between writing rows and
// appending the event would make every retry mint an id that collides.
func (s *SecondFactor) recoveryCredential(
	ctx context.Context, subjectID string, now time.Time,
) (ids.CredentialID, error) {
	existing, err := s.recovery.Credential(ctx, subjectID)
	switch {
	case err == nil:
		return existing, nil
	case errors.Is(err, ErrNoRecoveryCode):
		return ids.New[ids.Credential](now, s.entropy), nil
	default:
		return ids.CredentialID{}, fmt.Errorf("looking up an existing code set: %w", err)
	}
}

// ConsumeRecoveryCodeCommand redeems one code.
type ConsumeRecoveryCodeCommand struct {
	UserID ids.UserID

	// Code is as the user typed it: case and separators are normalized here, so a
	// code read off paper with or without its hyphens produces the same digest.
	// It is never logged, stored, or placed in an event.
	Code string

	IdempotencyKey string
}

// ConsumeRecoveryCodeResult reports what redeeming produced.
type ConsumeRecoveryCodeResult struct {
	CredentialID ids.CredentialID

	// Remaining is the count AFTER this consumption, taken from the event the
	// aggregate recorded rather than from a count query — a decision made from an
	// eventually-consistent read can be made twice.
	Remaining int

	// Exhausted is true when this was the last code. It carries its own event so a
	// reactor can force the re-issue interstitial without having to distinguish
	// "Remaining hit zero" from "a regenerate happened".
	Exhausted bool

	Position eventsourcing.Position
}

// ConsumeRecoveryCode burns one code.
//
// # Single use is the SQL statement, not a check here
//
// RecoveryCodes.Consume is one UPDATE with `consumed_at IS NULL` in its WHERE.
// Nothing in this function reads the code's state first, and nothing may be added
// that does: a read-then-write lets two simultaneous presentations of one code
// both observe it unspent and both succeed, which is precisely the concurrency
// somebody working from a photographed sheet produces.
//
// # The code is spent BEFORE the append
//
// If the append then fails, the user has lost one code — an inconvenience, and
// they have nine more. The other order is not an inconvenience: appending first
// and burning after leaves a live code for every consumption that crashed at the
// wrong moment, and a single-use secret that is sometimes multi-use is exactly
// what somebody holding the sheet needs. This mirrors VerifyEmail, for the same
// reason.
//
// The domain decides FIRST, in memory, and writes nothing: it is what refuses an
// account that cannot authenticate and a set with nothing left, and doing that
// after the burn would spend a code on a request that was never going to succeed.
func (s *SecondFactor) ConsumeRecoveryCode(
	ctx context.Context, cmd ConsumeRecoveryCodeCommand,
) (ConsumeRecoveryCodeResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return ConsumeRecoveryCodeResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.UserID.IsZero():
		return ConsumeRecoveryCodeResult{}, errs.ValidationFailedf("a user id is required")
	}
	code := normalizeRecoveryCode(cmd.Code)
	if code == "" {
		return ConsumeRecoveryCodeResult{}, errWrongRecoveryCode()
	}

	user, err := s.users.Load(ctx, cmd.UserID.String())
	if err != nil {
		return ConsumeRecoveryCodeResult{}, fmt.Errorf("loading the account for a recovery code: %w", err)
	}
	subjectID := user.SubjectID()
	if subjectID == "" {
		return ConsumeRecoveryCodeResult{}, errs.NotFoundf("no such account")
	}

	now := s.clock.Now().UTC()
	if err := user.ConsumeRecoveryCode(now); err != nil {
		// A deactivated account and an empty set are both refused here, and both
		// produce the ordinary refusal: "you have no codes left" tells whoever is
		// typing that they have found a real account and exhausted its fallback.
		s.refused(ctx, subjectID, "domain_refused")
		return ConsumeRecoveryCodeResult{}, errWrongRecoveryCode()
	}

	credentialID, err := s.recovery.Consume(ctx, subjectID, recoveryDigest(subjectID, code))
	if err != nil {
		if errors.Is(err, ErrNoRecoveryCode) {
			// Unknown, already spent, and belonging to somebody else are one answer.
			s.refused(ctx, subjectID, "no_such_code")
			return ConsumeRecoveryCodeResult{}, errWrongRecoveryCode()
		}
		return ConsumeRecoveryCodeResult{}, fmt.Errorf("redeeming a recovery code: %w", err)
	}

	result := ConsumeRecoveryCodeResult{CredentialID: credentialID}
	var expected string
	for _, e := range user.Uncommitted() {
		switch ev := e.(type) {
		case *contract.RecoveryCodeConsumed:
			result.Remaining = ev.Remaining
			expected = ev.CredentialID
		case *contract.RecoveryCodesExhausted:
			result.Exhausted = true
		}
	}

	// The burned row must belong to the code set this account's own log records. A
	// row that does not was written by something other than this handler, or
	// survives a set the log has since replaced; either way the event history does
	// not support the consumption, and appending against it would let one table
	// write spend a factor down.
	//
	// Compared against the EVENT rather than against the aggregate's method map,
	// because the last code removes that method as it is spent — a check against
	// the map would refuse exactly the consumption that exhausts the set, which is
	// the one whose event a reactor is waiting for.
	if expected == "" || expected != credentialID.String() {
		s.log.ErrorContext(ctx, "a recovery code was redeemed against a credential the "+
			"account's own log does not record",
			"module", "identity", "subject_id", subjectID,
			"credential_id", credentialID.String())
		return ConsumeRecoveryCodeResult{}, errWrongRecoveryCode()
	}

	position, err := s.appendUser(ctx, cmd.IdempotencyKey, subjectID, cmd.UserID, user)
	if err != nil {
		return ConsumeRecoveryCodeResult{}, err
	}
	result.Position = position
	return result, nil
}

// ---------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------

// mintRecoveryCodes generates a set and the digests that will be stored.
//
// The plaintext codes are returned to exactly one caller and the digests to the
// store; the two are produced together so no code can be handed out that nothing
// can redeem, and no digest can be stored for a code nobody was given.
func (s *SecondFactor) mintRecoveryCodes(subjectID string, count int) ([]string, [][]byte, error) {
	if count < 1 || count > MaxRecoveryCodeCount {
		return nil, nil, errs.ValidationFailedf(
			"a recovery-code set holds between 1 and %d codes", MaxRecoveryCodeCount)
	}
	codes := make([]string, 0, count)
	digests := make([][]byte, 0, count)
	for range count {
		raw := make([]byte, recoveryCodeBytes)
		if _, err := io.ReadFull(s.codeEntropy, raw); err != nil {
			// Refused, never degraded. A short read leaves trailing zero bytes, and
			// a set of codes whose tails are predictable is a set an attacker can
			// search — while the user is told they hold ten independent secrets.
			return nil, nil, fmt.Errorf("generating recovery codes: %w", err)
		}
		code := group(recoveryCodeAlphabet.EncodeToString(raw))
		codes = append(codes, code)
		digests = append(digests, recoveryDigest(subjectID, normalizeRecoveryCode(code)))
	}
	return codes, digests, nil
}

// group inserts hyphens for legibility. Presentation only — normalization strips
// them again before anything is hashed.
func group(code string) string {
	var b strings.Builder
	for i, r := range code {
		if i > 0 && i%recoveryCodeGroup == 0 {
			b.WriteByte('-')
		}
		b.WriteRune(r)
	}
	return b.String()
}

// normalizeRecoveryCode reduces what a user typed to the canonical form.
//
// Uppercased, with everything outside the base32 alphabet dropped: hyphens,
// spaces and the stray punctuation a paper-to-keyboard transcription collects.
// Doing it HERE rather than in the store is what makes the digest a function of
// the code alone — a store comparing raw input would make "AB CD" and "ABCD" two
// different credentials, and the user cannot tell which one they were given.
func normalizeRecoveryCode(code string) string {
	var b strings.Builder
	b.Grow(len(code))
	for _, r := range strings.ToUpper(code) {
		switch {
		case r >= 'A' && r <= 'Z', r >= '2' && r <= '7':
			b.WriteRune(r)
		}
	}
	return b.String()
}

// recoveryDigest is what the store holds and what a presented code is hashed to.
//
// SHA-256, not Argon2id: the code came from crypto/rand, so there is no candidate
// list and no dictionary — an attacker with the digest has nothing better than
// enumerating 2^80. A slow hash would add latency to every redemption and make
// the endpoint a memory-amplification vector for anyone posting garbage.
//
// The subject is mixed IN, not merely filtered on in the query. Both are true —
// the statement matches subject and digest — but binding it here means a digest
// row copied from one account to another hashes to nothing the second account can
// present, so a single table write does not move a working credential.
//
// Both prefixes are length-prefixed with a fixed-width count, so no choice of
// subject id can shift the boundary between the parts and make two different
// triples collide.
func recoveryDigest(subjectID, normalizedCode string) []byte {
	h := sha256.New()
	var n [8]byte
	for _, part := range []string{recoveryDigestDomain, subjectID} {
		binary.BigEndian.PutUint64(n[:], uint64(len(part)))
		_, _ = h.Write(n[:])
		_, _ = h.Write([]byte(part))
	}
	_, _ = h.Write([]byte(normalizedCode))
	return h.Sum(nil)
}

// ---------------------------------------------------------------------------
// Internals
// ---------------------------------------------------------------------------

// errWrongCode is the ONE answer every failed TOTP confirmation gives.
//
// It is a function rather than a package-level value so no caller can compare
// against it by identity and re-derive the distinction this exists to remove.
func errWrongCode() error {
	return errs.ValidationFailedf("that code is not valid; check your authenticator and try again")
}

// errWrongRecoveryCode is the ONE answer every failed redemption gives.
func errWrongRecoveryCode() error {
	return errs.ValidationFailedf("that recovery code is not valid")
}

// conflictOnRace turns a lost optimistic-concurrency race into CONFLICT.
//
// `ErrWrongExpectedRevision` means the account changed between the load and the
// append — another request of the caller's own, a concurrent disable, a
// suspension. Reaching a client as INTERNAL it says "we broke, retry with
// backoff", when the honest and actionable answer is the catalogue's CONFLICT:
// re-read and try again. The distinction is not cosmetic. A client that treats
// it as INTERNAL will retry the SAME stale command against a state it never
// saw, which is exactly what the expected-revision precondition exists to
// refuse.
//
// # Where this may be used, and where it may not
//
// Only where the caller is already known AND the race is reachable. CONFLICT
// confirms that an account exists and that something is happening to it, so on a
// path that has not yet verified a credential it is a disclosure ADR-036
// forbids: `Register` answers a lost race with its own indistinguishable
// non-answer instead, and `Authenticate` with the uniform refusal.
//
// The commands that DO use it — EnrollTotp, ConfirmTotp, GenerateRecoveryCodes,
// RevokeSession — are past that point and append to a stream that already
// exists, so a concurrent disable or suspension genuinely lands between their
// load and their append.
//
// Two callers deliberately left alone for reasons that are NOT disclosure, and
// the distinction matters to anyone extending this:
//
//   - `CreateSession` appends to a stream named by a freshly minted session id,
//     so its precondition is "must not exist" and only an id collision could
//     fail it. Mapping it would be harmless and would also never fire.
//   - `ConsumeRecoveryCode` runs inside authentication, where every refusal is
//     deliberately uniform (`errWrongRecoveryCode`). A distinguishable answer
//     there would separate "wrong code" from "the account changed", which is a
//     difference an attacker can generate at will by racing their own requests.
//
// Any other error passes through untouched, so an outage stays INTERNAL.
func conflictOnRace(err error) error {
	if err == nil || !errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
		return err
	}
	return errs.Conflictf("the account changed while this request was in flight; " +
		"re-read it and try again").Wrap(err)
}

// refused records WHY a refusal happened, where saying so is safe.
//
// The wire answer is uniform; this is the other half of that decision. A system
// that cannot tell "wrong code" from "no enrolment" in its own logs cannot
// investigate an attack, and the temptation is then to put the distinction back
// on the wire.
func (s *SecondFactor) refused(ctx context.Context, subjectID, reason string) {
	s.log.InfoContext(ctx, "a second-factor presentation was refused",
		"module", "identity", "subject_id", subjectID, "reason", reason)
}

// appendUser writes the account stream.
//
// One stream, but through the multi-stream appender: the expected-revision
// precondition and the derived event ids are the same machinery registration
// uses, and a second append path would be a second place for the id derivation
// to drift.
func (s *SecondFactor) appendUser(
	ctx context.Context,
	idempotencyKey, subjectID string,
	userID ids.UserID,
	user *domain.User,
) (eventsourcing.Position, error) {
	pending := user.Uncommitted()
	if len(pending) == 0 {
		return eventsourcing.Position{}, nil
	}
	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return eventsourcing.Position{}, err
	}

	meta := s.metadata(ctx, subjectID, idempotencyKey)
	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			// Stamped per EVENT TYPE, not once for the command: two events of
			// one command can sit at different schema versions.
			Meta: eventsourcing.StampSchemaVersion(meta, s.schemas, e.EventType()),
		})
	}

	results, err := s.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream,
		// The exact loaded revision. An enrolment decided against events that have
		// since been superseded — a concurrent disable, a suspension — is refused
		// rather than layered on top of a state it never saw.
		Expected: eventsourcing.ExpectedFor(user),
		Events:   events,
	}})
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}

	// Cleared only now. Clearing before the append is durable would lose the events
	// if the caller retried after a transient failure.
	user.ClearUncommitted()
	return results[0].Position, nil
}

// metadata builds the envelope shared by every event of one command.
//
// Pseudonyms and nothing else: no address, no account label, and no OrgID —
// enrolling a second factor happens on an account, not in an organization.
func (s *SecondFactor) metadata(
	ctx context.Context, subjectID, idempotencyKey string,
) eventsourcing.Metadata {
	meta := eventsourcing.Metadata{
		OccurredAt: s.clock.Now().UTC(),
		SubjectIDs: []string{subjectID},
		ActorID:    subjectID,
	}
	trace := eventsourcing.TraceFrom(ctx)
	meta.CorrelationID = trace.CorrelationID
	meta.CausationID = trace.CausationID
	if meta.CorrelationID == "" {
		meta.CorrelationID = eventsourcing.DeriveEventID(idempotencyKey, 0).String()
	}
	if meta.CausationID == "" {
		meta.CausationID = idempotencyKey
	}
	return meta
}
