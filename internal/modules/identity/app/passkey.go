package app

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/google/uuid"
)

// Ceremonies performs the WebAuthn exchange.
//
// A port declared by its consumer (CONVENTIONS §2). The implementation is
// internal/adapter/webauthn; this package never learns how a signature is
// checked, and the adapter never learns what a passkey means to an account.
type Ceremonies interface {
	BeginRegistration(a CeremonyAccount) (CeremonyChallenge, error)
	FinishRegistration(a CeremonyAccount, state, response []byte) (CeremonyCredential, error)

	BeginLogin(a CeremonyAccount, stored []CeremonyStored) (CeremonyChallenge, error)
	FinishLogin(a CeremonyAccount, stored []CeremonyStored, state, response []byte) (CeremonyAssertion, error)
}

// The port's own types, so this package names nothing from an adapter.
type (
	// CeremonyAccount is what the authenticator is told about the person: a
	// PSEUDONYM and a public handle, never an address. The handle travels to the
	// authenticator and is stored there permanently, which is the one place
	// ADR-002 can never reach to erase.
	CeremonyAccount struct {
		SubjectID string
		Username  string
		Existing  [][]byte
	}

	CeremonyChallenge struct {
		Options   []byte
		State     []byte
		ExpiresAt time.Time
	}

	CeremonyCredential struct {
		ID             string
		PublicKey      []byte
		SignCount      uint32
		AAGUID         []byte
		Transports     []string
		UserVerified   bool
		BackupEligible bool
		BackupState    bool
	}

	CeremonyStored struct {
		ID             string
		PublicKey      []byte
		SignCount      uint32
		AAGUID         []byte
		Transports     []string
		UserVerified   bool
		BackupEligible bool
		BackupState    bool
	}

	CeremonyAssertion struct {
		ID           string
		SignCount    uint32
		UserVerified bool

		// CloneWarning is why this is a struct and not an id. The library sets it
		// and returns NO ERROR, so a caller that ignores it has clone detection
		// that does nothing while every test passes.
		CloneWarning bool
	}
)

// Passkeys is identity slice 2's use case.
type Passkeys struct {
	clock      clock.Clock
	entropy    io.Reader
	users      AggregateLoader[*domain.User]
	subjects   UserDirectory
	appender   eventsourcing.MultiAppender
	schemas    eventsourcing.SchemaVersions
	ceremonies Ceremonies
	store      PasskeyStore
	challenges ChallengeStore
	recovery   RecoveryCodeIssuer
	ttl        time.Duration
	log        *slog.Logger
}

// RecoveryCodeIssuer mints a recovery-code set for an account.
//
// # Why the passkey flow holds it at all
//
// identity.md §5 names the lockout risk as "the real design problem": a person
// whose only method is a passkey on a lost device must still be able to get back
// in. So codes are issued at FIRST passkey registration, "not offered as an
// afterthought" — an afterthought is a path most people never take, and the
// people who skip it are exactly the ones who later cannot recover.
//
// A narrow port rather than the whole second-factor use case, because this needs
// one operation and holding more would let a passkey flow enrol a TOTP secret.
type RecoveryCodeIssuer interface {
	// Issue mints a set and returns the plaintext codes ONCE. They are shown to
	// the person and never recoverable afterwards.
	Issue(ctx context.Context, userID ids.UserID, idempotencyKey string) ([]string, error)
}

// PasskeysDeps is what the flow needs.
type PasskeysDeps struct {
	Clock   clock.Clock
	Entropy io.Reader

	Users    AggregateLoader[*domain.User]
	Subjects UserDirectory

	Appender eventsourcing.MultiAppender
	Schemas  eventsourcing.SchemaVersions

	Ceremonies Ceremonies
	Store      PasskeyStore
	Challenges ChallengeStore

	// Recovery issues the code set at first registration. Required: see
	// RecoveryCodeIssuer.
	Recovery RecoveryCodeIssuer

	// TTL bounds a ceremony. Zero takes DefaultCeremonyTTL.
	TTL time.Duration

	Log *slog.Logger
}

// DefaultCeremonyTTL is how long a ceremony stays redeemable server-side.
//
// Slightly longer than the browser's own timeout, deliberately: the two clocks
// are different, and a challenge that expired server-side while the browser was
// still prompting produces a refusal the person cannot act on. Short enough that
// an abandoned ceremony is not a hole left open on a shared machine.
const DefaultCeremonyTTL = 5 * time.Minute

func NewPasskeys(d PasskeysDeps) (*Passkeys, error) {
	switch {
	case d.Clock == nil:
		return nil, errors.New("identity: the passkey flow needs a clock")
	case d.Entropy == nil:
		return nil, errors.New("identity: the passkey flow needs an entropy source; a " +
			"guessable ceremony id lets somebody answer a ceremony they did not start")
	case d.Users == nil:
		return nil, errors.New("identity: the passkey flow needs the account aggregate")
	case d.Subjects == nil:
		return nil, errors.New("identity: the passkey flow needs a user directory")
	case d.Appender == nil:
		return nil, errors.New("identity: the passkey flow needs an appender")
	case d.Schemas == nil:
		return nil, errors.New("identity: the passkey flow needs schema versions")
	case d.Ceremonies == nil:
		return nil, errors.New("identity: the passkey flow needs a ceremony implementation")
	case d.Store == nil:
		return nil, errors.New("identity: the passkey flow needs a credential store")
	case d.Challenges == nil:
		return nil, errors.New("identity: the passkey flow needs a challenge store; without " +
			"one nothing makes a ceremony single-use and one signature mints two sessions")
	case d.Recovery == nil:
		return nil, errors.New("identity: the passkey flow needs a recovery-code issuer; " +
			"identity.md §5 calls lockout the real design problem, and a person whose " +
			"only method is a passkey on a lost device must still be able to get back in")
	}
	p := &Passkeys{
		clock: d.Clock, entropy: d.Entropy, users: d.Users, subjects: d.Subjects,
		appender: d.Appender, schemas: d.Schemas, ceremonies: d.Ceremonies,
		store: d.Store, challenges: d.Challenges, recovery: d.Recovery,
		ttl: d.TTL, log: d.Log,
	}
	if p.ttl <= 0 {
		p.ttl = DefaultCeremonyTTL
	}
	if p.log == nil {
		p.log = slog.Default()
	}
	return p, nil
}

// BeginRegistrationCommand starts an enrolment for an authenticated caller.
type BeginRegistrationCommand struct {
	// SubjectID is the CALLER'S pseudonym. There is no field naming another
	// account: a passkey is enrolled by its owner and by nobody else.
	SubjectID string
}

// BeginRegistrationResult is what the browser needs.
type BeginRegistrationResult struct {
	// ChallengeID is returned to the browser and sent back with the answer. Not
	// a credential: holding it lets somebody complete a ceremony they must still
	// produce a valid signature for.
	ChallengeID string

	// Options is the JSON for navigator.credentials.create.
	Options []byte

	ExpiresAt time.Time
}

// BeginRegistration issues a ceremony for an account to add a passkey.
func (p *Passkeys) BeginRegistration(
	ctx context.Context, cmd BeginRegistrationCommand,
) (BeginRegistrationResult, error) {
	if cmd.SubjectID == "" {
		return BeginRegistrationResult{}, errs.Internalf(
			"no authenticated subject reached the passkey handler")
	}

	user, err := p.load(ctx, cmd.SubjectID)
	if err != nil {
		return BeginRegistrationResult{}, err
	}
	existing, err := p.store.List(ctx, cmd.SubjectID)
	if err != nil {
		return BeginRegistrationResult{}, fmt.Errorf("listing existing passkeys: %w", err)
	}

	challenge, err := p.ceremonies.BeginRegistration(CeremonyAccount{
		SubjectID: cmd.SubjectID,
		Username:  user.Username(),
		// EXCLUSIONS, so an authenticator that already holds a credential for
		// this account says so instead of creating a second one the person
		// cannot tell apart.
		Existing: rawIDs(existing),
	})
	if err != nil {
		return BeginRegistrationResult{}, fmt.Errorf("beginning a passkey registration: %w", err)
	}

	id, err := p.ceremonyID()
	if err != nil {
		return BeginRegistrationResult{}, err
	}
	now := p.clock.Now().UTC()
	if err := p.challenges.Issue(ctx, Challenge{
		ID:        id,
		SubjectID: cmd.SubjectID,
		Purpose:   CeremonyRegistration,
		State:     challenge.State,
		ExpiresAt: now.Add(p.ttl),
	}); err != nil {
		return BeginRegistrationResult{}, fmt.Errorf("storing the ceremony: %w", err)
	}

	return BeginRegistrationResult{
		ChallengeID: id,
		Options:     challenge.Options,
		ExpiresAt:   now.Add(p.ttl),
	}, nil
}

// FinishRegistrationCommand completes an enrolment.
type FinishRegistrationCommand struct {
	SubjectID   string
	ChallengeID string

	// Response is the browser's attestation payload, verbatim.
	Response []byte

	// Label is the person's own name for the device.
	Label string

	IdempotencyKey string
}

// FinishRegistrationResult reports what was enrolled.
type FinishRegistrationResult struct {
	CredentialID string

	// RecoveryCodes are returned ONCE, and only when this was the account's
	// FIRST passkey. Never recoverable afterwards — the store holds digests.
	RecoveryCodes []string

	// Activated reports that this registration completed the account.
	Activated bool
}

// FinishRegistration verifies the authenticator's answer and records it.
//
// # The order, and why each step is where it is
//
//  1. Consume the challenge. Single-use, atomic, and it fails before anything is
//     verified — a replayed ceremony costs nothing.
//  2. Verify. The adapter decides; this learns only whether it passed.
//  3. Store the credential. The unique constraint is what makes credential-ID
//     uniqueness true under concurrency (ADR-057).
//  4. Append. AFTER the store, so a crash between them leaves a credential the
//     log does not name — unusable, because a login loads the account and finds
//     no such method — rather than an account claiming a passkey nothing can
//     verify against.
//  5. Recovery codes, only on the FIRST passkey (identity.md §5).
func (p *Passkeys) FinishRegistration(
	ctx context.Context, cmd FinishRegistrationCommand,
) (FinishRegistrationResult, error) {
	switch {
	case cmd.SubjectID == "":
		return FinishRegistrationResult{}, errs.Internalf(
			"no authenticated subject reached the passkey handler")
	case cmd.IdempotencyKey == "":
		return FinishRegistrationResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.ChallengeID == "":
		return FinishRegistrationResult{}, errs.ValidationFailedf("a ceremony id is required")
	case len(cmd.Response) == 0:
		return FinishRegistrationResult{}, errs.ValidationFailedf("a ceremony response is required")
	}

	now := p.clock.Now().UTC()
	challenge, err := p.challenges.Consume(ctx, cmd.ChallengeID, CeremonyRegistration, now)
	if err != nil {
		if errors.Is(err, ErrNoSuchChallenge) {
			return FinishRegistrationResult{}, errs.ValidationFailedf(
				"this registration has expired; start again")
		}
		return FinishRegistrationResult{}, err
	}
	if challenge.SubjectID != cmd.SubjectID {
		// The ceremony belongs to somebody else. It is already consumed, which is
		// correct: a caller who can guess a ceremony id must not be able to probe
		// for one by trying it repeatedly.
		return FinishRegistrationResult{}, errs.ValidationFailedf(
			"this registration has expired; start again")
	}

	user, err := p.load(ctx, cmd.SubjectID)
	if err != nil {
		return FinishRegistrationResult{}, err
	}
	existing, err := p.store.List(ctx, cmd.SubjectID)
	if err != nil {
		return FinishRegistrationResult{}, fmt.Errorf("listing existing passkeys: %w", err)
	}
	first := len(existing) == 0

	cred, err := p.ceremonies.FinishRegistration(CeremonyAccount{
		SubjectID: cmd.SubjectID, Username: user.Username(), Existing: rawIDs(existing),
	}, challenge.State, cmd.Response)
	if err != nil {
		// ONE refusal for every cause. Which check failed is exactly what an
		// attacker wants to know.
		return FinishRegistrationResult{}, errs.ValidationFailedf(
			"this passkey could not be verified")
	}

	credentialID, err := ids.Parse[ids.Credential](passkeyCredentialID(cred.ID))
	if err != nil {
		// The aggregate keys methods by a prefixed ULID and a WebAuthn credential
		// id is the authenticator's own bytes, so one is DERIVED from the other —
		// see passkeyCredentialID. A failure here is a bug in that derivation.
		return FinishRegistrationResult{}, errs.Internalf("deriving the credential id").Wrap(err)
	}

	if err := user.RegisterPasskey(credentialID, cmd.Label,
		cred.BackupEligible, cred.BackupState, cred.UserVerified, now); err != nil {
		return FinishRegistrationResult{}, err
	}

	// STORED BEFORE THE APPEND. A crash between them leaves a credential the log
	// does not name, which is inert: a login loads the account and finds no such
	// method. The reverse order leaves an account claiming a passkey nothing can
	// verify against, which is a person who cannot sign in.
	if err := p.store.Register(ctx, NewPasskey{
		CredentialID: cred.ID, SubjectID: cmd.SubjectID, PublicKey: cred.PublicKey,
		SignCount: cred.SignCount, AAGUID: cred.AAGUID, Transports: cred.Transports,
		UserVerified: cred.UserVerified, BackupEligible: cred.BackupEligible,
		BackupState: cred.BackupState, Label: cmd.Label, RegisteredAt: now,
	}); err != nil {
		if errors.Is(err, ErrPasskeyAlreadyRegistered) {
			// WebAuthn L3 §7.1 step 27. Refused rather than replaced: replacing a
			// registration is the takeover the uniqueness exists to prevent.
			return FinishRegistrationResult{}, errs.Conflictf(
				"that authenticator is already registered")
		}
		return FinishRegistrationResult{}, fmt.Errorf("storing the passkey: %w", err)
	}

	result := FinishRegistrationResult{CredentialID: cred.ID}
	if len(user.Uncommitted()) > 0 {
		if err := p.append(ctx, cmd.IdempotencyKey, cmd.SubjectID, user); err != nil {
			return FinishRegistrationResult{}, err
		}
		result.Activated = user.State() == domain.StateActive
	}

	if first {
		// identity.md §5: issued at FIRST registration, not offered afterwards.
		// A failure here does NOT undo the passkey — the person has a working
		// credential and losing it to a code-minting error would be worse — but it
		// is loud, because an account with a passkey and no recovery path is the
		// lockout this exists to prevent.
		userID, idErr := p.subjects.UserBySubject(ctx, cmd.SubjectID)
		if idErr != nil {
			p.log.ErrorContext(ctx, "a first passkey was registered and no recovery codes "+
				"were issued; this account has one way in and no way back",
				"module", "identity", "subject_id", cmd.SubjectID, "error", idErr)
			return result, nil
		}
		codes, codeErr := p.recovery.Issue(ctx, userID, cmd.IdempotencyKey+":recovery")
		if codeErr != nil {
			p.log.ErrorContext(ctx, "a first passkey was registered and no recovery codes "+
				"were issued; this account has one way in and no way back",
				"module", "identity", "subject_id", cmd.SubjectID, "error", codeErr)
			return result, nil
		}
		result.RecoveryCodes = codes
	}
	return result, nil
}

// RemovePasskeyCommand deletes one of the caller's credentials.
type RemovePasskeyCommand struct {
	SubjectID    string
	CredentialID string

	IdempotencyKey string
}

// RemovePasskey deletes a credential.
//
// The aggregate decides whether it MAY be removed — the two invariants live
// there — and this performs the deletion in the order that fails safely: the
// aggregate first, so a refusal costs nothing, then the row, then the append.
func (p *Passkeys) RemovePasskey(ctx context.Context, cmd RemovePasskeyCommand) error {
	switch {
	case cmd.SubjectID == "":
		return errs.Internalf("no authenticated subject reached the passkey handler")
	case cmd.IdempotencyKey == "":
		return errs.ValidationFailedf("an idempotency key is required")
	case cmd.CredentialID == "":
		return errs.ValidationFailedf("a credential id is required")
	}

	user, err := p.load(ctx, cmd.SubjectID)
	if err != nil {
		return err
	}
	credentialID, err := ids.Parse[ids.Credential](passkeyCredentialID(cmd.CredentialID))
	if err != nil {
		return errs.NotFoundf("no such passkey")
	}

	now := p.clock.Now().UTC()
	if err := user.RemovePasskey(credentialID, cmd.SubjectID, now); err != nil {
		return err
	}
	if len(user.Uncommitted()) == 0 {
		return nil
	}

	// The ROW before the append, for FinishRegistration's reason in reverse: a
	// crash between them leaves a credential the log says is gone and the store
	// still holds. That direction is safe — the aggregate is the authority on
	// which methods exist, and a login checks it — while the reverse leaves a
	// credential that still authenticates after the person was told it was gone.
	if err := p.store.Remove(ctx, cmd.CredentialID, cmd.SubjectID); err != nil {
		if errors.Is(err, ErrNoSuchPasskey) {
			return errs.NotFoundf("no such passkey")
		}
		return fmt.Errorf("removing the passkey: %w", err)
	}
	return p.append(ctx, cmd.IdempotencyKey, cmd.SubjectID, user)
}

// load resolves a pseudonym to its account aggregate.
func (p *Passkeys) load(ctx context.Context, subjectID string) (*domain.User, error) {
	userID, err := p.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			return nil, errs.NotFoundf("no such account")
		}
		return nil, fmt.Errorf("resolving the account: %w", err)
	}
	user, err := p.users.Load(ctx, userID.String())
	if err != nil {
		return nil, fmt.Errorf("loading the account: %w", err)
	}
	if user.SubjectID() == "" {
		return nil, errs.NotFoundf("no such account")
	}
	return user, nil
}

func (p *Passkeys) append(
	ctx context.Context, idempotencyKey, subjectID string, user *domain.User,
) error {
	userID, err := p.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		return fmt.Errorf("resolving the account: %w", err)
	}
	stream, err := eventsourcing.NewStreamID(UserCategory, userID.String())
	if err != nil {
		return err
	}
	meta := eventsourcing.Metadata{
		OccurredAt: p.clock.Now().UTC(),
		SubjectIDs: []string{subjectID},
		ActorID:    subjectID,
	}
	trace := eventsourcing.TraceFrom(ctx)
	meta.CorrelationID, meta.CausationID = trace.CorrelationID, trace.CausationID
	if meta.CorrelationID == "" {
		meta.CorrelationID = eventsourcing.DeriveEventID(idempotencyKey, 0).String()
	}
	if meta.CausationID == "" {
		meta.CausationID = idempotencyKey
	}

	pending := user.Uncommitted()
	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, p.schemas, e.EventType()),
		})
	}
	if _, err := p.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream: stream, Expected: eventsourcing.ExpectedFor(user), Events: events,
	}}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this account changed concurrently; try again")
		}
		return fmt.Errorf("recording the passkey change: %w", err)
	}
	user.ClearUncommitted()
	return nil
}

// ceremonyID mints an unguessable id for a ceremony in flight.
func (p *Passkeys) ceremonyID() (string, error) {
	id := ids.New[ids.Credential](p.clock.Now().UTC(), p.entropy)
	if id.IsZero() {
		return "", errs.Internalf("minting a ceremony id")
	}
	return id.String(), nil
}

// rawIDs decodes stored credential ids for an exclusion or allow list.
func rawIDs(stored []StoredPasskey) [][]byte {
	out := make([][]byte, 0, len(stored))
	for _, s := range stored {
		if raw, err := decodeCredentialID(s.CredentialID); err == nil {
			out = append(out, raw)
		}
	}
	return out
}

// passkeyCredentialNamespace makes the derivation below reproducible.
var passkeyCredentialNamespace = uuid.MustParse("2c8f5b41-7d3a-4e19-9f62-8a0d4c7b1e35")

// passkeyCredentialID derives the aggregate's credential id from WebAuthn's.
//
// # Two id spaces meet here, and neither can move
//
// The aggregate keys every method by a prefixed ULID (ADR-030) — sixteen bytes,
// minted by this system. A WebAuthn credential id is the AUTHENTICATOR'S own
// bytes, arbitrary length, chosen by hardware this system does not control. One
// cannot be the other.
//
// So the aggregate's id is DERIVED from the authenticator's, by the same
// namespaced SHA-1 UUID construction event ids use (EVENT-SOURCING §3). That
// makes the mapping stable across processes and across restarts without anything
// having to store it, which matters because the log records the derived id and
// the store records the real one — and a replay must arrive at the same answer
// years later.
//
// It is NOT reversible, and does not need to be: every lookup that needs the
// authenticator's bytes has them, either from the ceremony or from the store.
func passkeyCredentialID(webauthnID string) string {
	u := uuid.NewSHA1(passkeyCredentialNamespace, []byte(webauthnID))
	return ids.FromUUID[ids.Credential](u).String()
}

// decodeCredentialID turns a stored credential id back into the raw bytes an
// allowCredentials or excludeCredentials list carries.
func decodeCredentialID(id string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(id)
}

// ---------------------------------------------------------------------------
// Authentication
// ---------------------------------------------------------------------------

// BeginLoginCommand starts a passkey sign-in.
//
// It carries no identifier, and that absence is the feature: identity.md §5 asks
// for usernameless login, so the authenticator names the account. A field for an
// address here would reintroduce the enumeration oracle every other public
// surface in this module removes — "does this address have a passkey" is the
// same question as "does this address have an account".
type BeginLoginCommand struct{}

// BeginLoginResult is what the browser needs.
type BeginLoginResult struct {
	ChallengeID string
	Options     []byte
	ExpiresAt   time.Time
}

// BeginLogin issues a discoverable-login ceremony.
//
// No account is looked up and none is named. The options list no credentials,
// so the authenticator offers whatever it holds for this relying party — which
// is what makes the call answer identically whether or not any account exists.
func (p *Passkeys) BeginLogin(ctx context.Context, _ BeginLoginCommand) (BeginLoginResult, error) {
	challenge, err := p.ceremonies.BeginLogin(CeremonyAccount{}, nil)
	if err != nil {
		return BeginLoginResult{}, fmt.Errorf("beginning a passkey login: %w", err)
	}

	id, err := p.ceremonyID()
	if err != nil {
		return BeginLoginResult{}, err
	}
	now := p.clock.Now().UTC()
	if err := p.challenges.Issue(ctx, Challenge{
		ID: id, Purpose: CeremonyLogin, State: challenge.State, ExpiresAt: now.Add(p.ttl),
	}); err != nil {
		return BeginLoginResult{}, fmt.Errorf("storing the ceremony: %w", err)
	}
	return BeginLoginResult{ChallengeID: id, Options: challenge.Options, ExpiresAt: now.Add(p.ttl)}, nil
}

// FinishLoginCommand completes a passkey sign-in.
type FinishLoginCommand struct {
	ChallengeID string

	// Response is the browser's assertion payload, verbatim. It names the
	// credential, which names the account.
	Response []byte

	IdempotencyKey string
}

// FinishLoginResult is the evidence CreateSession requires.
type FinishLoginResult struct {
	Proof Proof

	// CloneWarned reports that the authenticator's counter went BACKWARDS.
	//
	// Surfaced so a caller can tell the person why they are being asked to step
	// up. The assurance reduction is already applied to the Proof — this is not
	// the enforcement, it is the explanation.
	CloneWarned bool
}

// FinishLogin verifies an assertion and produces a Proof.
//
// # What the sign count does, and what it must never do
//
// identity.md §5: the counter is "not treated as mandatory, because most synced
// passkeys never increment it. A regression here locks out legitimate users." So
// a regression is NOT a denial. It caps the session at AAL1 and records a
// warning event, which means anything requiring step-up asks for it and ordinary
// reads keep working.
//
// The alternative — denying — signs people out for using two devices at once,
// which identity.md §6 and §9 treat as ordinary rather than theoretical.
func (p *Passkeys) FinishLogin(
	ctx context.Context, cmd FinishLoginCommand,
) (FinishLoginResult, error) {
	switch {
	case cmd.IdempotencyKey == "":
		return FinishLoginResult{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.ChallengeID == "":
		return FinishLoginResult{}, errs.Unauthenticatedf("this sign-in has expired; try again")
	case len(cmd.Response) == 0:
		return FinishLoginResult{}, errs.Unauthenticatedf("this sign-in has expired; try again")
	}

	now := p.clock.Now().UTC()
	challenge, err := p.challenges.Consume(ctx, cmd.ChallengeID, CeremonyLogin, now)
	if err != nil {
		// ONE answer for unknown, spent, expired and wrong-purpose — and the same
		// answer a bad signature gets below.
		return FinishLoginResult{}, errs.Unauthenticatedf("this sign-in has expired; try again")
	}

	presented, err := credentialIDFromAssertion(cmd.Response)
	if err != nil {
		return FinishLoginResult{}, errs.Unauthenticatedf("this passkey could not be verified")
	}
	stored, err := p.store.Find(ctx, presented)
	if err != nil {
		if errors.Is(err, ErrNoSuchPasskey) {
			// An unknown credential answers exactly as a bad signature does.
			// Distinguishing them would tell a caller which credential ids are
			// registered, and a credential id is not secret — it travels in every
			// allowCredentials list — so the answer must not be an oracle.
			return FinishLoginResult{}, errs.Unauthenticatedf("this passkey could not be verified")
		}
		return FinishLoginResult{}, fmt.Errorf("reading the passkey: %w", err)
	}

	user, err := p.load(ctx, stored.SubjectID)
	if err != nil {
		return FinishLoginResult{}, errs.Unauthenticatedf("this passkey could not be verified")
	}
	assertion, err := p.ceremonies.FinishLogin(
		CeremonyAccount{SubjectID: stored.SubjectID, Username: user.Username()},
		[]CeremonyStored{{
			ID: stored.CredentialID, PublicKey: stored.PublicKey, SignCount: stored.SignCount,
			AAGUID: stored.AAGUID, Transports: stored.Transports,
			UserVerified: stored.UserVerified, BackupEligible: stored.BackupEligible,
			BackupState: stored.BackupState,
		}},
		challenge.State, cmd.Response)
	if err != nil {
		return FinishLoginResult{}, errs.Unauthenticatedf("this passkey could not be verified")
	}

	// The counter, advanced ATOMICALLY. The comparison is the database's; this
	// only reads which of the three things happened.
	outcome, err := p.store.Advance(ctx, stored.CredentialID, assertion.SignCount, now)
	if err != nil {
		return FinishLoginResult{}, fmt.Errorf("advancing the passkey's sign count: %w", err)
	}

	// BOTH signals, and either is enough. The library's CloneWarning and the
	// store's regression answer the same question from two sides, and reading
	// only one would make the check depend on a library flag this codebase has
	// no control over — which is precisely how a check becomes decorative.
	regressed := assertion.CloneWarning || outcome.Regressed

	result := FinishLoginResult{CloneWarned: regressed}
	aal := domain.AALForVerified([]contract.MethodKind{contract.MethodPasskey}, assertion.UserVerified)

	if regressed {
		// CAPPED, not denied. Anything requiring step-up will ask for it; ordinary
		// reads keep working. See the doc comment.
		aal = contract.AAL1

		if err := user.NoteCloneWarning(
			mustPasskeyCredentialID(stored.CredentialID),
			outcome.Stored, assertion.SignCount, now,
		); err == nil && len(user.Uncommitted()) > 0 {
			// Appended, and a failure here does NOT fail the sign-in: the person
			// authenticated, and refusing them because a warning could not be
			// recorded would turn an observability gap into a lockout. It is loud
			// instead.
			if appendErr := p.append(ctx, cmd.IdempotencyKey+":clone", stored.SubjectID, user); appendErr != nil {
				p.log.ErrorContext(ctx, "a passkey's signature counter regressed and the "+
					"warning could not be recorded; clone detection is silent for this login",
					"module", "identity", "subject_id", stored.SubjectID,
					"stored", outcome.Stored, "presented", assertion.SignCount,
					"error", appendErr)
			}
		}
	}

	userID, err := p.subjects.UserBySubject(ctx, stored.SubjectID)
	if err != nil {
		return FinishLoginResult{}, errs.Unauthenticatedf("this passkey could not be verified")
	}
	result.Proof = Proof{
		userID:    userID,
		subjectID: stored.SubjectID,
		methods:   []contract.MethodKind{contract.MethodPasskey},
		aal:       aal,
		at:        now,
	}
	return result, nil
}

// mustPasskeyCredentialID derives the aggregate's id, falling back to zero.
//
// A zero id makes NoteCloneWarning refuse, which is the safe direction: the
// warning is not recorded and the caller logs that it could not be, rather than
// an event being attributed to a credential that does not exist.
func mustPasskeyCredentialID(webauthnID string) ids.CredentialID {
	id, err := ids.Parse[ids.Credential](passkeyCredentialID(webauthnID))
	if err != nil {
		return ids.CredentialID{}
	}
	return id
}

// credentialIDFromAssertion reads which credential signed.
//
// The assertion names it, and the server must look it up to learn whose it is —
// that is what makes usernameless login possible. Parsed with the TOLERANT
// decoder for ADR-047's reason: the payload comes from a browser this system
// does not control, and a field the current build has never heard of must not
// make a person's sign-in fail.
func credentialIDFromAssertion(response []byte) (string, error) {
	parsed, err := codec.Tolerant[struct {
		ID string `json:"id"`
	}](response)
	if err != nil {
		return "", err
	}
	if parsed.ID == "" {
		return "", errors.New("identity: the assertion names no credential")
	}
	return parsed.ID, nil
}

// ListPasskeys returns the caller's own enrolled authenticators, newest first.
//
// Scoped to the subject and to nothing else. The store's Find is deliberately
// unscoped — a ceremony asks whose a credential is — so every scoping decision
// has to be made by the caller, and this is one of them.
func (p *Passkeys) ListPasskeys(
	ctx context.Context, subjectID string,
) ([]StoredPasskey, error) {
	if subjectID == "" {
		return nil, errs.Internalf("no authenticated subject reached the passkey handler")
	}
	out, err := p.store.List(ctx, subjectID)
	if err != nil {
		return nil, fmt.Errorf("listing passkeys: %w", err)
	}
	return out, nil
}
