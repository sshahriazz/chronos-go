package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Federated ceremony purposes. Distinct from a WebAuthn ceremony's, and checked
// in the statement that consumes one, so a ceremony issued to LINK a provider to
// an existing account cannot be answered as a SIGN-IN — which would let anybody
// who can start a link complete an authentication.
const (
	CeremonyFederatedLogin CeremonyPurpose = "federated_login"
	CeremonyFederatedLink  CeremonyPurpose = "federated_link"
)

// FederationProviders resolves a provider by name and performs its ceremony.
//
// A port declared by its consumer (CONVENTIONS §2). The implementation is
// internal/adapter/oidc; this package never learns how a code is exchanged or a
// JWKS is fetched, and the adapter never learns what a provider identity means
// to an account.
type FederationProviders interface {
	// Begin builds an authorization request for one provider.
	Begin(name string) (FederatedCeremony, error)

	// Finish exchanges the code and verifies the token, returning what the
	// provider proved.
	Finish(ctx context.Context, name string, state FederatedCeremonyState, cb FederatedCallback) (FederatedIdentity, error)

	// Names lists the configured providers, so a client can render the buttons
	// this deployment actually supports.
	Names() []string
}

// The port's own types, so this package names nothing from an adapter.
type (
	FederatedCeremony struct {
		AuthorizationURL string

		// State is the CSRF binding AND the ceremony's key. The provider echoes
		// it, so it is what the callback arrives holding — using it as the
		// storage key means the callback needs no other correlation.
		State string

		// Session is the adapter's own state: the PKCE verifier and the nonce.
		// Both stay server-side, which is what makes them a binding rather than
		// a claim.
		Session FederatedCeremonyState
	}

	// FederatedCeremonyState is opaque here and meaningful only to the adapter.
	FederatedCeremonyState struct {
		Nonce    string `json:"nonce"`
		Verifier string `json:"verifier"`
		State    string `json:"state"`
	}

	FederatedCallback struct {
		Code  string
		State string

		// Issuer is RFC 9207's `iss`, when the provider sends one.
		Issuer string
	}

	// FederatedIdentity is what a completed ceremony proved.
	FederatedIdentity struct {
		Issuer  contract.Issuer
		Subject string

		// Email is the address the provider asserted. It exists here for exactly
		// one step — being reduced to a blind index — and is never stored, logged
		// or placed in an event (ADR-002).
		Email string

		// EmailVerification is the provider's TRI-STATE claim.
		EmailVerification contract.ProviderVerification

		// The two provider-specific signals the auto-link decision needs.
		EntraEmailDomainOwnerVerified bool
		AppleUsesPrivateRelay         bool
		GitHubNoreply                 bool
	}
)

// Federation is identity.md §7's flow.
type Federation struct {
	clock       clock.Clock
	providers   FederationProviders
	index       EmailIndexer
	directory   AccountDirectory
	subjects    UserDirectory
	users       AggregateLoader[*domain.User]
	claims      AggregateLoader[*domain.FederatedClaim]
	appender    eventsourcing.MultiAppender
	schemas     eventsourcing.SchemaVersions
	challenges  ChallengeStore
	revocations SessionRevoker
	ttl         time.Duration
	log         *slog.Logger
}

// FederationDeps is what the flow needs.
type FederationDeps struct {
	Clock     clock.Clock
	Providers FederationProviders

	// Index reduces the provider's asserted address to a blind index. It is the
	// ONLY thing done with that address, and the reason the flow can hold one at
	// all without violating ADR-002.
	Index EmailIndexer

	// Directory answers which account claims an index — the "does an account
	// already exist for this address" half of the auto-link decision.
	Directory AccountDirectory
	Subjects  UserDirectory

	Users  AggregateLoader[*domain.User]
	Claims AggregateLoader[*domain.FederatedClaim]

	// Appender writes the account and the provider-identity claim in ONE atomic
	// append. Two sequential writes would leave an account holding a link whose
	// uniqueness was never claimed, which is rule 4 defeated by a crash.
	Appender eventsourcing.MultiAppender
	Schemas  eventsourcing.SchemaVersions

	Challenges  ChallengeStore
	Revocations SessionRevoker

	TTL time.Duration
	Log *slog.Logger
}

// DefaultFederatedCeremonyTTL bounds an authorization request.
//
// Ten minutes: long enough to read a consent screen and complete the provider's
// own second factor, short enough that an abandoned request is not a hole left
// open on a shared machine.
const DefaultFederatedCeremonyTTL = 10 * time.Minute

func NewFederation(d FederationDeps) (*Federation, error) {
	switch {
	case d.Clock == nil:
		return nil, errors.New("identity: federation needs a clock")
	case d.Providers == nil:
		return nil, errors.New("identity: federation needs providers")
	case d.Index == nil:
		return nil, errors.New("identity: federation needs an email indexer; without one " +
			"the provider's address would have to be compared in the clear")
	case d.Directory == nil, d.Subjects == nil:
		return nil, errors.New("identity: federation needs the account directories")
	case d.Users == nil, d.Claims == nil:
		return nil, errors.New("identity: federation needs the account and claim aggregates")
	case d.Appender == nil:
		return nil, errors.New("identity: federation needs a multi-stream appender; the " +
			"account and the provider-identity claim must move in ONE append, or a crash " +
			"leaves a link whose uniqueness was never claimed")
	case d.Schemas == nil:
		return nil, errors.New("identity: federation needs schema versions")
	case d.Challenges == nil:
		return nil, errors.New("identity: federation needs a challenge store; without one " +
			"nothing makes a ceremony single-use and one code mints two sessions")
	case d.Revocations == nil:
		return nil, errors.New("identity: federation needs a session revoker")
	}
	f := &Federation{
		clock: d.Clock, providers: d.Providers, index: d.Index,
		directory: d.Directory, subjects: d.Subjects,
		users: d.Users, claims: d.Claims,
		appender: d.Appender, schemas: d.Schemas,
		challenges: d.Challenges, revocations: d.Revocations,
		ttl: d.TTL, log: d.Log,
	}
	if f.ttl <= 0 {
		f.ttl = DefaultFederatedCeremonyTTL
	}
	if f.log == nil {
		f.log = slog.Default()
	}
	return f, nil
}

// Providers lists what this deployment supports.
func (f *Federation) Providers() []string { return f.providers.Names() }

// BeginCommand starts a provider ceremony.
type BeginFederatedCommand struct {
	// Provider names the configured provider, e.g. "google".
	Provider string

	// SubjectID is set for a LINK — the caller is authenticated and attaching a
	// provider to their own account — and empty for a sign-in.
	SubjectID string
}

// BeginFederatedResult is where to send the browser.
type BeginFederatedResult struct {
	AuthorizationURL string
	ExpiresAt        time.Time
}

// Begin issues an authorization request.
func (f *Federation) Begin(
	ctx context.Context, cmd BeginFederatedCommand,
) (BeginFederatedResult, error) {
	if cmd.Provider == "" {
		return BeginFederatedResult{}, errs.ValidationFailedf("a provider is required")
	}

	ceremony, err := f.providers.Begin(cmd.Provider)
	if err != nil {
		return BeginFederatedResult{}, errs.ValidationFailedf("that provider is not configured")
	}

	purpose := CeremonyFederatedLogin
	if cmd.SubjectID != "" {
		purpose = CeremonyFederatedLink
	}

	session, err := codec.Marshal(ceremony.Session)
	if err != nil {
		return BeginFederatedResult{}, errs.Internalf("encoding the ceremony").Wrap(err)
	}

	now := f.clock.Now().UTC()
	// KEYED BY STATE. The provider echoes it, so the callback arrives holding
	// the key already and needs no second correlation value — and a callback
	// whose state names no ceremony is refused before anything is exchanged.
	if err := f.challenges.Issue(ctx, Challenge{
		ID:        ceremony.State,
		SubjectID: cmd.SubjectID,
		Purpose:   purpose,
		State:     session,
		ExpiresAt: now.Add(f.ttl),
	}); err != nil {
		return BeginFederatedResult{}, fmt.Errorf("storing the ceremony: %w", err)
	}

	return BeginFederatedResult{
		AuthorizationURL: ceremony.AuthorizationURL,
		ExpiresAt:        now.Add(f.ttl),
	}, nil
}

// FinishLoginCommand completes a federated sign-in.
type FinishFederatedLoginCommand struct {
	Provider string
	Code     string
	State    string
	Issuer   string

	IdempotencyKey string
}

// FinishFederatedLoginResult is the outcome of a sign-in.
type FinishFederatedLoginResult struct {
	// Proof is non-zero only when an account was resolved and linked.
	Proof Proof

	// LinkRefused reports that the provider identity is genuine and no account
	// could be attached to it without further proof — §7 rule 2.
	//
	// It is NOT an error. The person authenticates with an existing method and
	// links explicitly from settings, and telling them that is the whole point:
	// identity.md §7.5 requires the refusal be said explicitly rather than
	// silently creating a second account.
	LinkRefused bool

	// AccountExists reports that some account already claims the address the
	// provider asserted. Carried WITH LinkRefused so a client can say "you
	// already have an account — sign in and link this from settings" rather than
	// the dead end §7.5 names.
	AccountExists bool
}

// FinishLogin completes a sign-in and links only when §7 permits it.
func (f *Federation) FinishLogin(
	ctx context.Context, cmd FinishFederatedLoginCommand,
) (FinishFederatedLoginResult, error) {
	identity, challenge, err := f.complete(ctx, cmd.Provider, CeremonyFederatedLogin,
		FederatedCallback{Code: cmd.Code, State: cmd.State, Issuer: cmd.Issuer})
	if err != nil {
		return FinishFederatedLoginResult{}, err
	}
	_ = challenge

	now := f.clock.Now().UTC()

	// The address becomes an INDEX here and is never used as anything else.
	var index contract.EmailIndex
	if identity.Email != "" {
		if idx, idxErr := f.index.Of(identity.Email); idxErr == nil {
			index = idx
		}
	}

	local := domain.LocalAccount{}
	var account Account
	if index != "" {
		found, findErr := f.directory.AccountByEmailIndex(ctx, index)
		switch {
		case findErr == nil:
			account, local.Exists = found, true
		case errors.Is(findErr, ErrNoSuchAccount):
			// Nothing claims it. Not an error.
		default:
			return FinishFederatedLoginResult{}, fmt.Errorf("resolving the account: %w", findErr)
		}
	}

	// An existing LINK short-circuits the decision entirely: this identity has
	// already been attached to an account by somebody who proved it, and rule 1
	// is about creating a link rather than using one.
	claim, err := f.claims.Load(ctx, federatedClaimKey(identity.Issuer, identity.Subject))
	if err != nil {
		return FinishFederatedLoginResult{}, fmt.Errorf("loading the provider claim: %w", err)
	}
	if claim.Held() {
		return f.proveExistingLink(ctx, claim.SubjectID(), identity, now)
	}

	if local.Exists {
		user, loadErr := f.loadBySubject(ctx, account.SubjectID)
		if loadErr != nil {
			return FinishFederatedLoginResult{}, loadErr
		}
		local.EmailVerified = user.EmailVerified()
	}

	decision, reason := domain.DecideAutoLinkWithReason(domain.ProviderIdentity{
		Issuer:                        identity.Issuer,
		Subject:                       identity.Subject,
		EmailIndex:                    index,
		EmailVerification:             identity.EmailVerification,
		EntraEmailDomainOwnerVerified: identity.EntraEmailDomainOwnerVerified,
		AppleUsesPrivateRelay:         identity.AppleUsesPrivateRelay,
		GitHubNoreply:                 identity.GitHubNoreply,
	}, local)

	if decision != domain.LinkAuto {
		// §7 rule 2. Reported, not errored: the person authenticates with an
		// existing method and links explicitly. Saying so is what stops the dead
		// end §7.5 describes.
		// The REASON is logged and never returned. The caller must not learn
		// which condition failed — that is an oracle about somebody else's
		// account and about a third party's claims — while an operator asking
		// "why can nobody sign in with Google" has no other way to find out.
		f.log.InfoContext(ctx, "a federated sign-in was not auto-linked",
			"module", "identity", "issuer", string(identity.Issuer),
			"account_exists", local.Exists, "reason", string(reason),
			"provider_says", string(identity.EmailVerification),
			"local_verified", local.EmailVerified)
		return FinishFederatedLoginResult{LinkRefused: true, AccountExists: local.Exists}, nil
	}

	return f.link(ctx, account.SubjectID, identity, true, cmd.IdempotencyKey, now)
}

// FinishLinkCommand attaches a provider to the CALLER'S account.
type FinishFederatedLinkCommand struct {
	SubjectID string
	Provider  string
	Code      string
	State     string
	Issuer    string

	IdempotencyKey string
}

// FinishLink attaches a provider identity to an authenticated caller's account.
//
// This is §7 rule 3's path, and the one that is always available: a person whose
// sign-in was refused an auto-link authenticates with an existing method and
// links from settings. Nothing here consults the auto-link rules, because the
// caller has already proven the account — which is exactly the proof rule 1's
// conditions exist to substitute for when it is absent.
func (f *Federation) FinishLink(ctx context.Context, cmd FinishFederatedLinkCommand) error {
	if cmd.SubjectID == "" {
		return errs.Internalf("no authenticated subject reached the federation handler")
	}

	identity, challenge, err := f.complete(ctx, cmd.Provider, CeremonyFederatedLink,
		FederatedCallback{Code: cmd.Code, State: cmd.State, Issuer: cmd.Issuer})
	if err != nil {
		return err
	}
	if challenge.SubjectID != cmd.SubjectID {
		// The ceremony belongs to somebody else. Already consumed, which is
		// correct: a caller who can guess a state must not be able to probe for
		// one by trying it repeatedly.
		return errs.ValidationFailedf("this sign-in has expired; try again")
	}

	now := f.clock.Now().UTC()
	if _, err := f.link(ctx, cmd.SubjectID, identity, false, cmd.IdempotencyKey, now); err != nil {
		return err
	}
	return nil
}

// UnlinkCommand removes a provider identity from the caller's account.
type UnlinkFederatedCommand struct {
	SubjectID string

	Issuer          string
	ProviderSubject string

	IdempotencyKey string
}

// Unlink removes a link, refusing to leave the account with no way in.
func (f *Federation) Unlink(ctx context.Context, cmd UnlinkFederatedCommand) error {
	switch {
	case cmd.SubjectID == "":
		return errs.Internalf("no authenticated subject reached the federation handler")
	case cmd.IdempotencyKey == "":
		return errs.ValidationFailedf("an idempotency key is required")
	case cmd.Issuer == "" || cmd.ProviderSubject == "":
		return errs.ValidationFailedf("a provider identity is required")
	}

	issuer := contract.Issuer(cmd.Issuer)
	user, err := f.loadBySubject(ctx, cmd.SubjectID)
	if err != nil {
		return err
	}
	now := f.clock.Now().UTC()

	// The AGGREGATE decides, and its rule is the one §7 names: removing the last
	// federated link from a passwordless account is refused, because the holder
	// would then have nothing at all.
	if err := user.UnlinkFederatedIdentity(issuer, cmd.ProviderSubject, cmd.SubjectID, now); err != nil {
		return err
	}
	if len(user.Uncommitted()) == 0 {
		return nil
	}

	claim, err := f.claims.Load(ctx, federatedClaimKey(issuer, cmd.ProviderSubject))
	if err != nil {
		return fmt.Errorf("loading the provider claim: %w", err)
	}
	if err := claim.Release(cmd.SubjectID, contract.UnlinkByHolder, now); err != nil {
		return err
	}

	userID, err := f.subjects.UserBySubject(ctx, cmd.SubjectID)
	if err != nil {
		return fmt.Errorf("resolving the account: %w", err)
	}
	return f.append(ctx, cmd.IdempotencyKey, cmd.SubjectID,
		streamPart{UserCategory, userID.String(), user},
		streamPart{FederatedClaimCategory, federatedClaimKey(issuer, cmd.ProviderSubject), claim},
	)
}

// complete consumes the ceremony and verifies the provider's answer.
func (f *Federation) complete(
	ctx context.Context, provider string, purpose CeremonyPurpose, cb FederatedCallback,
) (FederatedIdentity, Challenge, error) {
	switch {
	case provider == "":
		return FederatedIdentity{}, Challenge{}, errs.ValidationFailedf("a provider is required")
	case cb.State == "" || cb.Code == "":
		return FederatedIdentity{}, Challenge{}, errs.ValidationFailedf(
			"this sign-in has expired; try again")
	}

	now := f.clock.Now().UTC()
	// SINGLE USE, atomic, purpose-checked. A read-then-delete races two
	// callbacks and both win — one code producing two sessions.
	challenge, err := f.challenges.Consume(ctx, cb.State, purpose, now)
	if err != nil {
		return FederatedIdentity{}, Challenge{}, errs.ValidationFailedf(
			"this sign-in has expired; try again")
	}

	session, err := codec.Tolerant[FederatedCeremonyState](challenge.State)
	if err != nil {
		return FederatedIdentity{}, Challenge{}, errs.Internalf("decoding the ceremony").Wrap(err)
	}

	identity, err := f.providers.Finish(ctx, provider, session, cb)
	if err != nil {
		// LOGGED and not returned. The caller gets one answer for every cause —
		// which check failed is exactly what somebody probing a redirect endpoint
		// wants — while an operator still needs the reason, and destroying it at
		// the moment it is produced is what makes a federated outage
		// undiagnosable.
		f.log.WarnContext(ctx, "a federated ceremony was refused",
			"module", "identity", "provider", provider, "error", err)
		return FederatedIdentity{}, Challenge{}, errs.Unauthenticatedf(
			"this sign-in could not be verified")
	}
	return identity, challenge, nil
}

// link attaches the identity and claims its uniqueness, in ONE append.
func (f *Federation) link(
	ctx context.Context, subjectID string, identity FederatedIdentity,
	autoLinked bool, idempotencyKey string, now time.Time,
) (FinishFederatedLoginResult, error) {
	user, err := f.loadBySubject(ctx, subjectID)
	if err != nil {
		return FinishFederatedLoginResult{}, err
	}
	if err := user.LinkFederatedIdentity(identity.Issuer, identity.Subject,
		identity.EmailVerification, autoLinked, now); err != nil {
		return FinishFederatedLoginResult{}, err
	}

	claim, err := f.claims.Load(ctx, federatedClaimKey(identity.Issuer, identity.Subject))
	if err != nil {
		return FinishFederatedLoginResult{}, fmt.Errorf("loading the provider claim: %w", err)
	}
	// RULE 4. A second account linking this identity contends on the claim's own
	// stream and loses the append.
	if err := claim.Claim(identity.Issuer, identity.Subject, subjectID, now); err != nil {
		return FinishFederatedLoginResult{}, err
	}

	userID, err := f.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		return FinishFederatedLoginResult{}, fmt.Errorf("resolving the account: %w", err)
	}
	if len(user.Uncommitted()) > 0 || len(claim.Uncommitted()) > 0 {
		if err := f.append(ctx, idempotencyKey, subjectID,
			streamPart{UserCategory, userID.String(), user},
			streamPart{FederatedClaimCategory, federatedClaimKey(identity.Issuer, identity.Subject), claim},
		); err != nil {
			return FinishFederatedLoginResult{}, err
		}
	}

	return FinishFederatedLoginResult{Proof: Proof{
		userID:    userID,
		subjectID: subjectID,
		methods:   []contract.MethodKind{contract.MethodFederated},
		// A federated sign-in is ONE factor. identity.md §2 puts "federated link
		// alone" on the AAL1 row: the provider may have required its own second
		// factor, and this system has no way to know that it did.
		aal: contract.AAL1,
		at:  now,
	}}, nil
}

// proveExistingLink signs somebody in through a link that already exists.
func (f *Federation) proveExistingLink(
	ctx context.Context, subjectID string, identity FederatedIdentity, now time.Time,
) (FinishFederatedLoginResult, error) {
	user, err := f.loadBySubject(ctx, subjectID)
	if err != nil {
		return FinishFederatedLoginResult{}, err
	}
	if !user.HasFederatedLink(identity.Issuer, identity.Subject) {
		// The claim says this identity belongs to the account and the ACCOUNT
		// disagrees. The account's own stream wins — it is the authority on which
		// methods it has — and the disagreement is loud, because it means the two
		// appends came apart.
		f.log.ErrorContext(ctx, "a provider identity is claimed by an account whose own "+
			"stream does not hold the link",
			"module", "identity", "subject_id", subjectID, "issuer", string(identity.Issuer))
		return FinishFederatedLoginResult{}, errs.Unauthenticatedf(
			"this sign-in could not be verified")
	}

	userID, err := f.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		return FinishFederatedLoginResult{}, fmt.Errorf("resolving the account: %w", err)
	}
	return FinishFederatedLoginResult{Proof: Proof{
		userID:    userID,
		subjectID: subjectID,
		methods:   []contract.MethodKind{contract.MethodFederated},
		aal:       contract.AAL1,
		at:        now,
	}}, nil
}

func (f *Federation) loadBySubject(ctx context.Context, subjectID string) (*domain.User, error) {
	userID, err := f.subjects.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			return nil, errs.NotFoundf("no such account")
		}
		return nil, fmt.Errorf("resolving the account: %w", err)
	}
	user, err := f.users.Load(ctx, userID.String())
	if err != nil {
		return nil, fmt.Errorf("loading the account: %w", err)
	}
	if user.SubjectID() == "" {
		return nil, errs.NotFoundf("no such account")
	}
	return user, nil
}

func (f *Federation) append(
	ctx context.Context, idempotencyKey, subjectID string, parts ...streamPart,
) error {
	meta := eventsourcing.Metadata{
		OccurredAt: f.clock.Now().UTC(),
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

	var (
		appends []eventsourcing.StreamAppend
		seq     int
	)
	for _, part := range parts {
		pending := part.agg.Uncommitted()
		if len(pending) == 0 {
			continue
		}
		stream, err := eventsourcing.NewStreamID(part.category, part.key)
		if err != nil {
			return err
		}
		events := make([]eventsourcing.PendingEvent, 0, len(pending))
		for _, ev := range pending {
			events = append(events, eventsourcing.PendingEvent{
				ID:    eventsourcing.DeriveEventID(idempotencyKey, seq),
				Event: ev,
				Meta:  eventsourcing.StampSchemaVersion(meta, f.schemas, ev.EventType()),
			})
			seq++
		}
		appends = append(appends, eventsourcing.StreamAppend{
			Stream:   stream,
			Expected: eventsourcing.ExpectedFor(part.agg),
			Events:   events,
		})
	}
	if len(appends) == 0 {
		return nil
	}
	if _, err := f.appender.AppendToMany(ctx, appends); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Rule 4 losing the race, among other things. The same message
			// whichever it was, for FederatedClaim.Claim's reason.
			return errs.Conflictf("this account could not be linked").Wrap(err)
		}
		return fmt.Errorf("recording the federated link: %w", err)
	}
	for _, part := range parts {
		part.agg.ClearUncommitted()
	}
	return nil
}

// FederatedClaimCategory names the stream a provider identity's uniqueness lives
// on. Permanent: it is half of the stream name every claim is written to.
const FederatedClaimCategory eventsourcing.Category = "federated_claim"

// federatedClaimKey names the stream for one provider identity.
//
// Both halves, hashed to a fixed shape: an issuer is a URL and a provider
// subject is whatever the provider chose, and neither is safe to put in a stream
// name unescaped. The pair is what rule 4 is keyed on, so the hash must cover
// both — a key derived from the subject alone would let two providers' subjects
// collide into one claim.
func federatedClaimKey(issuer contract.Issuer, subject string) string {
	sum := sha256.Sum256([]byte(string(issuer) + "\x00" + subject))
	return hex.EncodeToString(sum[:])
}

// FederationFlowShim is the interface a composition root returns.
//
// Named so cmd/api can return a nil INTERFACE rather than a typed nil pointer —
// the distinction that broke the passkey wiring on its first run, where a nil
// pointer in an interface made the interface non-nil and every handler guard
// silently stopped firing.
type FederationFlowShim interface {
	Providers() []string
	Begin(ctx context.Context, cmd BeginFederatedCommand) (BeginFederatedResult, error)
	FinishLogin(ctx context.Context, cmd FinishFederatedLoginCommand) (FinishFederatedLoginResult, error)
	FinishLink(ctx context.Context, cmd FinishFederatedLinkCommand) error
	Unlink(ctx context.Context, cmd UnlinkFederatedCommand) error
}

var _ FederationFlowShim = (*Federation)(nil)
