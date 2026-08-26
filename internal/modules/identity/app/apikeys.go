package app

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"log/slog"
	"regexp"
	"strings"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// The two stream categories this file writes.
const (
	// ServiceAccountCategory names a service account's stream:
	// service_account-<svc id>.
	ServiceAccountCategory eventsourcing.Category = "service_account"

	// APIKeyCategory names one key's stream: api_key-<key id>.
	//
	// One stream per KEY rather than one per organization or one per owner. A
	// key's rotation and revocation are its own decisions and its own
	// concurrency boundary; sharing a stream would serialise every key operation
	// in an organization behind every other, which is Session's argument
	// unchanged.
	APIKeyCategory eventsourcing.Category = "api_key"
)

const (
	// apiKeyTokenBytes is the entropy in the secret half of a key. 256 bits,
	// exactly as a session token, and for the reason `secret` states in its
	// package comment: the value is machine-generated and machine-checked, so
	// there is no cost to being far above the 128-bit floor.
	apiKeyTokenBytes = 32

	// apiKeyTokenDomain separates API key digests from every other SHA-256 this
	// system computes.
	//
	// Its own separator rather than reusing sessionTokenDomain, and the reason
	// is the same one sessionTokenDomain gives for not reusing an emailed
	// token's purpose: the two live in different tables with different
	// lifetimes and different consequences, and without a separator a digest
	// lifted from one is presentable to the other's lookup. That the columns
	// differ today is a property of the current schema rather than of the
	// construction.
	apiKeyTokenDomain = "chronos/identity/api_key/v1"

	// apiKeyPrefix is the fixed first segment of every token this system mints.
	//
	// It exists for LEAK RESPONSE and not for parsing. A fixed, unusual,
	// greppable prefix is what lets a secret scanner — GitHub's, a customer's
	// pre-commit hook, our own log scrubber — recognise one of our credentials
	// in a paste without knowing anything else about it (identity.md §10). A
	// token that looked like ordinary base64 would be invisible to every one of
	// them.
	apiKeyPrefix = "chr"
)

// APIKeyToken is the wire form of a key, and it is the one place its grammar is
// written.
//
//	chr_<env>_<key id>_<secret>
//	 │    │      │        └─ 256 random bits, base64url, shown once, never stored
//	 │    │      └────────── the public identifier — which key leaked, without the secret
//	 │    └───────────────── the deployment, so a staging token cannot be replayed at prod
//	 └────────────────────── the scanner prefix
//
// # Why the environment is in the token and not only in configuration
//
// It is bound into the DIGEST, so a token minted in staging hashes to a value
// production's table does not contain. The alternative — an environment column
// compared after the lookup — is a check somebody can forget, and the failure of
// forgetting is that a token from a system with weaker access controls works
// against the one with real customer data.
//
// # Why the key id travels in the token at all
//
// The lookup does not need it: the digest is the primary key. It is there so
// that a token found in a log, a paste or a bug report can be attributed to a
// key and revoked WITHOUT anybody having to present the secret. identity.md §10
// calls that the leak-response path, and it is the difference between "revoke
// this key" and "revoke every key in the organization and hope".
type APIKeyToken struct {
	Environment string
	KeyID       ids.APIKeyID

	// Plaintext is the whole token, exactly as it goes to the caller and comes
	// back on the wire. It is returned by Mint to one caller and never stored,
	// never logged and never put in an event.
	Plaintext string
}

// apiKeyEnvironment is what may appear in the environment segment.
//
// Lower-case alphanumeric, short. It is part of a credential's public form, so
// it is bounded here rather than trusted from configuration: an environment
// name containing an underscore would add a segment and make every token
// unparseable, and one containing a '_' typed by a deployer is the kind of
// mistake that is discovered when the first key fails to authenticate.
var apiKeyEnvironment = regexp.MustCompile(`^[a-z][a-z0-9]{0,15}$`)

// APIKeyTokenDigest is what `api_key_secret` holds and what a presented token is
// hashed to.
//
// SHA-256 and not Argon2id, and the rule is where the entropy came from: the
// secret is 256 bits from crypto/rand, so there is no candidate list to search
// and a slow hash would add tens of milliseconds to EVERY request a machine
// credential makes while buying nothing — and would make the authenticator a
// memory-amplification vector for anyone posting garbage tokens. This is the
// argument `secret`'s package comment makes and `SessionTokenDigest` repeats.
//
// # Where this departs from identity.md §10, and why
//
// The design says HMAC-SHA256 under a server-side pepper. A pepper defends a
// LOW-ENTROPY secret against an attacker who has the digests and can guess
// candidates offline; it buys nothing against 256 bits of crypto/rand, because
// there are no candidates. What it costs is real: a second key to hold, to
// distribute to every process that authenticates, and to rotate — and a
// rotation of it invalidates every key in the system at once, with no migration
// path, because the stored digests cannot be recomputed without the plaintexts
// nobody has.
//
// So the derivation is `secret.Digest`, which is the platform's one
// length-prefixed, domain-separated SHA-256. Writing a second construction here
// is precisely the drift this repository already paid for once — `digestUnder`
// used to carry its own copy, byte for byte identical, with its own near-copy of
// the boundary test.
//
// It hashes the WHOLE token. The environment and the key id are therefore bound
// to the secret by the digest itself: a token pairing key A's id with key B's
// secret resolves to nothing, and so does a staging token presented to
// production, with no comparison for anybody to forget.
//
// Exported because the authenticator must reduce an incoming token exactly as
// this reduced the issued one. Two implementations of that reduction is two
// chances for them to differ, and the failure mode of differing is that every
// key in the system resolves to nothing, at deploy time, for everyone at once.
func APIKeyTokenDigest(plaintext string) []byte {
	return digestUnder(apiKeyTokenDomain, plaintext)
}

// MintAPIKeyToken draws a token for a key.
//
// The plaintext is returned to exactly one caller and the digest to the store,
// so there is no moment at which a token exists that nothing can resolve, and
// none at which a digest is stored for a token nobody was given.
func MintAPIKeyToken(
	environment string, keyID ids.APIKeyID, entropy io.Reader,
) (APIKeyToken, []byte, error) {
	if !apiKeyEnvironment.MatchString(environment) {
		return APIKeyToken{}, nil, errs.Internalf(
			"%q is not a usable API key environment; it is lower-case alphanumeric and at "+
				"most 16 characters, because it is a segment of a credential and an "+
				"underscore in it would make every token this deployment mints unparseable",
			environment)
	}
	if keyID.IsZero() {
		return APIKeyToken{}, nil, errs.Internalf("an API key token needs the key it belongs to")
	}

	raw := make([]byte, apiKeyTokenBytes)
	if _, err := io.ReadFull(entropy, raw); err != nil {
		// Refused, never degraded. A short read leaves trailing zero bytes, and a
		// credential whose tail is predictable is one an attacker can search
		// while the holder believes they hold 256 bits.
		return APIKeyToken{}, nil, fmt.Errorf("generating an API key: %w", err)
	}
	// base64url without padding: the token travels in an Authorization header
	// and is pasted into CI configuration, so '+', '/' and '=' would all need
	// escaping somewhere if they ever appeared.
	plaintext := apiKeyPrefix + "_" + environment + "_" + keyID.String() + "_" +
		base64.RawURLEncoding.EncodeToString(raw)

	return APIKeyToken{
		Environment: environment,
		KeyID:       keyID,
		Plaintext:   plaintext,
	}, APIKeyTokenDigest(plaintext), nil
}

// LooksLikeAPIKey reports whether a bearer token is one of ours to try.
//
// A cheap prefix test and nothing more. It exists so the authenticator can route
// a presented bearer to the right resolver without either resolver having to
// interpret the other's tokens — and it is deliberately not a validity check: a
// value that starts with `chr_` and is otherwise nonsense is routed here and
// refused here, rather than falling through to the session lookup and producing
// a second, differently-worded refusal that a caller could tell apart.
func LooksLikeAPIKey(token string) bool {
	return strings.HasPrefix(token, apiKeyPrefix+"_")
}

// ParseAPIKeyToken splits a presented token into its parts.
//
// The parse is for ROUTING and for leak attribution, never for authentication:
// nothing it returns is trusted. The key id it yields names the key the
// PRESENTER claims to hold, and the only thing that establishes they hold it is
// the digest probe, which covers the whole string anyway.
//
// Exactly five segments, because the key id contains its own underscore
// (`key_01ARZ…`, ADR-030) and so occupies two of them. Splitting with a limit
// would let a secret containing an underscore change the meaning of the
// segments; base64url contains none, so a token with a sixth segment is not one
// this system minted.
func ParseAPIKeyToken(token string) (APIKeyToken, error) {
	parts := strings.Split(token, "_")
	if len(parts) != 5 || parts[0] != apiKeyPrefix {
		return APIKeyToken{}, errs.Unauthenticatedf("this is not an API key")
	}
	if !apiKeyEnvironment.MatchString(parts[1]) {
		return APIKeyToken{}, errs.Unauthenticatedf("this is not an API key")
	}
	keyID, err := ids.Parse[ids.APIKey](parts[2] + "_" + parts[3])
	if err != nil {
		return APIKeyToken{}, errs.Unauthenticatedf("this is not an API key")
	}
	if parts[4] == "" {
		return APIKeyToken{}, errs.Unauthenticatedf("this is not an API key")
	}
	return APIKeyToken{Environment: parts[1], KeyID: keyID, Plaintext: token}, nil
}

// ---------------------------------------------------------------------------
// Ports
// ---------------------------------------------------------------------------

// NewAPIKeySecret is one digest and the facts a machine request resolves from.
//
// The owner, the organization and the scopes travel with the digest and are
// stored beside it, which is migration 00051's deliberate divergence from the
// session pair: the authenticator touches no projection, so a rebuild of
// `api_key_view` does not break every integration in the fleet. They cannot
// drift, because nothing edits any of them — changing a key's owner, scopes or
// organization means a new key.
type NewAPIKeySecret struct {
	Digest    []byte
	KeyID     ids.APIKeyID
	OrgID     string
	Owner     domain.APIKeyOwner
	Scopes    []string
	ExpiresAt time.Time
	IssuedAt  time.Time
}

// APIKeySecrets is the AUTHORITATIVE half of a key: the digests, which are never
// in the log.
//
// Declared by the consumer and narrowed to three operations (ADR-001,
// CONVENTIONS §2). Every one of them is a write, and there is deliberately no
// read: this port is held by the command handlers, and a handler able to read a
// digest is a handler through which one can reach a log line or an error
// message.
type APIKeySecrets interface {
	// Issue records a freshly minted secret.
	Issue(ctx context.Context, secret NewAPIKeySecret) error

	// Retire puts a deadline on every CURRENT secret of a key, which is what a
	// rotation supersedes. It returns how many it retired, so a caller can tell
	// "rotated the live secret" from "rotated a key whose secret had already
	// been swept" without a second query.
	Retire(ctx context.Context, keyID ids.APIKeyID, retiresAt time.Time) (int, error)

	// Delete removes every secret a key ever had. This is revocation, and it is
	// immediate: identity.md §10 requires it to take effect at once, and waiting
	// for a projection is far too late for a credential somebody has published.
	Delete(ctx context.Context, keyID ids.APIKeyID) (int, error)
}

// ServiceAccountDirectory answers "does this service account exist, in this
// organization".
//
// Narrowed to existence deliberately: the one caller is the key-issuing command,
// which needs to know that the owner it is about to bind a credential to is
// real and is this tenant's, and needs nothing else. Row-level security supplies
// the "this tenant's" half, so a service account in another organization is
// indistinguishable here from one that does not exist — which is the answer
// ADR-036 wants a caller naming somebody else's principal to get.
type ServiceAccountDirectory interface {
	Exists(ctx context.Context, id ids.ServiceAccountID) (bool, error)
}

// ---------------------------------------------------------------------------
// The use case
// ---------------------------------------------------------------------------

// APIKeys is identity.md §10: service accounts, and the machine credentials that
// act as them.
//
// # Every command here is ORGANIZATION-scoped, and none of them is self-scoped
//
// That is the difference between this file and every other use case in the
// module. A person's password, sessions and second factors are theirs and are
// reached with `relation: "self"`; an API key is a credential that acts inside a
// TENANT, so the RPCs declare `admin` on `organization` and the request goes
// through gates 1, 2 and 3 like any other org-scoped write. The organization
// comes from the resolved tenant scope and never from the request — a request
// field naming an organization would make every one of these an existence probe
// for org ids.
type APIKeys struct {
	clock    clock.Clock
	entropy  io.Reader
	env      string
	accounts AggregateLoader[*domain.ServiceAccount]
	keys     AggregateLoader[*domain.APIKey]
	appender eventsourcing.MultiAppender
	schemas  eventsourcing.SchemaVersions
	secrets  APIKeySecrets
	dir      ServiceAccountDirectory
	log      *slog.Logger
}

// APIKeysDeps is everything the commands need.
type APIKeysDeps struct {
	Clock clock.Clock

	// Entropy is the source for key secrets. REQUIRED, with no default: a
	// defaulted entropy source is the one dependency where a wiring mistake is
	// silent, produces working software, and yields guessable credentials.
	Entropy io.Reader

	// Environment is the segment every token this deployment mints carries, and
	// is bound into the digest. REQUIRED, with no default — a defaulted value
	// would be the same in staging and in production, which is exactly the
	// property the segment exists to break.
	Environment string

	Accounts AggregateLoader[*domain.ServiceAccount]
	Keys     AggregateLoader[*domain.APIKey]

	// Appender writes. MultiAppender rather than a repository, for the reason
	// every other identity use case takes it: one append path means one
	// derivation of event ids.
	Appender eventsourcing.MultiAppender

	// Schemas stamps each appended event with its schema version. Without it the
	// event is stored at version 0 while the registry declares 1, and the
	// aggregate can never be loaded back — invisibly, because projections do not
	// upcast.
	Schemas eventsourcing.SchemaVersions

	// Secrets is the authoritative digest store. REQUIRED: without it a key is
	// appended to the log and no caller is ever given a way to use it, and —
	// worse — a REVOCATION would append an event and leave the credential live
	// until the projector caught up, which is the one thing identity.md §10
	// says revocation may not do.
	Secrets APIKeySecrets

	// Directory checks that a named service account exists in this tenant.
	// REQUIRED: without it a key can be bound to a principal that does not
	// exist, which is a credential nothing can revoke by owner and nobody can
	// find on a screen.
	Directory ServiceAccountDirectory

	// Log is optional and defaults to slog.Default(). Nothing here logs a token:
	// the only values that reach it are identifiers and pseudonyms.
	Log *slog.Logger
}

// NewAPIKeys validates the wiring and returns the handlers.
func NewAPIKeys(deps APIKeysDeps) (*APIKeys, error) {
	missing := func(name string) error {
		return fmt.Errorf("identity/app: API keys need %s", name)
	}
	switch {
	case deps.Clock == nil:
		return nil, missing("a clock")
	case deps.Entropy == nil:
		return nil, missing("an entropy source; a defaulted one is the single dependency " +
			"whose absence produces software that works and credentials that are guessable")
	case deps.Environment == "":
		return nil, missing("an environment name for the tokens it mints; without one a " +
			"staging token and a production token are the same shape and the same digest")
	case !apiKeyEnvironment.MatchString(deps.Environment):
		return nil, fmt.Errorf("identity/app: %q is not a usable API key environment; it is "+
			"lower-case alphanumeric and at most 16 characters, because an underscore in it "+
			"would add a segment and make every token this deployment mints unparseable",
			deps.Environment)
	case deps.Accounts == nil:
		return nil, missing("a service account loader")
	case deps.Keys == nil:
		return nil, missing("an API key loader")
	case deps.Appender == nil:
		return nil, missing("an appender")
	case deps.Schemas == nil:
		return nil, missing("a schema registry; without one every event it writes is stored " +
			"at version 0 and the key can never be loaded back")
	case deps.Secrets == nil:
		return nil, missing("a secret store; without one a revocation appends an event and " +
			"leaves the credential live until the projector catches up, which is the one " +
			"thing revocation may not do")
	case deps.Directory == nil:
		return nil, missing("a service account directory")
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &APIKeys{
		clock: deps.Clock, entropy: deps.Entropy, env: deps.Environment,
		accounts: deps.Accounts, keys: deps.Keys,
		appender: deps.Appender, schemas: deps.Schemas,
		secrets: deps.Secrets, dir: deps.Directory, log: log,
	}, nil
}

// ---------------------------------------------------------------------------
// Service accounts
// ---------------------------------------------------------------------------

// CreateServiceAccountCommand brings a non-human principal into existence.
type CreateServiceAccountCommand struct {
	// OrgID is the RESOLVED tenant, read from the scope gate 1 established and
	// never from the request. A request field naming an organization would make
	// this an existence probe for org ids and, worse, would let a member of one
	// organization create a principal inside another.
	OrgID string

	// ActorID is the caller's pseudonym, read from the session. A person,
	// always: the RPC requires AAL2, and no machine credential can reach AAL2,
	// so a service account cannot create another one.
	ActorID string

	// Name is the machine-readable label. Bounded and pattern-checked by the
	// aggregate, because it enters an append-only log in cleartext.
	Name string

	IdempotencyKey string
}

// CreateServiceAccountResult is the created principal.
type CreateServiceAccountResult struct {
	ServiceAccountID ids.ServiceAccountID
	Position         eventsourcing.Position
}

// CreateServiceAccount records the principal, and gives it nothing.
//
// It mints NO credential, and the separation is the point: creating a principal
// and giving it a way in are two decisions, the second is the one that changes
// what can happen, and an incident timeline has to be able to tell them apart.
// A service account that has just been created can authenticate nothing at all.
func (a *APIKeys) CreateServiceAccount(
	ctx context.Context, cmd CreateServiceAccountCommand,
) (CreateServiceAccountResult, error) {
	if cmd.IdempotencyKey == "" {
		return CreateServiceAccountResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	now := a.clock.Now().UTC()
	id := ids.New[ids.ServiceAccount](now, a.entropy)

	account := eventsourcing.NewAggregate(domain.NewServiceAccount)
	if err := account.Create(id, cmd.OrgID, cmd.Name, cmd.ActorID, now); err != nil {
		return CreateServiceAccountResult{}, err
	}

	stream, err := eventsourcing.NewStreamID(ServiceAccountCategory, id.String())
	if err != nil {
		return CreateServiceAccountResult{}, err
	}
	position, err := a.append(ctx, cmd.IdempotencyKey, cmd.OrgID, cmd.ActorID, stream,
		eventsourcing.ExpectedFor(account), account)
	if err != nil {
		return CreateServiceAccountResult{}, err
	}
	return CreateServiceAccountResult{ServiceAccountID: id, Position: position}, nil
}

// ---------------------------------------------------------------------------
// Keys
// ---------------------------------------------------------------------------

// CreateAPIKeyCommand mints a machine credential.
type CreateAPIKeyCommand struct {
	// OrgID is the resolved tenant. It becomes the key's IMMUTABLE binding.
	OrgID string

	// ActorID is the caller's pseudonym. It is who the key is attributed to in
	// the log and who the security mail names — never taken from the request.
	ActorID string

	// Owner is the principal the key acts as. When it is zero the key is a
	// PERSONAL access token owned by the caller, which is the shape a script or
	// a personal CLI wants; when it names a service account the key is an
	// integration credential that survives the caller's departure.
	//
	// The default is deliberately the NARROWER of the two. A key that defaulted
	// to a service account would be a durable, org-owned credential created by
	// a client that simply did not send the field.
	Owner domain.APIKeyOwner

	// Scopes is the coarse capability list. Required — see
	// domain.normalizeScopes for why an empty list is refused rather than read
	// as "everything the owner can do".
	Scopes []string

	// Lifetime is how long the key lives. Zero means
	// domain.DefaultAPIKeyLifetime; the aggregate caps it at
	// domain.MaxAPIKeyLifetime.
	Lifetime time.Duration

	IdempotencyKey string
}

// CreateAPIKeyResult carries the plaintext back ONCE.
//
// Only the digest is stored, so this is the only moment the token exists
// anywhere this system can reach. A caller that loses it rotates the key, which
// is the correct outcome — an endpoint that could re-display it would turn a
// stolen admin session into a permanent copy of every credential the
// organization holds.
type CreateAPIKeyResult struct {
	KeyID     ids.APIKeyID
	Token     string
	Owner     domain.APIKeyOwner
	Scopes    []string
	ExpiresAt time.Time
	Position  eventsourcing.Position
}

// CreateAPIKey mints a key and returns its one and only plaintext.
//
// # The order of operations, and why each step is where it is
//
//  1. Resolve and CHECK the owner. A key bound to a service account that does
//     not exist, or to one in another organization, is a credential nothing can
//     revoke by owner and nobody can find on a screen.
//  2. Decide, in the aggregate. Every bound — the mandatory expiry, the
//     lifetime ceiling, the scope grammar — lives there and not here.
//  3. Mint the token BEFORE the append, so a failure to produce entropy costs
//     nothing but the request. A token generated after the event would leave a
//     key in the log that no caller was ever given a way to use.
//  4. Append.
//  5. Store the digest LAST. A digest stored before the append would be a live
//     credential for a key the log does not contain — and if the append then
//     failed, nothing would ever revoke it, because revocation works from the
//     key's stream.
func (a *APIKeys) CreateAPIKey(
	ctx context.Context, cmd CreateAPIKeyCommand,
) (CreateAPIKeyResult, error) {
	if cmd.IdempotencyKey == "" {
		return CreateAPIKeyResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	if cmd.ActorID == "" {
		return CreateAPIKeyResult{}, errs.Unauthenticatedf("this request has not authenticated")
	}

	owner := cmd.Owner
	if owner.Kind == "" && owner.ID == "" {
		// The narrower default: a personal access token owned by the caller.
		owner = domain.UserOwner(cmd.ActorID)
	}
	if err := a.checkOwner(ctx, owner); err != nil {
		return CreateAPIKeyResult{}, err
	}

	now := a.clock.Now().UTC()
	lifetime := cmd.Lifetime
	if lifetime == 0 {
		lifetime = domain.DefaultAPIKeyLifetime
	}
	keyID := ids.New[ids.APIKey](now, a.entropy)

	key := eventsourcing.NewAggregate(domain.NewAPIKey)
	if err := key.Issue(
		keyID, cmd.OrgID, owner, cmd.Scopes, now.Add(lifetime), cmd.ActorID, now,
	); err != nil {
		return CreateAPIKeyResult{}, err
	}

	token, digest, err := MintAPIKeyToken(a.env, keyID, a.entropy)
	if err != nil {
		return CreateAPIKeyResult{}, err
	}

	stream, err := eventsourcing.NewStreamID(APIKeyCategory, keyID.String())
	if err != nil {
		return CreateAPIKeyResult{}, err
	}
	position, err := a.append(ctx, cmd.IdempotencyKey, cmd.OrgID, cmd.ActorID, stream,
		eventsourcing.ExpectedFor(key), key)
	if err != nil {
		return CreateAPIKeyResult{}, err
	}

	if err := a.secrets.Issue(ctx, NewAPIKeySecret{
		Digest:    digest,
		KeyID:     keyID,
		OrgID:     cmd.OrgID,
		Owner:     owner,
		Scopes:    key.Scopes(),
		ExpiresAt: key.ExpiresAt(),
		IssuedAt:  now,
	}); err != nil {
		// The key exists in the log and has no secret. Reported as a failure so
		// the caller mints another rather than being handed a token that resolves
		// to nothing on its first request. The dead key is visible on the
		// management screen and revocable like any other.
		return CreateAPIKeyResult{}, fmt.Errorf("storing an API key secret: %w", err)
	}

	return CreateAPIKeyResult{
		KeyID:     keyID,
		Token:     token.Plaintext,
		Owner:     owner,
		Scopes:    key.Scopes(),
		ExpiresAt: key.ExpiresAt(),
		Position:  position,
	}, nil
}

// RotateAPIKeyCommand replaces a key's secret, keeping the key.
type RotateAPIKeyCommand struct {
	OrgID   string
	ActorID string
	KeyID   ids.APIKeyID

	// Overlap is how long the superseded secret keeps working. Zero is
	// MEANINGFUL and is the leak response: the old secret dies at the instant of
	// the rotation. The caller distinguishes "I did not say" from "immediately"
	// with Immediate below, because a zero duration cannot express both.
	Overlap time.Duration

	// Immediate makes a zero Overlap mean zero rather than the default.
	//
	// A separate flag rather than a *time.Duration, because the two readings of
	// an absent overlap have opposite consequences — the default keeps a leaked
	// secret alive for a day, and zero breaks every consumer that has not
	// reconfigured — and a nil pointer that a caller forgot to set would resolve
	// to whichever of those the implementation happened to pick.
	Immediate bool

	// Lifetime is the NEW secret's deadline. Zero means
	// domain.DefaultAPIKeyLifetime. Rotation re-arms the clock rather than
	// inheriting the old deadline: a key rotated on its last day that kept the
	// old one would expire hours after everybody reconfigured for it.
	Lifetime time.Duration

	IdempotencyKey string
}

// RotateAPIKeyResult carries the new plaintext back once, and says when the old
// one dies.
type RotateAPIKeyResult struct {
	KeyID string
	Token string

	// PreviousRetiresAt is when the superseded secret stops resolving. Returned
	// so a client can show it: "your old key works until 14:02 tomorrow" is the
	// sentence that makes a rotation safe to perform, and a client that had to
	// compute it from a policy constant would be computing a number this server
	// might change.
	PreviousRetiresAt time.Time
	ExpiresAt         time.Time
	Position          eventsourcing.Position
}

// RotateAPIKey issues a new secret and puts a deadline on the old one.
//
// # Both halves, and neither alone
//
// A rotation that only issued would leave the old secret live forever. One that
// only retired would be a revocation. Both happen, in this order:
//
//  1. append, so the log records the rotation and the deadline before either
//     secret changes;
//  2. RETIRE the current secret, stamping it with the deadline the event
//     recorded;
//  3. ISSUE the new one.
//
// Retire before issue, and that order is load-bearing. `Retire` puts a deadline
// on every secret whose `retires_at IS NULL` — that is what makes it idempotent
// under a second rotation — so issuing first would immediately retire the secret
// that was just minted, and the caller would be handed a token that was already
// dying.
//
// # What a failure between the steps leaves behind
//
// A failure after the append and before the retire leaves both secrets live and
// the log saying the old one should be dying. That is the SAFE direction — the
// caller sees an error and retries, and the retry is idempotent because the
// event ids derive from the same key — and it is the direction chosen
// deliberately over the alternative, in which a rotation that failed halfway has
// already killed the secret every consumer is still using.
func (a *APIKeys) RotateAPIKey(
	ctx context.Context, cmd RotateAPIKeyCommand,
) (RotateAPIKeyResult, error) {
	if cmd.IdempotencyKey == "" {
		return RotateAPIKeyResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	key, err := a.load(ctx, cmd.OrgID, cmd.KeyID)
	if err != nil {
		return RotateAPIKeyResult{}, err
	}

	now := a.clock.Now().UTC()
	overlap := cmd.Overlap
	if overlap == 0 && !cmd.Immediate {
		overlap = domain.DefaultRotationOverlap
	}
	lifetime := cmd.Lifetime
	if lifetime == 0 {
		lifetime = domain.DefaultAPIKeyLifetime
	}

	if err := key.Rotate(overlap, now.Add(lifetime), cmd.ActorID, now); err != nil {
		return RotateAPIKeyResult{}, err
	}
	pending := key.Uncommitted()
	if len(pending) != 1 {
		return RotateAPIKeyResult{}, errs.Internalf(
			"a rotation recorded %d events; exactly one is expected", len(pending))
	}
	rotated, ok := pending[0].(*contract.ApiKeyRotated)
	if !ok {
		return RotateAPIKeyResult{}, errs.Internalf("a rotation recorded a %T", pending[0])
	}

	// Minted before the append, for CreateAPIKey's reason: a failure to produce
	// entropy must cost nothing but the request.
	token, digest, err := MintAPIKeyToken(a.env, cmd.KeyID, a.entropy)
	if err != nil {
		return RotateAPIKeyResult{}, err
	}

	stream, err := eventsourcing.NewStreamID(APIKeyCategory, cmd.KeyID.String())
	if err != nil {
		return RotateAPIKeyResult{}, err
	}
	position, err := a.append(ctx, cmd.IdempotencyKey, cmd.OrgID, cmd.ActorID, stream,
		eventsourcing.ExpectedFor(key), key)
	if err != nil {
		return RotateAPIKeyResult{}, err
	}

	if _, err := a.secrets.Retire(ctx, cmd.KeyID, rotated.PreviousRetiresAt); err != nil {
		// Reported rather than swallowed. The log says the old secret retires at
		// a deadline, and the row does not — so the old secret outlives the
		// rotation, which is the failure the whole mechanism exists to prevent.
		// The caller retries; the retry derives the same event ids and is
		// collapsed by the store.
		return RotateAPIKeyResult{}, fmt.Errorf("retiring the superseded API key secret: %w", err)
	}
	if err := a.secrets.Issue(ctx, NewAPIKeySecret{
		Digest:    digest,
		KeyID:     cmd.KeyID,
		OrgID:     key.OrgID(),
		Owner:     domain.APIKeyOwner{Kind: key.OwnerKind(), ID: key.OwnerID()},
		Scopes:    key.Scopes(),
		ExpiresAt: key.ExpiresAt(),
		IssuedAt:  now,
	}); err != nil {
		// The old secret is retiring and the new one does not exist. Reported so
		// the caller retries within the overlap window rather than discovering it
		// when the old secret dies.
		a.log.ErrorContext(ctx, "an API key rotation stored no new secret; the superseded "+
			"secret is already retiring",
			"key_id", cmd.KeyID.String(), "retires_at", rotated.PreviousRetiresAt, "error", err)
		return RotateAPIKeyResult{}, fmt.Errorf("storing the rotated API key secret: %w", err)
	}

	return RotateAPIKeyResult{
		KeyID:             cmd.KeyID.String(),
		Token:             token.Plaintext,
		PreviousRetiresAt: rotated.PreviousRetiresAt,
		ExpiresAt:         key.ExpiresAt(),
		Position:          position,
	}, nil
}

// RevokeAPIKeyCommand ends a key.
type RevokeAPIKeyCommand struct {
	OrgID   string
	ActorID string
	KeyID   ids.APIKeyID

	// Reason is a short machine-readable label — `leaked`, `owner_left`. It
	// enters an event, so it carries no free text (ADR-002).
	Reason string

	IdempotencyKey string
}

// RevokeAPIKeyResult reports what the revocation did.
type RevokeAPIKeyResult struct {
	// Changed is false when the key was already revoked. Nothing was appended,
	// and it is NOT an error: the caller wanted the key unusable and it is.
	Changed bool

	// SecretsDestroyed is how many digest rows were removed. Recorded so a test
	// can assert the immediate half RAN rather than assert that a function was
	// called, and so an operator can see that a revocation of an
	// already-revoked key still swept a secret that had somehow survived.
	SecretsDestroyed int

	Position eventsourcing.Position
}

// RevokeAPIKey ends the key in the log AND destroys its secrets in the same
// request.
//
// # Why both, and why neither alone is enough
//
// This is the question operator offboarding answered for a person
// (operator/app/operators.go, Disable), and the answer is the same shape:
//
//   - The EVENT alone leaves the credential usable until the projector catches
//     up. identity.md §10 says revocation is immediate and gives the reason: an
//     API key has no short-lived access token whose expiry bounds the window, so
//     "eventually" here means "until a projector that may be minutes behind, or
//     stopped, notices".
//   - The DELETE alone leaves nothing in the log saying why the key stopped
//     working, and a rebuild would not reproduce the revocation — the key would
//     read as live on every screen while resolving nothing, which is the state
//     that generates a support ticket nobody can close.
//
// # The order: append first, then destroy
//
// Destroying first and failing the append would cut off a working integration
// with nothing recorded anywhere to say why — the caller sees an error, retries,
// and the log still contains no revocation. Appending first leaves at worst a
// short window in which the log says revoked and the credential still resolves,
// which is loud (the error is returned and logged) and self-correcting on retry.
//
// # Already revoked is not a no-op
//
// A second call records nothing and STILL destroys secrets, for the reason
// operator offboarding gives: a second call is what somebody makes when they are
// not sure the first took, and answering it by doing nothing is how a
// half-finished revocation stays half-finished. A rotation racing the first
// revocation can insert a secret the first sweep never saw.
func (a *APIKeys) RevokeAPIKey(
	ctx context.Context, cmd RevokeAPIKeyCommand,
) (RevokeAPIKeyResult, error) {
	if cmd.IdempotencyKey == "" {
		return RevokeAPIKeyResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	key, err := a.load(ctx, cmd.OrgID, cmd.KeyID)
	if err != nil {
		return RevokeAPIKeyResult{}, err
	}

	now := a.clock.Now().UTC()
	if err := key.Revoke(cmd.ActorID, cmd.Reason, now); err != nil {
		return RevokeAPIKeyResult{}, err
	}

	result := RevokeAPIKeyResult{}
	if len(key.Uncommitted()) > 0 {
		stream, err := eventsourcing.NewStreamID(APIKeyCategory, cmd.KeyID.String())
		if err != nil {
			return RevokeAPIKeyResult{}, err
		}
		position, err := a.append(ctx, cmd.IdempotencyKey, cmd.OrgID, cmd.ActorID, stream,
			eventsourcing.ExpectedFor(key), key)
		if err != nil {
			return RevokeAPIKeyResult{}, err
		}
		result.Changed = true
		result.Position = position
	}

	destroyed, err := a.secrets.Delete(ctx, cmd.KeyID)
	if err != nil {
		// The revocation IS recorded and the projection will mark the key within
		// seconds. Reported rather than hidden, because those seconds are exactly
		// what "immediate" was supposed to remove — and unlike a session, nothing
		// else bounds the window.
		a.log.ErrorContext(ctx, "a revoked API key's secrets could not be destroyed; it "+
			"remains usable until they are",
			"key_id", cmd.KeyID.String(), "error", err)
		return RevokeAPIKeyResult{}, fmt.Errorf("destroying the API key's secrets: %w", err)
	}
	result.SecretsDestroyed = destroyed

	a.log.WarnContext(ctx, "an API key was revoked",
		"key_id", cmd.KeyID.String(), "secrets_destroyed", destroyed,
		"changed", result.Changed, "reason", cmd.Reason)
	return result, nil
}

// ---------------------------------------------------------------------------
// Shared
// ---------------------------------------------------------------------------

// checkOwner refuses a key bound to a principal that is not this tenant's.
//
// For a USER owner there is nothing to check here: the only user a key may be
// owned by is the caller, and the caller is the actor — a request naming another
// person's pseudonym as an owner would let an admin mint a credential that acts
// as a colleague, which is impersonation with an audit trail that says the
// colleague did it. The API layer therefore never populates a user owner from
// the request, and this refuses one that disagrees with the actor in case it
// ever does.
//
// For a SERVICE ACCOUNT owner the check is existence, and row-level security
// makes it a tenant check too: an account in another organization is invisible,
// so a caller naming one gets the same answer as for one that does not exist.
func (a *APIKeys) checkOwner(ctx context.Context, owner domain.APIKeyOwner) error {
	switch owner.Kind {
	case contract.OwnerServiceAccount:
		id, err := ids.Parse[ids.ServiceAccount](owner.ID)
		if err != nil {
			return errs.NotFoundf("no such service account")
		}
		exists, err := a.dir.Exists(ctx, id)
		if err != nil {
			return errs.Internalf("resolving the service account").Wrap(err)
		}
		if !exists {
			return errs.NotFoundf("no such service account")
		}
		return nil
	case contract.OwnerUser:
		return nil
	default:
		return errs.ValidationFailedf(
			"an API key is owned by a user or by a service account and by nothing else")
	}
}

// load rebuilds a key and refuses one belonging to another organization.
//
// The org check is HERE and not only in row-level security, because this reads
// the event STREAM rather than a table — the log has no RLS, so a caller holding
// any key id could otherwise load, rotate and revoke a key in somebody else's
// tenant. A key id is not a secret: it travels in the token, appears on a
// management screen and is printed in leak reports.
//
// A key in another organization answers exactly as one that does not exist. The
// distinction would turn the management screen into a probe for which key ids
// exist across every tenant (ADR-036).
func (a *APIKeys) load(
	ctx context.Context, orgID string, keyID ids.APIKeyID,
) (*domain.APIKey, error) {
	if orgID == "" {
		return nil, errs.Internalf("no organization in scope for an API key command")
	}
	if keyID.IsZero() {
		return nil, errs.NotFoundf("no such API key")
	}
	key, err := a.keys.Load(ctx, keyID.String())
	if err != nil {
		return nil, fmt.Errorf("loading an API key: %w", err)
	}
	if key.State() == domain.APIKeyNone || key.OrgID() != orgID {
		return nil, errs.NotFoundf("no such API key")
	}
	return key, nil
}

// append writes one aggregate's uncommitted events to one stream.
//
// It mirrors Authentication.append deliberately, including the derived event ids
// and the per-event schema stamp, because a second append path in this module
// would be a second place for the id derivation to drift.
func (a *APIKeys) append(
	ctx context.Context,
	idempotencyKey, orgID, actorID string,
	stream eventsourcing.StreamID,
	expected eventsourcing.ExpectedRevision,
	agg eventsourcing.Root,
) (eventsourcing.Position, error) {
	pending := agg.Uncommitted()
	if len(pending) == 0 {
		return eventsourcing.Position{}, nil
	}

	meta := a.metadata(ctx, orgID, actorID, idempotencyKey)
	events := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		events = append(events, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(idempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, a.schemas, e.EventType()),
		})
	}

	results, err := a.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{{
		Stream:   stream,
		Expected: expected,
		Events:   events,
	}})
	if err != nil {
		return eventsourcing.Position{}, err
	}
	if len(results) == 0 {
		return eventsourcing.Position{}, errs.Internalf("the append reported no result")
	}
	agg.ClearUncommitted()
	return results[0].Position, nil
}

// metadata builds the envelope shared by every event of one command.
//
// # It sets OrgID, and every other identity use case does not
//
// That is not an inconsistency. An authentication happens on an ACCOUNT, which
// exists before any organization does, so its events carry no tenant. A service
// account and a key exist only inside one, and the projector reads the tenant
// scope from exactly this field (`projection.ScopeOf`) — every statement it runs
// goes through `SET LOCAL app.org_id`, so an event with no OrgID would be
// projected unscoped and the row-level security policy on `api_key_view` would
// refuse the insert. The projection would stop, which is the correct direction
// for that mistake to fail in and is still a mistake worth not making.
//
// # No SubjectIDs, and an ActorID that is always a person
//
// The events concern a KEY and a machine principal, and neither is a data
// subject: there is no personal data in either, so there is nothing for a
// pseudonym to stand in for and `AudienceSubject` would resolve to nobody.
//
// The ACTOR is the admin who performed the action, and it is what the security
// mail is addressed to (`notify.AudienceActor`). That is the right recipient
// rather than a fallback: an attacker holding a stolen admin session minting a
// durable machine credential is exactly what these alerts exist to interrupt,
// and the person who can recognise "I did not do that" is the admin whose
// authority was used.
func (a *APIKeys) metadata(
	ctx context.Context, orgID, actorID, idempotencyKey string,
) eventsourcing.Metadata {
	meta := eventsourcing.Metadata{
		OccurredAt: a.clock.Now().UTC(),
		OrgID:      orgID,
		ActorID:    actorID,
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
