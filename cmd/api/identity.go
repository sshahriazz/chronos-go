package main

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/hibp"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totp"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totpseal"
	identityapi "github.com/chronos/chronos-go/internal/modules/identity/api"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// ---------------------------------------------------------------------------
// The attempt ceiling
//
// This is a POLICY DECISION and it lives here, at the composition root, because
// that is the only place that can see both halves of it: the ratelimit package
// deliberately holds no default rule set, and the app layer takes a limiter it
// cannot inspect.
// ---------------------------------------------------------------------------

// authnLimitPrefix namespaces the counter keys. Without a prefix a login attempt
// and any future API-key attempt for the same identifier would share a counter,
// and each would consume the other's budget.
const authnLimitPrefix = "authn"

// authnRules is the attempt ceiling every authentication passes through.
//
// TWO windows, because one cannot express both shapes of abuse and the package
// says so in its own doc: a per-minute rule stops a burst and still permits
// thousands of attempts a day, while a per-day rule stops the grind and lets an
// attacker fire the whole budget in one second. The strictest answer wins.
//
// The numbers:
//
//   - burst, 10 per minute. A real person who has forgotten which password they
//     used tries three or four times and stops; ten is well clear of that, and it
//     is also well clear of a mistyped password manager. Against an attacker it
//     turns online guessing into 10 attempts/minute against a 51 ms Argon2id
//     verify behind a MANDATORY second factor.
//   - grind, 100 per day. Ten a minute unthrottled over a day is 14,400 attempts
//     against one address, which is a real dictionary run. 100 is two orders of
//     magnitude below that and still more failures than any genuine user
//     produces in a day.
//
// Both are FIXED windows, so the honest worst case is 2x each number across a
// window boundary (a full budget spent at the end of one window and again at the
// start of the next). Stated rather than papered over: these numbers are a
// deterrent, not a guarantee, and the guarantee is carried by the hasher's
// concurrency bound and by the second factor.
//
// The ceiling FAILS OPEN — an unreachable Valkey allows the attempt and marks
// the decision Degraded. That trade rests on those same two controls, and
// IDENTITY-SLICE-1 records that it must be revisited if password-only
// authentication ever becomes reachable.
var authnRules = []ratelimit.Rule{
	{Name: "burst", Limit: 10, Window: time.Minute},
	{Name: "grind", Limit: 100, Window: 24 * time.Hour},
}

// ---------------------------------------------------------------------------
// The verification-mail ceiling
//
// NOTIFICATIONS.md §4 states the policy this implements, and it is implemented
// as written rather than reinvented: "Limits apply per address, per account, and
// per source IP, with an hourly ceiling per address across all classes."
//
// Per address and per account collapse into ONE counter here, and not by
// oversight: a verification link belongs to the account that claims the address,
// the address is unique across accounts by the reservation stream (ADR-044), so
// the per-address counter IS the per-account counter for this class of mail. The
// day a second class of mail can be aimed at an account by some identifier OTHER
// than its address, a third scope has to appear beside these two.
// ---------------------------------------------------------------------------

// mailAddressLimitPrefix namespaces the PER-ADDRESS counter, and it is
// deliberately not verification-specific.
//
// "An hourly ceiling per address across ALL classes" is only true if every class
// of triggered mail — verification today, password reset next — increments the
// SAME key. A prefix of "verification" would give each new class its own fresh
// budget, and an attacker with two endpoints would simply alternate between them
// to double the mail one victim receives.
const mailAddressLimitPrefix = "mail_address"

// mailCallerLimitPrefix namespaces the PER-CALLER counter. Separate from the
// address one because the two answer different questions: how much mail can be
// aimed at one victim, and how many victims one caller can reach.
const mailCallerLimitPrefix = "mail_caller"

// mailAddressRules bound how much triggered mail ONE address can be made to
// receive. This is the mail-bombing control.
//
//   - hourly, 3. A real person who lost the mail asks once, checks their spam
//     folder, and asks again; three is clear of that and clear of a double-click.
//     Against an attacker it caps one victim at three unsolicited messages an
//     hour — an annoyance rather than a mailbox flood, and low enough that the
//     victim's provider never sees a volume worth flagging our domain for.
//   - daily, 10. Three an hour unbounded is 72 messages a day, which IS a flood.
//     Ten is more than any genuine user needs in a day and two orders of magnitude
//     below what an inbox notices.
//
// Fixed windows, so the honest worst case is 2x each number across a boundary.
var mailAddressRules = []ratelimit.Rule{
	{Name: "hourly", Limit: 3, Window: time.Hour},
	{Name: "daily", Limit: 10, Window: 24 * time.Hour},
}

// mailCallerRules bound how many DISTINCT addresses one caller can touch. This
// is the enumeration control, and it is the reason the endpoint can be public.
//
//   - hourly, 20. With the per-address rule at 3, this permits a caller to reach
//     at least 7 distinct addresses an hour and at most 20. A sweep worth running
//     needs thousands.
//   - daily, 100.
//
// # The deployment constraint this rule carries
//
// The scope is an ADDRESS, and which address depends on API_TRUSTED_PROXY_HOPS.
// It defaults to 0, meaning the connection's peer address — the only thing about
// a caller the server knows first-hand — and the header is not read at all.
//
// So the constraint is now a configured one rather than an unavoidable one, and
// it cuts both ways:
//
//   - Left at 0 behind a proxy that terminates connections, every caller
//     collapses into ONE bucket and this rule becomes a global ceiling of 20
//     resends an hour for the whole deployment. The symptom — legitimate users
//     refused at random once traffic grows — looks nothing like its cause, which
//     is why it is stated here, in the file that chooses the number.
//   - Set ABOVE the number of proxies that actually append to X-Forwarded-For,
//     the selected entry moves into the part of the header the caller wrote, and
//     20/hour becomes 20 per address an attacker is free to invent. That failure
//     has no symptom at all.
//
// internal/platform/clientip owns the extraction and the whole argument for it.
var mailCallerRules = []ratelimit.Rule{
	{Name: "hourly", Limit: 20, Window: time.Hour},
	{Name: "daily", Limit: 100, Window: 24 * time.Hour},
}

// usernameCheckLimitPrefix namespaces the username-availability counter.
//
// Its OWN prefix, and not shared with the mail budgets. Sharing would let a
// person picking a handle at the signup form spend the budget that stops a
// stranger mail-bombing their mailbox, which is the one budget in this file whose
// exhaustion has a victim other than the caller.
const usernameCheckLimitPrefix = "username_check"

// usernameCheckRules bound how many handles one caller may test.
//
// This is NOT an information control and must not be read as one. The endpoint
// is an enumeration oracle by design (ADR-051): a handle is published, so
// "@alice is taken" is readable from any mention, any profile URL and the person
// themselves, and no ceiling here changes that. What it bounds is RESOURCE use —
// each call reads one stream from KurrentDB, and an unmetered public endpoint
// that does so is an amplification vector.
//
// The numbers are therefore set for a person choosing a handle rather than
// against an adversary who has better ways to get the same answers:
//
//   - hourly, 60. A signup form that checks as the user types debounces to a few
//     calls per candidate, and somebody trying twenty candidates is still well
//     inside it.
//   - daily, 600.
//
// Both are far above mailCallerRules, deliberately: this call sends no mail,
// creates nothing and grants nothing, so refusing it early costs a real user
// their signup and buys nothing back. It carries the same
// API_TRUSTED_PROXY_HOPS deployment constraint mailCallerRules documents in
// full — left at 0 behind a terminating proxy, every caller collapses into one
// bucket and this becomes a global ceiling.
var usernameCheckRules = []ratelimit.Rule{
	{Name: "hourly", Limit: 60, Window: time.Hour},
	{Name: "daily", Limit: 600, Window: 24 * time.Hour},
}

// startIdentity builds the identity module and the enforcement pipeline.
//
// It is the answer to the failure this repository has now shipped six times:
// code that is built, fully tested, and constructed by no binary. Every adapter
// below already existed and passed its own tests while cmd/api registered
// SystemService alone, so the entire slice — registration, login, sessions,
// second factors — was unreachable at runtime with a green suite.
//
// Nothing here fails the boot (ADR-010). But nothing here half-succeeds either:
// if the handler cannot be constructed, d.identity stays nil and main leaves the
// service UNREGISTERED. Registering a handler over nil collaborators would
// answer every RPC with a panic, which is worse than answering none of them —
// a 404 says "this build does not serve identity", a panic says nothing at all.
func (d *dependencies) startIdentity(cfg *config.Config, log *slog.Logger) {
	// The hashing bound first, because it is the one decision here that is not
	// recoverable by restarting with different configuration: sized too high, the
	// process is OOM-killed under a load that is not even an attack.
	d.cpuLimit = resolveCPULimit(log)
	d.hashConcurrency = cfg.Identity.PasswordHashConcurrency
	if d.hashConcurrency == 0 {
		d.hashConcurrency = d.cpuLimit
	}

	svc, err := d.buildIdentity(cfg, log)
	if err != nil {
		log.Error("IDENTITY IS NOT WIRED; this server serves no registration, no login, "+
			"no session and no second factor. IdentityService is left unregistered rather "+
			"than registered over a partial graph, so callers get 'unimplemented' instead "+
			"of a panic", "error", err)
	} else {
		d.identity = svc
		log.Info("identity service constructed",
			"password_hash_concurrency", d.hashConcurrency,
			"cpu_limit", d.cpuLimit,
			"attempt_ceiling", ruleNames(d.limiter),
			// Logged for the same reason the attempt ceiling is: a mail ceiling
			// nobody can see the shape of is one nobody notices has been
			// misconfigured, and the symptom of a wrong number here is a stranger's
			// full mailbox rather than anything this process reports.
			"mail_ceiling_per_address", ruleNames(d.mailAddressLimiter),
			"mail_ceiling_per_caller", ruleNames(d.mailCallerLimiter),
			// The trust boundary the per-caller ceiling's bucket is derived through.
			// Logged because it is the one number here whose WRONG value produces no
			// error, no metric and no failed request: 0 behind a proxy makes the
			// per-caller rule global, and a value above the number of proxies that
			// append to X-Forwarded-For makes the bucket key attacker-chosen. An
			// operator comparing this line against the topology is the only check
			// that exists.
			"trusted_proxy_hops", d.callerScope.TrustedHops())
	}

	// The gates are built WHETHER OR NOT identity was, and that is deliberate.
	// The pipeline guards SystemService too, and a policy set loaded over both
	// services is what makes an unannotated method a refusal to serve rather than
	// an endpoint nobody checks (ADR-021).
	d.startGates(log)
}

// buildIdentity constructs the handler, returning the first thing that is
// missing rather than a partially-built service.
//
// Every constructor below already refuses its own nil dependencies. This
// function exists to make that refusal reach ONE log line at startup instead of
// a panic during somebody's registration — and to keep the ordering visible:
// adapters, then use cases, then the handler, each built before the thing that
// holds it.
func (d *dependencies) buildIdentity(
	cfg *config.Config, log *slog.Logger,
) (*identityapi.Service, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: identity's tables carry no RLS, so the " +
			"system transaction helper is the whole access path and there is no substitute")
	}
	if d.store == nil {
		return nil, errors.New("no event store: every identity command is an append, and " +
			"a handler that cannot append can only fail")
	}
	if d.vault == nil {
		return nil, errors.New("no PII vault: an email address has nowhere to go but the " +
			"vault (ADR-002), so registration cannot complete without one")
	}
	if !cfg.Identity.Configured() {
		return nil, errors.New("identity key material is not configured: set " +
			"IDENTITY_EMAIL_INDEX_KEY, IDENTITY_PASSWORD_PEPPER_KEY and IDENTITY_TOTP_SEAL_KEY")
	}

	tx := pgadapter.New(d.pool)

	// ---- key material ---------------------------------------------------
	//
	// Decoded here rather than in config so the keys exist as bytes in exactly
	// one scope. config validated the shape at boot; a failure at this point is
	// a Config nobody validated.
	indexKey, err := cfg.Identity.EmailIndexKeyBytes()
	if err != nil {
		return nil, err
	}
	index, err := blindindex.New(indexKey)
	if err != nil {
		return nil, fmt.Errorf("email blind index: %w", err)
	}

	// EVERY version this process must be able to open, not just the current one.
	// A verifier is sealed under the key of its own version, so a process holding
	// only the newest key cannot open any row the re-sealing job has not reached —
	// and the symptom is not a stalled job, it is every one of those users unable
	// to log in from the moment the new key is deployed.
	pepperKeys, err := cfg.Identity.PasswordPepperKeySet()
	if err != nil {
		return nil, err
	}
	pepper, err := argon2id.NewPepperKeys(pepperKeys, cfg.Identity.PasswordPepperVersion)
	if err != nil {
		return nil, fmt.Errorf("password pepper: %w", err)
	}
	// The bound is passed EXPLICITLY rather than left to the package default,
	// which is runtime.GOMAXPROCS(0) — the host's core count under a CFS quota.
	// See resolveCPULimit.
	hasher, err := argon2id.New(pepper, argon2id.DefaultParams,
		argon2id.WithConcurrencyLimit(d.hashConcurrency, argon2id.DefaultMaxWait))
	if err != nil {
		return nil, fmt.Errorf("password hasher: %w", err)
	}
	d.hasher = hasher

	// Same rule, and the consequence is worse: a TOTP secret nobody can open is a
	// second factor the user can never satisfy, with no reset flow behind it.
	sealKeySet, err := cfg.Identity.TotpSealKeySet()
	if err != nil {
		return nil, err
	}
	sealKeys, err := totpseal.NewKeys(sealKeySet, cfg.Identity.TotpSealKeyVersion)
	if err != nil {
		return nil, fmt.Errorf("totp sealing keys: %w", err)
	}
	sealer, err := totpseal.New(sealKeys)
	if err != nil {
		return nil, fmt.Errorf("totp sealer: %w", err)
	}

	// ---- PostgreSQL adapters --------------------------------------------
	credentials, err := identitypg.NewCredentials(tx)
	if err != nil {
		return nil, fmt.Errorf("credential store: %w", err)
	}
	secondFactors, err := identitypg.NewSecondFactors(tx)
	if err != nil {
		return nil, fmt.Errorf("second-factor store: %w", err)
	}
	sessions, err := identitypg.NewSessions(tx)
	if err != nil {
		return nil, fmt.Errorf("session store: %w", err)
	}

	// Held for WORKSPACE, which needs both to issue an invitation and may reach
	// neither directly (CONVENTIONS §2). Captured here rather than rebuilt in
	// buildWorkspace so there is ONE blind index in the process: two would be
	// two HMAC keys in theory and the same key by accident, and the day they
	// diverged every invitation would fail to recognise an existing account and
	// silently take a second seat for somebody who already had one.
	d.emailIndex = index
	readModel, err := identitypg.NewReadModel(tx)
	if err != nil {
		return nil, fmt.Errorf("identity read model: %w", err)
	}
	d.accounts = &accountDirectory{accounts: sessions, reads: readModel}
	guards, err := identitypg.NewGuards(tx)
	if err != nil {
		return nil, fmt.Errorf("single-use guards: %w", err)
	}
	// Reservations is the LAPSED-lease reader, used by the sweep that cmd/worker
	// runs. It is constructed here so a missing table or a broken constructor
	// fails at this boot rather than at the worker's, and because leaving it out
	// would make this composition root quietly narrower than the module.
	if _, err := identitypg.NewReservations(tx); err != nil {
		return nil, fmt.Errorf("reservation reader: %w", err)
	}

	// ---- TOTP -----------------------------------------------------------
	//
	// The replay guard is Guards, and it is not optional: an authenticator
	// without one accepts an observed code for the whole 90-second window, and
	// every code still validates exactly as expected, so the failure is invisible.
	authenticator, err := totp.New(cfg.Identity.TotpIssuer, guards)
	if err != nil {
		return nil, fmt.Errorf("totp authenticator: %w", err)
	}

	// app.TotpEnroller is a FUNC type, and the lambda belongs here by design: the
	// app package cannot import the totp adapter (the adapter already imports app
	// for TOTPReplayGuard), so the composition root is the only place the two
	// types can meet without a cycle.
	enroller := app.TotpEnroller(func(accountName string) (app.TotpEnrollment, error) {
		enrollment, err := authenticator.Enroll(accountName)
		if err != nil {
			return app.TotpEnrollment{}, err
		}
		return app.TotpEnrollment{Secret: enrollment.Secret, URI: enrollment.URI}, nil
	})

	// ---- the attempt ceiling --------------------------------------------
	//
	// The counter is NEVER nil. When Valkey is unreachable it is a counter that
	// fails, and that is a deliberate choice between two bad options:
	//
	//   - Refuse to build identity. The ceiling is then never absent — and a
	//     thirty-second Valkey blip during a rolling restart takes login off
	//     entirely, for as long as nobody notices to restart again. valkey.NewClient
	//     DIALS, so this is not a hypothetical: reachability at boot would become a
	//     precondition for serving authentication at all.
	//   - Build it over a failing counter. Every attempt is then allowed and marked
	//     Degraded, the app layer reports it through AuthObserver.CeilingUnavailable,
	//     and the alert fires — which is exactly the behaviour ratelimit already
	//     documents for a counter it cannot reach.
	//
	// The second is chosen, and it is the same trade the ratelimit package took:
	// failing closed makes a cache outage a total authentication outage, and the
	// damage of failing open is bounded by the hasher's concurrency limit and by
	// the mandatory second factor. What must not happen is either of these being
	// SILENT, which is why the unavailable counter is loud at construction and
	// counted at every attempt.
	counter := d.counter
	if counter == nil {
		log.Error("THE ATTEMPT CEILING IS DEGRADED FROM BOOT: valkey is unreachable, so " +
			"every authentication attempt will be allowed and counted as " +
			"chronos_auth_ceiling_unavailable_total. Password guessing is unthrottled " +
			"until valkey returns AND this process is restarted")
		counter = unavailableCounter{}
	}
	limiter, err := ratelimit.New(counter, authnLimitPrefix, authnRules...)
	if err != nil {
		return nil, fmt.Errorf("attempt ceiling: %w", err)
	}
	d.limiter = limiter

	// The two mail ceilings, over the SAME counter and therefore with the same
	// failure mode: an unreachable Valkey degrades them and the resend proceeds
	// unmetered, loudly. app.ResendVerification argues that trade where it is
	// taken — failing closed would make a cache blip permanently lock out everyone
	// who registered during it, because a Pending account has no other route in.
	mailAddressLimiter, err := ratelimit.New(counter, mailAddressLimitPrefix, mailAddressRules...)
	if err != nil {
		return nil, fmt.Errorf("verification-mail address ceiling: %w", err)
	}
	mailCallerLimiter, err := ratelimit.New(counter, mailCallerLimitPrefix, mailCallerRules...)
	if err != nil {
		return nil, fmt.Errorf("verification-mail caller ceiling: %w", err)
	}
	usernameCheckLimiter, err := ratelimit.New(
		counter, usernameCheckLimitPrefix, usernameCheckRules...)
	if err != nil {
		return nil, fmt.Errorf("username check ceiling: %w", err)
	}
	d.mailAddressLimiter = mailAddressLimiter
	d.mailCallerLimiter = mailCallerLimiter
	d.usernameCheckLimiter = usernameCheckLimiter

	// ---- the caller-scope trust boundary ---------------------------------
	//
	// Built here, from configuration, and refused rather than defaulted: a hop
	// count out of range is a deployment mistake with NO runtime symptom in either
	// direction, so the only place it can be caught is the boot that reads it.
	//
	// Note what is NOT done — falling back to a zero-hop resolver on error. That
	// would be a server that starts with a trust boundary the operator asked for
	// and did not get, which is how a per-caller ceiling becomes a global one with
	// nothing in the log to say so.
	callerScope, err := clientip.NewResolver(cfg.API.TrustedProxyHops)
	if err != nil {
		return nil, fmt.Errorf("caller-scope trust boundary: %w", err)
	}
	d.callerScope = callerScope

	// ---- aggregate repositories -----------------------------------------
	//
	// Read-only from the use cases' point of view: writes go through
	// eventsourcing.MultiAppender, because a registration touches two streams and
	// two sequential single-stream appends are exactly the non-atomic pattern the
	// multi-append exists to remove.
	// The SAME codec and upcaster registry the store appends through — see
	// dependencies.codec. Building a second pair here would let a type be
	// registered for writing and not for reading, which is a command that writes
	// an event this binary cannot load back.
	users := eventsourcing.NewRepository[*domain.User](
		d.store, d.codec, d.upcasters, app.UserCategory, domain.New)
	sessionRepo := eventsourcing.NewRepository[*domain.Session](
		d.store, d.codec, d.upcasters, app.SessionCategory, domain.NewSession)
	reservations := eventsourcing.NewRepository[*domain.EmailReservation](
		d.store, d.codec, d.upcasters, app.ReservationCategory, domain.NewReservation)

	// The public handle's reservation (ADR-051). A repository of its own because
	// it is a different aggregate on a different category — and the category's key
	// is the HANDLE in the clear rather than a keyed index, which is the one place
	// this differs from the address's: hiding a value that is published by design
	// would cost log readability and protect nothing.
	usernameReservations := eventsourcing.NewRepository[*domain.UsernameReservation](
		d.store, d.codec, d.upcasters, app.UsernameCategory, domain.NewUsernameReservation)

	// The process clock, not a second one built here. It is clock.System{} in
	// every deployment; in local it may be the movable clock (ADR-054), and
	// identity is precisely the module that has to follow it — a TOTP step, a
	// session deadline and a token expiry that disagreed with the rest of the
	// process about what time it is would each be a different kind of bug.
	clk := d.clock

	// ---- use cases -------------------------------------------------------
	// One minter for verification tokens. Held in a local rather than built inline
	// so the lambda below closes over a single instance: token.New() carries the
	// entropy source, and a per-call constructor would make "which source mints
	// our secrets" a question with more than one answer.
	verificationTokens := token.New()

	// Authentication is built BEFORE registration, and the order is a
	// dependency rather than a preference: RegistrationDeps.Revocations is
	// *Authentication, because VerifyEmail voids every session established
	// before the address was proven (IDENTITY-REVIEW C8). The reverse
	// direction does not exist — authentication needs nothing registration
	// builds — so there is no cycle to break here, only an order to keep.
	authnDeps := app.AuthenticationDeps{
		Clock:       clk,
		Entropy:     rand.Reader,
		Index:       index,
		Limiter:     limiter,
		Hasher:      hasher,
		Credentials: credentials,
		Accounts:    sessions,
		Users:       users,
		Sessions:    sessionRepo,
		Live:        sessions,
		Tokens:      sessions,
		Sealer:      sealer,
		Secrets:     secondFactors,
		Verifier:    authenticator,
		Breach:      hibp.New(),
		Appender:    d.store,
		Log:         log,
		// Without this the two outcomes that leave NO event behind — a throttled
		// attempt and a ceiling that could not be evaluated — are counted nowhere,
		// and a degraded attempt-ceiling is indistinguishable from one that is
		// simply never reached.
		Observer: d.metrics.Authn(),

		// The SAME Valkey client the authorization Guard caches decisions in, and
		// that is the whole point rather than a convenience: revoking a session
		// bumps the principal's epoch, which is what invalidates every decision
		// cached for them (ADR-045). A second client would bump an epoch nothing
		// reads, and "sign out everywhere" would report success while a permit
		// cached for that principal kept authorizing for up to MaxDecisionTTL.
		//
		// Nil when Valkey could not be reached at startup. That is not silently
		// degraded: NewAuthentication logs it, revocation then FAILS rather than
		// pretending, and the composition-root test below is what notices the
		// wiring going missing — nothing at runtime can tell the difference
		// between "no epochs wired" and "no revocations happened yet".
		Epochs: epochsOrNil(d.authzCache),
		// The SAME registry the repositories upcast with. Without it every event
		// is appended at version 0 while the registry declares 1, and the aggregate
		// cannot be loaded back — invisibly, because projections do not upcast.
		Schemas: d.upcasters,
	}
	// Recorded FROM the struct that is about to be passed, never rebuilt beside
	// it. A second d.metrics.Authn() here would keep the composition-root
	// assertion green while the service itself was built with the nop observer —
	// which is the exact shape of "tested and wired into nothing".
	d.authObserver = authnDeps.Observer

	authentication, err := app.NewAuthentication(authnDeps)
	if err != nil {
		return nil, fmt.Errorf("authentication: %w", err)
	}
	d.revocations = authentication

	registration, err := app.NewRegistration(app.RegistrationDeps{
		Clock: clk,
		// crypto/rand, always. Making the entropy source wireable would turn
		// "what mints our secrets" into a configuration question whose one wrong
		// answer is unrecoverable.
		Entropy:      rand.Reader,
		Index:        index,
		Breach:       hibp.New(),
		Hasher:       hasher,
		Vault:        d.vault,
		Credentials:  credentials,
		Reservations: reservations,
		// The SAME loader the availability check reads through, so "is this handle
		// free" is answered from one place. A second loader would be a second answer
		// to a question that must have one, and the two would diverge exactly when
		// one of them was changed.
		Usernames: usernameReservations,
		Users:     users,
		Appender:  d.store,
		Tokens:    guards,
		Digest:    token.Digest,
		// The verification token's minter. A function rather than the *Minter
		// itself because adapter/token imports app, so app cannot name the
		// adapter's return type — the same shape as Digest above and TotpEnroller
		// below.
		//
		// Register mints the token, stores its digest and drops the plaintext. The
		// plaintext currently reaches nobody: no reactor consumes
		// EmailVerificationRequested, and the event cannot carry the token
		// (ADR-002), so a real user still cannot verify. That is the unfinished
		// half of this fix, recorded in IDENTITY-SLICE-1 rather than papered over
		// by sending mail inline, which ADR-017 forbids.
		Minter: func(p app.TokenPurpose, now time.Time) (app.MintedToken, error) {
			t, err := verificationTokens.Mint(p, now)
			if err != nil {
				return app.MintedToken{}, err
			}
			return app.MintedToken{
				Plaintext: t.Plaintext, Digest: t.Digest, ExpiresAt: t.ExpiresAt,
			}, nil
		},
		Directory: readModel,
		// The SAME handlers RevokeAllSessions is served from, so a verification
		// and a "sign out everywhere" void sessions through one code path with one
		// epoch bump. A second implementation here would be a second answer to
		// "what does revoking everything mean", and the two would diverge exactly
		// when one of them was changed.
		Revocations: authentication,
		Log:         log,
		// The SAME registry the repositories upcast with. Without it every event
		// is appended at version 0 while the registry declares 1, and the aggregate
		// cannot be loaded back — invisibly, because projections do not upcast.
		Schemas: d.upcasters,
	})
	if err != nil {
		return nil, fmt.Errorf("registration: %w", err)
	}

	// The resend path. It appends EmailVerificationRequested and nothing else —
	// the reactor cmd/worker runs mints the token, revokes every earlier one and
	// sends the mail — so this use case holds no minter, no token store and no
	// dispatcher. That is the point: there is exactly one place a verification
	// link is created, and a request handler is not it.
	//
	// TokenTTL is the adapter's own constant rather than a number retyped here. It
	// only sets the deadline the EVENT advertises; the token the reactor mints
	// carries its own, and the store enforces that one.
	resend, err := app.NewResendVerification(app.ResendVerificationDeps{
		Clock: clk,
		Index: index,
		Users: users,
		// The SAME index -> account lookup authentication uses. A second reader
		// would be a second answer to "which account claims this address", and the
		// two would diverge exactly when one of them was changed.
		Directory:      sessions,
		Appender:       d.store,
		Schemas:        d.upcasters,
		AddressLimiter: mailAddressLimiter,
		CallerLimiter:  mailCallerLimiter,
		TokenTTL:       token.VerificationTTL,
		Log:            log,
	})
	if err != nil {
		return nil, fmt.Errorf("verification resend: %w", err)
	}

	// The password-reset pair. It holds the SAME two mail ceilings the resend
	// holds, over the same counter and therefore the same keys — that sharing is
	// required rather than convenient. NOTIFICATIONS.md §4 asks for "an hourly
	// ceiling per address across ALL classes", and mailAddressLimitPrefix is
	// deliberately not verification-specific for exactly this moment: giving reset
	// mail its own budget would let an attacker alternate between
	// ResendEmailVerification and RequestPasswordReset and double the mail one
	// victim receives.
	//
	// TokenTTL is the adapter's own constant — one hour, far shorter than a
	// verification link's day, because a reset token grants account access rather
	// than confirming an address. It only sets the deadline the EVENT advertises;
	// the token the issuer mints carries its own and the store enforces that one.
	//
	// Directory and Subjects are the two lookups in opposite directions, and both
	// are the readers the rest of the module already uses: `sessions` answers
	// "which account claims this address" for authentication, `readModel` answers
	// "which account is this pseudonym" for verification. A third reader here
	// would be a third answer to a question that must have one.
	passwordResets, err := app.NewPasswordReset(app.PasswordResetDeps{
		Clock:          clk,
		Index:          index,
		Directory:      sessions,
		Subjects:       readModel,
		Users:          users,
		Appender:       d.store,
		Schemas:        d.upcasters,
		AddressLimiter: mailAddressLimiter,
		CallerLimiter:  mailCallerLimiter,
		TokenTTL:       token.ResetTTL,
		Breach:         hibp.New(),
		Hasher:         hasher,
		Credentials:    credentials,
		Tokens:         guards,
		Digest:         token.Digest,
		// The SAME handlers RevokeAllSessions is served from, so a reset and a
		// "sign out everywhere" void sessions through one code path with one epoch
		// bump. A second implementation here would be a second answer to "what does
		// revoking everything mean", and the two would diverge exactly when one of
		// them was changed.
		Revocations: authentication,
		Log:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("password reset: %w", err)
	}

	secondFactor, err := app.NewSecondFactor(app.SecondFactorDeps{
		Clock:    clk,
		Entropy:  rand.Reader,
		Users:    users,
		Appender: d.store,
		Enroll:   enroller,
		Sealer:   sealer,
		Secrets:  secondFactors,
		Verifier: authenticator,
		Recovery: secondFactors,
		Log:      log,
		// The SAME registry the repositories upcast with. Without it every event
		// is appended at version 0 while the registry declares 1, and the aggregate
		// cannot be loaded back — invisibly, because projections do not upcast.
		Schemas: d.upcasters,
	})
	if err != nil {
		return nil, fmt.Errorf("second factors: %w", err)
	}

	// The account lifecycle: the holder's own off switch, and the request to be
	// erased.
	//
	// `Revocations` is the SAME *app.Authentication the password reset holds, and
	// for the stronger version of the same reason. A reset revokes and then
	// appends, in two writes, and that order fails safe because the revocation is
	// its destructive half. A deactivation has no granting half, so it folds the
	// revocation into its OWN append and needs the planning half of the same code
	// — one answer to "what does revoking everything for this subject mean",
	// reached two ways.
	//
	// `Subjects` is `readModel`, the reader that already answers "which account is
	// this pseudonym" for verification and for the reset. A third reader would be
	// a third answer to a question that must have one.
	//
	// GracePeriod is left at zero so the use case applies its own default, which
	// is the 30-day statutory clock FEATURES.md names. It is a field rather than a
	// constant in the use case so a deployment can shorten it; there is no
	// environment variable yet because nothing consumes the request, and a knob
	// that changes nothing observable is a knob that gets set wrong unnoticed.
	lifecycle, err := app.NewLifecycle(app.LifecycleDeps{
		Clock:       clk,
		Subjects:    readModel,
		Users:       users,
		Appender:    d.store,
		Schemas:     d.upcasters,
		Revocations: authentication,
		Log:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("account lifecycle: %w", err)
	}

	// The identifier-change flow (identity.md §12).
	//
	// `Addresses` is the one dependency that is genuinely new rather than shared,
	// and it exists so that no address crosses back into the module: identity's
	// vault port is write-only by design, and every move this flow makes needs the
	// CURRENT value. The moves therefore happen inside the vault adapter.
	//
	// Everything else is the reader or the appender the rest of the module already
	// holds, for the reason stated at each of its other uses: a second reader is a
	// second answer to a question that must have one. In particular `Revocations`
	// is the SAME *app.Authentication the reset and the deactivation use, so
	// "void every session for this subject" has one implementation and one epoch
	// bump — and §4.4 is enforced identically whether the trigger was a recovery
	// or an identifier change.
	//
	// TTL and Revert are left at zero so the use case applies its own defaults.
	// Revert must stay equal to token.RevertTTL, and a test asserts it: a token
	// that dies before the aggregate's window closes leaves a window nothing can
	// act on, and one that outlives it leaves a link that redeems into a refusal.
	//
	// Built from `d.piiVault` rather than `d.vault`: the latter is identity's
	// deliberately write-only view, and the address book is the one component
	// that must read — inside the adapter, so nothing crosses back.
	if d.piiVault == nil {
		return nil, errors.New("no PII vault: an email change has to MOVE addresses " +
			"between the vault's slots, and without it a completed change leaves the " +
			"account's mail going to the address it just left")
	}
	addressBook, err := piivault.NewAddressBook(d.piiVault)
	if err != nil {
		return nil, fmt.Errorf("vault address book: %w", err)
	}
	emailChanges, err := app.NewEmailChange(app.EmailChangeDeps{
		Clock:       clk,
		Index:       index,
		Subjects:    readModel,
		Users:       users,
		Claims:      reservations,
		Appender:    d.store,
		Schemas:     d.upcasters,
		Addresses:   addressBook,
		Tokens:      guards,
		Digest:      token.Digest,
		Revocations: authentication,
		Log:         log,
	})
	if err != nil {
		return nil, fmt.Errorf("email change: %w", err)
	}

	// The public availability check. It holds a LOADER and a ceiling and nothing
	// else — no appender, no token store, no vault — so the handler for it cannot
	// create an account, spend a token or claim a handle. That narrowness is the
	// point: it is the only public RPC in this service whose answer is deliberately
	// distinguishable, so it must be the one that can do the least.
	usernames, err := app.NewUsernames(app.UsernamesDeps{
		Reservations:  usernameReservations,
		CallerLimiter: usernameCheckLimiter,
		Log:           log,
	})
	if err != nil {
		return nil, fmt.Errorf("username availability: %w", err)
	}

	queries, err := app.NewQueries(app.QueriesDeps{
		Accounts: readModel,
		Sessions: readModel,
		Methods:  readModel,
		History:  readModel,
	})
	if err != nil {
		return nil, fmt.Errorf("identity read side: %w", err)
	}

	// Recorded so a composition-root test can assert it without reaching into the
	// handler, which exposes none of its collaborators by design.
	d.totpEnroller = enroller

	return identityapi.New(identityapi.Deps{
		Registration:   registration,
		Resender:       resend,
		Resets:         passwordResets,
		Usernames:      usernames,
		Authentication: authentication,
		SecondFactor:   secondFactor,
		Lifecycle:      lifecycle,
		Emails:         emailChanges,
		Queries:        queries,
		Directory:      readModel,
		CallerScope:    callerScope,
	})
}

// ruleNames is for the startup log line: an attempt ceiling nobody can see the
// shape of is one nobody notices has been misconfigured.
func ruleNames(l *ratelimit.Limiter) []string {
	if l == nil {
		return nil
	}
	rules := l.Rules()
	out := make([]string, len(rules))
	for i, r := range rules {
		out[i] = fmt.Sprintf("%s=%d/%s", r.Name, r.Limit, r.Window)
	}
	return out
}

// unavailableCounter is the attempt ceiling with no store behind it.
//
// It ERRORS rather than returning a count, because the two are read completely
// differently by the limiter: an error produces a Degraded decision that the
// caller must surface, while a low count is an ordinary allow that nobody
// reports. Returning 0 here would be an attempt ceiling that silently permits
// everything — a control that is present, tested, green, and doing nothing,
// which is precisely the failure ADR-045 records for a different control.
type unavailableCounter struct{}

func (unavailableCounter) Incr(context.Context, string, time.Duration) (int64, error) {
	return 0, errors.New("cmd/api: the attempt-ceiling counter is unavailable; valkey was " +
		"unreachable when this process started")
}

// counterOrNil avoids the typed-nil trap for the rate-limit counter, exactly as
// tombstonesOrNil does for the Guard's ports: a nil *valkeyadapter.Counter inside
// a non-nil ratelimit.Counter interface passes ratelimit.New's nil check and then
// panics on the first login attempt.
func counterOrNil(c *valkeyadapter.Counter) ratelimit.Counter {
	if c == nil {
		return nil
	}
	return c
}

// vaultOrNil does the same for the PII vault. A nil *piivault.Vault inside a
// non-nil app.SubjectVault passes NewRegistration's nil check, and the first
// registration panics with the address already in hand.
func vaultOrNil(v *piivault.Vault) app.SubjectVault {
	if v == nil {
		return nil
	}
	return v
}
