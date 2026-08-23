// Package api is identity's Connect handler layer: the only place in the module
// where a generated protobuf type meets a domain or use-case type.
//
// # What this layer is for
//
// Three steps, in this order, and nothing else:
//
//  1. turn a wire DTO into an app command,
//  2. call the app service,
//  3. turn the app result into a wire DTO.
//
// It holds no business rule. Everything a handler here could be tempted to check
// is already checked somewhere with a better claim to it: the shape of a request
// by protovalidate running as an interceptor (ADR-007), the caller's identity and
// assurance level by the gate pipeline (ADR-021), and every rule about accounts,
// credentials and sessions by `app` and `domain`.
//
// # Why the package exists at all
//
// Proto types are wire DTOs, never domain types. `internal/modules/identity/domain`
// may not import `gen/proto`, and `make lint`'s depguard contract enforces it — so
// the conversion has to live on this side of the boundary, and this package is
// where it does. A handler that reached past `app` into `domain` or the event
// store would move the boundary rather than cross it.
//
// # The caller is read from the context, never from the request
//
// Nine of the thirteen RPCs act on the CALLER'S OWN account. Not one of them takes
// a subject id, a user id or an account id on the wire, and that is a property of
// the schema rather than an accident: a request field naming the account would
// make every one of them an existence probe for any pseudonym a caller can
// obtain. The caller comes from `interceptor.PrincipalFrom`, which only the authn
// gate can write.
//
// # Refusals stay undifferentiated
//
// ADR-036 requires one answer for every authentication failure. That property is
// carried by `app` returning a single error for all of them and by this package
// mapping errors through `srvconnect.Error` and nothing else — there is
// deliberately no `switch` on an app error anywhere below, because a switch is how
// two indistinguishable refusals become two distinguishable Connect codes.
//
// # Secrets are returned once and never logged
//
// The session bearer token, the TOTP secret and its provisioning URI, and the
// plaintext recovery codes are copied from an app result straight into the
// response of the call that minted them. This package logs nothing at all, which
// is the cheapest way to guarantee none of them reaches a log line.
package api

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
)

// ---------------------------------------------------------------------------
// Ports
//
// Declared here, by the consumer, and narrowed to the methods this layer calls
// (ADR-001, CONVENTIONS §2). They are satisfied by *app.Registration,
// *app.Authentication, *app.SecondFactor and *app.Queries as written.
//
// Narrow interfaces rather than the concrete structs for one reason that matters
// more than testability: a handler holding *app.Authentication can reach every
// method on it, including ones no RPC exposes. A handler holding this interface
// cannot.
// ---------------------------------------------------------------------------

// Registration is the enrolment half of the module.
type Registration interface {
	Register(ctx context.Context, cmd app.RegisterCommand) (app.RegisterResult, error)
	VerifyEmail(ctx context.Context, cmd app.VerifyEmailCommand) (app.VerifyEmailResult, error)
}

// Resender issues a replacement verification link.
//
// A port of its own rather than a third method on Registration, and the split is
// not cosmetic: Registration's two methods both act on a caller who has just
// proven something (a password, a token), while this one acts on an address typed
// by an unauthenticated stranger. Keeping it separate is what lets the handler
// for it hold nothing that could create an account or spend a token.
type Resender interface {
	Resend(
		ctx context.Context, cmd app.ResendVerificationCommand,
	) (app.ResendVerificationResult, error)
}

// PasswordResets is the reset half: asking for a link, and redeeming one.
//
// A port of its own rather than two more methods on Registration, and the split
// is not cosmetic. Registration's two methods bring an account into existence;
// these two act on an account that already exists, on behalf of an
// unauthenticated stranger who typed an address or followed a link. Keeping them
// separate is what lets the handler for them hold nothing that could create an
// account, and lets the handler for registration hold nothing that could replace
// a credential.
type PasswordResets interface {
	Request(
		ctx context.Context, cmd app.RequestPasswordResetCommand,
	) (app.RequestPasswordResetResult, error)
	Complete(ctx context.Context, cmd app.ResetPasswordCommand) (app.ResetPasswordResult, error)
}

// UsernameChecks answers "is this public handle free?".
//
// A port of its own rather than a method on Registration, and the split is the
// one every other port here is drawn on: a handler holding this interface can
// READ a reservation stream and can do nothing else. It cannot create an
// account, spend a token, mint a session or claim a handle — which matters more
// than usual for this one, because it is the only RPC in the service that is
// public, unauthenticated, and deliberately NOT an undifferentiated answer.
type UsernameChecks interface {
	Check(ctx context.Context, cmd app.CheckUsernameCommand) (app.CheckUsernameResult, error)
}

// Authentication is the login and session half.
type Authentication interface {
	Authenticate(ctx context.Context, cmd app.AuthenticateCommand) (app.AuthenticateResult, error)
	CreateSession(ctx context.Context, cmd app.CreateSessionCommand) (app.CreateSessionResult, error)
	RevokeSession(ctx context.Context, cmd app.RevokeSessionCommand) (app.RevokeSessionResult, error)
	RevokeAllSessions(
		ctx context.Context, cmd app.RevokeAllSessionsCommand,
	) (app.RevokeAllSessionsResult, error)
}

// SecondFactor is TOTP enrolment and recovery codes.
type SecondFactor interface {
	EnrollTotp(ctx context.Context, cmd app.EnrollTotpCommand) (app.EnrollTotpResult, error)
	ConfirmTotp(ctx context.Context, cmd app.ConfirmTotpCommand) (app.ConfirmTotpResult, error)
	GenerateRecoveryCodes(
		ctx context.Context, cmd app.GenerateRecoveryCodesCommand,
	) (app.GenerateRecoveryCodesResult, error)
}

// Lifecycle is the account's own on/off switch and its request to be erased.
//
// A port of its own rather than more methods on Registration or Authentication,
// and the split is the same one every other port here is drawn on: a handler
// holding this interface can switch an account off and can do nothing else. It
// cannot create an account, replace a credential or mint a session.
//
// It has TWO methods and not four. There is no Reactivate, because a deactivated
// account cannot hold the session such a call would need — the reversal happens
// inside the authentication instead (app.Lifecycle, domain.User.NeedsReactivation).
// There is no Suspend, because every caller reaching this service is the account
// holder acting on their own account, and identity.md §1 makes a suspension
// something the holder may never perform or reverse.
type Lifecycle interface {
	Deactivate(
		ctx context.Context, cmd app.DeactivateAccountCommand,
	) (app.DeactivateAccountResult, error)
	RequestDeletion(
		ctx context.Context, cmd app.RequestAccountDeletionCommand,
	) (app.RequestAccountDeletionResult, error)
	CancelDeletion(
		ctx context.Context, cmd app.CancelAccountDeletionCommand,
	) (app.CancelAccountDeletionResult, error)
}

// Queries is identity's read side.
type Queries interface {
	GetUser(ctx context.Context, subjectID string) (app.AccountView, error)
	ListSessions(
		ctx context.Context, subjectID string, pageToken page.Token, pageSize int,
	) (page.Page[app.SessionSummary], error)
	ListMethods(ctx context.Context, subjectID string) ([]app.AuthMethod, error)
	ListLoginHistory(
		ctx context.Context, subjectID string, pageToken page.Token, pageSize int,
	) (page.Page[app.LoginRecord], error)
}

// Deps is everything a handler needs, one field per collaborator.
//
// A struct rather than five positional arguments because four of the five are
// pointers to types whose names differ only by their role, and the compiler
// cannot tell a swapped pair apart.
type Deps struct {
	Registration Registration
	Resender     Resender

	// Resets is the password-reset pair. Required; see New.
	Resets PasswordResets

	// Usernames answers the public availability check. Required; see New.
	Usernames UsernameChecks

	Authentication Authentication
	SecondFactor   SecondFactor

	// Lifecycle is deactivation and the deletion request. Required; see New.
	Lifecycle Lifecycle

	Queries Queries

	// Directory turns the caller's pseudonym into the account id the second-factor
	// commands are keyed by. See Service.callerUser for why it is here.
	Directory app.UserDirectory

	// CallerScope decides which address the per-caller ceilings count against.
	//
	// A VALUE, and deliberately not a pointer with a nil check like every other
	// field here. The zero Resolver trusts no proxy and answers with the
	// connection's peer address, so the field left off a struct literal produces
	// the STRICTEST behaviour rather than a panic or — far worse — a trusted
	// header. Refusing a nil would defend the wrong direction: the dangerous
	// misconfiguration is a resolver that trusts too much, and no constructor
	// check can see that one.
	CallerScope clientip.Resolver
}

// Service implements chronos.identity.v1.IdentityService.
//
// Every field is required and none may be nil; see New.
type Service struct {
	registration Registration
	resender     Resender
	resets       PasswordResets
	usernames    UsernameChecks
	authn        Authentication
	secondFactor SecondFactor
	lifecycle    Lifecycle
	queries      Queries
	directory    app.UserDirectory
	callerScope  clientip.Resolver
}

// New builds the handler, refusing a partial one.
//
// A nil collaborator is refused HERE rather than tolerated, because the
// alternative is a nil-pointer panic on the first request to whichever screen
// uses it — after the composition root has reported a healthy start, and in a
// process that answers every other RPC correctly. That is precisely the failure
// mode compile-time wiring exists to avoid, and a constructor that returns
// (*Service, error) is what makes cmd/api unable to ignore it.
func New(deps Deps) (*Service, error) {
	missing := func(what string) error {
		return fmt.Errorf("identity/api: the identity handler needs %s", what)
	}
	switch {
	case deps.Registration == nil:
		return nil, missing("a registration service")
	case deps.Resender == nil:
		// Refused rather than tolerated as "resend is optional". A nil here serves
		// ResendEmailVerification with a panic, and the people who reach that RPC
		// are by definition the ones already locked out of their own account.
		return nil, missing("a verification resender")
	case deps.Resets == nil:
		// Refused rather than tolerated as "reset is optional". A nil here serves
		// both reset RPCs with a panic, and the people who reach them are by
		// definition the ones already locked out of their own account — the same
		// argument the resender is refused under, with a worse population.
		return nil, missing("a password-reset service")
	case deps.Usernames == nil:
		// Refused rather than tolerated as "the availability check is optional". A
		// nil here serves CheckUsernameAvailability with a panic, and that endpoint
		// is the ONLY way a person can find out their handle is taken before they
		// spend a verification link they cannot get back — so its absence would show
		// up as users losing their signup at the last step, which reads as a bug in
		// verification rather than in wiring.
		return nil, missing("a username availability service")
	case deps.Authentication == nil:
		return nil, missing("an authentication service")
	case deps.SecondFactor == nil:
		return nil, missing("a second-factor service")
	case deps.Lifecycle == nil:
		// Refused rather than tolerated as "the lifecycle is optional". A nil here
		// serves both lifecycle RPCs with a panic, and one of them is the only way
		// a person can switch their own account off — the control a worried account
		// holder reaches for first.
		return nil, missing("an account lifecycle service")
	case deps.Queries == nil:
		return nil, missing("a read side")
	case deps.Directory == nil:
		return nil, missing("a user directory")
	}
	return &Service{
		registration: deps.Registration,
		resender:     deps.Resender,
		resets:       deps.Resets,
		usernames:    deps.Usernames,
		authn:        deps.Authentication,
		secondFactor: deps.SecondFactor,
		lifecycle:    deps.Lifecycle,
		queries:      deps.Queries,
		directory:    deps.Directory,
		callerScope:  deps.CallerScope,
	}, nil
}

// ---------------------------------------------------------------------------
// The caller
// ---------------------------------------------------------------------------

// callerSubject reads the authenticated caller's pseudonym from the context.
//
// The context, and never the request. `interceptor.PrincipalFrom` is the only
// reader of a value only the authn gate can write, so a subject obtained here
// cannot have been chosen by whoever sent the request. Every authenticated RPC
// below starts with this call and uses nothing else to name an account.
//
// # Which identifier a principal carries
//
// `authz.Principal.ID` is taken to be the SubjectID pseudonym, because that is
// the identifier identity's own read side, its session projection and its
// revocation commands are all keyed by, and because ADR-002 makes the pseudonym
// the thing that travels. The authenticator that populates it is built alongside
// this package (S1-25); if it settles on the UserID instead, this function is the
// one place that changes.
//
// # Only a human principal may act here
//
// A KindAPIKey or KindServiceAccount principal carries the KEY's identifier, not
// a person's pseudonym, so reading it as a subject would answer for whatever
// account that string happened to name. Refused rather than resolved: these
// endpoints are a person's own account screens, and there is no delegation
// convention for them yet.
//
// Unauthenticated with a fixed message. Nothing here distinguishes "no principal"
// from "the wrong kind of principal" on the wire — an unauthenticated caller
// learns only that they are unauthenticated.
func callerSubject(ctx context.Context) (string, error) {
	principal, ok := interceptor.PrincipalFrom(ctx)
	if !ok || principal.Subject.Kind != authz.KindUser || principal.Subject.ID == "" {
		return "", errs.Unauthenticatedf("this request has not authenticated")
	}
	return principal.Subject.ID, nil
}

// callerUser resolves the caller's pseudonym to the account id.
//
// It exists because `app.SecondFactor` is keyed by UserID while everything else
// identity exposes is keyed by SubjectID, and the principal carries the
// pseudonym. The mapping is a lookup rather than a rule, which is why it is
// allowed to live in a handler at all — and it is `app.UserDirectory`, the
// narrowest port in the module that answers the question, rather than the read
// side, so this layer cannot acquire the ability to read anybody's account state
// as a side effect of enrolling a factor.
//
// An unknown subject is NotFound with no detail. It is the same answer the read
// side gives, and it has to be: a caller able to tell "no such account" from "not
// your account" can test pseudonyms for existence.
//
// # "no such account" and "could not tell" are not the same failure
//
// Only app.ErrNoSuchSubject means the directory holds no account. Everything else
// — the read model unreachable, a scan that failed, a context that expired — is
// the directory being unable to answer, and reporting THAT as NotFound throws the
// cause away twice over: the caller is told their account does not exist during
// an outage, and the outage itself leaves no trace, because a NotFound is a
// classified refusal that the transport's error gate deliberately does not log.
// An INTERNAL with the cause attached is both honest and findable, and it is the
// same distinction interceptor.ErrAuthenticationUnavailable already draws one
// gate earlier.
//
// It is not an existence oracle. The INTERNAL depends on the state of the read
// model and not on the subject asked about, so it says nothing about any account
// — which is exactly what makes it safe to say.
func (s *Service) callerUser(ctx context.Context) (ids.UserID, error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return ids.UserID{}, err
	}
	userID, err := s.directory.UserBySubject(ctx, subjectID)
	switch {
	case errors.Is(err, app.ErrNoSuchSubject):
		return ids.UserID{}, errs.NotFoundf("no such account")
	case err != nil:
		return ids.UserID{}, errs.Internalf("the user directory is unavailable").Wrap(err)
	}
	return userID, nil
}

// ---------------------------------------------------------------------------
// The idempotency key
// ---------------------------------------------------------------------------

// idempotencyKey reads the client-generated key every mutating command needs.
//
// It comes from the SAME header gate 5 claims, so a retry that the gate collapses
// and a retry that reaches the app layer derive the same event ids rather than
// two chains for one command. Read here rather than taken from the context
// because the four public RPCs — Register, VerifyEmail, Authenticate,
// CreateSession — bypass the gate entirely (a public method has no principal, and
// the idempotency scope is built from one), and they still require a key.
//
// Absent is a REFUSAL, never a server-generated substitute. A key minted here
// would make every retry look like a new request, which is the exact failure the
// header exists to prevent, with the added insult of looking handled.
func idempotencyKey(header interceptor.Header) (string, error) {
	key := header.Get(interceptor.IdempotencyHeader)
	if key == "" {
		return "", errs.ValidationFailedf(
			"%s is required on every mutating request", interceptor.IdempotencyHeader)
	}
	return key, nil
}

// fail renders an error onto the wire.
//
// One function, used by every handler, and it does exactly one thing: hand the
// error to the transport mapping the rest of the server already uses. There is no
// branch on the error's reason here and there must not be one — the app layer
// answers every authentication failure with one error, and a switch in this layer
// is how that single answer would become several distinguishable Connect codes
// (ADR-036).
func fail(err error) error { return srvconnect.Error(err) }

// The handler must satisfy the generated interface, and the compiler is what says
// so. Without this the omission of one RPC is a failure at the mux.Handle call in
// cmd/api, which is a different package and a later commit — and an RPC that is
// declared, policy-annotated and unimplemented is exactly the shape of gap ADR-021
// exists to make impossible.
var _ identityv1connect.IdentityServiceHandler = (*Service)(nil)

// And the app services must satisfy the ports declared above. A consumer-declared
// interface that no producer implements is a mock the tests pass against and the
// composition root cannot wire — the failure the module's own adapters were built,
// tested and wired into nothing by.
var (
	_ Registration   = (*app.Registration)(nil)
	_ PasswordResets = (*app.PasswordReset)(nil)
	_ UsernameChecks = (*app.Usernames)(nil)
	_ Authentication = (*app.Authentication)(nil)
	_ SecondFactor   = (*app.SecondFactor)(nil)
	_ Lifecycle      = (*app.Lifecycle)(nil)
	_ Queries        = (*app.Queries)(nil)
)
