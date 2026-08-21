package api_test

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/modules/identity/api"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clientip"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
	srvconnect "github.com/chronos/chronos-go/internal/server/connect"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/chronos/chronos-go/internal/server/policy"
)

// The tests in this package drive the REAL generated request and response types
// through the REAL gate pipeline against fake app services.
//
// The pipeline is not decoration. `interceptor.PrincipalFrom` reads a context key
// that only the authn gate can write — the key's type is unexported precisely so
// that no other package, this test included, can forge a caller. So the only
// honest way to give a handler a principal is to run the pipeline that puts one
// there, which is what testServer does. A test that could inject a principal
// directly would also be a test that proved nothing about where handlers get one.

// callerSubject is the pseudonym every authenticated test acts as.
const callerSubject = "sub_caller"

// callerUser is the account callerSubject resolves to through the directory.
var callerUser = ids.FromUUID[ids.User]([16]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16})

// otherSubject is an account the caller is NOT. It appears only in fakes, to
// prove that a handler which read an account from anywhere but the principal
// would be caught.
const otherSubject = "sub_someone_else"

// ---------------------------------------------------------------------------
// Fake app services
//
// Function fields rather than canned values, so a case can both observe the
// command it was handed and choose what to answer. Every one records under a
// mutex: the handler runs on the server's goroutine and the assertions on the
// test's, and -race is the point of running them.
// ---------------------------------------------------------------------------

type fakeRegistration struct {
	mu sync.Mutex

	registerFn func(app.RegisterCommand) (app.RegisterResult, error)
	verifyFn   func(app.VerifyEmailCommand) (app.VerifyEmailResult, error)

	registerCmds []app.RegisterCommand
	verifyCmds   []app.VerifyEmailCommand
}

func (f *fakeRegistration) Register(
	_ context.Context, cmd app.RegisterCommand,
) (app.RegisterResult, error) {
	f.mu.Lock()
	f.registerCmds = append(f.registerCmds, cmd)
	fn := f.registerFn
	f.mu.Unlock()
	if fn == nil {
		return app.RegisterResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeRegistration) VerifyEmail(
	_ context.Context, cmd app.VerifyEmailCommand,
) (app.VerifyEmailResult, error) {
	f.mu.Lock()
	f.verifyCmds = append(f.verifyCmds, cmd)
	fn := f.verifyFn
	f.mu.Unlock()
	if fn == nil {
		return app.VerifyEmailResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeRegistration) registered() []app.RegisterCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.RegisterCommand(nil), f.registerCmds...)
}

func (f *fakeRegistration) verified() []app.VerifyEmailCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.VerifyEmailCommand(nil), f.verifyCmds...)
}

// fakeResender records every resend command and answers with whatever outcome a
// test asks for. The OUTCOME is the interesting knob: the handler must render
// all of them identically.
type fakeResender struct {
	mu sync.Mutex

	resendFn func(app.ResendVerificationCommand) (app.ResendVerificationResult, error)
	cmds     []app.ResendVerificationCommand
}

func (f *fakeResender) Resend(
	_ context.Context, cmd app.ResendVerificationCommand,
) (app.ResendVerificationResult, error) {
	f.mu.Lock()
	f.cmds = append(f.cmds, cmd)
	fn := f.resendFn
	f.mu.Unlock()
	if fn == nil {
		return app.ResendVerificationResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeResender) resends() []app.ResendVerificationCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.ResendVerificationCommand(nil), f.cmds...)
}

// fakeResets records what the two password-reset RPCs asked the app layer for.
//
// The COMMANDS are kept rather than a call count, because every assertion worth
// making about these two handlers is about a field of one: which address was
// looked up, which caller scope was derived, and that the token and the password
// arrived unchanged. A counter would pass on a handler that reset the wrong
// account.
type fakeResets struct {
	mu sync.Mutex

	requestFn  func(app.RequestPasswordResetCommand) (app.RequestPasswordResetResult, error)
	completeFn func(app.ResetPasswordCommand) (app.ResetPasswordResult, error)

	requested []app.RequestPasswordResetCommand
	completed []app.ResetPasswordCommand
}

func (f *fakeResets) Request(
	_ context.Context, cmd app.RequestPasswordResetCommand,
) (app.RequestPasswordResetResult, error) {
	f.mu.Lock()
	f.requested = append(f.requested, cmd)
	fn := f.requestFn
	f.mu.Unlock()
	if fn == nil {
		return app.RequestPasswordResetResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeResets) Complete(
	_ context.Context, cmd app.ResetPasswordCommand,
) (app.ResetPasswordResult, error) {
	f.mu.Lock()
	f.completed = append(f.completed, cmd)
	fn := f.completeFn
	f.mu.Unlock()
	if fn == nil {
		return app.ResetPasswordResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeResets) requests() []app.RequestPasswordResetCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.RequestPasswordResetCommand(nil), f.requested...)
}

func (f *fakeResets) completions() []app.ResetPasswordCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.ResetPasswordCommand(nil), f.completed...)
}

type fakeAuthentication struct {
	mu sync.Mutex

	authenticateFn func(app.AuthenticateCommand) (app.AuthenticateResult, error)
	createFn       func(app.CreateSessionCommand) (app.CreateSessionResult, error)
	revokeFn       func(app.RevokeSessionCommand) (app.RevokeSessionResult, error)
	revokeAllFn    func(app.RevokeAllSessionsCommand) (app.RevokeAllSessionsResult, error)

	authenticateCmds []app.AuthenticateCommand
	createCmds       []app.CreateSessionCommand
	revokeCmds       []app.RevokeSessionCommand
	revokeAllCmds    []app.RevokeAllSessionsCommand
}

func (f *fakeAuthentication) Authenticate(
	_ context.Context, cmd app.AuthenticateCommand,
) (app.AuthenticateResult, error) {
	f.mu.Lock()
	f.authenticateCmds = append(f.authenticateCmds, cmd)
	fn := f.authenticateFn
	f.mu.Unlock()
	if fn == nil {
		return app.AuthenticateResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeAuthentication) CreateSession(
	_ context.Context, cmd app.CreateSessionCommand,
) (app.CreateSessionResult, error) {
	f.mu.Lock()
	f.createCmds = append(f.createCmds, cmd)
	fn := f.createFn
	f.mu.Unlock()
	if fn == nil {
		return app.CreateSessionResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeAuthentication) RevokeSession(
	_ context.Context, cmd app.RevokeSessionCommand,
) (app.RevokeSessionResult, error) {
	f.mu.Lock()
	f.revokeCmds = append(f.revokeCmds, cmd)
	fn := f.revokeFn
	f.mu.Unlock()
	if fn == nil {
		return app.RevokeSessionResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeAuthentication) RevokeAllSessions(
	_ context.Context, cmd app.RevokeAllSessionsCommand,
) (app.RevokeAllSessionsResult, error) {
	f.mu.Lock()
	f.revokeAllCmds = append(f.revokeAllCmds, cmd)
	fn := f.revokeAllFn
	f.mu.Unlock()
	if fn == nil {
		return app.RevokeAllSessionsResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeAuthentication) authenticated() []app.AuthenticateCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.AuthenticateCommand(nil), f.authenticateCmds...)
}

func (f *fakeAuthentication) created() []app.CreateSessionCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.CreateSessionCommand(nil), f.createCmds...)
}

func (f *fakeAuthentication) revoked() []app.RevokeSessionCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.RevokeSessionCommand(nil), f.revokeCmds...)
}

func (f *fakeAuthentication) revokedAll() []app.RevokeAllSessionsCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.RevokeAllSessionsCommand(nil), f.revokeAllCmds...)
}

type fakeSecondFactor struct {
	mu sync.Mutex

	enrollFn   func(app.EnrollTotpCommand) (app.EnrollTotpResult, error)
	confirmFn  func(app.ConfirmTotpCommand) (app.ConfirmTotpResult, error)
	recoveryFn func(app.GenerateRecoveryCodesCommand) (app.GenerateRecoveryCodesResult, error)

	enrollCmds   []app.EnrollTotpCommand
	confirmCmds  []app.ConfirmTotpCommand
	recoveryCmds []app.GenerateRecoveryCodesCommand
}

func (f *fakeSecondFactor) EnrollTotp(
	_ context.Context, cmd app.EnrollTotpCommand,
) (app.EnrollTotpResult, error) {
	f.mu.Lock()
	f.enrollCmds = append(f.enrollCmds, cmd)
	fn := f.enrollFn
	f.mu.Unlock()
	if fn == nil {
		return app.EnrollTotpResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeSecondFactor) ConfirmTotp(
	_ context.Context, cmd app.ConfirmTotpCommand,
) (app.ConfirmTotpResult, error) {
	f.mu.Lock()
	f.confirmCmds = append(f.confirmCmds, cmd)
	fn := f.confirmFn
	f.mu.Unlock()
	if fn == nil {
		return app.ConfirmTotpResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeSecondFactor) GenerateRecoveryCodes(
	_ context.Context, cmd app.GenerateRecoveryCodesCommand,
) (app.GenerateRecoveryCodesResult, error) {
	f.mu.Lock()
	f.recoveryCmds = append(f.recoveryCmds, cmd)
	fn := f.recoveryFn
	f.mu.Unlock()
	if fn == nil {
		return app.GenerateRecoveryCodesResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeSecondFactor) enrolled() []app.EnrollTotpCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.EnrollTotpCommand(nil), f.enrollCmds...)
}

func (f *fakeSecondFactor) confirmed() []app.ConfirmTotpCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.ConfirmTotpCommand(nil), f.confirmCmds...)
}

func (f *fakeSecondFactor) generated() []app.GenerateRecoveryCodesCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.GenerateRecoveryCodesCommand(nil), f.recoveryCmds...)
}

// queryCall records one read: which method, for which subject, with which token
// and size. Every list assertion in this package is written against it, so a
// handler that sent a page token to the wrong list, or asked about the wrong
// account, shows up as a recorded call that does not match.
type queryCall struct {
	method    string
	subjectID string
	token     page.Token
	size      int
}

// fakeLifecycle records the two lifecycle commands.
//
// It records the COMMAND, not just that it was called, because the property
// every test here asserts is which subject the handler named — and the handler is
// required to take it from the principal and from nowhere else.
type fakeLifecycle struct {
	mu sync.Mutex

	deactivateFn func(app.DeactivateAccountCommand) (app.DeactivateAccountResult, error)
	deletionFn   func(app.RequestAccountDeletionCommand) (app.RequestAccountDeletionResult, error)

	deactivateCmds []app.DeactivateAccountCommand
	deletionCmds   []app.RequestAccountDeletionCommand
}

func (f *fakeLifecycle) Deactivate(
	_ context.Context, cmd app.DeactivateAccountCommand,
) (app.DeactivateAccountResult, error) {
	f.mu.Lock()
	f.deactivateCmds = append(f.deactivateCmds, cmd)
	fn := f.deactivateFn
	f.mu.Unlock()
	if fn == nil {
		return app.DeactivateAccountResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeLifecycle) RequestDeletion(
	_ context.Context, cmd app.RequestAccountDeletionCommand,
) (app.RequestAccountDeletionResult, error) {
	f.mu.Lock()
	f.deletionCmds = append(f.deletionCmds, cmd)
	fn := f.deletionFn
	f.mu.Unlock()
	if fn == nil {
		return app.RequestAccountDeletionResult{}, nil
	}
	return fn(cmd)
}

type fakeQueries struct {
	mu sync.Mutex

	accountFn  func(string) (app.AccountView, error)
	sessionsFn func(string, page.Token, int) (page.Page[app.SessionSummary], error)
	methodsFn  func(string) ([]app.AuthMethod, error)
	historyFn  func(string, page.Token, int) (page.Page[app.LoginRecord], error)

	calls []queryCall
}

func (f *fakeQueries) record(c queryCall) {
	f.mu.Lock()
	f.calls = append(f.calls, c)
	f.mu.Unlock()
}

func (f *fakeQueries) recorded() []queryCall {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]queryCall(nil), f.calls...)
}

func (f *fakeQueries) GetUser(_ context.Context, subjectID string) (app.AccountView, error) {
	f.record(queryCall{method: "GetUser", subjectID: subjectID})
	if f.accountFn == nil {
		return app.AccountView{}, nil
	}
	return f.accountFn(subjectID)
}

func (f *fakeQueries) ListSessions(
	_ context.Context, subjectID string, token page.Token, size int,
) (page.Page[app.SessionSummary], error) {
	f.record(queryCall{method: "ListSessions", subjectID: subjectID, token: token, size: size})
	if f.sessionsFn == nil {
		return page.Page[app.SessionSummary]{}, nil
	}
	return f.sessionsFn(subjectID, token, size)
}

func (f *fakeQueries) ListMethods(_ context.Context, subjectID string) ([]app.AuthMethod, error) {
	f.record(queryCall{method: "ListMethods", subjectID: subjectID})
	if f.methodsFn == nil {
		return nil, nil
	}
	return f.methodsFn(subjectID)
}

func (f *fakeQueries) ListLoginHistory(
	_ context.Context, subjectID string, token page.Token, size int,
) (page.Page[app.LoginRecord], error) {
	f.record(queryCall{method: "ListLoginHistory", subjectID: subjectID, token: token, size: size})
	if f.historyFn == nil {
		return page.Page[app.LoginRecord]{}, nil
	}
	return f.historyFn(subjectID, token, size)
}

type fakeDirectory struct {
	mu       sync.Mutex
	fn       func(string) (ids.UserID, error)
	subjects []string
}

func (f *fakeDirectory) UserBySubject(_ context.Context, subjectID string) (ids.UserID, error) {
	f.mu.Lock()
	f.subjects = append(f.subjects, subjectID)
	fn := f.fn
	f.mu.Unlock()
	if fn == nil {
		return callerUser, nil
	}
	return fn(subjectID)
}

func (f *fakeDirectory) asked() []string {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]string(nil), f.subjects...)
}

// ---------------------------------------------------------------------------
// The gate pipeline, stubbed to the minimum that lets a request through
// ---------------------------------------------------------------------------

type stubAuthenticator struct {
	principal interceptor.Principal
	err       error
}

func (s stubAuthenticator) Authenticate(
	_ context.Context, _ interceptor.Header,
) (interceptor.Principal, error) {
	return s.principal, s.err
}

type stubOrgResolver struct{}

func (stubOrgResolver) Resolve(
	ctx context.Context, _ interceptor.Principal, _ interceptor.Header,
) (context.Context, error) {
	return ctx, nil
}

type allowChecker struct{}

func (allowChecker) Check(_ context.Context, _ authz.Query) (authz.Decision, error) {
	return authz.Allow("test"), nil
}

func (allowChecker) BatchCheck(_ context.Context, qs []authz.Query) ([]authz.Decision, error) {
	out := make([]authz.Decision, len(qs))
	for i := range out {
		out[i] = authz.Allow("test")
	}
	return out, nil
}

type stubSubscriptions struct{}

func (stubSubscriptions) Permit(_ context.Context, _ optionsv1.OperationClass) error { return nil }

// memStore is an in-memory cqrs.Store, enough to make gate 5 real.
type memStore struct {
	mu      sync.Mutex
	records map[string]cqrs.Record
}

func newMemStore() *memStore { return &memStore{records: map[string]cqrs.Record{}} }

func (m *memStore) Claim(
	_ context.Context, s cqrs.Scope, fp [32]byte, _ time.Duration,
) (cqrs.Record, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	if r, ok := m.records[s.String()]; ok {
		return r, nil
	}
	m.records[s.String()] = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
	return cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}, nil
}

func (m *memStore) Complete(_ context.Context, s cqrs.Scope, response []byte) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	r := m.records[s.String()]
	r.State = cqrs.StateDone
	r.Response = response
	m.records[s.String()] = r
	return nil
}

func (m *memStore) Release(_ context.Context, s cqrs.Scope) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	delete(m.records, s.String())
	return nil
}

// fakeUsernames records what CheckUsernameAvailability asked the app layer for.
//
// The COMMANDS are kept rather than a call count, for fakeResets' reason: the
// assertions worth making about this handler are that the raw handle reached the
// app layer unchanged — normalization is the app layer's, not the transport's —
// and that the caller scope was derived from the connection rather than from a
// field the caller could choose.
type fakeUsernames struct {
	mu sync.Mutex

	checkFn func(app.CheckUsernameCommand) (app.CheckUsernameResult, error)
	checked []app.CheckUsernameCommand
}

func (f *fakeUsernames) Check(
	_ context.Context, cmd app.CheckUsernameCommand,
) (app.CheckUsernameResult, error) {
	f.mu.Lock()
	f.checked = append(f.checked, cmd)
	fn := f.checkFn
	f.mu.Unlock()
	if fn == nil {
		return app.CheckUsernameResult{}, nil
	}
	return fn(cmd)
}

func (f *fakeUsernames) checks() []app.CheckUsernameCommand {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]app.CheckUsernameCommand(nil), f.checked...)
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

type harness struct {
	client       identityv1connect.IdentityServiceClient
	registration *fakeRegistration
	resender     *fakeResender
	resets       *fakeResets
	usernames    *fakeUsernames
	authn        *fakeAuthentication
	secondFactor *fakeSecondFactor
	lifecycle    *fakeLifecycle
	queries      *fakeQueries
	directory    *fakeDirectory
}

// options tweaks the pipeline for the few tests that need a different caller.
type options struct {
	// principal replaces the default caller. The zero value keeps the default.
	principal *interceptor.Principal

	// authnErr makes the authn gate refuse, which is how an unauthenticated
	// request is expressed — there is no way to reach a gated handler without one.
	authnErr error

	// trustedProxyHops builds the handler's caller-scope resolver with a trust
	// boundary. The zero value is the production default: trust nothing, ignore
	// X-Forwarded-For entirely.
	trustedProxyHops int
}

func defaultPrincipal() interceptor.Principal {
	return interceptor.Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: callerSubject},
		Context: authz.AuthContext{AAL: 2, ActiveOrg: "org_test", SessionID: "sess_test"},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2,
	}
}

func newHarness(t *testing.T, opts ...options) *harness {
	t.Helper()

	var o options
	if len(opts) > 0 {
		o = opts[0]
	}

	h := &harness{
		registration: &fakeRegistration{},
		resender:     &fakeResender{},
		resets:       &fakeResets{},
		usernames:    &fakeUsernames{},
		authn:        &fakeAuthentication{},
		secondFactor: &fakeSecondFactor{},
		lifecycle:    &fakeLifecycle{},
		queries:      &fakeQueries{},
		directory:    &fakeDirectory{},
	}

	// Built from the option rather than defaulted to a zero Resolver, so the
	// production default (0 hops) is exercised by every test in this package that
	// does not ask for something else.
	callerScope, err := clientip.NewResolver(o.trustedProxyHops)
	if err != nil {
		t.Fatalf("building the caller-scope resolver: %v", err)
	}

	svc, err := api.New(api.Deps{
		Registration:   h.registration,
		Resender:       h.resender,
		Resets:         h.resets,
		Usernames:      h.usernames,
		Authentication: h.authn,
		SecondFactor:   h.secondFactor,
		Lifecycle:      h.lifecycle,
		Queries:        h.queries,
		Directory:      h.directory,
		CallerScope:    callerScope,
	})
	if err != nil {
		t.Fatalf("building the handler: %v", err)
	}

	policies, err := policy.Load("chronos.identity.v1.IdentityService")
	if err != nil {
		t.Fatalf("loading identity's policies: %v", err)
	}

	guard, err := authz.NewGuard(authz.GuardDeps{Checker: allowChecker{}})
	if err != nil {
		t.Fatalf("building the authz guard: %v", err)
	}
	once, err := cqrs.NewOnce(cqrs.OnceDeps{Store: newMemStore()})
	if err != nil {
		t.Fatalf("building the idempotency kernel: %v", err)
	}
	idem, err := interceptor.NewIdempotency(once)
	if err != nil {
		t.Fatalf("building gate 5: %v", err)
	}

	principal := defaultPrincipal()
	if o.principal != nil {
		principal = *o.principal
	}
	gates, err := interceptor.NewGates(interceptor.Deps{
		Policies:      policies,
		Authn:         stubAuthenticator{principal: principal, err: o.authnErr},
		Org:           stubOrgResolver{},
		Authz:         guard,
		Subscriptions: stubSubscriptions{},
		Idempotency:   idem,
	})
	if err != nil {
		t.Fatalf("building the gate pipeline: %v", err)
	}

	mux := http.NewServeMux()
	mux.Handle(identityv1connect.NewIdentityServiceHandler(
		svc, connect.WithInterceptors(gates)))
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)

	h.client = identityv1connect.NewIdentityServiceClient(server.Client(), server.URL)
	return h
}

// withKey attaches an idempotency key, which every mutating RPC requires.
func withKey[T any](msg *T, key string) *connect.Request[T] {
	req := connect.NewRequest(msg)
	req.Header().Set(interceptor.IdempotencyHeader, key)
	return req
}

// ---------------------------------------------------------------------------
// Assertions shared across files
// ---------------------------------------------------------------------------

func requireCode(t *testing.T, err error, want connect.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected an error with code %v, got success", want)
	}
	if got := connect.CodeOf(err); got != want {
		t.Fatalf("code = %v, want %v (error: %v)", got, want, err)
	}
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

// A nil collaborator must be refused at construction. The failure it prevents is
// a nil-pointer PANIC on the first request to one screen, in a process that
// started healthy and answers every other RPC — so a test that only checked the
// happy path would report a fully working handler.
func TestNewRefusesAPartiallyWiredHandler(t *testing.T) {
	t.Parallel()

	full := func() api.Deps {
		return api.Deps{
			Registration:   &fakeRegistration{},
			Resender:       &fakeResender{},
			Resets:         &fakeResets{},
			Usernames:      &fakeUsernames{},
			Authentication: &fakeAuthentication{},
			SecondFactor:   &fakeSecondFactor{},
			Lifecycle:      &fakeLifecycle{},
			Queries:        &fakeQueries{},
			Directory:      &fakeDirectory{},
		}
	}

	tests := map[string]func(*api.Deps){
		"no registration service":   func(d *api.Deps) { d.Registration = nil },
		"no verification resender":  func(d *api.Deps) { d.Resender = nil },
		"no password-reset service": func(d *api.Deps) { d.Resets = nil },
		// A nil here panics the ONE endpoint that lets a person find out their
		// handle is taken before they spend a verification link they cannot get
		// back, so its absence would read as a bug in verification rather than in
		// wiring.
		"no username availability service": func(d *api.Deps) { d.Usernames = nil },
		"no authentication service":        func(d *api.Deps) { d.Authentication = nil },
		"no second-factor service":         func(d *api.Deps) { d.SecondFactor = nil },
		"no lifecycle service":             func(d *api.Deps) { d.Lifecycle = nil },
		"no read side":                     func(d *api.Deps) { d.Queries = nil },
		"no user directory":                func(d *api.Deps) { d.Directory = nil },
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deps := full()
			remove(&deps)
			svc, err := api.New(deps)
			if err == nil {
				t.Fatalf("New accepted a handler with %s", name)
			}
			if svc != nil {
				t.Fatalf("New returned a handler alongside an error: %#v", svc)
			}
			if !strings.Contains(err.Error(), "identity/api") {
				t.Fatalf("error does not name the package: %v", err)
			}
		})
	}

	t.Run("a complete set is accepted", func(t *testing.T) {
		t.Parallel()
		if _, err := api.New(full()); err != nil {
			t.Fatalf("New refused a complete set: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Error mapping
// ---------------------------------------------------------------------------

// The handler must add no error mapping of its own.
//
// Every RPC's error path must produce EXACTLY what srvconnect.Error produces for
// the same domain error — the mapping the whole server shares. The property this
// protects is ADR-036's: the app layer answers every authentication failure with
// one error, and a second mapping in this layer is how one answer becomes several
// distinguishable ones.
//
// Asserted against srvconnect.Error rather than against a literal code table, so
// the test states "no second mapping exists here" rather than restating the first.
func TestErrorsAreMappedByTheServerWideMappingAndNothingElse(t *testing.T) {
	t.Parallel()

	domainErrors := map[string]error{
		"an undifferentiated refusal":             errs.Unauthenticatedf("authentication failed"),
		"not found":                               errs.NotFoundf("no such account"),
		"a conflict":                              errs.Conflictf("this account already exists"),
		"a validation failure":                    errs.ValidationFailedf("an idempotency key is required"),
		"an internal fault":                       errs.Internalf("reading an account"),
		"an error that never passed through errs": errors.New("raw"),
	}

	for name, domainErr := range domainErrors {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			want := srvconnect.Error(domainErr)
			wantCode := connect.CodeOf(want)
			wantMsg := want.Error()

			h := newHarness(t)
			h.registration.registerFn = func(app.RegisterCommand) (app.RegisterResult, error) {
				return app.RegisterResult{}, domainErr
			}
			h.registration.verifyFn = func(app.VerifyEmailCommand) (app.VerifyEmailResult, error) {
				return app.VerifyEmailResult{}, domainErr
			}
			h.authn.authenticateFn = func(app.AuthenticateCommand) (app.AuthenticateResult, error) {
				return app.AuthenticateResult{}, domainErr
			}
			h.authn.revokeFn = func(app.RevokeSessionCommand) (app.RevokeSessionResult, error) {
				return app.RevokeSessionResult{}, domainErr
			}
			h.queries.accountFn = func(string) (app.AccountView, error) {
				return app.AccountView{}, domainErr
			}
			h.secondFactor.confirmFn = func(app.ConfirmTotpCommand) (app.ConfirmTotpResult, error) {
				return app.ConfirmTotpResult{}, domainErr
			}

			ctx := t.Context()
			calls := map[string]func() error{
				"Register": func() error {
					_, err := h.client.Register(ctx, withKey(&identityv1.RegisterRequest{}, "k1"))
					return err
				},
				"VerifyEmail": func() error {
					_, err := h.client.VerifyEmail(ctx, withKey(&identityv1.VerifyEmailRequest{}, "k2"))
					return err
				},
				"Authenticate": func() error {
					_, err := h.client.Authenticate(ctx, withKey(&identityv1.AuthenticateRequest{}, "k3"))
					return err
				},
				"GetUser": func() error {
					_, err := h.client.GetUser(ctx, connect.NewRequest(&identityv1.GetUserRequest{}))
					return err
				},
				"ConfirmTotp": func() error {
					_, err := h.client.ConfirmTotp(ctx, withKey(&identityv1.ConfirmTotpRequest{}, "k4"))
					return err
				},
				"RevokeSession": func() error {
					_, err := h.client.RevokeSession(ctx, withKey(&identityv1.RevokeSessionRequest{
						SessionId: "sess_01ARZ3NDEKTSV4RRFFQ69G5FAV",
					}, "k5"))
					return err
				},
			}
			for method, call := range calls {
				err := call()
				if err == nil {
					t.Fatalf("%s: expected an error", method)
				}
				if got := connect.CodeOf(err); got != wantCode {
					t.Errorf("%s: code = %v, want %v (the server-wide mapping)", method, got, wantCode)
				}
				if err.Error() != wantMsg {
					t.Errorf("%s: message = %q, want %q", method, err.Error(), wantMsg)
				}
			}
		})
	}
}

// An unauthenticated caller reaches no handler at all, and every authenticated
// RPC refuses. This is the pipeline's guarantee rather than the handler's, and it
// is asserted here because the handler's own principal check is only reachable
// when the pipeline has been bypassed.
func TestAnUnauthenticatedCallerReachesNoAuthenticatedHandler(t *testing.T) {
	t.Parallel()

	h := newHarness(t, options{authnErr: errors.New("no session")})
	ctx := t.Context()

	_, err := h.client.GetUser(ctx, connect.NewRequest(&identityv1.GetUserRequest{}))
	requireCode(t, err, connect.CodeUnauthenticated)

	if calls := h.queries.recorded(); len(calls) != 0 {
		t.Fatalf("the read side was called for an unauthenticated request: %+v", calls)
	}
}
