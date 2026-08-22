//go:build integration

// Package protocolit is the protocol conformance suite: it drives the real
// server the way a CLIENT does, over every wire format ADR-007 promises, and
// checks the promises the published contract makes rather than the behaviour
// the handlers happen to have.
//
// # Why this package exists
//
// Twenty-nine RPCs across three services had exactly one kind of caller in the
// test suite: the generated Go Connect client, over the Connect protocol, with
// a well-formed protobuf message. Everything below is what that caller cannot
// reach.
//
//   - ADR-007 says one port serves Connect, gRPC and gRPC-Web. A browser using
//     connect-web speaks a different wire format from the Go client, and against
//     the REAL binary — gates, interceptors, otelhttp wrapper and all — nothing
//     had confirmed the server answers it. internal/server/connect/server_test.go
//     covers the five protocol/version pairs, but against a stub service on an
//     httptest server with no interceptors: it proves the transport is
//     negotiable, not that a gated RPC survives the trip.
//   - Eight RPCs are `idempotency_level = NO_SIDE_EFFECTS` and
//     buf.gen.openapi.yaml passes `allow-get`, so docs/api/chronos-openapi.yaml
//     advertises GET endpoints with query parameters for all eight. No test had
//     ever called one. A published route that 404s is a lie every generated
//     client inherits.
//   - CONVENTIONS §5 says clients branch on the machine-readable `reason` and
//     NEVER on the HTTP status. Nothing had checked that `reason` reaches a
//     client at all — let alone over gRPC, where details travel in a trailer,
//     or over gRPC-Web, where they travel in a trailer encoded into the body.
//   - Nothing had ever sent the server malformed input over the wire: a string
//     where a number belongs, a truncated body, an unknown member, the wrong
//     Content-Type.
//
// # A failing assertion here is a finding, not a test to adjust
//
// Every case is written against the DOCUMENTED contract — the proto, the
// generated OpenAPI, CONVENTIONS — not against the code. Where the two disagree
// the test says so, names the document, and fails. Defects found this way are
// listed in the package's report; the server was not changed to make anything
// here pass.
//
// # The matrix
//
// Files are one concern each, and every test names its RPCs and its transports
// in its subtests, so `go test -run 'TestX/Y' -v` addresses one cell.
//
//	file                          | what it varies                     | cells
//	------------------------------|------------------------------------|----------------
//	protocol_test.go              | 9 reads x 6 transports             | 54
//	                              | 2 mutations x 6 transports         | 12
//	                              | 3 refusals x 6 transports (reason) | 18
//	getroute_test.go              | 9 documented GET routes            | 9
//	                              | 8 GET routes, no bearer token      | 8
//	                              | 7 GET query-parameter rules        | 7
//	                              | 2 mutations, GET refused           | 2
//	validation_test.go            | 27 declared protovalidate rules    | 27
//	                              | 9 well-formed requests             | 9
//	malformed_test.go             | 16 malformed encodings             | 16
//	                              | 1 unknown procedure x 6 transports | 6
//	auth_test.go                  | 21 authenticated RPCs, anonymous   | 21
//	                              | 8 unusable bearer tokens           | 8
//	                              | 6 assurance-floor methods          | 6
//	idempotency_test.go           | 20 mutating RPCs, key omitted      | 20
//	                              | replay, collision, scope, reads,   |
//	                              | concurrent duplicates              | 5
//	catalogue_conformance_test.go | 5 provokable reason codes          | 5
//	aggregatewrite_test.go        | 2 aggregates written twice         | 2
//
// The transports are Connect over HTTP/1.1 and h2c, Connect's GET form, gRPC
// over h2c, and gRPC-Web over both — plus raw net/http for every case in
// getroute_test.go, validation_test.go, malformed_test.go, auth_test.go,
// idempotency_test.go and catalogue_conformance_test.go, which are written
// without the generated client so they measure the wire rather than the client
// library's agreement with the server.
//
// # What "the real stack" means here
//
// Same answer as internal/adapter/identityit, and for the same reason: the
// composition root is unexported inside `package main`, so the only way to test
// what production actually assembles is to COMPILE AND RUN cmd/api and speak to
// it over TCP. Every interceptor, every gate, every policy annotation is the
// production one, constructed by the production code, in the production order.
//
// The projectors are supplied here, as identityit supplies them, because
// cmd/projector is a separate binary that the local stack does not run — and a
// bearer token authenticates nothing until session_view has the session
// (migration 00010).
//
// # Running it alongside identityit
//
// Both packages start identity projectors, and a projection is guarded by ONE
// Postgres advisory lease. This package deliberately does NOT require the lease:
// if identityit holds it, identityit's projectors project this package's events
// too — they subscribe to $all, so the read model advances either way — and the
// runners here sit in their normal standby loop. Every wait in this package is
// on the DATA appearing, never on lease ownership.
//
// The reverse is not true: identityit's harness fails the run outright if it
// cannot take the lease. So `go test -tags=integration ./...` can start this
// package first and break that one. Run them with `-p 1`, or run this package on
// its own.
package protocolit_test

import (
	"bufio"
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"
	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/gen/proto/chronos/organization/v1/organizationv1connect"
	"github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1/workspacev1connect"
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/modules/notification"
	notificationcontract "github.com/chronos/chronos-go/internal/modules/notification/contract"
	notificationdomain "github.com/chronos/chronos-go/internal/modules/notification/domain"
	notificationprojection "github.com/chronos/chronos-go/internal/modules/notification/projection"
	"github.com/chronos/chronos-go/internal/modules/organization"
	organizationprojection "github.com/chronos/chronos-go/internal/modules/organization/projection"
	"github.com/chronos/chronos-go/internal/modules/profile"
	profileprojection "github.com/chronos/chronos-go/internal/modules/profile/projection"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspaceprojection "github.com/chronos/chronos-go/internal/modules/workspace/projection"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/chronos/chronos-go/internal/server/interceptor"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// h is the one harness for the package: one cmd/api process, one set of
// projectors, one pair of accounts. Starting cmd/api costs a compile plus a
// boot, and an account costs a registration, a verification and a TOTP
// enrolment — paying either per test would put this suite past `go test`'s
// timeout for no additional coverage.
//
// Isolation between RUNS comes from the key material: every run generates its
// own blind-index key, so every address this run registers hashes into an index
// space no earlier run can collide with.
var h *harness

type harness struct {
	suffix   string
	baseURL  string
	clockURL string

	// http is the ordinary HTTP/1.1 client. The h2c client lives in clientFor,
	// because the protocol matrix needs one per transport.
	http *http.Client

	// identity is the default-protocol client, used for the fixtures rather than
	// for assertions: the assertions build their own client per protocol.
	identity identityv1connect.IdentityServiceClient

	// organization is the same, for the tenant-creation fixtures.
	organization organizationv1connect.OrganizationServiceClient

	// workspace is the first client whose RPC traverses every gate.
	workspace workspacev1connect.WorkspaceServiceClient

	pool      *pgxpool.Pool
	pg        *pgadapter.DB
	store     *kurrentadapter.Store
	codec     *eventcodec.JSON
	upcasters *eventsourcing.UpcasterRegistry

	index  *blindindex.Index
	guards *identitypg.Guards

	cancelProjectors context.CancelFunc
	projectorsDone   chan struct{}

	serverLog  *strings.Builder
	logMu      sync.Mutex
	stopServer func()

	// active is the fully-enrolled account: verified, TOTP-confirmed, ACTIVE,
	// holding an AAL2 session. Everything that needs an authenticated caller
	// uses it.
	active *accountFixture

	// bootstrap is an account that stopped at "verified": it has a password, no
	// second factor, and an AAL1 session. It is what proves the difference
	// between `min_aal` and `bootstrap_min_aal` on the wire — the same session
	// is admitted to EnrollTotp and refused by GenerateRecoveryCodes.
	bootstrap *accountFixture

	// bearerMu serialises the lazy re-establishment in activeBearer. Tests are
	// sequential today; the mutex costs nothing and removes the failure mode
	// where adding t.Parallel() silently produces two sign-ins for one account.
	bearerMu sync.Mutex
}

// accountFixture is one account and the session established for it.
type accountFixture struct {
	email     string
	username  string
	password  string
	subjectID string
	userID    string
	secret    string // the confirmed TOTP secret; empty for a bootstrap account
	bearer    string
	sessionID string
}

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "protocolit: %v\n", err)
		os.Exit(1)
	}
	os.Exit(code)
}

func runMain(m *testing.M) (int, error) {
	var err error
	h, err = newHarness()
	if err != nil {
		return 0, err
	}
	defer h.close()
	defer h.closeOnSignal()()
	return m.Run(), nil
}

// closeOnSignal tears the harness down when this process is KILLED rather than
// when it returns. `go test` enforces -timeout with SIGQUIT, and a signalled
// process runs no deferred function — without this, a timed-out run leaves the
// cmd/api child holding a Postgres pool, a KurrentDB subscription and a
// listening socket, one copy per aborted run.
func (hh *harness) closeOnSignal() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig, ok := <-ch
		if !ok {
			return
		}
		fmt.Fprintf(os.Stderr, "protocolit: %v — tearing down the harness\n", sig)
		hh.close()
		os.Exit(2)
	}()
	return func() { signal.Stop(ch); close(ch) }
}

func newHarness() (*harness, error) {
	root, err := repoRoot()
	if err != nil {
		return nil, err
	}

	var raw [6]byte
	if _, err := io.ReadFull(rand.Reader, raw[:]); err != nil {
		return nil, fmt.Errorf("entropy: %w", err)
	}
	suffix := hex.EncodeToString(raw[:])

	env, err := loadDotEnv(filepath.Join(root, ".env"))
	if err != nil {
		return nil, err
	}

	indexKey, err := randomKeyHex()
	if err != nil {
		return nil, err
	}
	pepperKey, err := randomKeyHex()
	if err != nil {
		return nil, err
	}
	sealKey, err := randomKeyHex()
	if err != nil {
		return nil, err
	}

	port, err := freePort()
	if err != nil {
		return nil, err
	}
	clockPort, err := freePort()
	if err != nil {
		return nil, err
	}

	env["APP_ENV"] = "local"
	env["OTEL_ENABLED"] = "false"
	env["TEMPORAL_ENABLED"] = "false"
	env["IDENTITY_EMAIL_INDEX_KEY"] = indexKey
	env["IDENTITY_PASSWORD_PEPPER_KEY"] = pepperKey
	env["IDENTITY_TOTP_SEAL_KEY"] = sealKey
	env["IDENTITY_TOTP_ISSUER"] = "ChronosPT"
	env["API_PORT"] = strconv.Itoa(port)
	env["CLOCK_CONTROL_ENABLED"] = "true"
	env["CLOCK_CONTROL_ADDR"] = fmt.Sprintf("127.0.0.1:%d", clockPort)

	hh := &harness{
		suffix:    suffix,
		baseURL:   fmt.Sprintf("http://127.0.0.1:%d", port),
		clockURL:  fmt.Sprintf("http://127.0.0.1:%d", clockPort),
		http:      &http.Client{Timeout: 60 * time.Second},
		serverLog: &strings.Builder{},
	}
	hh.identity = identityv1connect.NewIdentityServiceClient(hh.http, hh.baseURL)
	hh.organization = organizationv1connect.NewOrganizationServiceClient(hh.http, hh.baseURL)
	hh.workspace = workspacev1connect.NewWorkspaceServiceClient(hh.http, hh.baseURL)

	if err := hh.dialInfra(env); err != nil {
		return nil, err
	}
	if err := hh.startServer(root, env); err != nil {
		return nil, err
	}
	if err := hh.verifyClockControl(context.Background()); err != nil {
		hh.close()
		return nil, err
	}
	hh.startProjectors()
	if err := hh.buildAccounts(); err != nil {
		hh.close()
		return nil, err
	}
	return hh, nil
}

// dialInfra opens this test's own connections to Postgres and KurrentDB.
//
// For OBSERVATION and for the ONE fixture step that has no public route — the
// verification token, which the server mails and this process has no mailbox
// for. Everything else goes over HTTP to the server, because a test that wrote
// its own rows would be asserting against its own work.
func (hh *harness) dialInfra(env map[string]string) error {
	dsn := fmt.Sprintf("postgres://%s:%s@%s:%s/%s?sslmode=disable",
		env["POSTGRES_APP_USER"], env["POSTGRES_APP_PASSWORD"],
		envOr(env, "POSTGRES_HOST", "localhost"), envOr(env, "POSTGRES_PORT", "5432"),
		env["POSTGRES_DB"])

	pool, err := pgxpool.New(context.Background(), dsn)
	if err != nil {
		return fmt.Errorf("postgres pool: %w", err)
	}
	hh.pool = pool
	hh.pg = pgadapter.New(pool)

	// Every module's events and schemas, from the modules' own composition
	// surfaces — the same three calls cmd/projector makes. A type registered in
	// one binary and not another is a projector that stops on an event the API
	// happily wrote.
	upcasters := eventsourcing.NewUpcasterRegistry()
	hh.upcasters = upcasters
	identity.RegisterSchemas(upcasters)
	notification.RegisterSchemas(upcasters)
	profile.RegisterSchemas(upcasters)
	organization.RegisterSchemas(upcasters)
	workspace.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	identity.RegisterEvents(codec)
	notification.RegisterEvents(codec)
	profile.RegisterEvents(codec)
	organization.RegisterEvents(codec)
	workspace.RegisterEvents(codec)
	hh.codec = codec

	client, err := kurrentadapter.Dial(
		envOr(env, "KURRENTDB_CONNECTION_STRING", "kurrentdb://localhost:2113?tls=false"))
	if err != nil {
		return fmt.Errorf("kurrentdb: %w", err)
	}
	hh.store = kurrentadapter.NewStore(client, codec)

	key, err := hex.DecodeString(env["IDENTITY_EMAIL_INDEX_KEY"])
	if err != nil {
		return err
	}
	if hh.index, err = blindindex.New(key); err != nil {
		return fmt.Errorf("blind index: %w", err)
	}
	if hh.guards, err = identitypg.NewGuards(hh.pg); err != nil {
		return fmt.Errorf("guards: %w", err)
	}
	return nil
}

// startServer compiles and runs cmd/api.
//
// `go build` rather than `go run`, so the process this test signals is the
// server itself and not a wrapper that would leave it orphaned.
func (hh *harness) startServer(root string, env map[string]string) error {
	bin := filepath.Join(os.TempDir(), "chronos-api-protocolit-"+hh.suffix)
	build := exec.Command("go", "build", "-o", bin, "./cmd/api")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		return fmt.Errorf("building cmd/api: %w\n%s", err, out)
	}

	cmd := exec.Command(bin)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), flatten(env)...)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return fmt.Errorf("starting cmd/api: %w", err)
	}
	go func() {
		s := bufio.NewScanner(stdout)
		s.Buffer(make([]byte, 0, 64*1024), 1<<20)
		for s.Scan() {
			hh.logMu.Lock()
			hh.serverLog.WriteString(s.Text())
			hh.serverLog.WriteByte('\n')
			hh.logMu.Unlock()
		}
	}()
	hh.stopServer = func() {
		_ = cmd.Process.Signal(os.Interrupt)
		done := make(chan struct{})
		go func() { _, _ = cmd.Process.Wait(); close(done) }()
		select {
		case <-done:
		case <-time.After(10 * time.Second):
			_ = cmd.Process.Kill()
		}
		_ = os.Remove(bin)
	}

	deadline := time.Now().Add(90 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := hh.http.Get(hh.baseURL + "/readyz")
		if err == nil {
			_, _ = io.Copy(io.Discard, resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
		}
		time.Sleep(250 * time.Millisecond)
	}
	return fmt.Errorf("cmd/api never became ready\n--- server log ---\n%s", hh.serverLogs())
}

func (hh *harness) serverLogs() string {
	hh.logMu.Lock()
	defer hh.logMu.Unlock()
	return hh.serverLog.String()
}

var closeOnce sync.Once

func (hh *harness) close() {
	closeOnce.Do(func() {
		if hh.cancelProjectors != nil {
			hh.cancelProjectors()
			<-hh.projectorsDone
		}
		if hh.stopServer != nil {
			hh.stopServer()
		}
		if hh.pool != nil {
			hh.pool.Close()
		}
	})
}

// ---------------------------------------------------------------------------
// projectors
// ---------------------------------------------------------------------------

// startProjectors runs every projection cmd/projector runs.
//
// It does NOT wait for the leases, and that is the difference from identityit's
// harness. A projection is global: whichever process holds the lease applies
// every event in the log, including this package's. So if another integration
// package is already projecting, these runners stand by and the read model still
// advances — and every wait in this package is on the row appearing, which is
// true in both cases. Requiring ownership here would turn "somebody else is
// already doing the work correctly" into a failed run.
func (hh *harness) startProjectors() {
	ctx, cancel := context.WithCancel(context.Background())
	hh.cancelProjectors = cancel

	views := []projection.Projection{
		notificationprojection.NewFeed(hh.codec),
		notificationprojection.NewPushSubscriptions(hh.codec),
		notificationprojection.NewPreferences(hh.codec),
		profileprojection.NewProfile(hh.codec),
		// Organization's two: gate 3 reads the first on every request, and gate 1
		// verifies membership against the second.
		organizationprojection.NewStatus(hh.codec),
		workspaceprojection.NewOrgMembers(hh.codec),
		workspaceprojection.NewMembers(hh.codec),
		identityprojection.NewUser(hh.codec),
		identityprojection.NewSession(hh.codec),
		identityprojection.NewReservation(hh.codec),
	}
	done := make(chan struct{})
	hh.projectorsDone = done

	deps := projection.Deps{
		Subscriber:     hh.store,
		Codec:          hh.codec,
		Categories:     hh.store,
		Types:          hh.store,
		Batch:          hh.pg,
		TX:             hh.pg,
		Checkpoints:    pgadapter.Checkpoints{},
		Lease:          pgadapter.NewLease(hh.pool),
		Clock:          clock.System{},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Holder:         "protocolit-" + hh.suffix,
		LeaseRetry:     50 * time.Millisecond,
		SubscribeRetry: 50 * time.Millisecond,
	}

	var wg sync.WaitGroup
	for _, v := range views {
		wg.Add(1)
		go func(v projection.Projection) {
			defer wg.Done()
			_ = projection.NewRunner(v, deps).Run(ctx)
		}(v)
	}
	go func() { wg.Wait(); close(done) }()
}

// ---------------------------------------------------------------------------
// the two account fixtures
// ---------------------------------------------------------------------------

// buildAccounts creates the package's two accounts over the PUBLIC API.
//
// Every step but one is an HTTP call through the production handlers. The
// exception is the verification token: the server mails it, this process has no
// mailbox, and there is deliberately no RPC that hands one out — so the token is
// minted through the same guard table the server reads it from. That is one
// out-of-band write, and it is the only one in this package.
func (hh *harness) buildAccounts() error {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	active, err := hh.newVerifiedAccount(ctx, "active")
	if err != nil {
		return fmt.Errorf("building the active account: %w", err)
	}
	if err := hh.enrolAndActivate(ctx, active); err != nil {
		return fmt.Errorf("enrolling the active account: %w", err)
	}
	hh.active = active

	boot, err := hh.newVerifiedAccount(ctx, "boot")
	if err != nil {
		return fmt.Errorf("building the bootstrap account: %w", err)
	}
	hh.bootstrap = boot
	return nil
}

// newVerifiedAccount registers, verifies and signs in — leaving an account with
// a password, no second factor, and an AAL1 bootstrap session.
func (hh *harness) newVerifiedAccount(ctx context.Context, tag string) (*accountFixture, error) {
	a := &accountFixture{
		email:    hh.freshEmail(tag),
		username: hh.freshUsername(),
		password: "correct-horse-battery-staple-" + hh.suffix,
	}

	// PUBLIC mutations carry an Idempotency-Key too. The gate pipeline returns
	// before gate 5 for a public method, so the header is enforced a second time
	// inside the handler (identity/api.idempotencyKey). The published OpenAPI
	// spec used to document the parameter on none of them, which meant a
	// generated client could not register anyone; it now documents all twenty
	// mutations, and TestTheOpenAPISpecDocumentsTheIdempotencyKeyOnEveryMutation
	// is what keeps it that way.
	if _, err := hh.identity.Register(ctx,
		authed(&identityv1.RegisterRequest{Email: a.email}, "")); err != nil {
		return nil, fmt.Errorf("Register: %w\n%s", err, hh.serverLogs())
	}

	index, err := hh.emailIndex(a.email)
	if err != nil {
		return nil, err
	}
	row, err := hh.awaitAccount(ctx, index)
	if err != nil {
		return nil, err
	}
	a.subjectID, a.userID = row.subjectID, row.userID

	tok, err := hh.mintVerificationToken(ctx, a.subjectID)
	if err != nil {
		return nil, err
	}
	if _, err := hh.identity.VerifyEmail(ctx,
		authed(&identityv1.VerifyEmailRequest{
			Token: tok, Password: a.password, Username: a.username,
		}, "")); err != nil {
		return nil, fmt.Errorf("VerifyEmail: %w\n%s", err, hh.serverLogs())
	}
	if err := hh.awaitState(ctx, index, func(r accountRow) bool { return r.verified }); err != nil {
		return nil, fmt.Errorf("waiting for the address to be verified: %w", err)
	}

	session, err := hh.identity.CreateSession(ctx,
		authed(&identityv1.CreateSessionRequest{
			Identifier: a.email, Password: a.password,
			DeviceId: "dev_" + tag + "_" + hh.suffix,
		}, ""))
	if err != nil {
		return nil, fmt.Errorf("CreateSession (bootstrap): %w\n%s", err, hh.serverLogs())
	}
	if got := session.Msg.GetAssuranceLevel(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		return nil, fmt.Errorf("a password-only session came back at %v, want AAL1", got)
	}
	a.bearer, a.sessionID = session.Msg.GetToken(), session.Msg.GetSessionId()
	if err := hh.awaitSessionProjected(ctx, a.sessionID); err != nil {
		return nil, err
	}
	return a, nil
}

// enrolAndActivate takes a verified account through TOTP enrolment and signs it
// back in at AAL2.
func (hh *harness) enrolAndActivate(ctx context.Context, a *accountFixture) error {
	enrolled, err := hh.identity.EnrollTotp(ctx,
		authed(&identityv1.EnrollTotpRequest{}, a.bearer))
	if err != nil {
		return fmt.Errorf("EnrollTotp: %w\n%s", err, hh.serverLogs())
	}
	secret, err := secretFromURI(enrolled.Msg.GetProvisioningUri())
	if err != nil {
		return err
	}
	a.secret = secret

	code, err := hh.freshCode(ctx, secret)
	if err != nil {
		return err
	}
	confirmed, err := hh.identity.ConfirmTotp(ctx,
		authed(&identityv1.ConfirmTotpRequest{Code: code}, a.bearer))
	if err != nil {
		return fmt.Errorf("ConfirmTotp: %w\n%s", err, hh.serverLogs())
	}
	if !confirmed.Msg.GetActivated() {
		return fmt.Errorf("confirming a TOTP factor on a verified account did not activate it")
	}
	return hh.reSignIn(ctx, a)
}

// disposableAccount returns a fresh, fully-activated AAL2 account that the
// caller is free to DESTROY.
//
// # Why this exists
//
// Ten RPCs had no happy path asserted anywhere in this package, and the reason
// was the same for most of them: `DeactivateAccount`, `RequestAccountDeletion`
// and `RevokeAllSessions` end the account or its sessions, so calling one on the
// shared fixture breaks every test that runs after it — and the order those run
// in is not fixed. The gap was therefore not an oversight but a missing
// primitive, and this is the primitive.
//
// Each call is a genuinely separate subject: its own address, its own handle,
// its own TOTP secret and its own AAL2 session. Destroying it affects nothing
// else, so a destructive RPC can be driven to SUCCESS rather than only to its
// refusals.
//
// It costs a registration, a verification, an enrolment and two sign-ins, which
// is why it is a per-test helper and not the default bearer.
func (hh *harness) disposableAccount(t *testing.T, tag string) *accountFixture {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	a, err := hh.newVerifiedAccount(ctx, tag)
	if err != nil {
		t.Fatalf("building a disposable account (%s): %v", tag, err)
	}
	if err := hh.enrolAndActivate(ctx, a); err != nil {
		t.Fatalf("activating the disposable account (%s): %v", tag, err)
	}
	return a
}

// bootstrapAccount returns a fresh VERIFIED account that has no second factor.
//
// The distinction from disposableAccount is the whole point: an account that has
// not yet enrolled is the only state in which `EnrollTotp` and `ConfirmTotp` can
// be driven through their real success path, because both are the bootstrap
// itself. Enrolling first would leave nothing to enrol.
func (hh *harness) bootstrapAccount(t *testing.T, tag string) *accountFixture {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 120*time.Second)
	defer cancel()

	a, err := hh.newVerifiedAccount(ctx, tag)
	if err != nil {
		t.Fatalf("building a bootstrap account (%s): %v", tag, err)
	}
	return a
}

// mintResetToken issues a password-reset token for a subject.
//
// Production mints this inside the reset reactor and delivers it by mail; a test
// that waited for the mail would be asserting the mail adapter. The token is
// minted through the SAME token.New() and guards.Issue() the server uses, so
// what is short-circuited is the delivery, not the credential — a token this
// produces is indistinguishable from a real one to everything downstream.
//
// Mirrors mintVerificationToken, including reading the SERVER's clock rather
// than the test process's: a token minted against wall time while the server sat
// at an advanced clock would arrive already expired (ADR-054).
func (hh *harness) mintResetToken(ctx context.Context, subjectID string) (string, error) {
	now, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return "", err
	}
	minted, err := token.New().Mint(app.PurposePasswordReset, now.now)
	if err != nil {
		return "", fmt.Errorf("minting a reset token: %w", err)
	}
	if err := hh.guards.Issue(ctx, app.PurposePasswordReset,
		subjectID, minted.Digest, minted.ExpiresAt); err != nil {
		return "", fmt.Errorf("issuing a reset token: %w", err)
	}
	return minted.Plaintext, nil
}

// seedNotification creates one unread notification and returns its id.
//
// # Why it appends an EVENT rather than a feed row
//
// The first version of this wrote straight into notification_feed, and the
// server refused the resulting MarkNotificationsRead with `internal`. It was
// right to. app/inbox.go appends the read event with
// `Expected: eventsourcing.StreamExists()` and says why: "a read event on a
// stream with no created event is a fact about nothing". A hand-written feed row
// is exactly that — the answer without the fact — which is the one thing this
// codebase does not allow anywhere, and contract.NotificationCreated states the
// same rule from the other side: "The in-app delivery IS this event. The feed
// table is a projection built from it, so nothing writes that table directly."
//
// So the fixture appends the event the reactor would have appended and waits for
// the feed projector to catch up. What is short-circuited is the DECISION to
// notify — which belongs to another module and would drag its whole pipeline
// into an idempotency test — and not the record of it.
func (hh *harness) seedNotification(t *testing.T, subjectID, orgID string) string {
	t.Helper()

	ctx, cancel := context.WithTimeout(t.Context(), 60*time.Second)
	defer cancel()

	// ids.New carries its own prefix — ids.Notification{}.Prefix() is "notif" —
	// so concatenating one produces "notif_evt_…", which the published pattern
	// `^notif_[0-7][0-9A-HJKMNP-TV-Z]{25}$` duly refuses.
	id := ids.New[ids.Notification](time.Now(), ids.Entropy()).String()

	stream, err := eventsourcing.NewStreamID(notificationdomain.Category, id)
	if err != nil {
		t.Fatalf("seeding a notification: stream id: %v", err)
	}

	now, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		t.Fatalf("seeding a notification: reading the server clock: %v", err)
	}

	// `security`, because it is the one class no preference can switch off — the
	// fixture must not depend on whatever the account's preferences happen to be.
	if _, err := hh.store.Append(ctx, stream, eventsourcing.NoStream(),
		[]eventsourcing.PendingEvent{{
			ID: ids.New[ids.Event](time.Now(), ids.Entropy()),
			Event: &notificationcontract.NotificationCreated{
				NotificationID: id,
				SubjectID:      subjectID,
				Template:       "identity.account_deletion_requested",
				Class:          "security",
				OrgID:          orgID,
				OccurredAt:     now.now,
			},
			Meta: eventsourcing.Metadata{OrgID: orgID, OccurredAt: now.now},
		}}); err != nil {
		t.Fatalf("seeding a notification: append: %v", err)
	}

	// Wait for the PROJECTOR, not for a sleep: the feed row is what
	// MarkNotificationsRead's ownership check reads, and it does not exist until
	// the projection catches up.
	if err := hh.await(ctx, 30*time.Second, "the notification feed projection",
		func() (bool, error) {
			return hh.feedRowExists(ctx, id, orgID)
		}); err != nil {
		t.Fatalf("seeding a notification: the feed projection never produced %s: %v", id, err)
	}
	return id
}

// feedRowExists reads notification_feed under the org scope RLS demands.
func (hh *harness) feedRowExists(ctx context.Context, notificationID, orgID string) (bool, error) {
	tx, err := hh.pool.Begin(ctx)
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(ctx) }()

	// notification_feed carries `CREATE POLICY tenant_isolation ... USING (org_id
	// = current_setting('app.org_id', true))`, so an unscoped read returns
	// nothing and would look like "not projected yet" forever.
	if _, err := tx.Exec(ctx, `SELECT set_config('app.org_id', $1, true)`, orgID); err != nil {
		return false, err
	}
	var n int
	if err := tx.QueryRow(ctx,
		`SELECT count(*) FROM notification_feed WHERE notification_id = $1`,
		notificationID).Scan(&n); err != nil {
		return false, err
	}
	return n > 0, nil
}

// reSignIn establishes a fresh AAL2 session for an enrolled account.
func (hh *harness) reSignIn(ctx context.Context, a *accountFixture) error {
	code, err := hh.freshCode(ctx, a.secret)
	if err != nil {
		return err
	}
	res, err := hh.identity.CreateSession(ctx,
		authed(&identityv1.CreateSessionRequest{
			Identifier: a.email, Password: a.password, Code: code,
			DeviceId: "dev_aal2_" + hh.suffix,
		}, ""))
	if err != nil {
		return fmt.Errorf("CreateSession (AAL2): %w\n%s", err, hh.serverLogs())
	}
	if got := res.Msg.GetAssuranceLevel(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2 {
		return fmt.Errorf("a password+code session came back at %v, want AAL2", got)
	}
	a.bearer, a.sessionID = res.Msg.GetToken(), res.Msg.GetSessionId()
	return hh.awaitSessionProjected(ctx, a.sessionID)
}

// activeBearer returns a LIVE bearer token for the active account.
//
// Lazy rather than cached-once because the movable clock is global and
// forward-only: one test advances it past the 14-day idle window to prove an
// expired session is refused, and that expires every other session in the
// package along with it. Re-establishing on demand makes the suite
// order-independent, which is the property that stops "which file did the
// clock test end up in" from deciding whether the rest passes.
//
// The liveness probe is GetUser, which is also the cheapest assertion available
// that the session still resolves.
func (hh *harness) activeBearer(t *testing.T) string {
	t.Helper()
	hh.bearerMu.Lock()
	defer hh.bearerMu.Unlock()

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	_, err := hh.identity.GetUser(ctx,
		authed(&identityv1.GetUserRequest{}, hh.active.bearer))
	if err == nil {
		return hh.active.bearer
	}
	if connectrpc.CodeOf(err) != connectrpc.CodeUnauthenticated {
		t.Fatalf("probing the active session returned %v, which is neither success nor an "+
			"expired session: %v", connectrpc.CodeOf(err), err)
	}
	if err := hh.reSignIn(ctx, hh.active); err != nil {
		t.Fatalf("re-establishing the active session: %v", err)
	}
	return hh.active.bearer
}

// bootstrapBearer returns a LIVE AAL1 bearer for the bootstrap account.
//
// Lazy for the same reason activeBearer is: the clock is global and one test
// pushes it past the idle window. The account has no second factor, so a
// password-only CreateSession re-establishes it at exactly AAL1 — which is the
// property every step-up assertion in this package depends on.
func (hh *harness) bootstrapBearer(t *testing.T) string {
	t.Helper()
	hh.bearerMu.Lock()
	defer hh.bearerMu.Unlock()

	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	_, err := hh.identity.GetUser(ctx,
		authed(&identityv1.GetUserRequest{}, hh.bootstrap.bearer))
	if err == nil {
		return hh.bootstrap.bearer
	}
	if connectrpc.CodeOf(err) != connectrpc.CodeUnauthenticated {
		t.Fatalf("probing the bootstrap session returned %v: %v", connectrpc.CodeOf(err), err)
	}
	res, err := hh.identity.CreateSession(ctx,
		authed(&identityv1.CreateSessionRequest{
			Identifier: hh.bootstrap.email, Password: hh.bootstrap.password,
			DeviceId: "dev_boot2_" + hh.suffix,
		}, ""))
	if err != nil {
		t.Fatalf("re-establishing the bootstrap session: %v\n%s", err, hh.serverLogs())
	}
	if got := res.Msg.GetAssuranceLevel(); got != optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1 {
		t.Fatalf("the bootstrap account signed in at %v, want AAL1; it must have no second "+
			"factor for the step-up assertions in this package to mean anything", got)
	}
	hh.bootstrap.bearer, hh.bootstrap.sessionID = res.Msg.GetToken(), res.Msg.GetSessionId()
	if err := hh.awaitSessionProjected(ctx, hh.bootstrap.sessionID); err != nil {
		t.Fatalf("%v", err)
	}
	return hh.bootstrap.bearer
}

// ---------------------------------------------------------------------------
// request helpers
// ---------------------------------------------------------------------------

// authed builds an authenticated request carrying a fresh idempotency key.
//
// One helper rather than the read/write pair identityit uses, because the key is
// ignored on a read (gate 5 passes reads straight through) and sending it
// anyway is exactly what a real client library does.
// keyless builds a request with a bearer and DELIBERATELY no Idempotency-Key.
//
// authed() always sets one — which is right for almost every call in this
// package and wrong for the one property that needs the header absent. Reaching
// for authed() there does not fail loudly: the request simply carries a key, the
// mutation EXECUTES, and a test written to observe a refusal instead observes a
// success it caused. That happened while
// TestEveryMutationRefusesIdenticallyOverEveryProtocol was being written, and it
// ran RevokeAllSessions against the shared fixture six times before the
// discrepancy between two methods and the other eighteen gave it away.
func keyless[T any](msg *T, bearer string) *connectrpc.Request[T] {
	req := connectrpc.NewRequest(msg)
	if bearer != "" {
		req.Header().Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	return req
}

func authed[T any](msg *T, bearer string) *connectrpc.Request[T] {
	req := connectrpc.NewRequest(msg)
	req.Header().Set(interceptor.IdempotencyHeader, newIdempotencyKey())
	if bearer != "" {
		req.Header().Set(interceptor.AuthorizationHeader, "Bearer "+bearer)
	}
	return req
}

func newIdempotencyKey() string {
	return "idem_" + ids.New[ids.Event](time.Now(), ids.Entropy()).String()
}

// clientFor returns an HTTP client that speaks exactly one HTTP version.
//
// Pinned rather than negotiated, because "the server answers gRPC" is a claim
// about h2c and a client that quietly fell back to HTTP/1.1 would prove
// something else. h2c has no ALPN to negotiate over plaintext, so
// SetUnencryptedHTTP2 is what makes the prior-knowledge upgrade happen.
func clientFor(h2 bool) *http.Client {
	tr := &http.Transport{}
	var p http.Protocols
	if h2 {
		p.SetUnencryptedHTTP2(true)
	} else {
		p.SetHTTP1(true)
	}
	tr.Protocols = &p
	return &http.Client{Transport: tr, Timeout: 60 * time.Second}
}

// ---------------------------------------------------------------------------
// waiting for the read model
// ---------------------------------------------------------------------------

type accountRow struct {
	subjectID string
	userID    string
	state     string
	verified  bool
}

func (hh *harness) emailIndex(email string) (string, error) {
	normalized, err := domain.NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	idx, err := hh.index.Of(normalized)
	if err != nil {
		return "", fmt.Errorf("blind index: %w", err)
	}
	return string(idx), nil
}

func (hh *harness) awaitAccount(ctx context.Context, index string) (accountRow, error) {
	var out accountRow
	err := hh.await(ctx, 30*time.Second, "the account projection", func() (bool, error) {
		row, found, err := hh.accountRow(ctx, index)
		if err != nil || !found {
			return false, err
		}
		out = row
		return true, nil
	})
	return out, err
}

func (hh *harness) awaitState(
	ctx context.Context, index string, want func(accountRow) bool,
) error {
	return hh.await(ctx, 30*time.Second, "the account projection", func() (bool, error) {
		row, found, err := hh.accountRow(ctx, index)
		if err != nil || !found {
			return false, err
		}
		return want(row), nil
	})
}

func (hh *harness) accountRow(ctx context.Context, index string) (accountRow, bool, error) {
	var row accountRow
	found := false
	err := hh.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// `email_released_at IS NULL` mirrors the production lookup: an address
		// can have been held by one account and then another, and a query without
		// it returns whichever row the planner reached first.
		err := q.QueryRow(ctx, `
			SELECT subject_id, user_id, state, email_verified
			FROM user_view WHERE email_index = $1 AND email_released_at IS NULL`, index).
			Scan(&row.subjectID, &row.userID, &row.state, &row.verified)
		if err != nil {
			if strings.Contains(err.Error(), "no rows") {
				return nil
			}
			return err
		}
		found = true
		return nil
	})
	return row, found, err
}

// awaitSessionProjected blocks until the session the API just minted resolves.
//
// A session has two halves written by two different things: CreateSession
// appends SessionCreated and writes session_token itself, while session_view is
// written by the identity_session projector, and migration 00010 made resolution
// require both. Between the call returning and the projector catching up, the
// bearer token authenticates NOTHING — and the refusal is
// `unauthenticated: authentication failed`, which reads exactly like a broken
// credential.
func (hh *harness) awaitSessionProjected(ctx context.Context, sessionID string) error {
	return hh.await(ctx, 30*time.Second,
		fmt.Sprintf("session %s to become resolvable", sessionID), func() (bool, error) {
			var n int
			err := hh.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
				return q.QueryRow(ctx,
					`SELECT count(*) FROM session_view WHERE session_id = $1`, sessionID).Scan(&n)
			})
			return n > 0, err
		})
}

func (hh *harness) await(
	ctx context.Context, budget time.Duration, what string, done func() (bool, error),
) error {
	deadline := time.Now().Add(budget)
	for {
		ok, err := done()
		if err != nil {
			return fmt.Errorf("waiting for %s: %w", what, err)
		}
		if ok {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("waited %s for %s and it never happened", budget, what)
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
}

// mintVerificationToken issues a verification token through the same guard
// table the server reads it from.
//
// Against the SERVER's clock, not this process's: the expiry is written here and
// compared there, so minting against wall time while the server runs ahead
// silently shortens the TTL by however far the suite has travelled.
func (hh *harness) mintVerificationToken(ctx context.Context, subjectID string) (string, error) {
	now, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return "", err
	}
	minted, err := token.New().Mint(app.PurposeEmailVerification, now.now)
	if err != nil {
		return "", fmt.Errorf("minting a verification token: %w", err)
	}
	if err := hh.guards.Issue(ctx, app.PurposeEmailVerification,
		subjectID, minted.Digest, minted.ExpiresAt); err != nil {
		return "", fmt.Errorf("issuing a verification token: %w", err)
	}
	return minted.Plaintext, nil
}

// ---------------------------------------------------------------------------
// TOTP
// ---------------------------------------------------------------------------

// totpPeriod is RFC 6238's step, in seconds. Not imported from the totp adapter
// on purpose: a test that derived the period from the code under test would
// agree with it about a wrong value.
const totpPeriod = 30

// totpBoundaryMargin is how much of a step must remain for a code to be worth
// minting. A code generated in the last moment of a step can arrive in the next.
const totpBoundaryMargin = 3

// maxStepJumps bounds the loop in freshCode, so a clock that answers but does
// not move turns a failing fixture into an error rather than a hung suite.
const maxStepJumps = 8

var (
	usedStepsMu sync.Mutex
	usedSteps   = map[string]bool{}
)

// freshCode returns a TOTP code the server will accept, TRAVELLING through the
// step boundary rather than waiting for it (ADR-054).
//
// The replay guard is keyed on (credential, step) and fails closed, so there is
// no way to get a second valid code for one authenticator inside one step. The
// step is thirty seconds of the SERVER's clock, and the clock control is what
// makes those thirty seconds cost a millisecond of loopback HTTP.
func (hh *harness) freshCode(ctx context.Context, secret string) (string, error) {
	usedStepsMu.Lock()
	defer usedStepsMu.Unlock()

	reading, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return "", err
	}
	now := reading.now
	for range maxStepJumps {
		step := now.Unix() / totpPeriod
		key := secret + ":" + strconv.FormatInt(step, 10)
		remaining := totpPeriod - (now.Unix() % totpPeriod)
		if !usedSteps[key] && remaining > totpBoundaryMargin {
			usedSteps[key] = true
			return totp.GenerateCode(secret, now)
		}
		advanced, err := hh.clockState(ctx, http.MethodPost, fmt.Sprintf(
			"%s/debug/clock/advance?by=%ds", hh.clockURL, remaining+1))
		if err != nil {
			return "", fmt.Errorf("advancing past a spent TOTP step: %w", err)
		}
		now = advanced.now
	}
	return "", fmt.Errorf("could not find an unspent TOTP step in %d jumps; the clock "+
		"control is answering but not moving", maxStepJumps)
}

// secretFromURI reads the secret out of the provisioning URI, which is what an
// authenticator app scans. A URI with the wrong secret, algorithm or digit count
// produces codes the server rejects.
func secretFromURI(uri string) (string, error) {
	key, err := otp.NewKeyFromURL(uri)
	if err != nil {
		return "", fmt.Errorf("parsing the provisioning URI %q: %w", uri, err)
	}
	return key.Secret(), nil
}

// ---------------------------------------------------------------------------
// the movable clock (ADR-054)
// ---------------------------------------------------------------------------

type clockReading struct {
	offset time.Duration
	now    time.Time
}

// verifyClockControl proves the control is REACHABLE before any test relies on
// it, and asserts its one security property: it refuses to move backwards.
func (hh *harness) verifyClockControl(ctx context.Context) error {
	before, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return fmt.Errorf("the movable clock is unreachable at %s, so every TOTP step "+
			"boundary in this package would be waited out in real time: %w\n"+
			"--- server log ---\n%s", hh.clockURL, err, hh.serverLogs())
	}
	if _, err := hh.clockState(ctx, http.MethodPost,
		hh.clockURL+"/debug/clock/advance?by=-1s"); err == nil {
		return errors.New("the movable clock accepted a NEGATIVE advance: it can be " +
			"rewound, which un-expires tokens and steps back into TOTP steps whose codes " +
			"have already been observed")
	}
	after, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return err
	}
	if after.offset != before.offset {
		return fmt.Errorf("a refused advance still moved the clock: offset went from %s to %s",
			before.offset, after.offset)
	}
	return nil
}

func (hh *harness) clockState(ctx context.Context, method, url string) (clockReading, error) {
	req, err := http.NewRequestWithContext(ctx, method, url, nil)
	if err != nil {
		return clockReading{}, err
	}
	resp, err := hh.http.Do(req)
	if err != nil {
		return clockReading{}, err
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return clockReading{}, err
	}
	if resp.StatusCode != http.StatusOK {
		return clockReading{}, fmt.Errorf("%s %s: %s: %s",
			method, url, resp.Status, strings.TrimSpace(string(body)))
	}

	var out clockReading
	for line := range strings.SplitSeq(string(body), "\n") {
		k, v, ok := strings.Cut(strings.TrimSpace(line), "=")
		if !ok {
			continue
		}
		switch k {
		case "offset":
			if out.offset, err = time.ParseDuration(v); err != nil {
				return clockReading{}, fmt.Errorf("offset %q: %w", v, err)
			}
		case "now":
			if out.now, err = time.Parse(time.RFC3339Nano, v); err != nil {
				return clockReading{}, fmt.Errorf("now %q: %w", v, err)
			}
		}
	}
	if out.now.IsZero() {
		return clockReading{}, fmt.Errorf("the clock control returned no instant: %q", body)
	}
	return clockReading{offset: out.offset, now: out.now.UTC()}, nil
}

// advanceServerClock pushes the server's clock forward. The server experiences
// the duration as elapsed: a session may now be idle-expired, a token may now be
// past its expiry. It only ever moves forward.
func (hh *harness) advanceServerClock(t *testing.T, d time.Duration) {
	t.Helper()
	if _, err := hh.clockState(t.Context(), http.MethodPost,
		fmt.Sprintf("%s/debug/clock/advance?by=%s", hh.clockURL, d)); err != nil {
		t.Fatalf("advancing the server's clock by %s: %v", d, err)
	}
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

// freshEmail is unique per run AND per call, so no two accounts in the package
// contend for one address.
func (hh *harness) freshEmail(tag string) string {
	return fmt.Sprintf("pt.%s.%s.%s@example.test", tag, hh.suffix, randomTag())
}

// freshUsername stays inside the 30-character ceiling identity.proto declares,
// which the tag plus the run suffix plus a per-call tag does not.
// freshSlug is unique per run AND per call, so no two organizations in the
// package contend for one URL name unless a test means them to.
func (hh *harness) freshSlug() string {
	return "org-" + strings.ToLower(hh.suffix) + "-" + strings.ToLower(randomTag())
}

func (hh *harness) freshUsername() string {
	return fmt.Sprintf("pt_%s_%s", hh.suffix, randomTag())
}

func randomTag() string {
	var b [4]byte
	if _, err := io.ReadFull(rand.Reader, b[:]); err != nil {
		panic(err)
	}
	return hex.EncodeToString(b[:])
}

func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", errors.New("no go.mod above the working directory")
		}
		dir = parent
	}
}

// loadDotEnv reads the committed local-stack configuration, so a credential
// mismatch shows up as a failure to connect rather than as a silently different
// database.
func loadDotEnv(path string) (map[string]string, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}
	env := map[string]string{}
	for line := range strings.SplitSeq(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		k, v, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		env[strings.TrimSpace(k)] = strings.Trim(strings.TrimSpace(v), `"`)
	}
	return env, nil
}

func envOr(env map[string]string, key, def string) string {
	if v := env[key]; v != "" {
		return v
	}
	return def
}

func flatten(env map[string]string) []string {
	out := make([]string, 0, len(env))
	for k, v := range env {
		out = append(out, k+"="+v)
	}
	return out
}

func randomKeyHex() (string, error) {
	var k [32]byte
	if _, err := io.ReadFull(rand.Reader, k[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(k[:]), nil
}

func freePort() (int, error) {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port, nil
}
