//go:build integration

// Package identityit holds the end-to-end proof of the identity slice.
//
// Everything below this package has unit tests and adapter tests. Nothing had
// ever run as a whole: a registration that reaches KurrentDB, becomes a
// user_view row through a real projector, is verified, enrols a second factor,
// authenticates, mints a bearer token, and has that token accepted and then
// refused by the real interceptor stack. Each of those steps is owned by a
// different package, and the seams between them are exactly where this
// repository has repeatedly found code that was built, tested, and connected to
// nothing.
//
// # What "the real stack" means here, and where it falls short
//
// The composition root — newDependencies, startIdentity, startGates,
// registerServices, handlerOptions — is unexported and lives in `package main`
// under cmd/api. It is unreachable from any other package, so an httptest
// server cannot be built over it without adding a file to cmd/api.
//
// Rather than hand-assemble a parallel stack (which would prove the wrong
// thing: a test over a graph that differs from production tells you about the
// test's graph), this harness COMPILES AND RUNS cmd/api itself and speaks to it
// over TCP with the generated Connect client. Every interceptor, every gate,
// every policy annotation and every adapter is the production one, constructed
// by the production code, in the order production constructs it. The only
// difference from a deployed server is that the process is a child of the test
// and its environment is written by the test.
//
// Two things the real deployment would supply are supplied here instead:
//
//   - The PROJECTORS. cmd/projector is a separate binary and is not running in
//     the local stack. Identity's read model is what `Authenticate` resolves an
//     identifier against, so nothing authenticates until the projections run.
//     They are driven here from the same `identity/projection` constructors and
//     the same `platform/projection` runner cmd/projector uses.
//   - Two workarounds for production defects this test found. Both are
//     documented at the point of use, and both are marked so that fixing the
//     defect makes the workaround dead rather than making the test lie.
package identityit_test

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
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/chronos/chronos-go/gen/proto/chronos/identity/v1/identityv1connect"
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	"github.com/chronos/chronos-go/internal/adapter/piivault"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/argon2id"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/blindindex"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totp"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/totpseal"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/kurrent-io/KurrentDB-Client-Go/kurrentdb"
	"github.com/valkey-io/valkey-go"
)

// ---------------------------------------------------------------------------
// package-level fixture
// ---------------------------------------------------------------------------

// h is the one harness for the package. A single API process and a single set
// of projectors are shared by every test, because starting cmd/api costs a
// compile plus a boot, and because the projections are global objects — three
// tests each running their own `identity_user` projector would contend on one
// advisory lease and prove nothing about any of them.
//
// Test isolation comes from the KEY MATERIAL instead. Every run generates its
// own blind-index key, so every address this run registers hashes into an index
// space no other run — and no earlier run's leftover rows — can collide with.
// That is what makes "exactly one registration wins" a statement about this
// run's concurrency rather than about the state of a shared database.
var h *harness

type harness struct {
	suffix  string
	baseURL string
	client  identityv1connect.IdentityServiceClient
	http    *http.Client

	// clockURL is cmd/api's movable-clock control (ADR-054), on its own loopback
	// listener and never on baseURL.
	//
	// It is what makes this package finish in a minute instead of four. Almost
	// every rule identity enforces is derived from the server's clock, and the
	// one this suite collides with constantly is RFC 6238's thirty-second step:
	// the replay guard is keyed on (credential, step) and fails closed, so a
	// test needing a second code for one authenticator cannot have one until the
	// step rolls over. It used to buy that by sleeping. It now buys it by
	// pushing the server's clock forward, which is the same event without the
	// wall-clock cost.
	//
	// The control only moves FORWARD, so nothing here can rewind into a spent
	// step, un-expire a token or restore a lockout. See internal/platform/clock.
	clockURL string

	pool  *pgxpool.Pool
	pg    *pgadapter.DB
	store *kurrentadapter.Store
	codec *eventcodec.JSON

	// kurrent is the raw client behind store, kept for the one thing the port
	// does not expose: reading $all between two positions. A property about how
	// many accounts exist for an address cannot be asked of one stream, and it
	// must not be asked of a projection — see accountsRegisteredFor.
	kurrent *kurrentdb.Client

	index  *blindindex.Index
	guards *identitypg.Guards

	// secondFactor is the production use case, constructed in-process. The
	// scenario no longer needs it — enrolment now runs over HTTP through the
	// bootstrap session (bootstrapFirstFactor) — so it remains only for tests
	// that need to reach the use case without a session at all.
	secondFactor *app.SecondFactor

	// The kernel-path account fixture's dependencies. See
	// registerThroughTheKernel for why an account has to be creatable by a route
	// other than the public one.
	hasher          *argon2id.Hasher
	vault           *piivault.Vault
	userRepo        *eventsourcing.Repository[*domain.User]
	reservationRepo *eventsourcing.Repository[*domain.EmailReservation]

	// usernameRepo writes the public handle's reservation stream. Used by exactly
	// one test, for the one transition that has no producer yet: the tombstone.
	usernameRepo *eventsourcing.Repository[*domain.UsernameReservation]

	// projectors is the running set, and cancelProjectors stops them. The
	// rebuild property needs them stopped, because Rebuild takes the same lease.
	cancelProjectors context.CancelFunc
	projectorsDone   chan struct{}

	// leases is the ONE thing the projection runner does not report: whether
	// this process actually became the single writer. See leaseWatch.
	leases *leaseWatch

	serverLog  *strings.Builder
	logMu      sync.Mutex
	stopServer func()
}

func TestMain(m *testing.M) {
	code, err := runMain(m)
	if err != nil {
		fmt.Fprintf(os.Stderr, "identityit: %v\n", err)
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
// when it returns.
//
// `go test` enforces its -timeout by sending SIGQUIT, and a signalled process
// runs no deferred function: without this, a suite that times out — or a Ctrl-C
// — leaves the cmd/api child running with nothing left to reap it. That orphan
// keeps a Postgres pool, a KurrentDB subscription and a listening socket, and it
// accumulates one copy per aborted run.
//
// The returned function unregisters the handler; it is deliberately NOT the
// teardown, so the ordinary path still closes through the defer above and closes
// exactly once (harness.close is idempotent for that reason).
func (hh *harness) closeOnSignal() func() {
	ch := make(chan os.Signal, 1)
	signal.Notify(ch, os.Interrupt, syscall.SIGTERM, syscall.SIGQUIT)
	go func() {
		sig, ok := <-ch
		if !ok {
			return
		}
		fmt.Fprintf(os.Stderr, "identityit: %v — tearing down the harness\n", sig)
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

	// Per-run key material. The blind-index key in particular MUST be shared
	// between the server and this test: the test resolves an address to its
	// account by computing the same index the server computed, which is the only
	// way to find a row for an address that appears in no column anywhere.
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
	// The clock control gets its own port, picked here rather than left at the
	// config default of :0, because the alternative is scraping the resolved
	// address out of the server's startup log — and a harness that parses a log
	// line to find a control surface silently loses the control the day the line
	// is reworded.
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
	env["IDENTITY_TOTP_ISSUER"] = "ChronosIT"
	env["API_PORT"] = fmt.Sprint(port)
	env["CLOCK_CONTROL_ENABLED"] = "true"
	env["CLOCK_CONTROL_ADDR"] = fmt.Sprintf("127.0.0.1:%d", clockPort)

	hh := &harness{
		suffix:    suffix,
		baseURL:   fmt.Sprintf("http://127.0.0.1:%d", port),
		clockURL:  fmt.Sprintf("http://127.0.0.1:%d", clockPort),
		http:      &http.Client{Timeout: 60 * time.Second},
		serverLog: &strings.Builder{},
	}
	hh.client = identityv1connect.NewIdentityServiceClient(hh.http, hh.baseURL)

	if err := hh.dialInfra(env, indexKey, sealKey, pepperKey); err != nil {
		return nil, err
	}
	// BEFORE the server starts, so nothing this run does is measured against a
	// budget a previous run spent. See protocolit's copy for the whole argument;
	// the short version is that every test here calls from 127.0.0.1, so the
	// suite shares one per-caller bucket and the daily ones do not refill within
	// a working day.
	if err := resetPerCallerLimits(env); err != nil {
		return nil, err
	}
	if err := hh.startServer(root, env); err != nil {
		return nil, err
	}
	if err := hh.verifyClockControl(); err != nil {
		hh.close()
		return nil, err
	}
	if err := hh.startProjectors(); err != nil {
		hh.close()
		return nil, err
	}
	return hh, nil
}

// dialInfra opens the test's own connections to Postgres and KurrentDB.
//
// These are for OBSERVATION and for the two out-of-band fixtures, never for
// driving the scenario: every step of the scenario goes over HTTP to the server
// process. A test that wrote its own rows would be asserting against its own
// work.
func (hh *harness) dialInfra(env map[string]string, indexKeyHex, sealKeyHex, pepperKeyHex string) error {
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

	upcasters := eventsourcing.NewUpcasterRegistry()
	identity.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	identity.RegisterEvents(codec)
	hh.codec = codec

	client, err := kurrentadapter.Dial(
		envOr(env, "KURRENTDB_CONNECTION_STRING", "kurrentdb://localhost:2113?tls=false"))
	if err != nil {
		return fmt.Errorf("kurrentdb: %w", err)
	}
	hh.store = kurrentadapter.NewStore(client, codec)
	hh.kurrent = client

	indexKey, err := hex.DecodeString(indexKeyHex)
	if err != nil {
		return err
	}
	if hh.index, err = blindindex.New(indexKey); err != nil {
		return fmt.Errorf("blind index: %w", err)
	}
	if hh.guards, err = identitypg.NewGuards(hh.pg); err != nil {
		return fmt.Errorf("guards: %w", err)
	}

	// The in-process second-factor use case. Built from the same constructors
	// cmd/api uses, with the same key material, so the sealed secret it writes
	// is one the server can open.
	sealBytes, err := hex.DecodeString(sealKeyHex)
	if err != nil {
		return err
	}
	sealKeys, err := totpseal.NewKeys(map[int][]byte{1: sealBytes}, 1)
	if err != nil {
		return fmt.Errorf("totp seal keys: %w", err)
	}
	sealer, err := totpseal.New(sealKeys)
	if err != nil {
		return fmt.Errorf("totp sealer: %w", err)
	}
	secrets, err := identitypg.NewSecondFactors(hh.pg)
	if err != nil {
		return fmt.Errorf("second factors: %w", err)
	}
	authenticator, err := totp.New("ChronosIT", hh.guards)
	if err != nil {
		return fmt.Errorf("totp: %w", err)
	}
	users := eventsourcing.NewRepository[*domain.User](
		hh.store, codec, upcasters, app.UserCategory, domain.New)
	sf, err := app.NewSecondFactor(app.SecondFactorDeps{
		Clock:    clock.System{},
		Entropy:  rand.Reader,
		Users:    users,
		Appender: hh.store,
		Enroll: app.TotpEnroller(func(accountName string) (app.TotpEnrollment, error) {
			e, err := authenticator.Enroll(accountName)
			if err != nil {
				return app.TotpEnrollment{}, err
			}
			return app.TotpEnrollment{Secret: e.Secret, URI: e.URI}, nil
		}),
		Sealer:   sealer,
		Secrets:  secrets,
		Verifier: authenticator,
		Recovery: secrets,
		// The same registry the server passes. Without it this out-of-band service
		// writes events at schema version 0 — which is the production bug the
		// scenario exists to catch, reproduced inside the test itself and therefore
		// indistinguishable from it.
		Schemas: upcasters,
		Log:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		return fmt.Errorf("second factor use case: %w", err)
	}
	hh.secondFactor = sf

	return hh.buildKernelFixtures(pepperKeyHex,
		envOr(env, "OPENBAO_ADDR", "http://localhost:8200"),
		env["OPENBAO_DEV_TOKEN"],
		envOr(env, "OPENBAO_KEK_NAME", "chronos-kek"),
		upcasters)
}

// startServer compiles and runs cmd/api.
//
// `go build` rather than `go run`, so the process this test signals is the
// server itself and not a wrapper that would leave it orphaned.
func (hh *harness) startServer(root string, env map[string]string) error {
	bin := filepath.Join(os.TempDir(), "chronos-api-identityit-"+hh.suffix)
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
			body, _ := io.ReadAll(resp.Body)
			_ = resp.Body.Close()
			if resp.StatusCode == http.StatusOK {
				return nil
			}
			_ = body
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

// closeOnce guards close, which is now reachable from two places: the ordinary
// defer in runMain and the signal handler. Killing the child twice is harmless;
// closing the pool twice is not.
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

// startProjectors runs identity's three projections exactly as cmd/projector
// does.
//
// They are not optional scaffolding. `Authenticate` resolves an identifier by
// reading user_view, and `VerifyEmail` resolves a subject to a user id the same
// way — so with no projector running, a registration succeeds in the log and
// every subsequent call behaves as if the account does not exist. That is worth
// stating plainly: in the local stack as shipped, cmd/api alone serves an
// identity API in which nothing that was registered can ever be found.
func (hh *harness) startProjectors() error {
	ctx, cancel := context.WithCancel(context.Background())
	hh.cancelProjectors = cancel

	views := []projection.Projection{
		identityprojection.NewUser(hh.codec),
		identityprojection.NewSession(hh.codec),
		identityprojection.NewReservation(hh.codec),
	}
	done := make(chan struct{})
	hh.projectorsDone = done
	hh.leases = newLeaseWatch(pgadapter.NewLease(hh.pool))

	var wg sync.WaitGroup
	for _, v := range views {
		wg.Add(1)
		go func(v projection.Projection) {
			defer wg.Done()
			_ = projection.NewRunner(v, hh.projectionDeps()).Run(ctx)
		}(v)
	}
	go func() { wg.Wait(); close(done) }()

	names := make([]string, 0, len(views))
	for _, v := range views {
		names = append(names, v.Name())
	}
	return hh.awaitLeases(names)
}

// awaitLeases blocks until this process holds every projection's lease, and
// FAILS THE RUN if it does not.
//
// This is the guard for the failure that invalidated a whole mutation pass. A
// runner that loses the lease race becomes a STANDBY: it logs at DEBUG, retries
// forever, and reports nothing to its caller — so a projector that never
// acquired anything is indistinguishable, from inside this package, from one
// that is merely idle. Every assertion here then reads rows that some OTHER
// process is advancing, most often a leaked test binary from an earlier run
// that is running unmutated code. A mutation asserted against that projection
// reads as CAUGHT while nothing caught it, which is the worst answer a mutation
// pass can produce: it is silently wrong in the direction of "all clear".
//
// 60 seconds because the acquisition is a single pg_try_advisory_lock issued as
// the runner's first act; anything approaching that budget is contention, not
// slowness.
func (hh *harness) awaitLeases(names []string) error {
	deadline := time.Now().Add(60 * time.Second)
	for {
		missing := hh.leases.missing(names)
		if len(missing) == 0 {
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf(
				"this run never became the single writer for %v: something else holds those "+
					"projection advisory leases. The usual cause is a leaked identityit.test "+
					"binary from an earlier run — check `ps` — and the consequence is that "+
					"every assertion in this package would have been served by a projector "+
					"this run does not control", missing)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func (hh *harness) projectionDeps() projection.Deps {
	return projection.Deps{
		Subscriber:     hh.store,
		Codec:          hh.codec,
		Categories:     hh.store,
		Types:          hh.store,
		Batch:          hh.pg,
		TX:             hh.pg,
		Checkpoints:    pgadapter.Checkpoints{},
		Lease:          hh.leases,
		Clock:          clock.System{},
		Log:            slog.New(slog.NewTextHandler(io.Discard, nil)),
		Holder:         "identityit-" + hh.suffix,
		LeaseRetry:     50 * time.Millisecond,
		SubscribeRetry: 50 * time.Millisecond,
	}
}

// leaseWatch is postgres.Lease plus a record of which names this process won.
//
// It changes nothing about the mutual exclusion — every call goes straight
// through — and exists only because projection.Lease.Acquire's held=false is
// swallowed by the runner's retry loop. See awaitLeases for why that silence is
// dangerous here specifically.
type leaseWatch struct {
	inner projection.Lease
	mu    sync.Mutex
	held  map[string]bool
}

func newLeaseWatch(inner projection.Lease) *leaseWatch {
	return &leaseWatch{inner: inner, held: map[string]bool{}}
}

func (l *leaseWatch) Acquire(
	ctx context.Context, name string,
) (projection.Release, bool, error) {
	rel, held, err := l.inner.Acquire(ctx, name)
	if held {
		l.mu.Lock()
		l.held[name] = true
		l.mu.Unlock()
	}
	return rel, held, err
}

// missing reports which of names this process has never held.
func (l *leaseWatch) missing(names []string) []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, n := range names {
		if !l.held[n] {
			out = append(out, n)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// small helpers
// ---------------------------------------------------------------------------

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

// loadDotEnv reads the committed local-stack configuration. The test does not
// invent credentials: it uses the ones the running stack was started with, so a
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
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

// ---------------------------------------------------------------------------
// the movable clock (ADR-054)
// ---------------------------------------------------------------------------

// verifyClockControl proves the control is REACHABLE before any test relies on it.
//
// Checked once, at startup, and it fails the whole run rather than one test.
// The failure it exists for is the quiet one: a server that came up without the
// control — a renamed variable, a validation that now refuses the address, a
// port something else took — answers `connection refused` to every advance.
// Each individual test would then fail somewhere else entirely, on a TOTP code
// the server rejects, and the cause would be four layers away from the message.
//
// It also asserts the control's ONE security property while it is here: an
// attempt to move the clock backwards is refused. That is not decoration. It is
// the property that keeps time travel from becoming a way to un-expire a token
// or step back into a spent TOTP step, and this is the only place in the suite
// where anything tries it.
func (hh *harness) verifyClockControl() error {
	before, err := hh.clockState(http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return fmt.Errorf("the movable clock is unreachable at %s, so every TOTP step "+
			"boundary in this package would be waited out in real time and several tests "+
			"would fail on a code the server considers stale: %w\n--- server log ---\n%s",
			hh.clockURL, err, hh.serverLogs())
	}

	// Backwards is refused. A control that accepted it would let this suite
	// rewind into a step whose code it has already spent, and the replay guard —
	// which is the whole reason a second code costs thirty seconds — would be
	// the only thing left standing between a test and a replayed credential.
	if _, err := hh.clockState(http.MethodPost,
		hh.clockURL+"/debug/clock/advance?by=-1s"); err == nil {
		return errors.New("the movable clock accepted a NEGATIVE advance: it can be " +
			"rewound, which un-expires tokens, restores elapsed lockouts and steps back " +
			"into TOTP steps whose codes have already been observed")
	}

	after, err := hh.clockState(http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		return err
	}
	if after.offset != before.offset {
		return fmt.Errorf("a refused advance still moved the clock: offset went from %s "+
			"to %s", before.offset, after.offset)
	}
	return nil
}

// clockReading is what the control reports: how far ahead of the wall clock the
// server is, and what instant it therefore believes it is.
type clockReading struct {
	offset time.Duration
	now    time.Time
}

// clockState calls the control and parses its two-line reply.
//
// A non-2xx is an error carrying the body, because the body is the refusal's
// reason and discarding it turns "by=-1s would move it backwards" into "400".
func (hh *harness) clockState(method, url string) (clockReading, error) {
	req, err := http.NewRequestWithContext(context.Background(), method, url, nil)
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

// serverNow is what the SERVER thinks the time is, which is the only clock that
// decides whether a TOTP code validates.
//
// Asked rather than computed. The test process could add the last known offset
// to its own time.Now, and it would be right until the moment another parallel
// test advanced the clock between the two reads — at which point it would mint
// a code for a step the server has already left, and the failure would read as
// a broken authenticator.
func (hh *harness) serverNow(t *testing.T) time.Time {
	t.Helper()
	r, err := hh.clockState(http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		t.Fatalf("reading the server's clock: %v", err)
	}
	return r.now
}

// advanceServerClock pushes the server's clock forward and returns its new now.
//
// This is the replacement for a sleep, and it is exactly as strong: the server
// experiences the duration as elapsed. Every rule derived from the clock is
// enforced on the far side of it — a session may now be idle-expired, a token
// may now be past its expiry, an attempt ceiling's window may have rolled. That
// is what time passing means, and it is why the control is refused outside
// local rather than merely discouraged.
func (hh *harness) advanceServerClock(t *testing.T, d time.Duration) time.Time {
	t.Helper()
	r, err := hh.clockState(http.MethodPost,
		fmt.Sprintf("%s/debug/clock/advance?by=%s", hh.clockURL, d))
	if err != nil {
		t.Fatalf("advancing the server's clock by %s: %v", d, err)
	}
	return r.now
}

// systemQuery runs a read through the SYSTEM transaction, which is identity's
// only access path: its tables carry no RLS and there is no workspace to scope
// them by (IDENTITY-SLICE-1).
func (hh *harness) systemQuery(t *testing.T, scan func(context.Context, db.Querier) error) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err := hh.pg.InSystemTx(ctx, scan); err != nil {
		t.Fatalf("system query: %v", err)
	}
}

// ---------------------------------------------------------------------------
// reading the log, which is the only place uniqueness is decided
// ---------------------------------------------------------------------------

// logTail reports the position just past the end of $all.
//
// Taken BEFORE the work under test so accountsRegisteredFor reads exactly that
// work and nothing else: a window of "the last N events" is not a stable amount
// of history, because creating a stream also writes the server's own index
// entries.
func (hh *harness) logTail(t *testing.T) kurrentdb.AllPosition {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Backwards, From: kurrentdb.End{},
	}, 1)
	if err != nil {
		t.Fatalf("reading the tail of $all: %v", err)
	}
	defer rs.Close()
	ev, err := rs.Recv()
	if errors.Is(err, io.EOF) {
		return kurrentdb.Start{}
	}
	if err != nil {
		t.Fatalf("reading the tail of $all: %v", err)
	}
	return kurrentdb.Position{Commit: ev.Event.Position.Commit, Prepare: ev.Event.Position.Prepare}
}

// accountsRegisteredFor returns the subject of every account the LOG says was
// registered with this email index, in commit order.
//
// This exists because the obvious question — "how many accounts hold this
// address?" — has been asked of user_view, and user_view is the one place that
// cannot answer it. Its email_index carried a bare UNIQUE constraint, so a
// second account for one address did not appear as a second row: the INSERT was
// refused, the identity projector stopped, and `SELECT count(*)` kept returning
// 1. An assertion on that count measured the projection's ability to hide the
// duplicate. The constraint is now partial (migration 00014) and the count would
// be honest — but a projection is still derived, still behind, and still able to
// filter, so the assertion belongs here regardless.
//
// $all rather than $et-identity.UserRegistered.v1, and the difference matters
// for a test that runs immediately after the write: $all is the log itself and
// is consistent the moment the append returns, while a $et- link stream is
// produced by a system projection that can lag.
func (hh *harness) accountsRegisteredFor(
	t *testing.T, index string, from kurrentdb.AllPosition,
) []string {
	t.Helper()
	rs, err := hh.kurrent.ReadAll(context.Background(), kurrentdb.ReadAllOptions{
		Direction: kurrentdb.Forwards, From: from,
	}, ^uint64(0))
	if err != nil {
		t.Fatalf("reading $all: %v", err)
	}
	defer rs.Close()

	registered := new(contract.UserRegistered)
	var subjects []string
	for {
		ev, err := rs.Recv()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			t.Fatalf("reading $all: %v", err)
		}
		if ev.Event == nil || ev.Event.EventType != registered.EventType() {
			continue
		}
		decoded, err := hh.codec.Unmarshal(ev.Event.EventType, ev.Event.Data)
		if err != nil {
			t.Fatalf("decoding %s at %s: %v", ev.Event.EventType, ev.Event.StreamID, err)
		}
		e, ok := decoded.(*contract.UserRegistered)
		if !ok {
			t.Fatalf("%s decoded as %T", ev.Event.EventType, decoded)
		}
		if string(e.EmailIndex) == index {
			subjects = append(subjects, e.SubjectID)
		}
	}
	return subjects
}

// resetPerCallerLimits clears the per-IP counters this suite spends.
//
// The same reset protocolit performs, and for the same reason: several rate
// limits are scoped to the CALLER's address, every test here calls from
// 127.0.0.1, and the daily ones do not refill within a working day. Without it
// the second or third full run fails with RATE_LIMITED in tests that have
// nothing to do with rate limiting.
//
// The limits themselves are NOT raised for tests. They are security controls
// whose numbers cmd/api/identity.go argues against specific attacks, and a knob
// that relaxes them is a knob that can relax them in production. Clearing a
// counter changes no behaviour; raising a ceiling changes what is permitted.
//
// clearCallerCeiling in resend_integration_test.go stays. It clears the same
// keys mid-test, immediately before measuring a ceiling — this one only
// guarantees the run STARTS clean, and a test that spends the budget itself
// still has to reset before it counts.
func resetPerCallerLimits(env map[string]string) error {
	addr := envOr(env, "VALKEY_ADDR", "localhost:6379")
	client, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{addr},
		Password:     env["VALKEY_PASSWORD"],
		DisableCache: true,
	})
	if err != nil {
		return fmt.Errorf("dialling valkey at %s to reset the rate-limit counters: %w",
			addr, err)
	}
	defer client.Close()

	ctx := context.Background()
	for _, pattern := range []string{"mail_address:*", "mail_caller:*", "username_check:*", "authn:*"} {
		keys, err := client.Do(ctx, client.B().Keys().Pattern(pattern).Build()).AsStrSlice()
		if err != nil {
			return fmt.Errorf("listing %s: %w", pattern, err)
		}
		if len(keys) == 0 {
			continue
		}
		if err := client.Do(ctx, client.B().Del().Key(keys...).Build()).Error(); err != nil {
			return fmt.Errorf("clearing %s: %w", pattern, err)
		}
	}
	return nil
}
