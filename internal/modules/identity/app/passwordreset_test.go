package app

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// journal records the order of the reset's destructive steps.
//
// It has its OWN lock, and that is the point rather than an oversight corrected
// later: three different fakes write to it, each holding its own mutex, so a
// bare slice is written concurrently under three unrelated locks. The race
// detector found exactly that during `make check` — under `-race`, with two
// concurrent resets in flight — and the failure was in the test's bookkeeping,
// which is the worst kind: it hides a real finding behind a fake one.
type journal struct {
	mu    sync.Mutex
	steps []string
}

func (j *journal) record(step string) {
	if j == nil {
		return
	}
	j.mu.Lock()
	defer j.mu.Unlock()
	j.steps = append(j.steps, step)
}

func (j *journal) recorded() []string {
	j.mu.Lock()
	defer j.mu.Unlock()
	return append([]string(nil), j.steps...)
}

// resetCredentials is the credential table with the ONE property the reset
// depends on: Replace is a compare-and-set.
//
// It is a real map guarded by a mutex rather than a stub that always succeeds,
// because the property under test is what happens when two callers reach it at
// once. A stub that returned nil would make TestTwoConcurrentResets pass while
// the production statement had lost its WHERE clause — which is exactly the
// mutation this file has to catch.
type resetCredentials struct {
	mu sync.Mutex

	// rows is keyed by subject, mirroring the partial unique index that permits
	// one usable password per subject.
	rows map[string]PasswordCredential

	findErr    error
	replaceErr error

	// journal records the order of the destructive calls, shared with the token
	// store and the revoker. The ordering claim in Complete's doc — revoke first,
	// replace last — is a claim about sequence, and no per-call assertion can see
	// it.
	journal *journal
}

func newResetCredentials(journal *journal) *resetCredentials {
	return &resetCredentials{rows: map[string]PasswordCredential{}, journal: journal}
}

func (c *resetCredentials) put(cred PasswordCredential) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.rows[cred.SubjectID] = cred
}

func (c *resetCredentials) verifier(subjectID string) string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.rows[subjectID].Verifier
}

func (c *resetCredentials) Find(_ context.Context, subjectID string) (PasswordCredential, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.findErr != nil {
		return PasswordCredential{}, c.findErr
	}
	row, ok := c.rows[subjectID]
	if !ok {
		return PasswordCredential{}, ErrNoPasswordCredential
	}
	return row, nil
}

func (c *resetCredentials) Replace(
	_ context.Context, cred ids.CredentialID, expected, replacement string, pepperVersion int32,
) error {
	c.journal.record("replace")
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.replaceErr != nil {
		return c.replaceErr
	}
	for subject, row := range c.rows {
		if row.ID != cred {
			continue
		}
		// The compare-and-set. This single line is the whole reason two
		// simultaneous resets cannot both land.
		if row.Verifier != expected {
			return ErrCredentialMoved
		}
		row.Verifier = replacement
		row.PepperVersion = pepperVersion
		row.Failures = 0
		c.rows[subject] = row
		return nil
	}
	return ErrCredentialMoved
}

// The rest of the port is unreachable from a reset. Each fails loudly rather
// than returning a zero value, so a handler that started calling one is caught
// here instead of silently writing a credential nobody asked it to.
func (c *resetCredentials) Store(context.Context, NewPasswordCredential) error {
	return errors.New("a reset must not create a credential")
}

func (c *resetCredentials) StoreFirst(context.Context, NewPasswordCredential) error {
	return errors.New("a reset must not create an account's first credential")
}

func (c *resetCredentials) Rehash(context.Context, ids.CredentialID, string, string, int32) error {
	return errors.New("not used by a reset")
}

func (c *resetCredentials) RecordSuccess(context.Context, ids.CredentialID) error {
	return errors.New("not used by a reset")
}

func (c *resetCredentials) RecordFailure(context.Context, ids.CredentialID) (int32, error) {
	return 0, errors.New("not used by a reset")
}

func (c *resetCredentials) Disable(context.Context, ids.CredentialID) error {
	return errors.New("a reset must not disable an authenticator")
}

// resetTokens is liveTokens with the cross-purpose sweep implemented, so a test
// can prove that redeeming a reset kills an outstanding VERIFICATION link too.
type resetTokens struct {
	mu       sync.Mutex
	inner    *liveTokens
	journal  *journal
	sweeps   int
	sweepErr error
}

func newResetTokens(journal *journal) *resetTokens {
	return &resetTokens{inner: newLiveTokens(), journal: journal}
}

func (s *resetTokens) Issue(
	ctx context.Context, purpose TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Issue(ctx, purpose, subjectID, digest, expiresAt)
}

func (s *resetTokens) Consume(
	ctx context.Context, purpose TokenPurpose, digest []byte, now time.Time,
) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.Consume(ctx, purpose, digest, now)
}

func (s *resetTokens) RevokeAll(ctx context.Context, purpose TokenPurpose, subjectID string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.inner.RevokeAll(ctx, purpose, subjectID)
}

func (s *resetTokens) RevokeAllPurposes(_ context.Context, subjectID string) (int, error) {
	s.journal.record("revoke-tokens")
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sweeps++
	if s.sweepErr != nil {
		return 0, s.sweepErr
	}
	n := 0
	for k, row := range s.inner.rows {
		if row.subjectID == subjectID {
			delete(s.inner.rows, k)
			n++
		}
	}
	return n, nil
}

// liveFor reports every purpose the subject still holds a redeemable token for.
func (s *resetTokens) liveFor(subjectID string, now time.Time) []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []string
	for k, row := range s.inner.rows {
		if row.subjectID == subjectID && row.expiresAt.After(now) {
			purpose, _, _ := strings.Cut(k, "|")
			out = append(out, purpose)
		}
	}
	return out
}

// journallingRevoker is fakeRevoker with a shared ordering journal and a
// configurable count, so a test can assert BOTH that sessions were voided and
// that they were voided before the credential moved.
type journallingRevoker struct {
	mu      sync.Mutex
	calls   []RevokeAllSessionsCommand
	revoked int
	err     error
	journal *journal
}

func (r *journallingRevoker) RevokeAllSessions(
	_ context.Context, cmd RevokeAllSessionsCommand,
) (RevokeAllSessionsResult, error) {
	r.journal.record("revoke-sessions")
	r.mu.Lock()
	defer r.mu.Unlock()
	r.calls = append(r.calls, cmd)
	if r.err != nil {
		return RevokeAllSessionsResult{}, r.err
	}
	return RevokeAllSessionsResult{Revoked: r.revoked, Scanned: r.revoked}, nil
}

func (r *journallingRevoker) commands() []RevokeAllSessionsCommand {
	r.mu.Lock()
	defer r.mu.Unlock()
	return append([]RevokeAllSessionsCommand(nil), r.calls...)
}

// racingAppender fails its first n appends with ErrWrongExpectedRevision.
//
// It reproduces the one race the reset cannot answer by giving up: a login
// appending an authenticator lockout or a rehash to the SAME account stream
// (app.Authentication does both) between this command's load and its append. By
// then the verifier has already been replaced, so an append that surrendered
// would leave a credential the log does not explain.
type racingAppender struct {
	mu       sync.Mutex
	failures int
	inner    *syncAppender
}

func (a *racingAppender) AppendToMany(
	ctx context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	a.mu.Lock()
	fail := a.failures > 0
	if fail {
		a.failures--
	}
	a.mu.Unlock()
	if fail {
		return nil, eventsourcing.ErrWrongExpectedRevision
	}
	return a.inner.AppendToMany(ctx, appends)
}

// syncAppender serialises access to fakeAppender's slice.
//
// The concurrency tests below run two Complete calls at once, and fakeAppender
// records every call in an unguarded slice. Without this the race detector fires
// on the TEST's bookkeeping rather than on anything under test, which is the
// worst kind of flake: it hides a real finding behind a fake one.
type syncAppender struct {
	mu    sync.Mutex
	inner *fakeAppender
}

func (a *syncAppender) AppendToMany(
	ctx context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.inner.AppendToMany(ctx, appends)
}

func (a *syncAppender) snapshot() [][]eventsourcing.StreamAppend {
	a.mu.Lock()
	defer a.mu.Unlock()
	return append([][]eventsourcing.StreamAppend(nil), a.inner.calls...)
}

// resetBreach is fakeBreach with a lock, for the same reason syncAppender exists.
type resetBreach struct {
	mu       sync.Mutex
	breached bool
	corpus   string
	err      error
}

func (b *resetBreach) Breached(context.Context, string) (bool, string, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.breached, b.corpus, b.err
}

func (b *resetBreach) set(breached bool, corpus string, err error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	b.breached, b.corpus, b.err = breached, corpus, err
}

// resetHasher is fakeHasher with a lock, for the same reason syncAppender exists.
type resetHasher struct {
	mu    sync.Mutex
	calls int
	seen  []string
	err   error
}

func (h *resetHasher) Hash(
	_ context.Context, password string, _ ids.UserID, _ ids.CredentialID,
) (string, error) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.calls++
	h.seen = append(h.seen, password)
	if h.err != nil {
		return "", h.err
	}
	return "$argon2id$fake$" + hex.EncodeToString([]byte(password)), nil
}

func (h *resetHasher) Verify(
	context.Context, string, string, ids.UserID, ids.CredentialID,
) (bool, error) {
	return false, errors.New("a reset never verifies a password")
}

func (h *resetHasher) NeedsRehash(string) bool { return false }
func (h *resetHasher) PepperVersion() int32    { return 3 }

func (h *resetHasher) hashed() (int, []string) {
	h.mu.Lock()
	defer h.mu.Unlock()
	return h.calls, append([]string(nil), h.seen...)
}

// resetVerifierFor is what resetHasher produces for a password, so a test can
// name the expected stored value instead of matching a substring.
func resetVerifierFor(password string) string {
	return "$argon2id$fake$" + hex.EncodeToString([]byte(password))
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const (
	resetEmail       = "Reset+User@Example.COM"
	resetOldPassword = "the-old-passphrase"
	resetNewPassword = "a-brand-new-passphrase"
)

type resetHarness struct {
	t *testing.T

	indexer   fakeIndexer
	directory *resendDirectory
	subjects  fakeDirectory
	appender  eventsourcing.MultiAppender
	recorder  *syncAppender
	schemas   *eventsourcing.UpcasterRegistry
	counter   *memoryCounter
	breach    *resetBreach
	hasher    *resetHasher
	creds     *resetCredentials
	tokens    *resetTokens
	revoker   *journallingRevoker
	journal   *journal
	calls     []string
	logs      *bytes.Buffer

	// user is the account every assertion is made against, and by default it is
	// also the instance the loader hands back.
	//
	// userFn overrides that with a BUILDER, which the concurrency tests set: two
	// Complete calls at once would otherwise record onto one shared aggregate,
	// which races on the uncommitted buffer and is not what production does —
	// eventsourcing.Repository rebuilds a fresh aggregate on every Load.
	user         *domain.User
	userFn       func() *domain.User
	credentialID ids.CredentialID
	loadErr      error
	loads        atomic.Int64

	addressRules []ratelimit.Rule
	callerRules  []ratelimit.Rule
}

func newResetHarness(t *testing.T) *resetHarness {
	t.Helper()
	h := &resetHarness{
		t:         t,
		directory: &resendDirectory{},
		recorder:  &syncAppender{inner: &fakeAppender{}},
		schemas:   identitySchemas(),
		counter:   newMemoryCounter(),
		breach:    &resetBreach{},
		hasher:    &resetHasher{},
		// Deliberately generous, so a test that is not about the ceiling never
		// trips it by accident. The ceiling tests narrow them.
		addressRules: []ratelimit.Rule{{Name: "hourly", Limit: 1000, Window: time.Hour}},
		callerRules:  []ratelimit.Rule{{Name: "hourly", Limit: 1000, Window: time.Hour}},
	}
	h.appender = h.recorder
	h.journal = &journal{}
	h.creds = newResetCredentials(h.journal)
	h.tokens = newResetTokens(h.journal)
	h.revoker = &journallingRevoker{journal: h.journal, revoked: 2}
	h.user = h.verifiedUserWithPassword()
	h.directory.account = Account{UserID: h.user.ID(), SubjectID: h.user.SubjectID()}
	h.subjects = fakeDirectory{user: h.user.ID(), only: h.user.SubjectID()}
	h.creds.put(PasswordCredential{
		ID:            h.credentialID,
		SubjectID:     h.user.SubjectID(),
		Verifier:      "$argon2id$fake$old",
		PepperVersion: 3,
		Failures:      4,
		EnabledAt:     testNow,
	})
	return h
}

func (h *resetHarness) index(email string) contract.EmailIndex {
	h.t.Helper()
	idx, err := h.indexer.Of(email)
	if err != nil {
		h.t.Fatalf("deriving the test index: %v", err)
	}
	return idx
}

// verifiedUserWithPassword is the state a reset is FOR: an account that proved
// its address and has a usable password. Positioned as if loaded from its
// stream, so ExpectedFor reports a revision rather than NoStream.
func (h *resetHarness) verifiedUserWithPassword() *domain.User {
	h.t.Helper()
	userID := ids.New[ids.User](testNow, &fixedEntropy{})
	subjectID := ids.New[ids.Subject](testNow, &fixedEntropy{b: 99}).String()
	h.credentialID = ids.New[ids.Credential](testNow, &fixedEntropy{b: 7})
	return mustVerifiedUser(userID, subjectID, h.index(resetEmail), h.credentialID)
}

// mustVerifiedUser builds a verified account with a usable password.
//
// It PANICS rather than calling t.Fatalf, because the concurrency tests call it
// from goroutines the testing package does not permit Fatalf from — and a
// fixture that cannot be built is a broken test either way.
func mustVerifiedUser(
	userID ids.UserID, subjectID string, index contract.EmailIndex, credentialID ids.CredentialID,
) *domain.User {
	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, subjectID, index, testNow); err != nil {
		panic("fixture: registering: " + err.Error())
	}
	if err := user.VerifyEmail(index, testNow); err != nil {
		panic("fixture: verifying: " + err.Error())
	}
	if err := user.SetPassword(credentialID, testNow); err != nil {
		panic("fixture: setting the first password: " + err.Error())
	}
	user.ClearUncommitted()
	return user
}

func (h *resetHarness) build() *PasswordReset {
	h.t.Helper()
	addr, err := ratelimit.New(h.counter, "test_addr", h.addressRules...)
	if err != nil {
		h.t.Fatalf("building the address ceiling: %v", err)
	}
	caller, err := ratelimit.New(h.counter, "test_caller", h.callerRules...)
	if err != nil {
		h.t.Fatalf("building the caller ceiling: %v", err)
	}
	var log *slog.Logger
	if h.logs != nil {
		log = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	r, err := NewPasswordReset(PasswordResetDeps{
		Clock:     clock.NewFixed(testNow),
		Index:     h.indexer,
		Directory: h.directory,
		Subjects:  h.subjects,
		Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
			h.loads.Add(1)
			if h.loadErr != nil {
				return nil, h.loadErr
			}
			if h.userFn != nil {
				return h.userFn(), nil
			}
			return h.user, nil
		}),
		Appender:       h.appender,
		Schemas:        h.schemas,
		AddressLimiter: recordingLimiter{inner: addr, log: &h.calls, label: "address"},
		CallerLimiter:  recordingLimiter{inner: caller, log: &h.calls, label: "caller"},
		TokenTTL:       time.Hour,
		Breach:         h.breach,
		Hasher:         h.hasher,
		Credentials:    h.creds,
		Tokens:         h.tokens,
		Digest:         testDigest,
		Revocations:    h.revoker,
		Log:            log,
	})
	if err != nil {
		h.t.Fatalf("wiring the reset: %v", err)
	}
	return r
}

func (h *resetHarness) request(email string) (RequestPasswordResetResult, error) {
	h.t.Helper()
	return h.build().Request(context.Background(), RequestPasswordResetCommand{
		Email:          email,
		CallerScope:    "198.51.100.9",
		IdempotencyKey: "idem-reset-request-1",
	})
}

// issue puts a redeemable reset token in the store and returns its plaintext,
// exactly as the reset-mail issuer would.
func (h *resetHarness) issue(plaintext string) string {
	h.t.Helper()
	if err := h.tokens.Issue(context.Background(), PurposePasswordReset,
		h.user.SubjectID(), testDigest(PurposePasswordReset, plaintext),
		testNow.Add(time.Hour)); err != nil {
		h.t.Fatalf("issuing a reset token: %v", err)
	}
	return plaintext
}

func (h *resetHarness) complete(token, password string) (ResetPasswordResult, error) {
	h.t.Helper()
	return h.build().Complete(context.Background(), ResetPasswordCommand{
		Token:          token,
		Password:       password,
		IdempotencyKey: "idem-reset-complete-1",
	})
}

// appended returns every event the appender saw, flattened.
func (h *resetHarness) appended() []eventsourcing.Event {
	h.t.Helper()
	var out []eventsourcing.Event
	for _, call := range h.recorder.snapshot() {
		for _, stream := range call {
			for _, e := range stream.Events {
				out = append(out, e.Event)
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// A nil dependency must be refused at construction. Two of them — the ceilings
// and the revoker — have no runtime symptom at all when missing: the reset still
// succeeds, and what is absent is an anti-abuse control and the entire point of
// §4.5.
func TestNewPasswordResetRefusesAMissingDependency(t *testing.T) {
	t.Parallel()

	limiter, err := ratelimit.New(newMemoryCounter(), "p",
		ratelimit.Rule{Name: "hourly", Limit: 3, Window: time.Hour})
	if err != nil {
		t.Fatalf("building a limiter: %v", err)
	}
	users := loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
		return nil, nil
	})
	full := func() PasswordResetDeps {
		return PasswordResetDeps{
			Clock:          clock.NewFixed(testNow),
			Index:          fakeIndexer{},
			Directory:      &resendDirectory{},
			Subjects:       fakeDirectory{},
			Users:          users,
			Appender:       &fakeAppender{},
			Schemas:        identitySchemas(),
			AddressLimiter: limiter,
			CallerLimiter:  limiter,
			TokenTTL:       time.Hour,
			Breach:         &resetBreach{},
			Hasher:         &resetHasher{},
			Credentials:    newResetCredentials(nil),
			Tokens:         newResetTokens(nil),
			Digest:         testDigest,
			Revocations:    &journallingRevoker{},
		}
	}

	tests := map[string]func(*PasswordResetDeps){
		"no clock":            func(d *PasswordResetDeps) { d.Clock = nil },
		"no indexer":          func(d *PasswordResetDeps) { d.Index = nil },
		"no account lookup":   func(d *PasswordResetDeps) { d.Directory = nil },
		"no subject lookup":   func(d *PasswordResetDeps) { d.Subjects = nil },
		"no user loader":      func(d *PasswordResetDeps) { d.Users = nil },
		"no appender":         func(d *PasswordResetDeps) { d.Appender = nil },
		"no address ceiling":  func(d *PasswordResetDeps) { d.AddressLimiter = nil },
		"no caller ceiling":   func(d *PasswordResetDeps) { d.CallerLimiter = nil },
		"no token lifetime":   func(d *PasswordResetDeps) { d.TokenTTL = 0 },
		"no breach checker":   func(d *PasswordResetDeps) { d.Breach = nil },
		"no hasher":           func(d *PasswordResetDeps) { d.Hasher = nil },
		"no credential store": func(d *PasswordResetDeps) { d.Credentials = nil },
		"no token store":      func(d *PasswordResetDeps) { d.Tokens = nil },
		"no digest function":  func(d *PasswordResetDeps) { d.Digest = nil },
		"no session revoker":  func(d *PasswordResetDeps) { d.Revocations = nil },
		"a zero pepper version": func(d *PasswordResetDeps) {
			d.Hasher = zeroPepperHasher{PasswordHasher: &resetHasher{}}
		},
	}
	for name, remove := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			deps := full()
			remove(&deps)
			reset, err := NewPasswordReset(deps)
			if err == nil {
				t.Fatalf("NewPasswordReset accepted a reset with %s", name)
			}
			if reset != nil {
				t.Fatalf("NewPasswordReset returned a value alongside an error: %#v", reset)
			}
			if !strings.Contains(err.Error(), "identity/app") {
				t.Fatalf("the error does not name the package: %v", err)
			}
		})
	}

	t.Run("a complete set is accepted", func(t *testing.T) {
		t.Parallel()
		if _, err := NewPasswordReset(full()); err != nil {
			t.Fatalf("NewPasswordReset refused a complete set: %v", err)
		}
	})
}

// ---------------------------------------------------------------------------
// Requesting a link — enumeration
// ---------------------------------------------------------------------------

// Every account state answers a reset request the same way, and only one of them
// appends anything.
//
// The response-level proof lives over HTTP (identityit), where the bytes on the
// wire are compared. What this asserts is the half a byte comparison cannot see:
// that four of the five branches perform NO WRITE. A handler that answered
// identically and then mailed a suspended account would pass a byte comparison
// and be a mail-bombing primitive aimed at the one population that cannot
// complain about it.
func TestAResetRequestAnswersEveryAccountStateTheSameWay(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		arrange func(*resetHarness)
		want    ResetOutcome
		appends bool
	}{
		"no account claims the address": {
			arrange: func(h *resetHarness) { h.directory.err = ErrNoSuchAccount },
			want:    ResetNoAccount,
		},
		"a verified account with a password": {
			arrange: func(*resetHarness) {},
			want:    ResetRequested,
			appends: true,
		},
		"an account that never proved its address": {
			arrange: func(h *resetHarness) {
				user := eventsourcing.NewAggregate(domain.New)
				if err := user.Register(h.user.ID(), h.user.SubjectID(),
					h.index(resetEmail), testNow); err != nil {
					h.t.Fatalf("registering: %v", err)
				}
				user.ClearUncommitted()
				h.user = user
			},
			want: ResetNoPassword,
		},
		"a passwordless account": {
			arrange: func(h *resetHarness) {
				user := eventsourcing.NewAggregate(domain.New)
				index := h.index(resetEmail)
				if err := user.Register(h.user.ID(), h.user.SubjectID(), index, testNow); err != nil {
					h.t.Fatalf("registering: %v", err)
				}
				if err := user.VerifyEmail(index, testNow); err != nil {
					h.t.Fatalf("verifying: %v", err)
				}
				user.ClearUncommitted()
				h.user = user
			},
			want: ResetNoPassword,
		},
		"a deactivated account": {
			arrange: func(h *resetHarness) {
				if err := h.user.Deactivate(h.user.SubjectID(), testNow); err != nil {
					h.t.Fatalf("deactivating: %v", err)
				}
				h.user.ClearUncommitted()
			},
			want: ResetNotEligible,
		},
		"a suspended account": {
			arrange: func(h *resetHarness) {
				if err := h.user.Suspend("operator", "fraud", testNow); err != nil {
					h.t.Fatalf("suspending: %v", err)
				}
				h.user.ClearUncommitted()
			},
			want: ResetNotEligible,
		},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newResetHarness(t)
			tt.arrange(h)

			result, err := h.request(resetEmail)
			if err != nil {
				t.Fatalf("a reset request for %s returned an error: %v; every account state "+
					"must answer alike, and an error is the most distinguishable answer of all",
					name, err)
			}
			if result.Outcome != tt.want {
				t.Errorf("outcome = %v, want %v", result.Outcome, tt.want)
			}
			appended := len(h.recorder.snapshot())
			switch {
			case tt.appends && appended != 1:
				t.Errorf("the eligible account appended %d times, want 1", appended)
			case !tt.appends && appended != 0:
				t.Errorf("%s appended %d time(s); a reset link was requested for an account "+
					"that must not receive one", name, appended)
			}
		})
	}
}

// The link is addressed by the ACCOUNT, never by the request.
//
// The appended event carries the account's own pseudonym and the account's own
// blind index, and there is no field anywhere in the flow that could carry an
// address. That is what makes "send to the stored verified address" a property
// of the shape rather than of a check somebody could delete (identity.md §4.5).
func TestAResetRequestNamesTheAccountAndNeverAnAddress(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	if _, err := h.request(resetEmail); err != nil {
		t.Fatalf("requesting a reset: %v", err)
	}

	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("the request appended %d events, want 1", len(events))
	}
	requested, ok := events[0].(*contract.PasswordResetRequested)
	if !ok {
		t.Fatalf("the request appended %T, want *contract.PasswordResetRequested", events[0])
	}
	if requested.SubjectID != h.user.SubjectID() {
		t.Errorf("the event names subject %q, want the account's own %q",
			requested.SubjectID, h.user.SubjectID())
	}
	if requested.Index != h.user.EmailIndex() {
		t.Errorf("the event carries index %q, want the account's own %q",
			requested.Index, h.user.EmailIndex())
	}
	if strings.Contains(string(requested.Index), "@") {
		t.Errorf("the event carries something address-shaped: %q", requested.Index)
	}
	if got, want := requested.ExpiresAt, testNow.Add(time.Hour); !got.Equal(want) {
		t.Errorf("the advertised deadline is %s, want %s", got, want)
	}
}

// A request whose address resolves to an account that claims a DIFFERENT index
// appends nothing.
//
// The projection is behind the log by construction, so this is reachable: a row
// that has not caught up with an address change names an account whose current
// claim is somewhere else. Appending would ask for a link to be mailed to the
// address the vault holds, which is not the one that was typed.
func TestAResetRequestRefusesAnAccountThatClaimsAnotherAddress(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	other := eventsourcing.NewAggregate(domain.New)
	otherIndex := h.index("somebody-else@example.com")
	if err := other.Register(h.user.ID(), h.user.SubjectID(), otherIndex, testNow); err != nil {
		t.Fatalf("registering: %v", err)
	}
	if err := other.VerifyEmail(otherIndex, testNow); err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if err := other.SetPassword(h.credentialID, testNow); err != nil {
		t.Fatalf("setting a password: %v", err)
	}
	other.ClearUncommitted()
	h.user = other

	result, err := h.request(resetEmail)
	if err != nil {
		t.Fatalf("requesting a reset: %v", err)
	}
	if result.Outcome != ResetNotEligible {
		t.Errorf("outcome = %v, want ResetNotEligible", result.Outcome)
	}
	if len(h.recorder.snapshot()) != 0 {
		t.Errorf("a link was requested for an address the account no longer claims")
	}
}

// ---------------------------------------------------------------------------
// Requesting a link — the ceiling
// ---------------------------------------------------------------------------

// Both ceilings are spent BEFORE the account is looked up, and the caller's
// before the address's.
//
// Spent after the lookup, the limiter becomes the enumeration oracle the empty
// response exists to prevent: three requests to a refusal means "registered",
// unlimited means "nobody". Address-first would let a sweep across a thousand
// addresses lock a thousand real people out of their own recovery.
func TestTheResetCeilingsAreSpentBeforeTheAccountIsLookedUp(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	h.directory.err = ErrNoSuchAccount
	if _, err := h.request(resetEmail); err != nil {
		t.Fatalf("requesting a reset: %v", err)
	}

	want := []string{"caller:198.51.100.9", "address:" + string(h.index(resetEmail))}
	if len(h.calls) != len(want) {
		t.Fatalf("the ceilings were consulted %v, want %v", h.calls, want)
	}
	for i := range want {
		if h.calls[i] != want[i] {
			t.Errorf("ceiling call %d was %q, want %q", i, h.calls[i], want[i])
		}
	}
	if len(h.directory.calls) != 1 {
		t.Fatalf("the directory was consulted %d times, want 1", len(h.directory.calls))
	}
}

// An unknown address spends exactly as much budget as a registered one, so the
// request number at which a caller is refused says nothing about which addresses
// have accounts.
func TestTheResetCeilingRefusesAnUnknownAddressOnTheSameRequest(t *testing.T) {
	t.Parallel()

	spend := func(t *testing.T, unknown bool) int {
		t.Helper()
		h := newResetHarness(t)
		h.addressRules = []ratelimit.Rule{{Name: "hourly", Limit: 3, Window: time.Hour}}
		if unknown {
			h.directory.err = ErrNoSuchAccount
		}
		reset := h.build()
		allowed := 0
		for i := range 6 {
			_, err := reset.Request(context.Background(), RequestPasswordResetCommand{
				Email:          resetEmail,
				CallerScope:    "198.51.100.9",
				IdempotencyKey: "idem-" + string(rune('a'+i)),
			})
			if err == nil {
				allowed++
				continue
			}
			if errs.ReasonOf(err) != errs.RateLimited {
				t.Fatalf("request %d failed with %v, want a rate-limit refusal", i, err)
			}
		}
		return allowed
	}

	known := spend(t, false)
	unknown := spend(t, true)
	if known != unknown {
		t.Errorf("a registered address was allowed %d requests and an unknown one %d; "+
			"the ceiling discloses which addresses have accounts", known, unknown)
	}
	if known != 3 {
		t.Errorf("the ceiling allowed %d requests, want the configured 3", known)
	}
}

// A ceiling that cannot be evaluated ALLOWS the request, and says so.
//
// Failing closed would mean a Valkey blip stops every locked-out person from
// asking for the link that is their only way back in. Failing open silently
// would be a control nobody can tell has stopped running.
func TestAnUnreachableResetCeilingAllowsAndLogs(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	h.logs = &bytes.Buffer{}
	h.counter.err = errors.New("valkey unreachable")

	result, err := h.request(resetEmail)
	if err != nil {
		t.Fatalf("a degraded ceiling refused the request: %v", err)
	}
	if result.Outcome != ResetRequested {
		t.Errorf("outcome = %v, want ResetRequested", result.Outcome)
	}
	logged := h.logs.String()
	if !strings.Contains(logged, "ceiling_unavailable") {
		t.Errorf("the degraded evaluation was not recorded; logs:\n%s", logged)
	}
}

// ---------------------------------------------------------------------------
// Redeeming a link — the §4.5 contract
// ---------------------------------------------------------------------------

// The whole of identity.md §4.5, asserted in one place.
//
// Each clause is checked against an OBSERVABLE consequence rather than against
// "the method was called": the sessions are voided with no exception and under
// the reset reason, the outstanding verification token for the same subject is
// gone, the verifier in the store is the new one, and the log carries exactly
// one PasswordChanged marked ViaReset.
func TestACompletedResetVoidsEverythingSection45Requires(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	// A live verification link for the same account — the "trojan identifier"
	// variant. It is a DIFFERENT purpose, so only a sweep across every purpose
	// kills it.
	if err := h.tokens.Issue(context.Background(), PurposeEmailVerification,
		h.user.SubjectID(), testDigest(PurposeEmailVerification, "verify-me"),
		testNow.Add(24*time.Hour)); err != nil {
		t.Fatalf("issuing a verification token: %v", err)
	}
	plaintext := h.issue("reset-me")

	result, err := h.complete(plaintext, resetNewPassword)
	if err != nil {
		t.Fatalf("completing a reset: %v\n", err)
	}

	// (1) every session, sparing none.
	commands := h.revoker.commands()
	if len(commands) != 1 {
		t.Fatalf("sessions were voided %d times, want exactly 1", len(commands))
	}
	cmd := commands[0]
	if cmd.SubjectID != h.user.SubjectID() {
		t.Errorf("voided sessions for %q, want %q", cmd.SubjectID, h.user.SubjectID())
	}
	if !cmd.Except.IsZero() {
		t.Errorf("the reset spared session %s; §4.5 requires that it spare NOTHING, "+
			"including the session performing it", cmd.Except)
	}
	if cmd.Reason != RevokeReasonPasswordReset {
		t.Errorf("voided under reason %q, want %q", cmd.Reason, RevokeReasonPasswordReset)
	}
	if result.SessionsRevoked != 2 {
		t.Errorf("reported %d sessions revoked, want 2", result.SessionsRevoked)
	}

	// (2) every outstanding token of EVERY purpose.
	if live := h.tokens.liveFor(h.user.SubjectID(), testNow); len(live) != 0 {
		t.Errorf("the subject still holds redeemable tokens for %v; a reset must void "+
			"every purpose, not only reset tokens", live)
	}
	if h.tokens.sweeps != 1 {
		t.Errorf("the cross-purpose sweep ran %d times, want 1", h.tokens.sweeps)
	}
	if result.TokensRevoked != 1 {
		t.Errorf("reported %d tokens swept, want 1 (the outstanding verification link)",
			result.TokensRevoked)
	}

	// (5) the credential actually moved, and to the password that was submitted.
	got := h.creds.verifier(h.user.SubjectID())
	if got == "$argon2id$fake$old" {
		t.Fatal("the stored verifier is unchanged; the reset did not replace the password")
	}
	if _, seen := h.hasher.hashed(); len(seen) != 1 || seen[0] != resetNewPassword {
		t.Errorf("the hasher was given %v, want exactly [%q]", seen, resetNewPassword)
	}

	// The log records it, once, as a reset.
	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("the reset appended %d events, want exactly 1: %#v", len(events), events)
	}
	changed, ok := events[0].(*contract.PasswordChanged)
	if !ok {
		t.Fatalf("the reset appended %T, want *contract.PasswordChanged", events[0])
	}
	if !changed.ViaReset {
		t.Error("PasswordChanged.ViaReset is false; the notification and the risk " +
			"weighting for a reset differ from an ordinary change")
	}
	if changed.CredentialID != h.credentialID.String() {
		t.Errorf("the event names credential %q, want %q",
			changed.CredentialID, h.credentialID)
	}
}

// The destructive steps happen in the order the doc claims: tokens, then
// sessions, then the credential.
//
// Both orders "work" in the happy path, and they fail in opposite directions.
// Replacing the verifier first and then failing to revoke leaves a new password
// live WITH the attacker's session — the exact state §4.5 forbids, reached
// through an error path where nothing notices.
func TestAResetVoidsSessionsAndTokensBeforeItMovesTheCredential(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	plaintext := h.issue("reset-me")
	if _, err := h.complete(plaintext, resetNewPassword); err != nil {
		t.Fatalf("completing a reset: %v", err)
	}

	want := []string{"revoke-tokens", "revoke-sessions", "replace"}
	got := h.journal.recorded()
	if len(got) != len(want) {
		t.Fatalf("the reset performed %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("the reset performed %v, want %v", got, want)
		}
	}
}

// A failure to void sessions stops the reset with the password UNCHANGED.
//
// This is the "fails towards less access" claim made concrete: the person is
// told it did not work and asks for another link, and nothing was granted to
// anybody in the meantime.
func TestAResetThatCannotVoidSessionsChangesNoPassword(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	h.revoker.err = errors.New("the session store is unreachable")
	plaintext := h.issue("reset-me")

	if _, err := h.complete(plaintext, resetNewPassword); err == nil {
		t.Fatal("a reset that could not void sessions reported success")
	}
	if got := h.creds.verifier(h.user.SubjectID()); got != "$argon2id$fake$old" {
		t.Errorf("the verifier is %q; a reset that could not void sessions must not "+
			"leave a new password live", got)
	}
	if len(h.recorder.snapshot()) != 0 {
		t.Error("a failed reset appended to the log")
	}
}

// ---------------------------------------------------------------------------
// Redeeming a link — the token
// ---------------------------------------------------------------------------

// A spent link is refused, and refused identically to one that never existed.
func TestAResetLinkIsSingleUse(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	plaintext := h.issue("reset-me")
	if _, err := h.complete(plaintext, resetNewPassword); err != nil {
		t.Fatalf("the first redemption failed: %v", err)
	}

	_, second := h.complete(plaintext, "another-new-passphrase")
	if second == nil {
		t.Fatal("a spent reset link was accepted a second time")
	}
	_, unknown := h.complete("never-issued-at-all", "another-new-passphrase")
	if unknown == nil {
		t.Fatal("a token that was never issued was accepted")
	}
	if second.Error() != unknown.Error() {
		t.Errorf("a spent link says %q and an unknown one says %q; the difference tells "+
			"whoever holds a link whether it was ever real", second, unknown)
	}
	if errs.ReasonOf(second) != errs.ValidationFailed {
		t.Errorf("a spent link was refused with %v, want VALIDATION_FAILED",
			errs.ReasonOf(second))
	}
	// The hash runs only AFTER the token is spent, so two refused redemptions cost
	// no Argon2id at all. That ordering is what keeps a public endpoint from being
	// a CPU amplifier for anyone posting garbage tokens.
	if calls, _ := h.hasher.hashed(); calls != 1 {
		t.Errorf("the hasher ran %d times for one successful and two refused "+
			"redemptions, want 1", calls)
	}
}

// An expired link is refused exactly as an unknown one is.
func TestAnExpiredResetLinkIsRefusedLikeAnUnknownOne(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	if err := h.tokens.Issue(context.Background(), PurposePasswordReset,
		h.user.SubjectID(), testDigest(PurposePasswordReset, "stale"),
		testNow.Add(-time.Minute)); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	_, expired := h.complete("stale", resetNewPassword)
	_, unknown := h.complete("never-issued", resetNewPassword)
	if expired == nil {
		t.Fatal("an expired reset link was accepted")
	}
	if expired.Error() != unknown.Error() {
		t.Errorf("expired says %q, unknown says %q", expired, unknown)
	}
}

// Every unusable reset link gets ONE answer, and this is the test that pins it.
//
// # Why the expired-vs-unknown test above is not enough
//
// TestAnExpiredResetLinkIsRefusedLikeAnUnknownOne compares two facts that reach
// Complete through the SAME branch: TokenStore.Consume returns ErrTokenNotFound
// for unknown, spent and expired alike, so those three are equal by
// construction and stay equal however that branch is written. Replacing that
// branch's errRejectedResetLink() with "that link has expired" left the whole
// repository green — an S1-29 mutation survivor — because nothing compared it
// against the refusals decided FURTHER DOWN.
//
// The refusals that can actually diverge are the five errRejectedResetLink call
// sites, and they are decided at three different depths: before the account is
// known, after the subject fails to resolve, and after the aggregate says it
// has no usable password. Whoever holds a link that does not work is entitled
// to learn nothing about which of those it was — and the population holding a
// link they cannot use includes everyone who guessed one.
func TestEveryUnusableResetLinkIsRefusedIdentically(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		arrange func(*resetHarness) string
	}{
		{
			// Never issued. The reference case: nothing about it touches an
			// account at all.
			name:    "a link that was never issued",
			arrange: func(*resetHarness) string { return "never-issued" },
		},
		{
			name: "a link whose deadline has passed",
			arrange: func(h *resetHarness) string {
				if err := h.tokens.Issue(context.Background(), PurposePasswordReset,
					h.user.SubjectID(), testDigest(PurposePasswordReset, "stale"),
					testNow.Add(-time.Minute)); err != nil {
					h.t.Fatalf("issuing: %v", err)
				}
				return "stale"
			},
		},
		{
			// Redeemed once already. Reached through the same Consume as the two
			// above, and kept in the table because it is the case an attacker who
			// watched a successful reset actually holds.
			name: "a link that has already been spent",
			arrange: func(h *resetHarness) string {
				plaintext := h.issue("spent-once")
				if _, err := h.complete(plaintext, resetNewPassword); err != nil {
					h.t.Fatalf("the first redemption failed: %v", err)
				}
				return plaintext
			},
		},
		{
			// A live token whose subject resolves to no account. Decided AFTER
			// Consume — the link is spent by the time this refusal is produced —
			// so a distinguishable answer here says "that link was real".
			name: "a live link naming a subject with no account",
			arrange: func(h *resetHarness) string {
				plaintext := h.issue("orphaned-subject")
				h.subjects = fakeDirectory{user: h.user.ID(), only: "subj_nobody"}
				return plaintext
			},
		},
		{
			// A live token for an account the log says has no usable password.
			// Reachable when the credential was disabled between the request and
			// the click, and decided deeper still — after the aggregate loads.
			name: "a live link for an account with no usable password",
			arrange: func(h *resetHarness) string {
				plaintext := h.issue("passwordless")
				// The SAME account identity — the token was issued against this
				// subject — rebuilt without the PasswordSet event, which is what a
				// credential removed between the request and the click looks like
				// from the log's side.
				user := eventsourcing.NewAggregate(domain.New)
				index := h.index(resetEmail)
				if err := user.Register(h.user.ID(), h.user.SubjectID(), index, testNow); err != nil {
					h.t.Fatalf("registering: %v", err)
				}
				if err := user.VerifyEmail(index, testNow); err != nil {
					h.t.Fatalf("verifying: %v", err)
				}
				user.ClearUncommitted()
				h.user = user
				return plaintext
			},
		},
	}

	// The reference is the plainest one: a link this system never issued.
	reference := func() error {
		h := newResetHarness(t)
		_, err := h.complete("never-issued", resetNewPassword)
		return err
	}()
	if reference == nil {
		t.Fatal("a link that was never issued was accepted")
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			h := newResetHarness(t)
			token := tc.arrange(h)

			_, err := h.complete(token, resetNewPassword)
			if err == nil {
				t.Fatal("an unusable reset link was accepted")
			}
			if err.Error() != reference.Error() {
				t.Errorf("refusal is %q, want %q — a distinguishable refusal tells whoever "+
					"holds the link which of five facts is true about it",
					err.Error(), reference.Error())
			}
			if errs.ReasonOf(err) != errs.ReasonOf(reference) {
				t.Errorf("refusal reason is %s, want %s; the errs.Reason is the Connect code "+
					"on the wire", errs.ReasonOf(err), errs.ReasonOf(reference))
			}
		})
	}
}

// A VERIFICATION token cannot be redeemed as a reset token.
//
// The purpose is mixed into the digest, so the two hash to different values from
// one plaintext. Without that binding, anyone who can cause a verification mail
// to be sent — by registering, or through ResendEmailVerification — obtains a
// password-reset token for an account they do not own.
func TestAVerificationTokenCannotBeRedeemedAsAReset(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	if err := h.tokens.Issue(context.Background(), PurposeEmailVerification,
		h.user.SubjectID(), testDigest(PurposeEmailVerification, "shared-plaintext"),
		testNow.Add(24*time.Hour)); err != nil {
		t.Fatalf("issuing: %v", err)
	}

	if _, err := h.complete("shared-plaintext", resetNewPassword); err == nil {
		t.Fatal("a verification token was redeemed as a password reset")
	}
	if got := h.creds.verifier(h.user.SubjectID()); got != "$argon2id$fake$old" {
		t.Errorf("the verifier moved to %q on a cross-purpose redemption", got)
	}
	if live := h.tokens.liveFor(h.user.SubjectID(), testNow); len(live) != 1 {
		t.Errorf("the verification token is no longer live: %v", live)
	}
}

// A breached or too-short password is rejected WITHOUT spending the link.
//
// Both refusals are functions of the caller's own bytes and consult neither the
// token nor the account, so leaving the link alive costs nothing and saves a
// person who picked a weak password from being locked out by their own choice.
func TestARejectedPasswordDoesNotBurnTheResetLink(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		arrange  func(*resetHarness)
		password string
	}{
		"a breached password": {
			arrange:  func(h *resetHarness) { h.breach.set(true, "HIBP", nil) },
			password: resetNewPassword,
		},
		"a password below the floor": {
			arrange:  func(*resetHarness) {},
			password: "short",
		},
		"no password at all": {
			arrange:  func(*resetHarness) {},
			password: "",
		},
	}
	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h := newResetHarness(t)
			tt.arrange(h)
			plaintext := h.issue("reset-me")

			if _, err := h.complete(plaintext, tt.password); err == nil {
				t.Fatalf("%s was accepted", name)
			}
			// The corpus is quieted for the retry: the point is that the LINK
			// survived, not that the same password is refused twice.
			h.breach.set(false, "", nil)
			// The link still works.
			if _, err := h.complete(plaintext, resetNewPassword); err != nil {
				t.Fatalf("the link was burned by %s: %v", name, err)
			}
		})
	}
}

// An unreachable breach corpus ALLOWS the reset and records that the check did
// not run. Blocking would stop every reset in the system on a third-party
// outage; failing open silently would be a control nobody can tell has stopped.
func TestAnUnreachableBreachCorpusDoesNotBlockAReset(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	h.logs = &bytes.Buffer{}
	h.breach.set(false, "", errors.New("hibp unreachable"))
	plaintext := h.issue("reset-me")

	if _, err := h.complete(plaintext, resetNewPassword); err != nil {
		t.Fatalf("an unreachable corpus blocked the reset: %v", err)
	}
	if !strings.Contains(h.logs.String(), "breach_corpus_unavailable") {
		t.Errorf("the skipped screening was not recorded; logs:\n%s", h.logs.String())
	}
}

// ---------------------------------------------------------------------------
// Redeeming a link — the second factor (ASVS 5.0 V6.4.3)
// ---------------------------------------------------------------------------

// A reset changes exactly ONE credential and grants nothing.
//
// This is the assertion that stands in for "the reset does not bypass the second
// factor". The property is carried by shape — there is no session field to fill
// and no TOTP call to make — so the test is written against what the reset
// APPENDS and what it touches: one PasswordChanged, no UserActivated, nothing
// second-factor shaped, and a result with no bearer token in it.
//
// Ask what this would do if the feature were deleted: a reset that helpfully
// signed the caller in would have to append a SessionCreated or return a token,
// and both are checked here.
func TestAResetGrantsNothingBeyondTheNewPassword(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	// Give the account a real second factor, so "the reset removed it" is a
	// reachable failure rather than a vacuous one.
	totpID := ids.New[ids.Credential](testNow, &fixedEntropy{b: 33})
	if err := h.user.StartTotpEnrollment(totpID, testNow.Add(time.Hour), testNow); err != nil {
		t.Fatalf("starting enrolment: %v", err)
	}
	if err := h.user.EnableTotp(totpID, testNow); err != nil {
		t.Fatalf("enabling TOTP: %v", err)
	}
	h.user.ClearUncommitted()
	if h.user.State() != domain.StateActive {
		t.Fatalf("the fixture account is %v, want Active", h.user.State())
	}

	plaintext := h.issue("reset-me")
	result, err := h.complete(plaintext, resetNewPassword)
	if err != nil {
		t.Fatalf("completing a reset: %v", err)
	}

	for _, e := range h.appended() {
		switch e.(type) {
		case *contract.PasswordChanged:
		case *contract.SessionCreated:
			t.Error("the reset created a session; a reset must not advance the caller " +
				"towards one (ASVS 5.0 V6.4.3)")
		case *contract.TotpDisabled:
			t.Error("the reset disabled the account's second factor")
		case *contract.RecoveryCodeConsumed:
			t.Error("the reset consumed a recovery code")
		default:
			t.Errorf("the reset appended an unexpected %T", e)
		}
	}

	// The second factor is still enrolled and still usable.
	m, ok := h.user.Method(totpID)
	if !ok || !m.Usable() {
		t.Error("the account's TOTP credential is no longer usable after a reset")
	}
	if h.user.State() != domain.StateActive {
		t.Errorf("the account is %v after a reset, want Active and unchanged", h.user.State())
	}

	// And nothing session-shaped comes back. Asserted structurally: the result
	// type has four fields and none of them is a credential.
	if result.SubjectID != h.user.SubjectID() || result.UserID != h.user.ID() {
		t.Errorf("the result names %s/%s, want %s/%s",
			result.SubjectID, result.UserID, h.user.SubjectID(), h.user.ID())
	}
}

// A suspended account is refused before anything is destroyed.
//
// domain.User.mutable is what refuses, and it is consulted through
// ChangePassword BEFORE the token sweep and the session revocation — so a live
// link for an account that has since been suspended cannot be used to strip its
// sessions and tokens as a denial of service.
func TestAResetOnASuspendedAccountDestroysNothing(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	plaintext := h.issue("reset-me")
	if err := h.user.Suspend("operator", "fraud", testNow); err != nil {
		t.Fatalf("suspending: %v", err)
	}
	h.user.ClearUncommitted()

	if _, err := h.complete(plaintext, resetNewPassword); err == nil {
		t.Fatal("a reset on a suspended account succeeded")
	}
	if got := h.journal.recorded(); len(got) != 0 {
		t.Errorf("a refused reset performed %v; nothing may be destroyed before the "+
			"aggregate has agreed to the change", got)
	}
}

// ---------------------------------------------------------------------------
// Concurrency
// ---------------------------------------------------------------------------

// Two simultaneous resets for one account produce exactly ONE password change.
//
// Both hold a valid link — an attacker triggered one, the victim triggered
// another — and both consume their own token successfully, because the digests
// differ.
//
// # What this test can and cannot prove, and why the assertion moved
//
// It used to assert "exactly one wins", and it was 60% FLAKY under `-race`
// (7 of 12, then 12 of 15) for a structural reason: the mechanism that makes
// exactly one win is the expected-revision precondition on the account stream,
// and the fake appender these unit tests share ignores `Expected` entirely and
// returns success for every call. So the assertion was made against a fake with
// no optimistic concurrency in it. It passed only when the interleaving happened
// to let the winner's token sweep beat the loser's consume — luck, not the
// property.
//
// A test that cannot fail for the right reason is not evidence, so the real
// property now lives where it can be proven, over a real KurrentDB:
// `internal/adapter/identityit`, TestTwoConcurrentResetsOverRealInfrastructure.
//
// What a fake CAN prove is what this asserts now: that both attempts carry the
// loaded revision rather than AnyRevision. That is the precondition the real
// mechanism needs, it is the thing a refactor would silently drop, and it is
// checkable without a database.
func TestTwoConcurrentResetsProduceExactlyOnePasswordChange(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	userID, subjectID, credID := h.user.ID(), h.user.SubjectID(), h.credentialID
	index := h.index(resetEmail)
	// A FRESH aggregate per load, as eventsourcing.Repository gives production.
	// Sharing one instance across two goroutines would race on its uncommitted
	// buffer and prove nothing about the handler.
	h.userFn = func() *domain.User {
		return mustVerifiedUser(userID, subjectID, index, credID)
	}
	first := h.issue("reset-one")
	second := h.issue("reset-two")
	reset := h.build()

	type outcome struct {
		password string
		err      error
	}
	results := make(chan outcome, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i, pair := range []struct{ token, password string }{
		{first, "first-new-passphrase"},
		{second, "second-new-passphrase"},
	} {
		go func(i int, token, password string) {
			start.Wait()
			_, err := reset.Complete(context.Background(), ResetPasswordCommand{
				Token:          token,
				Password:       password,
				IdempotencyKey: "idem-concurrent-" + string(rune('a'+i)),
			})
			results <- outcome{password: password, err: err}
		}(i, pair.token, pair.password)
	}
	start.Done()

	var winners []string
	var refused int
	for range 2 {
		got := <-results
		switch {
		case got.err == nil:
			winners = append(winners, got.password)
		case errs.ReasonOf(got.err) == errs.Conflict,
			errs.ReasonOf(got.err) == errs.ValidationFailed:
			// Two safe refusals, and which one arrives depends on the interleaving.
			// CONFLICT is the compare-and-set losing. VALIDATION_FAILED is the
			// loser's own link having been swept by the winner before it could be
			// consumed — §4.5's "void every outstanding token of every purpose"
			// applied to a second live reset link, which is exactly what it is for.
			refused++
		default:
			t.Errorf("a concurrent reset failed with an unexpected error: %v", got.err)
		}
	}

	// Both attempts must have presented the loaded revision. Against this fake
	// both can "succeed", and that is expected here — see the doc comment.
	calls := h.recorder.snapshot()
	if len(calls) == 0 {
		t.Fatal("neither reset appended anything; the test proved nothing")
	}
	for i, call := range calls {
		for _, entry := range call {
			if entry.Expected.IsAny() {
				t.Errorf("append %d presented AnyRevision; a reset that does not pin the "+
					"loaded revision cannot be serialised against a competing reset, and "+
					"the loser would silently overwrite the winner", i)
			}
		}
	}
	if len(winners)+refused != 2 {
		t.Fatalf("%d succeeded and %d refused; every attempt must end in one or the other",
			len(winners), refused)
	}

	// Every successful attempt must have written a verifier that matches the
	// password it was given. That is provable here and it is worth pinning: it
	// catches a reset that appends PasswordChanged without replacing the
	// credential, which would leave the log claiming a change that never happened.
	stored := h.creds.verifier(h.user.SubjectID())
	if len(winners) > 0 && stored != resetVerifierFor(winners[len(winners)-1]) {
		t.Errorf("the stored verifier is %q, which matches no password that succeeded; "+
			"a reset recorded a change it did not make", stored)
	}

	// One PasswordChanged per success, and no more. A retry that appended twice
	// for one reset is a real defect and this fake CAN see it — unlike "exactly
	// one reset wins", which it cannot. See the doc comment.
	changes := 0
	for _, e := range h.appended() {
		if _, ok := e.(*contract.PasswordChanged); ok {
			changes++
		}
	}
	if changes != len(winners) {
		t.Errorf("the log carries %d PasswordChanged events for %d successful reset(s); "+
			"a retry appended an extra one", changes, len(winners))
	}
}

// The same link presented twice at the same instant is redeemed once.
//
// The token store's Consume is the guard here rather than the credential CAS,
// and it must hold on its own: a single-use secret that is sometimes multi-use is
// exactly what an attacker who intercepted one mail needs.
func TestOneResetLinkPresentedTwiceAtOnceIsRedeemedOnce(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	userID, subjectID, credID := h.user.ID(), h.user.SubjectID(), h.credentialID
	index := h.index(resetEmail)
	h.userFn = func() *domain.User {
		return mustVerifiedUser(userID, subjectID, index, credID)
	}
	plaintext := h.issue("reset-me")
	reset := h.build()

	errsCh := make(chan error, 2)
	var start sync.WaitGroup
	start.Add(1)
	for i := range 2 {
		go func(i int) {
			start.Wait()
			_, err := reset.Complete(context.Background(), ResetPasswordCommand{
				Token:          plaintext,
				Password:       "new-passphrase-" + string(rune('a'+i)),
				IdempotencyKey: "idem-double-" + string(rune('a'+i)),
			})
			errsCh <- err
		}(i)
	}
	start.Done()

	succeeded := 0
	for range 2 {
		if err := <-errsCh; err == nil {
			succeeded++
		}
	}
	if succeeded != 1 {
		t.Fatalf("%d of 2 simultaneous presentations of ONE link succeeded, want exactly 1",
			succeeded)
	}
}

// A reset racing a LOGIN still records the change.
//
// A login appends to the account's own stream when it locks out an authenticator
// or rehashes a verifier, so the reset's expected revision can be stale through
// no fault of its own. By then the verifier is already replaced — an append that
// gave up would leave a credential the log cannot account for, which the tamper
// reconciliation reports as an injected credential (identity.md §4.2).
func TestAResetRacingALoginStillRecordsTheChange(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	racer := &racingAppender{failures: 1, inner: h.recorder}
	h.appender = racer
	plaintext := h.issue("reset-me")

	if _, err := h.complete(plaintext, resetNewPassword); err != nil {
		t.Fatalf("a reset that lost one append race gave up: %v", err)
	}
	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("the log carries %d events, want exactly 1 PasswordChanged", len(events))
	}
	if _, ok := events[0].(*contract.PasswordChanged); !ok {
		t.Fatalf("the log carries %T, want *contract.PasswordChanged", events[0])
	}
	// The aggregate was reloaded for the retry rather than re-appended blind.
	if h.loads.Load() < 2 {
		t.Errorf("the account was loaded %d times; a retry must re-read the stream so the "+
			"event is recorded against what the stream says NOW", h.loads.Load())
	}
}

// When every append attempt loses, the reset reports a divergence rather than
// pretending. The password IS the new one by then, and saying so is what lets an
// operator act before the reconciliation job raises it as tampering.
func TestAResetThatCannotRecordTheChangeSaysSo(t *testing.T) {
	t.Parallel()

	h := newResetHarness(t)
	h.appender = &racingAppender{failures: 99, inner: h.recorder}
	plaintext := h.issue("reset-me")

	_, err := h.complete(plaintext, resetNewPassword)
	if err == nil {
		t.Fatal("a reset that never recorded its change reported success")
	}
	if errs.ReasonOf(err) != errs.Internal {
		t.Errorf("reason = %v, want INTERNAL", errs.ReasonOf(err))
	}
	if !strings.Contains(err.Error(), "disagree") {
		t.Errorf("the error does not state that the store and the log now disagree: %v", err)
	}
	if got := h.creds.verifier(h.user.SubjectID()); got == "$argon2id$fake$old" {
		t.Error("the verifier is unchanged, so the test never reached the state it is about")
	}
}
