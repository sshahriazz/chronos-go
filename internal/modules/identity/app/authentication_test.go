package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// The login path, tested for the properties that decide whether it is safe
// rather than for the ones that decide whether it works.
//
// Four of them are invisible to a functional test and each has its own case
// below, because each has a plausible "simplification" that would delete it while
// every ordinary login kept passing:
//
//   - An identifier that matches no account still pays for an Argon2id
//     evaluation. Skipping it is a timing oracle for account existence.
//   - Every refusal is byte-identical, including its errs.Reason. A distinct
//     message for "suspended" or "wrong code" is an oracle on the wire.
//   - The attempt ceiling is consulted BEFORE the hasher, and a degraded ceiling
//     is surfaced. A limiter that silently stopped counting looks exactly like one
//     that is never reached.
//   - SessionCreated is appended BEFORE the token row is written. The reverse
//     leaves a digest that SweepSessionTokens can never find.

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// authHasher models the real hasher's BINDING and its VERSIONING, not just its
// arithmetic.
//
// Verify returns ErrVerifierUnreadable when the ids it is given are not the ones
// the verifier was sealed under, exactly as the Argon2id adapter does when a row
// is copied between accounts. A fake that ignored the ids would let the dummy
// verifier appear to work while production returned early on the AAD and did no
// hashing at all — which is the precise failure the dummy exists to prevent.
//
// The verifier also carries a policy version, because the rehash path cannot be
// tested without one. A fake whose Hash returned the same string for the same
// password could not express "below current policy" at all: NeedsRehash would have
// nothing to answer from, and PasswordCredentials.Rehash — which refuses a
// replacement equal to the stored value — would refuse every upgrade. Here Verify
// accepts ANY version (an old verifier still opens, which is what makes a
// transparent upgrade possible) and NeedsRehash compares the encoded version
// against the hasher's current one.
type authHasher struct {
	hashes    int
	verifies  int
	hashErr   error
	verifyErr error

	// version is the policy Hash writes at. Zero means currentVerifierVersion, so
	// a harness that says nothing about versions produces verifiers that are
	// already current and never rehash.
	version int

	// pepper is what PepperVersion reports, and it is what Rehash must be handed.
	pepper int32

	// onHash runs inside Hash, which is the window between a rehash reading the
	// stored verifier and writing its replacement. It is how the concurrent
	// password change is driven — see the compare-and-set test.
	onHash func()
}

var _ PasswordHasher = (*authHasher)(nil)

// currentVerifierVersion is the policy the fake hasher writes at by default.
const currentVerifierVersion = 2

func (h *authHasher) at() int {
	if h.version == 0 {
		return currentVerifierVersion
	}
	return h.version
}

func (h *authHasher) Hash(
	_ context.Context, password string, user ids.UserID, cred ids.CredentialID,
) (string, error) {
	h.hashes++
	if h.onHash != nil {
		h.onHash()
	}
	if h.hashErr != nil {
		return "", h.hashErr
	}
	if user.IsZero() || cred.IsZero() {
		// The real hasher refuses this: without both ids there is no AAD binding.
		return "", errors.New("argon2id: hashing needs both a user id and a credential id")
	}
	return verifierForAt(h.at(), password, user, cred), nil
}

func (h *authHasher) Verify(
	_ context.Context, password, verifier string, user ids.UserID, cred ids.CredentialID,
) (bool, error) {
	h.verifies++
	if h.verifyErr != nil {
		return false, h.verifyErr
	}
	_, stored, ok := parseVerifier(verifier, user, cred)
	if !ok {
		return false, fmt.Errorf("%w: the verifier does not authenticate under this row",
			ErrVerifierUnreadable)
	}
	return stored == password, nil
}

// NeedsRehash reports a verifier written below the hasher's current policy.
//
// A verifier this fake cannot parse is reported as needing one: an unreadable
// stored value is by definition not current, and the real hasher takes the same
// view of a format it does not recognise.
func (h *authHasher) NeedsRehash(verifier string) bool {
	parts := strings.SplitN(verifier, ":", 5)
	if len(parts) != 5 || !strings.HasPrefix(parts[1], "v") {
		return true
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	if err != nil {
		return true
	}
	return version < h.at()
}

func (h *authHasher) PepperVersion() int32 {
	if h.pepper == 0 {
		return 3
	}
	return h.pepper
}

// parseVerifier splits a fake verifier and checks it authenticates under this row.
func parseVerifier(verifier string, user ids.UserID, cred ids.CredentialID) (int, string, bool) {
	parts := strings.SplitN(verifier, ":", 5)
	if len(parts) != 5 || parts[0] != "argon2" {
		return 0, "", false
	}
	if parts[2] != user.String() || parts[3] != cred.String() {
		// The AAD binding. A row copied between accounts fails to open here rather
		// than validating the attacker's own password against the victim's account.
		return 0, "", false
	}
	version, err := strconv.Atoi(strings.TrimPrefix(parts[1], "v"))
	if err != nil {
		return 0, "", false
	}
	return version, parts[4], true
}

func verifierPrefixAt(version int, user ids.UserID, cred ids.CredentialID) string {
	return "argon2:v" + strconv.Itoa(version) + ":" + user.String() + ":" + cred.String() + ":"
}

func verifierFor(password string, user ids.UserID, cred ids.CredentialID) string {
	return verifierForAt(currentVerifierVersion, password, user, cred)
}

func verifierForAt(
	version int, password string, user ids.UserID, cred ids.CredentialID,
) string {
	return verifierPrefixAt(version, user, cred) + password
}

// authLimiter is the attempt ceiling. It records every scope it was asked about
// and the ORDER relative to hashing is asserted through the journal below.
type authLimiter struct {
	allowed bool
	err     error
	scopes  []string
}

var _ AttemptLimiter = (*authLimiter)(nil)

func (l *authLimiter) Allow(ctx context.Context, scope string) (ratelimit.Decision, error) {
	l.scopes = append(l.scopes, scope)
	if l.err != nil {
		// The real limiter fails OPEN: the decision that comes back with the error
		// is allowed-and-degraded.
		return ratelimit.Decision{Degraded: true}, l.err
	}
	if !l.allowed {
		return ratelimit.Decision{Rule: "per-minute", RetryAfter: time.Minute}, nil
	}
	// ratelimit.Decision's allow flag is unexported, so an allowing decision can
	// only be produced by the real limiter. Driving it through one is better than
	// a fake that could not express the type's own zero-value-denies discipline.
	limiter, err := ratelimit.New(allowingCounter{}, "test",
		ratelimit.Rule{Name: "per-minute", Limit: 100, Window: time.Minute})
	if err != nil {
		return ratelimit.Decision{}, err
	}
	return limiter.Allow(ctx, scope)
}

type allowingCounter struct{}

func (allowingCounter) Incr(context.Context, string, time.Duration) (int64, error) { return 1, nil }

// authCredentials models the credential table's behaviour rather than its shape.
//
// Three properties are modelled deliberately, because a lockout and a rehash are
// both decided from them:
//
//   - The failure count is PER CREDENTIAL and is cleared by a success. A single
//     shared counter would let a password success mask an authenticator's grind,
//     and the lockout threshold would then be reached by whichever credential
//     happened to fail last.
//   - RecordFailure returns the post-increment total from the same call that
//     wrote it, as the real statement's RETURNING does.
//   - Rehash is a real compare-and-set. A fake that wrote unconditionally would
//     make the ErrCredentialMoved branch — the one that stops a rehash undoing a
//     concurrent password change — unreachable from any test.
type authCredentials struct {
	rows      map[string]PasswordCredential
	findErr   error
	failures  []ids.CredentialID
	successes []ids.CredentialID
	failErr   error
	counts    map[ids.CredentialID]int32

	rehashes   []rehashCall
	rehashErr  error
	disabled   []ids.CredentialID
	disableErr error
}

// rehashCall is one compare-and-set as the handler issued it.
type rehashCall struct {
	cred        ids.CredentialID
	expected    string
	replacement string
	pepper      int32
}

var _ PasswordCredentials = (*authCredentials)(nil)

func (c *authCredentials) Store(context.Context, NewPasswordCredential) error {
	return errors.New("not used by authentication")
}

func (c *authCredentials) StoreFirst(context.Context, NewPasswordCredential) error {
	return errors.New("not used by authentication")
}

func (c *authCredentials) Find(_ context.Context, subjectID string) (PasswordCredential, error) {
	if c.findErr != nil {
		return PasswordCredential{}, c.findErr
	}
	row, ok := c.rows[subjectID]
	if !ok {
		return PasswordCredential{}, ErrNoPasswordCredential
	}
	row.Failures = c.counts[row.ID]
	return row, nil
}

func (c *authCredentials) Rehash(
	_ context.Context, cred ids.CredentialID, expected, replacement string, pepper int32,
) error {
	c.rehashes = append(c.rehashes, rehashCall{cred, expected, replacement, pepper})
	if c.rehashErr != nil {
		return c.rehashErr
	}
	for subject, row := range c.rows {
		if row.ID != cred {
			continue
		}
		if row.Verifier != expected {
			// The row moved under the write: a concurrent password change, or a
			// disable. The real statement matches zero rows and says the same thing.
			return ErrCredentialMoved
		}
		row.Verifier = replacement
		row.PepperVersion = pepper
		c.rows[subject] = row
		return nil
	}
	return ErrCredentialMoved
}

func (c *authCredentials) RecordSuccess(_ context.Context, cred ids.CredentialID) error {
	c.successes = append(c.successes, cred)
	delete(c.counts, cred)
	return nil
}

func (c *authCredentials) RecordFailure(_ context.Context, cred ids.CredentialID) (int32, error) {
	c.failures = append(c.failures, cred)
	if c.failErr != nil {
		return 0, c.failErr
	}
	c.counts[cred]++
	return c.counts[cred], nil
}

func (c *authCredentials) Disable(_ context.Context, cred ids.CredentialID) error {
	c.disabled = append(c.disabled, cred)
	return c.disableErr
}

type authAccounts struct {
	rows map[contract.EmailIndex]Account
	err  error
}

var _ AccountDirectory = (*authAccounts)(nil)

func (a *authAccounts) AccountByEmailIndex(
	_ context.Context, index contract.EmailIndex,
) (Account, error) {
	if a.err != nil {
		return Account{}, a.err
	}
	row, ok := a.rows[index]
	if !ok {
		return Account{}, ErrNoSuchAccount
	}
	return row, nil
}

// authSessionTokens records issued digests and writes into the shared journal, so
// "the append happened first" is a property a test can assert rather than a
// comment.
type authSessionTokens struct {
	journal *[]string
	issued  []NewSessionToken
	err     error
}

var _ SessionTokens = (*authSessionTokens)(nil)

func (s *authSessionTokens) Issue(_ context.Context, token NewSessionToken) error {
	*s.journal = append(*s.journal, "token")
	if s.err != nil {
		return s.err
	}
	s.issued = append(s.issued, token)
	return nil
}

type authLive struct {
	sessions []ids.SessionID
	err      error
	asked    []string
}

var _ LiveSessions = (*authLive)(nil)

func (l *authLive) List(_ context.Context, subjectID string, _ time.Time) ([]ids.SessionID, error) {
	l.asked = append(l.asked, subjectID)
	if l.err != nil {
		return nil, l.err
	}
	return l.sessions, nil
}

// authEpochs records revocation-epoch bumps and writes into the shared journal.
//
// The journal is what makes the ORDER testable: the bump must land before the
// append, so that a failure to invalidate leaves nothing in the log. A fake that
// only counted calls could not tell that ordering apart, and the wrong order is
// the one whose retry silently skips the invalidation.
type authEpochs struct {
	journal *[]string
	bumped  []authz.Principal
	err     error
}

var _ RevocationEpochs = (*authEpochs)(nil)

func (e *authEpochs) BumpEpoch(_ context.Context, p authz.Principal) error {
	*e.journal = append(*e.journal, "epoch")
	e.bumped = append(e.bumped, p)
	return e.err
}

// authAppender records every append and writes into the shared journal.
//
// errFor fails ONE stream category rather than all of them. It exists because the
// two properties that matter about a lockout and a rehash — neither may change the
// login's answer — can only be shown by breaking the account-stream append while
// leaving the attempt journal working. An appender that failed everything would
// fail the attempt's own append too, which IS reported to the caller, and the test
// would then be asserting the wrong thing.
type authAppender struct {
	journal *[]string
	err     error
	errFor  func(eventsourcing.StreamID) error
	calls   [][]eventsourcing.StreamAppend
}

var _ eventsourcing.MultiAppender = (*authAppender)(nil)

func (a *authAppender) AppendToMany(
	_ context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	*a.journal = append(*a.journal, "append")
	snapshot := make([]eventsourcing.StreamAppend, len(appends))
	copy(snapshot, appends)
	a.calls = append(a.calls, snapshot)
	if a.err != nil {
		return nil, a.err
	}
	if a.errFor != nil {
		for _, stream := range appends {
			if err := a.errFor(stream.Stream); err != nil {
				return nil, err
			}
		}
	}
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for range appends {
		out = append(out, eventsourcing.AppendResult{
			Position: eventsourcing.Position{Commit: 7, Prepare: 7},
		})
	}
	return out, nil
}

// events flattens every event this appender was handed, in order.
func (a *authAppender) events() []eventsourcing.Event {
	var out []eventsourcing.Event
	for _, call := range a.calls {
		for _, stream := range call {
			for _, e := range stream.Events {
				out = append(out, e.Event)
			}
		}
	}
	return out
}

func (a *authAppender) streams() []eventsourcing.StreamID {
	var out []eventsourcing.StreamID
	for _, call := range a.calls {
		for _, stream := range call {
			out = append(out, stream.Stream)
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const (
	authCode     = "123456"
	authTotpSeed = "JBSWY3DPEHPK3PXP"
)

type authHarness struct {
	t *testing.T

	clock       *clock.Fixed
	entropy     *fixedEntropy
	accounts    *authAccounts
	limiter     *authLimiter
	hasher      *authHasher
	credentials *authCredentials
	sessions    map[string]*domain.Session
	live        *authLive
	epochs      *authEpochs
	tokens      *authSessionTokens
	sealer      *fakeSealer
	secrets     *fakeSecrets
	verifier    *fakeVerifier
	breach      *fakeBreach
	appender    *authAppender
	journal     []string
	logs        *bytes.Buffer

	auth *Authentication

	index     contract.EmailIndex
	userID    ids.UserID
	subjectID string
	credID    ids.CredentialID
	totpID    ids.CredentialID
	user      *domain.User
}

func newAuthHarness(t *testing.T) *authHarness {
	t.Helper()

	h := &authHarness{
		t:       t,
		clock:   clock.NewFixed(testNow),
		entropy: &fixedEntropy{},
		logs:    &bytes.Buffer{},
	}
	h.userID = ids.New[ids.User](testNow, h.entropy)
	h.subjectID = ids.New[ids.Subject](testNow, h.entropy).String()
	h.credID = ids.New[ids.Credential](testNow, h.entropy)
	h.totpID = ids.New[ids.Credential](testNow, h.entropy)

	index, err := fakeIndexer{}.Of(testEmail)
	if err != nil {
		t.Fatalf("indexing the test address: %v", err)
	}
	h.index = index

	h.user = newActiveUser(t, h.userID, h.subjectID, index, h.credID, h.totpID)
	h.accounts = &authAccounts{rows: map[contract.EmailIndex]Account{
		index: {UserID: h.userID, SubjectID: h.subjectID},
	}}
	h.limiter = &authLimiter{allowed: true}
	h.hasher = &authHasher{}
	h.credentials = &authCredentials{
		rows: map[string]PasswordCredential{
			h.subjectID: {
				ID:            h.credID,
				SubjectID:     h.subjectID,
				Verifier:      verifierFor(testPassword, h.userID, h.credID),
				PepperVersion: 3,
				EnabledAt:     testNow,
			},
		},
		counts: map[ids.CredentialID]int32{},
	}
	h.sessions = map[string]*domain.Session{}
	h.live = &authLive{}
	h.appender = &authAppender{journal: &h.journal}
	h.epochs = &authEpochs{journal: &h.journal}
	h.tokens = &authSessionTokens{journal: &h.journal}
	h.sealer = &fakeSealer{}
	h.secrets = newFakeSecrets()
	h.secrets.rows[h.subjectID] = TotpSecret{
		ID:        h.totpID,
		SubjectID: h.subjectID,
		Sealed:    "sealed:" + h.subjectID + ":" + h.totpID.String() + ":" + authTotpSeed,
		Enabled:   true,
	}
	h.verifier = newFakeVerifier(authTotpSeed, authCode)
	h.breach = &fakeBreach{}

	auth, err := NewAuthentication(h.deps())
	if err != nil {
		t.Fatalf("wiring authentication: %v", err)
	}
	h.auth = auth
	return h
}

func (h *authHarness) deps() AuthenticationDeps {
	return AuthenticationDeps{
		Clock:       h.clock,
		Entropy:     h.entropy,
		Index:       fakeIndexer{},
		Limiter:     h.limiter,
		Hasher:      h.hasher,
		Credentials: h.credentials,
		Accounts:    h.accounts,
		Users: loaderFunc[*domain.User](func(_ context.Context, key string) (*domain.User, error) {
			if key != h.userID.String() {
				return eventsourcing.NewAggregate(domain.New), nil
			}
			return h.user, nil
		}),
		Sessions: loaderFunc[*domain.Session](func(_ context.Context, key string) (*domain.Session, error) {
			if s, ok := h.sessions[key]; ok {
				return s, nil
			}
			return eventsourcing.NewAggregate(domain.NewSession), nil
		}),
		Live:     h.live,
		Tokens:   h.tokens,
		Sealer:   h.sealer,
		Secrets:  h.secrets,
		Verifier: h.verifier,
		Breach:   h.breach,
		Appender: h.appender,
		Epochs:   h.epochs,
		Log:      slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug})),
	}
}

func (h *authHarness) login(cmd AuthenticateCommand) (AuthenticateResult, error) {
	h.t.Helper()
	if cmd.IdempotencyKey == "" {
		cmd.IdempotencyKey = "idem-login"
	}
	if cmd.Identifier == "" {
		cmd.Identifier = testEmail
	}
	return h.auth.Authenticate(context.Background(), cmd)
}

// newActiveUser builds the account state a login runs against: verified address,
// usable password, proven authenticator, and therefore Active.
func newActiveUser(
	t *testing.T, userID ids.UserID, subjectID string,
	index contract.EmailIndex, credID, totpID ids.CredentialID,
) *domain.User {
	t.Helper()
	u := eventsourcing.NewAggregate(domain.New)
	mustDo(t, u.Register(userID, subjectID, index, testNow))
	// Verification FIRST, and it is no longer a choice: domain.User.SetPassword
	// refuses a password on an unproven address (IDENTITY-REVIEW C8), which is
	// also the order the real flow produces — Register creates no credential and
	// VerifyEmail sets the first one. The activation the domain records therefore
	// comes from EnableTotp, which is the last of the three preconditions to
	// arrive.
	mustDo(t, u.VerifyEmail(index, testNow))
	mustDo(t, u.SetPassword(credID, testNow))
	mustDo(t, u.StartTotpEnrollment(totpID, testNow.Add(time.Hour), testNow))
	mustDo(t, u.EnableTotp(totpID, testNow))
	if u.State() != domain.StateActive {
		t.Fatalf("the test account is %s, want active", u.State())
	}
	u.ClearUncommitted()
	return u
}

func mustDo(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Fatalf("building the test account: %v", err)
	}
}

// eventOf returns the single appended event of a type, failing if there is not
// exactly one.
func eventOf[T eventsourcing.Event](t *testing.T, appender *authAppender) T {
	t.Helper()
	var (
		found T
		seen  int
	)
	for _, e := range appender.events() {
		if typed, ok := e.(T); ok {
			found = typed
			seen++
		}
	}
	if seen != 1 {
		t.Fatalf("found %d events of type %T, want exactly 1 (appended: %s)",
			seen, found, describe(appender.events()))
	}
	return found
}

func describe(events []eventsourcing.Event) string {
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType())
	}
	if len(out) == 0 {
		return "nothing"
	}
	return strings.Join(out, ", ")
}

// ---------------------------------------------------------------------------
// Authenticate — the properties that are invisible to a functional test
// ---------------------------------------------------------------------------

// An identifier with no account must cost what a wrong password costs.
//
// The assertion is on the number of Verify calls, not on elapsed time: a wall
// clock in a unit test is a flake, and the count is what the cost is made of. A
// build that skips the dummy verify makes exactly zero of them.
func TestAnUnknownIdentifierStillPaysForAHash(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
		t.Fatal("an unknown identifier was accepted")
	}
	if h.hasher.verifies != 1 {
		t.Errorf("the hasher verified %d times for an unknown identifier, want 1; "+
			"skipping it is a timing oracle for account existence", h.hasher.verifies)
	}
	if h.hasher.hashes != 1 {
		t.Errorf("the dummy verifier was built %d times, want 1", h.hasher.hashes)
	}
}

// The dummy verifier is built ONCE and reused. A per-attempt build would double
// the cost of every unknown identifier and make it distinguishable again — in the
// other direction.
func TestTheDummyVerifierIsBuiltOnce(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	for range 3 {
		if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
			t.Fatal("an unknown identifier was accepted")
		}
	}
	if h.hasher.hashes != 1 {
		t.Errorf("built the dummy verifier %d times across 3 attempts, want 1", h.hasher.hashes)
	}
	if h.hasher.verifies != 3 {
		t.Errorf("verified %d times across 3 attempts, want 3", h.hasher.verifies)
	}
}

// The dummy verifier must be checked under the ids it was sealed with, or the
// real hasher returns before doing any Argon2id work.
//
// authHasher.Verify models exactly that: a mismatched pair is
// ErrVerifierUnreadable, never a plain false. So a build that passed zero ids
// would log the failure this asserts is absent.
func TestTheDummyVerifierIsCheckedUnderItsOwnIds(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
		t.Fatal("an unknown identifier was accepted")
	}
	if strings.Contains(h.logs.String(), "dummy verifier could not be checked") {
		t.Error("the dummy verify failed, so the unknown-identifier path did no hashing work")
	}
}

// Every refusal is the same refusal — message and reason both.
func TestEveryRefusalIsIdentical(t *testing.T) {
	cases := []struct {
		name    string
		arrange func(*authHarness)
		cmd     AuthenticateCommand
		reason  contract.FailureReason
	}{
		{
			name:    "unknown identifier",
			arrange: func(h *authHarness) { delete(h.accounts.rows, h.index) },
			cmd:     AuthenticateCommand{Password: testPassword, Code: authCode},
			reason:  contract.ReasonNoSuchIdentifier,
		},
		{
			name:    "wrong password",
			arrange: func(*authHarness) {},
			cmd:     AuthenticateCommand{Password: "not the password", Code: authCode},
			reason:  contract.ReasonWrongPassword,
		},
		{
			name: "no usable password credential",
			arrange: func(h *authHarness) {
				delete(h.credentials.rows, h.subjectID)
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonIncomplete,
		},
		{
			name: "deactivated account",
			arrange: func(h *authHarness) {
				mustDo(h.t, h.user.Deactivate(h.subjectID, testNow))
				h.user.ClearUncommitted()
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonDeactivated,
		},
		{
			name: "suspended account",
			arrange: func(h *authHarness) {
				mustDo(h.t, h.user.Suspend("operator", "fraud", testNow))
				h.user.ClearUncommitted()
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonSuspended,
		},
		{
			name:    "wrong second factor",
			arrange: func(*authHarness) {},
			cmd:     AuthenticateCommand{Password: testPassword, Code: "000000"},
			reason:  contract.ReasonWrongSecondFactor,
		},
		{
			name: "unproven authenticator",
			arrange: func(h *authHarness) {
				row := h.secrets.rows[h.subjectID]
				row.Enabled = false
				h.secrets.rows[h.subjectID] = row
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonWrongSecondFactor,
		},
		{
			name: "an authenticator the account's own log does not record",
			arrange: func(h *authHarness) {
				// The row is well-formed and opens cleanly; the aggregate simply has
				// no such credential. Only a check against the account's own events
				// catches it, which is the tampering the AAD binding makes expensive
				// rather than impossible.
				stray := ids.New[ids.Credential](testNow, h.entropy)
				h.secrets.rows[h.subjectID] = TotpSecret{
					ID:        stray,
					SubjectID: h.subjectID,
					Sealed:    "sealed:" + h.subjectID + ":" + stray.String() + ":" + authTotpSeed,
					Enabled:   true,
				}
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonWrongSecondFactor,
		},
		{
			// A locked-out authenticator must answer exactly what a wrong password
			// answers. If it did not, a lockout would be a signal an attacker could
			// read — "this account exists, has a password I got right, and I have
			// now taken its second factor away" — and the reply would confirm the
			// grind worked.
			name: "locked-out authenticator",
			arrange: func(h *authHarness) {
				if _, err := h.user.RecordAuthenticatorFailure(
					h.totpID, domain.LockoutThreshold, testNow,
				); err != nil {
					h.t.Fatalf("locking out the test authenticator: %v", err)
				}
				h.user.ClearUncommitted()
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonWrongSecondFactor,
		},
		{
			name: "unreadable verifier",
			arrange: func(h *authHarness) {
				row := h.credentials.rows[h.subjectID]
				row.Verifier = "argon2:someone-else:somewhere-else:" + testPassword
				h.credentials.rows[h.subjectID] = row
			},
			cmd:    AuthenticateCommand{Password: testPassword, Code: authCode},
			reason: contract.ReasonWrongPassword,
		},
	}

	// The reference is the plainest failure there is. Everything else must match
	// it exactly — a distinct message or reason anywhere in this table is an
	// oracle, and the whole point is that the caller cannot tell these apart.
	reference := func() error {
		h := newAuthHarness(t)
		_, err := h.login(AuthenticateCommand{Password: "wrong", Code: authCode})
		return err
	}()

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuthHarness(t)
			tc.arrange(h)

			_, err := h.login(tc.cmd)
			if err == nil {
				t.Fatal("the attempt was accepted")
			}
			if err.Error() != reference.Error() {
				t.Errorf("refusal is %q, want %q — a distinguishable refusal is an oracle",
					err.Error(), reference.Error())
			}
			if errs.ReasonOf(err) != errs.ReasonOf(reference) {
				t.Errorf("refusal reason is %s, want %s",
					errs.ReasonOf(err), errs.ReasonOf(reference))
			}
			// Every one of these paths costs exactly one password verification —
			// the real one, or the dummy standing in for it. A branch that returns
			// without paying it answers faster than a wrong password does, and the
			// difference is measurable from any network however uniform the wire
			// answer is.
			if h.hasher.verifies != 1 {
				t.Errorf("verified %d times, want 1: this refusal costs less than a wrong "+
					"password, so response time is the answer", h.hasher.verifies)
			}

			failed := eventOf[*contract.AuthenticationFailed](t, h.appender)
			if failed.Reason != tc.reason {
				t.Errorf("the event records reason %q, want %q; the distinction belongs in "+
					"the log and the event, and nowhere else", failed.Reason, tc.reason)
			}
			if failed.Index != h.index {
				t.Errorf("the event carries index %q, want %q — the stuffing signal is the "+
					"index", failed.Index, h.index)
			}
		})
	}
}

// An account state that refuses must still cost a password verification, or the
// response time answers "does this address have a suspended account?".
func TestARefusedAccountStateStillPaysForAHash(t *testing.T) {
	h := newAuthHarness(t)
	mustDo(t, h.user.Suspend("operator", "fraud", testNow))
	h.user.ClearUncommitted()

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err == nil {
		t.Fatal("a suspended account authenticated")
	}
	if h.hasher.verifies != 1 {
		t.Errorf("verified %d times for a suspended account, want 1: the state check must "+
			"come after the password, not before it", h.hasher.verifies)
	}
}

// The identifier that matched no account leaves an event with an EMPTY subject.
func TestAnUnknownIdentifierRecordsNoSubject(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
		t.Fatal("an unknown identifier was accepted")
	}
	failed := eventOf[*contract.AuthenticationFailed](t, h.appender)
	if failed.SubjectID != "" {
		t.Errorf("the event names subject %q; inventing one creates a permanent record "+
			"keyed to a person who does not exist here", failed.SubjectID)
	}
	if failed.Reason != contract.ReasonNoSuchIdentifier {
		t.Errorf("reason is %q, want %q", failed.Reason, contract.ReasonNoSuchIdentifier)
	}
	// The metadata must not name a subject either.
	for _, call := range h.appender.calls {
		for _, stream := range call {
			for _, e := range stream.Events {
				if len(e.Meta.SubjectIDs) != 0 || e.Meta.ActorID != "" {
					t.Errorf("the envelope names %v / %q for an identifier with no account",
						e.Meta.SubjectIDs, e.Meta.ActorID)
				}
			}
		}
	}
}

// The ceiling is consulted BEFORE the hasher, and a refusal stops there.
func TestTheCeilingIsConsultedBeforeTheHasher(t *testing.T) {
	h := newAuthHarness(t)
	h.limiter.allowed = false

	_, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err == nil {
		t.Fatal("a rate-limited attempt was accepted")
	}
	if errs.ReasonOf(err) != errs.Unauthenticated {
		t.Errorf("a rate-limited attempt answered %s; it must answer exactly what a wrong "+
			"password answers", errs.ReasonOf(err))
	}
	if h.hasher.verifies != 0 || h.hasher.hashes != 0 {
		t.Errorf("the hasher ran (%d hashes, %d verifies) for an attempt the ceiling refused; "+
			"the ceiling exists to stop work, and running it first makes the ceiling free "+
			"to defeat", h.hasher.hashes, h.hasher.verifies)
	}
	if len(h.limiter.scopes) != 1 || h.limiter.scopes[0] != string(h.index) {
		t.Errorf("the limiter was asked about %v, want one call scoped to the blind index",
			h.limiter.scopes)
	}
	// No append: an attempt refused by the ceiling is refused without limit, so one
	// event per refusal is an unbounded write to the log for an unauthenticated
	// caller.
	if len(h.appender.calls) != 0 {
		t.Errorf("a rate-limited attempt appended %d times, want 0", len(h.appender.calls))
	}
	if !strings.Contains(h.logs.String(), "refused by the attempt ceiling") {
		t.Error("a rate-limited attempt produced no log line, so the ceiling is invisible")
	}
}

// A limiter that cannot be consulted fails OPEN and the degradation is surfaced.
func TestADegradedCeilingIsSurfacedAndFailsOpen(t *testing.T) {
	h := newAuthHarness(t)
	h.limiter.err = errors.New("valkey is unreachable")

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("a degraded ceiling refused a correct login: %v", err)
	}
	if res.Proof.SubjectID() != h.subjectID {
		t.Errorf("the login produced no proof for %q", h.subjectID)
	}
	if !strings.Contains(h.logs.String(), "ceiling could not be evaluated") {
		t.Error("the ceiling failed open and said nothing; a ceiling that has silently " +
			"stopped counting is indistinguishable from one that is never reached")
	}
}

// A correct password with no code challenges rather than authenticating.
func TestACorrectPasswordAloneOnlyChallenges(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, DeviceID: "dev_1"})
	if err != nil {
		t.Fatalf("a correct password was refused: %v", err)
	}
	if !res.SecondFactorRequired {
		t.Fatal("a password alone completed an authentication")
	}
	if res.Proof.SubjectID() != "" || res.Proof.AAL() != contract.AAL0 {
		t.Error("a challenge returned a usable proof; password alone is AAL1 and must mint " +
			"no session")
	}
	if len(res.Offered) != 1 || res.Offered[0] != contract.MethodTOTP {
		t.Errorf("offered %v, want [totp]", res.Offered)
	}

	challenged := eventOf[*contract.SecondFactorChallenged](t, h.appender)
	if challenged.SubjectID != h.subjectID || challenged.DeviceID != "dev_1" {
		t.Errorf("the challenge event is %+v", challenged)
	}
	// A proof nobody produced mints nothing.
	if _, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	}); err == nil {
		t.Fatal("a session was minted from a challenge")
	}
}

// Password plus TOTP is AAL2, taken from domain.AALFor rather than a literal.
func TestPasswordAndCodeReachAAL2(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{
		Password: testPassword, Code: authCode, DeviceID: "dev_1",
	})
	if err != nil {
		t.Fatalf("a complete authentication was refused: %v", err)
	}
	if res.SecondFactorRequired {
		t.Fatal("a complete authentication asked for another factor")
	}
	if res.Proof.AAL() != contract.AAL2 {
		t.Errorf("the proof records AAL%d, want AAL2", res.Proof.AAL())
	}

	ok := eventOf[*contract.AuthenticationSucceeded](t, h.appender)
	if ok.AAL != domain.AALFor(ok.Methods) {
		t.Errorf("the event records AAL%d for methods %v, which AALFor calls AAL%d",
			ok.AAL, ok.Methods, domain.AALFor(ok.Methods))
	}
	if len(ok.Methods) != 2 ||
		ok.Methods[0] != contract.MethodPassword || ok.Methods[1] != contract.MethodTOTP {
		t.Errorf("the event records methods %v, want [password totp] in the order satisfied",
			ok.Methods)
	}
	// The password credential's consecutive-failure count is cleared by a success.
	if len(h.credentials.successes) != 2 {
		t.Errorf("recorded %d credential successes, want 2 (password and authenticator)",
			len(h.credentials.successes))
	}
}

// A replayed code is its own reason, and it is loud.
func TestAReplayedCodeIsRecordedAsOne(t *testing.T) {
	h := newAuthHarness(t)

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("the first presentation was refused: %v", err)
	}
	if _, err := h.login(AuthenticateCommand{
		Password: testPassword, Code: authCode, IdempotencyKey: "idem-second",
	}); err == nil {
		t.Fatal("a replayed code was accepted")
	}
	failed := eventOf[*contract.AuthenticationFailed](t, h.appender)
	if failed.Reason != contract.ReasonReplayedCode {
		t.Errorf("a replayed code was recorded as %q, want %q; a wrong code is a typo and a "+
			"replayed one means somebody has observed a real code",
			failed.Reason, contract.ReasonReplayedCode)
	}
	if !strings.Contains(h.logs.String(), "was replayed") {
		t.Error("a replayed code produced no log line")
	}
}

// A wrong password is counted against its credential; an unknown identifier
// cannot be.
func TestAWrongPasswordIsCountedAndAnUnknownOneIsNot(t *testing.T) {
	h := newAuthHarness(t)

	if _, err := h.login(AuthenticateCommand{Password: "wrong", Code: authCode}); err == nil {
		t.Fatal("a wrong password was accepted")
	}
	if len(h.credentials.failures) != 1 || h.credentials.failures[0] != h.credID {
		t.Errorf("counted failures %v, want one against %s", h.credentials.failures, h.credID)
	}

	other := newAuthHarness(t)
	delete(other.accounts.rows, other.index)
	if _, err := other.login(AuthenticateCommand{Password: testPassword}); err == nil {
		t.Fatal("an unknown identifier was accepted")
	}
	if len(other.credentials.failures) != 0 {
		t.Errorf("counted %d failures for an identifier with no credential; inventing one "+
			"creates a row that reveals the account does not exist",
			len(other.credentials.failures))
	}
}

// Nothing secret reaches an event.
func TestNoAppendedEventCarriesASecret(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, DeviceID: "dev_1", IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	secrets := map[string]string{
		"the password":     testPassword,
		"the TOTP code":    authCode,
		"the TOTP secret":  authTotpSeed,
		"the bearer token": session.Token,
		"the address":      testEmail,
	}
	for _, e := range h.appender.events() {
		rendered := fmt.Sprintf("%+v", e)
		for name, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Errorf("%s appears in %s: %s", name, e.EventType(), rendered)
			}
		}
	}
	// The same rule for the log.
	logged := h.logs.String()
	for name, secret := range secrets {
		if secret == testEmail && strings.Contains(logged, "@") {
			t.Errorf("an address reached the log: %s", logged)
		}
		if strings.Contains(logged, secret) {
			t.Errorf("%s appears in the log", name)
		}
	}
}

// The attempt journal is keyed by the blind index, so an attempt against an
// address with no account still has a stream — and it never contends.
// The attempt journal is keyed by DATE, so an unauthenticated caller cannot
// choose a stream name.
//
// Keying it by the identifier is the obvious design and it is unsafe: the stream
// name would then come from whoever posts the login form, so guessing addresses
// creates one permanent stream per guess. KurrentDB's delete is a soft delete,
// every name lands in `$streams` and the category stream, and every projector's
// `$all` scan grows with them. The attempt ceiling does not stop it — it bounds
// the rate, not the total, and it fails open by design.
func TestAttemptsAreJournalledUnderTheDateNotTheIdentifier(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
		t.Fatal("an unknown identifier was accepted")
	}
	streams := h.appender.streams()
	if len(streams) != 1 {
		t.Fatalf("appended to %d streams, want 1", len(streams))
	}
	want, err := eventsourcing.NewStreamID(AttemptCategory, attemptStreamKey(h.clock.Now()))
	if err != nil {
		t.Fatalf("building the expected stream: %v", err)
	}
	if streams[0] != want {
		t.Errorf("appended to %s, want %s", streams[0], want)
	}
	// The stream name must not contain the thing the caller supplied. Asserted
	// directly, because "it is keyed by the date" and "it does not contain the
	// index" can drift apart if somebody later appends the index for readability.
	if strings.Contains(string(streams[0]), string(h.index)) {
		t.Errorf("the stream name %s carries the attempted identifier, so a caller "+
			"chooses stream names by choosing addresses", streams[0])
	}
	if !h.appender.calls[0][0].Expected.IsAny() {
		t.Errorf("the attempt journal appended with precondition %s; simultaneous "+
			"attempts must all be recorded, and every attempt in the system now shares "+
			"one stream per day, so a precondition here would serialise every login",
			h.appender.calls[0][0].Expected)
	}
}

// Two different identifiers share one stream, and the identifier still reaches
// the read model.
//
// The second half is what makes the first half safe to do: credential-stuffing
// detection counts by `email_index` in `login_history_view`, which is a PROJECTED
// COLUMN fed by the event. Moving the identifier out of the stream NAME costs
// nothing there — but only while the event still carries it, which is what this
// asserts.
func TestOneDaysAttemptsShareOneStreamAndStillNameTheirIdentifier(t *testing.T) {
	h := newAuthHarness(t)
	delete(h.accounts.rows, h.index)

	for _, email := range []string{"alice@example.com", "mallory@elsewhere.test"} {
		if _, err := h.login(AuthenticateCommand{
			Identifier: email, Password: testPassword, IdempotencyKey: "cmd-" + email,
		}); err == nil {
			t.Fatalf("%s was accepted with no account", email)
		}
	}

	seen := map[eventsourcing.StreamID]bool{}
	for _, s := range h.appender.streams() {
		seen[s] = true
	}
	if len(seen) != 1 {
		t.Errorf("two identifiers produced %d streams; an attacker creates one permanent "+
			"stream per address they guess", len(seen))
	}

	var indexed int
	for _, call := range h.appender.calls {
		for _, a := range call {
			for _, e := range a.Events {
				if f, ok := e.Event.(*contract.AuthenticationFailed); ok && f.Index != "" {
					indexed++
				}
			}
		}
	}
	if indexed != 2 {
		t.Errorf("%d of 2 failures carry an email index; without it credential-stuffing "+
			"detection cannot count attempts per address", indexed)
	}
}

// A breached password does not block the login; it restricts the session.
func TestABreachedPasswordRestrictsTheSessionRatherThanBlockingIt(t *testing.T) {
	h := newAuthHarness(t)
	h.breach.breached = true
	h.breach.corpus = "hibp"

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("a breached password blocked the login: %v", err)
	}
	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}
	if !session.RequiresCredentialRotation {
		t.Error("a session established with a breached password is unrestricted")
	}
	created := eventOf[*contract.SessionCreated](t, h.appender)
	if !created.RequiresCredentialRotation {
		t.Error("SessionCreated does not record the rotation requirement, so a rebuild " +
			"loses it")
	}
}

// An unreachable breach corpus never blocks a login.
func TestAnUnreachableBreachCorpusDoesNotBlockALogin(t *testing.T) {
	h := newAuthHarness(t)
	h.breach.err = errors.New("hibp is unreachable")

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("an unreachable corpus blocked a correct login: %v", err)
	}
	if !strings.Contains(h.logs.String(), "breach screening did not run") {
		t.Error("screening was skipped silently")
	}
}

// An outage in the lookup is NOT reported as a wrong password.
func TestALookupOutageIsNotALoginFailure(t *testing.T) {
	h := newAuthHarness(t)
	h.accounts.err = errors.New("the database is unreachable")

	_, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err == nil {
		t.Fatal("an outage produced a successful login")
	}
	if errs.ReasonOf(err) == errs.Unauthenticated {
		t.Error("a database outage was reported as a failed authentication; a global wave " +
			"of them then looks like user error and is investigated as such")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("an outage appended %d times, want 0", len(h.appender.calls))
	}
}

// ---------------------------------------------------------------------------
// CreateSession
// ---------------------------------------------------------------------------

// The append comes first and the token row second.
func TestSessionCreatedIsAppendedBeforeTheTokenRow(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	h.journal = nil
	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, DeviceID: "dev_1", IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	if len(h.journal) != 2 || h.journal[0] != "append" || h.journal[1] != "token" {
		t.Fatalf("the order was %v, want [append token]; a token row written first survives "+
			"a crash as a digest SweepSessionTokens can never find, because the sweep joins "+
			"session_view", h.journal)
	}
	if len(h.tokens.issued) != 1 {
		t.Fatalf("issued %d token rows, want 1", len(h.tokens.issued))
	}
	issued := h.tokens.issued[0]
	if issued.SessionID != session.SessionID {
		t.Errorf("the token row names session %s, want %s", issued.SessionID, session.SessionID)
	}
	if !bytes.Equal(issued.Digest, SessionTokenDigest(session.Token)) {
		t.Error("the stored digest is not the digest of the token the caller was handed")
	}
	if strings.Contains(fmt.Sprintf("%+v", h.appender.events()), session.Token) {
		t.Error("the bearer token reached an event")
	}
}

// The token is 256 bits of entropy, stored only as a digest.
func TestTheSessionTokenIsFullEntropyAndOnlyStoredAsADigest(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	raw, err := base64.RawURLEncoding.DecodeString(session.Token)
	if err != nil {
		t.Fatalf("the token is not base64url: %v", err)
	}
	// An absolute floor, not len(raw) != sessionTokenBytes: an assertion that
	// follows its own constant is satisfied by halving the constant.
	if len(raw) < 32 {
		t.Errorf("the token carries %d bytes, want at least 32", len(raw))
	}
	if bytes.Contains([]byte(session.Token), h.tokens.issued[0].Digest) {
		t.Error("the token contains its own digest")
	}
}

// The digest is domain-separated, so it cannot collide with any other SHA-256
// this system stores.
func TestTheSessionTokenDigestIsDomainSeparated(t *testing.T) {
	plain := sha256.Sum256([]byte("a-token"))
	if bytes.Equal(SessionTokenDigest("a-token"), plain[:]) {
		t.Error("the digest is a bare SHA-256 of the token, so a digest from any other " +
			"scheme over the same bytes is interchangeable with it")
	}
	// The separator is length-prefixed, so no shift of the boundary produces a
	// collision. Checked by construction: the digest of a token is not the digest
	// of the token with the last separator byte moved into it.
	if bytes.Equal(SessionTokenDigest("x"), SessionTokenDigest("1x")) {
		t.Error("two different tokens share a digest")
	}
	if len(SessionTokenDigest("x")) != 32 {
		t.Errorf("the digest is %d bytes, want 32", len(SessionTokenDigest("x")))
	}
}

// A proof nobody produced mints nothing, and neither does a stale or weak one.
func TestOnlyAFreshAAL2ProofMintsASession(t *testing.T) {
	valid := func(h *authHarness) Proof {
		res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
		if err != nil {
			t.Fatalf("authenticating: %v", err)
		}
		return res.Proof
	}

	cases := []struct {
		name  string
		proof func(*authHarness) Proof
		after time.Duration
	}{
		{
			name:  "the zero proof",
			proof: func(*authHarness) Proof { return Proof{} },
		},
		{
			name: "a proof below AAL2",
			proof: func(h *authHarness) Proof {
				p := valid(h)
				p.aal = contract.AAL1
				return p
			},
		},
		{
			name: "a proof with no subject",
			proof: func(h *authHarness) Proof {
				p := valid(h)
				p.subjectID = ""
				return p
			},
		},
		{
			name:  "a stale proof",
			proof: valid,
			after: DefaultProofWindow + time.Second,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuthHarness(t)
			proof := tc.proof(h)
			h.clock.Advance(tc.after)
			before := len(h.appender.calls)

			_, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
				Proof: proof, IdempotencyKey: "idem-session",
			})
			if err == nil {
				t.Fatal("a session was minted")
			}
			if errs.ReasonOf(err) != errs.Unauthenticated {
				t.Errorf("refused with %s, want UNAUTHENTICATED", errs.ReasonOf(err))
			}
			if len(h.appender.calls) != before {
				t.Error("a refused session was appended anyway")
			}
			if len(h.tokens.issued) != 0 {
				t.Error("a refused session issued a token row")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The first enrolment
// ---------------------------------------------------------------------------

// bootstrapAccount replaces the harness's active account with one that has just
// verified its address and has no second factor: the state every account passes
// through, and the only one a password-only authentication is honoured in.
//
// The TOTP secret is removed as well, so the fixture cannot pass a second factor
// even by accident — an account that still had one would exercise the ordinary
// path and the tests below would prove nothing.
func (h *authHarness) bootstrapAccount(t *testing.T) *domain.User {
	t.Helper()
	u := eventsourcing.NewAggregate(domain.New)
	mustDo(t, u.Register(h.userID, h.subjectID, h.index, testNow))
	mustDo(t, u.VerifyEmail(h.index, testNow))
	mustDo(t, u.SetPassword(h.credID, testNow))
	if u.State() != domain.StatePending {
		t.Fatalf("the bootstrap fixture is %s, want pending", u.State())
	}
	u.ClearUncommitted()
	h.user = u
	delete(h.secrets.rows, h.subjectID)
	return u
}

// An account enrolling its first factor authenticates on its password alone, and
// the session it earns records AAL1.
//
// This is the whole point of the mechanism: the account can now reach EnrollTotp
// and ConfirmTotp, which declare a bootstrap floor of AAL1, and nothing else that
// asks for AAL2.
func TestAFirstEnrolmentAuthenticatesOnOneFactorAndMintsAnAAL1Session(t *testing.T) {
	h := newAuthHarness(t)
	h.bootstrapAccount(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, DeviceID: "dev_1"})
	if err != nil {
		t.Fatalf("an account with no second factor could not authenticate to enrol one: %v\n%s",
			err, h.logs.String())
	}
	if res.SecondFactorRequired {
		t.Fatal("the account was challenged for a second factor it has no way to obtain")
	}
	if res.Proof.AAL() != contract.AAL1 {
		t.Fatalf("the proof records AAL%d, want AAL1: a password alone is one factor and the "+
			"session must say so", res.Proof.AAL())
	}
	if res.Proof.SubjectID() != h.subjectID {
		t.Fatalf("the proof names %q, want %q", res.Proof.SubjectID(), h.subjectID)
	}

	// The journal records it as what it is: a completed authentication at AAL1,
	// with the level taken from AALFor over the methods actually used.
	ok := eventOf[*contract.AuthenticationSucceeded](t, h.appender)
	if ok.AAL != contract.AAL1 || ok.AAL != domain.AALFor(ok.Methods) {
		t.Errorf("the event records AAL%d for methods %v, which AALFor calls AAL%d",
			ok.AAL, ok.Methods, domain.AALFor(ok.Methods))
	}
	if len(ok.Methods) != 1 || ok.Methods[0] != contract.MethodPassword {
		t.Errorf("the event records methods %v, want [password]", ok.Methods)
	}

	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, DeviceID: "dev_1", IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("a first-enrolment proof minted no session: %v", err)
	}
	if session.AAL != contract.AAL1 {
		t.Fatalf("the session records AAL%d, want AAL1", session.AAL)
	}
	if session.Token == "" {
		t.Error("the session carries no bearer token, so it can never be presented")
	}
	created := eventOf[*contract.SessionCreated](t, h.appender)
	if created.AAL != contract.AAL1 {
		t.Errorf("the appended session records AAL%d, want AAL1", created.AAL)
	}
	if len(h.tokens.issued) != 1 {
		t.Errorf("issued %d token rows, want 1", len(h.tokens.issued))
	}
}

// An account that already has a second factor is never handed a one-factor
// session.
//
// This is the stolen-password attack at the layer that mints the session. The
// gate refuses the enrolment for such an account too, but the two defences are
// independent on purpose: an attacker who could obtain an AAL1 session on an
// established account would be one policy edit away from using it.
func TestAnAccountWithASecondFactorIsNeverHandedAOneFactorSession(t *testing.T) {
	h := newAuthHarness(t) // the default fixture is Active with a proven TOTP

	res, err := h.login(AuthenticateCommand{Password: testPassword, DeviceID: "dev_1"})
	if err != nil {
		t.Fatalf("a correct password was refused: %v", err)
	}
	if !res.SecondFactorRequired {
		t.Fatal("an account that HAS a second factor completed an authentication without it")
	}
	if res.Proof.AAL() != contract.AAL0 || res.Proof.SubjectID() != "" {
		t.Fatalf("an incomplete authentication produced a usable proof at AAL%d",
			res.Proof.AAL())
	}
	if _, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	}); err == nil {
		t.Fatal("a session was minted for an account that did not present its second factor")
	}
}

// The states a password-only authentication is NOT honoured in.
//
// Each row is a way the exemption could be widened by accident, and each is
// refused with the ordinary undifferentiated error — the account state is never
// distinguishable on the wire (ADR-036).
func TestOnlyAVerifiedNeverEnrolledAccountAuthenticatesOnOneFactor(t *testing.T) {
	for _, tc := range []struct {
		name    string
		account func(*testing.T, *authHarness)
	}{
		{
			name: "the address was never verified",
			account: func(t *testing.T, h *authHarness) {
				u := eventsourcing.NewAggregate(domain.New)
				mustDo(t, u.Register(h.userID, h.subjectID, h.index, testNow))
				// Applied as a raw EVENT rather than taken as a decision, because
				// the decision is now refused: an unverified account cannot be
				// given a password (IDENTITY-REVIEW C8). The state is still
				// reachable by replay — every account registered before that rule
				// existed has exactly this shape — so this case asserts that
				// CanAuthenticate refuses it on its own, without relying on the
				// newer rule having prevented it from ever being written.
				u.Apply(&contract.PasswordSet{
					SubjectID:    h.subjectID,
					CredentialID: h.credID.String(),
					SetAt:        testNow,
				})
				u.ClearUncommitted()
				h.user = u
				delete(h.secrets.rows, h.subjectID)
			},
		},
		{
			name: "the account has held a factor and lost it",
			account: func(t *testing.T, h *authHarness) {
				// Pending, verified, no primary — so DisableTotp is permitted and the
				// account ends with no usable second factor while having proven one.
				u := eventsourcing.NewAggregate(domain.New)
				mustDo(t, u.Register(h.userID, h.subjectID, h.index, testNow))
				mustDo(t, u.VerifyEmail(h.index, testNow))
				mustDo(t, u.StartTotpEnrollment(h.totpID, testNow.Add(time.Hour), testNow))
				mustDo(t, u.EnableTotp(h.totpID, testNow))
				mustDo(t, u.DisableTotp(h.totpID, h.subjectID, testNow))
				// The password LAST, so the account never holds a primary and a
				// real second factor at the same instant — which would make it
				// Active and put DisableTotp behind the "keep one factor" rule.
				mustDo(t, u.SetPassword(h.credID, testNow))
				u.ClearUncommitted()
				h.user = u
				delete(h.secrets.rows, h.subjectID)
			},
		},
		{
			name: "the account's only second factor is locked out",
			account: func(t *testing.T, h *authHarness) {
				// Active, so it HAS held a factor — and a lockout has just taken the
				// last one away, which leaves it with nothing to offer. That is the
				// state a rule written as "offer nothing, so bootstrap" would confuse
				// with a first enrolment, and it must not: this account's factor
				// exists, is registered in its log, and is being ground by somebody.
				locked, err := h.user.RecordAuthenticatorFailure(
					h.totpID, domain.LockoutThreshold, testNow)
				mustDo(t, err)
				if !locked {
					t.Fatal("the fixture did not lock the authenticator out")
				}
				h.user.ClearUncommitted()
				delete(h.secrets.rows, h.subjectID)
			},
		},
		{
			name: "the account is deactivated",
			account: func(t *testing.T, h *authHarness) {
				mustDo(t, h.user.Deactivate(h.subjectID, testNow))
				h.user.ClearUncommitted()
				delete(h.secrets.rows, h.subjectID)
			},
		},
		{
			name: "the account is suspended",
			account: func(t *testing.T, h *authHarness) {
				mustDo(t, h.user.Suspend("op_1", "abuse", testNow))
				h.user.ClearUncommitted()
				delete(h.secrets.rows, h.subjectID)
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuthHarness(t)
			tc.account(t, h)

			res, err := h.login(AuthenticateCommand{Password: testPassword})
			if err == nil {
				t.Fatalf("a one-factor authentication succeeded at AAL%d for an account that "+
					"may not have one", res.Proof.AAL())
			}
			if errs.ReasonOf(err) != errs.Unauthenticated {
				t.Errorf("refused with %s, want UNAUTHENTICATED", errs.ReasonOf(err))
			}
			if len(h.tokens.issued) != 0 {
				t.Error("a refused authentication issued a session token")
			}
		})
	}
}

// The AAL1 carve-out is reachable ONLY through a proof this package marked as a
// first enrolment.
//
// `bootstrap` is unexported, so no caller can set it; what this pins is the
// other half — that CreateSession consults the mark rather than inferring it
// from the level, and that a mark without the level is refused rather than
// honoured.
func TestOnlyAMarkedFirstEnrolmentMintsBelowAAL2(t *testing.T) {
	bootstrapProof := func(h *authHarness) Proof {
		h.bootstrapAccount(t)
		res, err := h.login(AuthenticateCommand{Password: testPassword})
		if err != nil {
			t.Fatalf("authenticating a first enrolment: %v", err)
		}
		return res.Proof
	}

	for _, tc := range []struct {
		name  string
		proof func(*authHarness) Proof
		want  errs.Reason
	}{
		{
			name: "an ordinary AAL1 proof, unmarked",
			proof: func(h *authHarness) Proof {
				p := bootstrapProof(h)
				p.bootstrap = false
				return p
			},
			want: errs.Unauthenticated,
		},
		{
			name: "a first enrolment claiming AAL2",
			proof: func(h *authHarness) Proof {
				p := bootstrapProof(h)
				p.aal = contract.AAL2
				return p
			},
			want: errs.Internal,
		},
		{
			name: "a first enrolment claiming a level no session may record",
			proof: func(h *authHarness) Proof {
				p := bootstrapProof(h)
				p.aal = contract.AAL0
				return p
			},
			want: errs.Unauthenticated,
		},
		{
			name: "a stale first enrolment",
			proof: func(h *authHarness) Proof {
				p := bootstrapProof(h)
				p.at = testNow.Add(-DefaultProofWindow - time.Second)
				return p
			},
			want: errs.Unauthenticated,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuthHarness(t)
			proof := tc.proof(h)
			before := len(h.appender.calls)

			if _, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
				Proof: proof, IdempotencyKey: "idem-session",
			}); err == nil {
				t.Fatal("a session was minted")
			} else if errs.ReasonOf(err) != tc.want {
				t.Errorf("refused with %s, want %s", errs.ReasonOf(err), tc.want)
			}
			if len(h.appender.calls) != before {
				t.Error("a refused session was appended anyway")
			}
			if len(h.tokens.issued) != 0 {
				t.Error("a refused session issued a token row")
			}
		})
	}
}

// A session records both deadlines, and the idle one never exceeds the absolute.
func TestASessionCarriesBothDeadlines(t *testing.T) {
	h := newAuthHarness(t)

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	session, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	})
	if err != nil {
		t.Fatalf("creating a session: %v", err)
	}

	if !session.IdleExpiresAt.Equal(testNow.Add(DefaultIdleWindow)) {
		t.Errorf("idle deadline is %s, want %s",
			session.IdleExpiresAt, testNow.Add(DefaultIdleWindow))
	}
	if !session.AbsoluteExpiresAt.Equal(testNow.Add(DefaultAbsoluteWindow)) {
		t.Errorf("absolute deadline is %s, want %s",
			session.AbsoluteExpiresAt, testNow.Add(DefaultAbsoluteWindow))
	}
	if session.IdleExpiresAt.After(session.AbsoluteExpiresAt) {
		t.Error("the idle deadline outlives the absolute one, so it never fires")
	}
	if !h.tokens.issued[0].IdleExpiresAt.Equal(session.IdleExpiresAt) {
		t.Error("the token row's idle deadline differs from the session's")
	}
	created := eventOf[*contract.SessionCreated](t, h.appender)
	if created.AAL != contract.AAL2 {
		t.Errorf("SessionCreated records AAL%d, want AAL2", created.AAL)
	}
}

// A failure to store the token is reported, not swallowed.
func TestAFailedTokenWriteIsReported(t *testing.T) {
	h := newAuthHarness(t)
	h.tokens.err = errors.New("the database is unreachable")

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err != nil {
		t.Fatalf("authenticating: %v", err)
	}
	if _, err := h.auth.CreateSession(context.Background(), CreateSessionCommand{
		Proof: res.Proof, IdempotencyKey: "idem-session",
	}); err == nil {
		t.Fatal("a session with no token was reported as a success; the caller would hold " +
			"a token that resolves to nothing")
	}
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

func (h *authHarness) liveSession(t *testing.T, subjectID string) ids.SessionID {
	t.Helper()
	id := ids.New[ids.Session](testNow, h.entropy)
	session := eventsourcing.NewAggregate(domain.NewSession)
	if err := session.Create(id, subjectID, "dev_1", contract.AAL2,
		testNow.Add(time.Hour), testNow.Add(24*time.Hour), testNow, false); err != nil {
		t.Fatalf("building a session: %v", err)
	}
	session.ClearUncommitted()
	h.sessions[id.String()] = session
	return id
}

func TestRevokeSessionAppendsARevocation(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)

	res, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, Reason: "signed out",
		IdempotencyKey: "idem-revoke",
	})
	if err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if !res.Changed {
		t.Error("the revocation reported no change")
	}
	revoked := eventOf[*contract.SessionRevoked](t, h.appender)
	if revoked.SessionID != id.String() || revoked.SubjectID != h.subjectID {
		t.Errorf("the event is %+v", revoked)
	}
	if revoked.ActorID != h.subjectID {
		t.Errorf("the actor is %q, want the subject when none was named", revoked.ActorID)
	}
	streams := h.appender.streams()
	want, err := eventsourcing.NewStreamID(SessionCategory, id.String())
	if err != nil {
		t.Fatalf("building the expected stream: %v", err)
	}
	if len(streams) != 1 || streams[0] != want {
		t.Errorf("appended to %v, want %s", streams, want)
	}
}

// A session belonging to somebody else is a NotFound, and nothing is appended.
func TestRevokingAnotherSubjectsSessionIsANotFound(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, "subj_someone_else")

	_, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
	})
	if err == nil {
		t.Fatal("one subject revoked another's session")
	}
	if errs.ReasonOf(err) != errs.NotFound {
		t.Errorf("refused with %s, want NOT_FOUND — a session id is not a secret, so any "+
			"other answer turns the device list into a probe", errs.ReasonOf(err))
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("appended %d times for a session that is not the caller's", len(h.appender.calls))
	}

	// An unknown session id must produce the SAME answer.
	unknown := ids.New[ids.Session](testNow, h.entropy)
	_, other := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: unknown, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke-2",
	})
	if other == nil || other.Error() != err.Error() {
		t.Errorf("an unknown session answered %v and somebody else's answered %v", other, err)
	}
}

// Revoking twice appends once.
func TestRevokingTwiceAppendsOnce(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)

	for range 2 {
		if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
			SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
		}); err != nil {
			t.Fatalf("revoking: %v", err)
		}
	}
	if len(h.appender.calls) != 1 {
		t.Errorf("appended %d times for two revocations of one session, want 1",
			len(h.appender.calls))
	}
}

// "Sign out everywhere else" spares exactly one session, in one atomic append.
func TestRevokeAllSparesOnlyTheNamedSession(t *testing.T) {
	h := newAuthHarness(t)
	keep := h.liveSession(t, h.subjectID)
	first := h.liveSession(t, h.subjectID)
	second := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{keep, first, second}

	res, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, Except: keep, Reason: "password changed",
		IdempotencyKey: "idem-revoke-all",
	})
	if err != nil {
		t.Fatalf("revoking all: %v", err)
	}
	if res.Revoked != 2 || res.Scanned != 3 {
		t.Errorf("revoked %d of %d scanned, want 2 of 3", res.Revoked, res.Scanned)
	}
	if len(h.appender.calls) != 1 {
		t.Fatalf("appended %d times, want 1: a half-completed sign-out-everywhere is worse "+
			"than one that failed", len(h.appender.calls))
	}
	if len(h.appender.calls[0]) != 2 {
		t.Fatalf("the append covered %d streams, want 2", len(h.appender.calls[0]))
	}
	for _, e := range h.appender.events() {
		revoked, ok := e.(*contract.SessionRevoked)
		if !ok {
			t.Fatalf("appended %s, want only SessionRevoked", e.EventType())
		}
		if revoked.SessionID == keep.String() {
			t.Error("the spared session was revoked; \"sign out everywhere else\" must not " +
				"sign the caller out of the device they are asking from")
		}
	}
	// Every event id is distinct, so the store cannot collapse one revocation into
	// another.
	seen := map[string]bool{}
	for _, stream := range h.appender.calls[0] {
		for _, e := range stream.Events {
			if seen[e.ID.String()] {
				t.Errorf("two events share id %s", e.ID)
			}
			seen[e.ID.String()] = true
		}
	}
}

// A password reset spares nothing.
func TestRevokeAllWithNoExceptionRevokesEverything(t *testing.T) {
	h := newAuthHarness(t)
	first := h.liveSession(t, h.subjectID)
	second := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{first, second}

	res, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, ActorID: "operator", Reason: "password reset",
		IdempotencyKey: "idem-reset",
	})
	if err != nil {
		t.Fatalf("revoking all: %v", err)
	}
	if res.Revoked != 2 {
		t.Errorf("revoked %d sessions, want 2; a reset voids every session including the "+
			"one that asked, because the acting party may be the attacker", res.Revoked)
	}
	for _, e := range h.appender.events() {
		if revoked, ok := e.(*contract.SessionRevoked); ok && revoked.ActorID != "operator" {
			t.Errorf("the actor is %q, want the one named by the command", revoked.ActorID)
		}
	}
}

// A session the projection attributes to the wrong subject is skipped, loudly.
func TestRevokeAllSkipsASessionWhoseStreamDisagrees(t *testing.T) {
	h := newAuthHarness(t)
	mine := h.liveSession(t, h.subjectID)
	theirs := h.liveSession(t, "subj_someone_else")
	h.live.sessions = []ids.SessionID{mine, theirs}

	res, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-revoke-all",
	})
	if err != nil {
		t.Fatalf("revoking all: %v", err)
	}
	if res.Revoked != 1 {
		t.Errorf("revoked %d sessions, want 1; the stream wins over the projection", res.Revoked)
	}
	if !strings.Contains(h.logs.String(), "belongs to another on its own stream") {
		t.Error("a projection that disagrees with the log was skipped silently")
	}
}

// A work list that cannot be read is an error, never an empty sign-out.
func TestRevokeAllReportsAnUnreadableWorkList(t *testing.T) {
	h := newAuthHarness(t)
	h.live.err = errors.New("the database is unreachable")

	if _, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, IdempotencyKey: "idem-revoke-all",
	}); err == nil {
		t.Fatal("an unreadable work list reported a successful sign-out of nothing")
	}
}

// ---------------------------------------------------------------------------
// Revocation invalidates cached authorization (ADR-045, S1-26)
// ---------------------------------------------------------------------------
//
// A revoked session stops resolving on its own once the projection applies
// SessionRevoked. The authorization decision cache does not: it is keyed by
// principal and resource and knows nothing about the session that earned the
// permit, so without an epoch bump a cached permit keeps authorizing for up to
// authz.MaxDecisionTTL after the user pressed the button. Each case below fails if
// that bump is removed, aimed at the wrong principal, ordered after the append, or
// reduced to a log line.

// The bump names the SUBJECT as a user principal — the same shape the
// authenticator puts in authz.Principal, which is what every cached permit is
// keyed under.
func TestRevokingASessionInvalidatesTheSubjectsCachedDecisions(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)

	if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if len(h.epochs.bumped) != 1 {
		t.Fatalf("bumped %d epochs, want 1: without it a permit cached for this principal "+
			"keeps authorizing after the session is gone", len(h.epochs.bumped))
	}
	want := authz.Principal{Kind: authz.KindUser, ID: h.subjectID}
	if h.epochs.bumped[0] != want {
		t.Errorf("invalidated %+v, want %+v", h.epochs.bumped[0], want)
	}
}

// The invalidation comes FIRST. If it fails, nothing may be in the log: the retry
// then redoes both, whereas a retry against an already-revoked session appends
// nothing and would never reach the invalidation that failed.
func TestTheEpochIsBumpedBeforeTheRevocationIsAppended(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)
	h.journal = nil

	if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if len(h.journal) != 2 || h.journal[0] != "epoch" || h.journal[1] != "append" {
		t.Errorf("the journal is %v, want [epoch append]: an append that outlives a failed "+
			"invalidation can never be retried into one, because the retry finds the "+
			"session already revoked and appends nothing", h.journal)
	}
}

// The SESSION's owner is invalidated, never the actor. An operator or a password
// reset revokes on somebody else's behalf, and flushing the actor's cache would
// leave the revoked subject's permits live while reporting success.
func TestRevocationInvalidatesTheSessionOwnerRatherThanTheActor(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)

	if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, ActorID: "operator",
		IdempotencyKey: "idem-revoke",
	}); err != nil {
		t.Fatalf("revoking: %v", err)
	}
	if len(h.epochs.bumped) != 1 || h.epochs.bumped[0].ID != h.subjectID {
		t.Errorf("invalidated %+v, want the session's own subject %q",
			h.epochs.bumped, h.subjectID)
	}
}

// A revocation whose cache invalidation failed is REFUSED, not logged. Reporting
// success would tell somebody responding to a compromise that they are signed out
// while a cached permit still authorizes them.
func TestARevocationIsRefusedWhenTheCacheCannotBeInvalidated(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)
	h.epochs.err = errors.New("valkey is unreachable")

	_, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
	})
	if err == nil {
		t.Fatal("a revocation that could not invalidate the decision cache reported success")
	}
	if errs.ReasonOf(err) != errs.Internal {
		t.Errorf("refused with %s, want INTERNAL", errs.ReasonOf(err))
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("appended %d times despite a failed invalidation; the retry would then find "+
			"the session already revoked and never bump the epoch", len(h.appender.calls))
	}
	if !strings.Contains(h.logs.String(), "could not be invalidated") {
		t.Error("the failed invalidation left no log line to alert on")
	}
	if strings.Contains(h.logs.String(), testEmail) {
		t.Error("an address reached the log; only pseudonyms may (ADR-002)")
	}
}

// "Sign out everywhere else" invalidates once, for the principal, INCLUDING the
// session it spared: the cache is keyed by principal, so there is no per-session
// entry that could be kept, and the spared session simply recomputes.
func TestRevokeAllInvalidatesOnceIncludingTheSparedSession(t *testing.T) {
	h := newAuthHarness(t)
	keep := h.liveSession(t, h.subjectID)
	first := h.liveSession(t, h.subjectID)
	second := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{keep, first, second}
	h.journal = nil

	if _, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, Except: keep, IdempotencyKey: "idem-revoke-all",
	}); err != nil {
		t.Fatalf("revoking all: %v", err)
	}
	want := authz.Principal{Kind: authz.KindUser, ID: h.subjectID}
	if len(h.epochs.bumped) != 1 || h.epochs.bumped[0] != want {
		t.Fatalf("invalidated %+v, want exactly one bump of %+v", h.epochs.bumped, want)
	}
	if len(h.journal) != 2 || h.journal[0] != "epoch" || h.journal[1] != "append" {
		t.Errorf("the journal is %v, want [epoch append]", h.journal)
	}
}

// A password reset is what calls this, and it must not be able to end every
// session while leaving that principal's cached permits live.
func TestRevokeAllIsRefusedWhenTheCacheCannotBeInvalidated(t *testing.T) {
	h := newAuthHarness(t)
	first := h.liveSession(t, h.subjectID)
	second := h.liveSession(t, h.subjectID)
	h.live.sessions = []ids.SessionID{first, second}
	h.epochs.err = errors.New("valkey is unreachable")

	res, err := h.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: h.subjectID, Reason: "password reset", IdempotencyKey: "idem-reset",
	})
	if err == nil {
		t.Fatal("a password reset signed every session out and reported success without " +
			"invalidating the decision cache")
	}
	if res.Revoked != 0 {
		t.Errorf("reported %d revocations on a failed call", res.Revoked)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("appended %d times despite a failed invalidation", len(h.appender.calls))
	}
}

// Nothing to revoke invalidates nothing. A bump is harmless but not free, and a
// call that appended no event has revoked nobody.
func TestARevocationThatChangesNothingInvalidatesNothing(t *testing.T) {
	h := newAuthHarness(t)
	id := h.liveSession(t, h.subjectID)

	for range 2 {
		if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
			SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
		}); err != nil {
			t.Fatalf("revoking: %v", err)
		}
	}
	if len(h.epochs.bumped) != 1 {
		t.Errorf("bumped %d epochs for two revocations of one session, want 1",
			len(h.epochs.bumped))
	}

	// Somebody else's session is a NotFound, and must not flush the caller's cache
	// either: that would make the device list a way to evict another principal's
	// permits at will.
	theirs := h.liveSession(t, "subj_someone_else")
	if _, err := h.auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: theirs, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke-2",
	}); err == nil {
		t.Fatal("one subject revoked another's session")
	}
	if len(h.epochs.bumped) != 1 {
		t.Errorf("bumped %d epochs, want 1: a refused revocation invalidates nothing",
			len(h.epochs.bumped))
	}

	// An empty work list is the same: nothing was revoked.
	empty := newAuthHarness(t)
	if _, err := empty.auth.RevokeAllSessions(context.Background(), RevokeAllSessionsCommand{
		SubjectID: empty.subjectID, IdempotencyKey: "idem-revoke-all",
	}); err != nil {
		t.Fatalf("revoking all: %v", err)
	}
	if len(empty.epochs.bumped) != 0 {
		t.Errorf("bumped %d epochs with no live session to revoke", len(empty.epochs.bumped))
	}
}

// The empty-subject branch is unreachable from both callers, which is exactly why
// it is exercised directly: a guard no test runs is a guard nobody knows is
// broken. An empty id would bump one shared counter for "the principal with no
// id" and report success for every subject.
func TestInvalidatingWithNoSubjectIsRefused(t *testing.T) {
	h := newAuthHarness(t)

	if err := h.auth.invalidateAuthorization(context.Background(), ""); err == nil {
		t.Fatal("an invalidation with no subject reported success")
	}
	if len(h.epochs.bumped) != 0 {
		t.Errorf("bumped %+v for an empty subject", h.epochs.bumped)
	}
}

// The port is optional, and its absence is stated at construction. Without the
// warning an unwired invalidation is invisible: every revocation still succeeds,
// every test still passes, and permits cached for a revoked principal survive.
func TestAuthenticationWarnsWhenNoRevocationEpochsAreWired(t *testing.T) {
	h := newAuthHarness(t)
	deps := h.deps()
	deps.Epochs = nil

	auth, err := NewAuthentication(deps)
	if err != nil {
		t.Fatalf("wiring authentication without revocation epochs: %v", err)
	}
	if auth.InvalidatesAuthorization() {
		t.Error("InvalidatesAuthorization reported true with no port wired; the composition " +
			"root's assertion would pass against nothing")
	}
	if !strings.Contains(h.logs.String(), "no revocation epochs are wired") {
		t.Error("an unwired decision-cache invalidation was not reported at construction")
	}

	// It still revokes: the session stops resolving, which is the mechanism this
	// one adds to rather than replaces.
	id := h.liveSession(t, h.subjectID)
	res, err := auth.RevokeSession(context.Background(), RevokeSessionCommand{
		SessionID: id, SubjectID: h.subjectID, IdempotencyKey: "idem-revoke",
	})
	if err != nil || !res.Changed {
		t.Fatalf("revoking without an invalidation port: changed=%v err=%v", res.Changed, err)
	}
	if !h.auth.InvalidatesAuthorization() {
		t.Error("InvalidatesAuthorization reported false with a port wired")
	}
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// Every port is required. A nil one would surface as a panic during somebody's
// login rather than as a refusal to start.
func TestAuthenticationRefusesIncompleteWiring(t *testing.T) {
	h := newAuthHarness(t)

	cases := map[string]func(*AuthenticationDeps){
		"clock":       func(d *AuthenticationDeps) { d.Clock = nil },
		"entropy":     func(d *AuthenticationDeps) { d.Entropy = nil },
		"indexer":     func(d *AuthenticationDeps) { d.Index = nil },
		"limiter":     func(d *AuthenticationDeps) { d.Limiter = nil },
		"hasher":      func(d *AuthenticationDeps) { d.Hasher = nil },
		"credentials": func(d *AuthenticationDeps) { d.Credentials = nil },
		"accounts":    func(d *AuthenticationDeps) { d.Accounts = nil },
		"users":       func(d *AuthenticationDeps) { d.Users = nil },
		"sessions":    func(d *AuthenticationDeps) { d.Sessions = nil },
		"live":        func(d *AuthenticationDeps) { d.Live = nil },
		"tokens":      func(d *AuthenticationDeps) { d.Tokens = nil },
		"sealer":      func(d *AuthenticationDeps) { d.Sealer = nil },
		"secrets":     func(d *AuthenticationDeps) { d.Secrets = nil },
		"verifier":    func(d *AuthenticationDeps) { d.Verifier = nil },
		"breach":      func(d *AuthenticationDeps) { d.Breach = nil },
		"appender":    func(d *AuthenticationDeps) { d.Appender = nil },
	}
	for name, remove := range cases {
		t.Run("without a "+name, func(t *testing.T) {
			deps := h.deps()
			remove(&deps)
			if _, err := NewAuthentication(deps); err == nil {
				t.Fatalf("wiring succeeded with no %s", name)
			}
		})
	}
}

// An idle window beyond the absolute one is refused at wiring time, not at every
// login.
func TestAnIdleWindowMayNotOutliveTheAbsoluteOne(t *testing.T) {
	h := newAuthHarness(t)
	deps := h.deps()
	deps.IdleWindow = 48 * time.Hour
	deps.AbsoluteWindow = 24 * time.Hour

	if _, err := NewAuthentication(deps); err == nil {
		t.Fatal("an idle window that never fires was accepted")
	}
}

// The domain separator's length prefix must actually separate.
//
// ("ab","cd") and ("a","bcd") concatenate to the same bytes, so a digest built by
// plain concatenation gives them the same value. A fixed-width length prefix makes
// them different. This is the classic collision pair, and it is the only way to
// observe the prefix at all: with the production domain hardcoded there is just
// one (domain, token) pair, so removing the prefix changes no output and the
// mutation survives.
//
// It matters the moment a second separator exists. Two schemes whose digests can
// be made to collide means a token minted for one is redeemable under the other.
func TestTheDomainSeparatorCannotBeShifted(t *testing.T) {
	t.Parallel()

	if bytes.Equal(digestUnder("ab", "cd"), digestUnder("a", "bcd")) {
		t.Error(`digestUnder("ab","cd") equals digestUnder("a","bcd"): the domain and the ` +
			`token are concatenated without a length prefix, so a separator can be chosen ` +
			`to move the boundary and make two different schemes hash alike`)
	}
	// And the production entry point must go through it rather than hashing the
	// token bare — otherwise the property above is real and unused.
	if !bytes.Equal(SessionTokenDigest("tok"), digestUnder(sessionTokenDomain, "tok")) {
		t.Error("SessionTokenDigest does not derive its value under the session domain")
	}
}

// countingAuthObserver records what the login path reported.
type countingAuthObserver struct {
	throttled   []string
	unavailable int
}

func (o *countingAuthObserver) Throttled(rule string) { o.throttled = append(o.throttled, rule) }
func (o *countingAuthObserver) CeilingUnavailable()   { o.unavailable++ }

// The two outcomes with no event must still be counted.
//
// An attempt refused above the ceiling appends nothing — refusals are unbounded,
// and one event each would let an unauthenticated caller drive unbounded writes
// into the log. The cost is that the attempts most indicative of an attack are
// invisible to `login_history_view`, and therefore to the stuffing signal that
// reads it. A degraded ceiling is worse still: the limiter fails open, so every
// attempt proceeds unthrottled and the only trace was a log line.
//
// Both are asserted here because "we log it" is not a control anything can alert
// on.
func TestTheOutcomesThatLeaveNoEventAreStillCounted(t *testing.T) {
	t.Run("refused above the ceiling", func(t *testing.T) {
		h := newAuthHarness(t)
		obs := &countingAuthObserver{}
		h.limiter.allowed = false
		h.auth = withObserver(t, h, obs)

		if _, err := h.login(AuthenticateCommand{Password: testPassword}); err == nil {
			t.Fatal("a throttled attempt was accepted")
		}
		if len(obs.throttled) != 1 {
			t.Fatalf("%d throttled attempts counted, want 1: refusals above the ceiling "+
				"append no event, so this counter is the only trace they exist", len(obs.throttled))
		}
		if obs.throttled[0] == "" {
			t.Error("the refusal was counted under an empty rule, merging every window " +
				"into one series")
		}
	})

	t.Run("allowed because the ceiling was unreachable", func(t *testing.T) {
		h := newAuthHarness(t)
		obs := &countingAuthObserver{}
		h.limiter.err = errors.New("valkey unreachable")
		h.auth = withObserver(t, h, obs)

		// Fails open: the attempt proceeds, so this is an ordinary login that
		// happens to have been unthrottled.
		if _, err := h.login(AuthenticateCommand{Password: testPassword}); err != nil {
			t.Fatalf("the limiter failed closed: %v", err)
		}
		if obs.unavailable != 1 {
			t.Errorf("%d unavailable-ceiling events counted, want 1: without it, "+
				"'password guessing is currently unthrottled' is a log line nothing "+
				"alerts on", obs.unavailable)
		}
	})
}

// withObserver rebuilds the handlers with an observer attached, through the real
// constructor so the nil-default path is exercised too.
func withObserver(t *testing.T, h *authHarness, obs AuthObserver) *Authentication {
	t.Helper()
	deps := h.deps()
	deps.Observer = obs
	auth, err := NewAuthentication(deps)
	if err != nil {
		t.Fatalf("wiring authentication with an observer: %v", err)
	}
	return auth
}

// ---------------------------------------------------------------------------
// Authenticator lockout
// ---------------------------------------------------------------------------

// wrongCode is a well-formed code the fake verifier never accepts.
const wrongCode = "000000"

// grind presents a wrong second factor n times.
//
// A distinct idempotency key per attempt, because a real client retrying gets a
// new one and because reusing one would make every derived event id identical —
// which is the shape a retry has, not the shape a second attempt has.
func (h *authHarness) grind(t *testing.T, n int) {
	t.Helper()
	for i := range n {
		if _, err := h.login(AuthenticateCommand{
			Password:       testPassword,
			Code:           wrongCode,
			IdempotencyKey: fmt.Sprintf("idem-grind-%d", i),
		}); err == nil {
			t.Fatalf("attempt %d with a wrong code was accepted", i+1)
		}
	}
}

// The threshold's worth of wrong codes disables the authenticator, and one fewer
// does not.
//
// Both halves are asserted in one test on purpose: "ten failures lock it out" is
// satisfied by a build that locks out on the first one, and that build locks out
// every user who mistypes a code once.
func TestConsecutiveWrongCodesDisableTheAuthenticator(t *testing.T) {
	t.Run("one short of the threshold", func(t *testing.T) {
		h := newAuthHarness(t)
		h.grind(t, domain.LockoutThreshold-1)

		for _, e := range h.appender.events() {
			if _, ok := e.(*contract.AuthenticatorDisabled); ok {
				t.Fatal("an authenticator was disabled before the threshold was reached")
			}
		}
		if len(h.credentials.disabled) != 0 {
			t.Errorf("disabled %v before the threshold", h.credentials.disabled)
		}
		if m, ok := h.user.Method(h.totpID); !ok || !m.Usable() {
			t.Error("the authenticator is unusable before the threshold was reached")
		}
	})

	t.Run("at the threshold", func(t *testing.T) {
		h := newAuthHarness(t)
		h.grind(t, domain.LockoutThreshold)

		disabled := eventOf[*contract.AuthenticatorDisabled](t, h.appender)
		if disabled.CredentialID != h.totpID.String() {
			t.Errorf("the lockout names credential %q, want the authenticator %q",
				disabled.CredentialID, h.totpID)
		}
		if disabled.SubjectID != h.subjectID {
			t.Errorf("the lockout names subject %q, want %q", disabled.SubjectID, h.subjectID)
		}
		if disabled.Failures != domain.LockoutThreshold {
			t.Errorf("the lockout records %d failures, want %d",
				disabled.Failures, domain.LockoutThreshold)
		}

		// The account stream, not the attempt journal. A lockout is a fact about
		// the account and has to survive on the stream a rebuild replays.
		var onUserStream bool
		for _, call := range h.appender.calls {
			for _, stream := range call {
				for _, e := range stream.Events {
					if _, ok := e.Event.(*contract.AuthenticatorDisabled); ok {
						onUserStream = stream.Stream.Category() == UserCategory
					}
				}
			}
		}
		if !onUserStream {
			t.Errorf("the lockout was appended to %v, want the %s category",
				h.appender.streams(), UserCategory)
		}

		if len(h.credentials.disabled) != 1 || h.credentials.disabled[0] != h.totpID {
			t.Errorf("disabled %v, want exactly the authenticator %s",
				h.credentials.disabled, h.totpID)
		}
		if m, ok := h.user.Method(h.totpID); !ok || m.Usable() {
			t.Error("the authenticator is still usable after the lockout")
		}
		if !strings.Contains(h.logs.String(), "disabled after consecutive failed") {
			t.Error("a lockout produced no log line; a throttle nobody can see is a throttle " +
				"nobody notices has stopped working")
		}
	})
}

// The lockout is recorded ONCE, however long the grind continues.
//
// Without the aggregate's already-disabled check this appends one event per
// subsequent attempt — an unbounded write to the account stream driven by whoever
// is still guessing.
func TestGrindingPastTheThresholdRecordsOneLockout(t *testing.T) {
	h := newAuthHarness(t)
	h.grind(t, domain.LockoutThreshold*3)

	eventOf[*contract.AuthenticatorDisabled](t, h.appender) // fails unless exactly one
	if len(h.credentials.disabled) != 1 {
		t.Errorf("disabled the credential %d times, want 1", len(h.credentials.disabled))
	}
}

// A locked-out authenticator cannot authenticate, even with a CORRECT code.
//
// The lock is asserted through the account's own log alone: the credential row in
// this harness is still enabled and still opens, so the only thing refusing the
// login is the aggregate. That is the layer that has to hold, because it is the
// one a projection rebuild reconstructs and the one a tampered row cannot reach.
func TestALockedOutAuthenticatorCannotAuthenticate(t *testing.T) {
	h := newAuthHarness(t)
	if _, err := h.user.RecordAuthenticatorFailure(
		h.totpID, domain.LockoutThreshold, testNow,
	); err != nil {
		t.Fatalf("locking out the test authenticator: %v", err)
	}
	h.user.ClearUncommitted()

	res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
	if err == nil {
		t.Fatalf("a locked-out authenticator completed an authentication: %+v", res)
	}
	if res.Proof.SubjectID() != "" || res.Proof.AAL() != contract.AAL0 {
		t.Error("a locked-out authenticator produced a usable proof")
	}
	failed := eventOf[*contract.AuthenticationFailed](t, h.appender)
	if failed.Reason != contract.ReasonWrongSecondFactor {
		t.Errorf("the event records %q, want %q", failed.Reason, contract.ReasonWrongSecondFactor)
	}
}

// A wrong PASSWORD is counted forever and never disables anything.
//
// Anyone who knows an address can produce these, so a password lockout would be a
// denial of service against every account an attacker can enumerate. The account
// must still be able to authenticate afterwards, which is the operational form of
// "a lockout cannot strand an account".
func TestNoNumberOfWrongPasswordsDisablesTheCredential(t *testing.T) {
	h := newAuthHarness(t)

	for i := range domain.LockoutThreshold * 3 {
		if _, err := h.login(AuthenticateCommand{
			Password:       "not the password",
			Code:           authCode,
			IdempotencyKey: fmt.Sprintf("idem-guess-%d", i),
		}); err == nil {
			t.Fatalf("guess %d was accepted", i+1)
		}
	}
	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.AuthenticatorDisabled); ok {
			t.Fatal("the password credential was disabled by repeated wrong guesses; that " +
				"locks out any account an attacker can name")
		}
	}
	if len(h.credentials.disabled) != 0 {
		t.Errorf("disabled %v, want nothing", h.credentials.disabled)
	}
	// The count is still the only evidence of a slow grind under the ceiling, so it
	// has to be surfaced even though it locks nothing out.
	if !strings.Contains(h.logs.String(), "passed the lockout threshold") {
		t.Error("a password ground past the lockout threshold produced no log line, so the " +
			"failure column is written and read by nothing")
	}

	// And the account still works.
	if _, err := h.login(AuthenticateCommand{
		Password: testPassword, Code: authCode, IdempotencyKey: "idem-real",
	}); err != nil {
		t.Fatalf("the account could not authenticate after the guessing stopped: %v", err)
	}
}

// A lockout that cannot be recorded does not change the login's answer, does not
// disable the row, and is loud.
//
// Log-first is what makes the second assertion right: disabling the credential
// after an append that failed would leave a locked-out authenticator with nothing
// in the log saying why — invisible to the account's history and to a rebuild.
func TestALockoutThatCannotBeRecordedDoesNotFailTheLogin(t *testing.T) {
	h := newAuthHarness(t)
	h.appender.errFor = func(s eventsourcing.StreamID) error {
		if s.Category() == UserCategory {
			return errors.New("the account stream is unavailable")
		}
		return nil
	}

	reference := func() error {
		other := newAuthHarness(t)
		_, err := other.login(AuthenticateCommand{Password: testPassword, Code: wrongCode})
		return err
	}()

	h.grind(t, domain.LockoutThreshold-1)
	_, err := h.login(AuthenticateCommand{
		Password: testPassword, Code: wrongCode, IdempotencyKey: "idem-threshold",
	})
	if err == nil {
		t.Fatal("the attempt at the threshold was accepted")
	}
	if err.Error() != reference.Error() {
		t.Errorf("the refusal is %q, want %q — a lockout that failed to record must not be "+
			"visible to the caller", err.Error(), reference.Error())
	}
	if len(h.credentials.disabled) != 0 {
		t.Errorf("disabled %v after the lockout could not be recorded; the row would then be "+
			"locked with nothing in the log saying why", h.credentials.disabled)
	}
	if !strings.Contains(h.logs.String(), "could not be recorded") {
		t.Error("a lockout that did not land said nothing")
	}
	// The event must not be left pending on the aggregate. A loader that caches or
	// reuses one would hand the next command an uncommitted lockout and write it
	// against whatever expected revision that command happens to hold.
	if pending := h.user.Uncommitted(); len(pending) != 0 {
		t.Errorf("the aggregate still holds %s after a failed lockout append", describe(pending))
	}
	// Self-healing: the threshold is a floor, so the next failure tries again.
	h.appender.errFor = nil
	if _, err := h.login(AuthenticateCommand{
		Password: testPassword, Code: wrongCode, IdempotencyKey: "idem-retry",
	}); err == nil {
		t.Fatal("the retry was accepted")
	}
	eventOf[*contract.AuthenticatorDisabled](t, h.appender)
}

// A store that cannot count a failure cannot lock anything out, and says so.
func TestAFailureThatCannotBeCountedLocksNothingOut(t *testing.T) {
	h := newAuthHarness(t)
	h.credentials.failErr = errors.New("the credential table is unreachable")

	h.grind(t, domain.LockoutThreshold)

	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.AuthenticatorDisabled); ok {
			t.Fatal("a lockout was recorded from a count that was never written")
		}
	}
	if !strings.Contains(h.logs.String(), "lockout ceiling cannot be evaluated") {
		t.Error("a counter that stopped counting is invisible, so the throttle is silently " +
			"absent while every ordinary login keeps working")
	}
}

// ---------------------------------------------------------------------------
// Rehash on login
// ---------------------------------------------------------------------------

// stale replaces the stored verifier with one written under an older policy.
func (h *authHarness) stale(t *testing.T) string {
	t.Helper()
	row := h.credentials.rows[h.subjectID]
	row.Verifier = verifierForAt(currentVerifierVersion-1, testPassword, h.userID, h.credID)
	row.PepperVersion = 1
	h.credentials.rows[h.subjectID] = row
	if !h.hasher.NeedsRehash(row.Verifier) {
		t.Fatal("the fixture is not actually below current policy, so this test cannot fail")
	}
	return row.Verifier
}

// A verifier below current policy is re-derived and stored on a successful login.
//
// This is the ONLY mechanism that completes a pepper rotation for passwords:
// nothing else in the system ever holds the plaintext again, so without it
// `pepper_version < n` never reaches zero and the old transit key can never be
// destroyed.
func TestAStaleVerifierIsUpgradedOnLogin(t *testing.T) {
	h := newAuthHarness(t)
	old := h.stale(t)

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("a login against a stale verifier was refused: %v", err)
	}

	if len(h.credentials.rehashes) != 1 {
		t.Fatalf("issued %d rehashes, want 1", len(h.credentials.rehashes))
	}
	call := h.credentials.rehashes[0]
	switch {
	case call.cred != h.credID:
		t.Errorf("rehashed credential %s, want %s", call.cred, h.credID)
	case call.expected != old:
		t.Errorf("the compare-and-set expected %q, want the verifier the login read (%q); "+
			"without that guard the write is unconditional and can undo a password change",
			call.expected, old)
	case call.replacement == old:
		t.Error("the replacement is the stored verifier, so nothing was re-derived")
	case h.hasher.NeedsRehash(call.replacement):
		t.Error("the replacement is itself below current policy")
	case call.pepper != h.hasher.PepperVersion():
		t.Errorf("stored pepper version %d, want the hasher's current %d; a row at the wrong "+
			"version is invisible to the rotation job and locks out when the old key dies",
			call.pepper, h.hasher.PepperVersion())
	}
	if stored := h.credentials.rows[h.subjectID]; stored.Verifier != call.replacement {
		t.Errorf("the stored verifier is %q, want the replacement", stored.Verifier)
	}

	rehashed := eventOf[*contract.PasswordRehashed](t, h.appender)
	if rehashed.CredentialID != h.credID.String() || rehashed.SubjectID != h.subjectID {
		t.Errorf("the event is %+v", rehashed)
	}

	// And the next login does not pay for it again. No code: the rehash happens on
	// the first leg of the ceremony, and the fake verifier's replay guard would
	// refuse the same code twice for reasons that have nothing to do with rehashing.
	before := len(h.credentials.rehashes)
	if _, err := h.login(AuthenticateCommand{
		Password: testPassword, IdempotencyKey: "idem-second",
	}); err != nil {
		t.Fatalf("the second login was refused: %v", err)
	}
	if len(h.credentials.rehashes) != before {
		t.Error("a verifier already at current policy was rehashed again; the cost is then " +
			"an extra Argon2id evaluation on every login forever")
	}
}

// A verifier already at current policy is left alone.
func TestACurrentVerifierIsNotRehashed(t *testing.T) {
	h := newAuthHarness(t)

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("the login was refused: %v", err)
	}
	if len(h.credentials.rehashes) != 0 {
		t.Errorf("issued %d rehashes for a current verifier, want 0", len(h.credentials.rehashes))
	}
	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.PasswordRehashed); ok {
			t.Fatal("a current verifier recorded a rehash; a rehash event that fires on every " +
				"login is indistinguishable from one that never fires")
		}
	}
}

// A concurrent password change wins, and the rehash is dropped rather than
// retried.
//
// The race is driven where it actually happens: the plaintext is hashed AFTER the
// verifier was read and BEFORE the compare-and-set, so the row is changed inside
// Hash. Retrying here would write a re-encoding of the OLD password over the new
// one — quietly restoring a password the user may have replaced precisely because
// it was compromised.
func TestARehashDoesNotUndoAConcurrentPasswordChange(t *testing.T) {
	h := newAuthHarness(t)
	h.stale(t)

	const newPassword = "the password they just changed to"
	changed := verifierFor(newPassword, h.userID, h.credID)
	h.hasher.onHash = func() {
		row := h.credentials.rows[h.subjectID]
		row.Verifier = changed
		h.credentials.rows[h.subjectID] = row
	}

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("a concurrent password change failed the login that was already correct: %v", err)
	}

	if stored := h.credentials.rows[h.subjectID].Verifier; stored != changed {
		t.Fatalf("the stored verifier is %q, want the concurrent change %q — the rehash "+
			"clobbered a password change", stored, changed)
	}
	if len(h.credentials.rehashes) != 1 {
		t.Errorf("issued %d rehashes, want exactly 1 — ErrCredentialMoved must be dropped, "+
			"never retried", len(h.credentials.rehashes))
	}
	for _, e := range h.appender.events() {
		if _, ok := e.(*contract.PasswordRehashed); ok {
			t.Fatal("a rehash the store refused was recorded as having happened")
		}
	}
	if !strings.Contains(h.logs.String(), "discarded because the credential changed") {
		t.Error("a dropped rehash said nothing")
	}
}

// No rehash failure of any kind fails the login.
//
// The user authenticated. A rehash is an optimisation of the stored form of a
// credential that already verifies, so every one of these leaves a working login
// and a verifier that is merely still old.
func TestNoRehashFailureFailsTheLogin(t *testing.T) {
	for _, tc := range []struct {
		name    string
		arrange func(*authHarness)
		logged  string
	}{
		{
			name:    "the hasher cannot re-derive",
			arrange: func(h *authHarness) { h.hasher.hashErr = errors.New("openbao is unreachable") },
			logged:  "could not be re-derived",
		},
		{
			name: "the store refuses the write",
			arrange: func(h *authHarness) {
				h.credentials.rehashErr = errors.New("the credential table is read-only")
			},
			logged: "could not be stored",
		},
		{
			name: "the account stream is unavailable",
			arrange: func(h *authHarness) {
				h.appender.errFor = func(s eventsourcing.StreamID) error {
					if s.Category() == UserCategory {
						return errors.New("the account stream is unavailable")
					}
					return nil
				}
			},
			logged: "could not be appended",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newAuthHarness(t)
			h.stale(t)
			tc.arrange(h)

			res, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode})
			if err != nil {
				t.Fatalf("a rehash failure refused a correct login: %v", err)
			}
			if res.Proof.SubjectID() != h.subjectID || res.Proof.AAL() != contract.AAL2 {
				t.Errorf("the login produced proof %+v, want a complete one", res.Proof)
			}
			if !strings.Contains(h.logs.String(), tc.logged) {
				t.Errorf("a rehash failure produced no log line containing %q", tc.logged)
			}
			if pending := h.user.Uncommitted(); len(pending) != 0 {
				t.Errorf("the aggregate still holds %s after a failed rehash", describe(pending))
			}
		})
	}
}

// Nothing about a verifier reaches an event or a log line.
//
// A verifier in an event is permanent: it would survive the password being
// changed, survive the erasure of everything else about the person, and stay
// offline-crackable forever (ADR-002, identity.md §4).
func TestARehashPutsNoVerifierInAnEventOrTheLog(t *testing.T) {
	h := newAuthHarness(t)
	old := h.stale(t)

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err != nil {
		t.Fatalf("the login was refused: %v", err)
	}
	replacement := h.credentials.rows[h.subjectID].Verifier
	if replacement == old {
		t.Fatal("no rehash happened, so this test proves nothing")
	}

	secrets := map[string]string{
		"the old verifier": old,
		"the new verifier": replacement,
		"the password":     testPassword,
	}
	for _, e := range h.appender.events() {
		rendered := fmt.Sprintf("%+v", e)
		for name, secret := range secrets {
			if strings.Contains(rendered, secret) {
				t.Errorf("%s appears in %s: %s", name, e.EventType(), rendered)
			}
		}
	}
	logged := h.logs.String()
	for name, secret := range secrets {
		if strings.Contains(logged, secret) {
			t.Errorf("%s appears in the log", name)
		}
	}
}

// A refused account never writes to its own stream, and never pays for a rehash.
//
// The refusal path costs exactly one password verification for every cause
// (TestEveryRefusalIsIdentical); an extra Argon2id evaluation on one of them would
// put the difference back into the response time.
func TestARefusedLoginNeitherRehashesNorTouchesTheAccountStream(t *testing.T) {
	h := newAuthHarness(t)
	h.stale(t)
	mustDo(t, h.user.Suspend("operator", "fraud", testNow))
	h.user.ClearUncommitted()

	if _, err := h.login(AuthenticateCommand{Password: testPassword, Code: authCode}); err == nil {
		t.Fatal("a suspended account authenticated")
	}
	if len(h.credentials.rehashes) != 0 {
		t.Errorf("a refused login issued %d rehashes, want 0", len(h.credentials.rehashes))
	}
	if h.hasher.verifies != 1 {
		t.Errorf("a refused login cost %d verifications, want 1", h.hasher.verifies)
	}
	for _, stream := range h.appender.streams() {
		if stream.Category() == UserCategory {
			t.Errorf("a refused login wrote to %s", stream)
		}
	}
}

// One command never derives two events with the same id.
//
// eventsourcing.DeriveEventID hashes (idempotency key, index), and both appends a
// login can make start at index 0. Sharing the key would therefore give the
// account-stream event and the attempt-journal event the SAME id on two different
// streams — which the second idempotency layer deduplicates on (EVENT-SOURCING
// §3), so a retried command could find one present and skip the other. The
// suffixes exist for exactly this and nothing else asserts them.
func TestOneLoginNeverDerivesTwoEventsWithTheSameID(t *testing.T) {
	t.Run("a rehash beside a challenge", func(t *testing.T) {
		h := newAuthHarness(t)
		h.stale(t)

		before := len(h.appender.calls)
		if _, err := h.login(AuthenticateCommand{Password: testPassword}); err != nil {
			t.Fatalf("the login was refused: %v", err)
		}
		assertDistinctEventIDs(t, h, before, 2)
	})

	t.Run("a lockout beside a refusal", func(t *testing.T) {
		h := newAuthHarness(t)
		h.grind(t, domain.LockoutThreshold-1)

		before := len(h.appender.calls)
		if _, err := h.login(AuthenticateCommand{
			Password: testPassword, Code: wrongCode, IdempotencyKey: "idem-last",
		}); err == nil {
			t.Fatal("the attempt at the threshold was accepted")
		}
		assertDistinctEventIDs(t, h, before, 2)
	})
}

// assertDistinctEventIDs checks the appends made since index `from` carry
// wantEvents events in total and no two share an id.
func assertDistinctEventIDs(t *testing.T, h *authHarness, from, wantEvents int) {
	t.Helper()
	seen := map[string]string{}
	var total int
	for _, call := range h.appender.calls[from:] {
		for _, stream := range call {
			for _, e := range stream.Events {
				total++
				id := e.ID.String()
				if previous, clash := seen[id]; clash {
					t.Errorf("%s and %s were both derived as event %s; a retry deduplicates on "+
						"that id and would skip one of them", previous, e.Event.EventType(), id)
				}
				seen[id] = e.Event.EventType()
			}
		}
	}
	if total != wantEvents {
		t.Fatalf("the command appended %d events, want %d — this test proves nothing if the "+
			"second append did not happen", total, wantEvents)
	}
}
