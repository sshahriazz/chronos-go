package app

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"strings"
	"sync"
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

// memoryCounter is ratelimit.Counter over a map, so a test can drive a REAL
// ratelimit.Limiter rather than a fake that says "no".
//
// A fake limiter proves the handler honours a refusal. It cannot prove the
// policy refuses anything — a rule set with an off-by-one, or a scope that
// differs per call, allows for ever while every assertion against a stub passes.
type memoryCounter struct {
	mu     sync.Mutex
	counts map[string]int64
	err    error
}

func newMemoryCounter() *memoryCounter { return &memoryCounter{counts: map[string]int64{}} }

func (c *memoryCounter) Incr(_ context.Context, key string, _ time.Duration) (int64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.err != nil {
		return 0, c.err
	}
	c.counts[key]++
	return c.counts[key], nil
}

// recordingLimiter wraps an AttemptLimiter and logs the scopes it was asked
// about, in order. The ORDER is what several assertions below are about.
type recordingLimiter struct {
	inner AttemptLimiter
	log   *[]string
	label string
}

func (l recordingLimiter) Allow(ctx context.Context, scope string) (ratelimit.Decision, error) {
	*l.log = append(*l.log, l.label+":"+scope)
	return l.inner.Allow(ctx, scope)
}

// resendDirectory is the index -> account lookup, recording every call so a test
// can prove the lookup did NOT happen before the ceilings were spent.
type resendDirectory struct {
	account Account
	err     error
	calls   []contract.EmailIndex
}

func (d *resendDirectory) AccountByEmailIndex(
	_ context.Context, index contract.EmailIndex,
) (Account, error) {
	d.calls = append(d.calls, index)
	if d.err != nil {
		return Account{}, d.err
	}
	return d.account, nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const resendEmail = "Pending+User@Example.COM"

type resendHarness struct {
	t *testing.T

	indexer   fakeIndexer
	directory *resendDirectory
	appender  *fakeAppender
	schemas   *eventsourcing.UpcasterRegistry
	counter   *memoryCounter
	calls     []string
	logs      *bytes.Buffer

	user    *domain.User
	loadErr error

	addressRules []ratelimit.Rule
	callerRules  []ratelimit.Rule
}

func newResendHarness(t *testing.T) *resendHarness {
	t.Helper()
	h := &resendHarness{
		t:         t,
		directory: &resendDirectory{},
		appender:  &fakeAppender{},
		schemas:   identitySchemas(),
		counter:   newMemoryCounter(),
		// Deliberately generous, so a test that is not about the ceiling never
		// trips it by accident. The ceiling tests narrow them.
		addressRules: []ratelimit.Rule{{Name: "hourly", Limit: 1000, Window: time.Hour}},
		callerRules:  []ratelimit.Rule{{Name: "hourly", Limit: 1000, Window: time.Hour}},
	}
	h.user = h.pendingUser()
	h.directory.account = Account{UserID: h.user.ID(), SubjectID: h.user.SubjectID()}
	return h
}

// index is the blind index the handler will derive for an address, computed the
// same way the fake indexer does so a test can assert on the rate-limit scope.
func (h *resendHarness) index(email string) contract.EmailIndex {
	h.t.Helper()
	idx, err := h.indexer.Of(email)
	if err != nil {
		h.t.Fatalf("deriving the test index: %v", err)
	}
	return idx
}

// pendingUser is a registered, unverified account positioned as if loaded from
// its stream: the registration events are applied and then cleared, so
// ExpectedFor reports a revision rather than NoStream.
func (h *resendHarness) pendingUser() *domain.User {
	h.t.Helper()
	user := eventsourcing.NewAggregate(domain.New)
	userID := ids.New[ids.User](testNow, &fixedEntropy{})
	subjectID := ids.New[ids.Subject](testNow, &fixedEntropy{b: 99}).String()
	if err := user.Register(userID, subjectID, h.index(resendEmail), testNow); err != nil {
		h.t.Fatalf("building a pending account: %v", err)
	}
	user.ClearUncommitted()
	return user
}

func (h *resendHarness) build() *ResendVerification {
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
	r, err := NewResendVerification(ResendVerificationDeps{
		Clock:     clock.NewFixed(testNow),
		Index:     h.indexer,
		Directory: h.directory,
		Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
			return h.user, h.loadErr
		}),
		Appender:       h.appender,
		Schemas:        h.schemas,
		AddressLimiter: recordingLimiter{inner: addr, log: &h.calls, label: "address"},
		CallerLimiter:  recordingLimiter{inner: caller, log: &h.calls, label: "caller"},
		TokenTTL:       24 * time.Hour,
		Log:            log,
	})
	if err != nil {
		h.t.Fatalf("wiring the resend: %v", err)
	}
	return r
}

func (h *resendHarness) resend(email string) (ResendVerificationResult, error) {
	h.t.Helper()
	return h.build().Resend(context.Background(), ResendVerificationCommand{
		Email:          email,
		CallerScope:    "198.51.100.7",
		IdempotencyKey: "idem-resend-1",
	})
}

// requested returns the single EmailVerificationRequested the appender saw, or
// fails. It asserts the SHAPE of the append too — one stream, one event — because
// a resend that appended twice is two mails.
func (h *resendHarness) requested() (eventsourcing.StreamAppend, *contract.EmailVerificationRequested) {
	h.t.Helper()
	if len(h.appender.calls) != 1 {
		h.t.Fatalf("the appender was called %d times, want 1", len(h.appender.calls))
	}
	call := h.appender.calls[0]
	if len(call) != 1 {
		h.t.Fatalf("the append touched %d streams, want 1", len(call))
	}
	if len(call[0].Events) != 1 {
		h.t.Fatalf("the append carried %d events, want 1", len(call[0].Events))
	}
	event, ok := call[0].Events[0].Event.(*contract.EmailVerificationRequested)
	if !ok {
		h.t.Fatalf("the append carried %T, want *contract.EmailVerificationRequested",
			call[0].Events[0].Event)
	}
	return call[0], event
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

func TestNewResendVerificationRefusesAMissingDependency(t *testing.T) {
	t.Parallel()

	limiter, err := ratelimit.New(newMemoryCounter(), "p",
		ratelimit.Rule{Name: "hourly", Limit: 3, Window: time.Hour})
	if err != nil {
		t.Fatalf("building a limiter: %v", err)
	}
	users := loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
		return nil, nil
	})
	full := func() ResendVerificationDeps {
		return ResendVerificationDeps{
			Clock:          clock.NewFixed(testNow),
			Index:          fakeIndexer{},
			Directory:      &resendDirectory{},
			Users:          users,
			Appender:       &fakeAppender{},
			AddressLimiter: limiter,
			CallerLimiter:  limiter,
			TokenTTL:       time.Hour,
		}
	}

	tests := []struct {
		name string
		mut  func(*ResendVerificationDeps)
	}{
		{"no clock", func(d *ResendVerificationDeps) { d.Clock = nil }},
		{"no indexer", func(d *ResendVerificationDeps) { d.Index = nil }},
		{"no directory", func(d *ResendVerificationDeps) { d.Directory = nil }},
		{"no user loader", func(d *ResendVerificationDeps) { d.Users = nil }},
		{"no appender", func(d *ResendVerificationDeps) { d.Appender = nil }},
		{"no address ceiling", func(d *ResendVerificationDeps) { d.AddressLimiter = nil }},
		{"no caller ceiling", func(d *ResendVerificationDeps) { d.CallerLimiter = nil }},
		{"no token lifetime", func(d *ResendVerificationDeps) { d.TokenTTL = 0 }},
		{"negative token lifetime", func(d *ResendVerificationDeps) { d.TokenTTL = -time.Hour }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			deps := full()
			tt.mut(&deps)
			if _, err := NewResendVerification(deps); err == nil {
				t.Error("wiring succeeded with a missing dependency; a nil ceiling in " +
					"particular is an anti-abuse control that is present in the design, " +
					"absent at runtime, and green in every test that does not count mail")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// The happy path
// ---------------------------------------------------------------------------

func TestResendAppendsAVerificationRequestForAPendingAccount(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)

	result, err := h.resend(resendEmail)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if result.Outcome != ResendRequested {
		t.Fatalf("outcome %v, want ResendRequested", result.Outcome)
	}

	append0, event := h.requested()

	if got, want := string(append0.Stream), "user-"+h.user.ID().String(); got != want {
		t.Errorf("appended to %q, want %q: the event has to land on the ACCOUNT's own "+
			"stream or the reactor never sees it and no mail is sent", got, want)
	}
	if got, want := event.SubjectID, h.user.SubjectID(); got != want {
		t.Errorf("SubjectID %q, want %q: the reactor issues the token against this "+
			"pseudonym, so a wrong one mails a link that redeems somebody else's account",
			got, want)
	}
	if got, want := event.Index, h.index(resendEmail); got != want {
		t.Errorf("Index %q, want %q", got, want)
	}
	if want := testNow.Add(24 * time.Hour); !event.ExpiresAt.Equal(want) {
		t.Errorf("ExpiresAt %s, want %s (now + the token TTL)", event.ExpiresAt, want)
	}
	if !event.RequestedAt.Equal(testNow) {
		t.Errorf("RequestedAt %s, want %s", event.RequestedAt, testNow)
	}
	// The event type the reactor filters on, and the reactor's filter is derived
	// from this same method — so this asserts the two cannot drift.
	if got := event.EventType(); got != "identity.EmailVerificationRequested.v1" {
		t.Errorf("event type %q; the reactor's subscription filter names the other one", got)
	}
	// Stamped, or the event is stored at version 0 while the registry declares 1
	// and the account can never be loaded back.
	if got := append0.Events[0].Meta.SchemaVersion; got != 1 {
		t.Errorf("schema version %d, want 1", got)
	}
	// The exact loaded revision, so a concurrent write refuses instead of
	// appending a second request — and two requests on one stream is two mails.
	if got, want := append0.Expected, eventsourcing.ExpectedFor(h.user); got != want {
		t.Errorf("expected revision %v, want %v", got, want)
	}
}

func TestResendCarriesNoTokenAndNoAddress(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)

	if _, err := h.resend(resendEmail); err != nil {
		t.Fatalf("Resend: %v", err)
	}
	_, event := h.requested()

	// ADR-002: an event is permanent and replicated. The address that was typed
	// into this request may not survive in it, and neither may anything
	// redeemable. The event's own fields are checked rather than a serialization,
	// because a field added later is what this guards against.
	if strings.Contains(strings.ToLower(event.SubjectID), "example.com") {
		t.Error("the appended event carries the address")
	}
	if event.Index == "" {
		t.Error("the appended event carries no blind index, so the projector cannot " +
			"tell which claim the link would prove")
	}
	if strings.Contains(strings.ToLower(string(event.Index)), "pending") {
		t.Error("the blind index is not blind: the local part survived into the event")
	}
}

// ---------------------------------------------------------------------------
// The three silent paths
// ---------------------------------------------------------------------------

func TestResendIsSilentWhenNothingClaimsTheAddress(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	h.directory.err = ErrNoSuchAccount

	result, err := h.resend("nobody@example.com")
	if err != nil {
		t.Fatalf("resending for an unknown address was refused with %v; that refusal IS "+
			"the account-existence oracle the empty response exists to close", err)
	}
	if result.Outcome != ResendNoAccount {
		t.Errorf("outcome %v, want ResendNoAccount", result.Outcome)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for an address with no account; the reactor would mail a "+
			"verification link for an account that does not exist", len(h.appender.calls))
	}
}

func TestResendIsSilentForAnAlreadyVerifiedAccount(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	if err := h.user.VerifyEmail(h.index(resendEmail), testNow); err != nil {
		t.Fatalf("verifying the test account: %v", err)
	}
	h.user.ClearUncommitted()

	result, err := h.resend(resendEmail)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if result.Outcome != ResendAlreadyVerified {
		t.Errorf("outcome %v, want ResendAlreadyVerified", result.Outcome)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for a verified account: an unauthenticated caller who knows "+
			"somebody's address can have mail sent to them on demand", len(h.appender.calls))
	}
}

func TestResendIsSilentForADeactivatedAccount(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	if err := h.user.Deactivate(h.user.SubjectID(), testNow); err != nil {
		t.Fatalf("deactivating the test account: %v", err)
	}
	h.user.ClearUncommitted()

	result, err := h.resend(resendEmail)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if result.Outcome != ResendNotPending {
		t.Errorf("outcome %v, want ResendNotPending", result.Outcome)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for a deactivated account", len(h.appender.calls))
	}
}

func TestResendIsSilentWhenTheAccountClaimsADifferentAddress(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	// A stale projection row pointing at an account whose aggregate claims
	// something else. The decision is taken from the AGGREGATE, so this must not
	// append.
	other := "someone.else@example.com"

	result, err := h.resend(other)
	if err != nil {
		t.Fatalf("Resend: %v", err)
	}
	if result.Outcome != ResendNotPending {
		t.Errorf("outcome %v, want ResendNotPending", result.Outcome)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for an index the account does not claim: the reactor would "+
			"mail the address the vault holds, which is not the one that was typed",
			len(h.appender.calls))
	}
}

// ---------------------------------------------------------------------------
// The ceilings
// ---------------------------------------------------------------------------

// TestTheAddressCeilingStopsTheMail is the mail-bombing assertion, and it is
// deliberately written as "N are allowed and the N+1th produces NO append".
//
// Asserting only that the N+1th returns an error would pass on a handler that
// refused AFTER appending — which is a rate limiter that sends the mail and then
// apologises.
func TestTheAddressCeilingStopsTheMail(t *testing.T) {
	t.Parallel()
	const limit = 3
	h := newResendHarness(t)
	h.addressRules = []ratelimit.Rule{{Name: "hourly", Limit: limit, Window: time.Hour}}
	resend := h.build()

	for i := range limit {
		if _, err := resend.Resend(context.Background(), ResendVerificationCommand{
			Email: resendEmail, CallerScope: "198.51.100.7", IdempotencyKey: "k",
		}); err != nil {
			t.Fatalf("resend %d of %d was refused: %v", i+1, limit, err)
		}
	}
	if got := len(h.appender.calls); got != limit {
		t.Fatalf("%d appends after %d permitted resends, want %d", got, limit, limit)
	}

	_, err := resend.Resend(context.Background(), ResendVerificationCommand{
		Email: resendEmail, CallerScope: "198.51.100.7", IdempotencyKey: "k",
	})
	if err == nil {
		t.Fatal("the 4th resend in an hour was permitted; the per-address ceiling " +
			"permits an unauthenticated caller to fill a stranger's mailbox")
	}
	if got := errs.ReasonOf(err); got != errs.RateLimited {
		t.Errorf("reason %v, want RateLimited", got)
	}
	if got := len(h.appender.calls); got != limit {
		t.Errorf("%d appends after the refusal, want %d: the event was appended anyway, "+
			"so the reactor sends the mail the ceiling refused", got, limit)
	}
}

func TestTheCallerCeilingStopsASweep(t *testing.T) {
	t.Parallel()
	const limit = 2
	h := newResendHarness(t)
	h.callerRules = []ratelimit.Rule{{Name: "hourly", Limit: limit, Window: time.Hour}}
	h.directory.err = ErrNoSuchAccount
	resend := h.build()

	probe := func(email string) error {
		_, err := resend.Resend(context.Background(), ResendVerificationCommand{
			Email: email, CallerScope: "198.51.100.7", IdempotencyKey: "k",
		})
		return err
	}
	// Every address is DIFFERENT, so the per-address rule can never be what stops
	// this. Only the caller axis can.
	for i, email := range []string{"a@example.com", "b@example.com"} {
		if err := probe(email); err != nil {
			t.Fatalf("probe %d was refused: %v", i+1, err)
		}
	}
	if err := probe("c@example.com"); err == nil {
		t.Fatal("a caller swept three distinct addresses under a ceiling of two; the " +
			"per-caller axis counts nothing, and an unauthenticated enumeration sweep " +
			"is unbounded")
	}
}

// TestTheCeilingsAreSpentBeforeTheLookup is the enumeration property expressed as
// work rather than as wording.
//
// A known and an unknown address must consume IDENTICAL budget, in identical
// order. If the address budget were spent only when an account existed, an
// attacker would learn which addresses have accounts by watching which requests
// eventually get refused.
func TestTheCeilingsAreSpentBeforeTheLookup(t *testing.T) {
	t.Parallel()

	known := newResendHarness(t)
	if _, err := known.resend(resendEmail); err != nil {
		t.Fatalf("resend for a known address: %v", err)
	}

	unknown := newResendHarness(t)
	unknown.directory.err = ErrNoSuchAccount
	if _, err := unknown.resend(resendEmail); err != nil {
		t.Fatalf("resend for an unknown address: %v", err)
	}

	if got, want := strings.Join(known.calls, " "), strings.Join(unknown.calls, " "); got != want {
		t.Errorf("a known address spends %q and an unknown one spends %q; the difference "+
			"is an account-existence oracle visible in the rate-limit counters", got, want)
	}
	// And the counters really were touched — an assertion that two empty lists are
	// equal would pass on a handler with no ceiling at all.
	if len(known.calls) != 2 {
		t.Fatalf("%d ceiling evaluations, want 2 (caller and address)", len(known.calls))
	}
	if !strings.HasPrefix(known.calls[0], "caller:") {
		t.Errorf("the first ceiling evaluated was %q, want the CALLER's. Address-first "+
			"lets a sweep across a thousand addresses spend a thousand victims' budgets "+
			"before the attacker's own runs out", known.calls[0])
	}
	if want := "address:" + string(known.index(resendEmail)); known.calls[1] != want {
		t.Errorf("the address ceiling counted %q, want %q: the scope must be the blind "+
			"index, both so it identifies one address and so no address reaches Valkey",
			known.calls[1], want)
	}
	if strings.Contains(strings.ToLower(strings.Join(known.calls, " ")), "example.com") {
		t.Error("an email address reached a rate-limit key; a cache is a projection with " +
			"a shorter life and ADR-002 applies to it unchanged")
	}
	// The lookup happened only after both, on both paths.
	if len(known.directory.calls) != 1 || len(unknown.directory.calls) != 1 {
		t.Errorf("directory calls: known %d, unknown %d; want 1 each",
			len(known.directory.calls), len(unknown.directory.calls))
	}
}

func TestTheCeilingFailsOpenAndSaysSo(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	h.logs = &bytes.Buffer{}
	h.counter.err = errors.New("valkey is unreachable")

	result, err := h.resend(resendEmail)
	if err != nil {
		t.Fatalf("an unreachable counter refused the resend: %v. Failing closed here "+
			"turns a cache blip into permanent account loss for everyone who registered "+
			"during it — a Pending account cannot sign in and cannot re-register", err)
	}
	if result.Outcome != ResendRequested {
		t.Errorf("outcome %v, want ResendRequested", result.Outcome)
	}
	logs := h.logs.String()
	if !strings.Contains(logs, "ceiling_unavailable") {
		t.Errorf("a degraded ceiling was not reported; a control that has silently "+
			"stopped counting is indistinguishable from one that is never reached.\n%s", logs)
	}
	// Both axes degraded, both reported. One line would mean one of the two axes
	// is evaluated somewhere that swallows the failure.
	if got := strings.Count(logs, "ceiling_unavailable"); got != 2 {
		t.Errorf("%d degraded-ceiling log lines, want 2 (caller and address)", got)
	}
	if strings.Contains(strings.ToLower(logs), "example.com") {
		t.Error("the log line carries the address")
	}
}

// ---------------------------------------------------------------------------
// Refusals and races
// ---------------------------------------------------------------------------

func TestResendRequiresACallerScope(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)

	_, err := h.build().Resend(context.Background(), ResendVerificationCommand{
		Email: resendEmail, IdempotencyKey: "k",
	})
	if err == nil {
		t.Fatal("an empty caller scope was accepted; every caller would then share one " +
			"bucket, so the first few requests anywhere exhaust the budget for everybody")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends despite the refusal", len(h.appender.calls))
	}
}

func TestResendRequiresAnIdempotencyKey(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)

	_, err := h.build().Resend(context.Background(), ResendVerificationCommand{
		Email: resendEmail, CallerScope: "198.51.100.7",
	})
	if err == nil {
		t.Fatal("an empty idempotency key was accepted; every resend in the system would " +
			"then derive the same event id")
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("reason %v, want ValidationFailed", got)
	}
}

func TestResendTreatsALostRaceAsSuccess(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	h.appender.err = eventsourcing.ErrWrongExpectedRevision

	result, err := h.resend(resendEmail)
	if err != nil {
		t.Fatalf("a concurrent write to the account's stream was reported as a failure: %v. "+
			"Retrying would race again and could mail twice", err)
	}
	if result.Outcome != ResendRaced {
		t.Errorf("outcome %v, want ResendRaced", result.Outcome)
	}
}

func TestResendPropagatesARealAppendFailure(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)
	h.appender.err = errors.New("the event store is unreachable")

	if _, err := h.resend(resendEmail); err == nil {
		t.Fatal("an append that failed was reported as a resend that succeeded; the " +
			"person is told a link is on its way and no event was ever written")
	}
}

func TestResendRefusesAMalformedAddress(t *testing.T) {
	t.Parallel()
	h := newResendHarness(t)

	if _, err := h.resend("not-an-address"); err == nil {
		t.Fatal("a malformed address was accepted")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for a malformed address", len(h.appender.calls))
	}
}
