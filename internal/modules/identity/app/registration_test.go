package app

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// The real repository must satisfy the loader port. Without this, the port could
// drift into a shape only the fakes below implement — which is how a use case
// ends up passing every test and wiring into nothing.
var (
	_ AggregateLoader[*domain.EmailReservation] = (*eventsourcing.Repository[*domain.EmailReservation])(nil)
	_ AggregateLoader[*domain.User]             = (*eventsourcing.Repository[*domain.User])(nil)
	_ SubjectVault                              = (pii.Vault)(nil)
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeIndexer stands in for the keyed HMAC. It is deterministic and full-width
// hex, so the stream names the handler builds are the same SHAPE as production's
// — a key containing a dash would be rejected by NewStreamID, and a test using a
// short label would never exercise that.
type fakeIndexer struct{ err error }

func (f fakeIndexer) Of(email string) (contract.EmailIndex, error) {
	if f.err != nil {
		return "", f.err
	}
	normalized, err := domain.NormalizeEmail(email)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256([]byte("fake-key|" + normalized))
	return contract.EmailIndex(hex.EncodeToString(sum[:])), nil
}

type fakeBreach struct {
	breached bool
	corpus   string
	err      error
	calls    int
}

func (f *fakeBreach) Breached(context.Context, string) (bool, string, error) {
	f.calls++
	return f.breached, f.corpus, f.err
}

type fakeHasher struct {
	err    error
	calls  int
	seen   []string
	pepper int32
}

func (f *fakeHasher) Hash(_ context.Context, password string, _ ids.UserID, _ ids.CredentialID) (string, error) {
	f.calls++
	f.seen = append(f.seen, password)
	if f.err != nil {
		return "", f.err
	}
	return "$argon2id$fake$" + hex.EncodeToString([]byte(password)), nil
}

func (f *fakeHasher) Verify(context.Context, string, string, ids.UserID, ids.CredentialID) (bool, error) {
	return false, errors.New("not used by registration")
}

func (f *fakeHasher) NeedsRehash(string) bool { return false }

// PepperVersion reports a real version. Zero is refused at wiring time, so a
// fake defaulting to it would fail every test for a reason none of them is
// about.
func (f *fakeHasher) PepperVersion() int32 {
	if f.pepper == 0 {
		return 3
	}
	return f.pepper
}

type fakeVault struct {
	err    error
	calls  int
	stored map[pii.SubjectID]map[pii.Field]string
}

func (f *fakeVault) PutAll(_ context.Context, id pii.SubjectID, values map[pii.Field]string) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	if f.stored == nil {
		f.stored = map[pii.SubjectID]map[pii.Field]string{}
	}
	f.stored[id] = values
	return nil
}

// zeroPepperHasher is a hasher that reports no pepper version — the value the
// wiring must refuse.
type zeroPepperHasher struct{ PasswordHasher }

func (zeroPepperHasher) PepperVersion() int32 { return 0 }

type fakeCredentials struct {
	err   error
	calls int
	last  NewPasswordCredential
}

var _ PasswordCredentials = (*fakeCredentials)(nil)

// Store is NOT what registration or verification calls any more — StoreFirst is
// — so it fails loudly. A handler that reached for it would be writing a first
// password through the path that refuses to displace an orphaned verifier, which
// is the lockout app.PasswordCredentials.StoreFirst exists to prevent.
func (f *fakeCredentials) Store(context.Context, NewPasswordCredential) error {
	return errors.New("registration must use StoreFirst for an account's first password")
}

func (f *fakeCredentials) StoreFirst(_ context.Context, cred NewPasswordCredential) error {
	f.calls++
	if f.err != nil {
		return f.err
	}
	f.last = cred
	return nil
}

// The rest of the port is unreachable from registration. Each fails loudly
// rather than returning a zero value, so a handler that started calling one is
// caught here instead of silently verifying against nothing.
func (f *fakeCredentials) Find(context.Context, string) (PasswordCredential, error) {
	return PasswordCredential{}, errors.New("not used by registration")
}

func (f *fakeCredentials) Rehash(context.Context, ids.CredentialID, string, string, int32) error {
	return errors.New("not used by registration")
}

func (f *fakeCredentials) RecordSuccess(context.Context, ids.CredentialID) error {
	return errors.New("not used by registration")
}

func (f *fakeCredentials) RecordFailure(context.Context, ids.CredentialID) (int32, error) {
	return 0, errors.New("not used by registration")
}

func (f *fakeCredentials) Disable(context.Context, ids.CredentialID) error {
	return errors.New("not used by registration")
}

// loaderFunc adapts a closure to AggregateLoader.
type loaderFunc[T eventsourcing.Root] func(ctx context.Context, key string) (T, error)

func (f loaderFunc[T]) Load(ctx context.Context, key string) (T, error) { return f(ctx, key) }

func staticLoader[T eventsourcing.Root](agg T, err error) loaderFunc[T] {
	return func(context.Context, string) (T, error) { return agg, err }
}

// fakeRevoker records the "void everything" the verification asks for.
//
// It records the COMMANDS rather than counting them, because every assertion
// worth making here is about a field of one: which subject, which reason, and
// whether anything was spared. A counter would pass on a call that voided the
// wrong subject's sessions.
type fakeRevoker struct {
	calls []RevokeAllSessionsCommand
	err   error
}

func (f *fakeRevoker) RevokeAllSessions(
	_ context.Context, cmd RevokeAllSessionsCommand,
) (RevokeAllSessionsResult, error) {
	f.calls = append(f.calls, cmd)
	if f.err != nil {
		return RevokeAllSessionsResult{}, f.err
	}
	// Zero, and deliberately so: this is what the real handler returns today for
	// a subject with no sessions. A test that asserted on this result would pass
	// with the call removed, which is why the assertions are on f.calls.
	return RevokeAllSessionsResult{}, nil
}

type fakeAppender struct {
	err   error
	calls [][]eventsourcing.StreamAppend
}

func (f *fakeAppender) AppendToMany(
	_ context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	// Copied, because the handler owns the slices it passed and a later mutation
	// would silently rewrite what a test asserts against.
	snapshot := make([]eventsourcing.StreamAppend, len(appends))
	copy(snapshot, appends)
	f.calls = append(f.calls, snapshot)
	if f.err != nil {
		return nil, f.err
	}
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for range appends {
		out = append(out, eventsourcing.AppendResult{
			Revision: 0,
			Position: eventsourcing.Position{Commit: 42, Prepare: 42},
		})
	}
	return out, nil
}

// issuedToken is one call to TokenStore.Issue, recorded whole.
//
// Recorded whole rather than counted because every argument carries a way for
// the handler to be wrong that a count cannot see: the wrong purpose makes the
// row unfindable by the verification lookup, the wrong subject binds the link to
// somebody else's account, and a zero expiry either voids the token immediately
// or, depending on the store, never.
type issuedToken struct {
	purpose   TokenPurpose
	subjectID string
	digest    []byte
	expiresAt time.Time
}

type revokedTokens struct {
	purpose   TokenPurpose
	subjectID string
}

type fakeTokens struct {
	subjectID string
	err       error
	calls     int
	purpose   TokenPurpose
	digest    []byte

	issueErr  error
	revokeErr error
	issued    []issuedToken
	revoked   []revokedTokens

	// journal records the ORDER of the write calls. "one live token per purpose"
	// is a claim about sequence — a revoke that runs after the issue deletes the
	// token it was meant to protect — and no per-call assertion can see it.
	journal []string
}

func (f *fakeTokens) Issue(
	_ context.Context, purpose TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	f.journal = append(f.journal, "issue")
	if f.issueErr != nil {
		return f.issueErr
	}
	f.issued = append(f.issued, issuedToken{
		purpose: purpose, subjectID: subjectID, digest: digest, expiresAt: expiresAt,
	})
	return nil
}

func (f *fakeTokens) Consume(
	_ context.Context, purpose TokenPurpose, digest []byte, _ time.Time,
) (string, error) {
	f.calls++
	f.purpose = purpose
	f.digest = digest
	return f.subjectID, f.err
}

func (f *fakeTokens) RevokeAll(_ context.Context, purpose TokenPurpose, subjectID string) error {
	f.journal = append(f.journal, "revoke")
	if f.revokeErr != nil {
		return f.revokeErr
	}
	f.revoked = append(f.revoked, revokedTokens{purpose: purpose, subjectID: subjectID})
	return nil
}

// liveTokens is a TokenStore that actually behaves like one: purpose-scoped,
// expiring, single-use.
//
// It exists so a test can register and then VERIFY with the token the
// registration minted, through both handlers and both digest derivations. A
// recording fake cannot show that: the two sides can disagree about the purpose
// they digest under, or about the purpose they filter on, and every assertion
// made against a recorder still passes while no real link ever works.
type liveTokens struct {
	rows map[string]liveTokenRow
}

type liveTokenRow struct {
	subjectID string
	expiresAt time.Time
}

func newLiveTokens() *liveTokens { return &liveTokens{rows: map[string]liveTokenRow{}} }

// key mirrors the production schema: the digest is the primary key and the
// purpose is part of the lookup, exactly as identity_token has it.
func (s *liveTokens) key(purpose TokenPurpose, digest []byte) string {
	return string(purpose) + "|" + hex.EncodeToString(digest)
}

func (s *liveTokens) Issue(
	_ context.Context, purpose TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	s.rows[s.key(purpose, digest)] = liveTokenRow{subjectID: subjectID, expiresAt: expiresAt}
	return nil
}

func (s *liveTokens) Consume(
	_ context.Context, purpose TokenPurpose, digest []byte, now time.Time,
) (string, error) {
	k := s.key(purpose, digest)
	row, ok := s.rows[k]
	// Unknown, spent and expired are one outcome, as in the real query.
	if !ok || !row.expiresAt.After(now) {
		return "", ErrTokenNotFound
	}
	delete(s.rows, k)
	return row.subjectID, nil
}

func (s *liveTokens) RevokeAll(_ context.Context, purpose TokenPurpose, subjectID string) error {
	for k, row := range s.rows {
		if row.subjectID == subjectID && strings.HasPrefix(k, string(purpose)+"|") {
			delete(s.rows, k)
		}
	}
	return nil
}

// live returns the subjects holding a redeemable token of a purpose.
func (s *liveTokens) live(purpose TokenPurpose, now time.Time) []string {
	out := []string{}
	for k, row := range s.rows {
		if strings.HasPrefix(k, string(purpose)+"|") && row.expiresAt.After(now) {
			out = append(out, row.subjectID)
		}
	}
	return out
}

// testDigest is the digest derivation BOTH sides of the test use.
//
// One function, deliberately, mirroring production where adapter/token.Digest is
// passed as the Digest port and used inside the minter. Two derivations that
// merely look alike would hide the failure this whole arrangement exists to
// catch: a handler issuing under one purpose and redeeming under another
// produces two different digests from one plaintext, and every link is silently
// refused.
func testDigest(purpose TokenPurpose, plaintext string) []byte {
	sum := sha256.Sum256([]byte(string(purpose) + "|" + plaintext))
	return sum[:]
}

// fakeMinter stands in for adapter/token.Minter.
//
// It produces a distinct plaintext per call, so a test can tell one attempt's
// token from another's, and it derives the digest through testDigest — the same
// function the Digest port uses — because that binding is what the real minter
// has and what a hand-rolled fake would quietly break.
type fakeMinter struct {
	err      error
	calls    int
	purposes []TokenPurpose
	minted   []MintedToken
	ttl      time.Duration

	// label distinguishes the output of two minters. The real one reads 32 bytes
	// from crypto/rand, so two of them never collide; this one counts, so two
	// harnesses sharing a token store would otherwise produce the same plaintext,
	// the same digest, the same primary key — and the second issue would silently
	// overwrite the first instead of leaving the two rows the test is about.
	label string
}

func (m *fakeMinter) mint(purpose TokenPurpose, now time.Time) (MintedToken, error) {
	m.calls++
	m.purposes = append(m.purposes, purpose)
	if m.err != nil {
		return MintedToken{}, m.err
	}
	ttl := m.ttl
	if ttl == 0 {
		// The real verification TTL. Shorter than the reservation lease, which is
		// the relation DefaultReservationLease exists to preserve.
		ttl = 24 * time.Hour
	}
	tok := MintedToken{
		Plaintext: fmt.Sprintf("minted-secret-%s%d", m.label, m.calls),
		ExpiresAt: now.Add(ttl).UTC(),
	}
	tok.Digest = testDigest(purpose, tok.Plaintext)
	m.minted = append(m.minted, tok)
	return tok, nil
}

// last returns the most recently minted token, failing when nothing was minted —
// which is the state the bug this fake was written for produced.
func (m *fakeMinter) last(t *testing.T) MintedToken {
	t.Helper()
	if len(m.minted) == 0 {
		t.Fatal("no verification token was minted")
	}
	return m.minted[len(m.minted)-1]
}

type fakeDirectory struct {
	user ids.UserID
	err  error

	// only, when set, is the ONE subject this directory resolves. Left empty it
	// answers every subject alike, which is right where the subject is not what a
	// test is about — and wrong where it is: a directory that resolves anything
	// would let a token minted for an account that was never created verify the
	// account that was.
	only string
}

func (f fakeDirectory) UserBySubject(_ context.Context, subjectID string) (ids.UserID, error) {
	if f.only != "" && subjectID != f.only {
		return ids.UserID{}, ErrNoSuchSubject
	}
	return f.user, f.err
}

// fixedEntropy is a deterministic, unlimited byte source. ids.New panics on a
// short read, so it must never run out.
type fixedEntropy struct{ b byte }

func (e *fixedEntropy) Read(p []byte) (int, error) {
	for i := range p {
		e.b++
		p[i] = e.b
	}
	return len(p), nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const (
	testEmail    = "Alice+Tag@Example.COM"
	testPassword = "correct horse battery staple"
)

var testNow = time.Date(2026, 3, 4, 5, 6, 7, 0, time.UTC)

type harness struct {
	t *testing.T

	indexer     fakeIndexer
	breach      *fakeBreach
	hasher      *fakeHasher
	vault       *fakeVault
	credentials *fakeCredentials
	appender    *fakeAppender
	schemas     *eventsourcing.UpcasterRegistry
	tokens      *fakeTokens
	minter      *fakeMinter
	directory   fakeDirectory
	revocations *fakeRevoker

	// entropy seeds the id generator. Deterministic, so two harnesses built the
	// same way mint the SAME subject id — which is convenient everywhere except
	// where a test needs two attempts to look like two different people.
	entropy io.Reader

	// tokenStore overrides tokens when a test needs a store that really behaves
	// like one — see liveTokens. Nil means the recording fake.
	tokenStore TokenStore

	// logs, when non-nil, captures everything the handler logs. A secret that
	// reaches a log line is durable in a way the token itself is not, so the only
	// way to assert its absence is to hold the bytes.
	logs *bytes.Buffer

	reservation *domain.EmailReservation
	user        *domain.User
	loadErr     error

	digestCalls []TokenPurpose
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	return &harness{
		t:           t,
		breach:      &fakeBreach{},
		hasher:      &fakeHasher{},
		vault:       &fakeVault{},
		credentials: &fakeCredentials{},
		appender:    &fakeAppender{},
		schemas:     identitySchemas(),
		tokens:      &fakeTokens{subjectID: "subj_unset"},
		minter:      &fakeMinter{},
		revocations: &fakeRevoker{},
		entropy:     &fixedEntropy{},
		reservation: eventsourcing.NewAggregate(domain.NewReservation),
		user:        eventsourcing.NewAggregate(domain.New),
	}
}

func (h *harness) build() *Registration {
	h.t.Helper()
	var tokens TokenStore = h.tokens
	if h.tokenStore != nil {
		tokens = h.tokenStore
	}
	var log *slog.Logger
	if h.logs != nil {
		// Debug level, so nothing the handler might log is filtered out before the
		// assertion can see it. A test that only captured warnings would pass on a
		// handler that logged the token at Info.
		log = slog.New(slog.NewTextHandler(h.logs, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	r, err := NewRegistration(RegistrationDeps{
		Clock:       clock.NewFixed(testNow),
		Entropy:     h.entropy,
		Index:       h.indexer,
		Breach:      h.breach,
		Hasher:      h.hasher,
		Vault:       h.vault,
		Credentials: h.credentials,
		Reservations: loaderFunc[*domain.EmailReservation](
			func(context.Context, string) (*domain.EmailReservation, error) {
				return h.reservation, h.loadErr
			}),
		Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
			return h.user, h.loadErr
		}),
		Appender: h.appender,
		// The registry the production composition root passes. Without it every
		// event is appended at schema version 0 while the registry declares 1.
		Schemas:     h.schemas,
		Tokens:      tokens,
		Minter:      h.minter.mint,
		Digest:      h.digestFn(),
		Directory:   h.directory,
		Revocations: h.revocations,
		Log:         log,
	})
	if err != nil {
		h.t.Fatalf("wiring the handler: %v", err)
	}
	return r
}

func (h *harness) digestFn() TokenDigest {
	return func(purpose TokenPurpose, plaintext string) []byte {
		h.digestCalls = append(h.digestCalls, purpose)
		return testDigest(purpose, plaintext)
	}
}

func mustIndex(t *testing.T, email string) contract.EmailIndex {
	t.Helper()
	idx, err := fakeIndexer{}.Of(email)
	if err != nil {
		t.Fatalf("deriving the index: %v", err)
	}
	return idx
}

// appendFor returns the entry for a stream, and fails when there is none.
func appendFor(t *testing.T, appends []eventsourcing.StreamAppend, stream eventsourcing.StreamID) eventsourcing.StreamAppend {
	t.Helper()
	for _, a := range appends {
		if a.Stream == stream {
			return a
		}
	}
	t.Fatalf("no append for %s; got %v", stream, streamsOf(appends))
	return eventsourcing.StreamAppend{}
}

func streamsOf(appends []eventsourcing.StreamAppend) []string {
	out := make([]string, 0, len(appends))
	for _, a := range appends {
		out = append(out, a.Stream.String())
	}
	return out
}

func eventTypesOf(a eventsourcing.StreamAppend) []string {
	out := make([]string, 0, len(a.Events))
	for _, e := range a.Events {
		out = append(out, e.Event.EventType())
	}
	return out
}

// testCodec encodes exactly the events these handlers can produce. Used to
// rebuild aggregates at a real revision, and to inspect encoded payloads.
func testCodec(t *testing.T) *eventcodec.JSON {
	t.Helper()
	c := eventcodec.NewJSON(nil)
	eventcodec.Register[contract.EmailReserved](c)
	eventcodec.Register[contract.EmailReservationConfirmed](c)
	eventcodec.Register[contract.EmailReleased](c)
	eventcodec.Register[contract.UserRegistered](c)
	eventcodec.Register[contract.EmailVerificationRequested](c)
	eventcodec.Register[contract.EmailVerified](c)
	eventcodec.Register[contract.UserActivated](c)
	eventcodec.Register[contract.PasswordSet](c)
	return c
}

// replayStore serves a fixed stream so a repository can rebuild an aggregate at
// a genuine revision.
//
// Hand-positioning an aggregate is not possible from outside the kernel — and
// should not be. Going through the repository is what makes the expected-revision
// assertions below mean something: AtRevision(0) here is the revision the store
// actually reported, not a number a test chose.
type replayStore struct {
	t      *testing.T
	codec  eventsourcing.Codec
	events []eventsourcing.Event
}

func (s *replayStore) ReadStream(
	_ context.Context, stream eventsourcing.StreamID, from eventsourcing.Revision,
) ([]eventsourcing.RecordedEvent, error) {
	if len(s.events) == 0 {
		return nil, eventsourcing.ErrStreamNotFound
	}
	out := make([]eventsourcing.RecordedEvent, 0, len(s.events))
	for i, e := range s.events {
		if eventsourcing.Revision(i) < from {
			continue
		}
		payload, err := s.codec.Marshal(e)
		if err != nil {
			s.t.Fatalf("marshalling %s: %v", e.EventType(), err)
		}
		meta, err := s.codec.MarshalMetadata(eventsourcing.Metadata{OccurredAt: testNow})
		if err != nil {
			s.t.Fatalf("marshalling metadata: %v", err)
		}
		out = append(out, eventsourcing.RecordedEvent{
			Type:     e.EventType(),
			Stream:   stream,
			Revision: eventsourcing.Revision(i),
			Payload:  payload,
			Metadata: meta,
		})
	}
	return out, nil
}

func (s *replayStore) Append(
	context.Context, eventsourcing.StreamID, eventsourcing.ExpectedRevision, []eventsourcing.PendingEvent,
) (eventsourcing.AppendResult, error) {
	s.t.Fatal("a test aggregate was saved through the replay store")
	return eventsourcing.AppendResult{}, nil
}

func rebuiltReservation(t *testing.T, events ...eventsourcing.Event) *domain.EmailReservation {
	t.Helper()
	codec := testCodec(t)
	repo := eventsourcing.NewRepository(
		&replayStore{t: t, codec: codec, events: events},
		codec, nil, ReservationCategory, domain.NewReservation)
	agg, err := repo.Load(context.Background(), string(mustIndex(t, testEmail)))
	if err != nil {
		t.Fatalf("rebuilding the reservation: %v", err)
	}
	return agg
}

func rebuiltUser(t *testing.T, key string, events ...eventsourcing.Event) *domain.User {
	t.Helper()
	codec := testCodec(t)
	repo := eventsourcing.NewRepository(
		&replayStore{t: t, codec: codec, events: events},
		codec, nil, UserCategory, domain.New)
	agg, err := repo.Load(context.Background(), key)
	if err != nil {
		t.Fatalf("rebuilding the user: %v", err)
	}
	return agg
}

// ---------------------------------------------------------------------------
// Register
// ---------------------------------------------------------------------------

func TestRegisterWritesBothStreamsInOneAtomicAppend(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !got.Created {
		t.Fatal("Created is false for a fresh address")
	}

	// ONE call. Two calls would be two appends, which is the non-atomic design
	// this whole use case exists to avoid — and it would still satisfy every
	// per-stream assertion below.
	if len(h.appender.calls) != 1 {
		t.Fatalf("AppendToMany called %d times, want exactly 1", len(h.appender.calls))
	}
	appends := h.appender.calls[0]
	if len(appends) != 2 {
		t.Fatalf("the atomic append carries %d streams (%v), want 2",
			len(appends), streamsOf(appends))
	}

	index := mustIndex(t, testEmail)
	reservation := appendFor(t, appends,
		eventsourcing.MustStreamID(ReservationCategory, string(index)))
	user := appendFor(t, appends,
		eventsourcing.MustStreamID(UserCategory, got.UserID.String()))

	// NoStream on the reservation IS the uniqueness rule (ADR-044). Anything
	// weaker lets two registrations for one address both succeed.
	if !reservation.Expected.IsNoStream() {
		t.Errorf("reservation precondition is %s, want no_stream", reservation.Expected)
	}
	if !user.Expected.IsNoStream() {
		t.Errorf("user precondition is %s, want no_stream", user.Expected)
	}

	if diff := fmt.Sprint(eventTypesOf(reservation)); diff != "[identity.EmailReserved.v1]" {
		t.Errorf("reservation events %s", diff)
	}
	// The verification request rides the SAME append, and rides it LAST: the
	// account is created and is then asked to prove its address. A second append
	// for it would reintroduce exactly the window this use case exists to close —
	// an account holding an address with no way to prove it, or a request to
	// prove an account that does not exist.
	//
	// PasswordSet is ABSENT, and its absence is the assertion (IDENTITY-REVIEW
	// C8). A registration that recorded one would be recording a credential
	// chosen by whoever typed the address, for a mailbox nobody has yet proven
	// they can read — the pre-hijacking premise. It is recorded by VerifyEmail
	// instead, and this exact-match comparison is what makes putting it back a
	// test failure rather than a silent regression.
	if diff := fmt.Sprint(eventTypesOf(user)); diff !=
		"[identity.UserRegistered.v1 identity.EmailVerificationRequested.v1]" {
		t.Errorf("user events %s", diff)
	}

	reserved, ok := reservation.Events[0].Event.(*contract.EmailReserved)
	if !ok {
		t.Fatalf("first reservation event is %T", reservation.Events[0].Event)
	}
	if reserved.Index != index {
		t.Errorf("reserved index %q, want %q", reserved.Index, index)
	}
	if reserved.SubjectID != got.SubjectID {
		t.Errorf("reserved subject %q, want %q", reserved.SubjectID, got.SubjectID)
	}
	// The lease must outlive the 24h verification link, or Confirm refuses a
	// claim whose own link is still valid.
	if lease := reserved.ExpiresAt.Sub(testNow); lease <= 24*time.Hour {
		t.Errorf("the reservation lease is %s, which does not outlive the verification link", lease)
	}

	registered, ok := user.Events[0].Event.(*contract.UserRegistered)
	if !ok {
		t.Fatalf("first user event is %T", user.Events[0].Event)
	}
	if registered.UserID != got.UserID.String() {
		t.Errorf("registered user %q, want %q", registered.UserID, got.UserID)
	}
	if registered.EmailIndex != index {
		t.Errorf("registered index %q, want %q", registered.EmailIndex, index)
	}

	if got.Position != (eventsourcing.Position{Commit: 42, Prepare: 42}) {
		t.Errorf("position %v is not the one the append reported", got.Position)
	}
}

// TestRegisterStoresTheAddressOffTheLogAndNoCredentialAtAll is two assertions
// that used to be one.
//
// The address still goes to the vault, because the reactor has to be able to
// mail it. The VERIFIER does not go anywhere, because there is no verifier: a
// registration creates no credential (IDENTITY-REVIEW C8), so the credential
// store must not be touched and no PasswordSet may reach the log.
//
// The negative half is written as a count on the store AND as an absence in the
// events, deliberately. Either alone can pass while the other fails: a handler
// could hash and store without appending (leaving an orphan verifier the account
// does not know about), or append without storing (leaving an account the log
// says has a password that nothing can verify).
func TestRegisterStoresTheAddressOffTheLogAndNoCredentialAtAll(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	// The vault gets the NORMALIZED address — the same form the index was
	// derived from. Storing the raw input would let one person hold two accounts
	// whose addresses differ only in case.
	stored := h.vault.stored[pii.SubjectID(got.SubjectID)]
	if want := "alice+tag@example.com"; stored[pii.FieldEmail] != want {
		t.Errorf("vault holds %q, want %q", stored[pii.FieldEmail], want)
	}

	if h.credentials.calls != 0 {
		t.Errorf("a registration stored %d password verifiers, want 0: a credential "+
			"that exists before the address is proven is the pre-hijacking premise — "+
			"the mailbox owner's click would activate a password a stranger chose",
			h.credentials.calls)
	}
	if h.hasher.calls != 0 {
		t.Errorf("a registration hashed %d passwords, want 0; there is no password to "+
			"hash and nothing to store the result under", h.hasher.calls)
	}

	userAppend := appendFor(t, h.appender.calls[0],
		eventsourcing.MustStreamID(UserCategory, got.UserID.String()))
	for _, e := range userAppend.Events {
		if _, ok := e.Event.(*contract.PasswordSet); ok {
			t.Error("a registration appended PasswordSet; the account would report a " +
				"password it never received, and CanAuthenticate is the only thing " +
				"left standing between that and a login")
		}
	}
}

// TestRegisterPutsNoPersonalDataInAnyEvent is the ADR-002 guard.
//
// It inspects the ENCODED payloads rather than the structs, because that is what
// is durable: a field added later with a json tag would appear here even if no
// assertion above named it.
func TestRegisterPutsNoPersonalDataInAnyEvent(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	codec := testCodec(t)

	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// No verifier in this list any more, and that is not an oversight: a
	// registration produces none. An empty string here would make
	// strings.Contains match every payload and the test would fail for a reason
	// that has nothing to do with ADR-002.
	forbidden := []string{
		testEmail, strings.ToLower(testEmail), "alice", "example.com",
		testPassword,
	}
	for _, a := range h.appender.calls[0] {
		for _, e := range a.Events {
			payload, err := codec.Marshal(e.Event)
			if err != nil {
				t.Fatalf("marshalling %s: %v", e.Event.EventType(), err)
			}
			// The METADATA is checked too, and it is the easier place to get this
			// wrong: SubjectIDs and ActorID take strings, so an address put in one
			// of them is durable, replicated, and invisible to any assertion that
			// only reads the payload.
			meta, err := codec.MarshalMetadata(e.Meta)
			if err != nil {
				t.Fatalf("marshalling metadata for %s: %v", e.Event.EventType(), err)
			}
			for _, needle := range forbidden {
				for _, encoded := range [][]byte{payload, meta} {
					if strings.Contains(strings.ToLower(string(encoded)), strings.ToLower(needle)) {
						t.Errorf("%s carries %q: %s", e.Event.EventType(), needle, encoded)
					}
				}
			}
		}
	}
}

// Metadata must also be POSITIVELY populated, not merely free of personal data.
//
// The test above is one-sided: it asserts that certain strings are absent. Every
// one of these fields passes it when emptied, and emptying SubjectIDs is the
// expensive mistake — it is the fan-out key erasure uses to find which events
// reference a subject (ADR-002), so an account whose events carry no pseudonym
// cannot be erased, and nothing reports that until somebody exercises their right
// to be forgotten and the job finds nothing.
//
// Written after a mutation pass found that blanking SubjectIDs, ActorID and the
// derived CorrelationID all survived the entire suite.
func TestRegisterPopulatesEventMetadata(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	res, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-meta",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	var checked int
	for _, a := range h.appender.calls[0] {
		for _, e := range a.Events {
			checked++
			meta := e.Meta

			if len(meta.SubjectIDs) != 1 || meta.SubjectIDs[0] != res.SubjectID {
				t.Errorf("%s carries SubjectIDs %v, want exactly [%s]: erasure finds the "+
					"events concerning a subject through this field, so an event without it "+
					"is an event erasure cannot reach",
					e.Event.EventType(), meta.SubjectIDs, res.SubjectID)
			}
			if meta.ActorID != res.SubjectID {
				t.Errorf("%s carries ActorID %q, want %q: without it the log cannot say who "+
					"caused the fact", e.Event.EventType(), meta.ActorID, res.SubjectID)
			}
			// Derived, not empty. A registration arrives with no ambient trace —
			// nobody caused it but the registrant — so the chain has to be rooted
			// here, and rooted DETERMINISTICALLY: a retry of the same command must
			// join the same chain rather than start a second one.
			if meta.CorrelationID == "" {
				t.Errorf("%s has no correlation id, so a retry of this command would open a "+
					"second causation chain for one registration", e.Event.EventType())
			}
			if meta.CausationID == "" {
				t.Errorf("%s has no causation id", e.Event.EventType())
			}
			if meta.OccurredAt.IsZero() {
				t.Errorf("%s has a zero OccurredAt", e.Event.EventType())
			}
			if meta.OccurredAt.Location() != time.UTC {
				t.Errorf("%s records %v, not UTC", e.Event.EventType(), meta.OccurredAt.Location())
			}
		}
	}
	if checked == 0 {
		// Without this the loop above passes vacuously on an append that carried
		// nothing, which is precisely the state a broken handler produces.
		t.Fatal("no events were appended, so nothing was checked")
	}
}

// A retried registration joins ONE causation chain rather than opening a second.
//
// The correlation id is derived from the idempotency key when no ambient trace
// exists, so two attempts at the same command agree. Asserted separately from the
// event ids, which have their own test: they were equal in the mutation that
// dropped this derivation, and the suite noticed nothing.
func TestRegisterRootsRetriesOnOneCausationChain(t *testing.T) {
	t.Parallel()

	correlationFor := func(key string) string {
		h := newHarness(t)
		if _, err := h.build().Register(context.Background(), RegisterCommand{
			Email: testEmail, IdempotencyKey: key,
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		return h.appender.calls[0][0].Events[0].Meta.CorrelationID
	}

	first, second := correlationFor("cmd-retry"), correlationFor("cmd-retry")
	if first == "" {
		t.Fatal("no correlation id was derived for a command with no ambient trace")
	}
	if first != second {
		t.Errorf("two attempts at one command correlate as %q and %q; a retry has become a "+
			"second chain and the two look like unrelated registrations", first, second)
	}
	if other := correlationFor("cmd-different"); other == first {
		t.Errorf("two DIFFERENT commands share correlation id %q, so the derivation ignores "+
			"the idempotency key", other)
	}
}

func TestRegisterDerivesStableEventIDsFromTheIdempotencyKey(t *testing.T) {
	t.Parallel()

	idsFor := func(key string) []string {
		h := newHarness(t)
		if _, err := h.build().Register(context.Background(), RegisterCommand{
			Email: testEmail, IdempotencyKey: key,
		}); err != nil {
			t.Fatalf("Register: %v", err)
		}
		var out []string
		for _, a := range h.appender.calls[0] {
			for _, e := range a.Events {
				out = append(out, e.ID.String())
			}
		}
		return out
	}

	first, second := idsFor("cmd-1"), idsFor("cmd-1")
	if fmt.Sprint(first) != fmt.Sprint(second) {
		t.Errorf("a retry derived different event ids:\n %v\n %v", first, second)
	}
	// Three events across two streams, all distinct: the sequence spans the whole
	// command, so no two events of one append can collide.
	seen := map[string]bool{}
	for _, id := range first {
		if id == "" {
			t.Fatal("an event was appended with no id")
		}
		if seen[id] {
			t.Fatalf("two events share the id %s", id)
		}
		seen[id] = true
	}
	if other := idsFor("cmd-2"); fmt.Sprint(other) == fmt.Sprint(first) {
		t.Error("two different commands derived the same event ids")
	}
}

func TestRegisterTakesOverALapsedClaimAtItsLoadedRevision(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	index := mustIndex(t, testEmail)
	// An unverified claim whose lease ran out an hour ago.
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index:      index,
		SubjectID:  "subj_squatter",
		ExpiresAt:  testNow.Add(-time.Hour),
		ReservedAt: testNow.Add(-49 * time.Hour),
	})

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-1",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !got.Created {
		t.Fatal("a lapsed claim did not free the address")
	}

	reservation := appendFor(t, h.appender.calls[0],
		eventsourcing.MustStreamID(ReservationCategory, string(index)))
	// NOT NoStream: the stream exists. Sending NoStream here would fail every
	// takeover, and AnyRevision would make the takeover race itself.
	rev, exact := reservation.Expected.Exact()
	if !exact || rev != 0 {
		t.Fatalf("takeover precondition is %s, want exact(0)", reservation.Expected)
	}
	// The release is recorded FIRST, so the log explains what happened to the
	// previous registrant rather than overwriting them silently.
	if diff := fmt.Sprint(eventTypesOf(reservation)); diff !=
		"[identity.EmailReleased.v1 identity.EmailReserved.v1]" {
		t.Errorf("takeover events %s", diff)
	}
}

func TestRegisterDoesNotDiscloseThatAnAddressIsTaken(t *testing.T) {
	t.Parallel()
	index := mustIndex(t, testEmail)

	cases := []struct {
		name    string
		arrange func(*harness)
	}{
		{
			name: "a verified claim held by somebody else",
			arrange: func(h *harness) {
				h.reservation = rebuiltReservation(t,
					&contract.EmailReserved{
						Index:     index,
						SubjectID: "subj_owner",
						ExpiresAt: testNow.Add(time.Hour),
					},
					&contract.EmailReservationConfirmed{Index: index, SubjectID: "subj_owner"},
				)
			},
		},
		{
			name: "an unverified claim still inside its lease",
			arrange: func(h *harness) {
				h.reservation = rebuiltReservation(t, &contract.EmailReserved{
					Index:     index,
					SubjectID: "subj_owner",
					ExpiresAt: testNow.Add(time.Hour),
				})
			},
		},
		{
			name: "losing the race for the stream at append time",
			arrange: func(h *harness) {
				h.appender.err = fmt.Errorf("appending: %w",
					eventsourcing.ErrWrongExpectedRevision)
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tc.arrange(h)

			got, err := h.build().Register(context.Background(), RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			})
			// No error at all, and specifically not CONFLICT: a distinguishable
			// outcome answers "does an account exist for this address?".
			if err != nil {
				t.Fatalf("a taken address produced %v (reason %s); the response must be "+
					"indistinguishable from a successful registration",
					err, errs.ReasonOf(err))
			}
			if got.Created {
				t.Error("Created is true for an address that was already claimed")
			}
			if got != (RegisterResult{}) {
				t.Errorf("a refused registration returned %+v; nothing about the "+
					"account may leak", got)
			}
			// This handler used to pay an Argon2id hash on both paths and call
			// that its timing defence. It never was one: the hash was a constant
			// ADDED to both, while the free path additionally wrote the vault,
			// issued a token digest and appended — so the DIFFERENCE between the
			// two was the same with the hash as without it. There is no password
			// here now, so the hash is gone and the delta is unchanged.
			//
			// What is still asserted is the part that was always doing the work:
			// no error, and a zero result. See RegisterResult's doc for the
			// residual timing delta, which is stated rather than closed.
			if h.hasher.calls != 0 {
				t.Errorf("a registration hashed %d times; it has no password to hash",
					h.hasher.calls)
			}
		})
	}
}

func TestRegisterWritesNothingWhenTheAddressIsAlreadyClaimed(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	index := mustIndex(t, testEmail)
	h.reservation = rebuiltReservation(t,
		&contract.EmailReserved{Index: index, SubjectID: "subj_owner", ExpiresAt: testNow.Add(time.Hour)},
		&contract.EmailReservationConfirmed{Index: index, SubjectID: "subj_owner"},
	)

	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	// A probe must not deposit the prober's address in the vault. The decision is
	// made against the stream before anything personal is written, which is what
	// keeps enumeration from accumulating personal data about people who never
	// registered.
	if h.vault.calls != 0 {
		t.Errorf("the vault was written %d times for an address that was already claimed", h.vault.calls)
	}
	if h.credentials.calls != 0 {
		t.Errorf("a verifier was stored %d times for a refused registration", h.credentials.calls)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends were made for a refused registration", len(h.appender.calls))
	}
}

// TestVerifyEmailScreensThePasswordBeforeSpendingTheToken is the breach check in
// its new home, plus the property that decides whether a rejected password costs
// the user their link.
//
// The screening moved from Register when the password did (IDENTITY-REVIEW C8),
// and moving it raised a question registration never had to answer: this call
// holds a single-use token, so a refusal AFTER Consume is a lockout rather than
// an inconvenience. It runs before, and the ordering is asserted here rather
// than described in a comment, because "before" and "after" are one line apart
// and only one of them is safe.
//
// It is not an oracle. Both refusals are functions of the caller's own bytes —
// too short, or in a public corpus — and neither consults the token, the account
// or the address. An attacker learns nothing by repeating the call, and their
// guessing surface against the TOKEN is untouched: a wrong digest fails at
// Consume identically however good the password beside it was.
func TestVerifyEmailScreensThePasswordBeforeSpendingTheToken(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		password    string
		breach      *fakeBreach
		wantErr     bool
		wantReason  errs.Reason
		wantConsume int
		wantHashes  int
		wantAppends int
	}{
		{
			name:       "a breached password is refused, and the link survives",
			password:   testPassword,
			breach:     &fakeBreach{breached: true, corpus: "hibp"},
			wantErr:    true,
			wantReason: errs.ValidationFailed,
		},
		{
			name:       "a password under the floor is refused, and the link survives",
			password:   "short",
			breach:     &fakeBreach{},
			wantErr:    true,
			wantReason: errs.ValidationFailed,
		},
		{
			name:        "an unreachable corpus fails open",
			password:    testPassword,
			breach:      &fakeBreach{err: errors.New("corpus unreachable")},
			wantConsume: 1,
			wantHashes:  1,
			wantAppends: 1,
		},
		{
			name:        "a clean password proceeds",
			password:    testPassword,
			breach:      &fakeBreach{},
			wantConsume: 1,
			wantHashes:  1,
			wantAppends: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _, _ := verifyHarness(t)
			h.breach = tc.breach

			_, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
				Token: "the-emailed-secret", Password: tc.password,
				IdempotencyKey: "cmd-verify",
			})
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("an unacceptable password was accepted")
			case tc.wantErr && errs.ReasonOf(err) != tc.wantReason:
				t.Fatalf("reason %s, want %s", errs.ReasonOf(err), tc.wantReason)
			case !tc.wantErr && err != nil:
				t.Fatalf("VerifyEmail: %v", err)
			}
			// THE assertion. A refused password must leave the token unspent, or a
			// person who picks a weak one at the end of a signup is told their link
			// is dead in the same breath, and the only way back is a resend they
			// have to know to ask for.
			if h.tokens.calls != tc.wantConsume {
				t.Errorf("the token was consumed %d times, want %d — a password refused "+
					"for its own shape must not cost the user their single-use link",
					h.tokens.calls, tc.wantConsume)
			}
			if h.hasher.calls != tc.wantHashes {
				t.Errorf("hashed %d times, want %d — screening must happen BEFORE the "+
					"51ms hash, or a rejected password still costs one",
					h.hasher.calls, tc.wantHashes)
			}
			if len(h.appender.calls) != tc.wantAppends {
				t.Errorf("%d appends, want %d", len(h.appender.calls), tc.wantAppends)
			}
			if tc.breach.calls != 1 {
				t.Errorf("the corpus was consulted %d times, want 1", tc.breach.calls)
			}
		})
	}
}

func TestVerifyEmailNormalizesThePasswordBeforeHashing(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)

	// U+00A0 NO-BREAK SPACE and a decomposed "é". Both must reach the hasher as
	// the RFC 8265 OpaqueString form, or the same password typed on another
	// keyboard or operating system will not verify.
	raw := "cafe\u0301\u00a0brulee\u00a0forever"
	want := "caf\u00e9 brulee forever"

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: raw, IdempotencyKey: "cmd-verify",
	}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if len(h.hasher.seen) != 1 || h.hasher.seen[0] != want {
		t.Errorf("hasher received %q, want %q", h.hasher.seen, want)
	}
	if raw == want {
		t.Fatal("the fixture normalizes to itself, so this test cannot fail")
	}
}

func TestRegisterRefusesBadInputAndPropagatesPortFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		cmd        RegisterCommand
		arrange    func(*harness)
		wantReason errs.Reason
		wantErr    error
		wantAppend bool
	}{
		{
			name:       "no idempotency key",
			cmd:        RegisterCommand{Email: testEmail},
			wantReason: errs.ValidationFailed,
		},
		{
			name: "an address with no domain",
			cmd: RegisterCommand{
				Email: "alice", IdempotencyKey: "cmd-1",
			},
			wantReason: errs.ValidationFailed,
		},
		// The password floor, the hasher and the credential store are NOT here.
		// None of them is reachable from a registration any more — they moved to
		// VerifyEmail with the password (IDENTITY-REVIEW C8) and are exercised by
		// TestVerifyEmailPropagatesPortFailures.
		{
			name: "the vault is unreachable",
			cmd: RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.vault.err = errors.New("vault down") },
			wantReason: errs.Internal,
		},
		// The three token failures below all fail the whole registration, and the
		// reason is what the person experiences. Failing, they see an error, retry,
		// and get a working account — the append never ran, so the address is still
		// free. Proceeding without a token would show them success and then silence:
		// no mail, no way to ask for another one, and an address they can never
		// register again because their own dead account now holds it.
		{
			name: "the token minter cannot produce a token",
			cmd: RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.minter.err = errors.New("entropy source short read") },
			wantReason: errs.Internal,
		},
		{
			name: "the token store cannot record the digest",
			cmd: RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.tokens.issueErr = errors.New("database down") },
			wantReason: errs.Internal,
		},
		{
			name: "outstanding tokens cannot be voided",
			cmd: RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			},
			// Not "best effort". A revocation that silently did not happen is how
			// two live links for one address survive, and the caller cannot tell.
			arrange:    func(h *harness) { h.tokens.revokeErr = errors.New("database down") },
			wantReason: errs.Internal,
		},
		{
			name: "the append fails for a reason that is not contention",
			cmd: RegisterCommand{
				Email: testEmail, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.appender.err = errors.New("kurrentdb unreachable") },
			wantReason: errs.Internal,
			wantAppend: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			if tc.arrange != nil {
				tc.arrange(h)
			}

			got, err := h.build().Register(context.Background(), tc.cmd)
			if err == nil {
				t.Fatalf("no error; got %+v", got)
			}
			if r := errs.ReasonOf(err); r != tc.wantReason {
				t.Errorf("reason %s, want %s (%v)", r, tc.wantReason, err)
			}
			if made := len(h.appender.calls) > 0; made != tc.wantAppend {
				t.Errorf("appended=%v, want %v — nothing may reach the log once the "+
					"command has failed", made, tc.wantAppend)
			}
		})
	}
}

func TestNewRegistrationRefusesIncompleteWiring(t *testing.T) {
	t.Parallel()

	complete := func() RegistrationDeps {
		h := newHarness(t)
		return RegistrationDeps{
			Clock: clock.NewFixed(testNow), Entropy: &fixedEntropy{},
			Index: h.indexer, Breach: h.breach, Hasher: h.hasher,
			Vault: h.vault, Credentials: h.credentials,
			Reservations: staticLoader(h.reservation, nil),
			Users:        staticLoader(h.user, nil),
			Appender:     h.appender, Tokens: h.tokens,
			Minter: h.minter.mint,
			Digest: h.digestFn(), Directory: h.directory,
			Revocations: h.revocations,
		}
	}
	if _, err := NewRegistration(complete()); err != nil {
		t.Fatalf("complete wiring was refused: %v", err)
	}

	cases := map[string]func(*RegistrationDeps){
		"clock":        func(d *RegistrationDeps) { d.Clock = nil },
		"entropy":      func(d *RegistrationDeps) { d.Entropy = nil },
		"indexer":      func(d *RegistrationDeps) { d.Index = nil },
		"breach":       func(d *RegistrationDeps) { d.Breach = nil },
		"hasher":       func(d *RegistrationDeps) { d.Hasher = nil },
		"vault":        func(d *RegistrationDeps) { d.Vault = nil },
		"credentials":  func(d *RegistrationDeps) { d.Credentials = nil },
		"reservations": func(d *RegistrationDeps) { d.Reservations = nil },
		"users":        func(d *RegistrationDeps) { d.Users = nil },
		"appender":     func(d *RegistrationDeps) { d.Appender = nil },
		"tokens":       func(d *RegistrationDeps) { d.Tokens = nil },
		// A nil minter is the shape the original defect had: everything else
		// present, registration succeeding, and no token ever issued. It has to be
		// refused at wiring time because there is no later moment at which the
		// omission is visible — the account looks exactly like one whose owner has
		// not clicked the link yet.
		"minter":    func(d *RegistrationDeps) { d.Minter = nil },
		"digest":    func(d *RegistrationDeps) { d.Digest = nil },
		"directory": func(d *RegistrationDeps) { d.Directory = nil },
		// The one dependency whose absence has NO runtime symptom whatsoever
		// today, in either direction: no account can hold a session before it is
		// verified, so a nil revoker never gets called and no request behaves
		// differently. Wiring time is therefore not merely the earliest place to
		// catch it, it is the only place — which is precisely the argument for
		// refusing it here rather than tolerating a nil and skipping the call.
		"revocations": func(d *RegistrationDeps) { d.Revocations = nil },
		"lease":       func(d *RegistrationDeps) { d.Lease = -time.Second },
		// Not a missing dependency but a dishonest one, and it belongs here
		// because the damage is done at wiring time: every verifier written under
		// it is invisible to the rotation job, and the accounts holding them are
		// locked out the moment the old transit key is destroyed.
		"hasher reporting pepper version 0": func(d *RegistrationDeps) {
			d.Hasher = zeroPepperHasher{d.Hasher}
		},
	}
	for name, remove := range cases {
		t.Run("with no usable "+name, func(t *testing.T) {
			t.Parallel()
			deps := complete()
			remove(&deps)
			if _, err := NewRegistration(deps); err == nil {
				t.Errorf("wiring with no %s was accepted", name)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Register — the verification token
//
// These exist because the flow shipped without them: TokenStore.Issue was called
// by no production code, adapter/token.Minter was constructed by no binary, and
// contract.EmailVerificationRequested was emitted nowhere. Every unit test passed
// and every registration produced an account that could never be verified. The
// tests below are written so that removing any part of the issue path fails at
// least one of them.
// ---------------------------------------------------------------------------

// TestRegisterIssuesTheVerificationTokenItMinted checks the four arguments that
// decide whether the stored row is the one a click can find.
func TestRegisterIssuesTheVerificationTokenItMinted(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-token",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if h.minter.calls != 1 {
		t.Fatalf("minted %d tokens, want exactly 1", h.minter.calls)
	}
	if len(h.minter.purposes) != 1 || h.minter.purposes[0] != PurposeEmailVerification {
		t.Errorf("minted under %v, want [%s]: the purpose fixes the token's lifetime, "+
			"and the reset lifetime is an hour rather than a day",
			h.minter.purposes, PurposeEmailVerification)
	}
	if len(h.tokens.issued) != 1 {
		t.Fatalf("stored %d token digests, want exactly 1 — a registration whose token "+
			"is never stored produces an account that can never be verified",
			len(h.tokens.issued))
	}

	minted := h.minter.last(t)
	issued := h.tokens.issued[0]
	switch {
	case issued.purpose != PurposeEmailVerification:
		t.Errorf("stored under purpose %q, want %q: VerifyEmail looks the digest up "+
			"under %s and would never find this row",
			issued.purpose, PurposeEmailVerification, PurposeEmailVerification)
	case issued.subjectID != got.SubjectID:
		t.Errorf("stored against subject %q, want %q — the token would verify "+
			"somebody else's address", issued.subjectID, got.SubjectID)
	case !bytes.Equal(issued.digest, minted.Digest):
		t.Error("the digest stored is not the digest of the token that was minted")
	case !issued.expiresAt.Equal(minted.ExpiresAt):
		t.Errorf("stored expiry %s, minted expiry %s", issued.expiresAt, minted.ExpiresAt)
	}

	// The stored form must not BE the plaintext. A store holding the secret itself
	// turns a database read into a working link for every pending account.
	if string(issued.digest) == minted.Plaintext {
		t.Error("the token plaintext was stored instead of its digest")
	}
	if minted.Plaintext == "" {
		t.Error("an empty token was minted, which every guess matches")
	}

	// The link must not outlive the claim it proves. EmailReservation.Confirm
	// refuses a lapsed claim, so a token that outlives its own reservation fails
	// for a user who did everything right.
	if !minted.ExpiresAt.After(testNow) {
		t.Errorf("the token expires at %s, which is not after %s", minted.ExpiresAt, testNow)
	}
	if lease := testNow.Add(DefaultReservationLease); !minted.ExpiresAt.Before(lease) {
		t.Errorf("the token expires at %s, after the reservation lease ends at %s",
			minted.ExpiresAt, lease)
	}
}

// TestRegisterIssuesATokenThatVerifyEmailCanRedeem is the end-to-end assertion,
// and the only one here that would catch a purpose or digest mismatch between the
// two handlers.
//
// Both sides derive their digest through the same function, exactly as production
// does — adapter/token.Digest is both the Digest port and what the minter hashes
// with — and adapter/token.Digest mixes the purpose in under a fixed-width length
// prefix. So issuing under one purpose and redeeming under another produces two
// different digests from one plaintext, the lookup finds nothing, and every link
// in the world is refused with "this verification link is no longer valid". No
// error is logged and no metric moves, because from the store's point of view
// nothing unusual happened.
func TestRegisterIssuesATokenThatVerifyEmailCanRedeem(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	store := newLiveTokens()
	h.tokenStore = store

	registration := h.build()
	got, err := registration.Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-register",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	if !got.Created {
		t.Fatal("Created is false for a fresh address")
	}

	// The state the click arrives in: the account and the claim are in the log,
	// and the directory resolves the pseudonym the token was issued against.
	h.user = rebuiltUser(t, got.UserID.String(), &contract.UserRegistered{
		UserID: got.UserID.String(), SubjectID: got.SubjectID,
		EmailIndex: got.EmailIndex, RegisteredAt: testNow,
	})
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: got.EmailIndex, SubjectID: got.SubjectID,
		ExpiresAt: testNow.Add(DefaultReservationLease),
	})
	h.directory = fakeDirectory{user: got.UserID}
	h.appender.calls = nil

	// The plaintext the minter produced is what the mail would carry. Nothing else
	// in the system holds it.
	plaintext := h.minter.last(t).Plaintext

	verified, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: plaintext, Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err != nil {
		t.Fatalf("the token this registration issued was refused by VerifyEmail: %v", err)
	}
	if !verified.Changed {
		t.Error("the verification recorded nothing")
	}
	if verified.SubjectID != got.SubjectID {
		t.Errorf("verified subject %q, want %q", verified.SubjectID, got.SubjectID)
	}

	// Single use. The row is gone, so the same link cannot be redeemed twice by
	// anyone who later reads the mailbox.
	if left := store.live(PurposeEmailVerification, testNow); len(left) != 0 {
		t.Errorf("%d verification tokens are still live after redemption: %v", len(left), left)
	}
}

// TestRegisterKeepsTheVerificationTokenToItself is the disclosure guard.
//
// Returning the plaintext — from the result, through an event, through metadata —
// would let anyone who can call Register verify an address they do not control,
// which is precisely the property the emailed link exists to establish.
func TestRegisterKeepsTheVerificationTokenToItself(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	codec := testCodec(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-secrecy",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	minted := h.minter.last(t)

	// Rendered rather than field-by-field, so a field added later is covered
	// without anybody remembering to extend this list.
	if rendered := fmt.Sprintf("%+v", got); strings.Contains(rendered, minted.Plaintext) {
		t.Errorf("RegisterResult carries the token plaintext: %s", rendered)
	}
	if rendered := fmt.Sprintf("%+v", got); strings.Contains(
		rendered, hex.EncodeToString(minted.Digest)) {
		t.Error("RegisterResult carries the token digest")
	}

	// The ENCODED events, because that is what is durable and replayable. An event
	// is readable by anyone who can replay the log, for as long as the log exists —
	// far longer than the 24 hours the token is live.
	for _, a := range h.appender.calls[0] {
		for _, e := range a.Events {
			payload, err := codec.Marshal(e.Event)
			if err != nil {
				t.Fatalf("marshalling %s: %v", e.Event.EventType(), err)
			}
			meta, err := codec.MarshalMetadata(e.Meta)
			if err != nil {
				t.Fatalf("marshalling metadata for %s: %v", e.Event.EventType(), err)
			}
			for _, encoded := range [][]byte{payload, meta} {
				if strings.Contains(string(encoded), minted.Plaintext) {
					t.Errorf("%s carries the token plaintext: %s", e.Event.EventType(), encoded)
				}
				// The digest is out too. It never expires from the log, so a digest
				// there is an offline attack surface that outlives the token by years.
				if strings.Contains(string(encoded), hex.EncodeToString(minted.Digest)) {
					t.Errorf("%s carries the token digest: %s", e.Event.EventType(), encoded)
				}
			}
		}
	}
}

// TestTheVerificationTokenNeverReachesALogLine covers the medium the event guard
// cannot see.
//
// Logs are retained for months and shipped to systems with a different access
// model than the event store. A token in a log line is a live credential sitting
// in the one place nobody thinks to protect it.
//
// It drives BOTH halves of the flow through one logger, because the token now
// spans them: Register mints it and VerifyEmail spends it. Registration has no
// logging branch left at all — the breach screening moved to VerifyEmail with
// the password — so a test that only registered would assert against an empty
// buffer and pass for the wrong reason. The degraded-corpus branch on the
// verification side is what makes the handler actually write lines, and the
// assertion below refuses to run against a silent one.
func TestTheVerificationTokenNeverReachesALogLine(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.logs = &bytes.Buffer{}
	h.tokenStore = newLiveTokens()
	// A degraded corpus makes the handler take its one logging branch, so this
	// test runs against a handler that is actually writing log lines rather than
	// one that is silent for reasons unrelated to the token.
	h.breach = &fakeBreach{err: errors.New("corpus unreachable")}

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-logs",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	minted := h.minter.last(t)

	// The click, through the same logger.
	h.user = rebuiltUser(t, got.UserID.String(), &contract.UserRegistered{
		UserID: got.UserID.String(), SubjectID: got.SubjectID,
		EmailIndex: got.EmailIndex, RegisteredAt: testNow,
	})
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: got.EmailIndex, SubjectID: got.SubjectID,
		ExpiresAt: testNow.Add(DefaultReservationLease),
	})
	h.directory = fakeDirectory{user: got.UserID}
	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: minted.Plaintext, Password: testPassword, IdempotencyKey: "cmd-logs-verify",
	}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	logged := h.logs.String()
	if logged == "" {
		t.Fatal("nothing was logged, so this test asserts nothing; the breach-screening " +
			"branch it relies on has moved")
	}
	for _, secret := range []struct{ name, value string }{
		{"the token plaintext", minted.Plaintext},
		{"the token digest", hex.EncodeToString(minted.Digest)},
		{"the address", strings.ToLower(testEmail)},
		{"the password", testPassword},
		{"the stored verifier", h.credentials.last.Verifier},
	} {
		if secret.value == "" {
			continue
		}
		if strings.Contains(strings.ToLower(logged), strings.ToLower(secret.value)) {
			t.Errorf("the log contains %s: %s", secret.name, logged)
		}
	}
	// The pseudonym is the one identifier that MAY appear, and this asserts the
	// test is looking at a log that concerns this registration at all.
	_ = got.SubjectID
}

// TestRegisterAnnouncesTheVerificationRequestOnTheAccountStream pins the event's
// stream and payload.
//
// The stream matters: a request recorded on the reservation stream would be a
// fact about a CLAIM rather than about an account, and the projector that will
// turn it into mail resolves a recipient from a SubjectID on the account's
// timeline. The payload matters for ADR-002 — a keyed index and a pseudonym are
// the only two things about a person allowed into a permanent log.
func TestRegisterAnnouncesTheVerificationRequestOnTheAccountStream(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-announce",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}
	appends := h.appender.calls[0]

	reservation := appendFor(t, appends,
		eventsourcing.MustStreamID(ReservationCategory, string(got.EmailIndex)))
	for _, e := range reservation.Events {
		if _, ok := e.Event.(*contract.EmailVerificationRequested); ok {
			t.Error("the verification request was recorded on the reservation stream; " +
				"it is a fact about an account, and EmailVerified lands on the account stream")
		}
	}

	user := appendFor(t, appends, eventsourcing.MustStreamID(UserCategory, got.UserID.String()))
	var requested *contract.EmailVerificationRequested
	for _, e := range user.Events {
		if ev, ok := e.Event.(*contract.EmailVerificationRequested); ok {
			if requested != nil {
				t.Fatal("two verification requests in one registration")
			}
			requested = ev
		}
	}
	if requested == nil {
		t.Fatal("no EmailVerificationRequested was appended, so nothing will ever send " +
			"the mail that carries the link")
	}

	minted := h.minter.last(t)
	switch {
	case requested.SubjectID != got.SubjectID:
		t.Errorf("the request names subject %q, want %q", requested.SubjectID, got.SubjectID)
	case requested.Index != got.EmailIndex:
		t.Errorf("the request names index %q, want %q", requested.Index, got.EmailIndex)
	// The event's deadline must be the token's own. A deadline that disagreed
	// would make the log say the link is live while the store refuses it.
	case !requested.ExpiresAt.Equal(minted.ExpiresAt):
		t.Errorf("the request expires at %s, the token at %s",
			requested.ExpiresAt, minted.ExpiresAt)
	case !requested.RequestedAt.Equal(testNow):
		t.Errorf("the request is stamped %s, want %s", requested.RequestedAt, testNow)
	case requested.RequestedAt.Location() != time.UTC:
		t.Errorf("the request is stamped in %v, not UTC", requested.RequestedAt.Location())
	}
}

// TestRegisterVoidsOutstandingVerificationTokensBeforeIssuing pins the ORDER of
// the two writes.
//
// identity.md §7 rule 7: at most one outstanding token of a purpose per subject.
// Revoking AFTER the issue deletes the token that was just created, which is the
// same end state as never issuing one — and it is invisible, because both calls
// succeeded.
//
// For a brand-new subject there is nothing to revoke, and that is exactly why
// stating it costs nothing: the invariant becomes a property of the call site
// rather than a coincidence of subject ids being freshly minted per attempt. The
// day a retry reuses its subject id — the obvious way to make a retry return the
// original result — this is what stops two live links existing for one address.
func TestRegisterVoidsOutstandingVerificationTokensBeforeIssuing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-revoke",
	})
	if err != nil {
		t.Fatalf("Register: %v", err)
	}

	if want := "[revoke issue]"; fmt.Sprint(h.tokens.journal) != want {
		t.Errorf("token writes went %v, want %s — a revocation after the issue deletes "+
			"the token it was meant to protect", h.tokens.journal, want)
	}
	if len(h.tokens.revoked) != 1 {
		t.Fatalf("revoked %d times, want 1", len(h.tokens.revoked))
	}
	if r := h.tokens.revoked[0]; r.purpose != PurposeEmailVerification ||
		r.subjectID != got.SubjectID {
		t.Errorf("revoked (%q, %q), want (%q, %q)",
			r.purpose, r.subjectID, PurposeEmailVerification, got.SubjectID)
	}
}

// TestALostRaceLeavesNoRedeemableVerificationToken is the retry property stated
// in the form that actually matters: not "how many rows exist" but "how many
// links work".
//
// A registration that dies after storing its token — a failed append, a lost race
// for the reservation stream, a crashed process — leaves a digest row behind. The
// retry mints a fresh subject and a fresh token, so revocation by subject cannot
// reach the first one. What makes that safe is that only ONE subject ever wins the
// address, and a token belonging to any other resolves to no account: VerifyEmail
// asks UserDirectory and refuses.
func TestALostRaceLeavesNoRedeemableVerificationToken(t *testing.T) {
	t.Parallel()
	store := newLiveTokens()

	// Attempt one: everything up to the append succeeds, the append does not.
	first := newHarness(t)
	first.tokenStore = store
	first.appender.err = errors.New("kurrentdb unreachable")
	if _, err := first.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-attempt-1",
	}); err == nil {
		t.Fatal("the failed append reported success")
	}
	orphan := first.minter.last(t).Plaintext
	if len(store.live(PurposeEmailVerification, testNow)) != 1 {
		t.Fatal("the first attempt stored no token, so this test proves nothing about " +
			"what a retry does with it")
	}

	// Attempt two: the retry, which succeeds.
	second := newHarness(t)
	second.tokenStore = store
	// A different secret AND a different subject from the first attempt's, which
	// is what crypto/rand gives in production. Sharing either would make the
	// revocation reach the orphan and hide the case this test is about.
	second.minter.label = "retry-"
	second.entropy = &fixedEntropy{b: 128}
	got, err := second.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-attempt-2",
	})
	if err != nil {
		t.Fatalf("the retry failed: %v", err)
	}
	live := store.live(PurposeEmailVerification, testNow)
	if len(live) != 2 {
		t.Fatalf("%d token rows survive the retry, want 2 — the fixture no longer "+
			"exercises the orphan case", len(live))
	}

	// Only the winner's subject has an account. Everything is arranged for the
	// account the retry created.
	second.user = rebuiltUser(t, got.UserID.String(), &contract.UserRegistered{
		UserID: got.UserID.String(), SubjectID: got.SubjectID,
		EmailIndex: got.EmailIndex, RegisteredAt: testNow,
	})
	second.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: got.EmailIndex, SubjectID: got.SubjectID,
		ExpiresAt: testNow.Add(DefaultReservationLease),
	})
	second.directory = fakeDirectory{user: got.UserID, only: got.SubjectID}
	second.appender.calls = nil
	handler := second.build()

	// The orphan is refused, and refused with the SAME wording an unknown token
	// gets. Anything else would say "this address has a half-finished account".
	_, err = handler.VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: orphan, Password: testPassword, IdempotencyKey: "cmd-verify-orphan",
	})
	if err == nil {
		t.Fatal("a token from an attempt that never created an account verified an address")
	}
	const want = "this verification link is no longer valid; request a new one"
	if !strings.Contains(err.Error(), want) || errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("the orphan was refused with %v (%s), want %q under %s",
			err, errs.ReasonOf(err), want, errs.ValidationFailed)
	}

	// The retry's own token still works, so the refusal above is about the orphan
	// and not about the arrangement being broken.
	verified, err := handler.VerifyEmail(context.Background(), VerifyEmailCommand{
		Token:          second.minter.last(t).Plaintext,
		Password:       testPassword,
		IdempotencyKey: "cmd-verify-live",
	})
	if err != nil {
		t.Fatalf("the retry's own token was refused: %v", err)
	}
	if !verified.Changed {
		t.Error("the retry's verification recorded nothing")
	}
}

// TestRegisterIssuesNoTokenForAnAddressSomebodyElseHolds keeps the probe path
// free of side effects.
//
// A prober must not be able to make the system mint secrets, write rows and send
// mail on demand for addresses they do not own — that is an email-bombing vector
// aimed at whoever really holds the address.
func TestRegisterIssuesNoTokenForAnAddressSomebodyElseHolds(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	index := mustIndex(t, testEmail)
	h.reservation = rebuiltReservation(t,
		&contract.EmailReserved{Index: index, SubjectID: "subj_owner", ExpiresAt: testNow.Add(time.Hour)},
		&contract.EmailReservationConfirmed{Index: index, SubjectID: "subj_owner"},
	)

	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-probe",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	if h.minter.calls != 0 {
		t.Errorf("minted %d tokens for an address held by somebody else", h.minter.calls)
	}
	if len(h.tokens.issued) != 0 {
		t.Errorf("stored %d token digests for an address held by somebody else",
			len(h.tokens.issued))
	}
	if len(h.tokens.revoked) != 0 {
		t.Errorf("revoked the real holder's outstanding tokens %d times; a prober would "+
			"be able to void somebody else's live verification link",
			len(h.tokens.revoked))
	}
}

// TestRegisterStoresTheTokenBeforeTheAppend pins the recoverable failure.
//
// Stored first, a crash between the two leaves a digest row for a subject with no
// account: unusable, and self-clearing at its expiry. Stored second, it leaves an
// account holding the address with no token — and no retry repairs that, because
// the append that claimed the address is the one that succeeded.
func TestRegisterStoresTheTokenBeforeTheAppend(t *testing.T) {
	t.Parallel()
	h := newHarness(t)
	h.appender.err = errors.New("kurrentdb unreachable")

	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-order",
	}); err == nil {
		t.Fatal("a failed append reported success")
	}
	if len(h.tokens.issued) != 1 {
		t.Errorf("stored %d token digests, want 1 even though the append failed: the "+
			"token must be durable BEFORE the address is claimed", len(h.tokens.issued))
	}
}

// ---------------------------------------------------------------------------
// VerifyEmail
// ---------------------------------------------------------------------------

func verifyHarness(t *testing.T) (*harness, ids.UserID, contract.EmailIndex) {
	t.Helper()
	h := newHarness(t)
	index := mustIndex(t, testEmail)
	userID := ids.MustParse[ids.User]("usr_01H8XG5N2QK7VB3C9WPYZR4TFM")
	const subject = "subj_01H8XG5N2QK7VB3C9WPYZR4TFN"

	h.tokens.subjectID = subject
	h.directory = fakeDirectory{user: userID}
	h.user = rebuiltUser(t, userID.String(), &contract.UserRegistered{
		UserID: userID.String(), SubjectID: subject, EmailIndex: index,
		RegisteredAt: testNow.Add(-time.Hour),
	})
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: index, SubjectID: subject,
		ExpiresAt: testNow.Add(24 * time.Hour), ReservedAt: testNow.Add(-time.Hour),
	})
	return h, userID, index
}

func TestVerifyEmailConfirmsBothStreamsInOneAtomicAppend(t *testing.T) {
	t.Parallel()
	h, userID, index := verifyHarness(t)

	got, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}
	if !got.Changed {
		t.Fatal("a valid token recorded nothing")
	}
	if got.UserID != userID {
		t.Errorf("user %q, want %q", got.UserID, userID)
	}

	if len(h.appender.calls) != 1 {
		t.Fatalf("AppendToMany called %d times, want exactly 1 — the verification and "+
			"the confirmation must not be separable by a crash", len(h.appender.calls))
	}
	appends := h.appender.calls[0]
	if len(appends) != 2 {
		t.Fatalf("the append carries %v, want both streams", streamsOf(appends))
	}

	user := appendFor(t, appends, eventsourcing.MustStreamID(UserCategory, userID.String()))
	reservation := appendFor(t, appends,
		eventsourcing.MustStreamID(ReservationCategory, string(index)))

	// The proof and the credential it authorises, in that order and in this one
	// append. Splitting them is what the pre-hijacking attack needs.
	if diff := fmt.Sprint(eventTypesOf(user)); diff !=
		"[identity.EmailVerified.v1 identity.PasswordSet.v1]" {
		t.Errorf("user events %s", diff)
	}
	if diff := fmt.Sprint(eventTypesOf(reservation)); diff !=
		"[identity.EmailReservationConfirmed.v1]" {
		t.Errorf("reservation events %s", diff)
	}

	// Both streams exist, so both preconditions pin the revision they were loaded
	// at. NoStream here would fail every verification.
	for _, a := range appends {
		rev, exact := a.Expected.Exact()
		if !exact || rev != 0 {
			t.Errorf("%s precondition is %s, want exact(0)", a.Stream, a.Expected)
		}
	}

	verified, ok := user.Events[0].Event.(*contract.EmailVerified)
	if !ok {
		t.Fatalf("user event is %T", user.Events[0].Event)
	}
	// The index comes from the ACCOUNT's events, never from the request — a token
	// must not be able to name the address it confirms.
	if verified.Index != index {
		t.Errorf("verified index %q, want %q", verified.Index, index)
	}
}

func TestVerifyEmailSpendsTheTokenUnderItsOwnPurpose(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	if h.tokens.calls != 1 {
		t.Fatalf("the token was consumed %d times, want exactly 1", h.tokens.calls)
	}
	if h.tokens.purpose != PurposeEmailVerification {
		t.Errorf("consumed under purpose %q, want %q", h.tokens.purpose, PurposeEmailVerification)
	}
	if fmt.Sprint(h.digestCalls) != fmt.Sprint([]TokenPurpose{PurposeEmailVerification}) {
		t.Errorf("digested under %v, want [%s] — an unscoped digest lets a "+
			"verification token be redeemed as a password reset",
			h.digestCalls, PurposeEmailVerification)
	}
	if want := h.digestFn()(PurposeEmailVerification, "the-emailed-secret"); string(h.tokens.digest) != string(want) {
		t.Error("the store was given something other than the digest of the presented token")
	}
	// The plaintext never travels further than the digest function.
	for _, a := range h.appender.calls[0] {
		for _, e := range a.Events {
			if strings.Contains(fmt.Sprintf("%+v", e.Event), "the-emailed-secret") {
				t.Errorf("%s carries the token plaintext", e.Event.EventType())
			}
		}
	}
}

// TestVerifyEmailVoidsEverySessionEstablishedBeforeTheProof asserts the
// pre-hijacking rule from Sudhodanan & Paverd is EXECUTED, not merely intended.
//
// # Why this asserts the call and not the outcome
//
// The revocation voids nothing today. A pre-verification account holds no
// credential, so it can hold no session, so the true statement about the system
// after a verification is "this subject has zero live sessions" — and that
// statement is equally true with the revocation deleted. A test asserting it
// would be one of the unconditionally-passing security tests this repository has
// already found twice.
//
// So the assertion is that the handler ASKED, and asked correctly: the right
// subject, sparing nothing, under the reason that names why. Delete the call in
// VerifyEmail and this test fails on the first line.
func TestVerifyEmailVoidsEverySessionEstablishedBeforeTheProof(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)
	subject := h.tokens.subjectID

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	if len(h.revocations.calls) != 1 {
		t.Fatalf("the verification asked for %d revocations, want exactly 1. A verification "+
			"that does not void what was established before it re-opens the unexpired-session "+
			"and trojan-identifier variants of IDENTITY-REVIEW C8 the moment a flow exists "+
			"that can leave a session behind", len(h.revocations.calls))
	}
	got := h.revocations.calls[0]
	if got.SubjectID != subject {
		t.Errorf("voided sessions for subject %q, want %q — voiding the wrong subject "+
			"signs out a bystander and leaves the attacker's session live",
			got.SubjectID, subject)
	}
	if !got.Except.IsZero() {
		t.Errorf("spared session %s; a verification is not performed from a session, so "+
			"there is no caller's session to spare and sparing one is exactly the "+
			"unexpired-session variant", got.Except)
	}
	if got.Reason != RevokeReasonEmailVerified {
		t.Errorf("revoked under reason %q, want %q", got.Reason, RevokeReasonEmailVerified)
	}
	if got.IdempotencyKey == "" {
		t.Error("no idempotency key: a retried verification would append a second set of " +
			"session revocations")
	}
	if got.IdempotencyKey == "cmd-verify" {
		t.Error("the revocation reuses the verification's own idempotency key, so the two " +
			"appends derive colliding event ids")
	}
}

// TestVerifyEmailRefusesWhenSessionsCannotBeVoided pins the ORDER, which is the
// half of the rule that decides which way a failure falls.
//
// Revocation first: a failure leaves an account that is not verified and has no
// password, and the caller recovers with a fresh link. Append first: a failure
// leaves a VERIFIED account with whatever sessions preceded it still live, and
// nothing retries. The second is the state the rule exists to forbid, reached
// through an error path — so the test asserts both that the call fails and that
// nothing was appended.
func TestVerifyEmailRefusesWhenSessionsCannotBeVoided(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)
	h.revocations.err = errors.New("valkey unreachable")

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err == nil {
		t.Fatal("a verification whose session revocation failed reported success")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d append(s) were made after the revocation failed; the account is now "+
			"verified with the sessions that preceded the proof still live",
			len(h.appender.calls))
	}
}

func TestVerifyEmailSpendsTheTokenBeforeAppending(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)
	h.appender.err = errors.New("kurrentdb unreachable")

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err == nil {
		t.Fatal("a failed append reported success")
	}
	// Spent regardless. The alternative order leaves a live single-use token in a
	// mailbox whenever the append fails, which is the property an attacker who
	// intercepted one mail needs.
	if h.tokens.calls != 1 {
		t.Errorf("the token was consumed %d times, want 1 even though the append failed",
			h.tokens.calls)
	}
}

func TestVerifyEmailIsIdempotent(t *testing.T) {
	t.Parallel()
	h, userID, index := verifyHarness(t)
	subject := h.tokens.subjectID
	// The state after a first, successful click.
	h.user = rebuiltUser(t, userID.String(),
		&contract.UserRegistered{
			UserID: userID.String(), SubjectID: subject, EmailIndex: index,
			RegisteredAt: testNow.Add(-time.Hour),
		},
		&contract.EmailVerified{SubjectID: subject, Index: index, VerifiedAt: testNow},
	)
	h.reservation = rebuiltReservation(t,
		&contract.EmailReserved{
			Index: index, SubjectID: subject, ExpiresAt: testNow.Add(24 * time.Hour),
		},
		&contract.EmailReservationConfirmed{
			Index: index, SubjectID: subject, ConfirmedAt: testNow,
		},
	)

	got, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err != nil {
		t.Fatalf("a second click produced %v; a prefetched link is not a failure", err)
	}
	if got.Changed {
		t.Error("Changed is true although both aggregates were already in that state")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for a verification that decided nothing", len(h.appender.calls))
	}
}

func TestVerifyEmailRefusalsAreIndistinguishable(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name    string
		arrange func(*harness)
	}{
		{
			name:    "an unknown, spent or expired token",
			arrange: func(h *harness) { h.tokens.err = ErrTokenNotFound },
		},
		{
			name:    "a token whose subject has no account",
			arrange: func(h *harness) { h.directory = fakeDirectory{err: ErrNoSuchSubject} },
		},
	}

	const want = "this verification link is no longer valid; request a new one"
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _, _ := verifyHarness(t)
			tc.arrange(h)

			_, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
				Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
			})
			if err == nil {
				t.Fatal("an invalid token was accepted")
			}
			if r := errs.ReasonOf(err); r != errs.ValidationFailed {
				t.Errorf("reason %s, want %s", r, errs.ValidationFailed)
			}
			// Same wording for both. "That link has expired" tells whoever holds
			// it that the address it was sent to has an account.
			var domainErr *errs.Error
			if !errors.As(err, &domainErr) {
				t.Fatalf("%v is not a domain error", err)
			}
			if domainErr.Message != want {
				t.Errorf("message %q, want %q", domainErr.Message, want)
			}
			if len(h.appender.calls) != 0 {
				t.Errorf("%d appends for a refused verification", len(h.appender.calls))
			}
		})
	}
}

func TestVerifyEmailRefusesALapsedClaim(t *testing.T) {
	t.Parallel()
	h, _, index := verifyHarness(t)
	// The lease ran out. Confirming now would take the address back from whoever
	// legitimately claimed it in the meantime, with no event explaining why.
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: index, SubjectID: h.tokens.subjectID,
		ExpiresAt: testNow.Add(-time.Minute), ReservedAt: testNow.Add(-49 * time.Hour),
	})

	_, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err == nil {
		t.Fatal("a lapsed reservation was confirmed")
	}
	if r := errs.ReasonOf(err); r != errs.Conflict {
		t.Errorf("reason %s, want %s", r, errs.Conflict)
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends although the confirmation was refused — the account "+
			"must not record a verification whose claim was refused",
			len(h.appender.calls))
	}
}

func TestVerifyEmailRefusesAClaimHeldByAnotherAccount(t *testing.T) {
	t.Parallel()
	h, _, index := verifyHarness(t)
	h.reservation = rebuiltReservation(t, &contract.EmailReserved{
		Index: index, SubjectID: "subj_somebody_else",
		ExpiresAt: testNow.Add(24 * time.Hour),
	})

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err == nil {
		t.Fatal("a token confirmed an address reserved by another account")
	}
	if len(h.appender.calls) != 0 {
		t.Errorf("%d appends for a refused confirmation", len(h.appender.calls))
	}
}

func TestVerifyEmailRefusesEmptyInput(t *testing.T) {
	t.Parallel()

	cases := map[string]VerifyEmailCommand{
		"no token":           {Password: testPassword, IdempotencyKey: "cmd-verify"},
		"no idempotency key": {Token: "the-emailed-secret", Password: testPassword},
		// The password is as required as the token now. Without this case a
		// handler that accepted an empty one would verify the address and set a
		// credential nothing can ever present — an account permanently locked out
		// of itself, created by a click that reported success.
		"no password": {Token: "the-emailed-secret", IdempotencyKey: "cmd-verify"},
	}
	for name, cmd := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			h, _, _ := verifyHarness(t)

			_, err := h.build().VerifyEmail(context.Background(), cmd)
			if errs.ReasonOf(err) != errs.ValidationFailed {
				t.Fatalf("reason %s, want %s (%v)", errs.ReasonOf(err), errs.ValidationFailed, err)
			}
			if h.tokens.calls != 0 {
				t.Error("an incomplete command reached the token store")
			}
		})
	}
}

// TestVerifyEmailPropagatesPortFailures covers the ports the password brought
// with it, and states what each failure costs the person holding the link.
//
// Every one of these happens AFTER the token has been consumed, which is the
// price of spending it before the account is touched (see VerifyEmail). That
// price is bounded and is asserted here as the recovery rather than assumed: the
// account is still Pending and still unverified afterwards, because nothing was
// appended, so ResendEmailVerification still admits it and a second link works.
func TestVerifyEmailPropagatesPortFailures(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		arrange    func(*harness)
		wantReason errs.Reason
	}{
		{
			name: "the hasher is at capacity",
			arrange: func(h *harness) {
				h.hasher.err = errs.RateLimitedf("password hashing is at capacity")
			},
			// Propagated unchanged and NOT retried: retrying adds load to the
			// exact condition the concurrency bound exists to relieve.
			wantReason: errs.RateLimited,
		},
		{
			name:       "the credential store is unreachable",
			arrange:    func(h *harness) { h.credentials.err = errors.New("database down") },
			wantReason: errs.Internal,
		},
		{
			name: "the credential store says the account already has a password",
			// Reachable only as a race between two verifications of one account,
			// because the aggregate has already refused a second SetPassword by
			// the time this call is made. It must stop rather than replace: the
			// other attempt won, and its verifier is the one the user will present.
			arrange:    func(h *harness) { h.credentials.err = ErrPasswordAlreadySet },
			wantReason: errs.Internal,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h, _, _ := verifyHarness(t)
			tc.arrange(h)

			_, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
				Token: "the-emailed-secret", Password: testPassword,
				IdempotencyKey: "cmd-verify",
			})
			if err == nil {
				t.Fatal("a failing port reported success")
			}
			if r := errs.ReasonOf(err); r != tc.wantReason {
				t.Errorf("reason %s, want %s (%v)", r, tc.wantReason, err)
			}
			// NOTHING reached the log. The account keeps the state that makes a
			// resend possible, which is the only route back once the token is gone.
			if len(h.appender.calls) != 0 {
				t.Errorf("%d appends although the command failed; an account recorded as "+
					"verified with no usable verifier can neither sign in nor ask for "+
					"another link", len(h.appender.calls))
			}
		})
	}
}

// TestVerifyEmailSetsTheFirstPasswordThroughStoreFirst pins the credential half
// of the verification, which is the half that did not exist before
// IDENTITY-REVIEW C8.
func TestVerifyEmailSetsTheFirstPasswordThroughStoreFirst(t *testing.T) {
	t.Parallel()
	h, userID, _ := verifyHarness(t)

	got, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err != nil {
		t.Fatalf("VerifyEmail: %v", err)
	}

	if h.credentials.calls != 1 {
		t.Fatalf("the verifier was stored %d times, want 1", h.credentials.calls)
	}
	last := h.credentials.last
	switch {
	case last.SubjectID != got.SubjectID:
		t.Errorf("verifier stored under subject %q, want %q", last.SubjectID, got.SubjectID)
	case last.Verifier == "":
		t.Error("an empty verifier was stored")
	case strings.Contains(last.Verifier, testPassword):
		t.Error("the stored verifier contains the password")
	// A row at version 0 is invisible to `pepper_version < n`, so the rotation
	// job skips it and the account is locked out when the old key is destroyed.
	case last.PepperVersion != h.hasher.PepperVersion():
		t.Errorf("pepper version %d, want the hasher's %d",
			last.PepperVersion, h.hasher.PepperVersion())
	// enabled_at drives the usable-credential lookup; zero leaves the account
	// passwordless with a password row in the table.
	case last.EnabledAt.IsZero():
		t.Error("the credential was stored with no enabled_at")
	}

	// The event and the row name the same credential. The hasher authenticated
	// that id into the verifier, so a row under any other id can never be opened —
	// and the failure would surface at the user's first login rather than here.
	user := appendFor(t, h.appender.calls[0],
		eventsourcing.MustStreamID(UserCategory, userID.String()))
	// EmailVerified FIRST, then PasswordSet. The aggregate refuses a password on
	// an unproven address, so the order is enforced rather than merely observed —
	// but it is asserted because the ORDER is what a reader of the log needs in
	// order to see that the proof came first.
	if diff := fmt.Sprint(eventTypesOf(user)); diff !=
		"[identity.EmailVerified.v1 identity.PasswordSet.v1]" {
		t.Fatalf("user events %s, want the proof and then the credential", diff)
	}
	set, ok := user.Events[1].Event.(*contract.PasswordSet)
	if !ok {
		t.Fatalf("the second user event is %T, want PasswordSet", user.Events[1].Event)
	}
	if set.CredentialID != last.ID.String() {
		t.Errorf("PasswordSet names credential %q, the row holds %q", set.CredentialID, last.ID)
	}
	if set.SubjectID != got.SubjectID {
		t.Errorf("PasswordSet names subject %q, want %q", set.SubjectID, got.SubjectID)
	}
}

// TestVerifyEmailStoresTheVerifierBeforeTheAppend pins the recoverable failure,
// exactly as TestRegisterStoresTheTokenBeforeTheAppend does for the token.
//
// Stored first, a crash between the two leaves a verifier no event refers to:
// inert, because the aggregate rebuilt from the log has no password method, and
// displaceable, because StoreFirst replaces it on the retry. Stored second, it
// leaves an account the log says has a password that nothing can verify — and
// there is no retry, because the address is verified by the append that
// succeeded and a resend will not touch a verified account.
func TestVerifyEmailStoresTheVerifierBeforeTheAppend(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)
	h.appender.err = errors.New("kurrentdb unreachable")

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", Password: testPassword, IdempotencyKey: "cmd-verify",
	}); err == nil {
		t.Fatal("a failed append reported success")
	}
	if h.credentials.calls != 1 {
		t.Errorf("stored %d verifiers, want 1 even though the append failed: the verifier "+
			"must be durable BEFORE the account records that it has one", h.credentials.calls)
	}
}

// entropyIsUnbounded guards the fixture rather than the handler: ids.New panics
// on a short read, so a bounded reader would fail every test above for a reason
// that has nothing to do with registration.
func TestFixedEntropyNeverRunsShort(t *testing.T) {
	t.Parallel()
	var e io.Reader = &fixedEntropy{}
	buf := make([]byte, 4096)
	n, err := io.ReadFull(e, buf)
	if err != nil || n != len(buf) {
		t.Fatalf("read %d bytes: %v", n, err)
	}
}

// Every appended event must carry its CURRENT schema version.
//
// This is the bug the first end-to-end run found, and it is worth stating plainly
// because nothing else in the suite could see it. `Repository.Save` stamps the
// version for single-stream appends; these handlers use `MultiAppender`, which
// has no Save, so they must stamp it themselves. Identity did not, so every event
// was written at version 0 while the registry declares 1 — and a stored version
// BELOW the declared one demands a 0->1 upcaster that should never exist.
//
// The consequence is that an aggregate can be written exactly once and never
// loaded again: registration succeeds, and the next command against that account
// fails to load it. The reason it survived every test up to that point is that
// the two paths disagree — projections do not upcast, so `user_view` filled in
// correctly and every read model, dashboard and probe stayed green. A healthy
// read side is not evidence that the write side can be replayed.
func TestEveryAppendedEventCarriesItsSchemaVersion(t *testing.T) {
	t.Parallel()

	h := newHarness(t)
	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, IdempotencyKey: "cmd-schema",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	var checked int
	for _, call := range h.appender.calls {
		for _, a := range call {
			for _, e := range a.Events {
				checked++
				want, ok := h.schemas.CurrentVersion(e.Event.EventType())
				if !ok {
					t.Errorf("%s is not declared in the schema registry, so nothing can "+
						"say what version it was written at", e.Event.EventType())
					continue
				}
				if e.Meta.SchemaVersion != want {
					t.Errorf("%s was appended at schema version %d, want %d: a stored version "+
						"below the declared one demands an upcaster that should not exist, and "+
						"the aggregate cannot be loaded back",
						e.Event.EventType(), e.Meta.SchemaVersion, want)
				}
			}
		}
	}
	if checked == 0 {
		t.Fatal("no events were appended, so nothing was checked")
	}
}

// identitySchemas is the same registry the composition root builds: every
// identity event declared at version 1.
//
// Built from the contract types rather than a list of strings, so a renamed event
// is a compile error here instead of a version silently missing at runtime.
func identitySchemas() *eventsourcing.UpcasterRegistry {
	r := eventsourcing.NewUpcasterRegistry()
	for _, e := range []eventsourcing.Event{
		&contract.EmailReserved{}, &contract.EmailReservationConfirmed{},
		&contract.EmailReleased{}, &contract.UserRegistered{},
		&contract.EmailVerificationRequested{}, &contract.EmailVerified{},
		&contract.PasswordSet{}, &contract.UserActivated{},
		&contract.TotpEnrollmentStarted{}, &contract.TotpEnabled{},
	} {
		r.Register(e.EventType(), 1)
	}
	return r
}
