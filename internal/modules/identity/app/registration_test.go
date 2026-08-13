package app

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
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

func (f *fakeCredentials) Store(_ context.Context, cred NewPasswordCredential) error {
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

type fakeTokens struct {
	subjectID string
	err       error
	calls     int
	purpose   TokenPurpose
	digest    []byte
}

func (f *fakeTokens) Issue(context.Context, TokenPurpose, string, []byte, time.Time) error {
	return errors.New("not used by these handlers")
}

func (f *fakeTokens) Consume(
	_ context.Context, purpose TokenPurpose, digest []byte, _ time.Time,
) (string, error) {
	f.calls++
	f.purpose = purpose
	f.digest = digest
	return f.subjectID, f.err
}

func (f *fakeTokens) RevokeAll(context.Context, TokenPurpose, string) error { return nil }

type fakeDirectory struct {
	user ids.UserID
	err  error
}

func (f fakeDirectory) UserBySubject(context.Context, string) (ids.UserID, error) {
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
	tokens      *fakeTokens
	directory   fakeDirectory

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
		tokens:      &fakeTokens{subjectID: "subj_unset"},
		reservation: eventsourcing.NewAggregate(domain.NewReservation),
		user:        eventsourcing.NewAggregate(domain.New),
	}
}

func (h *harness) build() *Registration {
	h.t.Helper()
	r, err := NewRegistration(RegistrationDeps{
		Clock:       clock.NewFixed(testNow),
		Entropy:     &fixedEntropy{},
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
		Appender:  h.appender,
		Tokens:    h.tokens,
		Digest:    h.digestFn(),
		Directory: h.directory,
	})
	if err != nil {
		h.t.Fatalf("wiring the handler: %v", err)
	}
	return r
}

func (h *harness) digestFn() TokenDigest {
	return func(purpose TokenPurpose, plaintext string) []byte {
		h.digestCalls = append(h.digestCalls, purpose)
		sum := sha256.Sum256([]byte(string(purpose) + "|" + plaintext))
		return sum[:]
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
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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
	if diff := fmt.Sprint(eventTypesOf(user)); diff !=
		"[identity.UserRegistered.v1 identity.PasswordSet.v1]" {
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

func TestRegisterStoresTheAddressAndTheVerifierOffTheLog(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	got, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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

	if h.credentials.calls != 1 {
		t.Fatalf("the verifier was stored %d times, want 1", h.credentials.calls)
	}
	last := h.credentials.last
	switch {
	case last.SubjectID != got.SubjectID:
		t.Errorf("verifier stored under subject %q, want %q", last.SubjectID, got.SubjectID)
	// The credential id MUST be the one PasswordSet carries. The hasher
	// authenticated it into the verifier, so a row under any other id can never be
	// opened — and the failure surfaces at the user's first login, not here.
	case last.ID != got.CredentialID:
		t.Errorf("verifier stored under credential %q, want %q", last.ID, got.CredentialID)
	case last.Verifier == "":
		t.Error("an empty verifier was stored")
	case strings.Contains(last.Verifier, testPassword):
		t.Error("the stored verifier contains the password")
	// A row at version 0 is invisible to `pepper_version < n`, so the rotation
	// job skips it and the account is locked out when the old key is destroyed.
	case last.PepperVersion != h.hasher.PepperVersion():
		t.Errorf("pepper version %d, want the hasher's %d",
			last.PepperVersion, h.hasher.PepperVersion())
	case last.PepperVersion < 1:
		t.Errorf("pepper version %d is below the floor of 1", last.PepperVersion)
	// enabled_at drives the usable-credential lookup; zero leaves the account
	// passwordless with a password row in the table.
	case last.EnabledAt.IsZero():
		t.Error("the credential was stored with no enabled_at")
	}

	// The event and the row name the same credential.
	userAppend := appendFor(t, h.appender.calls[0],
		eventsourcing.MustStreamID(UserCategory, got.UserID.String()))
	set, ok := userAppend.Events[1].Event.(*contract.PasswordSet)
	if !ok {
		t.Fatalf("the second user event is %T, want PasswordSet", userAppend.Events[1].Event)
	}
	if set.CredentialID != last.ID.String() {
		t.Errorf("PasswordSet names credential %q, the row holds %q",
			set.CredentialID, last.ID)
	}
	if set.SubjectID != got.SubjectID {
		t.Errorf("PasswordSet names subject %q, want %q", set.SubjectID, got.SubjectID)
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
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
	}

	forbidden := []string{
		testEmail, strings.ToLower(testEmail), "alice", "example.com",
		testPassword, h.credentials.last.Verifier,
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
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-meta",
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
			Email: testEmail, Password: testPassword, IdempotencyKey: key,
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
			Email: testEmail, Password: testPassword, IdempotencyKey: key,
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
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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
		name       string
		arrange    func(*harness)
		wantHashed bool
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
			wantHashed: true,
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
			wantHashed: true,
		},
		{
			name: "losing the race for the stream at append time",
			arrange: func(h *harness) {
				h.appender.err = fmt.Errorf("appending: %w",
					eventsourcing.ErrWrongExpectedRevision)
			},
			wantHashed: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			tc.arrange(h)

			got, err := h.build().Register(context.Background(), RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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
			// The hash is the expensive step and it must be paid on BOTH paths,
			// or the two answers are separable by a stopwatch however carefully
			// the wire response is worded.
			if tc.wantHashed && h.hasher.calls != 1 {
				t.Errorf("the password was hashed %d times on the refused path, want 1: "+
					"skipping it makes the refusal measurably faster", h.hasher.calls)
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
		Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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

func TestRegisterScreensThePasswordBeforeHashingIt(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		breach      *fakeBreach
		wantErr     bool
		wantReason  errs.Reason
		wantHashes  int
		wantAppends int
	}{
		{
			name:       "a breached password is refused before the hash is paid for",
			breach:     &fakeBreach{breached: true, corpus: "hibp"},
			wantErr:    true,
			wantReason: errs.ValidationFailed,
		},
		{
			name:        "an unreachable corpus fails open",
			breach:      &fakeBreach{err: errors.New("corpus unreachable")},
			wantHashes:  1,
			wantAppends: 1,
		},
		{
			name:        "a clean password proceeds",
			breach:      &fakeBreach{},
			wantHashes:  1,
			wantAppends: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			h := newHarness(t)
			h.breach = tc.breach

			_, err := h.build().Register(context.Background(), RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
			})
			switch {
			case tc.wantErr && err == nil:
				t.Fatal("a breached password was accepted")
			case tc.wantErr && errs.ReasonOf(err) != tc.wantReason:
				t.Fatalf("reason %s, want %s", errs.ReasonOf(err), tc.wantReason)
			case !tc.wantErr && err != nil:
				t.Fatalf("Register: %v", err)
			}
			if tc.breach.calls != 1 {
				t.Errorf("the corpus was consulted %d times, want 1", tc.breach.calls)
			}
			if h.hasher.calls != tc.wantHashes {
				t.Errorf("hashed %d times, want %d — screening must happen BEFORE the "+
					"51ms hash, or a rejected password still costs one",
					h.hasher.calls, tc.wantHashes)
			}
			if len(h.appender.calls) != tc.wantAppends {
				t.Errorf("%d appends, want %d", len(h.appender.calls), tc.wantAppends)
			}
		})
	}
}

func TestRegisterNormalizesThePasswordBeforeHashing(t *testing.T) {
	t.Parallel()
	h := newHarness(t)

	// U+00A0 NO-BREAK SPACE and a decomposed "é". Both must reach the hasher as
	// the RFC 8265 OpaqueString form, or the same password typed on another
	// keyboard or operating system will not verify.
	raw := "cafe\u0301\u00a0brulee\u00a0forever"
	want := "caf\u00e9 brulee forever"

	if _, err := h.build().Register(context.Background(), RegisterCommand{
		Email: testEmail, Password: raw, IdempotencyKey: "cmd-1",
	}); err != nil {
		t.Fatalf("Register: %v", err)
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
			cmd:        RegisterCommand{Email: testEmail, Password: testPassword},
			wantReason: errs.ValidationFailed,
		},
		{
			name: "an address with no domain",
			cmd: RegisterCommand{
				Email: "alice", Password: testPassword, IdempotencyKey: "cmd-1",
			},
			wantReason: errs.ValidationFailed,
		},
		{
			name: "a password under the floor",
			cmd: RegisterCommand{
				Email: testEmail, Password: "short", IdempotencyKey: "cmd-1",
			},
			wantReason: errs.ValidationFailed,
		},
		{
			name: "the hasher is at capacity",
			cmd: RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
			},
			arrange: func(h *harness) {
				h.hasher.err = errs.RateLimitedf("password hashing is at capacity")
			},
			// Propagated unchanged and NOT retried: retrying adds load to the
			// exact condition the concurrency bound exists to relieve.
			wantReason: errs.RateLimited,
		},
		{
			name: "the vault is unreachable",
			cmd: RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.vault.err = errors.New("vault down") },
			wantReason: errs.Internal,
		},
		{
			name: "the credential store is unreachable",
			cmd: RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
			},
			arrange:    func(h *harness) { h.credentials.err = errors.New("database down") },
			wantReason: errs.Internal,
		},
		{
			name: "the append fails for a reason that is not contention",
			cmd: RegisterCommand{
				Email: testEmail, Password: testPassword, IdempotencyKey: "cmd-1",
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
			Digest: h.digestFn(), Directory: h.directory,
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
		"digest":       func(d *RegistrationDeps) { d.Digest = nil },
		"directory":    func(d *RegistrationDeps) { d.Directory = nil },
		"lease":        func(d *RegistrationDeps) { d.Lease = -time.Second },
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
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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

	if diff := fmt.Sprint(eventTypesOf(user)); diff != "[identity.EmailVerified.v1]" {
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
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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

func TestVerifyEmailSpendsTheTokenBeforeAppending(t *testing.T) {
	t.Parallel()
	h, _, _ := verifyHarness(t)
	h.appender.err = errors.New("kurrentdb unreachable")

	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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
				Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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
		Token: "the-emailed-secret", IdempotencyKey: "cmd-verify",
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
		"no token":           {IdempotencyKey: "cmd-verify"},
		"no idempotency key": {Token: "the-emailed-secret"},
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
