package app

import (
	"bytes"
	"context"
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
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// fakeSealer models the real binding rather than pretending to seal.
//
// Open REFUSES a value whose embedded subject and credential do not match the
// ones it is asked for, which is what makes "a secret sealed for one credential
// cannot be opened under another" a property this layer can be tested for. A fake
// that echoed its input back would pass every test here while the handler passed
// the wrong ids to a real sealer.
type fakeSealer struct {
	version  int32
	sealErr  error
	openErr  error
	sealings int
}

var _ TotpSealer = (*fakeSealer)(nil)

func (f *fakeSealer) Seal(secret, subjectID string, cred ids.CredentialID) (string, error) {
	f.sealings++
	if f.sealErr != nil {
		return "", f.sealErr
	}
	return "sealed:" + subjectID + ":" + cred.String() + ":" + secret, nil
}

func (f *fakeSealer) Open(sealed, subjectID string, cred ids.CredentialID) (string, error) {
	if f.openErr != nil {
		return "", f.openErr
	}
	prefix := "sealed:" + subjectID + ":" + cred.String() + ":"
	if !strings.HasPrefix(sealed, prefix) {
		return "", ErrSecretUnreadable
	}
	return strings.TrimPrefix(sealed, prefix), nil
}

func (f *fakeSealer) KeyVersion() int32 {
	if f.version == 0 {
		// A real version. Zero is refused at wiring time, so a fake defaulting to
		// it would fail every test for a reason none of them is about.
		return 4
	}
	return f.version
}

type fakeSecrets struct {
	rows        map[string]TotpSecret
	provisioned []NewTotpSecret
	enabled     []ids.CredentialID

	findErr      error
	provisionErr error
	enableErr    error
}

var _ TotpSecrets = (*fakeSecrets)(nil)

func newFakeSecrets() *fakeSecrets { return &fakeSecrets{rows: map[string]TotpSecret{}} }

func (f *fakeSecrets) Provision(_ context.Context, secret NewTotpSecret) error {
	if f.provisionErr != nil {
		return f.provisionErr
	}
	f.provisioned = append(f.provisioned, secret)
	// The real upsert also CLEARS enabled_at, so a restarted enrolment replaces an
	// abandoned secret rather than leaving a second confirmable one behind.
	f.rows[secret.SubjectID] = TotpSecret{
		ID: secret.ID, SubjectID: secret.SubjectID,
		Sealed: secret.Sealed, KeyVersion: secret.KeyVersion, Enabled: false,
	}
	return nil
}

func (f *fakeSecrets) Find(_ context.Context, subjectID string) (TotpSecret, error) {
	if f.findErr != nil {
		return TotpSecret{}, f.findErr
	}
	row, ok := f.rows[subjectID]
	if !ok {
		return TotpSecret{}, ErrNoTotpCredential
	}
	return row, nil
}

func (f *fakeSecrets) Enable(_ context.Context, cred ids.CredentialID) error {
	if f.enableErr != nil {
		return f.enableErr
	}
	f.enabled = append(f.enabled, cred)
	for subject, row := range f.rows {
		if row.ID == cred {
			row.Enabled = true
			f.rows[subject] = row
			return nil
		}
	}
	return ErrCredentialNotFound
}

// fakeVerifier models the real authenticator, replay guard included.
//
// A code that matches is accepted ONCE per credential; presenting it again
// returns ErrCodeReplayed, exactly as the Postgres-backed guard does. Without
// that, "a replayed code is refused" could not be tested above the adapter, and
// the handler branch that distinguishes it would never run.
type fakeVerifier struct {
	secret string
	code   string
	err    error

	spent      map[string]bool
	calls      int
	sawSecret  string
	sawCode    string
	sawCredIDs []ids.CredentialID
}

var _ TotpVerifier = (*fakeVerifier)(nil)

func newFakeVerifier(secret, code string) *fakeVerifier {
	return &fakeVerifier{secret: secret, code: code, spent: map[string]bool{}}
}

func (f *fakeVerifier) Verify(
	_ context.Context, secret, code string, cred ids.CredentialID, _ time.Time,
) (bool, error) {
	f.calls++
	f.sawSecret, f.sawCode = secret, code
	f.sawCredIDs = append(f.sawCredIDs, cred)
	if f.err != nil {
		return false, f.err
	}
	if secret != f.secret || code != f.code {
		return false, nil
	}
	key := cred.String() + ":" + code
	if f.spent[key] {
		return false, ErrCodeReplayed
	}
	f.spent[key] = true
	return true, nil
}

// fakeRecovery models the single-statement burn.
//
// Consume marks the digest spent under the same lookup that reads it, so two
// redemptions of one code cannot both succeed — the property the SQL carries in
// production, reproduced here so the handler can be held to it.
type fakeRecovery struct {
	creds   map[string]ids.CredentialID
	digests map[string]map[string]bool

	replaced     []NewRecoveryCodeSet
	consumeCalls int

	credErr    error
	replaceErr error
	consumeErr error

	// consumeCredential overrides which credential a burn reports, so the
	// cross-check against the account's own log can be driven.
	consumeCredential *ids.CredentialID
}

var _ RecoveryCodes = (*fakeRecovery)(nil)

func newFakeRecovery() *fakeRecovery {
	return &fakeRecovery{
		creds:   map[string]ids.CredentialID{},
		digests: map[string]map[string]bool{},
	}
}

func (f *fakeRecovery) Credential(_ context.Context, subjectID string) (ids.CredentialID, error) {
	if f.credErr != nil {
		return ids.CredentialID{}, f.credErr
	}
	cred, ok := f.creds[subjectID]
	if !ok {
		return ids.CredentialID{}, ErrNoRecoveryCode
	}
	return cred, nil
}

func (f *fakeRecovery) Replace(_ context.Context, set NewRecoveryCodeSet) error {
	if f.replaceErr != nil {
		return f.replaceErr
	}
	f.replaced = append(f.replaced, set)
	f.creds[set.SubjectID] = set.CredentialID
	// Whole-set replacement: the previous map is DROPPED, never merged.
	held := make(map[string]bool, len(set.Digests))
	for _, digest := range set.Digests {
		held[hex.EncodeToString(digest)] = false
	}
	f.digests[set.SubjectID] = held
	return nil
}

func (f *fakeRecovery) Consume(
	_ context.Context, subjectID string, digest []byte,
) (ids.CredentialID, error) {
	f.consumeCalls++
	if f.consumeErr != nil {
		return ids.CredentialID{}, f.consumeErr
	}
	held := f.digests[subjectID]
	key := hex.EncodeToString(digest)
	consumed, ok := held[key]
	if !ok || consumed {
		return ids.CredentialID{}, ErrNoRecoveryCode
	}
	held[key] = true
	if f.consumeCredential != nil {
		return *f.consumeCredential, nil
	}
	return f.creds[subjectID], nil
}

// shortReader yields fewer bytes than asked for and then stops. It exists to
// drive the branch that must REFUSE rather than mint a code with a predictable
// tail.
type shortReader struct{ left int }

func (r *shortReader) Read(p []byte) (int, error) {
	if r.left <= 0 {
		return 0, io.ErrUnexpectedEOF
	}
	n := min(r.left, len(p))
	for i := range n {
		p[i] = 0x41
	}
	r.left -= n
	return n, nil
}

// ---------------------------------------------------------------------------
// Harness
// ---------------------------------------------------------------------------

const (
	// sfSharedValue is a base32 TOTP shared value used as a fixture, not a
	// credential for any account.
	sfSharedValue = "JBSWY3DPEHPK3PXPJBSWY3DP"
	sfCode        = "123456"
	sfAccount     = "alice@example.com"
	sfSubject     = "subj_01JQ0000000000000000000001"
	sfIdempotent  = "idem-second-factor"
)

// sfOtherCredential is a credential id no fixture mints.
//
// Written out rather than generated: fixedEntropy is deterministic and the clock
// is fixed, so a second ids.New at the same instant produces the SAME id as the
// handler's — and a test comparing them would pass for the wrong reason.
var sfOtherCredential = ids.MustParse[ids.Credential]("cred_01ARZ3NDEKTSV4RRFFQ69G5FAV")

type sfHarness struct {
	t *testing.T

	user   *domain.User
	userID ids.UserID

	secrets  *fakeSecrets
	sealer   *fakeSealer
	verifier *fakeVerifier
	recovery *fakeRecovery
	appender *fakeAppender

	enrollment  TotpEnrollment
	enrollErr   error
	enrollNames []string

	loadErr     error
	codeEntropy io.Reader
}

func newSFHarness(t *testing.T) *sfHarness {
	t.Helper()
	h := &sfHarness{
		t:          t,
		secrets:    newFakeSecrets(),
		sealer:     &fakeSealer{},
		verifier:   newFakeVerifier(sfSharedValue, sfCode),
		recovery:   newFakeRecovery(),
		appender:   &fakeAppender{},
		enrollment: TotpEnrollment{Secret: sfSharedValue, URI: "otpauth://totp/Chronos:alice@example.com?secret=" + sfSharedValue},
	}
	h.user, h.userID = sfPendingUser(t)
	return h
}

func (h *sfHarness) build() *SecondFactor {
	h.t.Helper()
	sf, err := NewSecondFactor(SecondFactorDeps{
		Clock:   clock.NewFixed(testNow),
		Entropy: &fixedEntropy{},
		Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
			return h.user, h.loadErr
		}),
		Appender: h.appender,
		Enroll: func(accountName string) (TotpEnrollment, error) {
			h.enrollNames = append(h.enrollNames, accountName)
			return h.enrollment, h.enrollErr
		},
		Sealer:   h.sealer,
		Secrets:  h.secrets,
		Verifier: h.verifier,
		Recovery: h.recovery,
		// Discarded rather than default: these handlers log refusals by design, and
		// a passing test should not print them.
		Log: slog.New(slog.DiscardHandler),
	})
	if err != nil {
		h.t.Fatalf("wiring the handler: %v", err)
	}
	if h.codeEntropy != nil {
		sf.codeEntropy = h.codeEntropy
	}
	return sf
}

// appended returns every event the handler asked to append, flattened.
func (h *sfHarness) appended() []eventsourcing.PendingEvent {
	h.t.Helper()
	var out []eventsourcing.PendingEvent
	for _, call := range h.appender.calls {
		for _, entry := range call {
			out = append(out, entry.Events...)
		}
	}
	return out
}

// sfPendingUser builds an account with a password and a verified address, and
// therefore NO second factor: exactly the state enrolment exists to leave.
func sfPendingUser(t *testing.T) (*domain.User, ids.UserID) {
	t.Helper()
	entropy := &fixedEntropy{}
	userID := ids.New[ids.User](testNow, entropy)
	user := eventsourcing.NewAggregate(domain.New)
	index := mustIndex(t, testEmail)
	if err := user.Register(userID, sfSubject, index, testNow); err != nil {
		t.Fatalf("registering: %v", err)
	}
	// Verified BEFORE the password: domain.User.SetPassword refuses one on an
	// unproven address, which is also the order the real flow produces.
	if err := user.VerifyEmail(index, testNow); err != nil {
		t.Fatalf("verifying: %v", err)
	}
	if err := user.SetPassword(ids.New[ids.Credential](testNow, entropy), testNow); err != nil {
		t.Fatalf("setting a password: %v", err)
	}
	if user.State() != domain.StatePending {
		t.Fatalf("the fixture is %s; it must be pending, or activation cannot be observed",
			user.State())
	}
	user.ClearUncommitted()
	return user, userID
}

// sfActiveUser builds an account that has completed enrolment, with a recovery
// set of the given size.
func sfActiveUser(t *testing.T, codes int) (*domain.User, ids.UserID, ids.CredentialID) {
	t.Helper()
	user, userID := sfPendingUser(t)
	entropy := &fixedEntropy{}
	totpCred := ids.New[ids.Credential](testNow, entropy)
	if err := user.StartTotpEnrollment(totpCred, testNow.Add(time.Hour), testNow); err != nil {
		t.Fatalf("starting enrolment: %v", err)
	}
	if err := user.EnableTotp(totpCred, testNow); err != nil {
		t.Fatalf("enabling: %v", err)
	}
	recoveryCred := ids.New[ids.Credential](testNow, entropy)
	if codes > 0 {
		if err := user.GenerateRecoveryCodes(recoveryCred, codes, testNow); err != nil {
			t.Fatalf("generating: %v", err)
		}
	}
	if user.State() != domain.StateActive {
		t.Fatalf("the fixture is %s; TOTP should have activated it", user.State())
	}
	user.ClearUncommitted()
	return user, userID, recoveryCred
}

// secondFactorCodec encodes exactly the events these handlers can produce, so a
// test can inspect the bytes that would reach the log.
func secondFactorCodec(t *testing.T) *eventcodec.JSON {
	t.Helper()
	c := eventcodec.NewJSON(nil)
	eventcodec.Register[contract.TotpEnrollmentStarted](c)
	eventcodec.Register[contract.TotpEnabled](c)
	eventcodec.Register[contract.RecoveryCodesGenerated](c)
	eventcodec.Register[contract.RecoveryCodeConsumed](c)
	eventcodec.Register[contract.RecoveryCodesExhausted](c)
	eventcodec.Register[contract.UserActivated](c)
	return c
}

// assertNoSecretIsAppended encodes every appended event and its metadata, and
// fails if any of the forbidden strings appears in the bytes.
//
// The ENCODED form is what matters: a struct field holding a secret is invisible
// to a field-by-field assertion if somebody adds it, and the log stores bytes.
func assertNoSecretIsAppended(t *testing.T, h *sfHarness, forbidden ...string) {
	t.Helper()
	codec := secondFactorCodec(t)
	for _, e := range h.appended() {
		payload, err := codec.Marshal(e.Event)
		if err != nil {
			t.Fatalf("encoding %T: %v", e.Event, err)
		}
		meta, err := codec.MarshalMetadata(e.Meta)
		if err != nil {
			t.Fatalf("encoding metadata: %v", err)
		}
		for _, secret := range forbidden {
			if secret == "" {
				t.Fatal("an empty needle would pass against anything")
			}
			if bytes.Contains(payload, []byte(secret)) {
				t.Errorf("%T carries %q into the event log; an event is permanent, so a "+
					"secret in one outlives the credential it protects (ADR-002)",
					e.Event, secret)
			}
			if bytes.Contains(meta, []byte(secret)) {
				t.Errorf("the metadata of %T carries %q", e.Event, secret)
			}
		}
	}
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

func TestEverySecondFactorDependencyIsRequired(t *testing.T) {
	base := func() SecondFactorDeps {
		return SecondFactorDeps{
			Clock:   clock.NewFixed(testNow),
			Entropy: &fixedEntropy{},
			Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
				return nil, nil
			}),
			Appender: &fakeAppender{},
			Enroll:   func(string) (TotpEnrollment, error) { return TotpEnrollment{}, nil },
			Sealer:   &fakeSealer{},
			Secrets:  newFakeSecrets(),
			Verifier: newFakeVerifier(sfSharedValue, sfCode),
			Recovery: newFakeRecovery(),
		}
	}
	if _, err := NewSecondFactor(base()); err != nil {
		t.Fatalf("the complete set must wire: %v", err)
	}

	tests := map[string]func(*SecondFactorDeps){
		"clock":       func(d *SecondFactorDeps) { d.Clock = nil },
		"entropy":     func(d *SecondFactorDeps) { d.Entropy = nil },
		"users":       func(d *SecondFactorDeps) { d.Users = nil },
		"appender":    func(d *SecondFactorDeps) { d.Appender = nil },
		"enroller":    func(d *SecondFactorDeps) { d.Enroll = nil },
		"sealer":      func(d *SecondFactorDeps) { d.Sealer = nil },
		"secrets":     func(d *SecondFactorDeps) { d.Secrets = nil },
		"verifier":    func(d *SecondFactorDeps) { d.Verifier = nil },
		"recovery":    func(d *SecondFactorDeps) { d.Recovery = nil },
		"window":      func(d *SecondFactorDeps) { d.Window = -time.Second },
		"code count":  func(d *SecondFactorDeps) { d.RecoveryCodeCount = MaxRecoveryCodeCount + 1 },
		"key version": func(d *SecondFactorDeps) { d.Sealer = &fakeSealer{version: -1} },
	}
	for name, break_ := range tests {
		t.Run(name, func(t *testing.T) {
			deps := base()
			break_(&deps)
			if _, err := NewSecondFactor(deps); err == nil {
				t.Errorf("wiring succeeded with %s missing or invalid; a nil port surfaces as "+
					"a panic during somebody's enrolment rather than a refusal to start", name)
			}
		})
	}
}

// A sealer reporting version 0 must be refused, and the reason is not tidiness: a
// row written at 0 is invisible to the `pepper_version < n` re-sealing query, so
// it is skipped silently and the account loses its second factor months later
// when the old key is destroyed.
func TestASealerWithNoKeyVersionIsRefused(t *testing.T) {
	h := newSFHarness(t)
	_, err := NewSecondFactor(SecondFactorDeps{
		Clock:   clock.NewFixed(testNow),
		Entropy: &fixedEntropy{},
		Users: loaderFunc[*domain.User](func(context.Context, string) (*domain.User, error) {
			return h.user, nil
		}),
		Appender: h.appender,
		Enroll:   func(string) (TotpEnrollment, error) { return h.enrollment, nil },
		Sealer:   &fakeSealer{version: -3},
		Secrets:  h.secrets,
		Verifier: h.verifier,
		Recovery: h.recovery,
	})
	if err == nil {
		t.Fatal("a sealer below version 1 wired successfully")
	}
	if !strings.Contains(err.Error(), "key version") {
		t.Errorf("the error is %q; it must name the key version, or the operator has "+
			"nothing to act on", err)
	}
}

// ---------------------------------------------------------------------------
// EnrollTotp
// ---------------------------------------------------------------------------

func TestEnrollingSealsTheSecretAndReturnsItOnce(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()

	got, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err != nil {
		t.Fatalf("enrolling: %v", err)
	}

	if got.Secret != sfSharedValue {
		t.Errorf("the caller got secret %q, want %q: it is returned once and is "+
			"unrecoverable afterwards", got.Secret, sfSharedValue)
	}
	if !strings.Contains(got.URI, sfSharedValue) {
		t.Errorf("the provisioning URI %q does not carry the secret, so no authenticator "+
			"can be enrolled from it", got.URI)
	}
	if !got.ExpiresAt.Equal(testNow.Add(DefaultEnrollmentWindow)) {
		t.Errorf("the enrolment expires at %v, want %v", got.ExpiresAt,
			testNow.Add(DefaultEnrollmentWindow))
	}
	if len(h.enrollNames) != 1 || h.enrollNames[0] != sfAccount {
		t.Errorf("the enroller saw account names %v, want exactly [%q]", h.enrollNames, sfAccount)
	}

	if len(h.secrets.provisioned) != 1 {
		t.Fatalf("%d secrets were stored, want 1", len(h.secrets.provisioned))
	}
	stored := h.secrets.provisioned[0]
	if stored.Sealed == sfSharedValue || strings.Contains(stored.Sealed, "sealed:") == false {
		t.Errorf("the stored value is %q; a shared secret must be SEALED, not written in "+
			"the clear into the one table an attacker who reaches the database already has",
			stored.Sealed)
	}
	if !strings.HasSuffix(stored.Sealed, sfSharedValue) {
		t.Errorf("the sealed value does not carry the secret this enrolment generated")
	}
	if stored.ID != got.CredentialID || stored.SubjectID != sfSubject {
		t.Errorf("the row was stored as (%s, %s), want (%s, %s); the seal is bound to both "+
			"and cannot be opened from another row",
			stored.ID, stored.SubjectID, got.CredentialID, sfSubject)
	}
	if stored.KeyVersion != h.sealer.KeyVersion() {
		t.Errorf("the row records key version %d, want %d: at the wrong version the "+
			"re-sealing job visits the wrong rows", stored.KeyVersion, h.sealer.KeyVersion())
	}
	if h.secrets.rows[sfSubject].Enabled {
		t.Error("the enrolment was stored ENABLED; a secret nobody has produced a code " +
			"from must not be able to satisfy the second-factor requirement")
	}

	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("%d events were appended, want 1", len(events))
	}
	started, ok := events[0].Event.(*contract.TotpEnrollmentStarted)
	if !ok {
		t.Fatalf("appended %T, want *contract.TotpEnrollmentStarted", events[0].Event)
	}
	if started.CredentialID != got.CredentialID.String() || started.SubjectID != sfSubject {
		t.Errorf("the event names (%s, %s), want (%s, %s)",
			started.SubjectID, started.CredentialID, sfSubject, got.CredentialID)
	}
	assertNoSecretIsAppended(t, h, sfSharedValue, got.URI, stored.Sealed)
}

// The seal must be bound to the row that holds it. This asserts the handler
// passes the pair it stores under, which is what makes a copied row fail to open
// rather than becoming an authenticator the attacker holds the secret for.
func TestTheSecretIsSealedAgainstTheRowItIsStoredUnder(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()

	got, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err != nil {
		t.Fatalf("enrolling: %v", err)
	}
	sealed := h.secrets.rows[sfSubject].Sealed

	if _, err := h.sealer.Open(sealed, sfSubject, got.CredentialID); err != nil {
		t.Fatalf("the secret cannot be opened under its own row: %v", err)
	}

	other := sfOtherCredential
	if _, err := h.sealer.Open(sealed, sfSubject, other); !errors.Is(err, ErrSecretUnreadable) {
		t.Errorf("a secret sealed for %s opened under %s (err=%v); one write to the "+
			"credential table would then install an authenticator on any account",
			got.CredentialID, other, err)
	}
	if _, err := h.sealer.Open(sealed, "subj_someone_else", got.CredentialID); !errors.Is(err, ErrSecretUnreadable) {
		t.Errorf("a secret sealed for %s opened under another subject (err=%v)", sfSubject, err)
	}
}

// A restarted enrolment must land on the id the store already holds. Minting a
// fresh one collides with the partial unique index — and collides on every retry,
// leaving the account unable to enrol at all.
func TestEnrollingReusesAnAbandonedEnrollmentsCredentialId(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()

	first, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err != nil {
		t.Fatalf("first enrolment: %v", err)
	}

	// The event landed, so the aggregate now holds a PENDING method. A second
	// enrolment is legal — nothing was ever proven.
	h.user.Apply(&contract.TotpEnrollmentStarted{
		SubjectID: sfSubject, CredentialID: first.CredentialID.String(),
		ExpiresAt: first.ExpiresAt, StartedAt: testNow,
	})

	second, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent + "-2",
	})
	if err != nil {
		t.Fatalf("second enrolment: %v", err)
	}
	if second.CredentialID != first.CredentialID {
		t.Errorf("the restarted enrolment minted %s, want the stored %s; a fresh id "+
			"contends on credential_one_usable_per_kind_idx and fails on every retry",
			second.CredentialID, first.CredentialID)
	}
	if len(h.secrets.provisioned) != 2 {
		t.Fatalf("%d secrets stored, want 2", len(h.secrets.provisioned))
	}
	if h.secrets.rows[sfSubject].Enabled {
		t.Error("the replacement was stored enabled")
	}
}

func TestEnrollingIsRefusedWhenAnAuthenticatorIsAlreadyProven(t *testing.T) {
	h := newSFHarness(t)
	h.user, h.userID, _ = sfActiveUser(t, 0)
	sf := h.build()

	_, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if errs.ReasonOf(err) != errs.Conflict {
		t.Fatalf("enrolling over a proven authenticator gave %v, want a conflict", err)
	}
	if len(h.secrets.provisioned) != 0 {
		t.Error("a secret was stored for an enrolment the domain refused")
	}
	if len(h.appender.calls) != 0 {
		t.Error("something was appended for an enrolment the domain refused")
	}
}

func TestNothingIsStoredWhenSealingFails(t *testing.T) {
	h := newSFHarness(t)
	h.sealer.sealErr = errors.New("the key ring is unreachable")
	sf := h.build()

	if _, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	}); err == nil {
		t.Fatal("the enrolment succeeded with no working seal")
	}
	if len(h.secrets.provisioned) != 0 {
		t.Error("a secret was stored despite the seal failing; storing it unsealed puts a " +
			"working second factor in the clear in the credential table")
	}
	if len(h.appender.calls) != 0 {
		t.Error("an enrolment event was appended with no stored secret")
	}
}

func TestNothingIsAppendedWhenTheSecretCannotBeStored(t *testing.T) {
	h := newSFHarness(t)
	h.secrets.provisionErr = errors.New("the database is unreachable")
	sf := h.build()

	if _, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	}); err == nil {
		t.Fatal("the enrolment succeeded with no stored secret")
	}
	if len(h.appender.calls) != 0 {
		t.Error("the log now asserts an enrolment whose secret does not exist, and the " +
			"aggregate will refuse to start another")
	}
}

func TestEnrolmentValidatesItsCommand(t *testing.T) {
	tests := map[string]EnrollTotpCommand{
		"no idempotency key": {UserID: ids.MustParse[ids.User]("usr_01ARZ3NDEKTSV4RRFFQ69G5FAV"), AccountName: sfAccount},
		"no user":            {AccountName: sfAccount, IdempotencyKey: sfIdempotent},
		"no account name":    {UserID: ids.MustParse[ids.User]("usr_01ARZ3NDEKTSV4RRFFQ69G5FAV"), IdempotencyKey: sfIdempotent},
		"blank account name": {UserID: ids.MustParse[ids.User]("usr_01ARZ3NDEKTSV4RRFFQ69G5FAV"), AccountName: "   ", IdempotencyKey: sfIdempotent},
	}
	for name, cmd := range tests {
		t.Run(name, func(t *testing.T) {
			h := newSFHarness(t)
			sf := h.build()
			if _, err := sf.EnrollTotp(context.Background(), cmd); errs.ReasonOf(err) != errs.ValidationFailed {
				t.Errorf("got %v, want a validation failure", err)
			}
			if len(h.secrets.provisioned) != 0 || len(h.appender.calls) != 0 {
				t.Error("an invalid command still did work")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// ConfirmTotp
// ---------------------------------------------------------------------------

// enrolled runs a real enrolment so confirmation has something to confirm.
func (h *sfHarness) enrolled(sf *SecondFactor) ids.CredentialID {
	h.t.Helper()
	got, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err != nil {
		h.t.Fatalf("enrolling: %v", err)
	}
	h.user.Apply(&contract.TotpEnrollmentStarted{
		SubjectID: sfSubject, CredentialID: got.CredentialID.String(),
		ExpiresAt: got.ExpiresAt, StartedAt: testNow,
	})
	h.appender.calls = nil
	return got.CredentialID
}

func TestConfirmingWithALiveCodeCompletesTheAccount(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	cred := h.enrolled(sf)

	got, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent + "-confirm",
	})
	if err != nil {
		t.Fatalf("confirming: %v", err)
	}
	if got.CredentialID != cred {
		t.Errorf("confirmed %s, want %s", got.CredentialID, cred)
	}
	if !got.Changed {
		t.Error("the confirmation reported no change")
	}
	if !got.Activated {
		t.Error("the account did not activate; a verified address plus a proven second " +
			"factor is exactly the pair that completes it")
	}

	// The secret handed to the verifier must be the OPENED one, not the sealed
	// blob: verifying against ciphertext refuses every genuine code.
	if h.verifier.sawSecret != sfSharedValue {
		t.Errorf("the verifier saw secret %q, want the opened %q", h.verifier.sawSecret, sfSharedValue)
	}
	if len(h.verifier.sawCredIDs) != 1 || h.verifier.sawCredIDs[0] != cred {
		t.Errorf("the replay guard was keyed on %v, want [%s]; a claim keyed on anything "+
			"else lets one account's login spend another's step",
			h.verifier.sawCredIDs, cred)
	}

	if len(h.secrets.enabled) != 1 || h.secrets.enabled[0] != cred {
		t.Errorf("the row was enabled as %v, want [%s]; a proven factor the "+
			"usable-credential lookup skips is one the user cannot use",
			h.secrets.enabled, cred)
	}

	events := h.appended()
	if len(events) != 2 {
		t.Fatalf("%d events appended, want TotpEnabled and UserActivated", len(events))
	}
	if _, ok := events[0].Event.(*contract.TotpEnabled); !ok {
		t.Errorf("the first event is %T, want *contract.TotpEnabled", events[0].Event)
	}
	if _, ok := events[1].Event.(*contract.UserActivated); !ok {
		t.Errorf("the second event is %T, want *contract.UserActivated", events[1].Event)
	}
	assertNoSecretIsAppended(t, h, sfSharedValue, sfCode, h.secrets.rows[sfSubject].Sealed)
}

// A code that verified once must not verify again inside its window. Without the
// claim the second factor is a ninety-second bearer token (ADR-049).
func TestAReplayedCodeIsRefused(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	h.enrolled(sf)

	if _, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent + "-1",
	}); err != nil {
		t.Fatalf("the first confirmation: %v", err)
	}
	// Roll the aggregate back to pending, so the ONLY thing that can refuse the
	// second presentation is the replay claim.
	h.user, h.userID = sfPendingUser(t)
	h.user.Apply(&contract.TotpEnrollmentStarted{
		SubjectID: sfSubject, CredentialID: h.secrets.rows[sfSubject].ID.String(),
		ExpiresAt: testNow.Add(time.Hour), StartedAt: testNow,
	})
	h.appender.calls = nil

	_, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent + "-2",
	})
	if err == nil {
		t.Fatal("a replayed code was accepted")
	}
	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("a replayed code gave %v; it must be the ordinary refusal, or the "+
			"response tells an attacker their relayed code was genuine", err)
	}
	if len(h.appender.calls) != 0 {
		t.Error("a replayed code appended an event")
	}
}

// Every failure must look the same. An endpoint that answers "you have no
// authenticator" differently from "wrong code" hands an attacker holding a
// session the list of accounts worth attacking.
func TestEveryFailedConfirmationIsIndistinguishable(t *testing.T) {
	answers := map[string]func(*sfHarness, *SecondFactor){
		"wrong code": func(h *sfHarness, sf *SecondFactor) { h.enrolled(sf) },
		"no enrolment": func(*sfHarness, *SecondFactor) {
			// Nothing enrolled at all.
		},
		"unopenable secret": func(h *sfHarness, sf *SecondFactor) {
			h.enrolled(sf)
			row := h.secrets.rows[sfSubject]
			row.Sealed = "sealed:subj_someone_else:" + row.ID.String() + ":" + sfSharedValue
			h.secrets.rows[sfSubject] = row
		},
		"enrolment the log does not name": func(h *sfHarness, sf *SecondFactor) {
			h.enrolled(sf)
			// The aggregate forgets the enrolment; the row survives. This is what a
			// direct table write looks like.
			h.user, h.userID = sfPendingUser(t)
		},
	}

	var messages []string
	for name, setup := range answers {
		t.Run(name, func(t *testing.T) {
			h := newSFHarness(t)
			sf := h.build()
			setup(h, sf)

			_, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
				UserID: h.userID, Code: "999999", IdempotencyKey: sfIdempotent,
			})
			if err == nil {
				t.Fatal("the confirmation succeeded")
			}
			if errs.ReasonOf(err) != errs.ValidationFailed {
				t.Errorf("%s produced reason %q, want %q", name, errs.ReasonOf(err), errs.ValidationFailed)
			}
			messages = append(messages, err.Error())
			if len(h.appender.calls) != 0 {
				t.Error("a failed confirmation appended an event")
			}
			if len(h.secrets.enabled) != 0 {
				t.Error("a failed confirmation enabled the credential")
			}
		})
	}
	for _, m := range messages[1:] {
		if m != messages[0] {
			t.Errorf("two failures answer differently: %q vs %q — the difference is the "+
				"oracle the uniform answer exists to remove", messages[0], m)
		}
	}
}

func TestConfirmingTwiceAppendsNothing(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	cred := h.enrolled(sf)

	if _, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent + "-1",
	}); err != nil {
		t.Fatalf("the first confirmation: %v", err)
	}
	h.appender.calls = nil
	// A fresh code, and the aggregate already holds the factor as proven.
	h.verifier.code = "654321"

	got, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: "654321", IdempotencyKey: sfIdempotent + "-2",
	})
	if err != nil {
		t.Fatalf("the retried confirmation: %v", err)
	}
	if got.Changed || got.Activated {
		t.Errorf("the retry reported changed=%v activated=%v, want both false",
			got.Changed, got.Activated)
	}
	if got.CredentialID != cred {
		t.Errorf("the retry reported %s, want %s", got.CredentialID, cred)
	}
	if len(h.appender.calls) != 0 {
		t.Error("a retried confirmation appended a second TotpEnabled")
	}
}

// The row is enabled BEFORE the append, so a crash leaves a factor the aggregate
// still considers unproven — recoverable by retrying. The other order leaves the
// log asserting a proven factor the usable-credential lookup skips.
func TestTheRowIsEnabledBeforeTheEventIsAppended(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	cred := h.enrolled(sf)
	h.appender.err = errors.New("the log is unreachable")

	if _, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent + "-confirm",
	}); err == nil {
		t.Fatal("the confirmation succeeded with an unreachable log")
	}
	if len(h.secrets.enabled) != 1 || h.secrets.enabled[0] != cred {
		t.Errorf("the row was enabled as %v, want [%s] — the write must precede the "+
			"append, or a crash costs the user a second factor they cannot use",
			h.secrets.enabled, cred)
	}
}

// An Enable that fails must stop the command. Ignoring it — the shape a deferred
// enable takes — leaves the log asserting a proven factor while the row the
// usable-credential lookup reads says otherwise, and nothing ever repairs it
// because a retried confirmation finds the aggregate already satisfied.
func TestNothingIsAppendedWhenTheAuthenticatorCannotBeEnabled(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	h.enrolled(sf)
	h.secrets.enableErr = errors.New("the database is unreachable")

	_, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("the confirmation succeeded although the row could not be enabled")
	}
	if len(h.appender.calls) != 0 {
		t.Error("TotpEnabled was appended for a factor the usable-credential lookup " +
			"will never return")
	}
	// An outage is INTERNAL and must stay INTERNAL: the caller can do nothing with
	// it, and dressing a broken database in a specific reason would tell them to
	// fix an input that was never wrong.
	if got := errs.ReasonOf(err); got != errs.Internal {
		t.Errorf("reason %s, want %s — an unreachable database is ours, not the caller's",
			got, errs.Internal)
	}
}

// The one Enable failure that is NOT an outage: the enrolment was removed
// between the read a few lines above and this write. That is the account's own
// state, so it gets the refusal every other second-factor failure gets.
//
// INTERNAL would be wrong twice. It tells the caller to retry a code that can
// never work again — the secret is gone, they must enrol and scan the new QR —
// and it answers differently from the "no enrolment" branch above, which is
// exactly the account-existence oracle the uniform refusal exists to deny.
func TestARemovedEnrolmentIsRefusedAsAWrongCode(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	h.enrolled(sf)
	h.secrets.enableErr = ErrCredentialNotFound

	_, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("the confirmation succeeded although the enrolment had been removed")
	}
	if got := errs.ReasonOf(err); got != errs.ValidationFailed {
		t.Errorf("reason %s, want %s — a removed enrolment is the account's own state, "+
			"and INTERNAL tells the caller to retry a code that can never work again",
			got, errs.ValidationFailed)
	}
	// Byte-identical to what a plain wrong code returns, or this branch is the
	// oracle the whole function is shaped to deny.
	if err.Error() != errWrongCode().Error() {
		t.Errorf("the refusal reads %q, want %q — a distinguishable answer here tells a "+
			"caller which accounts hold an enrolment", err, errWrongCode())
	}
	if len(h.appender.calls) != 0 {
		t.Error("TotpEnabled was appended for an enrolment that no longer exists")
	}
}

func TestAnUnreachableReplayGuardRefusesRatherThanAccepts(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	h.enrolled(sf)
	h.verifier.err = errors.New("the replay guard is unavailable")

	if _, err := sf.ConfirmTotp(context.Background(), ConfirmTotpCommand{
		UserID: h.userID, Code: sfCode, IdempotencyKey: sfIdempotent,
	}); err == nil {
		t.Fatal("the confirmation succeeded while the replay guard was unavailable; an " +
			"attacker who can cause that outage has turned the second factor off")
	}
	if len(h.secrets.enabled) != 0 || len(h.appender.calls) != 0 {
		t.Error("the confirmation had effects despite failing")
	}
}

// ---------------------------------------------------------------------------
// GenerateRecoveryCodes
// ---------------------------------------------------------------------------

func TestGeneratingRecoveryCodesStoresOnlyDigests(t *testing.T) {
	h := newSFHarness(t)
	h.user, h.userID, _ = sfActiveUser(t, 0)
	sf := h.build()

	got, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent,
	})
	if err != nil {
		t.Fatalf("generating: %v", err)
	}
	if len(got.Codes) != DefaultRecoveryCodeCount {
		t.Fatalf("%d codes returned, want %d", len(got.Codes), DefaultRecoveryCodeCount)
	}
	if len(h.recovery.replaced) != 1 {
		t.Fatalf("%d sets stored, want 1", len(h.recovery.replaced))
	}
	set := h.recovery.replaced[0]
	if len(set.Digests) != len(got.Codes) {
		t.Fatalf("%d digests stored for %d codes", len(set.Digests), len(got.Codes))
	}
	if set.CredentialID != got.CredentialID || set.SubjectID != sfSubject {
		t.Errorf("the set was stored as (%s, %s), want (%s, %s)",
			set.SubjectID, set.CredentialID, sfSubject, got.CredentialID)
	}

	seen := map[string]bool{}
	for i, code := range got.Codes {
		if seen[code] {
			t.Fatalf("code %d repeats; a set with duplicates has fewer secrets than the "+
				"user is told they hold", i)
		}
		seen[code] = true

		normalized := normalizeRecoveryCode(code)
		if len(normalized) != 16 {
			t.Errorf("code %q normalizes to %d characters, want 16 (80 bits)", code, len(normalized))
		}
		// The stored digest must be what a PRESENTATION of this code hashes to, and
		// must not be the code.
		want := recoveryDigest(sfSubject, normalized)
		if !bytes.Equal(set.Digests[i], want) {
			t.Errorf("digest %d is not the digest of the code that was handed out", i)
		}
		if len(set.Digests[i]) != 32 {
			t.Errorf("digest %d is %d bytes; the column has a CHECK of 32", i, len(set.Digests[i]))
		}
		if bytes.Contains(set.Digests[i], []byte(normalized)) {
			t.Errorf("digest %d contains the code itself", i)
		}
	}

	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("%d events appended, want 1", len(events))
	}
	generated, ok := events[0].Event.(*contract.RecoveryCodesGenerated)
	if !ok {
		t.Fatalf("appended %T, want *contract.RecoveryCodesGenerated", events[0].Event)
	}
	if generated.Count != len(got.Codes) {
		t.Errorf("the event says %d codes, %d were issued", generated.Count, len(got.Codes))
	}
	forbidden := append([]string{}, got.Codes...)
	for _, digest := range set.Digests {
		forbidden = append(forbidden, hex.EncodeToString(digest))
	}
	assertNoSecretIsAppended(t, h, forbidden...)
}

// The invariant a mutation pass found broken once already: an account must not be
// able to answer "enrol a second factor" with a printed sheet.
func TestRecoveryCodesDoNotActivateTheAccount(t *testing.T) {
	h := newSFHarness(t) // password set, address verified, no real second factor
	sf := h.build()

	if _, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent,
	}); err != nil {
		t.Fatalf("generating: %v", err)
	}
	for _, e := range h.appended() {
		if _, ok := e.Event.(*contract.UserActivated); ok {
			t.Fatal("a recovery-code set activated the account; the mandatory second factor " +
				"is then satisfied by the one method whose whole purpose is to work when " +
				"the real ones have failed")
		}
	}
	if h.user.State() != domain.StatePending {
		t.Errorf("the account is %s, want pending", h.user.State())
	}
}

func TestRegeneratingReplacesTheWholeSet(t *testing.T) {
	h := newSFHarness(t)
	h.user, h.userID, _ = sfActiveUser(t, 0)
	sf := h.build()

	first, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent + "-1",
	})
	if err != nil {
		t.Fatalf("the first set: %v", err)
	}
	second, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent + "-2",
	})
	if err != nil {
		t.Fatalf("the second set: %v", err)
	}

	if second.CredentialID != first.CredentialID {
		t.Errorf("the regenerate minted %s, want the stored %s; a fresh id contends on "+
			"the one-usable-per-kind index and fails on every retry",
			second.CredentialID, first.CredentialID)
	}
	live := h.recovery.digests[sfSubject]
	if len(live) != len(second.Codes) {
		t.Fatalf("%d digests are live after a regenerate, want %d", len(live), len(second.Codes))
	}
	for _, code := range first.Codes {
		key := hex.EncodeToString(recoveryDigest(sfSubject, normalizeRecoveryCode(code)))
		if _, ok := live[key]; ok {
			t.Fatal("a code from the replaced set is still live; somebody who photographed " +
				"the old sheet keeps their access through the regeneration performed to " +
				"take it away")
		}
	}
}

func TestAShortReadRefusesRatherThanMintingAPredictableCode(t *testing.T) {
	h := newSFHarness(t)
	h.user, h.userID, _ = sfActiveUser(t, 0)
	// Enough for four codes, then nothing.
	h.codeEntropy = &shortReader{left: recoveryCodeBytes * 4}
	sf := h.build()

	if _, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent,
	}); err == nil {
		t.Fatal("codes were minted from an exhausted entropy source; the tail of a " +
			"short-read code is zeroes, which is a set an attacker can search while the " +
			"user is told they hold ten independent secrets")
	}
	if len(h.recovery.replaced) != 0 {
		t.Error("a partial set was stored")
	}
	if len(h.appender.calls) != 0 {
		t.Error("an event was appended for a set that was never minted")
	}
}

func TestTheRecoveryCodeCountIsBounded(t *testing.T) {
	tests := map[string]int{
		"negative":     -1,
		"beyond limit": MaxRecoveryCodeCount + 1,
	}
	for name, count := range tests {
		t.Run(name, func(t *testing.T) {
			h := newSFHarness(t)
			h.user, h.userID, _ = sfActiveUser(t, 0)
			sf := h.build()
			_, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
				UserID: h.userID, Count: count, IdempotencyKey: sfIdempotent,
			})
			if errs.ReasonOf(err) != errs.ValidationFailed {
				t.Errorf("a count of %d gave %v, want a validation failure", count, err)
			}
			if len(h.recovery.replaced) != 0 {
				t.Error("a set was stored for an out-of-range count")
			}
		})
	}
}

func TestNothingIsAppendedWhenTheCodeSetCannotBeStored(t *testing.T) {
	h := newSFHarness(t)
	h.user, h.userID, _ = sfActiveUser(t, 0)
	h.recovery.replaceErr = errors.New("the database is unreachable")
	sf := h.build()

	if _, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, IdempotencyKey: sfIdempotent,
	}); err == nil {
		t.Fatal("the generation succeeded with no stored digests")
	}
	if len(h.appender.calls) != 0 {
		t.Error("the log now asserts a code set nothing can redeem")
	}
}

// ---------------------------------------------------------------------------
// ConsumeRecoveryCode
// ---------------------------------------------------------------------------

// withCodes puts an active account and a live set of the given size in place.
func (h *sfHarness) withCodes(sf *SecondFactor, count int) []string {
	h.t.Helper()
	h.user, h.userID, _ = sfActiveUser(h.t, 0)
	got, err := sf.GenerateRecoveryCodes(context.Background(), GenerateRecoveryCodesCommand{
		UserID: h.userID, Count: count, IdempotencyKey: sfIdempotent + "-gen",
	})
	if err != nil {
		h.t.Fatalf("generating: %v", err)
	}
	h.user.Apply(&contract.RecoveryCodesGenerated{
		SubjectID: sfSubject, CredentialID: got.CredentialID.String(),
		Count: count, GeneratedAt: testNow,
	})
	h.appender.calls = nil
	return got.Codes
}

func TestConsumingACodeBurnsItExactlyOnce(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)

	got, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: codes[0], IdempotencyKey: sfIdempotent + "-1",
	})
	if err != nil {
		t.Fatalf("consuming: %v", err)
	}
	if got.Remaining != 2 {
		t.Errorf("%d codes remain, want 2", got.Remaining)
	}
	if got.Exhausted {
		t.Error("the set was reported exhausted with two codes left")
	}
	events := h.appended()
	if len(events) != 1 {
		t.Fatalf("%d events appended, want 1", len(events))
	}
	if _, ok := events[0].Event.(*contract.RecoveryCodeConsumed); !ok {
		t.Fatalf("appended %T, want *contract.RecoveryCodeConsumed", events[0].Event)
	}
	assertNoSecretIsAppended(t, h, codes[0], normalizeRecoveryCode(codes[0]))

	h.appender.calls = nil
	_, err = sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: codes[0], IdempotencyKey: sfIdempotent + "-2",
	})
	if err == nil {
		t.Fatal("the same code was spent twice; a single-use secret that is sometimes " +
			"multi-use is exactly what somebody holding the sheet needs")
	}
	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("a spent code gave %v, want the ordinary refusal", err)
	}
	if len(h.appender.calls) != 0 {
		t.Error("a spent code appended an event")
	}
}

func TestTheLastCodeEmitsExhausted(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 1)

	got, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: codes[0], IdempotencyKey: sfIdempotent + "-last",
	})
	if err != nil {
		t.Fatalf("consuming: %v", err)
	}
	if got.Remaining != 0 || !got.Exhausted {
		t.Errorf("the last code reported remaining=%d exhausted=%v, want 0 and true",
			got.Remaining, got.Exhausted)
	}

	var sawExhausted bool
	for _, e := range h.appended() {
		if _, ok := e.Event.(*contract.RecoveryCodesExhausted); ok {
			sawExhausted = true
		}
	}
	if !sawExhausted {
		t.Fatal("no RecoveryCodesExhausted was appended; a reactor cannot force the " +
			"re-issue interstitial without it, and the account is left with no fallback " +
			"and no prompt to restore one")
	}
}

// A code is bound to its subject by the digest, not only by the query's WHERE
// clause. A digest row copied to another account must hash to nothing that
// account can present.
func TestACodeDoesNotWorkOnAnotherAccount(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)

	mine := recoveryDigest(sfSubject, normalizeRecoveryCode(codes[0]))
	theirs := recoveryDigest("subj_someone_else", normalizeRecoveryCode(codes[0]))
	if bytes.Equal(mine, theirs) {
		t.Fatal("one code hashes to the same digest for two subjects; a row copied " +
			"between accounts is then a working credential on the second")
	}
}

func TestNormalizationAcceptsWhatAUserActuallyTypes(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)

	typed := strings.ToLower(strings.ReplaceAll(codes[0], "-", " "))
	if typed == codes[0] {
		t.Fatalf("the fixture %q is unchanged by lowering and unhyphenating, so this "+
			"test proves nothing", codes[0])
	}
	if _, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: typed, IdempotencyKey: sfIdempotent + "-typed",
	}); err != nil {
		t.Fatalf("a code read off paper in lower case with spaces was refused: %v", err)
	}
}

func TestAnUnknownRecoveryCodeAppendsNothing(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	h.withCodes(sf, 3)

	_, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: "AAAA-BBBB-CCCC-DDDD", IdempotencyKey: sfIdempotent,
	})
	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Fatalf("an unknown code gave %v, want the ordinary refusal", err)
	}
	if len(h.appender.calls) != 0 {
		t.Error("an unknown code appended an event, so the count of remaining codes " +
			"walks down on guesses")
	}
}

// The domain decides BEFORE the burn. A request that was never going to succeed
// must not cost the user a code.
func TestAnAccountThatCannotAuthenticateSpendsNoCode(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)
	if err := h.user.Deactivate("subj_self", testNow); err != nil {
		t.Fatalf("deactivating: %v", err)
	}
	h.user.ClearUncommitted()

	_, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: codes[0], IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("a deactivated account redeemed a recovery code")
	}
	if h.recovery.consumeCalls != 0 {
		t.Error("the code was burned for a request the domain refused")
	}
	if len(h.appender.calls) != 0 {
		t.Error("an event was appended for a request the domain refused")
	}
}

// A burn that names a credential the account's own log does not record must not
// produce an event: otherwise one table write is enough to spend a factor down.
func TestABurnAgainstAnUnknownCredentialAppendsNothing(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)
	stranger := sfOtherCredential
	h.recovery.consumeCredential = &stranger

	_, err := sf.ConsumeRecoveryCode(context.Background(), ConsumeRecoveryCodeCommand{
		UserID: h.userID, Code: codes[0], IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("a code belonging to a credential the log does not name was accepted")
	}
	if len(h.appender.calls) != 0 {
		t.Error("an event was appended against a credential the account does not hold")
	}
}

func TestConsumingValidatesItsCommand(t *testing.T) {
	h := newSFHarness(t)
	sf := h.build()
	codes := h.withCodes(sf, 3)

	tests := map[string]ConsumeRecoveryCodeCommand{
		"no idempotency key": {UserID: h.userID, Code: codes[0]},
		"no user":            {Code: codes[0], IdempotencyKey: sfIdempotent},
		"empty code":         {UserID: h.userID, Code: "  --  ", IdempotencyKey: sfIdempotent},
	}
	for name, cmd := range tests {
		t.Run(name, func(t *testing.T) {
			before := h.recovery.consumeCalls
			if _, err := sf.ConsumeRecoveryCode(context.Background(), cmd); errs.ReasonOf(err) != errs.ValidationFailed {
				t.Errorf("got %v, want a validation failure", err)
			}
			if h.recovery.consumeCalls != before {
				t.Error("an invalid command still reached the store")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// Codes
// ---------------------------------------------------------------------------

func TestRecoveryCodeDigestsAreDomainSeparated(t *testing.T) {
	// A digest must not be reproducible by hashing the code alone, or a digest
	// table stolen from anywhere else in this system could be substituted.
	code := "ABCD2345EFGH6789"
	if bytes.Equal(recoveryDigest(sfSubject, code), recoveryDigest("", code)) {
		t.Fatal("the subject does not participate in the digest")
	}
	// The length prefixes must make the boundary unmovable: ("ab", "cd") and
	// ("a", "bcd") are different triples and must hash differently.
	if bytes.Equal(recoveryDigest("ab", "CD"), recoveryDigest("a", "BCD")) {
		t.Fatal("the subject and code boundary can be shifted, so two different pairs " +
			"collide")
	}
}

func TestNormalizingDropsEverythingOutsideTheAlphabet(t *testing.T) {
	tests := map[string]string{
		"abcd-efgh":     "ABCDEFGH",
		"ABCD EFGH":     "ABCDEFGH",
		"a.b,c;d/e f g": "ABCDEFG",
		"01189":         "",
		"":              "",
	}
	for in, want := range tests {
		t.Run(fmt.Sprintf("%q", in), func(t *testing.T) {
			if got := normalizeRecoveryCode(in); got != want {
				t.Errorf("normalize(%q) = %q, want %q", in, got, want)
			}
		})
	}
}

// TestALostRaceIsAConflictNotAnInternalError pins the answer a caller gets when
// the account changed underneath their command.
//
// The expected-revision precondition refuses an append decided against a state
// that has since moved — a concurrent disable, a suspension, or simply the
// caller's own second tab. Reported as INTERNAL that reads "we broke, retry with
// backoff", and a client obeying it retries the SAME stale command, which the
// precondition refuses again for the same reason. CONFLICT is the catalogue's
// answer for "re-read and retry", and it is the one that terminates.
//
// Safe to disclose here because EnrollTotp is post-authentication and
// self-scoped: the caller has already proven the account is theirs, so
// confirming that something is happening to it tells them nothing new.
func TestALostRaceIsAConflictNotAnInternalError(t *testing.T) {
	h := newSFHarness(t)
	h.appender.err = fmt.Errorf("appending: %w", eventsourcing.ErrWrongExpectedRevision)
	sf := h.build()

	_, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("a lost optimistic-concurrency race was reported as success")
	}
	if got := errs.ReasonOf(err); got != errs.Conflict {
		t.Errorf("reason %v, want CONFLICT — INTERNAL tells the caller to retry a command "+
			"the precondition will refuse again for exactly the same reason", got)
	}
	// The sentinel stays reachable through the chain. The reason is what the
	// client branches on; the sentinel is what OUR code branches on, and a
	// mapping that swallowed it would break the callers that already do.
	if !errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
		t.Errorf("the wrong-expected-revision sentinel no longer survives the mapping: %v", err)
	}
}

// TestAnAppendOutageIsStillInternal is the other half of the test above.
//
// Without it, conflictOnRace could map EVERY append failure to CONFLICT and the
// test above would still pass — telling a caller to "re-read and try again" when
// the event store is simply down, which is advice that cannot work.
func TestAnAppendOutageIsStillInternal(t *testing.T) {
	h := newSFHarness(t)
	h.appender.err = errors.New("kurrentdb: connection refused")
	sf := h.build()

	_, err := sf.EnrollTotp(context.Background(), EnrollTotpCommand{
		UserID: h.userID, AccountName: sfAccount, IdempotencyKey: sfIdempotent,
	})
	if err == nil {
		t.Fatal("an unreachable event store was reported as success")
	}
	if got := errs.ReasonOf(err); got == errs.Conflict {
		t.Error("an append outage was reported as CONFLICT; only a lost revision race is a " +
			"conflict, and an outage is not something the caller can resolve by re-reading")
	}
}
