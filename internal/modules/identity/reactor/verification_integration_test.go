//go:build integration

package reactor

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	smtpadapter "github.com/chronos/chronos-go/internal/adapter/smtp"
	"github.com/chronos/chronos-go/internal/modules/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/adapter/token"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// The whole gap, closed and proven end to end against running infrastructure:
// EmailVerificationRequested → a freshly minted token → the notification kernel
// → the template → SMTP → a real message in Mailpit → the token pulled back out
// of the link that message contains → VerifyEmail accepting it.
//
// Every layer below this is unit-tested in isolation, and every one of those
// tests passed while the plaintext token reached nobody at all. This is the test
// that cannot pass unless a person could actually verify their address.
func TestVerificationMailReachesMailpitAndVerifies(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	const baseURL = "http://localhost:3000"
	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Name: "Chronos", Email: "no-reply@chronos.local"},
		BaseURL: baseURL,
	})
	if err := renderer.Load(ctx); err != nil {
		t.Fatalf("templates: %v", err)
	}
	transport := mail.NewTransport(renderer,
		smtpadapter.New(smtpadapter.Config{Host: "localhost", Port: 1025, Domain: "chronos.local"}),
		clock.System{}, nil)

	// A unique address per run, so the assertion cannot pass on a message an
	// earlier run left behind.
	to := fmt.Sprintf("verify+%d@example.test", time.Now().UnixNano())
	subject := fmt.Sprintf("subj_%d", time.Now().UnixNano())

	// ONE token store, shared by the issuer that mints and the use case that
	// redeems — exactly as identity_token is shared by the worker and the API.
	tokens := newMemoryTokens()
	minter := token.New()
	issuer, err := app.NewVerificationIssuer(app.VerificationIssuerDeps{
		Clock:  clock.System{},
		Tokens: tokens,
		Minter: func(p app.TokenPurpose, now time.Time) (app.MintedToken, error) {
			tok, err := minter.Mint(p, now)
			if err != nil {
				return app.MintedToken{}, err
			}
			return app.MintedToken{
				Plaintext: tok.Plaintext, Digest: tok.Digest, ExpiresAt: tok.ExpiresAt,
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("issuer: %v", err)
	}

	dispatcher := notify.NewDispatcher(notify.Deps{
		// The vault is the only source of the address, and it is consulted at
		// DELIVERY time. Nothing upstream of this line has ever seen it.
		Vault:      fixedVault{address: to, name: "Robin Ash", locale: "en", tz: "UTC"},
		Transports: []notify.Transport{transport},
	})

	r, err := NewVerificationMail(useCaseIssuer{issuer}, identityCodec(), dispatcher)
	if err != nil {
		t.Fatalf("reactor: %v", err)
	}
	if err := r.React(ctx, requestedEnvelope(t, subject)); err != nil {
		t.Fatalf("React: %v", err)
	}

	msg := waitForMessage(ctx, t, to)

	if !strings.Contains(msg.Subject, "Verify your email address") {
		t.Errorf("subject: %q", msg.Subject)
	}
	if msg.Text == "" || msg.HTML == "" {
		t.Error("a part is missing; HTML-only mail is a deliverability problem")
	}
	// Transactional mail carries no opt-out: nobody may unsubscribe from the one
	// message that is the only way into their own account.
	if strings.Contains(strings.ToLower(msg.HTML), "unsubscribe") {
		t.Error("the verification mail carried an unsubscribe link")
	}

	link := verifyLink.FindStringSubmatch(msg.Text)
	if link == nil {
		t.Fatalf("no verification link in the message body:\n%s", msg.Text)
	}
	if !strings.HasPrefix(link[0], baseURL) {
		t.Errorf("the link %q is not absolute against the configured base URL; email "+
			"clients do not resolve relative URLs", link[0])
	}
	if !strings.Contains(msg.HTML, link[1]) {
		t.Error("the HTML part carries a different token from the plaintext part")
	}
	plaintext := link[1]

	// Nothing that reached the wire may be the STORED form. If the digest were
	// mailable the store would be a list of live credentials.
	if strings.Contains(msg.Text, fmt.Sprintf("%x", token.Digest(app.PurposeEmailVerification, plaintext))) {
		t.Error("the message carries the stored digest")
	}

	// The claim under test: this is a token VerifyEmail accepts.
	//
	// A password travels with it because the account has none until this call —
	// registration deliberately creates no credential, so that a stranger who
	// registers somebody else's address leaves nothing behind for the mailbox
	// owner's click to activate (IDENTITY-REVIEW C8). The link and the password
	// are one step for exactly that reason, so a test that redeems the link
	// without one is exercising a flow that no longer exists.
	registration, userID := verifyingRegistration(t, tokens, subject)
	got, err := registration.VerifyEmail(ctx, app.VerifyEmailCommand{
		Token:          plaintext,
		Password:       "correct-horse-battery-staple-48",
		IdempotencyKey: "cmd-verify-integration",
	})
	if err != nil {
		t.Fatalf("VerifyEmail refused the token from the emailed link: %v", err)
	}
	if !got.Changed || got.UserID != userID {
		t.Errorf("VerifyEmail returned %+v, want a change on %s", got, userID)
	}

	// Single use. A link that verifies twice is a link that can be replayed out
	// of a mailbox someone else now reads.
	if _, err := registration.VerifyEmail(ctx, app.VerifyEmailCommand{
		Token: plaintext, IdempotencyKey: "cmd-verify-integration-2",
	}); err == nil {
		t.Error("the emailed token was redeemable a second time")
	}
}

// verifyLink pulls the token out of the link exactly as a mail client would
// hand it to the browser.
var verifyLink = regexp.MustCompile(`http://[^\s]+/verify-email\?token=([A-Za-z0-9_-]+)`)

// ---------------------------------------------------------------------------
// The redemption side, assembled from identity's own use case
// ---------------------------------------------------------------------------

// verifyingRegistration builds a Registration positioned exactly where a real
// one is when a link is clicked: an account that registered and claimed an
// address, and a reservation it still holds.
//
// Most of the stubs below are deps VerifyEmail never touches, and those panic
// rather than returning zero values, so a change that starts calling one is a
// loud failure rather than a test that quietly proves less than it says.
//
// Three of them ANSWER — the breach screen, the hasher and StoreFirst — because
// redeeming the link is now also the call that sets the account's first password
// (IDENTITY-REVIEW C8). They were panicking until that change landed, which is
// how this test caught it: the flow it exercises grew a step.
func verifyingRegistration(
	t *testing.T, tokens app.TokenStore, subjectID string,
) (*app.Registration, ids.UserID) {
	t.Helper()

	userID := ids.MustParse[ids.User]("usr_01H8XG5N2QK7VB3C9WPYZR4TFM")
	index := contract.EmailIndex("idx_integration")
	past := time.Now().Add(-time.Hour).UTC()

	user := eventsourcing.NewAggregate(domain.New)
	if err := user.Register(userID, subjectID, index, past); err != nil {
		t.Fatalf("building the account: %v", err)
	}
	reservation := eventsourcing.NewAggregate(domain.NewReservation)
	if err := reservation.Reserve(index, subjectID, past.Add(24*time.Hour), past); err != nil {
		t.Fatalf("building the reservation: %v", err)
	}

	schemas := eventsourcing.NewUpcasterRegistry()
	identity.RegisterSchemas(schemas)

	registration, err := app.NewRegistration(app.RegistrationDeps{
		Clock:        clock.System{},
		Entropy:      rand.Reader,
		Index:        stubIndexer{},
		Breach:       stubBreach{},
		Hasher:       stubHasher{},
		Vault:        stubVault{},
		Credentials:  stubCredentials{},
		Reservations: loader[*domain.EmailReservation]{agg: reservation},
		Users:        loader[*domain.User]{agg: user},
		Appender:     stubAppender{},
		Tokens:       tokens,
		Minter: func(app.TokenPurpose, time.Time) (app.MintedToken, error) {
			panic("VerifyEmail must not mint")
		},
		Digest:    token.Digest,
		Directory: stubDirectory{user: userID, subject: subjectID},
		// Answers rather than panics: VerifyEmail voids every session established
		// before the proof (IDENTITY-REVIEW C8), and this account has none. Wired
		// as a stub because this test is about mail delivery, not revocation —
		// registration_test.go asserts the call itself.
		Revocations: stubRevoker{},
		Schemas:     schemas,
	})
	if err != nil {
		t.Fatalf("wiring the registration use case: %v", err)
	}
	return registration, userID
}

type stubRevoker struct{}

func (stubRevoker) RevokeAllSessions(
	context.Context, app.RevokeAllSessionsCommand,
) (app.RevokeAllSessionsResult, error) {
	return app.RevokeAllSessionsResult{}, nil
}

type loader[T eventsourcing.Root] struct{ agg T }

func (l loader[T]) Load(context.Context, string) (T, error) { return l.agg, nil }

type stubAppender struct{}

func (stubAppender) AppendToMany(
	_ context.Context, appends []eventsourcing.StreamAppend,
) ([]eventsourcing.AppendResult, error) {
	out := make([]eventsourcing.AppendResult, 0, len(appends))
	for range appends {
		out = append(out, eventsourcing.AppendResult{
			Position: eventsourcing.Position{Commit: 1, Prepare: 1},
		})
	}
	return out, nil
}

type stubDirectory struct {
	user    ids.UserID
	subject string
}

func (d stubDirectory) UserBySubject(_ context.Context, subjectID string) (ids.UserID, error) {
	if subjectID != d.subject {
		return ids.UserID{}, app.ErrNoSuchSubject
	}
	return d.user, nil
}

type stubIndexer struct{}

func (stubIndexer) Of(string) (contract.EmailIndex, error) { panic("VerifyEmail derives no index") }

type stubBreach struct{}

// VerifyEmail screens the password now, so this answers instead of panicking.
// It reports "not breached" — this test is about whether the emailed link works,
// and a real corpus lookup would make it depend on a third-party service.
func (stubBreach) Breached(context.Context, string) (bool, string, error) {
	return false, "", nil
}

type stubHasher struct{}

// Likewise: the first password is hashed during VerifyEmail. A fixed verifier is
// enough — nothing here authenticates with it, and a real Argon2id pass would add
// ~50ms to a test measuring mail delivery.
func (stubHasher) Hash(context.Context, string, ids.UserID, ids.CredentialID) (string, error) {
	return "argon2id$stub$integration", nil
}

func (stubHasher) Verify(context.Context, string, string, ids.UserID, ids.CredentialID) (bool, error) {
	panic("VerifyEmail verifies no password")
}

func (stubHasher) NeedsRehash(string) bool { panic("VerifyEmail rehashes nothing") }

// PepperVersion is the one method NewRegistration calls at wiring time: a
// verifier stored below version 1 is invisible to key rotation, so it refuses
// anything lower.
func (stubHasher) PepperVersion() int32 { return 1 }

type stubVault struct{}

func (stubVault) PutAll(context.Context, pii.SubjectID, map[pii.Field]string) error {
	panic("VerifyEmail writes nothing to the vault")
}

type stubCredentials struct{}

func (stubCredentials) Store(context.Context, app.NewPasswordCredential) error {
	panic("VerifyEmail stores no credential")
}

// StoreFirst is what VerifyEmail uses now that the password is set by the party
// that proves the mailbox (IDENTITY-REVIEW C8). It accepts rather than panicking,
// because redeeming the emailed link IS the call that stores the first
// credential — the other methods still panic, since none of them belongs to this
// flow.
func (stubCredentials) StoreFirst(context.Context, app.NewPasswordCredential) error {
	return nil
}

// Replace is the password reset's write. Nothing in a verification performs one,
// so it fails loudly rather than returning nil.
func (stubCredentials) Replace(
	context.Context, ids.CredentialID, string, string, int32,
) error {
	return errors.New("a verification must not replace a password verifier")
}

func (stubCredentials) Find(context.Context, string) (app.PasswordCredential, error) {
	panic("VerifyEmail reads no credential")
}

func (stubCredentials) Rehash(context.Context, ids.CredentialID, string, string, int32) error {
	panic("VerifyEmail rehashes nothing")
}

func (stubCredentials) RecordSuccess(context.Context, ids.CredentialID) error {
	panic("VerifyEmail records no attempt")
}

func (stubCredentials) RecordFailure(context.Context, ids.CredentialID) (int32, error) {
	panic("VerifyEmail records no attempt")
}

func (stubCredentials) Disable(context.Context, ids.CredentialID) error {
	panic("VerifyEmail disables nothing")
}

// ---------------------------------------------------------------------------
// A token store with the real store's semantics
// ---------------------------------------------------------------------------

// memoryTokens mirrors identity_token: the digest is the key, the purpose is
// part of the lookup, and Consume is single-use.
type memoryTokens struct {
	rows map[string]memoryTokenRow
}

type memoryTokenRow struct {
	subjectID string
	expiresAt time.Time
}

func newMemoryTokens() *memoryTokens { return &memoryTokens{rows: map[string]memoryTokenRow{}} }

func (s *memoryTokens) key(purpose app.TokenPurpose, digest []byte) string {
	return string(purpose) + "|" + fmt.Sprintf("%x", digest)
}

func (s *memoryTokens) Issue(
	_ context.Context, purpose app.TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	s.rows[s.key(purpose, digest)] = memoryTokenRow{subjectID: subjectID, expiresAt: expiresAt}
	return nil
}

func (s *memoryTokens) Consume(
	_ context.Context, purpose app.TokenPurpose, digest []byte, now time.Time,
) (string, error) {
	k := s.key(purpose, digest)
	row, ok := s.rows[k]
	if !ok || !row.expiresAt.After(now) {
		return "", app.ErrTokenNotFound
	}
	delete(s.rows, k)
	return row.subjectID, nil
}

// RevokeAllPurposes belongs to the password reset. A verification issuer voids
// one purpose, never every purpose, so this fails loudly rather than quietly
// widening the sweep.
func (s *memoryTokens) RevokeAllPurposes(context.Context, string) (int, error) {
	return 0, errors.New("not used by the verification issuer")
}

func (s *memoryTokens) RevokeAll(_ context.Context, purpose app.TokenPurpose, subjectID string) error {
	for k, row := range s.rows {
		if row.subjectID == subjectID && strings.HasPrefix(k, string(purpose)+"|") {
			delete(s.rows, k)
		}
	}
	return nil
}

// useCaseIssuer is the composition root's adapter, reproduced here so this test
// exercises the same conversion cmd/worker performs.
type useCaseIssuer struct{ issuer *app.VerificationIssuer }

func (a useCaseIssuer) IssueVerification(
	ctx context.Context, subjectID string,
) (Verification, error) {
	v, err := a.issuer.IssueVerification(ctx, subjectID)
	if err != nil {
		return Verification{}, err
	}
	return Verification{
		Plaintext: v.Plaintext, ExpiresAt: v.ExpiresAt, TTL: v.TTL, Fingerprint: v.Fingerprint,
	}, nil
}

type fixedVault struct {
	address, name, locale, tz string
}

func (v fixedVault) Resolve(context.Context, string) (notify.Recipient, error) {
	return notify.Recipient{
		Address: v.address, Name: v.name, Locale: v.locale, Timezone: v.tz,
	}, nil
}

// ---------------------------------------------------------------------------
// Mailpit
// ---------------------------------------------------------------------------

// mailpitGet issues one request against Mailpit's HTTP API, carrying the test's
// context so a hung server ends the test at its own deadline rather than at the
// package timeout.
func mailpitGet(ctx context.Context, path string) (*http.Response, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:8025"+path, nil)
	if err != nil {
		return nil, err
	}
	return http.DefaultClient.Do(req)
}

type mailpitMessage struct {
	Subject string
	Text    string
	HTML    string
}

func waitForMessage(ctx context.Context, t *testing.T, to string) mailpitMessage {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		if id := findMessageID(ctx, to); id != "" {
			return fetchMessage(ctx, t, id)
		}
		select {
		case <-ctx.Done():
			t.Fatal("context ended while waiting for the message")
		case <-time.After(300 * time.Millisecond):
		}
	}
	t.Fatalf("no message for %s arrived in Mailpit", to)
	return mailpitMessage{}
}

func findMessageID(ctx context.Context, to string) string {
	resp, err := mailpitGet(ctx, "/api/v1/search?query="+to)
	if err != nil {
		return ""
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return ""
	}
	// Tolerant, and it has to be: Mailpit returns a dozen fields this test does
	// not model, and a strict decode would report "nothing arrived" for mail that
	// arrived fine.
	out, err := codec.Tolerant[struct {
		Messages []struct {
			ID string `json:"ID"`
		} `json:"messages"`
	}](body)
	if err != nil || len(out.Messages) == 0 {
		return ""
	}
	return out.Messages[0].ID
}

func fetchMessage(ctx context.Context, t *testing.T, id string) mailpitMessage {
	t.Helper()
	resp, err := mailpitGet(ctx, "/api/v1/message/"+id)
	if err != nil {
		t.Fatalf("fetching message: %v", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("reading message: %v", err)
	}
	out, err := codec.Tolerant[struct {
		Subject string `json:"Subject"`
		Text    string `json:"Text"`
		HTML    string `json:"HTML"`
	}](body)
	if err != nil {
		t.Fatalf("decoding message: %v", err)
	}
	return mailpitMessage{Subject: out.Subject, Text: out.Text, HTML: out.HTML}
}
