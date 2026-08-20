package app

import (
	"context"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/platform/clock"
)

// ---------------------------------------------------------------------------
// A token store that records the ORDER of the two calls
// ---------------------------------------------------------------------------

// sequencedTokens is liveTokens with a call log.
//
// The order is the whole point of this type. Both calls succeeding proves
// nothing: revoke-then-issue and issue-then-revoke leave a store in states that
// differ only by which rows survive, and the second order silently voids the
// token it just handed out. A counter cannot see that; a sequence can.
type sequencedTokens struct {
	live *liveTokens
	seq  []string

	issueErr  error
	revokeErr error
}

func newSequencedTokens() *sequencedTokens {
	return &sequencedTokens{live: newLiveTokens()}
}

func (s *sequencedTokens) Issue(
	ctx context.Context, purpose TokenPurpose, subjectID string, digest []byte, expiresAt time.Time,
) error {
	s.seq = append(s.seq, "issue")
	if s.issueErr != nil {
		return s.issueErr
	}
	return s.live.Issue(ctx, purpose, subjectID, digest, expiresAt)
}

func (s *sequencedTokens) Consume(
	ctx context.Context, purpose TokenPurpose, digest []byte, now time.Time,
) (string, error) {
	return s.live.Consume(ctx, purpose, digest, now)
}

// RevokeAllPurposes belongs to the reset. An issuer voids one purpose, never
// every purpose, so this fails loudly rather than quietly widening the sweep.
func (s *sequencedTokens) RevokeAllPurposes(context.Context, string) (int, error) {
	return 0, errors.New("not used by the verification issuer")
}

func (s *sequencedTokens) RevokeAll(
	ctx context.Context, purpose TokenPurpose, subjectID string,
) error {
	s.seq = append(s.seq, "revoke")
	if s.revokeErr != nil {
		return s.revokeErr
	}
	return s.live.RevokeAll(ctx, purpose, subjectID)
}

const issuerSubject = "subj_01H8XG5N2QK7VB3C9WPYZR4TFN"

// newIssuer builds the subject under test with the same digest derivation the
// rest of this suite uses, so a token it mints can be presented to VerifyEmail.
func newIssuer(t *testing.T, tokens TokenStore) (*VerificationIssuer, *fakeMinter) {
	t.Helper()
	minter := &fakeMinter{label: "issuer"}
	issuer, err := NewVerificationIssuer(VerificationIssuerDeps{
		Clock:  clock.NewFixed(testNow),
		Tokens: tokens,
		Minter: minter.mint,
	})
	if err != nil {
		t.Fatalf("wiring the issuer: %v", err)
	}
	return issuer, minter
}

// ---------------------------------------------------------------------------
// NewVerificationIssuer
// ---------------------------------------------------------------------------

func TestNewVerificationIssuerRefusesAMissingDependency(t *testing.T) {
	t.Parallel()
	minter := (&fakeMinter{}).mint

	tests := []struct {
		name string
		deps VerificationIssuerDeps
	}{
		{"no clock", VerificationIssuerDeps{Tokens: newLiveTokens(), Minter: minter}},
		{"no token store", VerificationIssuerDeps{Clock: clock.NewFixed(testNow), Minter: minter}},
		{"no minter", VerificationIssuerDeps{Clock: clock.NewFixed(testNow), Tokens: newLiveTokens()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if _, err := NewVerificationIssuer(tt.deps); err == nil {
				t.Error("wiring succeeded with a missing dependency; the failure would " +
					"first appear as a link nobody can redeem")
			}
		})
	}
}

// ---------------------------------------------------------------------------
// IssueVerification
// ---------------------------------------------------------------------------

func TestIssueVerificationRevokesBeforeIssuing(t *testing.T) {
	t.Parallel()
	tokens := newSequencedTokens()
	issuer, _ := newIssuer(t, tokens)

	if _, err := issuer.IssueVerification(context.Background(), issuerSubject); err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}

	if got := strings.Join(tokens.seq, ","); got != "revoke,issue" {
		t.Errorf("call order %q, want \"revoke,issue\" — issuing first and revoking "+
			"after voids the token just handed to the caller, and the mail then "+
			"carries a link that is dead on arrival", got)
	}
}

func TestIssueVerificationStoresTheDigestOfTheReturnedToken(t *testing.T) {
	t.Parallel()
	tokens := newLiveTokens()
	issuer, _ := newIssuer(t, tokens)

	got, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}
	if got.Plaintext == "" {
		t.Fatal("no plaintext was returned; nothing can be mailed")
	}

	// The redemption path's own lookup: purpose plus the digest of what the link
	// carries. Anything else stored here is a link that is refused on click, with
	// no error anywhere until a user complains.
	subject, err := tokens.Consume(
		context.Background(), PurposeEmailVerification,
		testDigest(PurposeEmailVerification, got.Plaintext), testNow)
	if err != nil {
		t.Fatalf("the issued token is not redeemable: %v", err)
	}
	if subject != issuerSubject {
		t.Errorf("the token redeems to %q, want %q", subject, issuerSubject)
	}
}

func TestIssueVerificationReportsTheMintersDeadline(t *testing.T) {
	t.Parallel()
	issuer, minter := newIssuer(t, newLiveTokens())

	got, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}

	want := minter.minted[0].ExpiresAt
	if !got.ExpiresAt.Equal(want) {
		t.Errorf("expiry %s, want the minter's %s", got.ExpiresAt, want)
	}
	// TTL is what the wording promises. Derived from the same instant the expiry
	// was stamped from, so "expires in 24 hours" cannot drift from the deadline
	// the store enforces.
	if got.TTL != want.Sub(testNow) {
		t.Errorf("ttl %s, want %s", got.TTL, want.Sub(testNow))
	}
}

// The invariant identity.md §7 rule 7 asks for, stated as a test: after any
// issuance, exactly ONE verification token for that subject can be redeemed.
//
// Without it, a retried delivery leaves two live links for one address, and
// spending one leaves the other usable — which is what an attacker who has seen
// a single mail needs.
func TestIssueVerificationLeavesExactlyOneLiveToken(t *testing.T) {
	t.Parallel()
	tokens := newLiveTokens()
	issuer, _ := newIssuer(t, tokens)

	first, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	second, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("second issuance: %v", err)
	}
	if first.Plaintext == second.Plaintext {
		t.Fatal("both issuances produced the same secret; the test cannot tell them apart")
	}

	if live := tokens.live(PurposeEmailVerification, testNow); len(live) != 1 {
		t.Errorf("%d live verification tokens, want exactly 1", len(live))
	}
	if _, err := tokens.Consume(context.Background(), PurposeEmailVerification,
		testDigest(PurposeEmailVerification, first.Plaintext), testNow); !errors.Is(err, ErrTokenNotFound) {
		t.Error("the FIRST token is still redeemable after a second issuance")
	}
	if _, err := tokens.Consume(context.Background(), PurposeEmailVerification,
		testDigest(PurposeEmailVerification, second.Plaintext), testNow); err != nil {
		t.Errorf("the most recent token is not redeemable: %v", err)
	}
}

func TestIssueVerificationRefusesAnEmptySubject(t *testing.T) {
	t.Parallel()
	tokens := newSequencedTokens()
	issuer, minter := newIssuer(t, tokens)

	if _, err := issuer.IssueVerification(context.Background(), ""); err == nil {
		t.Fatal("issued a token against no subject; nothing could ever redeem it")
	}
	if minter.calls != 0 {
		t.Errorf("minted %d tokens for an empty subject, want 0", minter.calls)
	}
	if len(tokens.seq) != 0 {
		t.Errorf("touched the store %v for an empty subject — RevokeAll with no "+
			"subject matches nothing in one store and everything in another", tokens.seq)
	}
}

// A minter that fails must not cost the subject the token they already hold.
// Minting first is what guarantees that: nothing is revoked until there is
// something to replace it with.
func TestIssueVerificationLeavesTheOldTokenAliveWhenMintingFails(t *testing.T) {
	t.Parallel()
	tokens := newLiveTokens()
	issuer, minter := newIssuer(t, tokens)

	existing, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	minter.err = errors.New("entropy source unavailable")

	if _, err := issuer.IssueVerification(context.Background(), issuerSubject); err == nil {
		t.Fatal("a failed mint reported success")
	}
	if _, err := tokens.Consume(context.Background(), PurposeEmailVerification,
		testDigest(PurposeEmailVerification, existing.Plaintext), testNow); err != nil {
		t.Errorf("a failed mint voided the live token: %v", err)
	}
}

func TestIssueVerificationFailsWhenTheStoreDoes(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		apply func(*sequencedTokens)
	}{
		{"revoke fails", func(s *sequencedTokens) { s.revokeErr = errors.New("postgres unreachable") }},
		{"issue fails", func(s *sequencedTokens) { s.issueErr = errors.New("postgres unreachable") }},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			tokens := newSequencedTokens()
			tt.apply(tokens)
			issuer, _ := newIssuer(t, tokens)

			got, err := issuer.IssueVerification(context.Background(), issuerSubject)
			if err == nil {
				t.Fatal("a failed store reported success; the caller would mail a link " +
					"whose digest was never recorded")
			}
			if got.Plaintext != "" {
				t.Error("a plaintext was returned alongside the failure; a caller that " +
					"ignored the error would mail an unredeemable link")
			}
		})
	}
}

// The fingerprint travels into a workflow id and a Message-ID header. It must
// identify the issuance without being any part of the secret.
func TestIssueVerificationFingerprintIsDistinctAndNotTheSecret(t *testing.T) {
	t.Parallel()
	issuer, _ := newIssuer(t, newLiveTokens())

	first, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("first issuance: %v", err)
	}
	second, err := issuer.IssueVerification(context.Background(), issuerSubject)
	if err != nil {
		t.Fatalf("second issuance: %v", err)
	}

	if first.Fingerprint == second.Fingerprint {
		t.Error("two issuances share a fingerprint; a redelivery would then be " +
			"deduplicated against the previous, revoked token")
	}
	for _, v := range []Verification{first, second} {
		if _, err := hex.DecodeString(v.Fingerprint); err != nil || len(v.Fingerprint) != 16 {
			t.Errorf("fingerprint %q is not 16 hex characters", v.Fingerprint)
		}
		if strings.Contains(v.Fingerprint, v.Plaintext) || strings.Contains(v.Plaintext, v.Fingerprint) {
			t.Error("the fingerprint overlaps the secret it names")
		}
		// Not the stored digest either: the digest is a lookup key, and putting
		// part of one into a workflow id and a mail header is a property nobody
		// should have to reason about.
		if v.Fingerprint == hex.EncodeToString(testDigest(PurposeEmailVerification, v.Plaintext))[:16] {
			t.Error("the fingerprint is a prefix of the stored digest")
		}
	}
}

// ---------------------------------------------------------------------------
// The join: a token this issuer minted is one VerifyEmail accepts
// ---------------------------------------------------------------------------

// This is the property the whole feature turns on, and neither half can assert
// it alone. The issuer can prove it wrote a row; VerifyEmail can prove it reads
// one. Only together do they prove that the link in the mail opens the account
// it was sent for — a purpose mismatch, a different digest derivation or a
// subject written under the wrong key would leave both halves passing and every
// real link refused.
func TestVerifyEmailAcceptsATokenFromTheIssuer(t *testing.T) {
	t.Parallel()
	h, userID, _ := verifyHarness(t)

	// ONE store, shared: the issuer writes the digest and VerifyEmail reads it,
	// exactly as identity_token is shared by the worker and the API.
	tokens := newLiveTokens()
	h.tokenStore = tokens
	issuer, _ := newIssuer(t, tokens)

	issued, err := issuer.IssueVerification(context.Background(), h.tokens.subjectID)
	if err != nil {
		t.Fatalf("IssueVerification: %v", err)
	}

	got, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: issued.Plaintext, Password: testPassword, IdempotencyKey: "cmd-verify",
	})
	if err != nil {
		t.Fatalf("VerifyEmail refused a token this issuer minted: %v", err)
	}
	if !got.Changed || got.UserID != userID {
		t.Errorf("VerifyEmail returned %+v, want a change on %s", got, userID)
	}

	// Single use, still: the shared store is the real one, so a second click
	// must be refused rather than confirming twice.
	if _, err := h.build().VerifyEmail(context.Background(), VerifyEmailCommand{
		Token: issued.Plaintext, Password: testPassword, IdempotencyKey: "cmd-verify-again",
	}); err == nil {
		t.Error("the issued token was redeemable twice")
	}
}
