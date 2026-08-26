package app

import (
	"context"
	"crypto/rand"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// ---------------------------------------------------------------------------
// Doubles
// ---------------------------------------------------------------------------

// secretCall is one call to the digest store, recorded WHOLE.
//
// Whole rather than counted, for the reason issuedToken is recorded whole: every
// argument carries a way for the handler to be wrong that a count cannot see —
// the wrong organization authenticates the key into another tenant, the wrong
// scopes widen it, and a zero deadline hands the caller a credential that never
// works.
type secretCall struct {
	op     string // "issue", "retire", "delete"
	secret NewAPIKeySecret
	keyID  ids.APIKeyID
	at     time.Time
}

type fakeKeySecrets struct {
	calls     []secretCall
	issueErr  error
	retireErr error
	deleteErr error
	destroyed int
}

func (f *fakeKeySecrets) Issue(_ context.Context, s NewAPIKeySecret) error {
	f.calls = append(f.calls, secretCall{op: "issue", secret: s, keyID: s.KeyID})
	return f.issueErr
}

func (f *fakeKeySecrets) Retire(_ context.Context, id ids.APIKeyID, at time.Time) (int, error) {
	f.calls = append(f.calls, secretCall{op: "retire", keyID: id, at: at})
	if f.retireErr != nil {
		return 0, f.retireErr
	}
	return 1, nil
}

func (f *fakeKeySecrets) Delete(_ context.Context, id ids.APIKeyID) (int, error) {
	f.calls = append(f.calls, secretCall{op: "delete", keyID: id})
	if f.deleteErr != nil {
		return 0, f.deleteErr
	}
	return f.destroyed, nil
}

func (f *fakeKeySecrets) ops() []string {
	out := make([]string, len(f.calls))
	for i, c := range f.calls {
		out[i] = c.op
	}
	return out
}

// fakeServiceAccounts answers the existence check the key-issuing command makes.
type fakeServiceAccounts struct {
	exists bool
	err    error
	asked  []ids.ServiceAccountID
}

func (f *fakeServiceAccounts) Exists(_ context.Context, id ids.ServiceAccountID) (bool, error) {
	f.asked = append(f.asked, id)
	return f.exists, f.err
}

// apiKeyLoader hands back one prepared aggregate for every key id.
type apiKeyLoader struct {
	key *domain.APIKey
	err error
}

func (l *apiKeyLoader) Load(context.Context, string) (*domain.APIKey, error) {
	if l.err != nil {
		return nil, l.err
	}
	if l.key != nil {
		return l.key, nil
	}
	return eventsourcing.NewAggregate(domain.NewAPIKey), nil
}

type svcAccountLoader struct{}

func (svcAccountLoader) Load(context.Context, string) (*domain.ServiceAccount, error) {
	return eventsourcing.NewAggregate(domain.NewServiceAccount), nil
}

const (
	keyTestOrg   = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	keyTestActor = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"
	keyTestEnv   = "test"
)

type keyHarness struct {
	keys     *APIKeys
	appender *fakeAppender
	secrets  *fakeKeySecrets
	accounts *fakeServiceAccounts
	loader   *apiKeyLoader
	now      time.Time
}

func newKeyHarness(t *testing.T, existing *domain.APIKey) *keyHarness {
	t.Helper()
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	h := &keyHarness{
		appender: &fakeAppender{},
		secrets:  &fakeKeySecrets{destroyed: 1},
		accounts: &fakeServiceAccounts{exists: true},
		loader:   &apiKeyLoader{key: existing},
		now:      now,
	}
	keys, err := NewAPIKeys(APIKeysDeps{
		Clock:       clock.NewFixed(now),
		Entropy:     &fixedEntropy{},
		Environment: keyTestEnv,
		Accounts:    svcAccountLoader{},
		Keys:        h.loader,
		Appender:    h.appender,
		Schemas:     eventsourcing.NewUpcasterRegistry(),
		Secrets:     h.secrets,
		Directory:   h.accounts,
	})
	if err != nil {
		t.Fatalf("NewAPIKeys: %v", err)
	}
	h.keys = keys
	return h
}

// ---------------------------------------------------------------------------
// The token
// ---------------------------------------------------------------------------

// The token's five segments carry the scanner prefix, the environment, the key
// id and the secret, in that order.
//
// The shape is asserted rather than trusted because two independent things
// depend on it: a secret scanner recognising `chr_` in a paste, and the leak
// response reading a key id out of a token nobody may present.
func TestAnAPIKeyTokenCarriesItsPrefixEnvironmentAndKeyID(t *testing.T) {
	id := ids.New[ids.APIKey](time.Now(), &fixedEntropy{})

	token, digest, err := MintAPIKeyToken(keyTestEnv, id, &fixedEntropy{})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	if len(digest) != 32 {
		t.Fatalf("the digest is %d bytes, want 32", len(digest))
	}

	parts := strings.Split(token.Plaintext, "_")
	if len(parts) != 5 {
		t.Fatalf("the token has %d underscore-separated segments, want 5 (%q); the key id "+
			"contains its own underscore, so a parser using a limit would let a secret "+
			"change what the segments mean", len(parts), token.Plaintext)
	}
	if parts[0] != "chr" {
		t.Fatalf("the token starts %q, want \"chr\"; the fixed prefix is what lets a secret "+
			"scanner recognise one of our credentials without knowing anything else "+
			"about it", parts[0])
	}
	if parts[1] != keyTestEnv {
		t.Fatalf("the token names environment %q, want %q", parts[1], keyTestEnv)
	}
	if got := parts[2] + "_" + parts[3]; got != id.String() {
		t.Fatalf("the token names key %q, want %q; a leaked token must be attributable to a "+
			"key without anybody presenting the secret", got, id)
	}
}

// EVERY TOKEN THIS SYSTEM MINTS CAN BE PARSED BY THE THING THAT AUTHENTICATES IT.
//
// # The bug this exists for
//
// The secret is 32 random bytes in base64url, and base64url's 63rd character is
// `_`. A 43-character secret therefore contains at least one underscore about
// half the time — and the parser split on every underscore and demanded exactly
// five segments, so about half of every API key this system ever minted was
// refused by the authenticator with "this is not an API key", before the digest
// was computed, seconds after the server itself had issued it.
//
// Nothing caught it. The mint had tests, the parse had tests, the digest had
// tests, the authenticator had tests — and each used a hand-written or
// fixed-entropy token, which is to say a token whose tail nobody rolled. The
// first thing to present a real minted token to a real server found it as a
// 50/50 coin flip between test runs.
//
// So this rolls REAL entropy, many times, and asserts the round trip. The count
// is high enough that a one-in-two failure is certain and a rare-character
// failure is very likely; it costs microseconds.
func TestEveryMintedTokenParsesBackToTheKeyItNames(t *testing.T) {
	for i := range 512 {
		id := ids.New[ids.APIKey](time.Now(), rand.Reader)

		token, _, err := MintAPIKeyToken(keyTestEnv, id, rand.Reader)
		if err != nil {
			t.Fatalf("mint %d: %v", i, err)
		}
		parsed, err := ParseAPIKeyToken(token.Plaintext)
		if err != nil {
			t.Fatalf("the server minted %q and its own parser refused it: %v\n\n"+
				"Every request this credential makes is refused as \"not an API key\" "+
				"before the digest is looked at, so the holder sees an authentication "+
				"failure for a key that was issued to them and is live in the database.",
				token.Plaintext, err)
		}
		if parsed.KeyID != id {
			t.Fatalf("the token names key %q and parses back as %q; a leaked credential "+
				"would be attributed to the wrong key", id, parsed.KeyID)
		}
		if parsed.Environment != keyTestEnv {
			t.Fatalf("the token names environment %q and parses back as %q",
				keyTestEnv, parsed.Environment)
		}
	}
}

// A secret with an underscore in it is a NORMAL token, not a malformed one.
//
// Stated on its own, with the underscore placed deliberately rather than left
// to chance, so the property is asserted and not merely sampled by the test
// above.
func TestASecretContainingAnUnderscoreIsStillOurToken(t *testing.T) {
	id := ids.New[ids.APIKey](time.Now(), &fixedEntropy{})
	token := "chr_test_" + id.String() + "_AAAA_BBBB_CCCC"

	parsed, err := ParseAPIKeyToken(token)
	if err != nil {
		t.Fatalf("a token whose secret contains an underscore was refused: %v; base64url "+
			"contains underscores, so this is roughly half of all real tokens", err)
	}
	if parsed.KeyID != id {
		t.Fatalf("the key id parsed as %q, want %q — the underscores in the secret must "+
			"not shift the segments", parsed.KeyID, id)
	}
}

// The digest covers the WHOLE token, so the environment and the key id are bound
// to the secret by the hash itself.
//
// This is the property that makes a staging token unusable against production
// and a token pairing one key's id with another's secret unresolvable — with no
// comparison anywhere for anybody to forget.
func TestTheDigestBindsTheEnvironmentAndTheKeyToTheSecret(t *testing.T) {
	id := ids.New[ids.APIKey](time.Now(), &fixedEntropy{})
	other := ids.New[ids.APIKey](time.Now().Add(time.Second), &fixedEntropy{})

	token, digest, err := MintAPIKeyToken("live", id, &fixedEntropy{})
	if err != nil {
		t.Fatalf("mint: %v", err)
	}
	secret := token.Plaintext[strings.LastIndex(token.Plaintext, "_")+1:]

	swappedEnv := "chr_test_" + id.String() + "_" + secret
	if equalDigest(APIKeyTokenDigest(swappedEnv), digest) {
		t.Fatal("a token with a different environment hashes to the same digest; the " +
			"environment must be bound in, or a staging credential works against " +
			"production")
	}

	swappedKey := "chr_live_" + other.String() + "_" + secret
	if equalDigest(APIKeyTokenDigest(swappedKey), digest) {
		t.Fatal("a token pairing another key's id with this secret hashes to the same " +
			"digest; the key id must be bound in, or attribution and rate limiting can be " +
			"aimed at a key the presenter does not hold")
	}
}

// The parser refuses everything that is not one of our tokens, with ONE outcome.
//
// A parse that distinguished "wrong prefix" from "unparseable key id" would be a
// shape oracle: an attacker could learn which of their guesses was structurally
// closer.
func TestTheTokenParserRefusesEveryMalformedShape(t *testing.T) {
	id := ids.New[ids.APIKey](time.Now(), &fixedEntropy{})
	good := "chr_test_" + id.String() + "_AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"

	refused := map[string]string{
		"empty":             "",
		"a session token":   "6vBpsPRE7CQnO0GEbLZ6FRSGfLPQ0aBqZ2LQhVjw6oA",
		"the wrong prefix":  "key_test_" + id.String() + "_AAAA",
		"a missing segment": "chr_test_" + id.String(),
		// NOT in this table any more, and its absence is the fix to a real
		// outage: `good + "_extra"` is a token whose SECRET is
		// `AAA…_extra`, and a secret is opaque. It used to be refused here
		// because the parser split on every underscore — which also refused
		// about half of the tokens this system mints, since base64url's 63rd
		// character is `_`. Refusing it costs nothing to an attacker (the
		// digest will not resolve) and cost every second integrator their
		// credential.
		"an unparseable key id": "chr_test_key_NOTAULID_AAAA",
		"an empty secret":       "chr_test_" + id.String() + "_",
		"an upper-case env":     "chr_TEST_" + id.String() + "_AAAA",
		"an env with an escape": "chr_te.st_" + id.String() + "_AAAA",
	}
	for name, token := range refused {
		t.Run(name, func(t *testing.T) {
			if _, err := ParseAPIKeyToken(token); err == nil {
				t.Fatalf("%q parsed as an API key; every malformed shape must be refused "+
					"identically, or the parser becomes an oracle for how close a guess "+
					"is", token)
			}
		})
	}
	if _, err := ParseAPIKeyToken(good); err != nil {
		t.Fatalf("a well-formed token was refused: %v; the negative cases above prove "+
			"nothing if the parser refuses everything", err)
	}
}

// LooksLikeAPIKey routes on the token's own shape, and a session token is never
// routed to the key resolver.
func TestOnlyAnAPIKeyIsRoutedToTheKeyResolver(t *testing.T) {
	if !LooksLikeAPIKey("chr_test_anything") {
		t.Fatal("a token starting chr_ was not recognised as an API key; it would fall " +
			"through to the session lookup and produce a differently-worded refusal")
	}
	// A session token is 32 random bytes as unpadded base64url, which contains no
	// underscore at all — so the two spaces cannot overlap.
	if LooksLikeAPIKey("6vBpsPRE7CQnO0GEbLZ6FRSGfLPQ0aBqZ2LQhVjw6oA") {
		t.Fatal("a session token was routed to the API key resolver")
	}
}

func equalDigest(a, b []byte) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// ---------------------------------------------------------------------------
// Creation
// ---------------------------------------------------------------------------

// The plaintext is returned and the DIGEST is what is stored.
//
// The assertion is that the two are different values and that the stored one is
// 32 bytes: a store that received the plaintext would mean a database dump
// yields presentable credentials, which is the single worst outcome available
// here.
func TestCreatingAKeyStoresADigestAndReturnsThePlaintextOnce(t *testing.T) {
	h := newKeyHarness(t, nil)

	res, err := h.keys.CreateAPIKey(context.Background(), CreateAPIKeyCommand{
		OrgID:          keyTestOrg,
		ActorID:        keyTestActor,
		Scopes:         []string{"organization:read"},
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Token == "" {
		t.Fatal("no token was returned; this is the only moment it exists anywhere this " +
			"system can reach")
	}
	if len(h.secrets.calls) != 1 || h.secrets.calls[0].op != "issue" {
		t.Fatalf("the secret store saw %v, want exactly one issue", h.secrets.ops())
	}
	stored := h.secrets.calls[0].secret
	if len(stored.Digest) != 32 {
		t.Fatalf("stored a %d-byte value; a digest is 32 bytes and the plaintext is not",
			len(stored.Digest))
	}
	if strings.Contains(string(stored.Digest), res.Token) {
		t.Fatal("the plaintext token reached the store; a database dump must yield digests " +
			"that cannot be presented")
	}
	if stored.OrgID != keyTestOrg {
		t.Fatalf("the secret is bound to organization %q, want %q; the authenticator reads "+
			"this column to establish the tenant scope", stored.OrgID, keyTestOrg)
	}
}

// The append happens BEFORE the digest is stored.
//
// A digest stored first would be a live credential for a key the log does not
// contain — and if the append then failed, nothing could ever revoke it, because
// revocation works from the key's own stream.
func TestAKeysDigestIsStoredOnlyAfterItsCreationIsInTheLog(t *testing.T) {
	h := newKeyHarness(t, nil)
	h.appender.err = errors.New("the store is unreachable")

	if _, err := h.keys.CreateAPIKey(context.Background(), CreateAPIKeyCommand{
		OrgID:          keyTestOrg,
		ActorID:        keyTestActor,
		Scopes:         []string{"organization:read"},
		IdempotencyKey: "idem-1",
	}); err == nil {
		t.Fatal("a key was created despite the append failing")
	}
	if len(h.secrets.calls) != 0 {
		t.Fatalf("the secret store saw %v after a failed append; a digest stored for a key "+
			"the log does not contain is a live credential nothing can revoke",
			h.secrets.ops())
	}
}

// A key naming a service account that does not exist is refused before anything
// is written.
//
// Row-level security makes the directory answer "not visible" for another
// tenant's account too, so this is also the cross-tenant check: a caller naming
// somebody else's service account gets the answer for one that does not exist.
func TestAKeyCannotBeBoundToAnUnknownServiceAccount(t *testing.T) {
	h := newKeyHarness(t, nil)
	h.accounts.exists = false

	_, err := h.keys.CreateAPIKey(context.Background(), CreateAPIKeyCommand{
		OrgID:          keyTestOrg,
		ActorID:        keyTestActor,
		Owner:          domain.ServiceAccountOwner(ids.New[ids.ServiceAccount](h.now, &fixedEntropy{})),
		Scopes:         []string{"organization:read"},
		IdempotencyKey: "idem-1",
	})
	if err == nil {
		t.Fatal("a key was bound to a service account nobody can see; the credential would " +
			"be invisible on every management screen and unreachable by an " +
			"owner-scoped revocation")
	}
	if len(h.appender.calls) != 0 || len(h.secrets.calls) != 0 {
		t.Fatalf("the refused command wrote: %d appends, %v secret calls",
			len(h.appender.calls), h.secrets.ops())
	}
}

// An absent owner defaults to the CALLER, never to a service account.
//
// The default has to be the narrower of the two: a key that defaulted to a
// service account would be a durable, org-owned credential created by a client
// that simply did not send the field, outliving the person who created it.
func TestAnUnownedKeyBelongsToTheCallerAndNotToAServiceAccount(t *testing.T) {
	h := newKeyHarness(t, nil)

	res, err := h.keys.CreateAPIKey(context.Background(), CreateAPIKeyCommand{
		OrgID:          keyTestOrg,
		ActorID:        keyTestActor,
		Scopes:         []string{"organization:read"},
		IdempotencyKey: "idem-1",
	})
	if err != nil {
		t.Fatalf("create: %v", err)
	}
	if res.Owner.Kind != contract.OwnerUser {
		t.Fatalf("a key with no owner became a %s key; the default must be the narrower "+
			"one, or a client that omits the field creates a credential that outlives "+
			"its creator", res.Owner.Kind)
	}
	if res.Owner.ID != keyTestActor {
		t.Fatalf("the key acts as %q, want the caller %q", res.Owner.ID, keyTestActor)
	}
}

// ---------------------------------------------------------------------------
// Rotation
// ---------------------------------------------------------------------------

func rotatableKey(t *testing.T, now time.Time) *domain.APIKey {
	t.Helper()
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	err := k.Issue(
		ids.New[ids.APIKey](now, &fixedEntropy{}), keyTestOrg,
		domain.UserOwner(keyTestActor), []string{"organization:read"},
		now.Add(domain.DefaultAPIKeyLifetime), keyTestActor, now,
	)
	if err != nil {
		t.Fatalf("issue: %v", err)
	}
	k.ClearUncommitted()
	return k
}

// The old secret is RETIRED before the new one is issued.
//
// The order is load-bearing rather than tidy: `Retire` stamps every secret whose
// retirement is unset, which is what makes it idempotent under a second
// rotation — so issuing first would immediately retire the secret that was just
// minted, and the caller would be handed a token that was already dying.
func TestARotationRetiresTheOldSecretBeforeIssuingTheNewOne(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	existing := rotatableKey(t, now)
	h := newKeyHarness(t, existing)

	res, err := h.keys.RotateAPIKey(context.Background(), RotateAPIKeyCommand{
		OrgID:          keyTestOrg,
		ActorID:        keyTestActor,
		KeyID:          existing.ID(),
		Overlap:        2 * time.Hour,
		IdempotencyKey: "idem-rotate",
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}

	got := h.secrets.ops()
	if len(got) != 2 || got[0] != "retire" || got[1] != "issue" {
		t.Fatalf("the secret store saw %v, want [retire issue]; issuing first would stamp "+
			"the brand-new secret with the retirement deadline and hand the caller a "+
			"token that is already dying", got)
	}
	if want := h.now.Add(2 * time.Hour); !h.secrets.calls[0].at.Equal(want) {
		t.Fatalf("the old secret was retired at %s, want %s; the deadline must be the one "+
			"the event recorded", h.secrets.calls[0].at, want)
	}
	if res.Token == "" {
		t.Fatal("a rotation returned no token; the caller has nothing to reconfigure with")
	}
	if !res.PreviousRetiresAt.Equal(h.now.Add(2 * time.Hour)) {
		t.Fatalf("the caller was told the old secret dies at %s, want %s; a client that had "+
			"to compute this from a policy constant would be computing a number the "+
			"server can change", res.PreviousRetiresAt, h.now.Add(2*time.Hour))
	}
}

// An omitted overlap gets the DEFAULT, and `Immediate` is what makes zero mean
// zero.
//
// The two readings of an absent overlap have opposite consequences — the default
// keeps a leaked secret alive for a day, immediate breaks every consumer that has
// not reconfigured — so the flag has to be able to distinguish them.
func TestAnOmittedRotationOverlapIsTheDefaultAndImmediateIsNotSilentlyDefaulted(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)

	silent := newKeyHarness(t, rotatableKey(t, now))
	res, err := silent.keys.RotateAPIKey(context.Background(), RotateAPIKeyCommand{
		OrgID: keyTestOrg, ActorID: keyTestActor, KeyID: silent.loader.key.ID(),
		IdempotencyKey: "idem-a",
	})
	if err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if want := silent.now.Add(domain.DefaultRotationOverlap); !res.PreviousRetiresAt.Equal(want) {
		t.Fatalf("an omitted overlap retired the old secret at %s, want the default %s "+
			"later; a client that sends nothing must not get an immediate revocation of "+
			"the secret its fleet is still using",
			res.PreviousRetiresAt, domain.DefaultRotationOverlap)
	}

	urgent := newKeyHarness(t, rotatableKey(t, now))
	res, err = urgent.keys.RotateAPIKey(context.Background(), RotateAPIKeyCommand{
		OrgID: keyTestOrg, ActorID: keyTestActor, KeyID: urgent.loader.key.ID(),
		Immediate:      true,
		IdempotencyKey: "idem-b",
	})
	if err != nil {
		t.Fatalf("immediate rotate: %v", err)
	}
	if !res.PreviousRetiresAt.Equal(urgent.now) {
		t.Fatalf("an immediate rotation retired the old secret at %s, want %s; this is the "+
			"leak response and a grace window is exactly the wrong behaviour for it",
			res.PreviousRetiresAt, urgent.now)
	}
}

// A key belonging to another organization answers as one that does not exist.
//
// The log has no row-level security, so without this check a caller holding any
// key id — a value that travels in a token and appears on a management screen —
// could rotate and revoke a key in somebody else's tenant.
func TestAKeyInAnotherOrganizationIsNotFound(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	existing := rotatableKey(t, now)
	h := newKeyHarness(t, existing)

	_, err := h.keys.RotateAPIKey(context.Background(), RotateAPIKeyCommand{
		OrgID:          "org_01ARZ3NDEKTSV4RRFFQ69G5FAW", // a different tenant
		ActorID:        keyTestActor,
		KeyID:          existing.ID(),
		IdempotencyKey: "idem-rotate",
	})
	if err == nil {
		t.Fatal("a key was rotated from another organization; the event stream carries no " +
			"row-level security, so this check is the whole tenant boundary on the " +
			"command path")
	}
	if len(h.appender.calls) != 0 || len(h.secrets.calls) != 0 {
		t.Fatalf("the refused command wrote: %d appends, %v secret calls",
			len(h.appender.calls), h.secrets.ops())
	}
}

// ---------------------------------------------------------------------------
// Revocation
// ---------------------------------------------------------------------------

// Revocation destroys the secrets in the same request, not eventually.
//
// The event alone would leave the credential usable until the projector caught
// up — and unlike a session, nothing else bounds that window: an API key has no
// short-lived access token in front of it (identity.md §10).
func TestRevokingAKeyDestroysItsSecretsInTheSameRequest(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	existing := rotatableKey(t, now)
	h := newKeyHarness(t, existing)

	res, err := h.keys.RevokeAPIKey(context.Background(), RevokeAPIKeyCommand{
		OrgID: keyTestOrg, ActorID: keyTestActor, KeyID: existing.ID(),
		Reason: "leaked", IdempotencyKey: "idem-revoke",
	})
	if err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if !res.Changed {
		t.Fatal("the revocation reported no change on a live key")
	}
	if got := h.secrets.ops(); len(got) != 1 || got[0] != "delete" {
		t.Fatalf("the secret store saw %v, want exactly one delete; the event alone leaves "+
			"the credential usable until the projector catches up", got)
	}
	if res.SecretsDestroyed != 1 {
		t.Fatalf("the revocation reported %d secrets destroyed, want 1; the count is the "+
			"evidence that the immediate half ran", res.SecretsDestroyed)
	}
}

// Appending comes FIRST, so a failed revocation never cuts off an integration
// with nothing in the log to explain it.
func TestARevocationDestroysNoSecretUntilItIsInTheLog(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	existing := rotatableKey(t, now)
	h := newKeyHarness(t, existing)
	h.appender.err = errors.New("the store is unreachable")

	if _, err := h.keys.RevokeAPIKey(context.Background(), RevokeAPIKeyCommand{
		OrgID: keyTestOrg, ActorID: keyTestActor, KeyID: existing.ID(),
		Reason: "leaked", IdempotencyKey: "idem-revoke",
	}); err == nil {
		t.Fatal("the revocation succeeded despite the append failing")
	}
	if len(h.secrets.calls) != 0 {
		t.Fatalf("the secret store saw %v after a failed append; a credential cut off with "+
			"nothing recorded anywhere is an outage nobody can explain", h.secrets.ops())
	}
}

// Revoking an ALREADY-revoked key records nothing and still sweeps secrets.
//
// A second call is what somebody makes when they are not sure the first took,
// and answering it by doing nothing is how a half-finished revocation stays
// half-finished — a rotation racing the first revocation can insert a secret the
// first sweep never saw.
func TestASecondRevocationRecordsNothingAndStillSweepsSecrets(t *testing.T) {
	now := time.Date(2026, 8, 26, 12, 0, 0, 0, time.UTC)
	existing := rotatableKey(t, now)
	if err := existing.Revoke(keyTestActor, "leaked", now); err != nil {
		t.Fatalf("pre-revoke: %v", err)
	}
	existing.ClearUncommitted()

	h := newKeyHarness(t, existing)
	res, err := h.keys.RevokeAPIKey(context.Background(), RevokeAPIKeyCommand{
		OrgID: keyTestOrg, ActorID: keyTestActor, KeyID: existing.ID(),
		Reason: "leaked", IdempotencyKey: "idem-revoke-2",
	})
	if err != nil {
		t.Fatalf("a second revocation failed: %v", err)
	}
	if res.Changed {
		t.Fatal("a second revocation reported a change; nothing was appended")
	}
	if len(h.appender.calls) != 0 {
		t.Fatalf("a second revocation appended %d times; the aggregate records nothing",
			len(h.appender.calls))
	}
	if got := h.secrets.ops(); len(got) != 1 || got[0] != "delete" {
		t.Fatalf("the secret store saw %v, want a delete; the sweep must run on a repeat "+
			"call, or a secret a racing rotation inserted survives the revocation", got)
	}
}

// ---------------------------------------------------------------------------
// Wiring
// ---------------------------------------------------------------------------

// Every dependency is required, and none has a stand-in.
//
// The entropy source is the one that matters most: a defaulted one produces
// software that works and credentials that are guessable, which no test of
// behaviour would catch.
func TestAPIKeysRefuseAPartialWiring(t *testing.T) {
	full := func() APIKeysDeps {
		return APIKeysDeps{
			Clock:       clock.NewFixed(time.Now()),
			Entropy:     &fixedEntropy{},
			Environment: keyTestEnv,
			Accounts:    svcAccountLoader{},
			Keys:        &apiKeyLoader{},
			Appender:    &fakeAppender{},
			Schemas:     eventsourcing.NewUpcasterRegistry(),
			Secrets:     &fakeKeySecrets{},
			Directory:   &fakeServiceAccounts{},
		}
	}
	cases := map[string]func(*APIKeysDeps){
		"no clock":       func(d *APIKeysDeps) { d.Clock = nil },
		"no entropy":     func(d *APIKeysDeps) { d.Entropy = nil },
		"no environment": func(d *APIKeysDeps) { d.Environment = "" },
		"a bad environment": func(d *APIKeysDeps) {
			// An underscore adds a segment and makes every token this deployment
			// mints unparseable — discovered when the first key fails to
			// authenticate, which is far too late.
			d.Environment = "pre_prod"
		},
		"no account loader": func(d *APIKeysDeps) { d.Accounts = nil },
		"no key loader":     func(d *APIKeysDeps) { d.Keys = nil },
		"no appender":       func(d *APIKeysDeps) { d.Appender = nil },
		"no schemas":        func(d *APIKeysDeps) { d.Schemas = nil },
		"no secret store":   func(d *APIKeysDeps) { d.Secrets = nil },
		"no directory":      func(d *APIKeysDeps) { d.Directory = nil },
	}
	for name, break_ := range cases {
		t.Run(name, func(t *testing.T) {
			deps := full()
			break_(&deps)
			if _, err := NewAPIKeys(deps); err == nil {
				t.Fatalf("%s was accepted; a partial wiring serves the first request with a "+
					"panic, after the composition root has reported a healthy start", name)
			}
		})
	}
	if _, err := NewAPIKeys(full()); err != nil {
		t.Fatalf("a complete wiring was refused: %v; the negative cases above prove nothing "+
			"if the constructor refuses everything", err)
	}
}
