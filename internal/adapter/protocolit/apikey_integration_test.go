//go:build integration

package protocolit_test

import (
	"context"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	organizationv1 "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
)

// API keys, driven through the RUNNING SERVER.
//
// # Why this file exists at all
//
// The key path has unit tests, domain tests and a policy loader that refuses an
// unannotated method. All of it passed while nothing had ever minted a key and
// presented it to a server.
//
// That gap has a track record in this repository. Passkeys answered `internal`
// for every caller because the adapter refused an empty credential list, and no
// unit test noticed because none of them went through the adapter. Federation,
// the operator plane and the customer directory each had a defect that survived
// a green suite and died the first time somebody ran them.
//
// A credential is the worst thing to be wrong about in that way: every layer can
// be individually correct while the token the server actually issues is not the
// token the authenticator actually accepts.
//
// So these tests mint a real key against a real server, present it over the
// wire, and assert what it can and cannot reach.

// TestAnApiKeyAuthenticatesAgainstTheRunningServer is the whole point.
//
// Mint, present, be recognised. If the digest the issuer stores and the digest
// the authenticator computes ever disagree — a different purpose string, a
// dropped length prefix, a base64 variant — everything else in this file still
// passes and this does not.
func TestAnApiKeyAuthenticatesAgainstTheRunningServer(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-auth")
	keyID, token := personalKey(t, ctx, admin, "organization:read")

	if !strings.HasPrefix(keyID, "key_") {
		t.Errorf("the key id %q is not a prefixed ULID (ADR-030)", keyID)
	}
	if token == "" {
		t.Fatal("the mint returned no token; the plaintext is returned exactly once and " +
			"a caller given none holds a credential nothing can present")
	}
	if strings.Contains(token, keyID) == false {
		// The public segment is what lets a leaked credential be attributed and
		// revoked without anybody presenting the secret. A token that did not
		// carry it would make a leak un-attributable.
		t.Errorf("the token does not carry its key id; a leaked credential could not be "+
			"attributed without presenting the secret (token prefix %q)", first(token, 12))
	}

	// THE ASSERTION. A read the key's scope covers, over the wire, as the key.
	res, err := h.identity.ListApiKeys(ctx,
		authed(&identityv1.ListApiKeysRequest{}, token))
	if err != nil {
		t.Fatalf("a freshly minted key could not authenticate: %v\n%s", err, h.serverLogs())
	}
	found := false
	for _, k := range res.Msg.GetApiKeys() {
		if k.GetKeyId() == keyID {
			found = true
		}
	}
	if !found {
		t.Errorf("the key authenticated and does not appear in its own organization's "+
			"list; the read is scoped to the wrong tenant (%d keys returned)",
			len(res.Msg.GetApiKeys()))
	}
}

// TestAnApiKeyCannotReachAPersonsOwnAccount is the rule that stops a key being
// a general-purpose impersonation of whoever minted it.
//
// Every self-scoped method is one of a person's account screens: their password,
// their sessions, their second factors, their deactivation. A key that reached
// one would let a token minted for "read the workspace list" change the password
// of the person who minted it.
//
// PermissionDenied, not Unauthenticated: the credential is perfectly valid and
// we know exactly who it is. What is wrong is that the endpoint acts on an
// account the caller does not have.
func TestAnApiKeyCannotReachAPersonsOwnAccount(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-self")
	_, token := personalKey(t, ctx, admin, "organization:read", "user:read")

	_, err := h.identity.GetUser(ctx, authed(&identityv1.GetUserRequest{}, token))
	if err == nil {
		t.Fatal("an API key read a person's own account. A token minted for a machine " +
			"integration can now see — and by the same route change — the account of " +
			"whoever minted it.")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodePermissionDenied {
		t.Errorf("want permission_denied, got %v: %v", got, err)
	}
}

// TestAnApiKeyCannotMintAnotherKey is the containment property.
//
// Key management requires AAL2 and a machine can never present a second factor,
// so a leaked key cannot make itself durable — it cannot mint a successor, and
// it cannot revoke the one that would be used to stop it.
//
// Without this a single leaked key is unbounded: whoever holds it mints a second
// one nobody is watching for, and revoking the first achieves nothing.
func TestAnApiKeyCannotMintAnotherKey(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-mint")
	keyID, token := personalKey(t, ctx, admin, "organization:write")

	t.Run("it cannot create", func(t *testing.T) {
		_, err := h.identity.CreateApiKey(ctx,
			authedIdem(&identityv1.CreateApiKeyRequest{
				Scopes: []string{"organization:read"},
			}, token))
		if err == nil {
			t.Fatal("an API key minted another API key. A leaked credential can now make " +
				"itself durable, and revoking the leaked one achieves nothing.")
		}
	})

	t.Run("it cannot revoke", func(t *testing.T) {
		_, err := h.identity.RevokeApiKey(ctx,
			authedIdem(&identityv1.RevokeApiKeyRequest{
				KeyId: keyID, Reason: "self_revocation_attempt",
			}, token))
		if err == nil {
			t.Fatal("an API key revoked a key. Whoever holds a leaked one can revoke the " +
				"credential an operator would use to investigate.")
		}
	})
}

// TestRevokingAKeyKillsItImmediately.
//
// "Immediately" means on the NEXT REQUEST, not when a projection catches up.
// Revocation deletes the secret rows as well as appending the event, so a
// revoked key has nothing left to resolve — the authenticator does not consult a
// flag that a lagging projector has not yet set.
//
// A key that kept working for the seconds after a revocation is a key that kept
// working during exactly the window somebody was trying to close.
func TestRevokingAKeyKillsItImmediately(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-revoke")
	keyID, token := personalKey(t, ctx, admin, "organization:read")

	if _, err := h.identity.ListApiKeys(ctx,
		authed(&identityv1.ListApiKeysRequest{}, token)); err != nil {
		t.Fatalf("the key did not work before revocation: %v\n%s", err, h.serverLogs())
	}

	if _, err := h.identity.RevokeApiKey(ctx,
		authedIdem(&identityv1.RevokeApiKeyRequest{
			KeyId: keyID, Reason: "leaked_in_build_log",
		}, admin.bearer)); err != nil {
		t.Fatalf("RevokeApiKey: %v\n%s", err, h.serverLogs())
	}

	// NO WAIT. The point is that there is nothing to wait for.
	_, err := h.identity.ListApiKeys(ctx, authed(&identityv1.ListApiKeysRequest{}, token))
	if err == nil {
		t.Fatal("a revoked key still authenticated on the very next request. Revocation " +
			"that waits for a projection leaves the credential live during exactly the " +
			"window somebody is trying to close.")
	}
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeUnauthenticated {
		t.Errorf("want unauthenticated for a revoked credential, got %v: %v", got, err)
	}
}

// TestRotationLeavesNoGapAndNoImmortalSecret is the property rotation exists
// for, and it has two halves that fail in opposite directions.
//
// A rotation that killed the old secret at the instant the new one was issued
// would break every caller mid-deploy. One that left it alive indefinitely would
// mean a compromised secret survives its own replacement, which is the reason
// somebody rotates in the first place.
func TestRotationLeavesNoGapAndNoImmortalSecret(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-rotate")
	keyID, old := personalKey(t, ctx, admin, "organization:read")

	res, err := h.identity.RotateApiKey(ctx,
		authedIdem(&identityv1.RotateApiKeyRequest{KeyId: keyID}, admin.bearer))
	if err != nil {
		t.Fatalf("RotateApiKey: %v\n%s", err, h.serverLogs())
	}
	fresh := res.Msg.GetToken()
	if fresh == "" || fresh == old {
		t.Fatal("rotation did not produce a NEW secret; the old one is the new one")
	}
	if res.Msg.GetPreviousRetiresAt() == nil {
		t.Fatal("rotation recorded no deadline for the superseded secret, so the old one " +
			"outlives its replacement — which is the thing rotation exists to prevent")
	}

	// NO GAP: the old secret still works inside the overlap.
	if _, err := h.identity.ListApiKeys(ctx,
		authed(&identityv1.ListApiKeysRequest{}, old)); err != nil {
		t.Errorf("the superseded secret stopped working immediately, so every caller "+
			"still holding it breaks mid-deploy: %v", err)
	}

	// And the new one works too, which is what makes the overlap an overlap
	// rather than a delay.
	if _, err := h.identity.ListApiKeys(ctx,
		authed(&identityv1.ListApiKeysRequest{}, fresh)); err != nil {
		t.Errorf("the fresh secret does not work: %v\n%s", err, h.serverLogs())
	}
}

// TestAnImmediateRotationClosesTheOverlap is the leak response.
//
// The overlap is a kindness to a deploy. When a secret is already in somebody
// else's hands the kindness is the problem, so `immediate` collapses it to zero
// — and this asserts the flag is honoured rather than accepted and ignored.
func TestAnImmediateRotationClosesTheOverlap(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-rotate-now")
	keyID, old := personalKey(t, ctx, admin, "organization:read")

	if _, err := h.identity.RotateApiKey(ctx,
		authedIdem(&identityv1.RotateApiKeyRequest{
			KeyId: keyID, Immediate: true,
		}, admin.bearer)); err != nil {
		t.Fatalf("RotateApiKey(immediate): %v\n%s", err, h.serverLogs())
	}

	_, err := h.identity.ListApiKeys(ctx, authed(&identityv1.ListApiKeysRequest{}, old))
	if err == nil {
		t.Fatal("an immediate rotation left the old secret live. The flag exists for the " +
			"case where the secret is already in somebody else's hands, and accepting " +
			"it while ignoring it is worse than not offering it.")
	}
}

// --------------------------------------------------------------------------
// Fixtures
// --------------------------------------------------------------------------

// adminWithOrg returns an AAL2 account that owns an organization.
//
// Both are required and for different reasons: key management declares
// `admin` on `organization`, so there must be an organization to be admin OF,
// and it declares min_aal 2, so the session must have presented a second factor.
func adminWithOrg(
	t *testing.T, ctx context.Context, tag string,
) (*accountFixture, string) {
	t.Helper()

	account := h.disposableAccount(t, tag)
	res, err := h.organization.CreateOrganization(ctx,
		authed(&organizationv1.CreateOrganizationRequest{
			Name: "Acme " + tag, Slug: h.freshSlug(),
		}, account.bearer))
	if err != nil {
		t.Fatalf("creating the organization: %v\n%s", err, h.serverLogs())
	}
	orgID := res.Msg.GetOrgId()

	// The same ceremony member_test performs, and every step of it is a gate.
	//
	// This package deliberately does not run cmd/worker, so the two things the
	// worker would do have to be done here: provisioning gives the organization a
	// status gate 3 will accept, and the access reactor writes the owner tuple
	// gate 2 answers `admin` from. Gate 1 needs the membership row, which the
	// projectors in this harness write — but not instantly, so it is awaited.
	//
	// Skipping any of them fails as NOT_FOUND from gate 1, which reads like a
	// missing organization rather than a projection that has not caught up.
	h.provision(t, ctx, orgID, account.subjectID)
	h.grantOwner(t, ctx, orgID, account.subjectID)
	h.awaitOrgStatus(t, ctx, orgID, "trialing")
	h.awaitOrgMember(t, ctx, orgID, account.subjectID)

	return account, orgID
}

func serviceAccount(t *testing.T, ctx context.Context, admin *accountFixture, name string) string {
	t.Helper()
	res, err := h.identity.CreateServiceAccount(ctx,
		authedIdem(&identityv1.CreateServiceAccountRequest{Name: name}, admin.bearer))
	if err != nil {
		t.Fatalf("CreateServiceAccount: %v\n%s", err, h.serverLogs())
	}
	id := res.Msg.GetServiceAccountId()
	if !strings.HasPrefix(id, "svc_") {
		t.Errorf("the service account id %q is not a prefixed ULID; a service account is a "+
			"DISTINCT principal kind and its id space is how that is visible", id)
	}
	return id
}

func apiKey(
	t *testing.T, ctx context.Context, admin *accountFixture, svc string, scopes ...string,
) (keyID, token string) {
	t.Helper()
	res, err := h.identity.CreateApiKey(ctx,
		authedIdem(&identityv1.CreateApiKeyRequest{
			ServiceAccountId: svc, Scopes: scopes,
		}, admin.bearer))
	if err != nil {
		t.Fatalf("CreateApiKey: %v\n%s", err, h.serverLogs())
	}
	return res.Msg.GetKeyId(), res.Msg.GetToken()
}

// authedIdem is `authed` with an Idempotency-Key, which every mutating method
// on this plane requires (CONVENTIONS §6).
func authedIdem[T any](msg *T, bearer string) *connectrpc.Request[T] {
	req := authed(msg, bearer)
	req.Header().Set("Idempotency-Key", newIdempotencyKey())
	return req
}

func first(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}

// personalKey mints a PERSONAL access token — a key owned by the caller.
//
// # Why the tests above use this and not a service account
//
// A key's authority is its owner's, narrowed by its scopes (access.md §5). The
// owner of a personal token is a person, and a person has tuples in the graph,
// so the whole path — mint, present, authenticate, resolve the tenant, ask
// OpenFGA — runs end to end.
//
// A SERVICE ACCOUNT has no tuples, because nothing writes any: the
// authorization model declares no `service_account` type and there is no RPC
// that grants one anything. So a service-account key authenticates perfectly
// and is refused by gate 2 for every method in the system. Using one here would
// make each test above pass or fail on that refusal rather than on the property
// it is named for — TestAnImmediateRotationClosesTheOverlap in particular
// passed while asserting nothing, because the revoked and un-revoked secret
// were refused identically.
//
// TestAServiceAccountKeyAuthenticatesAndCanReachNothing below states that gap
// on its own, so it is asserted once rather than smeared across six tests.
func personalKey(
	t *testing.T, ctx context.Context, admin *accountFixture, scopes ...string,
) (keyID, token string) {
	t.Helper()
	res, err := h.identity.CreateApiKey(ctx,
		authedIdem(&identityv1.CreateApiKeyRequest{Scopes: scopes}, admin.bearer))
	if err != nil {
		t.Fatalf("CreateApiKey: %v\n%s", err, h.serverLogs())
	}
	return res.Msg.GetKeyId(), res.Msg.GetToken()
}

// TestAServiceAccountKeyAuthenticatesAndCanReachNothing records the state of
// the second half of identity.md §10, exactly.
//
// # What works
//
// A service account can be created, a key can be minted for it, and that key
// authenticates: the digest resolves, the principal is built, the organization
// binding is read off the secret row, and gate 1 admits it without a membership
// check — correctly, because a service account is owned by an organization
// rather than a member of it.
//
// # What does not
//
// Gate 2 asks OpenFGA about the key's OWNER, and the model declares no
// `service_account` type, so no tuple naming one can exist and no RPC exists to
// write one. Every method is therefore refused, as NOT_FOUND.
//
// That is a missing feature and not a defect in what is built — "grant a
// service account a role" was never implemented — but it is the difference
// between a shipped integration credential and one that can do nothing, so it
// is asserted rather than left to be discovered by whoever first tries to use
// one.
//
// When grants land, THIS TEST FAILS, and its replacement is the positive case.
func TestAServiceAccountKeyAuthenticatesAndCanReachNothing(t *testing.T) {
	ctx, cancel := context.WithTimeout(t.Context(), 90*time.Second)
	defer cancel()

	admin, _ := adminWithOrg(t, ctx, "apikey-svc")
	svc := serviceAccount(t, ctx, admin, "ci_deploy")
	_, token := apiKey(t, ctx, admin, svc, "organization:read")

	_, err := h.identity.ListApiKeys(ctx, authed(&identityv1.ListApiKeysRequest{}, token))
	if err == nil {
		t.Fatal("a service-account key is now authorized. That is the feature landing — " +
			"replace this test with the positive case and delete the note in " +
			"docs/WORKLIST.md.")
	}
	// NOT_FOUND and not UNAUTHENTICATED. The distinction is the whole point: the
	// credential is valid and was recognised, and what is missing is a grant. An
	// UNAUTHENTICATED here would mean the key never resolved at all, which is a
	// different and much worse problem wearing the same symptom.
	if got := connectrpc.CodeOf(err); got != connectrpc.CodeNotFound {
		t.Errorf("want not_found — a recognised credential with no grant — got %v: %v\n\n"+
			"unauthenticated here would mean the key did not resolve, which is a "+
			"credential bug rather than a missing grant.", got, err)
	}
}
