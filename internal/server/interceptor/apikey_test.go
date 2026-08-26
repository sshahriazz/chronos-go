package interceptor

import (
	"context"
	"errors"
	"strings"
	"testing"

	optionsv1 "github.com/chronos/chronos-go/gen/proto/chronos/options/v1"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/server/policy"
)

// keyPrincipal is what the API key authenticator produces: the KEY as the
// subject, its owner as the acting principal, AAL1 permanently, a bound
// organization and a scope list.
func keyPrincipal(scopes ...string) Principal {
	return Principal{
		Subject: authz.Principal{
			Kind:           authz.KindAPIKey,
			ID:             "key_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			OnBehalfOf:     "svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			OnBehalfOfKind: authz.KindServiceAccount,
		},
		AAL:      optionsv1.AssuranceLevel_ASSURANCE_LEVEL_1,
		BoundOrg: "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		Scopes:   scopes,
	}
}

func sessionPrincipal() Principal {
	return Principal{
		Subject: authz.Principal{Kind: authz.KindUser, ID: "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		AAL:     optionsv1.AssuranceLevel_ASSURANCE_LEVEL_2,
	}
}

// A machine credential can never reach a person's own account screens.
//
// The self-scoped methods are a person's password, sessions, second factors and
// deactivation. A key acting on one would be acting on the account of whoever
// owns the key — so a personal access token minted to read a workspace list
// could change that person's password, or sign them out of every device.
//
// `identity/api.callerSubject` already refuses a non-user principal and is a
// real backstop, but it lives in ONE module: a self-scoped method added anywhere
// else would be unguarded until somebody remembered. This is the rule at the
// gate, where no handler can be forgotten.
func TestAMachineCredentialCannotReachASelfScopedMethod(t *testing.T) {
	selfScoped := policy.Policy{
		Method:       "/chronos.identity.v1.IdentityService/DeactivateAccount",
		Relation:     policy.RelationSelf,
		ResourceType: policy.ResourceTypeUser,
		Operation:    optionsv1.OperationClass_OPERATION_CLASS_WRITE,
	}
	if !selfScoped.SelfScoped() {
		t.Fatal("the fixture is not self-scoped, so this test asserts nothing")
	}

	// A key holding EVERY scope, so the refusal cannot be attributed to a
	// missing one.
	wide := keyPrincipal("user:write", "user:read", "organization:write")
	if err := machineCredentialCheck(selfScoped, wide); err == nil {
		t.Fatal("a machine credential reached a self-scoped method; it would act on the " +
			"account of whoever owns the key, so a read-only integration token could " +
			"change their password")
	}

	if err := machineCredentialCheck(selfScoped, sessionPrincipal()); err != nil {
		t.Fatalf("a session was refused its own account screen: %v; the rule must apply to "+
			"machine credentials only", err)
	}
}

// A key reaches only what its scopes cover, and the requirement is DERIVED from
// the method's own declaration.
//
// Deriving it rather than annotating it separately is what stops a new RPC being
// added with a forgotten scope annotation — the failure of forgetting would be a
// method every key in the system can reach.
func TestAMachineCredentialIsHeldToItsScopes(t *testing.T) {
	read := policy.Policy{
		Method:       "/chronos.workspace.v1.WorkspaceService/ListWorkspaces",
		Relation:     "member",
		ResourceType: "workspace",
		Operation:    optionsv1.OperationClass_OPERATION_CLASS_READ,
	}
	write := policy.Policy{
		Method:       "/chronos.workspace.v1.WorkspaceService/CreateWorkspace",
		Relation:     "admin",
		ResourceType: "workspace",
		Operation:    optionsv1.OperationClass_OPERATION_CLASS_GROW,
	}

	cases := []struct {
		name    string
		policy  policy.Policy
		scopes  []string
		allowed bool
	}{
		{"the exact read scope", read, []string{"workspace:read"}, true},
		{"write covers read", read, []string{"workspace:write"}, true},
		{"read does not cover write", write, []string{"workspace:read"}, false},
		{"another resource type", read, []string{"organization:read"}, false},
		{"no scopes at all", read, nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := machineCredentialCheck(tc.policy, keyPrincipal(tc.scopes...))
			if tc.allowed && err != nil {
				t.Fatalf("a key holding %v was refused %s: %v",
					tc.scopes, tc.policy.Method, err)
			}
			if !tc.allowed && err == nil {
				t.Fatalf("a key holding %v reached %s; access.md §4 makes a key's permission "+
					"the intersection of its scopes and its owner's access, and this half "+
					"of the intersection is the only one that can narrow below the owner",
					tc.scopes, tc.policy.Method)
			}
		})
	}
}

// A session is never scope-checked, because there is nothing to narrow.
//
// The asymmetry is deliberate: a session is a person acting as themselves, so
// the graph is the whole answer. A Principal with no scopes and a user kind must
// pass every method the graph allows.
func TestASessionIsNeverScopeChecked(t *testing.T) {
	p := policy.Policy{
		Method:       "/chronos.workspace.v1.WorkspaceService/CreateWorkspace",
		Relation:     "admin",
		ResourceType: "workspace",
		Operation:    optionsv1.OperationClass_OPERATION_CLASS_GROW,
	}
	if err := machineCredentialCheck(p, sessionPrincipal()); err != nil {
		t.Fatalf("a session carrying no scopes was refused: %v; scopes narrow a CREDENTIAL "+
			"below its owner, and a person is their own owner", err)
	}
}

// A method whose resource type is empty yields an empty required scope, and an
// empty requirement DENIES.
//
// It is the value a method the gate cannot characterise produces, and admitting
// it would open exactly the endpoints nobody has classified.
func TestAnUncharacterisedMethodAdmitsNoMachineCredential(t *testing.T) {
	unclassified := policy.Policy{
		Method:    "/chronos.example.v1.Service/Something",
		Operation: optionsv1.OperationClass_OPERATION_CLASS_READ,
	}
	if got := scopeFor(unclassified); got != "" {
		t.Fatalf("scopeFor produced %q for a method with no resource type, want the empty "+
			"string", got)
	}
	wide := keyPrincipal("workspace:write", "organization:write", "billing:write")
	if err := machineCredentialCheck(unclassified, wide); err == nil {
		t.Fatal("a key reached a method whose required scope could not be derived; an " +
			"unclassified endpoint must be closed to every credential, not open to all " +
			"of them")
	}
}

// The zero Principal is treated as a machine.
//
// Its kind is the empty string rather than KindUser, so it faces the stricter
// rules — which is the safe direction for a Principal a test double or a
// half-built authenticator produced.
func TestTheZeroPrincipalFacesTheStricterRules(t *testing.T) {
	if !(Principal{}).Machine() {
		t.Fatal("the zero Principal reports as human; a half-built authenticator would then " +
			"produce a caller exempt from the scope check and admitted to every personal " +
			"account screen")
	}
}

// Gate 2 asks about the OWNER, never about the key.
//
// Nothing in the OpenFGA model holds a tuple for `api_key:key_…` and nothing
// should: a key's authority is defined as its owner's narrowed by its scopes,
// not as a second set of grants that could drift from the owner's. A check
// naming the key would deny everything — fail closed, and silently wrong.
func TestTheAuthorizationCheckNamesTheOwnerAndNotTheKey(t *testing.T) {
	p := keyPrincipal("workspace:read")

	acting := p.Subject.Acting()
	if acting.Kind != authz.KindServiceAccount {
		t.Fatalf("the acting principal is a %s, want a service account; the owner's KIND "+
			"decides which object type the tuple names, and guessing it is how a service "+
			"account gets checked as a person", acting.Kind)
	}
	if acting.ID != p.Subject.OnBehalfOf {
		t.Fatalf("the acting principal is %q, want the owner %q", acting.ID, p.Subject.OnBehalfOf)
	}
	if acting.String() == p.Subject.String() {
		t.Fatal("the acting principal is the key itself; no tuple names a key, so the " +
			"check would deny everything for a reason nothing in the log explains")
	}
}

// A session's acting principal is unchanged.
//
// Every existing caller sets no OnBehalfOf, so Acting() must be the identity
// function for them — otherwise this change alters authorization for every human
// request in the system.
func TestASessionsActingPrincipalIsItself(t *testing.T) {
	s := sessionPrincipal()
	if got := s.Subject.Acting(); got != s.Subject {
		t.Fatalf("a session's acting principal is %v, want %v; delegation must be inert for "+
			"a principal that delegates nothing", got, s.Subject)
	}
}

// A delegation with no owner KIND is refused rather than guessed.
//
// The guess that would be reached for is `user`, and a service account silently
// checked as a user is the one substitution that could pick up a real person's
// grants.
func TestADelegationWithNoOwnerKindIsRefused(t *testing.T) {
	q := authz.Query{
		Principal: authz.Principal{
			Kind:       authz.KindAPIKey,
			ID:         "key_01ARZ3NDEKTSV4RRFFQ69G5FAV",
			OnBehalfOf: "svc_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		},
		Relation: "admin",
		Resource: authz.ResourceRef{Type: "organization", ID: "org_1"},
	}
	if err := q.Validate(); err == nil {
		t.Fatal("a principal delegating to an untyped owner validated; the object type " +
			"would have to be guessed, and the guess picks up a person's grants")
	}
}

// ---------------------------------------------------------------------------
// Routing
// ---------------------------------------------------------------------------

type stubAuthenticator struct {
	name   string
	called int
}

func (s *stubAuthenticator) Authenticate(context.Context, Header) (Principal, error) {
	s.called++
	return Principal{Subject: authz.Principal{Kind: authz.KindUser, ID: s.name}}, nil
}

type stubHeader map[string]string

func (h stubHeader) Get(k string) string { return h[k] }

// The bearer is routed on the TOKEN's own shape, never on a header.
//
// A separate header would let a caller choose which resolver runs — and a caller
// who can choose the resolver can choose which deadline and revocation rules
// apply to them.
func TestTheBearerIsRoutedOnTheTokensOwnShape(t *testing.T) {
	sessions := &stubAuthenticator{name: "sessions"}
	keys := &stubAuthenticator{name: "keys"}
	b, err := NewBearerAuthenticator(sessions, keys)
	if err != nil {
		t.Fatalf("NewBearerAuthenticator: %v", err)
	}

	cases := map[string]struct {
		token string
		want  *stubAuthenticator
	}{
		"an API key": {
			token: "chr_test_key_01ARZ3NDEKTSV4RRFFQ69G5FAV_" + strings.Repeat("A", 43),
			want:  keys,
		},
		"a session token": {
			token: "6vBpsPRE7CQnO0GEbLZ6FRSGfLPQ0aBqZ2LQhVjw6oA",
			want:  sessions,
		},
		"an empty header falls to the session resolver, which refuses it": {
			token: "",
			want:  sessions,
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			sessions.called, keys.called = 0, 0
			header := stubHeader{}
			if tc.token != "" {
				header[AuthorizationHeader] = "Bearer " + tc.token
			}
			if _, err := b.Authenticate(context.Background(), header); err != nil {
				t.Fatalf("authenticate: %v", err)
			}
			if tc.want.called != 1 {
				t.Fatalf("%s resolver was called %d times, want 1; routing on the token's "+
					"own prefix is what stops a caller choosing which rules apply to them",
					tc.want.name, tc.want.called)
			}
		})
	}
}

// Both resolvers are required, because neither absence is visible from the
// other's tests.
func TestTheBearerAuthenticatorRefusesAPartialComposition(t *testing.T) {
	if _, err := NewBearerAuthenticator(nil, &stubAuthenticator{}); err == nil {
		t.Fatal("a composition with no session resolver was accepted; every human request " +
			"would be refused")
	}
	if _, err := NewBearerAuthenticator(&stubAuthenticator{}, nil); err == nil {
		t.Fatal("a composition with no API key resolver was accepted; every machine " +
			"request would be refused, and no session test would notice")
	}
}

// An API key authenticator with no transaction is refused at construction.
func TestTheAPIKeyAuthenticatorNeedsATransaction(t *testing.T) {
	if _, err := NewAPIKeyAuthenticator(APIKeyAuthenticatorDeps{}); err == nil {
		t.Fatal("an API key authenticator was built with no transaction; it could resolve " +
			"nothing and would refuse every machine request")
	}
}

// An owner whose id does not parse under the kind it claims is refused at READ
// time, not only at write time.
//
// Two CHECK constraints already refuse the pairing when a row is written. This
// refuses it when a row is read, so a row written by anything that is not this
// application cannot get past the authenticator either — and it is
// ErrAuthenticationUnavailable rather than "bad credential", because answering
// "your key is wrong" to a tampered row hides the tampering.
func TestAnOwnerWhoseKindAndIDDisagreeIsRefusedOnRead(t *testing.T) {
	cases := map[string]struct{ kind, id string }{
		"a user kind with a service id": {"user", "svc_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		"a service kind with a user id": {"service_account", "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		"a kind this build cannot read": {"robot", "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"},
		"an id that is not an id":       {"user", "not-an-id"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := ownerPrincipalKind(tc.kind, tc.id); err == nil {
				t.Fatalf("%s was accepted; a flipped kind with a real id is the "+
					"confused-deputy shape the tagged pair exists to make "+
					"unrepresentable", name)
			}
		})
	}

	kind, err := ownerPrincipalKind("service_account", "svc_01ARZ3NDEKTSV4RRFFQ69G5FAV")
	if err != nil {
		t.Fatalf("a well-formed owner was refused: %v; the negative cases above prove "+
			"nothing if everything is refused", err)
	}
	if kind != authz.KindServiceAccount {
		t.Fatalf("a service account owner mapped to %q", kind)
	}
}

// The undifferentiated refusal is preserved: an unresolvable key is errNoSession
// and an unreadable ROW is ErrAuthenticationUnavailable.
//
// The distinction is the one SessionAuthenticator draws and it matters at least
// as much here: a database blip reported as a bad credential makes every
// integration in the fleet report an authentication failure to its own
// operators, who then go looking for a revoked key that was never revoked.
func TestTheTwoFailuresStayDistinct(t *testing.T) {
	if errors.Is(errNoSession, ErrAuthenticationUnavailable) {
		t.Fatal("\"no such credential\" and \"could not tell\" are the same error; an " +
			"outage would sign every integration out")
	}
}
