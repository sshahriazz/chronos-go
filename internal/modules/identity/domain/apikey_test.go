package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

const testOrg = "org_01ARZ3NDEKTSV4RRFFQ69G5FAV"

func liveKey(t *testing.T, scopes ...string) (*domain.APIKey, ids.APIKeyID) {
	t.Helper()
	if len(scopes) == 0 {
		scopes = []string{"organization:read"}
	}
	id := newID[ids.APIKey](t)
	owner := domain.ServiceAccountOwner(newID[ids.ServiceAccount](t))
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	if err := k.Issue(
		id, testOrg, owner, scopes, at.Add(domain.DefaultAPIKeyLifetime), "subj_actor", at,
	); err != nil {
		t.Fatalf("issue: %v", err)
	}
	k.ClearUncommitted()
	return k, id
}

// A key with no deadline is refused, because identity.md §10 makes expiry
// mandatory rather than optional.
//
// The assertion is on the ZERO time specifically, and not only on a past one.
// Zero is what an unset field looks like, so it is the value a client that
// simply omitted the lifetime would produce — and if it were accepted the key
// would be dead on arrival instead of permanent, which is the opposite failure
// and just as wrong.
func TestAnAPIKeyMustExpire(t *testing.T) {
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	err := k.Issue(newID[ids.APIKey](t), testOrg,
		domain.UserOwner(newID[ids.Subject](t).String()),
		[]string{"organization:read"}, time.Time{}, "subj_actor", at)
	if err == nil {
		t.Fatal("a key with no deadline was issued; identity.md §10 makes expiry mandatory, " +
			"and a credential with none outlives the integration it was minted for")
	}
	if len(k.Uncommitted()) != 0 {
		t.Fatalf("a refused issue recorded %d events; a rejected command must record nothing",
			len(k.Uncommitted()))
	}
}

// The lifetime ceiling is REFUSED and not clamped.
//
// Clamping would hand the caller a credential that dies at a date they were
// never told, which on a machine credential means an integration that stops one
// day for no reason anybody can trace back to this call.
func TestAnAPIKeyLifetimeCeilingIsRefusedNotClamped(t *testing.T) {
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	tooLong := at.Add(domain.MaxAPIKeyLifetime + time.Hour)
	err := k.Issue(newID[ids.APIKey](t), testOrg,
		domain.UserOwner(newID[ids.Subject](t).String()),
		[]string{"organization:read"}, tooLong, "subj_actor", at)
	if err == nil {
		t.Fatalf("a lifetime of %s was accepted; the ceiling is %s and exceeding it must be "+
			"refused rather than silently shortened",
			tooLong.Sub(at), domain.MaxAPIKeyLifetime)
	}
}

// An organization is required, and it is the whole cross-tenant control.
//
// Without the binding a key inherits every organization its owner belongs to, so
// a token leaked from one customer's CI reaches another customer's data
// (identity.md §10, review D2). The test asserts the REFUSAL rather than a
// default, because the plausible-looking alternative — defaulting to the
// caller's org — is what makes the field forgettable.
func TestAnAPIKeyIsBoundToOneOrganization(t *testing.T) {
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	err := k.Issue(newID[ids.APIKey](t), "",
		domain.UserOwner(newID[ids.Subject](t).String()),
		[]string{"organization:read"}, at.Add(time.Hour), "subj_actor", at)
	if err == nil {
		t.Fatal("a key with no organization was issued; the binding is what stops a token " +
			"leaked from one customer's CI reaching another customer's data")
	}
}

// Nothing changes the organization after issue.
//
// There is no command that could, and this is the test that says so: it drives
// the only two mutations the aggregate has and asserts the binding survives both.
// If a rebinding command is ever added, this fails and the reviewer has to argue
// with review D2 rather than with a comment.
func TestNothingRebindsAnAPIKeysOrganization(t *testing.T) {
	k, _ := liveKey(t)

	if err := k.Rotate(time.Hour, at.Add(time.Hour*24), "subj_actor", at); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := k.OrgID(); got != testOrg {
		t.Fatalf("a rotation moved the key to organization %q, want %q; rotation replaces a "+
			"secret and must not move a tenant boundary", got, testOrg)
	}
	if err := k.Revoke("subj_actor", "leaked", at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	if got := k.OrgID(); got != testOrg {
		t.Fatalf("a revocation moved the key to organization %q, want %q", got, testOrg)
	}
}

// The owner is a tagged pair, and the id must parse under the kind it claims.
//
// The mismatched cases are the point. A kind flipped on its own would name a
// principal that does not exist — which fails closed — but the direction that
// matters is a `subj_` id claimed as a service account, which on a system
// without this check could pick up a real person's grants.
func TestAnAPIKeyOwnerKindAndIDMustAgree(t *testing.T) {
	subject := newID[ids.Subject](t).String()
	account := newID[ids.ServiceAccount](t).String()

	cases := map[string]domain.APIKeyOwner{
		"no owner at all":                  {},
		"a kind with no id":                {Kind: contract.OwnerUser},
		"an id with no kind":               {ID: subject},
		"a user kind with a service id":    {Kind: contract.OwnerUser, ID: account},
		"a service kind with a user id":    {Kind: contract.OwnerServiceAccount, ID: subject},
		"a kind this system does not know": {Kind: "robot", ID: subject},
	}
	for name, owner := range cases {
		t.Run(name, func(t *testing.T) {
			k := eventsourcing.NewAggregate(domain.NewAPIKey)
			err := k.Issue(newID[ids.APIKey](t), testOrg, owner,
				[]string{"organization:read"}, at.Add(time.Hour), "subj_actor", at)
			if err == nil {
				t.Fatalf("%s was accepted as an owner; the pair must name exactly one "+
					"principal of a known kind, or a credential exists that nothing can "+
					"revoke by owner", name)
			}
		})
	}
}

// A key must carry at least one scope.
//
// Not because a scopeless key is dangerous — it can reach nothing — but because
// an empty list is exactly what a list dropped between the client and the server
// looks like, and the second reading is the one worth refusing at the write.
func TestAnAPIKeyMustNameAtLeastOneScope(t *testing.T) {
	k := eventsourcing.NewAggregate(domain.NewAPIKey)
	err := k.Issue(newID[ids.APIKey](t), testOrg,
		domain.UserOwner(newID[ids.Subject](t).String()),
		nil, at.Add(time.Hour), "subj_actor", at)
	if err == nil {
		t.Fatal("a key with no scopes was issued; an empty list is indistinguishable from " +
			"one lost in transit")
	}
}

// The scope grammar admits exactly `<resource type>:read|write`.
//
// The rejected cases are each a shape somebody would plausibly write, and each
// would mean something this system cannot enforce: an object id is OpenFGA's
// job, a wildcard is a scope that narrows nothing, and an unknown verb is a
// permission level the gate has no mapping for.
func TestTheScopeGrammarRefusesAnythingItCannotEnforce(t *testing.T) {
	refused := []string{
		"organization",            // no access level
		"organization:admin",      // a level the gate cannot derive
		"organization:*",          // a wildcard narrows nothing
		"*:read",                  // ditto, on the other axis
		"organization:read:extra", // a third axis is a second authz model
		"Organization:read",       // upper case; the resource type is a proto value
		"workspace:read ",         // trailing space
		"organization:read,write", // a list inside one scope
		"workspace_01ARZ:read",    // an object id belongs in OpenFGA
	}
	for _, scope := range refused {
		t.Run(scope, func(t *testing.T) {
			k := eventsourcing.NewAggregate(domain.NewAPIKey)
			err := k.Issue(newID[ids.APIKey](t), testOrg,
				domain.UserOwner(newID[ids.Subject](t).String()),
				[]string{scope}, at.Add(time.Hour), "subj_actor", at)
			if err == nil {
				t.Fatalf("%q was accepted as a scope; the grammar is "+
					"<resource type>:read|write and nothing else, because the gate derives "+
					"the required scope from an RPC's own declaration", scope)
			}
		})
	}
}

// Scopes are stored sorted and deduplicated.
//
// Both matter for the same reason: the list is rendered on a management screen,
// compared in a gate and written into an append-only event, so an order that
// depended on how a caller typed it would make two identical keys look different
// in all three places — and a list that grew by repetition would defeat the
// ceiling.
func TestScopesAreStoredSortedAndDeduplicated(t *testing.T) {
	k, _ := liveKey(t, "workspace:write", "organization:read", "workspace:write")

	got := k.Scopes()
	want := []string{"organization:read", "workspace:write"}
	if len(got) != len(want) {
		t.Fatalf("stored %v, want %v; duplicates must be collapsed or the scope ceiling "+
			"can be defeated by repetition", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("stored %v, want %v; an order that follows the caller's typing makes "+
				"two identical keys look different everywhere the list is shown", got, want)
		}
	}
}

// Scopes() returns a copy.
//
// Without it a caller appending to the returned slice widens the key in memory —
// silently, for the lifetime of the process, which is the hardest possible
// version of that bug to reproduce.
func TestScopesCannotBeWidenedThroughTheAccessor(t *testing.T) {
	k, _ := liveKey(t, "organization:read")

	stolen := k.Scopes()
	stolen[0] = "organization:write"

	if got := k.Scopes(); got[0] != "organization:read" {
		t.Fatalf("the key now carries %v; the accessor must return a copy, or a caller "+
			"mutating the result escalates the credential in memory", got)
	}
}

// A rotation records the deadline the old secret dies at, and it is derived from
// the instant of the rotation rather than from a policy constant read later.
//
// The assertion is on the arithmetic because the alternative design — storing
// only the overlap and computing the deadline at read time — would move every
// already-written rotation the day the constant changed, including retroactively
// extending a window that had already closed.
func TestARotationRecordsWhenThePreviousSecretDies(t *testing.T) {
	k, id := liveKey(t)

	const overlap = 3 * time.Hour
	if err := k.Rotate(overlap, at.Add(48*time.Hour), "subj_actor", at); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	pending := k.Uncommitted()
	if len(pending) != 1 {
		t.Fatalf("a rotation recorded %d events, want 1", len(pending))
	}
	ev, ok := pending[0].(*contract.ApiKeyRotated)
	if !ok {
		t.Fatalf("a rotation recorded a %T, want *contract.ApiKeyRotated", pending[0])
	}
	if ev.KeyID != id.String() {
		t.Fatalf("the rotation names key %q, want %q; a rotation must keep the key's id or "+
			"every consumer has to be reconfigured", ev.KeyID, id)
	}
	if want := at.Add(overlap); !ev.PreviousRetiresAt.Equal(want) {
		t.Fatalf("the superseded secret retires at %s, want %s; the deadline has to be "+
			"recorded at the moment of the rotation, not derived later from a constant "+
			"that can change", ev.PreviousRetiresAt, want)
	}
}

// A zero overlap is legal and is the leak response.
//
// It must be expressible: when the reason for rotating is that somebody else
// holds the old secret, a grace window is exactly the wrong behaviour.
func TestAnImmediateRotationRetiresTheOldSecretAtOnce(t *testing.T) {
	k, _ := liveKey(t)

	if err := k.Rotate(0, at.Add(48*time.Hour), "subj_actor", at); err != nil {
		t.Fatalf("an immediate rotation was refused: %v; it is the leak response, and a "+
			"system that cannot express it forces a revoke-and-remint instead", err)
	}
	ev := k.Uncommitted()[0].(*contract.ApiKeyRotated)
	if !ev.PreviousRetiresAt.Equal(at) {
		t.Fatalf("the superseded secret retires at %s, want %s (the rotation instant)",
			ev.PreviousRetiresAt, at)
	}
}

// The overlap has a ceiling, and exceeding it is refused.
//
// An unbounded overlap is "the old secret lives until somebody remembers to
// remove it", and nobody remembers — so a rotation performed BECAUSE a secret
// leaked would not have removed the leaked secret.
func TestARotationOverlapIsCapped(t *testing.T) {
	k, _ := liveKey(t)

	tooLong := domain.MaxRotationOverlap + time.Hour
	if err := k.Rotate(tooLong, at.Add(48*time.Hour), "subj_actor", at); err == nil {
		t.Fatalf("an overlap of %s was accepted; the cap is %s, and a superseded secret "+
			"that outlives the rotation by longer is one nobody is going to remove",
			tooLong, domain.MaxRotationOverlap)
	}
}

// A rotation must not change what a key may do.
//
// If it could, rotation would be a route to escalating a key without minting
// one — and the audit trail would read as routine maintenance.
func TestARotationChangesNothingButTheDeadline(t *testing.T) {
	k, _ := liveKey(t, "organization:read")
	ownerBefore, kindBefore := k.OwnerID(), k.OwnerKind()

	if err := k.Rotate(time.Hour, at.Add(48*time.Hour), "subj_actor", at); err != nil {
		t.Fatalf("rotate: %v", err)
	}
	if got := k.Scopes(); len(got) != 1 || got[0] != "organization:read" {
		t.Fatalf("the key now carries %v; a rotation that could widen scopes is an "+
			"escalation wearing the name of maintenance", got)
	}
	if k.OwnerID() != ownerBefore || k.OwnerKind() != kindBefore {
		t.Fatalf("the key now acts as %s:%s, was %s:%s; a rotation must not move a "+
			"credential to another principal",
			k.OwnerKind(), k.OwnerID(), kindBefore, ownerBefore)
	}
}

// A revoked key cannot be rotated back to life.
//
// Rotation keeps the key id, so every grant that names it would apply again —
// and the log would record a rotation rather than a restoration of access
// somebody deliberately removed.
func TestARevokedKeyCannotBeRotated(t *testing.T) {
	k, _ := liveKey(t)
	if err := k.Revoke("subj_actor", "leaked", at); err != nil {
		t.Fatalf("revoke: %v", err)
	}
	k.ClearUncommitted()

	if err := k.Rotate(time.Hour, at.Add(48*time.Hour), "subj_actor", at.Add(time.Minute)); err == nil {
		t.Fatal("a revoked key was rotated; the key id is unchanged by a rotation, so this " +
			"would restore every grant that names it with nothing in the log calling it a " +
			"restoration")
	}
	if len(k.Uncommitted()) != 0 {
		t.Fatalf("a refused rotation recorded %d events", len(k.Uncommitted()))
	}
}

// Revocation is idempotent, so a bulk incident response cannot half-fail.
func TestRevokingATwiceRevokedKeyRecordsNothingAndSucceeds(t *testing.T) {
	k, _ := liveKey(t)
	if err := k.Revoke("subj_actor", "leaked", at); err != nil {
		t.Fatalf("first revoke: %v", err)
	}
	k.ClearUncommitted()

	if err := k.Revoke("subj_actor", "leaked", at.Add(time.Minute)); err != nil {
		t.Fatalf("a second revocation failed: %v; an incident response revokes in bulk and "+
			"must not turn a partially-completed sweep into an error the caller cannot act "+
			"on", err)
	}
	if len(k.Uncommitted()) != 0 {
		t.Fatalf("a repeat revocation recorded %d events; it must record nothing",
			len(k.Uncommitted()))
	}
}

// An EXPIRED key is still revocable, and this is where it differs from a
// session.
//
// A session that has expired can never be used again, so a tombstone for it is
// inert. A key's deadline is a date the key carries and a rotation would move
// it — so refusing to revoke an expired key would mean a leaked secret on a key
// a day past its deadline could be brought back with one rotation.
func TestAnExpiredKeyIsStillRevocable(t *testing.T) {
	k, _ := liveKey(t)
	afterExpiry := at.Add(domain.DefaultAPIKeyLifetime + time.Hour)

	if k.Usable(afterExpiry) {
		t.Fatal("the key reports usable past its own deadline")
	}
	if err := k.Revoke("subj_actor", "leaked", afterExpiry); err != nil {
		t.Fatalf("an expired key could not be revoked: %v; its expiry is a date a rotation "+
			"can move, so leaving it un-revoked leaves a leaked secret one rotation away "+
			"from working", err)
	}
	if len(k.Uncommitted()) != 1 {
		t.Fatalf("revoking an expired key recorded %d events, want 1; the record is what "+
			"stops a later rotation", len(k.Uncommitted()))
	}
}

// `:write` implies `:read` on the same resource type, and nothing else is
// implied.
//
// Without the implication every writing key would have to carry both spellings,
// and the list somebody forgot to keep in step is the one that makes a working
// integration fail on a read it has always been able to do.
func TestWriteImpliesReadAndNothingElse(t *testing.T) {
	cases := []struct {
		name     string
		held     []string
		required string
		want     bool
	}{
		{"the exact scope", []string{"organization:read"}, "organization:read", true},
		{"write covers read", []string{"organization:write"}, "organization:read", true},
		{"read does NOT cover write", []string{"organization:read"}, "organization:write", false},
		{"another resource type is unrelated", []string{"workspace:write"}, "organization:read", false},
		{"an empty key reaches nothing", nil, "organization:read", false},
		{"an underivable requirement reaches nothing", []string{"organization:write"}, "", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := domain.APIKeyScopeSatisfied(tc.held, tc.required); got != tc.want {
				t.Fatalf("a key holding %v was %s %q; want %s",
					tc.held,
					map[bool]string{true: "admitted to", false: "refused"}[got],
					tc.required,
					map[bool]string{true: "admitted", false: "refused"}[tc.want])
			}
		})
	}
}

// An empty required scope is a DENIAL and not "no requirement".
//
// It is the value a method the gate cannot characterise produces, and admitting
// it would open exactly the endpoints nobody has classified.
func TestAnUnderivableScopeRequirementDeniesEvenAWideKey(t *testing.T) {
	wide := []string{"organization:write", "workspace:write", "billing:write"}
	if domain.APIKeyScopeSatisfied(wide, "") {
		t.Fatal("a key was admitted to a method whose required scope could not be derived; " +
			"an empty requirement must deny, or an unclassified endpoint is open to every " +
			"credential")
	}
}
