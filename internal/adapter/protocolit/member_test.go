//go:build integration

package protocolit_test

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"github.com/chronos/chronos-go/internal/adapter/stripe/stripetest"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	organizationv1 "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	valkeyadapter "github.com/chronos/chronos-go/internal/adapter/valkey"
	accessprojection "github.com/chronos/chronos-go/internal/modules/access/projection"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	workspacecontract "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/secret"
	"github.com/valkey-io/valkey-go"
)

// THE MEMBER RPCs, END TO END, THROUGH THE WHOLE PIPELINE.
//
// # What this proves that the unit tests cannot
//
// These are the first RPCs in the system whose authz gate names a request FIELD.
// `resource_id_field` had been declared in the schema and published in the
// OpenAPI document since the option existed, and the gate returned
// ErrGateUnavailable for every method that used one — so no RPC could carry it,
// and the declaration was documentation of something that did not work.
//
// The unit test for resourceIDFor proves the function reads the field. Only this
// proves the value reaches OpenFGA as the object of a real Check, against a real
// graph, with the tuple written by a real projector — which is the difference
// between "the resolver works" and "the endpoint is gated".
//
// It also closes the loop the seat rule turns on. The creator's membership, the
// joiner's seat, the removal that returns it and the tombstone that makes the
// removal immediate are four separate mechanisms in three modules; this is the
// only place they run together.
func TestWorkspaceMembersEndToEnd(t *testing.T) {
	stripetest.Key(t)
	if os.Getenv("OPENFGA_STORE_ID") == "" {
		t.Skip("OPENFGA_STORE_ID is not set")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	owner := h.disposableAccount(t, "member-owner")
	joiner := h.disposableAccount(t, "member-joiner")

	created, err := h.organization.CreateOrganization(ctx,
		authed(&organizationv1.CreateOrganizationRequest{
			Name: "Member Test", Slug: h.freshSlug(),
		}, owner.bearer))
	if err != nil {
		t.Fatalf("CreateOrganization: %v\n%s", err, h.serverLogs())
	}
	orgID := created.Msg.GetOrgId()

	h.provision(t, ctx, orgID, owner.subjectID)
	h.grantOwner(t, ctx, orgID, owner.subjectID)
	h.awaitOrgStatus(t, ctx, orgID, "trialing")
	h.awaitOrgMember(t, ctx, orgID, owner.subjectID)

	ws, err := h.workspace.CreateWorkspace(ctx,
		authed(&workspacev1.CreateWorkspaceRequest{Name: "Engineering"}, owner.bearer))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v\n%s", err, h.serverLogs())
	}
	workspaceID := ws.Msg.GetWorkspaceId()

	// The creator's own membership row. It comes from a `MemberJoined` appended
	// atomically with the workspace, not from `WorkspaceCreated` — and until it
	// did, the creator had no membership aggregate at all, so removing them was
	// a no-op that returned 200.
	h.awaitWorkspaceMember(t, ctx, orgID, workspaceID, owner.subjectID, "admin")

	// The access reactor, driven directly. This package deliberately does not run
	// cmd/worker — its verification-mail reactor mints a fresh token per
	// registration and destroys this package's own fixtures — so the reactor that
	// writes tuples is invoked here over the same streams the worker would read.
	//
	// The `parent` tuple has to land before gate 2 can answer about this
	// workspace at all: `admin` on a workspace is INHERITED from the
	// organization through that edge, and without it the org owner is refused
	// from their own workspace.
	h.applyAccess(t, ctx, "workspace", workspaceID)
	h.applyAccess(t, ctx, "membership", workspaceID+"."+owner.subjectID)
	h.awaitWorkspacePermission(t, ctx, workspaceID, owner.subjectID, "admin", true)

	t.Run("adding a member consumes a seat and grants access", func(t *testing.T) {
		res, err := h.workspace.AddWorkspaceMember(ctx,
			authed(&workspacev1.AddWorkspaceMemberRequest{
				WorkspaceId: workspaceID,
				SubjectId:   joiner.subjectID,
				Role:        "member",
			}, owner.bearer))
		if err != nil {
			t.Fatalf("AddWorkspaceMember: %v\n%s", err, h.serverLogs())
		}
		if !res.Msg.GetSeatConsumed() {
			t.Error("the join took no seat for somebody new to the organization, so the " +
				"plan's seat limit does not bind and the customer is under-charged")
		}

		h.awaitWorkspaceMember(t, ctx, orgID, workspaceID, joiner.subjectID, "member")

		h.applyAccess(t, ctx, "membership", workspaceID+"."+joiner.subjectID)

		// The membership tuple, written by the access projector from the
		// membership stream. Before the filter named that category, every one of
		// these events was skipped — and a grant that never lands DENIES, which
		// is what a healthy authorization graph looks like from outside.
		h.awaitWorkspacePermission(t, ctx, workspaceID, joiner.subjectID, "member", true)

		// And the organization membership, which is what lets the joiner resolve
		// the tenant at gate 1 at all. Without it they can authenticate and then
		// do nothing: gate 1 refuses to resolve an organization they demonstrably
		// belong to, and the refusal is NOT_FOUND, so the symptom is a workspace
		// that appears not to exist.
		h.awaitOrgMember(t, ctx, orgID, joiner.subjectID)
	})

	t.Run("a member cannot administer the workspace", func(t *testing.T) {
		// The joiner is a `member`, and these RPCs require `admin` on the
		// workspace. Without the `parent` edge this would pass for nobody and
		// without the membership tuple it would pass for everybody, so it is the
		// assertion that the two relations are actually distinguished.
		_, err := h.workspace.AddWorkspaceMember(ctx,
			authed(&workspacev1.AddWorkspaceMemberRequest{
				WorkspaceId: workspaceID,
				SubjectId:   owner.subjectID,
				Role:        "guest",
			}, joiner.bearer))
		if err == nil {
			t.Fatal("a plain member added somebody to a workspace they do not administer")
		}
		reason, ok := reasonOf(err)
		if !ok {
			t.Fatalf("the refusal carries no ErrorDetail: %v", err)
		}
		if reason != string(errs.NotFound) {
			t.Errorf("refused with %q, want %q — the disclosure ladder sits on the rung "+
				"that reveals less until parent-visibility is implemented (ADR-036 §5.1)",
				reason, errs.NotFound)
		}
	})

	t.Run("a workspace of another tenant is refused", func(t *testing.T) {
		// The caller IS an org admin, and org admins inherit `admin` on every
		// workspace of their organization through the `parent` edge. So this is
		// the assertion that the inheritance stops at the tenant boundary: the
		// named workspace has no parent edge to this organization, and the only
		// thing that makes the difference is that the gate asked about the
		// workspace the request named.
		//
		// It is also what would catch the gate reading the WRONG field — a
		// resource_id_field pointing at `subject_id`, say, would check
		// `workspace:subj_...` and deny here for a reason that has nothing to do
		// with tenancy, which the subtests above would then disagree with.
		_, err := h.workspace.AddWorkspaceMember(ctx,
			authed(&workspacev1.AddWorkspaceMemberRequest{
				WorkspaceId: "ws_01ARZ3NDEKTSV4RRFFQ69G5FAV",
				SubjectId:   joiner.subjectID,
				Role:        "member",
			}, owner.bearer))
		if err == nil {
			t.Fatal("an org admin added a member to a workspace that is not theirs; the " +
				"authz gate is checking the organization instead of the named workspace, " +
				"which every org admin already passes")
		}
	})

	t.Run("removing a member revokes immediately and returns the seat", func(t *testing.T) {
		res, err := h.workspace.RemoveWorkspaceMember(ctx,
			authed(&workspacev1.RemoveWorkspaceMemberRequest{
				WorkspaceId: workspaceID,
				SubjectId:   joiner.subjectID,
			}, owner.bearer))
		if err != nil {
			t.Fatalf("RemoveWorkspaceMember: %v\n%s", err, h.serverLogs())
		}
		if !res.Msg.GetSeatReleased() {
			t.Error("no seat came back when the person left their only workspace in the " +
				"organization, so it is consumed forever by somebody who is gone")
		}

		// IMMEDIATELY, without waiting for a projector. This is ADR-045's whole
		// point and the half that had no caller until the member RPCs existed:
		// being late to grant costs a moment of not seeing new access, and being
		// late to revoke is a security failure.
		//
		// No polling here, deliberately. A loop would pass on the tombstone OR on
		// the projector, and the two are seconds apart — which is exactly the
		// window this asserts is closed.
		h.assertDenied(t, ctx, workspaceID, joiner.subjectID, "member")

		// NOW let the reactor catch up, which removes the tuple and confirms the
		// tombstone — in that order, so a deletion that fails leaves the
		// tombstone denying (ADR-045).
		h.applyAccess(t, ctx, "membership", workspaceID+"."+joiner.subjectID)
		h.awaitWorkspacePermission(t, ctx, workspaceID, joiner.subjectID, "member", false)

		h.awaitNoWorkspaceMember(t, ctx, orgID, workspaceID, joiner.subjectID)
	})

	t.Run("the last admin cannot be removed", func(t *testing.T) {
		_, err := h.workspace.RemoveWorkspaceMember(ctx,
			authed(&workspacev1.RemoveWorkspaceMemberRequest{
				WorkspaceId: workspaceID,
				SubjectId:   owner.subjectID,
			}, owner.bearer))
		if err == nil {
			t.Fatal("the last admin left; the workspace now has nobody who may add one, " +
				"and no request from outside can repair it")
		}
		reason, ok := reasonOf(err)
		if !ok {
			t.Fatalf("the refusal carries no ErrorDetail: %v", err)
		}
		if reason != string(errs.Conflict) {
			t.Errorf("refused with %q, want %q: the request is well formed and the caller "+
				"is permitted, and it is the current state that says no", reason, errs.Conflict)
		}
	})
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

// applyAccess replays one stream through the access reactor.
//
// The same code cmd/worker runs, over the same events, without a second process
// competing for the log — which is this package's established shape and the
// reason the trial-cap test drives the provisioning reactor the same way.
//
// A BARE writer, deliberately: the tombstone assertions in this file want to see
// what the handler laid, and a confirming writer would clear it as a side effect
// of the very call that is supposed to happen afterwards. The confirmation
// ordering itself is asserted in cmd/worker's own wiring test.
func (hh *harness) applyAccess(t *testing.T, ctx context.Context, category, key string) {
	t.Helper()

	conn, err := fgaadapter.Dial(endpointOr("localhost:8081"), os.Getenv("OPENFGA_PRESHARED_KEY"))
	if err != nil {
		t.Fatalf("openfga: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	writer, err := fgaadapter.NewWriter(conn, fgaadapter.Config{
		StoreID: os.Getenv("OPENFGA_STORE_ID"),
		ModelID: os.Getenv("OPENFGA_MODEL_ID"),
	})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	tuples, err := accessprojection.NewTuples(writer, hh.codec)
	if err != nil {
		t.Fatalf("NewTuples: %v", err)
	}

	stream, err := eventsourcing.NewStreamID(eventsourcing.Category(category), key)
	if err != nil {
		t.Fatalf("stream id %s-%s: %v", category, key, err)
	}
	events, err := hh.store.ReadStream(ctx, stream, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", stream, err)
	}
	if len(events) == 0 {
		t.Fatalf("%s is empty, so replaying it through the access reactor proves nothing",
			stream)
	}
	for _, e := range events {
		if err := tuples.React(ctx, eventsourcing.Envelope{
			ID: e.ID, Type: e.Type, Payload: e.Payload, Live: true,
		}); err != nil {
			t.Fatalf("reacting to %s on %s: %v", e.Type, stream, err)
		}
	}
}

// awaitWorkspaceMember blocks until the membership projection has the row.
//
// A TENANT transaction, unlike awaitOrgMember: `workspace_member_view` carries
// the ordinary row security policy, because everything that reads it does so
// after gate 1 has resolved a scope. An unscoped read returns nothing and looks
// exactly like a projector that has not caught up.
func (hh *harness) awaitWorkspaceMember(
	t *testing.T, ctx context.Context, orgID, workspaceID, subjectID, wantRole string,
) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	var last string
	for {
		var role string
		scoped := db.WithTenant(ctx, db.Tenant{OrgID: orgID, UserID: "sub_probe"})
		err := hh.pg.InTenantTx(scoped, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT role FROM workspace_member_view
				 WHERE workspace_id = $1 AND subject_id = $2`,
				workspaceID, subjectID).Scan(&role)
		})
		if err == nil && role == wantRole {
			return
		}
		if err == nil {
			last = role
		}
		if time.Now().After(deadline) {
			t.Fatalf("workspace_member_view has %s as %q in %s after 60s, want %q; the seat "+
				"rule counts this table, so a missing row makes every join look like the "+
				"person's first (err: %v)", subjectID, last, workspaceID, wantRole, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// awaitNoWorkspaceMember blocks until the row is gone.
func (hh *harness) awaitNoWorkspaceMember(
	t *testing.T, ctx context.Context, orgID, workspaceID, subjectID string,
) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		var n int
		scoped := db.WithTenant(ctx, db.Tenant{OrgID: orgID, UserID: "sub_probe"})
		err := hh.pg.InTenantTx(scoped, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM workspace_member_view
				 WHERE workspace_id = $1 AND subject_id = $2`,
				workspaceID, subjectID).Scan(&n)
		})
		if err == nil && n == 0 {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("workspace_member_view still has %s in %s after 60s; every future join "+
				"of theirs would be counted as free (err: %v)", subjectID, workspaceID, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// awaitWorkspacePermission blocks until OpenFGA answers as expected.
func (hh *harness) awaitWorkspacePermission(
	t *testing.T, ctx context.Context, workspaceID, subjectID string,
	relation authz.Relation, want bool,
) {
	t.Helper()

	checker := hh.checker(t)
	deadline := time.Now().Add(60 * time.Second)
	for {
		decision, err := checker.Check(ctx, authz.Query{
			Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID},
			Relation:  relation,
			Resource:  authz.ResourceRef{Type: "workspace", ID: workspaceID},
		})
		if err == nil && decision.Allowed() == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("OpenFGA still answers %v for %s %s workspace:%s after 60s, want %v; "+
				"a grant that never lands DENIES, which is indistinguishable from a healthy "+
				"graph (err: %v)", !want, subjectID, relation, workspaceID, want, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// assertDenied checks the TOMBSTONE store, which is what denies before the
// projector has caught up.
//
// One call, no polling, and deliberately not a Check against OpenFGA: the tuple
// is still in the graph at this point, because the access projector has not seen
// the removal yet. A Check would therefore ALLOW, and that gap is precisely what
// the tombstone exists to close. A retry loop here would hide the whole property
// by eventually passing on the projector instead (ADR-045).
//
// The Guard's consultation of this store is unit-tested; what had never been
// exercised anywhere is whether anything LAYS one, and until the member RPCs
// existed nothing did.
func (hh *harness) assertDenied(
	t *testing.T, ctx context.Context, workspaceID, subjectID string, relation authz.Relation,
) {
	t.Helper()

	vk, err := valkey.NewClient(valkey.ClientOption{
		InitAddress:  []string{valkeyAddr()},
		Password:     os.Getenv("VALKEY_PASSWORD"),
		DisableCache: true,
	})
	if err != nil {
		t.Fatalf("valkey: %v", err)
	}
	defer vk.Close()

	revoked, err := valkeyadapter.NewAuthz(vk).Revoked(ctx, authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID},
		Relation:  relation,
		Resource:  authz.ResourceRef{Type: "workspace", ID: workspaceID},
	})
	if err != nil {
		t.Fatalf("reading the tombstone: %v", err)
	}
	if !revoked {
		t.Fatalf("no tombstone denies %s %s on workspace:%s the instant after they were "+
			"removed, so the revocation waits on projector lag — and being late to revoke "+
			"is a security failure rather than a delay (access.md §6.1)",
			subjectID, relation, workspaceID)
	}
}

// valkeyAddr reads the address the stack publishes, defaulting to the local one.
func valkeyAddr() string {
	if v := os.Getenv("VALKEY_ADDR"); v != "" {
		return v
	}
	return "localhost:6379"
}

// checker dials OpenFGA directly, bypassing every tombstone and cache.
func (hh *harness) checker(t *testing.T) *fgaadapter.Checker {
	t.Helper()

	conn, err := fgaadapter.Dial(endpointOr("localhost:8081"), os.Getenv("OPENFGA_PRESHARED_KEY"))
	if err != nil {
		t.Fatalf("openfga: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })

	checker, err := fgaadapter.New(conn, fgaadapter.Config{
		StoreID: os.Getenv("OPENFGA_STORE_ID"),
		ModelID: os.Getenv("OPENFGA_MODEL_ID"),
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	return checker
}

// AN INVITATION, END TO END.
//
// # What only this can prove
//
// Issuing an invitation touches four things no unit test can put together: the
// blind index and the account directory, both of which are IDENTITY'S and reach
// workspace only through ports satisfied at the composition root; the vault,
// which holds the address the event refuses to carry; and the seat pool, which
// is charged at issue rather than at acceptance.
//
// The composition root is the part worth testing here. Workspace declares those
// ports and cmd/api is the only place allowed to satisfy them — so a wiring that
// compiles and leaves them unsatisfied is exactly the shape of failure this
// repository keeps finding, and it would surface as "the invitation service is
// NOT constructed" in a log line nobody reads.
func TestInvitingEndToEnd(t *testing.T) {
	stripetest.Key(t)
	if os.Getenv("OPENFGA_STORE_ID") == "" {
		t.Skip("OPENFGA_STORE_ID is not set")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	owner := h.disposableAccount(t, "invite-owner")
	existing := h.disposableAccount(t, "invite-existing")

	created, err := h.organization.CreateOrganization(ctx,
		authed(&organizationv1.CreateOrganizationRequest{
			Name: "Invite Test", Slug: h.freshSlug(),
		}, owner.bearer))
	if err != nil {
		t.Fatalf("CreateOrganization: %v\n%s", err, h.serverLogs())
	}
	orgID := created.Msg.GetOrgId()

	h.provision(t, ctx, orgID, owner.subjectID)
	h.grantOwner(t, ctx, orgID, owner.subjectID)
	h.awaitOrgStatus(t, ctx, orgID, "trialing")
	h.awaitOrgMember(t, ctx, orgID, owner.subjectID)

	ws, err := h.workspace.CreateWorkspace(ctx,
		authed(&workspacev1.CreateWorkspaceRequest{Name: "Invites"}, owner.bearer))
	if err != nil {
		t.Fatalf("CreateWorkspace: %v\n%s", err, h.serverLogs())
	}
	workspaceID := ws.Msg.GetWorkspaceId()

	h.applyAccess(t, ctx, "workspace", workspaceID)
	h.applyAccess(t, ctx, "membership", workspaceID+"."+owner.subjectID)
	h.awaitWorkspacePermission(t, ctx, workspaceID, owner.subjectID, "admin", true)

	t.Run("inviting a stranger takes a seat and reveals nothing", func(t *testing.T) {
		stranger := h.freshEmail("stranger")

		res, err := h.workspace.InviteToWorkspace(ctx,
			authed(&workspacev1.InviteToWorkspaceRequest{
				WorkspaceId: workspaceID, Email: stranger, Role: "member",
			}, owner.bearer))
		if err != nil {
			t.Fatalf("InviteToWorkspace: %v\n%s", err, h.serverLogs())
		}

		if !strings.HasPrefix(res.Msg.GetInvitationId(), "inv_") {
			t.Errorf("invitation id %q is not a prefixed ULID", res.Msg.GetInvitationId())
		}
		if !res.Msg.GetSeatConsumed() {
			t.Error("inviting somebody new to the organization took no seat, so 60 pending " +
				"invitations against 50 seats would all look valid and the 51st acceptance " +
				"would fail for somebody who did nothing wrong")
		}
		if res.Msg.GetExpiresAt() == nil {
			t.Error("no expiry was published, so nothing tells the recipient when the link dies")
		}

		// The RESPONSE is the disclosure surface here, and it must carry neither
		// the credential nor the address. Serialising the whole message rather
		// than checking named fields, so a field added later is covered too.
		body := res.Msg.String()
		if strings.Contains(body, stranger) {
			t.Errorf("the response echoes the address back: %s", body)
		}
		if strings.Contains(body, "@") {
			t.Errorf("the response contains an address: %s", body)
		}
	})

	t.Run("inviting an existing account takes a seat but mints no identity", func(t *testing.T) {
		// The account exists and is in NO organization, so this still costs a
		// seat. What it must not do is create a second pseudonym for a person
		// who already has one — which is invisible from the response and visible
		// in the log.
		res, err := h.workspace.InviteToWorkspace(ctx,
			authed(&workspacev1.InviteToWorkspaceRequest{
				WorkspaceId: workspaceID, Email: existing.email, Role: "member",
			}, owner.bearer))
		if err != nil {
			t.Fatalf("InviteToWorkspace: %v\n%s", err, h.serverLogs())
		}

		issued := h.invitationIssued(t, ctx, res.Msg.GetInvitationId())
		if issued.SubjectID != existing.subjectID {
			t.Errorf("the invitation names %s, want the existing account's %s. A fresh "+
				"pseudonym would make accepting create a second identity for one person, "+
				"and the seat would be counted against somebody who cannot log in",
				issued.SubjectID, existing.subjectID)
		}
		if issued.EmailIndex == "" {
			t.Error("no blind index reached the event")
		}
	})

	t.Run("an invitation is accepted and creates a membership", func(t *testing.T) {
		// The invitee is an ACCOUNT with no organization: they can authenticate
		// but gate 1 resolves nothing for them, which is precisely the state the
		// accept RPC has to work in. Every other org-scoped call they make is
		// NOT_FOUND until this succeeds.
		invitee := h.disposableAccount(t, "invite-accepts")

		res, err := h.workspace.InviteToWorkspace(ctx,
			authed(&workspacev1.InviteToWorkspaceRequest{
				WorkspaceId: workspaceID, Email: invitee.email, Role: "member",
			}, owner.bearer))
		if err != nil {
			t.Fatalf("InviteToWorkspace: %v\n%s", err, h.serverLogs())
		}
		invitationID := res.Msg.GetInvitationId()

		// The token is not in the response, and not in the log — it is in the
		// mail, which does not exist yet (WORKLIST 5g). So it is read from the
		// credential store the same way the mail activity will: by digest.
		token := h.invitationToken(t, ctx, invitationID, orgID)

		accepted, err := h.workspace.AcceptInvitation(ctx,
			authed(&workspacev1.AcceptInvitationRequest{Token: token}, invitee.bearer))
		if err != nil {
			t.Fatalf("AcceptInvitation: %v\n%s", err, h.serverLogs())
		}
		if accepted.Msg.GetWorkspaceId() != workspaceID {
			t.Errorf("joined %s, want %s", accepted.Msg.GetWorkspaceId(), workspaceID)
		}
		if accepted.Msg.GetOrgId() != orgID {
			t.Errorf("reported org %s, want %s", accepted.Msg.GetOrgId(), orgID)
		}
		if accepted.Msg.GetAlreadyMember() {
			t.Error("reported already-member for somebody who had never joined")
		}

		h.awaitWorkspaceMember(t, ctx, orgID, workspaceID, invitee.subjectID, "member")

		// And gate 1 now resolves for them, which is the end-to-end consequence:
		// before accepting they were an account with no tenant, and every
		// org-scoped call answered NOT_FOUND.
		h.awaitOrgMember(t, ctx, orgID, invitee.subjectID)

		// THE LINK IS SPENT. A second click must not admit a second person.
		if _, err := h.workspace.AcceptInvitation(ctx,
			authed(&workspacev1.AcceptInvitationRequest{Token: token},
				existing.bearer)); err == nil {
			t.Fatal("a second account joined on one invitation; that is one seat " +
				"admitting two people")
		}

		// Asserted against the STORE as well, and not only against the second
		// call, because the two refuse for different reasons and only one of them
		// is the token. The settled invitation refuses a replay all by itself —
		// so a Consume that quietly stopped consuming would leave a live digest
		// behind and the call above would still fail, for the wrong reason and
		// with nothing to say so.
		if n := h.invitationTokenRows(t, ctx, invitationID); n != 0 {
			t.Errorf("%d digests survive a redeemed invitation; a credential that outlives "+
				"what it authorised is one a mail archive can replay", n)
		}
	})

	t.Run("the invitation list is projected and readable", func(t *testing.T) {
		// The PROJECTION, end to end. Until this ran, invitation_view was written
		// by a projector and read by nothing — a table that can be silently wrong
		// forever, which is the shape of failure this repository keeps finding.
		invitee := h.freshEmail("listed")
		res, err := h.workspace.InviteToWorkspace(ctx,
			authed(&workspacev1.InviteToWorkspaceRequest{
				// A MEMBER seat, not a guest one: the Trial plan grants zero
				// guest seats, so a guest invitation is refused by gate 4's
				// catalogue before it ever reaches the projection.
				WorkspaceId: workspaceID, Email: invitee, Role: "member",
			}, owner.bearer))
		if err != nil {
			t.Fatalf("InviteToWorkspace: %v\n%s", err, h.serverLogs())
		}
		invitationID := res.Msg.GetInvitationId()

		listed := h.awaitInvitationListed(t, ctx, workspaceID, invitationID, owner.bearer)
		if listed.GetRole() != "member" {
			t.Errorf("listed as %q, want member", listed.GetRole())
		}
		if listed.GetStatus() != "pending" {
			t.Errorf("listed as %q, want pending", listed.GetStatus())
		}
		if listed.GetInvitedBy() != owner.subjectID {
			t.Errorf("listed inviter %s, want %s", listed.GetInvitedBy(), owner.subjectID)
		}
		if listed.GetExpiresAt() == nil || listed.GetIssuedAt() == nil {
			t.Error("the listed invitation carries no timestamps")
		}

		// NO ADDRESS on the wire. The list names a pseudonym and the vault
		// resolves it at read time under the key erasure destroys — a response
		// carrying the address would make every cache a place personal data
		// lives (ADR-002).
		if body := listed.String(); strings.Contains(body, "@") ||
			strings.Contains(body, "listed") {
			t.Errorf("the listed invitation carries the address: %s", body)
		}

		// REVOKING moves it out of the pending list, which is what proves the
		// settlement half of the projection rather than only the insert.
		if _, err := h.workspace.RevokeInvitation(ctx,
			authed(&workspacev1.RevokeInvitationRequest{
				WorkspaceId: workspaceID, InvitationId: invitationID,
			}, owner.bearer)); err != nil {
			t.Fatalf("RevokeInvitation: %v\n%s", err, h.serverLogs())
		}
		h.awaitInvitationGone(t, ctx, workspaceID, invitationID, owner.bearer)
	})

	t.Run("a member cannot invite", func(t *testing.T) {
		_, err := h.workspace.InviteToWorkspace(ctx,
			authed(&workspacev1.InviteToWorkspaceRequest{
				WorkspaceId: workspaceID, Email: h.freshEmail("nope"), Role: "member",
			}, existing.bearer))
		if err == nil {
			t.Fatal("somebody with no permission on this workspace issued an invitation, " +
				"which spends a seat belonging to an organization they are not in")
		}
	})
}

// invitationIssued reads one invitation's event straight from the log.
//
// The LOG and not a projection, because what is being asserted is what was
// written: a projection could be correct while the event carried an address, and
// the event is the thing that is permanent.
func (hh *harness) invitationIssued(
	t *testing.T, ctx context.Context, invitationID string,
) *workspacecontract.InvitationIssued {
	t.Helper()

	stream, err := eventsourcing.NewStreamID("invitation", invitationID)
	if err != nil {
		t.Fatalf("stream id: %v", err)
	}
	events, err := hh.store.ReadStream(ctx, stream, 0)
	if err != nil {
		t.Fatalf("reading %s: %v", stream, err)
	}
	if len(events) == 0 {
		t.Fatalf("%s is empty; the RPC returned an id for an invitation that was never "+
			"appended", stream)
	}

	decoded, err := hh.codec.Unmarshal(events[0].Type, events[0].Payload)
	if err != nil {
		t.Fatalf("decoding %s: %v", events[0].Type, err)
	}
	issued, ok := decoded.(*workspacecontract.InvitationIssued)
	if !ok {
		t.Fatalf("the first event on %s is %T", stream, decoded)
	}

	// The address must not be there, in any form. Asserted on the RAW payload,
	// because a decoded struct only shows the fields this build knows about.
	if strings.Contains(string(events[0].Payload), "@") {
		t.Fatalf("an address reached the event log: %s\nA log is append-only, so this "+
			"cannot be undone and erasure by key destruction cannot reach it",
			events[0].Payload)
	}
	return issued
}

// invitationToken installs a link the test knows the plaintext of.
//
// # What it stands in for
//
// The reactor. Issuing appends InvitationIssued and mints NOTHING — whoever
// sends the mail mints the link, because nothing that survives the request can
// recover a plaintext from a digest (app.InvitationIssuer). The mail reactor is
// WORKLIST 5g and does not exist yet, so this performs its one relevant step:
// void whatever is outstanding, then store one digest.
//
// It is the same store, the same purpose and the same expiry the issuer uses. A
// test-only endpoint returning a live credential was the alternative, and it is
// the kind of production path that survives into production; skipping asserts
// nothing at all. Every check on the accept path still runs against the real
// thing: the token store, the subscription gate, the workspace aggregate, the
// directory and the seat pool.
func (hh *harness) invitationToken(
	t *testing.T, ctx context.Context, invitationID, orgID string,
) string {
	t.Helper()

	// The SERVER's clock, not this process's. Another test in this package
	// travels the server forward to expire a session, and the server is what
	// evaluates `expires_at > now` — so a window measured from real time is
	// already closed by the time the lookup runs, and the symptom is an
	// acceptance refused as NOT_FOUND for a link that was just installed.
	reading, err := hh.clockState(ctx, http.MethodGet, hh.clockURL+"/debug/clock")
	if err != nil {
		t.Fatalf("reading the server's clock: %v", err)
	}

	raw := make([]byte, secret.Bytes)
	if _, err := rand.Read(raw); err != nil {
		t.Fatalf("generating a token: %v", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw)
	digest := secret.Digest(workspaceapp.PurposeInvitation, plaintext)

	// A SYSTEM transaction, because invitation_token carries no row security:
	// redemption happens before any tenant scope exists (migration 00023).
	err = hh.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		// Void first, exactly as the issuer does: two live links for one
		// invitation means either can be redeemed.
		if _, err := q.Exec(ctx,
			`DELETE FROM invitation_token WHERE invitation_id = $1`, invitationID); err != nil {
			return err
		}
		_, err := q.Exec(ctx,
			`INSERT INTO invitation_token (digest, purpose, invitation_id, org_id, expires_at)
			 VALUES ($1, $2, $3, $4, $5)`,
			digest, string(workspaceapp.PurposeInvitation), invitationID, orgID,
			reading.now.UTC().Add(workspaceapp.InvitationTTL))
		return err
	})
	if err != nil {
		t.Fatalf("installing an invitation link: %v", err)
	}
	return plaintext
}

// invitationTokenRows counts the live digests for an invitation.
func (hh *harness) invitationTokenRows(t *testing.T, ctx context.Context, invitationID string) int {
	t.Helper()
	var n int
	err := hh.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx,
			`SELECT count(*) FROM invitation_token WHERE invitation_id = $1`,
			invitationID).Scan(&n)
	})
	if err != nil {
		t.Fatalf("counting invitation tokens: %v", err)
	}
	return n
}

// awaitInvitationListed blocks until the projection has the invitation.
func (hh *harness) awaitInvitationListed(
	t *testing.T, ctx context.Context, workspaceID, invitationID, bearer string,
) *workspacev1.WorkspaceInvitation {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := hh.workspace.ListWorkspaceInvitations(ctx,
			authed(&workspacev1.ListWorkspaceInvitationsRequest{
				WorkspaceId: workspaceID, Status: "pending", PageSize: 100,
			}, bearer))
		if err == nil {
			for _, inv := range res.Msg.GetInvitations() {
				if inv.GetInvitationId() == invitationID {
					return inv
				}
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is not in the pending list after 60s; the projection is written "+
				"and read by nothing, so it can be wrong indefinitely (err: %v)",
				invitationID, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// awaitInvitationGone blocks until a settled invitation leaves the pending list.
func (hh *harness) awaitInvitationGone(
	t *testing.T, ctx context.Context, workspaceID, invitationID, bearer string,
) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		res, err := hh.workspace.ListWorkspaceInvitations(ctx,
			authed(&workspacev1.ListWorkspaceInvitationsRequest{
				WorkspaceId: workspaceID, Status: "pending", PageSize: 100,
			}, bearer))
		if err == nil {
			var found bool
			for _, inv := range res.Msg.GetInvitations() {
				if inv.GetInvitationId() == invitationID {
					found = true
				}
			}
			if !found {
				return
			}
		}
		if time.Now().After(deadline) {
			t.Fatalf("%s is still pending 60s after being revoked; the settlement half of "+
				"the projection does not run, so every revoked invitation stays on the "+
				"admin screen forever (err: %v)", invitationID, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
