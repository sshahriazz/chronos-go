//go:build integration

package openfga_test

import (
	"context"
	"testing"
	"time"

	fgav1 "github.com/chronos/chronos-go/gen/thirdparty/openfga/v1"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	"github.com/chronos/chronos-go/internal/authzmodel"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/authz/model"
)

// The model this build would actually deploy is deployable.
//
// Assembly checks the fragments against each other; only OpenFGA can say whether
// the result is a model it accepts. Those are different questions, and the
// second one is answered at deploy time — which, for the highest-blast-radius
// deploy in the system, is far too late to find out.
func TestTheAssembledModelDeploys(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn := dial(t)
	deployer, err := fgaadapter.NewDeployer(conn)
	if err != nil {
		t.Fatalf("NewDeployer: %v", err)
	}

	m, err := authzmodel.Assemble()
	if err != nil {
		t.Fatalf("assembling the model this build ships: %v", err)
	}

	storeID := freshStore(t, ctx, deployer)
	modelID, err := deployer.Deploy(ctx, storeID, m)
	if err != nil {
		t.Fatalf("the model this build ships was REFUSED by OpenFGA: %v\n\n%s", err, m.String())
	}
	if modelID == "" {
		t.Fatal("the deploy returned no model id; checks pin an id and there is nothing to pin")
	}
	t.Logf("deployed model %s:\n%s", modelID, m.String())
}

// Inheritance works: an organization admin is an admin of a workspace created
// AFTERWARDS, and it costs one tuple.
//
// # Why this is the test that matters
//
// It is the property the whole topology is chosen for. organization.md §5.1
// claims that because `workspace.parent = organization`, the owner and every org
// admin have admin rights on every workspace "present and future, with no
// fan-out". If that is false, the alternative is writing a tuple per admin per
// workspace — which is fan-out, is O(admins x workspaces), and is the design
// this one was picked over.
//
// It also exercises the whole pipeline end to end on the fragments' own terms:
// the vocabulary a module writes, through assembly, through the translation to
// OpenFGA's Usersets, to a live Check. A mistake anywhere in that chain shows up
// here as a denial.
//
// Organization's fragment is the REAL one now that the module exists, so this
// test exercises what ships rather than a copy of it. Workspace is still a local
// fixture — that module does not exist yet — and is replaced the same way when
// it lands.
func TestAnOrgAdminInheritsAdminOnAWorkspaceCreatedAfterwards(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	conn := dial(t)
	deployer, err := fgaadapter.NewDeployer(conn)
	if err != nil {
		t.Fatalf("NewDeployer: %v", err)
	}

	m, err := model.Assemble([]model.Fragment{
		{Module: "identity", Types: []model.Type{{Name: "user"}}},
		orgdomain.AccessFragment(),
		{Module: "workspace", Types: []model.Type{{
			Name: "workspace",
			Relations: []model.Relation{
				{Name: "parent", Direct: []model.TypeRef{{Type: "organization"}}},
				{
					Name:     "admin",
					Direct:   []model.TypeRef{{Type: "user"}},
					Inherits: []model.Inheritance{{Through: "parent", Relation: "admin"}},
				},
			},
		}}},
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	storeID := freshStore(t, ctx, deployer)
	modelID, err := deployer.Deploy(ctx, storeID, m)
	if err != nil {
		t.Fatalf("Deploy: %v\n\n%s", err, m.String())
	}

	writer, err := fgaadapter.NewWriter(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("NewWriter: %v", err)
	}
	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}

	alice := authz.Principal{Kind: authz.KindUser, ID: "alice"}
	org := authz.ResourceRef{Type: "organization", ID: "acme"}

	// Alice is an admin of the organization. ONE tuple, written BEFORE any
	// workspace exists.
	if err := writer.Write(ctx, []authz.Tuple{
		{Subject: authz.Subject{Principal: alice}, Relation: "admin", Resource: org},
	}); err != nil {
		t.Fatalf("granting org admin: %v", err)
	}

	// A workspace is created LATER and linked to the org. Also one tuple, and it
	// names no user at all.
	ws := authz.ResourceRef{Type: "workspace", ID: "eng"}
	if err := writer.Write(ctx, []authz.Tuple{
		{
			// An OBJECT subject, not a principal: an organization is not an actor.
			Subject:  authz.Subject{Object: authz.ResourceRef{Type: "organization", ID: "acme"}},
			Relation: "parent",
			Resource: ws,
		},
	}); err != nil {
		t.Fatalf("linking the workspace to its organization: %v", err)
	}

	decision, err := checker.Check(ctx, authz.Query{
		Principal: alice, Relation: "admin", Resource: ws,
	})
	if err != nil {
		t.Fatalf("Check: %v", err)
	}
	if !decision.Allowed() {
		t.Fatal("an organization admin is NOT an admin of a workspace in that organization. " +
			"The inheritance in organization.md §5.1 is what makes tenancy roles cost one " +
			"tuple instead of one per admin per workspace; without it the model has to " +
			"fan out, which is the design this one was chosen over")
	}

	// The negative half. Without it the test would pass against a model that
	// allowed everything, which is exactly what a broken `Direct` list produces.
	mallory := authz.Principal{Kind: authz.KindUser, ID: "mallory"}
	denied, err := checker.Check(ctx, authz.Query{
		Principal: mallory, Relation: "admin", Resource: ws,
	})
	if err != nil {
		t.Fatalf("Check (negative): %v", err)
	}
	if denied.Allowed() {
		t.Fatal("a user with no grant anywhere is an admin of the workspace; the model " +
			"admits everyone and every positive assertion above is worthless")
	}
}

// freshStore provisions an isolated store, so a previous run's tuples cannot
// make this one pass.
func freshStore(t *testing.T, ctx context.Context, d *fgaadapter.Deployer) string {
	t.Helper()
	name := "chronos-deploy-" + time.Now().UTC().Format("150405.000000000")
	id, err := d.EnsureStore(ctx, name)
	if err != nil {
		t.Fatalf("EnsureStore: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		conn := dial(t)
		_, _ = fgav1.NewOpenFGAServiceClient(conn).DeleteStore(c,
			&fgav1.DeleteStoreRequest{StoreId: id})
	})
	return id
}

// EnsureStore is idempotent by name: a second call finds the first store.
//
// If it created a second, tuples would land in one store and checks read the
// other — and the server would look perfectly healthy while denying everything.
func TestEnsureStoreIsIdempotent(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	conn := dial(t)
	deployer, err := fgaadapter.NewDeployer(conn)
	if err != nil {
		t.Fatalf("NewDeployer: %v", err)
	}

	name := "chronos-idem-" + time.Now().UTC().Format("150405.000000000")
	first, err := deployer.EnsureStore(ctx, name)
	if err != nil {
		t.Fatalf("EnsureStore (first): %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = fgav1.NewOpenFGAServiceClient(conn).DeleteStore(c,
			&fgav1.DeleteStoreRequest{StoreId: first})
	})

	second, err := deployer.EnsureStore(ctx, name)
	if err != nil {
		t.Fatalf("EnsureStore (second): %v", err)
	}
	if second != first {
		t.Errorf("EnsureStore created a SECOND store (%s then %s) for one name. Tuples would "+
			"be written to one and checks answered from the other, and every check would "+
			"deny while the server looked healthy", first, second)
	}
}
