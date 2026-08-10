//go:build integration

package openfga_test

import (
	"context"
	"os"
	"testing"
	"time"

	fgav1 "github.com/chronos/chronos-go/gen/thirdparty/openfga/v1"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"google.golang.org/grpc"
)

func endpoint() string {
	if v := os.Getenv("OPENFGA_ENDPOINT"); v != "" {
		return v
	}
	return "localhost:8081"
}

func presharedKey() string {
	if v := os.Getenv("OPENFGA_PRESHARED_KEY"); v != "" {
		return v
	}
	return "chronos_dev_openfga_key"
}

func dial(t *testing.T) *grpc.ClientConn {
	t.Helper()
	conn, err := fgaadapter.Dial(endpoint(), presharedKey())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// store creates a store and writes a small model, returning both ids.
//
// A fresh store per run: a shared one would let a previous run's tuples make
// this one pass.
func store(t *testing.T, conn *grpc.ClientConn) (storeID, modelID string) {
	t.Helper()
	client := fgav1.NewOpenFGAServiceClient(conn)
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	created, err := client.CreateStore(ctx, &fgav1.CreateStoreRequest{
		Name: "chronos-test-" + time.Now().UTC().Format("150405.000000000"),
	})
	if err != nil {
		t.Fatalf("create store (is OPENFGA_PRESHARED_KEY right?): %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		_, _ = client.DeleteStore(c, &fgav1.DeleteStoreRequest{StoreId: created.GetId()})
	})

	// folder.parent : [folder] is self-referential, which is what gives
	// arbitrary nesting depth from a fixed model (access.md §3). viewer includes
	// editor, so role implication is encoded once and no caller checks two
	// relations.
	model, err := client.WriteAuthorizationModel(ctx, &fgav1.WriteAuthorizationModelRequest{
		StoreId:       created.GetId(),
		SchemaVersion: "1.1",
		TypeDefinitions: []*fgav1.TypeDefinition{
			{Type: "user"},
			{
				Type: "folder",
				Relations: map[string]*fgav1.Userset{
					"parent": {Userset: &fgav1.Userset_This{This: &fgav1.DirectUserset{}}},
					"editor": {Userset: &fgav1.Userset_This{This: &fgav1.DirectUserset{}}},
					"viewer": {Userset: &fgav1.Userset_Union{Union: &fgav1.Usersets{
						Child: []*fgav1.Userset{
							{Userset: &fgav1.Userset_This{This: &fgav1.DirectUserset{}}},
							{Userset: &fgav1.Userset_ComputedUserset{
								ComputedUserset: &fgav1.ObjectRelation{Relation: "editor"},
							}},
							{Userset: &fgav1.Userset_TupleToUserset{
								TupleToUserset: &fgav1.TupleToUserset{
									Tupleset:        &fgav1.ObjectRelation{Relation: "parent"},
									ComputedUserset: &fgav1.ObjectRelation{Relation: "viewer"},
								},
							}},
						},
					}}},
				},
				Metadata: &fgav1.Metadata{
					Relations: map[string]*fgav1.RelationMetadata{
						"parent": {DirectlyRelatedUserTypes: []*fgav1.RelationReference{{Type: "folder"}}},
						"editor": {DirectlyRelatedUserTypes: []*fgav1.RelationReference{{Type: "user"}}},
						"viewer": {DirectlyRelatedUserTypes: []*fgav1.RelationReference{{Type: "user"}}},
					},
				},
			},
		},
	})
	if err != nil {
		t.Fatalf("write model: %v", err)
	}
	return created.GetId(), model.GetAuthorizationModelId()
}

func write(t *testing.T, conn *grpc.ClientConn, storeID, modelID string, tuples ...*fgav1.TupleKey) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	_, err := fgav1.NewOpenFGAServiceClient(conn).Write(ctx, &fgav1.WriteRequest{
		StoreId:              storeID,
		AuthorizationModelId: modelID,
		Writes:               &fgav1.WriteRequestWrites{TupleKeys: tuples},
	})
	if err != nil {
		t.Fatalf("write tuples: %v", err)
	}
}

func tuple(user, relation, object string) *fgav1.TupleKey {
	return &fgav1.TupleKey{User: user, Relation: relation, Object: object}
}

func user(id string) authz.Principal {
	return authz.Principal{Kind: authz.KindUser, ID: id}
}

// The gRPC client works end to end: a direct grant is permitted and an absent
// one is refused.
//
// This is also the test that proves the pre-shared key is attached. Without it
// the server refuses even reflection with "missing bearer token", so store
// creation above would already have failed.
func TestCheckOverGRPC(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	write(t, conn, storeID, modelID, tuple("user:alice", "editor", "folder:docs"))

	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}
	ctx := context.Background()

	d, err := checker.Check(ctx, authz.Query{
		Principal: user("alice"), Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "docs"},
	})
	if err != nil || !d.Allowed() {
		t.Fatalf("alice should edit folder:docs, got %s (err=%v)", d, err)
	}

	d, err = checker.Check(ctx, authz.Query{
		Principal: user("bob"), Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "docs"},
	})
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if d.Allowed() {
		t.Fatal("bob has no tuple yet was permitted")
	}
}

// Role implication and inheritance are encoded in the model, not in callers.
// An editor is always a viewer, and viewer descends through parent — which is
// what lets arbitrary nesting work from a fixed model.
func TestInheritedAndImpliedAccess(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	write(t, conn, storeID, modelID,
		tuple("user:alice", "editor", "folder:root"),
		tuple("folder:root", "parent", "folder:projects"),
		tuple("folder:projects", "parent", "folder:q3"),
	)

	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}

	// Implied: editor ⇒ viewer, with no second check by the caller.
	d, err := checker.Check(context.Background(), authz.Query{
		Principal: user("alice"), Relation: "viewer",
		Resource: authz.ResourceRef{Type: "folder", ID: "root"},
	})
	if err != nil || !d.Allowed() {
		t.Fatalf("editor must imply viewer, got %s (err=%v)", d, err)
	}

	// Inherited two levels down.
	d, err = checker.Check(context.Background(), authz.Query{
		Principal: user("alice"), Relation: "viewer",
		Resource: authz.ResourceRef{Type: "folder", ID: "q3"},
	})
	if err != nil || !d.Allowed() {
		t.Fatalf("viewer must descend through parent, got %s (err=%v)", d, err)
	}
}

// BatchCheck must answer every question, matched to the right one.
//
// OpenFGA does not promise response ORDER, so the adapter correlates by id.
// Trusting arrival order would attach one resource's answer to another — a
// permit for the wrong object, which no test of a uniform batch would catch.
// Hence a batch whose answers deliberately differ.
func TestBatchCheckAnswersAreMatchedToTheirQuestions(t *testing.T) {
	conn := dial(t)
	storeID, modelID := store(t, conn)
	write(t, conn, storeID, modelID,
		tuple("user:alice", "editor", "folder:a"),
		tuple("user:alice", "editor", "folder:c"),
	)

	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: storeID, ModelID: modelID})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}

	qs := []authz.Query{
		{Principal: user("alice"), Relation: "editor", Resource: authz.ResourceRef{Type: "folder", ID: "a"}},
		{Principal: user("alice"), Relation: "editor", Resource: authz.ResourceRef{Type: "folder", ID: "b"}},
		{Principal: user("alice"), Relation: "editor", Resource: authz.ResourceRef{Type: "folder", ID: "c"}},
		{Principal: user("alice"), Relation: "editor", Resource: authz.ResourceRef{Type: "folder", ID: "d"}},
	}
	want := []bool{true, false, true, false}

	got, err := checker.BatchCheck(context.Background(), qs)
	if err != nil {
		t.Fatalf("batch: %v", err)
	}
	if len(got) != len(qs) {
		t.Fatalf("got %d answers for %d questions", len(got), len(qs))
	}
	for i := range qs {
		if got[i].Allowed() != want[i] {
			t.Errorf("folder:%s answered %s, want allowed=%v — answers are attached to "+
				"the wrong questions", qs[i].Resource.ID, got[i], want[i])
		}
	}
}

// A checker with no store id would evaluate every check against no tuples at
// all — permitting nothing, but for a reason nobody could find.
func TestCheckerRequiresAStore(t *testing.T) {
	if _, err := fgaadapter.New(dial(t), fgaadapter.Config{}); err == nil {
		t.Fatal("a checker with no store id must be refused")
	}
}

// The whole point of the kernel: an unreachable authorization service DENIES.
// Verified against a real dial to a port nothing is listening on, rather than
// against a stub that returns an error.
func TestUnreachableServiceDenies(t *testing.T) {
	conn, err := fgaadapter.Dial("localhost:59999", presharedKey())
	if err != nil {
		t.Fatalf("dial: %v", err)
	}
	defer func() { _ = conn.Close() }()

	checker, err := fgaadapter.New(conn, fgaadapter.Config{StoreID: "store"})
	if err != nil {
		t.Fatalf("new checker: %v", err)
	}
	guard, err := authz.NewGuard(authz.GuardDeps{Checker: checker})
	if err != nil {
		t.Fatalf("guard: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	d := guard.Check(ctx, authz.Query{
		Principal: user("alice"), Relation: "editor",
		Resource: authz.ResourceRef{Type: "folder", ID: "docs"},
	})
	if d.Allowed() {
		t.Fatal("an unreachable authorization service permitted access: an outage is now " +
			"a privilege-escalation path")
	}
}
