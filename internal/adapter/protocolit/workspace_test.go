//go:build integration

package protocolit_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	organizationv1 "github.com/chronos/chronos-go/gen/proto/chronos/organization/v1"
	workspacev1 "github.com/chronos/chronos-go/gen/proto/chronos/workspace/v1"
	fgaadapter "github.com/chronos/chronos-go/internal/adapter/openfga"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	accessprojection "github.com/chronos/chronos-go/internal/modules/access/projection"
	orgapp "github.com/chronos/chronos-go/internal/modules/organization/app"
	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// THE TRIAL CAP BINDS: three workspaces succeed and the fourth is refused.
//
// # What this proves that nothing else does
//
// It is the first request in the system to traverse the WHOLE pipeline:
//
//	authn -> org-context -> authz -> subscription -> entitlement -> idempotency
//
// Every one of those gates had never run for a real request before
// `CreateWorkspace` existed, because every other RPC is self-scoped and declares
// no entitlement. Unit tests cover each gate's decision in isolation; only this
// shows them composing, in order, against real OpenFGA, real Postgres and a real
// Stripe subscription.
//
// # Why the reactors are driven directly
//
// The harness runs the API and the projectors, deliberately NOT cmd/worker: the
// worker's verification-mail reactor mints a fresh token for every registration
// and every issuance revokes the outstanding one, so a live worker destroys this
// package's own fixtures. The two reactors this test needs are therefore invoked
// here — the same code cmd/worker runs, without a second process competing for
// the log.
func TestTheTrialWorkspaceCapBinds(t *testing.T) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	price := os.Getenv("STRIPE_TRIAL_PRICE_ID")
	storeID := os.Getenv("OPENFGA_STORE_ID")
	if key == "" || price == "" || storeID == "" {
		t.Skip("STRIPE_SECRET_KEY, STRIPE_TRIAL_PRICE_ID and OPENFGA_STORE_ID must all be set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key")
	}

	ctx, cancel := context.WithTimeout(t.Context(), 3*time.Minute)
	defer cancel()

	account := h.disposableAccount(t, "ws-cap")

	// 1. Create the organization through the API.
	created, err := h.organization.CreateOrganization(ctx,
		authed(&organizationv1.CreateOrganizationRequest{
			Name: "Cap Test", Slug: h.freshSlug(),
		}, account.bearer))
	if err != nil {
		t.Fatalf("CreateOrganization: %v\n%s", err, h.serverLogs())
	}
	orgID := created.Msg.GetOrgId()

	// 2. Provision it, as cmd/worker's reactor would. Until this runs the
	//    organization is `provisioning`, where gate 3 refuses GROW outright —
	//    which is itself part of the design, and is asserted below.
	h.provision(t, ctx, orgID, account.subjectID)

	// 3. Grant the owner tuple, as the access projector would. Without it gate 2
	//    asks OpenFGA and gets a denial from an empty graph.
	h.grantOwner(t, ctx, orgID, account.subjectID)

	// 4. Wait for the projections gates 1 and 3 read.
	h.awaitOrgStatus(t, ctx, orgID, "trialing")

	//    And the MEMBERSHIP, which is a SEPARATE projection with its own
	//    checkpoint. Waiting only for the status is not enough: gate 1 reads
	//    org_member_index, and a request arriving between the two projections
	//    catching up is refused NOT_FOUND — which is indistinguishable from
	//    "that organization is not yours".
	h.awaitOrgMember(t, ctx, orgID, account.subjectID)

	// 5. Three workspaces: the trial's cap.
	for i := 1; i <= 3; i++ {
		res, err := h.workspace.CreateWorkspace(ctx,
			authed(&workspacev1.CreateWorkspaceRequest{
				Name: "Workspace " + string(rune('A'+i-1)),
			}, account.bearer))
		if err != nil {
			t.Fatalf("workspace %d of 3 was refused: %v\n%s", i, err, h.serverLogs())
		}
		if !strings.HasPrefix(res.Msg.GetWorkspaceId(), "ws_") {
			t.Errorf("workspace id %q is not a prefixed ULID", res.Msg.GetWorkspaceId())
		}
	}

	// 6. The fourth is refused, and for the RIGHT reason.
	_, err = h.workspace.CreateWorkspace(ctx,
		authed(&workspacev1.CreateWorkspaceRequest{Name: "One Too Many"}, account.bearer))
	if err == nil {
		t.Fatal("a fourth workspace was created on a trial that grants three. The cap does " +
			"not bind, and a free signup can consume unbounded infrastructure")
	}
	reason, ok := reasonOf(err)
	if !ok {
		t.Fatalf("the refusal carries no chronos.errors.v1.ErrorDetail, so a client cannot "+
			"tell a quota problem from a permissions one: %v", err)
	}
	if reason != string(errs.QuotaExceeded) {
		t.Errorf("the fourth workspace was refused with reason %q, want %q. A customer needs "+
			"to be told to upgrade, not that they lack permission", reason, errs.QuotaExceeded)
	}
}

// provision runs the provisioning use case, exactly as cmd/worker's reactor does.
func (hh *harness) provision(t *testing.T, ctx context.Context, orgID, ownerSubject string) {
	t.Helper()

	repo := eventsourcing.NewRepository[*orgdomain.Organization](
		hh.store, hh.codec, hh.upcasters, orgdomain.Category, orgdomain.NewOrganization)

	provisioner, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: os.Getenv("STRIPE_SECRET_KEY"),
		PriceID:   os.Getenv("STRIPE_TRIAL_PRICE_ID"),
		TrialDays: 14,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	trials, err := orgapp.NewTrials(orgapp.TrialsDeps{Repo: repo, Now: clock.System{}.Now})
	if err != nil {
		t.Fatalf("NewTrials: %v", err)
	}
	provisioning, err := orgapp.NewProvisioning(orgapp.ProvisioningDeps{
		Provisioner: provisioner, Trials: trials,
	})
	if err != nil {
		t.Fatalf("NewProvisioning: %v", err)
	}
	if err := provisioning.Provision(ctx, orgID, ownerSubject, "cap-test-"+orgID); err != nil {
		t.Fatalf("provisioning %s: %v", orgID, err)
	}
}

// grantOwner runs the access projector over the creation event, as cmd/worker
// does, so gate 2 has a graph to answer from.
func (hh *harness) grantOwner(t *testing.T, ctx context.Context, orgID, ownerSubject string) {
	t.Helper()

	conn, err := fgaadapter.Dial(
		endpointOr("localhost:8081"),
		os.Getenv("OPENFGA_PRESHARED_KEY"))
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

	created := &orgcontract.OrganizationCreated{
		OrgID: orgID, OwnerID: ownerSubject, CreatedAt: time.Now().UTC(),
	}
	payload, err := hh.codec.Marshal(created)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}
	if err := tuples.React(ctx, eventsourcing.Envelope{
		ID:      ids.New[ids.Event](time.Now(), ids.Entropy()),
		Type:    created.EventType(),
		Payload: payload,
		Live:    true,
	}); err != nil {
		t.Fatalf("writing the owner tuple: %v", err)
	}

	// VERIFY it landed. React returns nil for an event it does not recognise —
	// which is correct for the many events that grant nothing, and means a
	// decode that produced an unexpected type is silently indistinguishable from
	// success. Without this check the failure surfaces three steps later as a
	// NOT_FOUND from gate 2, which reads as a permissions problem.
	checker, err := fgaadapter.New(conn, fgaadapter.Config{
		StoreID: os.Getenv("OPENFGA_STORE_ID"),
		ModelID: os.Getenv("OPENFGA_MODEL_ID"),
	})
	if err != nil {
		t.Fatalf("NewChecker: %v", err)
	}
	decision, err := checker.Check(ctx, authz.Query{
		Principal: authz.Principal{Kind: authz.KindUser, ID: ownerSubject},
		Relation:  "admin",
		Resource:  authz.ResourceRef{Type: "organization", ID: orgID},
	})
	if err != nil {
		t.Fatalf("checking the owner tuple: %v", err)
	}
	if !decision.Allowed() {
		t.Fatalf("the access projector reported success and %s is NOT an admin of %s. "+
			"React returns nil for an event it does not recognise, so a decode producing an "+
			"unexpected type looks exactly like a grant that was not needed",
			ownerSubject, orgID)
	}
}

// endpointOr reads the OpenFGA endpoint, defaulting to the local stack.
func endpointOr(def string) string {
	if v := os.Getenv("OPENFGA_ENDPOINT"); v != "" {
		return v
	}
	return def
}

// awaitOrgMember blocks until the membership projection has the caller.
//
// org_member_index carries NO row security — gate 1 reads it before any tenant
// scope exists, which is the whole point of migration 00021's comment — so this
// reads in a system transaction, unlike awaitOrgStatus below.
func (hh *harness) awaitOrgMember(t *testing.T, ctx context.Context, orgID, subjectID string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		var role string
		err := hh.pg.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT role FROM org_member_index WHERE org_id = $1 AND subject_id = $2`,
				orgID, subjectID).Scan(&role)
		})
		if err == nil && role != "" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("org_member_index has no row for %s in %s after 60s; gate 1 would "+
				"refuse every request as NOT_FOUND (err: %v)", subjectID, orgID, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// awaitOrgStatus blocks until the status projection reports what is expected.
func (hh *harness) awaitOrgStatus(t *testing.T, ctx context.Context, orgID, want string) {
	t.Helper()

	deadline := time.Now().Add(60 * time.Second)
	for {
		var status string
		// A TENANT transaction. org_status_view carries
		// `USING (org_id = current_setting('app.org_id', true))`, so an UNSCOPED
		// read returns nothing and looks exactly like "the projector has not
		// caught up" — which is how this test first failed, waiting sixty
		// seconds for a row that had been written immediately.
		scoped := db.WithTenant(ctx, db.Tenant{OrgID: orgID, UserID: "sub_probe"})
		err := hh.pg.InTenantTx(scoped, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT status FROM org_status_view WHERE org_id = $1`, orgID).Scan(&status)
		})
		if err == nil && status == want {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("org_status_view still reports %q for %s after 60s, want %q "+
				"(err: %v)", status, orgID, want, err)
		}
		time.Sleep(200 * time.Millisecond)
	}
}
