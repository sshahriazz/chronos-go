//go:build integration

package reactor_test

import (
	"context"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	"github.com/chronos/chronos-go/internal/modules/organization"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	orgreactor "github.com/chronos/chronos-go/internal/modules/organization/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// The whole provisioning loop, against real Stripe and real KurrentDB.
//
// # Why the reactor is driven directly rather than through cmd/worker
//
// Running the worker alongside a test is not a neutral act, and finding that out
// is worth recording. Its verification reactor consumes
// EmailVerificationRequested and mints a FRESH token — and every issuance
// revokes the outstanding one, deliberately, so there is never more than one live
// link. A test that mints its own token and then verifies is therefore racing a
// running worker, and loses: `this verification link is no longer valid`.
//
// So the reactor is constructed here and handed the envelope directly. That
// exercises everything that matters — the Stripe call, the aggregate transition,
// the atomic append — without a second process quietly competing for the same
// log.
//
// # Why the assertion is against the EVENT LOG and not the projection
//
// ADR-052: assert against the log, never a projection. The projection is written
// by cmd/projector, which this test does not run, and a test that waited for a
// row would be asserting that a different process happened to be up.
func TestProvisioningReachesTrialing(t *testing.T) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	price := os.Getenv("STRIPE_TRIAL_PRICE_ID")
	if key == "" || price == "" {
		t.Skip("STRIPE_SECRET_KEY and STRIPE_TRIAL_PRICE_ID are not both set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; this test creates real customers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()

	upcasters := eventsourcing.NewUpcasterRegistry()
	organization.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	organization.RegisterEvents(codec)

	client, err := kurrentadapter.Dial(kurrentDSN())
	if err != nil {
		t.Fatalf("kurrentdb: %v", err)
	}
	t.Cleanup(func() { _ = client.Close() })
	store := kurrentadapter.NewStore(client, codec)

	repo := eventsourcing.NewRepository[*domain.Organization](
		store, codec, upcasters, domain.Category, domain.NewOrganization)

	provisioner, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: key, PriceID: price, TrialDays: 14,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	trials, err := app.NewTrials(app.TrialsDeps{Repo: repo, Now: clock.System{}.Now})
	if err != nil {
		t.Fatalf("NewTrials: %v", err)
	}
	provisioning, err := app.NewProvisioning(app.ProvisioningDeps{
		Provisioner: provisioner, Trials: trials,
	})
	if err != nil {
		t.Fatalf("NewProvisioning: %v", err)
	}
	react, err := orgreactor.NewProvision(provisioning, codec, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("NewProvision: %v", err)
	}

	// An organization exactly as CreateOrganization leaves it.
	orgID := ids.New[ids.Org](time.Now(), ids.Entropy()).String()
	// Loaded rather than constructed: Load positions an empty aggregate BEFORE
	// the first event, which is what makes the append expect NoStream. A bare
	// struct claims to be at revision 0, and the append then expects a stream
	// that already has one event in it.
	org, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("loading the empty aggregate: %v", err)
	}
	now := time.Now().UTC()
	slug := "acme-" + strings.ToLower(ids.New[ids.Event](time.Now(), ids.Entropy()).String()[4:12])
	if err := org.Create(orgID, "Acme", slug, "sub_alice", now); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Save(ctx, domain.StreamKey(orgID), org, "provision-test-"+orgID,
		eventsourcing.Metadata{OrgID: orgID, OccurredAt: now}); err != nil {
		t.Fatalf("appending the creation: %v", err)
	}

	created := &contract.OrganizationCreated{
		OrgID: orgID, Name: "Acme", Slug: slug, OwnerID: "sub_alice", CreatedAt: now,
	}
	payload, err := codec.Marshal(created)
	if err != nil {
		t.Fatalf("marshalling: %v", err)
	}

	env := eventsourcing.Envelope{
		ID:      ids.New[ids.Event](time.Now(), ids.Entropy()),
		Type:    created.EventType(),
		Payload: payload,
		Live:    true,
	}
	if err := react.React(ctx, env); err != nil {
		t.Fatalf("React: %v\nthe organization stays in `provisioning` and is unusable", err)
	}

	// The LOG is the fact.
	reloaded, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("reloading %s: %v", orgID, err)
	}
	if got := reloaded.Status(); got != domain.StatusTrialing {
		t.Fatalf("after provisioning the organization is %s, want trialing", got)
	}
	if !strings.HasPrefix(reloaded.StripeSubscriptionID(), "sub_") {
		t.Errorf("the subscription id %q was not recorded; no webhook could ever be matched "+
			"back to this organization", reloaded.StripeSubscriptionID())
	}
	if reloaded.TrialEndsAt().IsZero() {
		t.Error("no trial deadline was recorded")
	}
	t.Logf("%s -> %s, subscription %s, trial ends %s",
		orgID, reloaded.Status(), reloaded.StripeSubscriptionID(),
		reloaded.TrialEndsAt().Format(time.RFC3339))

	// A REDELIVERY must be harmless. Delivery is at-least-once, and this is the
	// second run every reactor eventually gets.
	if err := react.React(ctx, env); err != nil {
		t.Fatalf("a redelivery failed: %v. The event would be retried until it parked, and "+
			"an operator would investigate work that had already succeeded", err)
	}
	again, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("reloading after the redelivery: %v", err)
	}
	if again.StripeSubscriptionID() != reloaded.StripeSubscriptionID() {
		t.Errorf("a redelivery changed the subscription from %s to %s; the customer now has "+
			"two", reloaded.StripeSubscriptionID(), again.StripeSubscriptionID())
	}
	if again.Version() != reloaded.Version() {
		t.Errorf("a redelivery appended another event (revision %d then %d); the log now "+
			"records two trials for one organization", reloaded.Version(), again.Version())
	}
}

func kurrentDSN() string {
	if v := os.Getenv("KURRENTDB_CONNECTION_STRING"); v != "" {
		return v
	}
	return "kurrentdb://localhost:2113?tls=false"
}
