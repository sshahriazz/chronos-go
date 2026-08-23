//go:build integration

package reactor_test

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	stripesdk "github.com/stripe/stripe-go/v86"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	kurrentadapter "github.com/chronos/chronos-go/internal/adapter/kurrentdb"
	stripeadapter "github.com/chronos/chronos-go/internal/adapter/stripe"
	"github.com/chronos/chronos-go/internal/modules/organization"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// A CARD ADDED MID-TRIAL CONVERTS THE TRIAL AUTOMATICALLY.
//
// # This answers BILLING-PLAN.md §9.3, which was an open question
//
// The plan asked: "Does the trial convert automatically at trial end when a card
// was added mid-trial? Stripe's default is yes — that is what a trial is. Worth
// confirming it is what we want rather than inheriting it."
//
// Inheriting a default is exactly how a billing system acquires behaviour nobody
// chose, so this CONFIRMS it against the real API rather than reasoning from the
// documentation. What is under test is not our mapping — TestEveryStripeStatusMaps
// covers that offline — but that a subscription THIS CODE created, with
// `missing_payment_method: pause` set, still converts when a payment method is
// present. The pause behaviour and the convert behaviour are configured by the
// same field, and it would be entirely possible for the first to suppress the
// second.
//
// It is the mirror of TestALapsedTrialSuspendsTheTenant: same provisioner, same
// clock mechanism, one difference — a card.
func TestATrialWithACardConvertsToActive(t *testing.T) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	price := os.Getenv("STRIPE_TRIAL_PRICE_ID")
	if key == "" || price == "" {
		t.Skip("STRIPE_SECRET_KEY and STRIPE_TRIAL_PRICE_ID are not both set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; this test attaches a payment method and " +
			"lets a subscription bill")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sc := stripesdk.NewClient(key)

	start := time.Now().UTC()
	testClock, err := sc.V1TestHelpersTestClocks.Create(ctx,
		&stripesdk.TestHelpersTestClockCreateParams{
			FrozenTime: stripesdk.Int64(start.Unix()),
			Name:       stripesdk.String("chronos trial convert"),
		})
	if err != nil {
		t.Fatalf("creating a test clock: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_, _ = sc.V1TestHelpersTestClocks.Delete(c, testClock.ID, nil)
	})

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

	// The SAME provisioner production uses, so what converts is the subscription
	// this system creates rather than one the test built to be convertible.
	provisioner, err := stripeadapter.NewProvisioner(stripeadapter.Config{
		SecretKey: key, PriceID: price, TrialDays: 14, TestClockID: testClock.ID,
	})
	if err != nil {
		t.Fatalf("NewProvisioner: %v", err)
	}
	trials, err := app.NewTrials(app.TrialsDeps{Repo: repo, Now: clock.System{}.Now})
	if err != nil {
		t.Fatalf("NewTrials: %v", err)
	}
	sync, err := app.NewSubscriptionSync(app.SubscriptionSyncDeps{
		Repo: repo, Now: clock.System{}.Now,
	})
	if err != nil {
		t.Fatalf("NewSubscriptionSync: %v", err)
	}

	orgID := ids.New[ids.Org](time.Now(), ids.Entropy()).String()
	org, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	slug := "conv-" + strings.ToLower(ids.New[ids.Event](time.Now(), ids.Entropy()).String()[4:12])
	if err := org.Create(orgID, "Convert", slug, "sub_alice", start); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Save(ctx, domain.StreamKey(orgID), org, "conv-"+orgID,
		eventsourcing.Metadata{OrgID: orgID, OccurredAt: start}); err != nil {
		t.Fatalf("appending the creation: %v", err)
	}

	sub, err := provisioner.Provision(ctx, orgID, "sub_alice")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := trials.StartTrial(ctx, orgID, sub, "conv-evt-"+orgID); err != nil {
		t.Fatalf("StartTrial: %v", err)
	}

	// THE CARD, attached mid-trial and made the subscription's default.
	//
	// `pm_card_visa` is Stripe's own test token. Attaching a payment method to
	// the CUSTOMER is not enough on its own — the subscription bills its own
	// default first — so both steps are here, and they are what the Customer
	// Portal does on the customer's behalf in production.
	pm, err := sc.V1PaymentMethods.Attach(ctx, "pm_card_visa",
		&stripesdk.PaymentMethodAttachParams{Customer: stripesdk.String(sub.CustomerID)})
	if err != nil {
		t.Fatalf("attaching a payment method: %v", err)
	}
	if _, err := sc.V1Subscriptions.Update(ctx, sub.SubscriptionID,
		&stripesdk.SubscriptionUpdateParams{
			DefaultPaymentMethod: stripesdk.String(pm.ID),
		}); err != nil {
		t.Fatalf("setting the default payment method: %v", err)
	}

	// Past the trial end, a day beyond so the boundary is not the thing tested.
	advanceTo := sub.TrialEndsAt.Add(24 * time.Hour)
	if _, err := sc.V1TestHelpersTestClocks.Advance(ctx, testClock.ID,
		&stripesdk.TestHelpersTestClockAdvanceParams{
			FrozenTime: stripesdk.Int64(advanceTo.Unix()),
		}); err != nil {
		t.Fatalf("advancing the test clock: %v", err)
	}
	waitForClock(ctx, t, sc, testClock.ID)

	current, err := sc.V1Subscriptions.Retrieve(ctx, sub.SubscriptionID, nil)
	if err != nil {
		t.Fatalf("re-fetching the subscription: %v", err)
	}
	if got := string(current.Status); got != "active" {
		t.Fatalf("a trial with a payment method ended as %q, want active. §9.3 assumed "+
			"Stripe's default converts; if it does not, every customer who added a card "+
			"during their trial is suspended at the end of it", got)
	}

	// THE SAME SUBSCRIPTION, which billing.md §5 case 25 requires: the id is
	// stable for the organization's whole life, so billing history stays
	// continuous and our mirror needs no re-keying.
	if current.ID != sub.SubscriptionID {
		t.Errorf("the subscription id changed from %s to %s across conversion",
			sub.SubscriptionID, current.ID)
	}

	// And the half this system owns.
	if err := sync.Apply(ctx, app.SubscriptionState{
		OrgID:          orgID,
		SubscriptionID: sub.SubscriptionID,
		Status:         domain.StripeStatus(current.Status),
	}, "conv-webhook-"+orgID); err != nil {
		t.Fatalf("applying the active status: %v", err)
	}

	reloaded, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if got := reloaded.Status(); got != domain.StatusActive {
		t.Fatalf("the trial converted and the organization is %s, want active. A paying "+
			"customer is locked out of what they just paid for", got)
	}
	t.Logf("%s: card added -> trial ended -> stripe %s -> org %s (subscription %s unchanged)",
		orgID, current.Status, reloaded.Status(), current.ID)
}
