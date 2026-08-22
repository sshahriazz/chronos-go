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

// A cardless trial that LAPSES suspends the tenant.
//
// # Why this test exists at all
//
// It is the single behaviour the whole cardless design rests on, and the one
// nothing else covers. Provisioning proves a trial STARTS. Cancelling a
// subscription proves the webhook path carries a status change. Neither proves
// that a trial nobody paid for actually ENDS — and if it does not, every trial
// org works forever for free, no error is raised, no metric moves, and the only
// signal is a finance question months later.
//
// # Why a Stripe test clock rather than a mocked status
//
// A mocked `paused` would assert that our mapping table maps `paused`, which
// TestEveryStripeStatusMaps already does without a network. What is unproven is
// that Stripe REACHES `paused` for a subscription this code creates — that
// `missing_payment_method: pause` was accepted, that no payment method was
// quietly attached, and that the trial has a real end. A test clock moves
// Stripe's own view of time, so the real subscription really does lapse.
func TestALapsedTrialSuspendsTheTenant(t *testing.T) {
	key := os.Getenv("STRIPE_SECRET_KEY")
	price := os.Getenv("STRIPE_TRIAL_PRICE_ID")
	if key == "" || price == "" {
		t.Skip("STRIPE_SECRET_KEY and STRIPE_TRIAL_PRICE_ID are not both set")
	}
	if strings.Contains(key, "_live_") {
		t.Fatal("STRIPE_SECRET_KEY is a LIVE key; test clocks do not exist in live mode and " +
			"this test creates real customers")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	sc := stripesdk.NewClient(key)

	// The clock starts NOW, so the trial's fourteen days are ahead of it.
	start := time.Now().UTC()
	testClock, err := sc.V1TestHelpersTestClocks.Create(ctx,
		&stripesdk.TestHelpersTestClockCreateParams{
			FrozenTime: stripesdk.Int64(start.Unix()),
			Name:       stripesdk.String("chronos trial lapse"),
		})
	if err != nil {
		t.Fatalf("creating a test clock: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		// Deleting the clock removes every customer and subscription on it, so
		// this test leaves nothing behind in the account.
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

	// The SAME provisioner production uses, pointed at the test clock. Building
	// the customer and subscription here instead would prove the test can create
	// a trial, not that this code does.
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

	// An organization, provisioned exactly as CreateOrganization leaves one.
	orgID := ids.New[ids.Org](time.Now(), ids.Entropy()).String()
	org, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("loading: %v", err)
	}
	slug := "lapse-" + strings.ToLower(ids.New[ids.Event](time.Now(), ids.Entropy()).String()[4:12])
	if err := org.Create(orgID, "Lapse", slug, "sub_alice", start); err != nil {
		t.Fatalf("Create: %v", err)
	}
	if _, err := repo.Save(ctx, domain.StreamKey(orgID), org, "lapse-"+orgID,
		eventsourcing.Metadata{OrgID: orgID, OccurredAt: start}); err != nil {
		t.Fatalf("appending the creation: %v", err)
	}

	sub, err := provisioner.Provision(ctx, orgID, "sub_alice")
	if err != nil {
		t.Fatalf("Provision: %v", err)
	}
	if err := trials.StartTrial(ctx, orgID, sub, "lapse-evt-"+orgID); err != nil {
		t.Fatalf("StartTrial: %v", err)
	}

	// Past the trial end. A day beyond, so the boundary is not the thing under
	// test — whether Stripe pauses is.
	advanceTo := sub.TrialEndsAt.Add(24 * time.Hour)
	if _, err := sc.V1TestHelpersTestClocks.Advance(ctx, testClock.ID,
		&stripesdk.TestHelpersTestClockAdvanceParams{
			FrozenTime: stripesdk.Int64(advanceTo.Unix()),
		}); err != nil {
		t.Fatalf("advancing the test clock: %v", err)
	}

	// Advancing is asynchronous: the clock reports `advancing` until Stripe has
	// re-run every schedule the jump crossed.
	waitForClock(ctx, t, sc, testClock.ID)

	current, err := sc.V1Subscriptions.Retrieve(ctx, sub.SubscriptionID, nil)
	if err != nil {
		t.Fatalf("re-fetching the subscription: %v", err)
	}
	if got := string(current.Status); got != "paused" {
		t.Fatalf("after the trial ended with no payment method the subscription is %q, want "+
			"paused. `missing_payment_method: pause` is what makes a lapsed cardless trial "+
			"recoverable rather than cancelled, and without it the tenant either keeps "+
			"working or is closed outright", got)
	}

	// Now the half this system owns: Stripe says paused, so the tenant suspends.
	if err := sync.Apply(ctx, app.SubscriptionState{
		OrgID:          orgID,
		SubscriptionID: sub.SubscriptionID,
		Status:         domain.StripeStatus(current.Status),
	}, "lapse-webhook-"+orgID); err != nil {
		t.Fatalf("applying the paused status: %v", err)
	}

	reloaded, err := repo.Load(ctx, domain.StreamKey(orgID))
	if err != nil {
		t.Fatalf("reloading: %v", err)
	}
	if got := reloaded.Status(); got != domain.StatusSuspended {
		t.Fatalf("the trial lapsed and the organization is %s, want suspended. It keeps "+
			"working, for free, and nothing anywhere says so", got)
	}

	// Suspended, not closed. The distinction is the whole reason `pause` was
	// chosen over `cancel`: closure opens the export window and starts retention
	// on somebody who merely forgot a card.
	if reloaded.Status() == domain.StatusClosed {
		t.Error("a lapsed trial CLOSED the organization; retention would begin on a customer " +
			"who has not left")
	}
	t.Logf("%s: trial ended -> stripe %s -> org %s", orgID, current.Status, reloaded.Status())
}

// waitForClock blocks until the test clock has finished advancing.
func waitForClock(ctx context.Context, t *testing.T, sc *stripesdk.Client, id string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Minute)
	for {
		clk, err := sc.V1TestHelpersTestClocks.Retrieve(ctx, id, nil)
		if err != nil {
			t.Fatalf("reading the test clock: %v", err)
		}
		if string(clk.Status) == "ready" {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("the test clock is still %q after two minutes", clk.Status)
		}
		time.Sleep(2 * time.Second)
	}
}
