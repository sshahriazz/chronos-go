package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/app"
)

type recordingProvisioner struct {
	calls int
	sub   app.Subscription
	err   error
}

func (r *recordingProvisioner) Provision(context.Context, string, string) (app.Subscription, error) {
	r.calls++
	return r.sub, r.err
}

type recordingTrials struct {
	calls int
	got   app.Subscription
	err   error
}

func (r *recordingTrials) StartTrial(
	_ context.Context, _ string, sub app.Subscription, _ string,
) error {
	r.calls++
	r.got = sub
	return r.err
}

func subscription() app.Subscription {
	return app.Subscription{
		CustomerID:     "cus_1",
		SubscriptionID: "sub_1",
		TrialEndsAt:    time.Date(2026, 9, 5, 0, 0, 0, 0, time.UTC),
	}
}

// The billing objects are created BEFORE the event is appended.
//
// # Why the order is not arbitrary
//
// Either order leaves a window, and they are not equally bad.
//
// Stripe-then-event: the objects exist and the event does not, because the
// process died between them. The reactor runs again, the provisioner finds the
// SAME objects by our id in Stripe's metadata, and the append happens. It
// converges.
//
// Event-then-Stripe: the organization is `trialing` with no subscription behind
// it. No trial clock, no `trial_will_end`, nothing to pause when it lapses — a
// free forever account that nothing alarms on. That is the exact failure the
// scope document names as the reason `Provisioning` exists at all.
//
// So this asserts that a failed provisioner appends NOTHING.
func TestNoTrialIsRecordedWhenProvisioningFails(t *testing.T) {
	t.Parallel()

	provisioner := &recordingProvisioner{err: errors.New("stripe is down")}
	trials := &recordingTrials{}

	provisioning, err := app.NewProvisioning(app.ProvisioningDeps{
		Provisioner: provisioner, Trials: trials,
	})
	if err != nil {
		t.Fatalf("NewProvisioning: %v", err)
	}

	if err := provisioning.Provision(t.Context(), "org_1", "sub_alice", "evt_1"); err == nil {
		t.Fatal("a failed provisioner reported success")
	}
	if trials.calls != 0 {
		t.Error("the trial was recorded although no subscription was created. The " +
			"organization is now `trialing` with nothing behind it: no trial clock, no " +
			"trial_will_end, and nothing to pause when it lapses")
	}
}

// The subscription Stripe returned is the one recorded — unchanged.
//
// The trial deadline in particular is STRIPE's answer. Recomputing it locally
// would give one trial two clocks that can disagree, and the one that matters is
// the one that will actually pause the subscription.
func TestTheSubscriptionStripeReturnedIsWhatIsRecorded(t *testing.T) {
	t.Parallel()

	want := subscription()
	provisioner := &recordingProvisioner{sub: want}
	trials := &recordingTrials{}

	provisioning, err := app.NewProvisioning(app.ProvisioningDeps{
		Provisioner: provisioner, Trials: trials,
	})
	if err != nil {
		t.Fatalf("NewProvisioning: %v", err)
	}
	if err := provisioning.Provision(t.Context(), "org_1", "sub_alice", "evt_1"); err != nil {
		t.Fatalf("Provision: %v", err)
	}

	if trials.got != want {
		t.Errorf("recorded %+v, want %+v", trials.got, want)
	}
	if !trials.got.TrialEndsAt.Equal(want.TrialEndsAt) {
		t.Error("the trial deadline was rewritten; it is Stripe's answer, and a local one " +
			"can disagree with the clock that will actually pause the subscription")
	}
}

// A failed append is reported, so the reactor retries.
//
// The Stripe objects already exist at this point. Reporting success would leave
// the organization in `provisioning` forever with a paid-for subscription
// attached to it and nothing to make them agree.
func TestAFailedAppendIsReported(t *testing.T) {
	t.Parallel()

	provisioning, err := app.NewProvisioning(app.ProvisioningDeps{
		Provisioner: &recordingProvisioner{sub: subscription()},
		Trials:      &recordingTrials{err: errors.New("append failed")},
	})
	if err != nil {
		t.Fatalf("NewProvisioning: %v", err)
	}

	got := provisioning.Provision(t.Context(), "org_1", "sub_alice", "evt_1")
	if got == nil {
		t.Fatal("a failed append reported success; the organization stays in `provisioning` " +
			"forever with a live Stripe subscription behind it")
	}
	if !strings.Contains(got.Error(), "org_1") {
		t.Errorf("the error does not name the organization, so the log line is not "+
			"actionable: %v", got)
	}
}

// Neither dependency is optional.
func TestProvisioningRefusesToBeBuiltHalfWired(t *testing.T) {
	t.Parallel()

	if _, err := app.NewProvisioning(app.ProvisioningDeps{
		Trials: &recordingTrials{},
	}); err == nil {
		t.Error("provisioning was built with no provisioner; every organization would stay " +
			"in `provisioning` forever")
	}
	if _, err := app.NewProvisioning(app.ProvisioningDeps{
		Provisioner: &recordingProvisioner{},
	}); err == nil {
		t.Error("provisioning was built with no trial starter")
	}
}
