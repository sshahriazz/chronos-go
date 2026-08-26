package main

import (
	"context"
	"log/slog"
	"slices"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// Every test in this repository passed while three notification channels were
// DEAD CODE and two dispatcher ports were nil.
//
// The unit tests construct their subjects directly, so they proved the in-app
// transport, the push transport and the preference reader all work — while the
// running binary wired none of them. A per-user channel toggle silently did
// nothing, because a nil Preferences port is permissive.
//
// Component tests cannot catch that. Only a test of the COMPOSITION ROOT can,
// which is what this is.
func TestDispatcherIsFullyWired(t *testing.T) {
	cfg := testConfig(t)
	log := slog.New(slog.DiscardHandler)

	d, closeAll := newDependencies(cfg, log, newCodec())
	defer closeAll()

	if d.notify == nil {
		t.Fatal("no dispatcher was constructed")
	}

	wired := d.notify.Channels()
	for _, required := range []notify.Channel{
		notify.ChannelEmail,
		notify.ChannelInApp,
		notify.ChannelWebPush,
	} {
		if !slicesContains(wired, required) {
			t.Errorf("the %s channel is built and tested but NOT wired into the running "+
				"worker — every notification on it silently goes nowhere. Wired: %v",
				required, wired)
		}
	}
}

// A nil Preferences port is PERMISSIVE: the dispatcher skips the check
// entirely. That is the safe direction — a security alert is never suppressed by
// an unreadable preference — but it means the per-user channel toggles do
// nothing at all, with no error anywhere to say so.
func TestPreferencesAndArbitrationAreWired(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if !d.notify.HasPreferences() {
		t.Error("no Preferences port is wired: every user's channel toggles are ignored, " +
			"and nothing reports it")
	}
	if !d.notify.HasReadState() {
		t.Error("no ReadState port is wired: an Activity email is never suppressed by an " +
			"in-app read, so ADR-026 arbitration does not happen")
	}
}

// THE TWO DATA-SUBJECT RIGHTS ARE WIRED INTO THE SENDING PATH.
//
// # A nil port here is not merely permissive; it is a legal obligation nobody
// # enforces
//
// The preference ports above fail safe when they are absent: a toggle does
// nothing and a security alert still arrives. These two do not. A nil
// Restrictions port sends mail to somebody who invoked Article 18; a nil
// Objections port processes a purpose somebody stopped under Article 21. Both
// are silent — the aggregate recorded the instruction, the projection holds the
// row, and the dispatcher never asks.
//
// That is exactly the shape this repository has already shipped: three
// notification channels fully built, fully tested and constructed by no binary.
// Only a composition-root test can catch it, because every unit test below these
// ports constructs its own dispatcher and passes either way.
//
// They are asserted TOGETHER and separately, because the two rights suppress
// different things and a single port serving both would mean the narrower one
// has silently become the wider one.
func TestBothDataSubjectRightsAreWiredIntoTheSendingPath(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if !d.notify.HasRestrictions() {
		t.Error("no Article 18 restriction lookup is wired: a person who halted " +
			"processing of their own data is contacted anyway, and nothing reports it")
	}
	if !d.notify.HasObjections() {
		t.Error("no Article 21 objection lookup is wired: activity and product mail " +
			"reaches every person who objected to it. The objection is recorded, the row " +
			"is projected, and the dispatcher never asks — so the only signal is a " +
			"complaint from somebody who already told us once")
	}
}

func testConfig(t *testing.T) *config.Config {
	t.Helper()
	for k, v := range map[string]string{
		"POSTGRES_DB": "chronos", "POSTGRES_USER": "chronos",
		"POSTGRES_PASSWORD": "x", "POSTGRES_APP_PASSWORD": "y",
		"OPENFGA_PRESHARED_KEY": "k",
		// CLEARED, not merely unset. `config.Load` reads the ambient
		// environment, and building the reactors now does network I/O: the
		// provisioning reactor mirrors the plan catalogue into Stripe. A
		// developer with a key exported in their shell would turn every test in
		// this file into a live API call, which is slow, flaky and creates
		// objects in a real account.
		"STRIPE_SECRET_KEY": "",
	} {
		t.Setenv(k, v)
	}
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config: %v", err)
	}
	return cfg
}

func slicesContains(haystack []notify.Channel, needle notify.Channel) bool {
	return slices.Contains(haystack, needle)
}

// Durable work is off by default, and the binary must say so rather than
// pretend. A starter without a running worker is the failure Temporal makes
// hardest to see: the run is created, the caller is told it started, and the
// task sits in a queue nothing polls.
func TestDurableWorkIsAbsentUntilEnabled(t *testing.T) {
	cfg := testConfig(t)
	log := slog.New(slog.DiscardHandler)

	d, closeAll := newDependencies(cfg, log, newCodec())
	defer closeAll()

	if d.temporal != nil || d.temporalWorker != nil {
		t.Fatal("a Temporal client was built with TEMPORAL_ENABLED=false")
	}
}

// The enabled-path assertions live in wiring_integration_test.go.
//
// TEMPORAL_ENABLED=true makes newDependencies DIAL, so asserting on the client
// here would make this suite require a running Temporal — it passes on a machine
// with the stack up and fails in CI, which is the same shape of mistake the key
// cache test in that file already documents. Verified rather than assumed: with
// the container stopped this test failed with "TEMPORAL_ENABLED=true built no
// client", and passed again once it was started.
//
// What stays here is the DISABLED path, which needs no infrastructure and is the
// half that silently ships wrong.

// With durable work off, the reactor must still deliver — inline, through the
// same dispatcher. A deployment without Temporal that silently sends nothing is
// the worst outcome available here.
func TestWithoutDurableWorkTheReactorStillDelivers(t *testing.T) {
	cfg := testConfig(t)
	log := slog.New(slog.DiscardHandler)

	d, closeAll := newDependencies(cfg, log, newCodec())
	defer closeAll()

	for _, r := range reactors(context.Background(), newCodec(), d) {
		er, ok := r.(*notify.EventReactor)
		if !ok {
			continue
		}
		if er.Durable() {
			t.Fatal("the reactor claims durable delivery with no Temporal client wired")
		}
	}
}
