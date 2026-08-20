package main

import (
	"log/slog"
	"os"
	"slices"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// TestMain gives every test in this package the identity key material a real
// deployment is required to have.
//
// config.Load REFUSES to start outside a local environment without
// IDENTITY_EMAIL_INDEX_KEY, IDENTITY_PASSWORD_PEPPER_KEY and
// IDENTITY_TOTP_SEAL_KEY, and .env.example supplies all three for local work. A
// test harness that omitted them would be exercising a configuration no
// deployment ever runs, and — now that this binary opens credentials — one in
// which the worker legitimately refuses to build.
//
// The values are the same throwaway constants .env.example uses. They are 32-byte
// hex keys with no relationship to anything: nothing in this package encrypts
// anything a test then reads back, so their only job is to be well-formed.
func TestMain(m *testing.M) {
	//nolint:gosec // G101: throwaway hex constants, identical to .env.example's
	for k, v := range map[string]string{
		"IDENTITY_EMAIL_INDEX_KEY":     "4f1f6f4b1c9d2a7e8b5c3d0e6a9f2b4c7d8e1a3f5b6c9d0e2a4f7b8c1d3e5a60",
		"IDENTITY_PASSWORD_PEPPER_KEY": "9a3c5e7f1b4d6a8c0e2f4b6d8a0c2e4f6b8d0a2c4e6f8b0d2a4c6e8f0b2d4a6c",
		"IDENTITY_TOTP_SEAL_KEY":       "2c4e6a8f0b1d3e5a7c9f1b3d5e7a9c0f2b4d6e8a1c3f5b7d9e0a2c4f6b8d0e2a",
	} {
		if err := os.Setenv(k, v); err != nil {
			panic(err)
		}
	}
	os.Exit(m.Run())
}

// Credential re-sealing is the third job in this binary that a component test is
// structurally unable to see, and the one whose absence is the most dangerous.
//
// The reservation sweep's absence eventually reaches a user who cannot register.
// Retention's absence reaches a disk. This one reaches an OPERATOR, through a
// number: `SELECT count(*) FROM credential WHERE pepper_version < n`, which
// simply never falls. Every other signal stays green — the worker is healthy, the
// queue is empty, no run fails, because no run was ever queued anywhere anything
// was listening. The two conclusions available from a count that will not move
// are "keep the key I meant to retire, forever" and "destroy it anyway", and the
// second permanently removes every password and every second factor still sealed
// under it.
//
// Only a test of the COMPOSITION ROOT can catch that. Three adapters in this
// repository were once fully built, fully tested and constructed by no binary.
func TestCredentialResealingIsBuiltAndRegistered(t *testing.T) {
	// A dead address, deliberately. The Temporal client is lazy and neither
	// building a worker nor registering on one performs any I/O, so this test
	// needs no infrastructure — and pointing it at a port nothing listens on is
	// what proves that rather than assuming it. Only Start dials, and Start is the
	// one step this test does not take.
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.reseal == nil {
		t.Fatal("credential re-sealing was not constructed: a password pepper or TOTP " +
			"sealing key rotation can never be completed, every retired key must be kept " +
			"alive for the lifetime of the deployment, and any account that has not signed " +
			"in since the rotation stays pinned to the old key")
	}

	// BOTH kinds, and this is the assertion that matters most in this file. The
	// bug this job replaces was a work list that could see only passwords: it
	// reported zero rows outstanding while every TOTP secret in the system still
	// depended on the key an operator was being told was safe to destroy. A binary
	// that wires one resealer reproduces exactly that, and every other test here
	// still passes.
	kinds := d.reseal.Kinds()
	for _, want := range []string{app.KindPassword, app.KindTOTP} {
		if !slices.Contains(kinds, want) {
			t.Errorf("the re-sealing job is not wired for credential kind %q, so its rows "+
				"stay at the old key version while the job reports a clean pass. Wired: %v",
				want, kinds)
		}
	}

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		t.Fatalf("dialling lazily: %v", err)
	}
	defer client.Close()

	// The production path, exactly — startTemporal calls this and then Start.
	w, names, err := d.newTemporalWorker(client)
	if err != nil {
		t.Fatalf("the worker this binary would build could not be built: %v", err)
	}
	if w == nil {
		t.Fatal("no worker was built")
	}

	if !slices.Contains(names, temporaladapter.ResealCredentialKeysWorkflow) {
		t.Errorf("the worker does not answer to %s, so the schedule that starts it queues "+
			"work where nothing is listening: the run is created, the caller is told it "+
			"started, and not one credential is ever carried onto the new key. "+
			"Registered: %v", temporaladapter.ResealCredentialKeysWorkflow, names)
	}
	// Registered BESIDE the others, not instead of them: a registration that
	// replaced another would pass a containment check while silently stranding
	// every notification workflow in flight, switching off the reservation sweep —
	// which IS a security control — or stopping retention.
	for _, other := range []string{
		temporaladapter.SendNotificationWorkflow,
		temporaladapter.SweepReservationsWorkflow,
		temporaladapter.PurgeIdentityRetentionWorkflow,
	} {
		if !slices.Contains(names, other) {
			t.Errorf("registering credential re-sealing displaced %s. Registered: %v", other, names)
		}
	}
}

// Re-sealing is built whether or not durable work is enabled, so a deployment
// without Temporal reports "re-sealing could not be constructed" rather than
// reporting nothing at all.
func TestResealingIsConstructedEvenWithDurableWorkDisabled(t *testing.T) {
	cfg := testConfig(t) // TEMPORAL_ENABLED defaults to false
	if cfg.Temporal.Enabled {
		t.Fatal("this test is meaningless with durable work enabled")
	}

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.reseal == nil {
		t.Fatal("no re-sealing job was constructed")
	}
}

// The worker must refuse to be built rather than register an activity wrapping
// nothing.
//
// A resealAdapter around a nil use case is a NON-nil interface, so
// NewResealActivities' own nil check passes and the failure moves to a panic on
// the first scheduled run — hourly, forever, in a job whose entire output is the
// input to an irreversible decision about destroying a key.
func TestTheWorkerRefusesToRegisterResealingThatWasNotBuilt(t *testing.T) {
	t.Setenv("TEMPORAL_HOSTPORT", "127.0.0.1:1")
	cfg := testConfig(t)

	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort:  cfg.Temporal.HostPort,
		Namespace: cfg.Temporal.Namespace,
		Queue:     cfg.Temporal.Queue,
	})
	if err != nil {
		t.Fatalf("dialling lazily: %v", err)
	}
	defer client.Close()

	d.reseal = nil
	if _, _, err := d.newTemporalWorker(client); err == nil {
		t.Fatal("a worker was built with no re-sealing use case; its schedule would start " +
			"runs that panic on every task")
	}
}
