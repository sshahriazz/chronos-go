//go:build integration

package protocolit_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	connectrpc "connectrpc.com/connect"

	compliancev1 "github.com/chronos/chronos-go/gen/proto/chronos/compliance/v1"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/reactor"
)

func temporalHostPort() string {
	if v := os.Getenv("TEMPORAL_HOSTPORT"); v != "" {
		return v
	}
	return "localhost:7233"
}

// THE WHOLE PATH, WITH NOBODY DRIVING IT.
//
// # What this covers that the other export tests do not
//
// The test beside this one drives the workflow's ACTIVITIES by hand, which
// proves they work against real infrastructure and proves nothing about whether
// anything CALLS them. Between an accepted request and a built bundle sit four
// things that only exist at runtime:
//
//   - the reactor's persistent subscription actually receiving the event,
//   - the reactor asking Temporal to start a run,
//   - a worker answering to the workflow NAME history records,
//   - that worker having every activity registered under the name the workflow
//     executes.
//
// Every one of those fails silently. A filter that matches nothing, a workflow
// name that drifted, an activity registered under its Go identifier — none
// produces an error anywhere. The request is accepted, the log agrees, and the
// person waits for a bundle nothing is building while Article 15's one-month
// clock runs out.
//
// Unit tests cover each in isolation: the reactor's filter, the registration
// function, the workflow under Temporal's test environment. This is the only
// test that runs them TOGETHER, against a real KurrentDB subscription and a real
// Temporal server, and asserts the outcome by polling the same endpoint a person
// would.
//
// # Nothing here is driven by hand
//
// The test makes ONE call — the request, through the public API — and then only
// polls. If the bundle appears, every link in the chain worked.
func TestAnExportRequestBuildsItsBundleWithNobodyDrivingIt(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// A queue unique to this run, so a worker started elsewhere — cmd/worker on
	// a developer's machine, or another test binary — cannot serve these tasks
	// and make the assertion pass without this worker existing.
	queue := "chronos-export-it-" + time.Now().Format("150405.000000")

	client, err := temporaladapter.Dial(temporaladapter.Config{
		HostPort: temporalHostPort(), Namespace: "default", Queue: queue,
	})
	if err != nil {
		t.Skipf("temporal is not reachable at %s: %v", temporalHostPort(), err)
	}
	t.Cleanup(client.Close)

	// The worker, registered through the SAME function cmd/worker calls. Not a
	// hand-rolled registration: a test that bound the workflow itself would pass
	// while production bound a different name, which is the failure this whole
	// test exists to catch.
	notifications, err := temporaladapter.NewNotificationActivities(silentDispatcher{})
	if err != nil {
		t.Fatal(err)
	}
	w, err := temporaladapter.NewWorker(temporaladapter.WorkerDeps{
		Client: client, Notifications: notifications,
	})
	if err != nil {
		t.Fatal(err)
	}
	exports, err := temporaladapter.NewExportActivities(exportRunnerAdapter{runs: h.exportRuns(t)})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.RegisterDataExport(exports); err != nil {
		t.Fatalf("registering the data export: %v", err)
	}
	if err := w.Start(); err != nil {
		t.Fatalf("worker start: %v", err)
	}
	t.Cleanup(w.Stop)

	// The reactor, on its own subscription group so it cannot consume the events
	// a real worker's group is responsible for — and on the REAL store, so the
	// filter it declares is the filter KurrentDB applies.
	group := compliancereactor.ExportReactorName + "-it-" + time.Now().Format("150405.000000")
	r, err := compliancereactor.NewExport(client, temporaladapter.ExportWorkflow, h.codec)
	if err != nil {
		t.Fatal(err)
	}
	runner := reactor.NewRunner(renamedReactor{Reactor: r, name: group}, reactor.Deps{
		Subscriber: h.store,
		Codec:      h.codec,
		Dedup:      pgadapter.NewDedup(h.pg),
		Log:        slog.New(slog.DiscardHandler),
		Clock:      clock.System{},
		Retry:      2 * time.Second,
	})
	runCtx, stopRunner := context.WithCancel(ctx)
	defer stopRunner()
	go func() { _ = runner.Run(runCtx) }()

	// Give the subscription time to attach BEFORE the event is written. A
	// persistent group created after the fact starts at the END of the log
	// (ADR-019), so an event appended first would never be delivered — and the
	// test would fail for a reason that has nothing to do with the code.
	time.Sleep(2 * time.Second)

	account := h.disposableAccount(t, "export-e2e")
	res, err := h.compliance.ExportMyData(ctx, authed(
		&compliancev1.ExportMyDataRequest{}, account.bearer))
	if err != nil {
		t.Fatalf("ExportMyData: %v\n%s", err, h.serverLogs())
	}
	exportID := res.Msg.GetExportId()
	t.Logf("requested %s; from here nothing in this test touches it", exportID)

	// Only polling from here. The chain has to do the rest.
	got := awaitExportWithin(t, account.bearer, exportID, 2*time.Minute,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY,
		compliancev1.DataExportStatus_DATA_EXPORT_STATUS_FAILED,
	)
	if got.GetStatus() != compliancev1.DataExportStatus_DATA_EXPORT_STATUS_READY {
		t.Fatalf("the export FAILED with %q. Every link ran and one of them refused",
			got.GetFailureReason())
	}
	if got.GetManifestUrl() == "" {
		t.Fatal("a READY export carries no manifest URL")
	}

	// And the bundle is real. Fetched through the signed URL a browser would
	// use, so this asserts the delivery path and not the object's presence.
	body := fetch(t, got.GetManifestUrl())
	if !strings.Contains(string(body), account.subjectID) {
		t.Fatalf("the bundle does not name the subject who asked for it: %s", truncate(body))
	}
	t.Logf("the bundle was built end to end: reactor → temporal → activities → log → "+
		"projection → poll, with %d file(s)", len(got.GetFiles()))
}

// awaitExportWithin is awaitExport with a caller-chosen deadline.
//
// Longer here than elsewhere because this test waits on a real workflow: a task
// queue poll, a workflow task, four activity tasks and a projection, none of
// which this process schedules.
func awaitExportWithin(
	t *testing.T, bearer, exportID string, within time.Duration,
	want ...compliancev1.DataExportStatus,
) *compliancev1.GetDataExportResponse {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), within+30*time.Second)
	defer cancel()

	deadline := time.Now().Add(within)
	var last *compliancev1.GetDataExportResponse
	for time.Now().Before(deadline) {
		res, err := h.compliance.GetDataExport(ctx, authed(
			&compliancev1.GetDataExportRequest{ExportId: exportID}, bearer))
		switch {
		case connectrpc.CodeOf(err) == connectrpc.CodeNotFound:
			// NOT an error, and treating it as one made this a race.
			//
			// The id came back from `ExportMyData` a moment ago, so the export
			// exists in the log by definition. The row this polls is written by a
			// projection, and NOT_FOUND is simply what the poll sees until the
			// projector catches up — which takes longer whenever the suite runs
			// more projections, so both call sites failed intermittently the day
			// two were added.
			//
			// An id that is genuinely unknown still fails, on the deadline below,
			// with the message that names every link in the chain.
		case err != nil:
			t.Fatalf("GetDataExport: %v\n%s", err, h.serverLogs())
		default:
			last = res.Msg
			for _, wanted := range want {
				if res.Msg.GetStatus() == wanted {
					return res.Msg
				}
			}
		}
		time.Sleep(500 * time.Millisecond)
	}
	t.Fatalf("the export was still %v after %s. Something in the chain is not connected: "+
		"the reactor never received the event, or never started a run, or no worker "+
		"answers to %q, or an activity is registered under a name the workflow does not "+
		"execute — and every one of those is silent\n%s",
		last.GetStatus(), within, temporaladapter.ExportWorkflow, h.serverLogs())
	return nil
}

// renamedReactor gives a reactor a test-local subscription group.
//
// The production NAME is permanent and shared: running this test under it would
// consume events a real worker's group is responsible for, and would leave a
// checkpoint under the real name that makes the worker skip a real request
// later.
type renamedReactor struct {
	reactor.Reactor
	name string
}

func (r renamedReactor) Name() string { return r.name }

// silentDispatcher stands in for the notification path, which this test does not
// exercise: the export's own mail is sent by cmd/worker's catalogue reactor, and
// what is under test here is whether the BUNDLE gets built.
type silentDispatcher struct{}

func (silentDispatcher) Dispatch(context.Context, notify.Notification) error { return nil }

// exportRunnerAdapter presents the use case as the workflow's port.
//
// # It is a COPY of cmd/worker's, and that is a real limitation
//
// The original lives in a main package, so nothing can import it. Copying it
// means this test exercises the whole chain EXCEPT the production adapter's one
// piece of judgement: mapping compliance's PermanentExportError onto the
// workflow engine's marker, which is what stops a restricted subject's export
// being retried for an hour.
//
// That half is covered where it lives, by
// TestThePermanenceMappingSurvivesTheAdapter in cmd/worker. Splitting it this
// way is the honest arrangement available: the alternative is a test that
// silently proves less than it appears to.
type exportRunnerAdapter struct{ runs *complianceapp.ExportRuns }

var _ temporaladapter.ExportRunner = exportRunnerAdapter{}

func (a exportRunnerAdapter) Begin(
	ctx context.Context, exportID string,
) (temporaladapter.ExportPlanResult, error) {
	plan, err := a.runs.Begin(ctx, exportID)
	if err != nil {
		return temporaladapter.ExportPlanResult{}, permanence(err)
	}
	return temporaladapter.ExportPlanResult{SubjectID: plan.SubjectID, Prefixes: plan.Prefixes}, nil
}

func (a exportRunnerAdapter) ListObjects(
	ctx context.Context, prefix, after string,
) (temporaladapter.ExportPageResult, error) {
	page, err := a.runs.ListObjects(ctx, prefix, after)
	if err != nil {
		return temporaladapter.ExportPageResult{}, permanence(err)
	}
	out := temporaladapter.ExportPageResult{
		Cursor:  page.Cursor,
		Objects: make([]temporaladapter.ExportObjectRef, 0, len(page.Objects)),
	}
	for _, o := range page.Objects {
		out.Objects = append(out.Objects, temporaladapter.ExportObjectRef{
			Key: o.Key.String(), Size: o.Size, ModifiedAt: o.ModifiedAt,
		})
	}
	return out, nil
}

func (a exportRunnerAdapter) WriteManifest(
	ctx context.Context, exportID string, objects []temporaladapter.ExportObjectRef,
) (string, error) {
	refs := make([]complianceapp.ExportedObject, 0, len(objects))
	for _, o := range objects {
		refs = append(refs, complianceapp.ExportedObject{
			Key: o.Key, Size: o.Size, ModifiedAt: o.ModifiedAt,
		})
	}
	key, err := a.runs.WriteManifest(ctx, exportID, refs)
	if err != nil {
		return "", permanence(err)
	}
	return key, nil
}

func (a exportRunnerAdapter) Fail(ctx context.Context, exportID, reason string) error {
	return a.runs.Fail(ctx, exportID, reason)
}

func permanence(err error) error {
	var permanent *complianceapp.PermanentExportError
	if errors.As(err, &permanent) {
		return fmt.Errorf("%w: %s", temporaladapter.ErrPermanentExport, permanent.Permanent())
	}
	return err
}
