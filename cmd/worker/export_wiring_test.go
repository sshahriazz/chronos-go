package main

import (
	"context"
	"log/slog"
	"testing"

	"time"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	compliancecontract "github.com/chronos/chronos-go/internal/modules/compliance/contract"
	compliancereactor "github.com/chronos/chronos-go/internal/modules/compliance/reactor"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// THE EXPORT REACTOR IS REGISTERED, AND SUBSCRIBES TO THE REQUEST EVENT.
//
// # Why this test exists
//
// The reactor was written, built, and registered in NOTHING for one commit. The
// linter caught it because the constructor was unused — which is luck rather
// than a gate: a constructor called from a test, or from a second binary, would
// have been "used" and the reactor would still have been wired to nobody.
//
// # What the absence costs
//
// Nothing errors. The request is appended, the person is told it was accepted,
// the projection shows `pending`, and no workflow ever builds a bundle. There is
// no parked event and no metric, because nothing consumed anything. Article 15
// gives a controller one month, and this is the failure that runs it out in
// silence.
func TestTheExportReactorIsRegistered(t *testing.T) {
	cfg := testConfig(t)
	d, closeAll := newDependencies(cfg, slog.New(slog.DiscardHandler), newCodec())
	defer closeAll()

	// Without Temporal it cannot be constructed, which is correct and is what
	// this environment produces. What the test asserts either way is that
	// `reactors` KNOWS about it: a registry that never mentions the export
	// reactor cannot register it when Temporal IS present.
	found := find(reactors(context.Background(), newCodec(), d),
		compliancereactor.ExportReactorName)
	if d.temporal != nil && found == nil {
		t.Fatalf("the worker registers no %q reactor: every accepted Article 15 request "+
			"is consumed by nothing", compliancereactor.ExportReactorName)
	}

	// The filter, asserted on a directly-constructed reactor because the registry
	// above cannot hold one without a Temporal client. A wrong filter is not a
	// crash: the group simply never receives the event it exists for.
	r, err := compliancereactor.NewExport(
		stubStarter{}, temporaladapter.ExportWorkflow, newCodec())
	if err != nil {
		t.Fatalf("NewExport: %v", err)
	}
	got := r.Filter().EventTypePrefixes
	if len(got) != 1 || got[0] != "compliance.DataExportRequested.v1" {
		t.Errorf("the export reactor subscribes to %v, not to the request event", got)
	}
}

// THE REACTOR STARTS THE NAME THE WORKER ANSWERS TO.
//
// The reactor takes the workflow name as an argument precisely so the two cannot
// drift — a module may not import the adapter that defines it. This asserts the
// composition root passes the right one: a reactor starting a name no worker
// registered produces requests that sit forever, with the run visible in
// Temporal as "workflow type not registered" and nothing in the log to say so.
func TestTheExportReactorStartsTheRegisteredWorkflow(t *testing.T) {
	starter := &exportStarter{}
	r, err := compliancereactor.NewExport(
		starter, temporaladapter.ExportWorkflow, newCodec())
	if err != nil {
		t.Fatal(err)
	}

	env, want := exportRequestedEnvelope(t)
	if err := r.React(context.Background(), env); err != nil {
		t.Fatalf("React: %v", err)
	}
	if len(starter.starts) != 1 {
		t.Fatalf("the reactor started %d workflows for one request", len(starter.starts))
	}
	got := starter.starts[0]
	if got.Name != temporaladapter.ExportWorkflow {
		t.Errorf("the reactor started %q and the worker registers %q",
			got.Name, temporaladapter.ExportWorkflow)
	}
	// The workflow id contains the EXPORT id, which is what makes a redelivered
	// event ask Temporal to start a run that already exists rather than build one
	// person's bundle twice.
	if !contains(got.ID, want) {
		t.Errorf("the workflow id is %q and does not contain the export id %q; a "+
			"redelivered event starts a SECOND run, and the person is mailed twice "+
			"about two bundles", got.ID, want)
	}
}

func contains(haystack, needle string) bool {
	return len(needle) > 0 && len(haystack) >= len(needle) &&
		indexOf(haystack, needle) >= 0
}

func indexOf(haystack, needle string) int {
	for i := 0; i+len(needle) <= len(haystack); i++ {
		if haystack[i:i+len(needle)] == needle {
			return i
		}
	}
	return -1
}

// exportStarter records the starts, keeping the whole Start so a test can assert
// the NAME and the ID rather than only that something happened.
type exportStarter struct{ starts []workflow.Start }

func (s *exportStarter) Start(_ context.Context, w workflow.Start) (workflow.Run, error) {
	s.starts = append(s.starts, w)
	return workflow.Run{ID: w.ID, RunID: "run_1"}, nil
}

// exportRequestedEnvelope is one real DataExportRequested, encoded by the real
// codec — so this fails if the event stops being decodable rather than passing
// against a hand-written JSON literal.
func exportRequestedEnvelope(t *testing.T) (eventsourcing.Envelope, string) {
	t.Helper()
	const exportID = "export_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	payload, err := newCodec().Marshal(&compliancecontract.DataExportRequested{
		SubjectID:   "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		ExportID:    exportID,
		RequestedAt: time.Unix(0, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("encoding the event: %v", err)
	}
	return eventsourcing.Envelope{
		ID:      ids.New[ids.Event](time.Unix(0, 0).UTC(), ids.Entropy()),
		Type:    (&compliancecontract.DataExportRequested{}).EventType(),
		Stream:  "dataexport-" + exportID,
		Payload: payload,
	}, exportID
}
