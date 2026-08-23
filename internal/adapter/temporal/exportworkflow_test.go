package temporal_test

import (
	"context"
	"errors"
	"fmt"
	"testing"
	"time"

	"go.temporal.io/sdk/testsuite"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
)

const testExportID = "export_01ARZ3NDEKTSV4RRFFQ69G5FAV"

// fakeExportRunner is every activity's I/O, recorded.
//
// The listing is a FUNCTION of the call count, so a test can hand back a cursor
// and then exhaust it — which is the behaviour under test: a run that pages must
// keep asking until the store says there is no more.
type fakeExportRunner struct {
	prefixes []string
	beginErr error

	pages   []temporaladapter.ExportPageResult
	listErr error
	listed  []string // "prefix|after", in order

	manifestKey string
	manifestErr error
	manifested  [][]temporaladapter.ExportObjectRef

	failed  []string
	failErr error
}

func (f *fakeExportRunner) Begin(
	_ context.Context, _ string,
) (temporaladapter.ExportPlanResult, error) {
	if f.beginErr != nil {
		return temporaladapter.ExportPlanResult{}, f.beginErr
	}
	prefixes := f.prefixes
	if prefixes == nil {
		prefixes = []string{"subj_x"}
	}
	return temporaladapter.ExportPlanResult{SubjectID: "subj_x", Prefixes: prefixes}, nil
}

func (f *fakeExportRunner) ListObjects(
	_ context.Context, prefix, after string,
) (temporaladapter.ExportPageResult, error) {
	f.listed = append(f.listed, prefix+"|"+after)
	if f.listErr != nil {
		return temporaladapter.ExportPageResult{}, f.listErr
	}
	i := len(f.listed) - 1
	if i >= len(f.pages) {
		return temporaladapter.ExportPageResult{}, nil
	}
	return f.pages[i], nil
}

func (f *fakeExportRunner) WriteManifest(
	_ context.Context, _ string, objects []temporaladapter.ExportObjectRef,
) (string, error) {
	f.manifested = append(f.manifested, objects)
	if f.manifestErr != nil {
		return "", f.manifestErr
	}
	if f.manifestKey == "" {
		return "obj_manifest", nil
	}
	return f.manifestKey, nil
}

func (f *fakeExportRunner) Fail(_ context.Context, _, reason string) error {
	f.failed = append(f.failed, reason)
	return f.failErr
}

func runExport(
	t *testing.T, f *fakeExportRunner,
) (temporaladapter.ExportRunResult, error) {
	t.Helper()
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	activities, err := temporaladapter.NewExportActivities(f)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterDataExportForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.ExportWorkflow,
		temporaladapter.ExportInput{ExportID: testExportID})
	if !env.IsWorkflowCompleted() {
		t.Fatal("the workflow did not complete")
	}
	var result temporaladapter.ExportRunResult
	if err := env.GetWorkflowError(); err != nil {
		return result, err
	}
	if err := env.GetWorkflowResult(&result); err != nil {
		t.Fatalf("decoding the result: %v", err)
	}
	return result, nil
}

func page(cursor string, keys ...string) temporaladapter.ExportPageResult {
	objects := make([]temporaladapter.ExportObjectRef, 0, len(keys))
	for _, k := range keys {
		objects = append(objects, temporaladapter.ExportObjectRef{
			Key: k, Size: 10, ModifiedAt: time.Unix(0, 0).UTC(),
		})
	}
	return temporaladapter.ExportPageResult{Objects: objects, Cursor: cursor}
}

// THE LISTING PAGES, AND THE CURSOR IS WHAT CARRIES IT.
//
// This is the property compliance.md §5's "resumable" reduces to. The workflow
// holds the cursor in its own state, so a worker that crashes after four pages
// replays those four from history — without touching the object store — and
// issues the fifth from exactly where the fourth stopped.
//
// A run that ignored the cursor would list the FIRST page forever, or once, and
// hand somebody a bundle missing everything after it.
func TestTheListingFollowsTheCursorToExhaustion(t *testing.T) {
	f := &fakeExportRunner{pages: []temporaladapter.ExportPageResult{
		page("c1", "a", "b"),
		page("c2", "c"),
		page("", "d"),
	}}

	result, err := runExport(t, f)
	if err != nil {
		t.Fatalf("ExportData: %v", err)
	}

	want := []string{"subj_x|", "subj_x|c1", "subj_x|c2"}
	if len(f.listed) != len(want) {
		t.Fatalf("the workflow made %d listings (%v), want %d — a run that ignores the "+
			"cursor stops at the first page and the bundle is missing everything after it",
			len(f.listed), f.listed, len(want))
	}
	for i := range want {
		if f.listed[i] != want[i] {
			t.Errorf("listing %d asked %q, want %q", i, f.listed[i], want[i])
		}
	}
	if result.Pages != 3 {
		t.Errorf("the run reports %d pages, want 3", result.Pages)
	}
	if result.Objects != 4 {
		t.Errorf("the manifest carries %d objects, want 4", result.Objects)
	}
	if len(f.manifested) != 1 || len(f.manifested[0]) != 4 {
		t.Fatalf("the manifest was written with %v", f.manifested)
	}
}

// EVERY PREFIX IS WALKED, NOT JUST THE FIRST.
//
// An export that stopped after one namespace would silently omit whole
// categories of a person's files — and the erasure walks the same list, so it
// would then delete exactly what the bundle left out.
func TestEveryPrefixIsWalked(t *testing.T) {
	f := &fakeExportRunner{
		prefixes: []string{"avatars/subj_x", "attachments/subj_x"},
		pages: []temporaladapter.ExportPageResult{
			page("", "a"),
			page("", "b"),
		},
	}
	if _, err := runExport(t, f); err != nil {
		t.Fatal(err)
	}
	if len(f.listed) != 2 ||
		f.listed[0] != "avatars/subj_x|" || f.listed[1] != "attachments/subj_x|" {
		t.Fatalf("the workflow listed %v; a prefix skipped is a category of files missing "+
			"from the bundle and deleted by the erasure that follows", f.listed)
	}
}

// PAST ITS BUDGET THE RUN REFUSES, AND DOES NOT TRUNCATE.
//
// Truncating is the tempting handling and the wrong one: it hands somebody an
// incomplete answer to Article 15 while reporting success, and there is nothing
// in the bundle to say it is short. A refusal reaches the person AND an operator.
func TestPastItsBudgetTheRunFailsRatherThanTruncating(t *testing.T) {
	// A cursor that never empties.
	pages := make([]temporaladapter.ExportPageResult, temporaladapter.MaxExportPagesForTest+3)
	for i := range pages {
		pages[i] = page("more", fmt.Sprintf("k%d", i))
	}
	f := &fakeExportRunner{pages: pages}

	// The workflow RETURNS an error here, so its result is not decodable — the
	// assertions below are on what reached the log and the store, which is what
	// the person and the operator actually see.
	if _, err := runExport(t, f); err == nil {
		t.Fatal("a run past its page budget reported success; the person receives a bundle " +
			"missing everything after the cut, and nothing says so")
	}
	if len(f.manifested) != 0 {
		t.Errorf("a truncated listing still wrote a manifest: %v", f.manifested)
	}
	if len(f.failed) != 1 || f.failed[0] != "too_many_objects" {
		t.Fatalf("the run recorded %v, want one too_many_objects failure. Without it the "+
			"request reads as pending forever and nobody is told", f.failed)
	}
	// And it stopped AT the budget rather than running on.
	if len(f.listed) > temporaladapter.MaxExportPagesForTest {
		t.Errorf("the run made %d listings past a budget of %d",
			len(f.listed), temporaladapter.MaxExportPagesForTest)
	}
}

// A FAILURE IS RECORDED IN THE LOG, NOT JUST RETURNED.
//
// A workflow that only returned an error leaves the subject's request pending
// forever from the log's point of view, with the truth living in a Temporal
// history that is retained for a bounded period and then gone.
func TestAFailedRunRecordsWhy(t *testing.T) {
	for name, f := range map[string]*fakeExportRunner{
		"the plan could not be read": {beginErr: errors.New("kurrent is down")},
		"the listing failed":         {listErr: errors.New("s3 is down")},
		"the manifest failed":        {manifestErr: errors.New("s3 is down")},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := runExport(t, f); err == nil {
				t.Fatal("a failed run reported success")
			}
			if len(f.failed) != 1 || f.failed[0] != "source_unreadable" {
				t.Fatalf("the run recorded %v, want one source_unreadable failure. The "+
					"person's request reads as pending forever and Article 15's month "+
					"runs out with nothing anywhere saying why", f.failed)
			}
		})
	}
}

// A RUN THAT CANNOT EVEN RECORD ITS FAILURE FAILS LOUDLY.
//
// The one case where returning an error is the whole remedy: if the append also
// fails there is nothing else to tell anybody with, so the workflow must not
// report success and leave a human with no signal.
func TestARunThatCannotRecordItsFailureDoesNotReportSuccess(t *testing.T) {
	f := &fakeExportRunner{
		beginErr: errors.New("kurrent is down"),
		failErr:  errors.New("kurrent is still down"),
	}
	if _, err := runExport(t, f); err == nil {
		t.Fatal("a run that could neither build the export nor record the failure reported " +
			"success; nothing anywhere says the request produced nothing")
	}
}

// A PERMANENT FAILURE IS NOT RETRIED FOR AN HOUR.
//
// A subject under Article 18 restriction will still be restricted on the
// hundredth attempt. Retrying it like an outage would burn the whole schedule to
// reach the same answer, and the person would wait for it.
func TestAPermanentFailureIsAttemptedOnce(t *testing.T) {
	f := &fakeExportRunner{
		beginErr: fmt.Errorf("%w: processing_restricted",
			temporaladapter.ErrPermanentExport),
	}
	if _, err := runExport(t, f); err == nil {
		t.Fatal("a restricted subject's export reported success")
	}
	if len(f.failed) != 1 || f.failed[0] != "processing_restricted" {
		t.Fatalf("the run recorded %v, want one processing_restricted failure", f.failed)
	}
}

// AN EXPORT WITH NO ID IS REFUSED BEFORE ANY ACTIVITY RUNS.
func TestARunWithNoExportIDDoesNothing(t *testing.T) {
	var suite testsuite.WorkflowTestSuite
	env := suite.NewTestWorkflowEnvironment()

	f := &fakeExportRunner{}
	activities, err := temporaladapter.NewExportActivities(f)
	if err != nil {
		t.Fatal(err)
	}
	temporaladapter.RegisterDataExportForTest(env, activities)

	env.ExecuteWorkflow(temporaladapter.ExportWorkflow, temporaladapter.ExportInput{})
	if env.GetWorkflowError() == nil {
		t.Fatal("a run with no export id reported success")
	}
	if len(f.listed) != 0 || len(f.manifested) != 0 {
		t.Error("a run with no export id still did I/O")
	}
}

// THE ACTIVITY SET REFUSES A NIL RUNNER.
//
// Registering one would queue runs that fail on their first task — every
// accepted request, forever, with the person who asked waiting for a bundle
// nothing builds.
func TestTheExportActivitiesRefuseANilRunner(t *testing.T) {
	if _, err := temporaladapter.NewExportActivities(nil); err == nil {
		t.Fatal("an activity set with no runner was accepted")
	}
}
