package temporal

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ExportWorkflow builds one data subject's portability bundle.
//
// The name is PERSISTED in workflow history, so it is permanent: renaming it
// strands every in-flight execution against a worker that no longer answers to
// the name history records — here, a person who exercised Article 15 and whose
// export never appears.
const ExportWorkflow = "chronos.compliance.DataExport.v1"

const (
	// beginExportActivity checks the run may proceed and reports what to walk.
	beginExportActivity = "chronos.compliance.BeginExport.v1"

	// listExportObjectsActivity returns ONE page of a subject's objects.
	listExportObjectsActivity = "chronos.compliance.ListExportObjects.v1"

	// writeExportManifestActivity reads the vault, writes the bundle and records
	// the completion.
	writeExportManifestActivity = "chronos.compliance.WriteExportManifest.v1"

	// failExportActivity records that the run stopped without a bundle.
	failExportActivity = "chronos.compliance.FailExport.v1"
)

// ExportInput names the request this run is about.
//
// An export id and nothing else — not the subject, not a prefix, not a field
// list. Workflow input is written to HISTORY, which is durable and replicated,
// so ADR-002 applies exactly as it does to the event log. Everything this run
// needs is read from the log inside the first activity, which means a history
// somebody reads later says only that an export happened, never whose or what
// was in it.
type ExportInput struct {
	ExportID string
}

// ExportRunResult is how the run ended.
//
// The run's OUTPUT rather than a log line: workflow results survive in the UI
// and in visibility queries long after logs rotate, and "why did this person's
// export never arrive" is a question asked days later.
type ExportRunResult struct {
	// Outcome is one of "ready", "failed".
	Outcome string

	// Objects is how many stored files the manifest referenced.
	Objects int

	// Pages is how many listing calls it took. Reported because it is the
	// measure of the thing this workflow exists to make resumable — a run that
	// crashed after four pages restarts and issues the fifth.
	Pages int

	// Reason is set only on a failure, and is the machine string recorded in the
	// log rather than the underlying error.
	Reason string
}

// exportPlan mirrors app.ExportPlan across the activity boundary.
//
// Declared here rather than imported, exactly as InvitationSweepPass is: an
// adapter may not depend on a module, and the two are matched by field name on
// the wire.
type exportPlan struct {
	SubjectID string
	Prefixes  []string
}

// exportListInput asks for one page.
type exportListInput struct {
	ExportID string
	Prefix   string

	// After is the cursor a previous page returned. THE resume point: the
	// workflow carries it in its own state, so a worker that dies mid-listing
	// replays the completed pages from history and issues the next one from
	// here — nothing is re-listed and nothing is re-read.
	After string
}

// exportedObject mirrors app.ExportedObject across the boundary.
type exportedObject struct {
	Key        string
	Size       int64
	ModifiedAt time.Time
}

// exportPage is one listing result.
type exportPage struct {
	Objects []exportedObject

	// Cursor is empty when this prefix is exhausted.
	Cursor string
}

// exportFailure records a stopped run.
type exportFailure struct {
	ExportID string
	Reason   string
}

// exportManifestInput writes the bundle.
//
// It carries the OBJECT LIST, which is metadata about a person's files — keys,
// sizes and timestamps — and therefore reaches workflow history. That is a
// deliberate, bounded exposure and worth stating: a key is opaque by
// construction (CLAUDE.md) and a size is not identifying, so what history holds
// is "this pseudonymous subject had N files of these sizes". The alternative —
// re-listing inside the manifest activity — would throw away the whole point of
// making the listing resumable.
//
// The PERSONAL DATA never travels this way. The vault is read inside the
// manifest activity and the plaintext reaches nothing durable but the bundle it
// produces.
type exportManifestInput struct {
	ExportID string
	Objects  []exportedObject
}

// ExportData is the workflow.
//
// # What is resumable, and what that means here
//
// compliance.md §5 asks for an export that is long-running and resumable with
// progress visible in the workflow. The resumable unit is a PAGE of the object
// listing: the cursor lives in workflow state, so a worker that crashes after
// four pages replays those four from history — without touching the object
// store — and issues the fifth from exactly where the fourth stopped.
//
// # Why the failure is recorded by an activity and not by returning
//
// A workflow that simply returned an error would leave the subject's export
// pending forever from the log's point of view, with the truth living only in a
// Temporal history that is retained for a bounded period. The failure activity
// appends DataExportFailed, so the poll endpoint can say what happened and a
// controller who owes an answer within a month can find the requests that
// produced none.
func ExportData(ctx workflow.Context, in ExportInput) (ExportRunResult, error) {
	var result ExportRunResult

	if in.ExportID == "" {
		// Refused permanently rather than retried: it will be empty on every
		// attempt, so retrying burns the whole schedule to reach this answer.
		return result, sdktemporal.NewNonRetryableApplicationError(
			"an export needs an id", errTypePermanent, nil)
	}

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// One activity is one vault read, one listing page, or one object write.
		// Generous against a slow store, short enough that a hung one is retried
		// rather than waited on for the whole run.
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			// Bounded by ScheduleToClose rather than by attempts. Article 15
			// gives a month; an hour of retries against a store that is down is
			// worth spending, and a run that cannot finish in an hour is one a
			// human should see rather than one that should keep trying.
			MaximumAttempts:        0,
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: time.Hour,
	})

	log := workflow.GetLogger(ctx)

	var plan exportPlan
	if err := workflow.ExecuteActivity(ctx, beginExportActivity, in).Get(ctx, &plan); err != nil {
		return recordFailure(ctx, in, &result, err)
	}

	// The listing. One page at a time, one prefix at a time, and the cursor is
	// the only state that has to survive a restart.
	objects := make([]exportedObject, 0, 16)
	for _, prefix := range plan.Prefixes {
		cursor := ""
		for {
			if result.Pages >= maxExportPages {
				// REFUSED, not truncated. An export that silently stopped listing
				// hands somebody an incomplete answer to Article 15 while reporting
				// success, which is the failure this whole path exists to prevent.
				log.Error("the export exceeded its page budget; the subject holds more "+
					"objects than one export may enumerate",
					"export_id", in.ExportID, "pages", result.Pages)
				return recordFailure(ctx, in, &result, errTooManyExportObjects)
			}

			var page exportPage
			if err := workflow.ExecuteActivity(ctx, listExportObjectsActivity, exportListInput{
				ExportID: in.ExportID, Prefix: prefix, After: cursor,
			}).Get(ctx, &page); err != nil {
				return recordFailure(ctx, in, &result, err)
			}
			result.Pages++
			objects = append(objects, page.Objects...)

			if page.Cursor == "" {
				break
			}
			cursor = page.Cursor
		}
	}

	var manifestKey string
	if err := workflow.ExecuteActivity(ctx, writeExportManifestActivity, exportManifestInput{
		ExportID: in.ExportID, Objects: objects,
	}).Get(ctx, &manifestKey); err != nil {
		return recordFailure(ctx, in, &result, err)
	}

	result.Outcome = "ready"
	result.Objects = len(objects)
	log.Info("data export ready",
		"export_id", in.ExportID, "objects", result.Objects, "pages", result.Pages)
	return result, nil
}

// maxExportPages mirrors app.MaxExportPages.
//
// Duplicated rather than imported for the reason every constant on this boundary
// is: an adapter may not depend on a module. A test asserts the two are equal —
// a workflow that gave up before the app's own bound, or ran past it, would turn
// a refusal into a truncation in one direction and an unbounded listing in the
// other.
const maxExportPages = 5

var errTooManyExportObjects = errors.New("this subject holds more objects than one export " +
	"may enumerate")

// ErrPermanentExport marks a failure retrying cannot fix.
//
// It is declared HERE and wrapped by the composition root's adapter, because
// this package may not import the module that knows which failures are
// permanent, and the module may not import this one. The adapter sits in the one
// place allowed to see both, and the mapping it performs is the whole reason the
// distinction survives the boundary: an activity error crosses a process and
// arrives as an ApplicationError, which does not carry the original type.
var ErrPermanentExport = errors.New("temporal: this export cannot be produced")

// recordFailure appends the failure to the LOG and returns the run's result.
//
// Without it a failed run leaves the subject's export pending forever from the
// log's point of view, with the truth living only in a Temporal history that is
// retained for a bounded period and then gone.
func recordFailure(
	ctx workflow.Context, in ExportInput, result *ExportRunResult, cause error,
) (ExportRunResult, error) {
	log := workflow.GetLogger(ctx)
	reason := exportReasonFor(cause)
	result.Outcome, result.Reason = "failed", reason

	// A SEPARATE, short retry budget. This activity is what makes a failure
	// visible, so it must not inherit the hour the failed work already spent —
	// and if it cannot append either, the workflow fails with both causes and a
	// human looks.
	failCtx := workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout:    30 * time.Second,
		ScheduleToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    2 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    30 * time.Second,
			MaximumAttempts:    0,
		},
	})
	if err := workflow.ExecuteActivity(failCtx, failExportActivity, exportFailure{
		ExportID: in.ExportID, Reason: reason,
	}).Get(failCtx, nil); err != nil {
		log.Error("the export failed AND the failure could not be recorded; the subject's "+
			"request will read as pending forever",
			"export_id", in.ExportID, "reason", reason, "error", err)
		return *result, fmt.Errorf("export %s failed (%s), and recording that failed too: %w",
			in.ExportID, reason, err)
	}
	return *result, fmt.Errorf("export %s failed: %s: %w", in.ExportID, reason, cause)
}

// exportReasonFor maps a cause to the machine string recorded in the log.
//
// Deliberately COARSE. The event carries a reason a person and an operator can
// act on, not a diagnosis: an object store's error names a bucket, a key and an
// endpoint, and none of that belongs in a permanent log (ADR-002 applies to
// operational detail too, by the same argument about what a log outlives).
func exportReasonFor(cause error) string {
	switch {
	case errors.Is(cause, errTooManyExportObjects):
		return reasonTooManyObjects
	case cause != nil && strings.Contains(cause.Error(), reasonRestricted):
		// The app layer marks this permanent and names it in the message. Matched
		// on the string because an activity error crosses a process boundary and
		// arrives as an ApplicationError, which does not carry the original type.
		return reasonRestricted
	default:
		return reasonUnreadable
	}
}

// The reasons, mirroring compliance's contract constants. A test asserts they
// match — a workflow recording a reason the module does not know produces an
// export whose failure nothing downstream can interpret.
const (
	reasonUnreadable     = "source_unreadable"
	reasonTooManyObjects = "too_many_objects"
	reasonRestricted     = "processing_restricted"
)

// ---------------------------------------------------------------------------
// Activities
// ---------------------------------------------------------------------------

// ExportRunner is the use case the activities call. Declared by its consumer.
type ExportRunner interface {
	Begin(ctx context.Context, exportID string) (ExportPlanResult, error)
	ListObjects(ctx context.Context, prefix, after string) (ExportPageResult, error)
	WriteManifest(ctx context.Context, exportID string, objects []ExportObjectRef) (string, error)
	Fail(ctx context.Context, exportID, reason string) error
}

// ExportPlanResult, ExportPageResult and ExportObjectRef are the port's own
// types, so this package names nothing from a module.
type (
	ExportPlanResult struct {
		SubjectID string
		Prefixes  []string
	}
	ExportPageResult struct {
		Objects []ExportObjectRef
		Cursor  string
	}
	ExportObjectRef struct {
		Key        string
		Size       int64
		ModifiedAt time.Time
	}
)

// ExportActivities holds the I/O half of the export.
type ExportActivities struct{ runner ExportRunner }

// NewExportActivities builds the activity set.
func NewExportActivities(r ExportRunner) (*ExportActivities, error) {
	if r == nil {
		return nil, errors.New("temporal: the export activities need a runner; without one " +
			"every run would report success while producing nothing, and a person who " +
			"exercised Article 15 would wait for a bundle that was never built")
	}
	return &ExportActivities{runner: r}, nil
}

// Begin checks the run may proceed and reports what to walk.
func (a *ExportActivities) Begin(ctx context.Context, in ExportInput) (exportPlan, error) {
	plan, err := a.runner.Begin(ctx, in.ExportID)
	if err != nil {
		return exportPlan{}, a.wrap(ctx, "beginning", in.ExportID, err)
	}
	// A CONVERSION rather than a field-by-field copy: the two types are the
	// same shape by design — the port's and the wire's — and a literal here
	// would silently drop a field the day one of them grows.
	return exportPlan(plan), nil
}

// ListObjects returns one page.
func (a *ExportActivities) ListObjects(
	ctx context.Context, in exportListInput,
) (exportPage, error) {
	page, err := a.runner.ListObjects(ctx, in.Prefix, in.After)
	if err != nil {
		return exportPage{}, a.wrap(ctx, "listing objects for", in.ExportID, err)
	}
	out := exportPage{Cursor: page.Cursor, Objects: make([]exportedObject, 0, len(page.Objects))}
	for _, o := range page.Objects {
		out.Objects = append(out.Objects, exportedObject(o))
	}
	return out, nil
}

// WriteManifest writes the bundle and records the completion.
func (a *ExportActivities) WriteManifest(
	ctx context.Context, in exportManifestInput,
) (string, error) {
	refs := make([]ExportObjectRef, 0, len(in.Objects))
	for _, o := range in.Objects {
		refs = append(refs, ExportObjectRef(o))
	}
	key, err := a.runner.WriteManifest(ctx, in.ExportID, refs)
	if err != nil {
		return "", a.wrap(ctx, "writing the manifest for", in.ExportID, err)
	}
	return key, nil
}

// Fail records that a run stopped without a bundle.
func (a *ExportActivities) Fail(ctx context.Context, in exportFailure) error {
	if err := a.runner.Fail(ctx, in.ExportID, in.Reason); err != nil {
		activity.GetLogger(ctx).Error("recording an export failure",
			"export_id", in.ExportID, "reason", in.Reason, "error", err)
		return err
	}
	return nil
}

// wrap logs and marks a permanent failure non-retryable.
//
// The distinction is the whole reason this helper exists: an unreachable store
// is worth an hour of retries, and a subject under Article 18 restriction will
// still be restricted on the hundredth attempt. Retrying both alike would make
// every permanent failure cost the full schedule before the subject is told.
func (a *ExportActivities) wrap(
	ctx context.Context, what, exportID string, err error,
) error {
	activity.GetLogger(ctx).Error(what+" an export", "export_id", exportID, "error", err)

	if errors.Is(err, ErrPermanentExport) {
		return sdktemporal.NewNonRetryableApplicationError(
			err.Error(), errTypePermanent, err)
	}
	return err
}

// RegisterDataExport binds the export workflow and its activities to a worker.
func (w *Worker) RegisterDataExport(a *ExportActivities) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register the data export on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register the data export with no " +
			"activity set; every accepted request would start a run that fails on its " +
			"first task, and the person who asked would wait for a bundle nothing builds")
	}
	registerDataExport(w.w, a)
	return []string{ExportWorkflow}, nil
}

// registerDataExport binds the workflow and its activities by NAME.
//
// By name rather than by function value, because the name is what history
// records — registering under a Go identifier would make a rename silently
// strand every in-flight execution.
func registerDataExport(r registry, a *ExportActivities) {
	r.RegisterWorkflowWithOptions(ExportData,
		workflow.RegisterOptions{Name: ExportWorkflow})
	r.RegisterActivityWithOptions(a.Begin,
		activity.RegisterOptions{Name: beginExportActivity})
	r.RegisterActivityWithOptions(a.ListObjects,
		activity.RegisterOptions{Name: listExportObjectsActivity})
	r.RegisterActivityWithOptions(a.WriteManifest,
		activity.RegisterOptions{Name: writeExportManifestActivity})
	r.RegisterActivityWithOptions(a.Fail,
		activity.RegisterOptions{Name: failExportActivity})
}
