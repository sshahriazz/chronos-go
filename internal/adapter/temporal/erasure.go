package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// ErasureWorkflow is one account's grace period.
//
// The name is PERSISTED in workflow history, so it is permanent: renaming it
// strands every in-flight execution against a worker that no longer answers to
// the name history records. Here that means outstanding erasure requests that
// never execute — a person who asked to be forgotten, was told a date, and is
// still in the database after it.
const ErasureWorkflow = "chronos.compliance.Erasure.v1"

const (
	// erasureStateActivity reads the CURRENT state of the request.
	erasureStateActivity = "chronos.compliance.ErasureState.v1"

	// executeErasureActivity confirms, destroys the key, and cleans up.
	executeErasureActivity = "chronos.compliance.ExecuteErasure.v1"
)

// errTypeDeferred marks an erasure blocked by a legal hold (compliance.md §7).
//
// # It is NON-RETRYABLE, and that is the opposite of what it looks like
//
// Every other failure in this workflow retries with no attempt limit, because
// erasure is a statutory obligation and giving up leaves it unmet. A hold is
// not a failure: it is the system working, and the request is DEFERRED rather
// than refused — it executes automatically when the hold lifts.
//
// Left retryable, the activity would run on a one-minute backoff for the entire
// length of a matter. Weeks of that is a query per minute against the event
// store to learn something that changes once, and the ErrHeld sentinel's own
// comment warned about it before this constant existed to prevent it.
//
// So the activity fails fast and the WORKFLOW waits — on a cadence chosen for
// how often the answer actually changes rather than for how quickly a transient
// error clears.
const errTypeDeferred = "ErasureDeferred"

// deferralPoll is how often a deferred erasure re-checks its hold.
//
// One hour. A legal matter closes on a scale of weeks, so the value is bounded
// below by nothing and above by how long we are willing to hold data after the
// obligation to hold it ends — which is a statutory clock the person is owed
// against. An hour is inconsequential against a month and cheap against a
// matter.
//
// Not the activity's retry backoff, deliberately: that grows toward a minute
// and is tuned for transient failure. This is tuned for a fact that changes
// when a human closes a case.
const deferralPoll = time.Hour

// ErasureInput names the subject this run is about.
//
// A pseudonym and nothing else. Workflow input is written to history, which is
// durable and replicated, so ADR-002 applies here exactly as it does to the
// event log — and an address in a workflow argument would be personal data in
// the one store erasure cannot reach.
//
// It carries NO DEADLINE, for the same reason InvitationLifecycleInput carries
// none: the deadline can move, and a run that slept to a date it was handed at
// start would act on a stale one.
type ErasureInput struct {
	SubjectID string
}

// ErasureResult is how the run ended.
//
// The run's OUTPUT rather than a log line: workflow results survive in the UI
// and in visibility queries long after logs rotate, and "why is this account
// still here" is a question asked weeks later.
type ErasureResult struct {
	// Outcome is one of "erased", "cancelled", "gone".
	Outcome string
}

// ErasureSnapshot is what the state activity reports.
type ErasureSnapshot struct {
	// Exists is false when the subject has no account events at all.
	Exists bool

	// Requested is false once the request has been withdrawn. It is THE reason
	// this workflow re-reads instead of sleeping to a deadline.
	Requested bool

	// Erased is true when an earlier attempt already completed.
	Erased bool

	// ScheduledFor is the current deadline.
	ScheduledFor time.Time
}

// Erasure waits out the grace period and then erases the account.
//
// # Why it re-reads instead of sleeping once and acting
//
// The grace period exists to be USED. A run that slept to its deadline and then
// erased would erase an account whose owner cancelled the request an hour after
// making it — and they would have no way to discover it until their account was
// gone. So every wake re-reads, and cancellation ends the run.
//
// A second request after a cancellation starts a NEW run with a new deadline,
// which is why the input carries no date.
//
// # Why the loop
//
// The deadline can move: a cancel-then-request cycle produces a later one, and
// this run may still be sleeping when it happens. Each iteration sleeps to the
// deadline it just read and then re-reads, so a moved date produces a longer
// wait rather than an early erasure.
func Erasure(ctx workflow.Context, in ErasureInput) (ErasureResult, error) {
	if in.SubjectID == "" {
		return ErasureResult{}, sdktemporal.NewNonRetryableApplicationError(
			"an erasure needs a subject", errTypePermanent, nil)
	}

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 2 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			// UNLIMITED, and this is the one workflow where that matters most.
			// Erasure is a legal obligation with a statutory clock; giving up
			// after N attempts would leave a request permanently unexecuted with
			// nothing but a workflow status to say so.
			MaximumAttempts: 0,
			// errTypeDeferred joins the permanent list, and it is not permanent
			// — see the constant. A hold is a WAIT, and the waiting belongs to
			// the workflow's own sleep rather than to a retry policy tuned for
			// transient failure.
			NonRetryableErrorTypes: []string{errTypePermanent, errTypeDeferred},
		},
		ScheduleToCloseTimeout: time.Hour,
	})

	var result ErasureResult
	for {
		var state ErasureSnapshot
		if err := workflow.ExecuteActivity(ctx, erasureStateActivity, in).
			Get(ctx, &state); err != nil {
			return result, fmt.Errorf("reading the erasure state of %s: %w", in.SubjectID, err)
		}

		switch {
		case !state.Exists:
			// No account events. Reachable if this run was started for a request
			// whose append then failed.
			result.Outcome = "gone"
			return result, nil
		case state.Erased:
			result.Outcome = "erased"
			return result, nil
		case !state.Requested:
			// WITHDRAWN. The whole point of the grace period, and the reason
			// this workflow re-reads rather than sleeping to a date.
			result.Outcome = "cancelled"
			return result, nil
		}

		now := workflow.Now(ctx).UTC()
		if !now.Before(state.ScheduledFor) {
			err := workflow.ExecuteActivity(ctx, executeErasureActivity, in).Get(ctx, nil)
			switch {
			case err == nil:
				result.Outcome = "erased"
				return result, nil

			case isDeferred(err):
				// A LEGAL HOLD. The request is deferred, not refused
				// (compliance.md §7), and the person has already been told —
				// the activity records ErasureDeferred on its first pass, which
				// is what the notification catalogue turns into their Article
				// 12(4) answer.
				//
				// So this waits. It does not fail the run: failing would end a
				// request that is still live, and the whole point of deferral
				// is that it executes automatically when the hold lifts.
				workflow.GetLogger(ctx).Info("erasure deferred by a legal hold",
					"subject", in.SubjectID, "recheck_in", deferralPoll)
				if sleepErr := workflow.Sleep(ctx, deferralPoll); sleepErr != nil {
					return result, sleepErr
				}
				continue

			default:
				return result, fmt.Errorf("erasing %s: %w", in.SubjectID, err)
			}
		}

		if err := workflow.Sleep(ctx, state.ScheduledFor.Sub(now)); err != nil {
			return result, err
		}
	}
}

// ErasureState reads the current state of an erasure request.
type ErasureState struct{ reader ErasureStateReader }

// ErasureStateReader is what the state activity asks. Declared by its consumer.
type ErasureStateReader interface {
	ErasureState(ctx context.Context, subjectID string) (ErasureSnapshot, error)
}

func NewErasureState(reader ErasureStateReader) (*ErasureState, error) {
	if reader == nil {
		return nil, fmt.Errorf("temporal: an erasure state reader is required")
	}
	return &ErasureState{reader: reader}, nil
}

func (s *ErasureState) Execute(ctx context.Context, in ErasureInput) (ErasureSnapshot, error) {
	snapshot, err := s.reader.ErasureState(ctx, in.SubjectID)
	if err != nil {
		activity.GetLogger(ctx).Error("reading erasure state",
			"subject", in.SubjectID, "error", err)
		return ErasureSnapshot{}, err
	}
	return snapshot, nil
}

// ExecuteErasure is the activity that actually erases.
type ExecuteErasure struct{ eraser Eraser }

// Eraser performs the erasure. Declared by its consumer; satisfied by
// compliance's own use case.
type Eraser interface {
	Execute(ctx context.Context, subjectID string) error
}

func NewExecuteErasure(eraser Eraser) (*ExecuteErasure, error) {
	if eraser == nil {
		return nil, fmt.Errorf("temporal: an eraser is required")
	}
	return &ExecuteErasure{eraser: eraser}, nil
}

// Execute runs the erasure once.
//
// Every failure is RETRYABLE here, deliberately, and the workflow's policy has
// no attempt limit. The alternative — classifying some failure as permanent and
// giving up — leaves a statutory obligation unmet with a workflow status as the
// only record. A wrong subject is already refused upstream by the aggregate,
// which is where a genuinely permanent failure belongs.
func (e *ExecuteErasure) Execute(ctx context.Context, in ErasureInput) error {
	err := e.eraser.Execute(ctx, in.SubjectID)
	switch {
	case err == nil:
		return nil

	case errors.Is(err, complianceapp.ErrHeld):
		// Not an error in the ordinary sense: the request is deferred and the
		// workflow will wait. Reported as NON-RETRYABLE so the retry policy
		// stops immediately and the WORKFLOW does the waiting — see
		// errTypeDeferred for why a retryable hold is a query per minute for
		// the length of a matter.
		//
		// INFO rather than ERROR, for the same reason: an operator scanning
		// error logs should not find a system working correctly.
		activity.GetLogger(ctx).Info("erasure deferred by a legal hold",
			"subject", in.SubjectID)
		return sdktemporal.NewNonRetryableApplicationError(
			"this erasure is deferred by a legal hold", errTypeDeferred, err)

	default:
		activity.GetLogger(ctx).Error("erasing a subject",
			"subject", in.SubjectID, "error", err)
		return err
	}
}

// isDeferred reports whether an activity failure was a legal hold.
//
// It matches on the application error's TYPE rather than on the message,
// because the message crosses a process boundary as text and the type is what
// Temporal preserves as structure.
func isDeferred(err error) bool {
	var appErr *sdktemporal.ApplicationError
	if !errors.As(err, &appErr) {
		return false
	}
	return appErr.Type() == errTypeDeferred
}

// RegisterErasure binds the erasure workflow to a worker.
//
// Refusing a nil activity set rather than registering the workflow alone: a run
// that starts and cannot find its first activity retries against a name nothing
// answers to, forever, and the only symptom is a workflow stuck in the UI while
// a statutory clock runs out.
func (w *Worker) RegisterErasure(
	state *ErasureState, execute *ExecuteErasure,
) ([]string, error) {
	switch {
	case w == nil || w.w == nil:
		return nil, errors.New("temporal: cannot register the erasure workflow on a nil worker")
	case state == nil || execute == nil:
		return nil, errors.New("temporal: refusing to register the erasure workflow with an " +
			"incomplete activity set; every started run would fail on its first task, and " +
			"the request it represents is a legal obligation with a clock")
	}
	registerErasure(w.w, state, execute)
	return []string{ErasureWorkflow}, nil
}

// registerErasure binds the workflow and its activities to a worker.
//
// One function, so a worker cannot register the workflow without the activities
// it calls — which would produce a run that starts, fails to find its first
// activity, and retries forever against a name nothing answers to.
func registerErasure(r registry, state *ErasureState, execute *ExecuteErasure) {
	r.RegisterWorkflowWithOptions(Erasure,
		workflow.RegisterOptions{Name: ErasureWorkflow})
	r.RegisterActivityWithOptions(state.Execute,
		activity.RegisterOptions{Name: erasureStateActivity})
	r.RegisterActivityWithOptions(execute.Execute,
		activity.RegisterOptions{Name: executeErasureActivity})
}
