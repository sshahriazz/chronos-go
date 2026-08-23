package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	"go.temporal.io/sdk/activity"
	sdktemporal "go.temporal.io/sdk/temporal"
	"go.temporal.io/sdk/workflow"
)

// SweepErasuresWorkflow is the backstop for deletion requests with no clock.
//
// The name is persisted in history and is therefore permanent.
const SweepErasuresWorkflow = "chronos.compliance.SweepErasures.v1"

// restartOverdueActivity restarts the clocks one batch at a time.
const restartOverdueActivity = "chronos.compliance.RestartOverdueErasures.v1"

// DefaultErasureSweepInterval is how often the backstop runs.
//
// SIX HOURS, which is deliberately not "often". The reactor starts a clock the
// moment a request is appended, so this finds only what that missed — and what
// it missed is a deployment-shaped failure, not a per-request one. A sweep every
// minute would scan the same rows constantly to catch something that happens
// when somebody changes a config.
//
// It is also well inside the grace period, so a request the reactor dropped is
// picked up long before its deadline rather than after it.
const DefaultErasureSweepInterval = 6 * time.Hour

const (
	defaultErasureSweepBatch  = 100
	defaultErasureSweepPasses = 20
)

// SweepErasuresInput bounds one run.
type SweepErasuresInput struct {
	// Batch is how many overdue requests one activity call handles.
	Batch int

	// MaxPasses bounds the run. Reached only if the backlog exceeds
	// Batch × MaxPasses, which on a healthy system never happens because the
	// reactor has already started every clock.
	MaxPasses int
}

func (in SweepErasuresInput) withDefaults() SweepErasuresInput {
	if in.Batch <= 0 {
		in.Batch = defaultErasureSweepBatch
	}
	if in.MaxPasses <= 0 {
		in.MaxPasses = defaultErasureSweepPasses
	}
	return in
}

// SweepErasuresResult is the run's output, which outlives its logs.
type SweepErasuresResult struct {
	Passes  int
	Scanned int

	// Started is the number that matters. On a healthy system it is ZERO: every
	// overdue request already has a running workflow, and starting one collapses
	// on the workflow id. Non-zero means requests existed that nothing was going
	// to act on.
	Started int

	Failed    int
	Truncated bool
}

// SweepErasures restarts erasure clocks for requests that have none.
func SweepErasures(
	ctx workflow.Context, in SweepErasuresInput,
) (SweepErasuresResult, error) {
	in = in.withDefaults()

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:        5 * time.Second,
			BackoffCoefficient:     2,
			MaximumInterval:        time.Minute,
			MaximumAttempts:        0,
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 15 * time.Minute,
	})

	// ONE clock reading for the whole run, taken here rather than in the
	// activity, so a retried attempt and the original agree about which requests
	// were overdue.
	now := workflow.Now(ctx).UTC()
	log := workflow.GetLogger(ctx)

	var total SweepErasuresResult
	for pass := 1; pass <= in.MaxPasses; pass++ {
		var got ErasureSweepPass
		err := workflow.ExecuteActivity(ctx, restartOverdueActivity, RestartOverdueInput{
			Now: now, Limit: in.Batch,
		}).Get(ctx, &got)
		if err != nil {
			// Returned rather than swallowed: "the sweep is broken" and "there
			// was nothing to sweep" look identical otherwise, and this is the
			// backstop for a statutory obligation.
			return total, fmt.Errorf("restarting overdue erasures (pass %d): %w", pass, err)
		}

		total.Passes = pass
		total.Scanned += got.Scanned
		total.Started += got.Started
		total.Failed += got.Failed

		if !got.More {
			return total, nil
		}
		total.Truncated = pass == in.MaxPasses
	}

	log.Warn("the erasure sweep stopped at its pass limit with work remaining; deletion "+
		"requests past their deadline are still without a running clock until the next run",
		"passes", total.Passes, "started", total.Started, "failed", total.Failed)
	return total, nil
}

// RestartOverdueInput is the activity argument.
//
// Now is passed IN for the reason SweepReservations passes its own: a retried
// attempt and the original must agree about which requests were overdue, and the
// workflow owns the only clock reading in the run.
type RestartOverdueInput struct {
	Now   time.Time
	Limit int
}

// ErasureSweepPass is what one activity call did.
type ErasureSweepPass struct {
	Scanned int
	Started int
	Failed  int
	More    bool
}

// ErasureSweeper is the use case this activity drives.
type ErasureSweeper interface {
	SweepOnce(ctx context.Context, now time.Time, limit int) (ErasureSweepPass, error)
}

// ErasureSweepActivities is the activity set.
type ErasureSweepActivities struct{ sweeper ErasureSweeper }

func NewErasureSweepActivities(s ErasureSweeper) (*ErasureSweepActivities, error) {
	if s == nil {
		return nil, errors.New("temporal: refusing to build the erasure-sweep activities " +
			"with no sweeper; every run would report a clean pass having scanned nothing")
	}
	return &ErasureSweepActivities{sweeper: s}, nil
}

// RestartOverdue runs one pass.
func (a *ErasureSweepActivities) RestartOverdue(
	ctx context.Context, in RestartOverdueInput,
) (ErasureSweepPass, error) {
	if in.Limit <= 0 {
		// Refused permanently: a retry re-reads the same input.
		return ErasureSweepPass{}, sdktemporal.NewNonRetryableApplicationError(
			fmt.Sprintf("an erasure sweep needs a positive batch size, got %d", in.Limit),
			errTypePermanent, nil)
	}
	pass, err := a.sweeper.SweepOnce(ctx, in.Now, in.Limit)
	if err != nil {
		activity.GetLogger(ctx).Error("restarting overdue erasures", "error", err)
		return ErasureSweepPass{}, err
	}
	return pass, nil
}

// RegisterErasureSweep binds the sweep to a worker.
func (w *Worker) RegisterErasureSweep(a *ErasureSweepActivities) ([]string, error) {
	switch {
	case w == nil || w.w == nil:
		return nil, errors.New("temporal: cannot register the erasure sweep on a nil worker")
	case a == nil:
		return nil, errors.New("temporal: refusing to register the erasure sweep with no " +
			"activity set; every run would fail on its first task")
	}
	registerErasureSweep(w.w, a)
	return []string{SweepErasuresWorkflow}, nil
}

func registerErasureSweep(r registry, a *ErasureSweepActivities) {
	r.RegisterWorkflowWithOptions(SweepErasures,
		workflow.RegisterOptions{Name: SweepErasuresWorkflow})
	r.RegisterActivityWithOptions(a.RestartOverdue,
		activity.RegisterOptions{Name: restartOverdueActivity})
}
