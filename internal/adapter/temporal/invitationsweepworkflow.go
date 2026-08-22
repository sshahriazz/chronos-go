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

// SweepInvitationsWorkflow expires invitations whose window has run out.
//
// The name is PERSISTED in workflow history and in the schedule that starts it,
// so it is permanent for the reason SweepReservationsWorkflow is: renaming it
// leaves the schedule pointing at a workflow no worker answers to. The symptom
// is not a missing email — it is seats held forever by invitations nobody can
// accept, and an organization paying for people who never arrived.
const SweepInvitationsWorkflow = "chronos.workspace.SweepInvitations.v1"

// expireInvitationsActivity is the single I/O step: read the work list, load
// each invitation aggregate, append its expiry, release its seat. All of it
// lives in the activity because workflow code must be deterministic — no clock,
// no network, no randomness — and every one of those is I/O.
const expireInvitationsActivity = "chronos.workspace.ExpireInvitations.v1"

// SweepInvitationsInput parametrises one run.
//
// It carries no invitation id, no organization and no subject: the work list is
// read inside the activity. Workflow input is written to history, which is
// durable and replicated, so the less that crosses this boundary the better
// (ADR-002).
type SweepInvitationsInput struct {
	// Batch is the per-pass LIMIT on the work list.
	Batch int

	// MaxPasses bounds the whole run. The sweep loops while its batch keeps
	// filling, so without a cap a large backlog would extend one execution's
	// history indefinitely.
	MaxPasses int
}

// SweepInvitationsResult is what one run did, and it is the run's OUTPUT rather
// than a log line: workflow results are visible in the UI and in visibility
// queries long after the log has rotated, and "how many seats did we give back,
// and how many failed" is the question asked when an organization's seat count
// does not match its people.
type SweepInvitationsResult struct {
	Passes  int
	Scanned int
	Expired int
	Stale   int
	Failed  int

	// Truncated reports that the run stopped at MaxPasses with the last batch
	// still full, so lapsed invitations were left behind. Part of the result
	// deliberately: a sweep that quietly stopped at its limit reads as
	// "everything is swept" while the backlog it did not reach grows.
	Truncated bool
}

// withDefaults fills in what a start left unset.
//
// Deterministic and pure — it runs inside the workflow, where a value differing
// between the original execution and a replay would corrupt history.
func (in SweepInvitationsInput) withDefaults() SweepInvitationsInput {
	if in.Batch <= 0 {
		in.Batch = defaultSweepBatch
	}
	if in.MaxPasses <= 0 {
		in.MaxPasses = defaultSweepMaxPasses
	}
	return in
}

// SweepInvitations drains the overdue list in bounded passes.
//
// # Why this exists when a per-invitation workflow also expires them
//
// That one makes expiry TIMELY. This makes it CERTAIN. A workflow that was never
// started — the worker down when the event arrived, Temporal unreachable, the
// reactor parked — leaves a seat held forever, and nothing else in the system
// would ever notice. It is the same relationship the trial reconciliation has
// with the Stripe webhook: the webhook does the work, and the reconciliation
// catches the webhook that never came.
//
// It reads the clock ONCE, through workflow.Now, and passes that instant to
// every pass. time.Now here would be non-deterministic and would fail replay;
// re-reading per pass would be legal but would make two passes of one run
// disagree about which invitations had lapsed, for no benefit.
func SweepInvitations(
	ctx workflow.Context, in SweepInvitationsInput,
) (SweepInvitationsResult, error) {
	in = in.withDefaults()

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// One pass: a bounded batch of aggregate loads, appends and seat
		// releases. Generous against a slow event store, short enough that a
		// hung one is retried rather than waited on for the whole run.
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			// Bounded by ScheduleToClose rather than by attempts: the next
			// scheduled run picks up whatever this one could not do.
			MaximumAttempts:        0,
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 15 * time.Minute,
	})

	now := workflow.Now(ctx).UTC()
	log := workflow.GetLogger(ctx)

	var total SweepInvitationsResult
	for pass := 1; pass <= in.MaxPasses; pass++ {
		var got InvitationSweepPass
		err := workflow.ExecuteActivity(ctx, expireInvitationsActivity, ExpireInvitationsInput{
			Now:   now,
			Limit: in.Batch,
		}).Get(ctx, &got)
		if err != nil {
			// Returned rather than swallowed: the run failed to sweep, and the
			// failure has to be visible AS a failure, because "the sweep is
			// broken" and "there was nothing to sweep" look identical otherwise.
			return total, fmt.Errorf("expiring invitations (pass %d): %w", pass, err)
		}

		total.Passes = pass
		total.Scanned += got.Scanned
		total.Expired += got.Expired
		total.Stale += got.Stale
		total.Failed += got.Failed

		if !got.More {
			return total, nil
		}
		total.Truncated = pass == in.MaxPasses
	}

	// Reached only with the last batch still full.
	log.Warn("the invitation sweep stopped at its pass limit with work remaining; the "+
		"seats those invitations hold stay held until the next run gives them back",
		"passes", total.Passes, "expired", total.Expired, "failed", total.Failed)
	return total, nil
}

// ExpireInvitationsInput is the activity argument.
//
// Now is passed IN rather than read in the activity, so a retried attempt and
// the original agree about which invitations had lapsed — and so the workflow,
// not the activity, owns the only clock reading in the run.
type ExpireInvitationsInput struct {
	Now   time.Time
	Limit int
}

// InvitationSweepPass is one pass's counters, crossing the activity boundary.
//
// It mirrors the use case's result rather than sharing the type, which keeps
// this adapter free of the workspace module — the same reason
// NotificationActivities declares its own Dispatcher interface.
type InvitationSweepPass struct {
	Scanned int
	Expired int
	Stale   int
	Failed  int

	// More reports that the batch limit was reached and there is likely work
	// left. It is what makes the workflow loop instead of guessing.
	More bool
}

// InvitationSweeper is the activity's dependency: the workspace use case that
// turns an overdue row into an expiry on the invitation's stream.
//
// Declared as an interface so this package neither depends on the workspace
// module nor can be tempted into re-implementing the decision. That decision has
// exactly one correct home, because it is the aggregate — loaded from its
// stream — that says whether an invitation may be expired, never the projected
// row: a resend moves the deadline after the row was read.
type InvitationSweeper interface {
	SweepOnce(ctx context.Context, now time.Time, limit int) (InvitationSweepPass, error)
}

// InvitationActivities holds the I/O half of the sweep.
type InvitationActivities struct{ sweeper InvitationSweeper }

// NewInvitationActivities builds the activity set.
func NewInvitationActivities(s InvitationSweeper) (*InvitationActivities, error) {
	if s == nil {
		return nil, errors.New("temporal: the invitation sweep activity needs a sweeper; " +
			"without one every run would report success while expiring nothing, and a seat " +
			"held by a lapsed invitation would be held forever")
	}
	return &InvitationActivities{sweeper: s}, nil
}

// ExpireInvitations performs one bounded pass.
//
// It returns an error only when the pass could not be ATTEMPTED — an unreadable
// work list, an invalid input. Individual invitations that fail are counted and
// reported in the pass, because one unreadable stream must not stop the rest of
// the batch from giving their seats back.
func (a *InvitationActivities) ExpireInvitations(
	ctx context.Context, in ExpireInvitationsInput,
) (InvitationSweepPass, error) {
	if in.Limit <= 0 {
		// Refused permanently rather than retried: a limit of zero scans nothing
		// and will scan nothing on every attempt, so retrying burns the whole
		// ScheduleToClose window to reach the same answer.
		return InvitationSweepPass{}, sdktemporal.NewNonRetryableApplicationError(
			fmt.Sprintf("a sweep batch of %d would scan nothing", in.Limit),
			errTypePermanent, nil)
	}
	if in.Now.IsZero() {
		return InvitationSweepPass{}, sdktemporal.NewNonRetryableApplicationError(
			"the sweep was given no instant to measure expiry against",
			errTypePermanent, nil)
	}

	pass, err := a.sweeper.SweepOnce(ctx, in.Now, in.Limit)
	if err != nil {
		return InvitationSweepPass{}, err
	}

	// Logged through the ACTIVITY's logger, which is heartbeat-aware and carries
	// the run id — so a pass that expired nothing is attributable to the run
	// that did it rather than to whichever process happened to hold the task.
	activity.GetLogger(ctx).Info("invitation sweep pass",
		"scanned", pass.Scanned, "expired", pass.Expired,
		"stale", pass.Stale, "failed", pass.Failed, "more", pass.More)
	return pass, nil
}

// RegisterInvitationSweep adds the sweep to a worker, returning the workflow
// names it now answers to.
//
// It returns the names rather than nothing so a composition-root test can assert
// the binary registered them WITHOUT starting a worker or reaching Temporal. For
// a control whose absence is invisible this matters more than usual: nothing
// about the system looks different until an organization notices it is paying
// for seats held by invitations that expired weeks ago.
func (w *Worker) RegisterInvitationSweep(a *InvitationActivities) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register the invitation sweep on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register the invitation sweep with no " +
			"activity set; the schedule would start runs that fail on every task")
	}
	registerInvitationSweep(w.w, a)
	return []string{SweepInvitationsWorkflow}, nil
}

// registerInvitationSweep binds the workflow and its activity by NAME.
//
// By name rather than by function value, because the name is what history and
// the schedule record — registering the function under its Go identifier would
// make a rename silently strand every in-flight execution.
func registerInvitationSweep(r registry, a *InvitationActivities) {
	r.RegisterWorkflowWithOptions(SweepInvitations,
		workflow.RegisterOptions{Name: SweepInvitationsWorkflow})
	r.RegisterActivityWithOptions(a.ExpireInvitations,
		activity.RegisterOptions{Name: expireInvitationsActivity})
}
