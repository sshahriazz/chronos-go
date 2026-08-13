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

// SweepReservationsWorkflow frees email reservations whose unverified lease has
// run out.
//
// The name is PERSISTED in workflow history and in the schedule that starts it,
// so it is permanent in the same way SendNotificationWorkflow is: renaming it
// leaves the schedule pointing at a workflow no worker answers to, and — because
// this one is a security control rather than a delivery mechanism — the symptom
// is not a missing email but addresses staying held by people who never proved
// they own them.
const SweepReservationsWorkflow = "chronos.identity.SweepEmailReservations.v1"

// releaseLapsedActivity is the single I/O step: read the work list, load each
// reservation aggregate, append its release. All of it lives in the activity
// because workflow code must be deterministic — no clock, no network, no
// randomness — and every one of those three things is I/O.
const releaseLapsedActivity = "chronos.identity.ReleaseLapsedReservations.v1"

// SweepReservationsInput parametrises one run.
//
// It carries no address, no index and no subject: the work list is read inside
// the activity. Workflow input is written to history, which is durable and
// replicated, so the less that crosses this boundary the better (ADR-002).
type SweepReservationsInput struct {
	// Batch is the per-pass LIMIT on the work list. Bounded because an
	// unbounded sweep is one query away from loading every reservation in the
	// system into one activity, and one slow pass then starves the next.
	Batch int

	// MaxPasses bounds the whole run. The sweep loops while its batch keeps
	// filling, so without a cap a large backlog would extend one execution's
	// history indefinitely.
	MaxPasses int
}

// SweepReservationsResult is what one run did, and it is the run's OUTPUT
// rather than a log line: workflow results are visible in the UI and in
// visibility queries long after the log has rotated, and "how many addresses did
// we free, and how many failed" is the question asked when somebody cannot
// register with their own address.
type SweepReservationsResult struct {
	Passes   int
	Scanned  int
	Released int
	Stale    int
	Failed   int

	// Truncated reports that the run stopped at MaxPasses with the last batch
	// still full — so lapsed reservations were left behind. It is deliberately
	// part of the result: a sweep that quietly stopped at its limit reads as
	// "everything is swept" while the backlog it did not reach grows.
	Truncated bool
}

// sweepDefaults are the batch and pass bounds a start that names neither gets.
//
// 200 × 10 = 2000 releases per run. Sized against the schedule interval rather
// than against Postgres: at the default interval a backlog larger than this is
// not a slow sweep, it is an incident, and Truncated is how it becomes visible.
const (
	defaultSweepBatch     = 200
	defaultSweepMaxPasses = 10
)

// withDefaults fills in what a start left unset.
//
// Deterministic and pure — it runs inside the workflow, where a value that
// differed between the original execution and a replay would corrupt history.
func (in SweepReservationsInput) withDefaults() SweepReservationsInput {
	if in.Batch <= 0 {
		in.Batch = defaultSweepBatch
	}
	if in.MaxPasses <= 0 {
		in.MaxPasses = defaultSweepMaxPasses
	}
	return in
}

// SweepReservations drains the lapsed list in bounded passes.
//
// The loop is the whole point. The work list is LIMITed, so a single pass that
// comes back full has almost certainly left work behind; stopping there would
// report success over a backlog. It loops while batches keep filling, and when
// it hits MaxPasses it says so in the result rather than returning quietly.
//
// It reads the clock ONCE, through workflow.Now, and passes that instant to
// every pass. time.Now here would be non-deterministic and would fail replay;
// re-reading the clock per pass would also be legal but would make two passes of
// one run disagree about which reservations had lapsed, for no benefit.
func SweepReservations(
	ctx workflow.Context, in SweepReservationsInput,
) (SweepReservationsResult, error) {
	in = in.withDefaults()

	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// One pass: a bounded batch of aggregate loads and appends. Generous
		// against a slow event store, short enough that a hung one is retried
		// rather than waited on for the whole run.
		StartToCloseTimeout: 5 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    5 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    time.Minute,
			// Bounded by ScheduleToClose rather than by attempts: the next
			// scheduled run picks up whatever this one could not do, so there is
			// no value in retrying past the point where that run starts.
			MaximumAttempts: 0,
			// An input the activity refuses is refused identically forever.
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 15 * time.Minute,
	})

	now := workflow.Now(ctx).UTC()
	log := workflow.GetLogger(ctx)

	var total SweepReservationsResult
	for pass := 1; pass <= in.MaxPasses; pass++ {
		var got SweepPass
		err := workflow.ExecuteActivity(ctx, releaseLapsedActivity, ReleaseLapsedInput{
			Now:   now,
			Limit: in.Batch,
		}).Get(ctx, &got)
		if err != nil {
			// Returned rather than swallowed: the run failed to sweep, and a
			// schedule with PauseOnFailure off simply runs again — but the
			// failure has to be visible as a failure, because "the sweep is
			// broken" and "there was nothing to sweep" look identical otherwise.
			return total, fmt.Errorf("sweeping lapsed reservations (pass %d): %w", pass, err)
		}

		total.Passes = pass
		total.Scanned += got.Scanned
		total.Released += got.Released
		total.Stale += got.Stale
		total.Failed += got.Failed

		if !got.More {
			return total, nil
		}
		total.Truncated = pass == in.MaxPasses
	}

	// Reached only with the last batch still full.
	log.Warn("the lapsed email-reservation sweep stopped at its pass limit with work "+
		"remaining; addresses claimed by unverified registrations stay held until the "+
		"next run frees them",
		"passes", total.Passes, "released", total.Released, "failed", total.Failed)
	return total, nil
}

// ReleaseLapsedInput is the activity argument.
//
// Now is passed IN rather than read in the activity, so that a retried attempt
// and the original agree about which reservations had lapsed — and so the
// workflow, not the activity, owns the only clock reading in the run.
type ReleaseLapsedInput struct {
	Now   time.Time
	Limit int
}

// SweepPass is one pass's counters, crossing the activity boundary.
//
// It mirrors the use case's result rather than sharing the type, which keeps
// this adapter free of the identity module — the same reason NotificationActivities
// declares its own Dispatcher interface instead of importing the dispatcher.
type SweepPass struct {
	Scanned  int
	Released int
	Stale    int
	Failed   int

	// More reports that the batch limit was reached and there is likely work
	// left. It is what makes the workflow loop instead of guessing.
	More bool
}

// ReservationSweeper is the activity's dependency: the identity use case that
// knows how to turn a lapsed row into a release on the address's stream.
//
// Declared as an interface so this package neither depends on the identity
// module nor can be tempted into re-implementing the decision. The decision has
// exactly one correct home, because it is the aggregate — loaded from its
// stream — that says whether a claim may be freed, never the projected row.
type ReservationSweeper interface {
	SweepOnce(ctx context.Context, now time.Time, limit int) (SweepPass, error)
}

// ReservationActivities holds the I/O half of the sweep.
type ReservationActivities struct{ sweeper ReservationSweeper }

// NewReservationActivities builds the activity set.
func NewReservationActivities(s ReservationSweeper) (*ReservationActivities, error) {
	if s == nil {
		return nil, errors.New("temporal: the reservation sweep activity needs a sweeper; " +
			"without one every run would report success while releasing nothing, and an " +
			"address claimed by an unverified registration would be held forever")
	}
	return &ReservationActivities{sweeper: s}, nil
}

// ReleaseLapsed performs one bounded pass.
//
// It returns an error only when the pass could not be attempted — an unreadable
// work list, an invalid input. Individual reservations that fail are counted and
// reported, because one address whose stream cannot be read must not stop the
// rest of the batch from being freed, and because the row stays lapsed and is
// picked up again by the next run.
func (a *ReservationActivities) ReleaseLapsed(
	ctx context.Context, in ReleaseLapsedInput,
) (SweepPass, error) {
	if in.Limit <= 0 {
		return SweepPass{}, sdktemporal.NewNonRetryableApplicationError(
			"a sweep limit of zero releases nothing and never will", errTypePermanent,
			fmt.Errorf("limit %d", in.Limit))
	}
	if in.Now.IsZero() {
		return SweepPass{}, sdktemporal.NewNonRetryableApplicationError(
			"a sweep needs the instant to measure deadlines against", errTypePermanent,
			errors.New("no time supplied"))
	}
	return a.sweeper.SweepOnce(ctx, in.Now.UTC(), in.Limit)
}

// RegisterReservationSweep adds the sweep to a worker, returning the workflow
// names it now answers to.
//
// It returns the names rather than nothing so a composition-root test can assert
// the binary registered them WITHOUT starting a worker or reaching Temporal.
// Three adapters in this repository were once fully built, fully tested and
// constructed by no binary; for a security control the equivalent gap is worse,
// because nothing about the system looks different until somebody cannot
// register with an address that is theirs.
func (w *Worker) RegisterReservationSweep(a *ReservationActivities) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register the reservation sweep on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register the reservation sweep with no " +
			"activity set; the schedule would start runs that fail on every task")
	}
	registerSweep(w.w, a)
	return []string{SweepReservationsWorkflow}, nil
}

// registry is the registration surface shared by a real worker and the SDK's
// test environment.
//
// Narrower than worker.Registry on purpose: the test environment offers these
// two methods and not the whole interface, and it is the test environment that
// has to go through the same code as production or the test proves nothing about
// what the binary registers.
type registry interface {
	RegisterWorkflowWithOptions(w any, options workflow.RegisterOptions)
	RegisterActivityWithOptions(a any, options activity.RegisterOptions)
}

// registerSweep is the ONE place the names are bound to the code, so the worker
// and the test cannot register different things under the same names.
func registerSweep(r registry, a *ReservationActivities) {
	r.RegisterWorkflowWithOptions(SweepReservations,
		workflow.RegisterOptions{Name: SweepReservationsWorkflow})
	r.RegisterActivityWithOptions(a.ReleaseLapsed,
		activity.RegisterOptions{Name: releaseLapsedActivity})
}
