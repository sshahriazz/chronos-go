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

// PurgeIdentityRetentionWorkflow deletes identity rows that can no longer affect
// any decision.
//
// The name is PERSISTED in workflow history and in the schedule that starts it,
// so it is permanent in the same way SweepReservationsWorkflow is: renaming it
// leaves the schedule pointing at a workflow no worker answers to. The symptom
// differs though, and it is worth being clear about the difference. The
// reservation sweep is a security control and its absence eventually reaches a
// user who cannot register. This one is retention: its absence reaches nobody
// at all, ever, until a table with no TTL is the largest thing in the database.
const PurgeIdentityRetentionWorkflow = "chronos.identity.PurgeRetention.v1"

// purgeRetentionActivity is the single I/O step: five DELETE statements, each in
// its own system transaction. All of it lives in the activity because workflow
// code must be deterministic, and every one of those statements is I/O.
const purgeRetentionActivity = "chronos.identity.PurgeRetentionStatements.v1"

// PurgeRetentionInput parametrises one run, and carries nothing.
//
// Deliberately empty. The horizons are POLICY — they are declared as constants
// beside the statements they govern, in identity's app package, where whoever
// changes what a session row is for will see them — and not per-run
// configuration. A schedule that could pass a shorter horizon is a schedule that
// can delete a year of session history because somebody typed a wrong argument
// once.
//
// It exists as a type rather than being omitted so the schedule's argument list
// is stable: adding a first field later is a change to what the workflow reads,
// not a change to how many arguments it takes.
type PurgeRetentionInput struct{}

// StatementResult is what one retention statement did, crossing the activity
// boundary and into workflow history.
//
// It mirrors identity's own result rather than sharing the type, which keeps this
// adapter free of the identity module — the same reason NotificationActivities
// declares its own Dispatcher interface and SweepPass mirrors the sweep's
// counters.
type StatementResult struct {
	// Statement names the table swept. A stable string, not a Go identifier: it
	// is what an operator greps for.
	Statement string

	// Deleted is the affected-row count.
	Deleted int64

	// Error is why this statement did nothing, or empty. A STRING rather than an
	// error because this crosses a serialisation boundary — and because it is
	// read by a human in the Temporal UI long after the run, where an error value
	// would be a JSON object nobody can act on.
	Error string
}

// PurgeRetentionResult is what one run did, per statement.
//
// It is the run's OUTPUT rather than a log line, for the reason
// SweepReservationsResult is: workflow results are visible in the UI and in
// visibility queries long after logs have rotated, and "when did we last actually
// delete anything from totp_replay" is the question asked when that table turns
// out to be enormous.
//
// Per statement rather than one total, deliberately. A total of four thousand
// rows is entirely compatible with the TOTP replay table never being touched —
// and that table is the reason this job exists.
type PurgeRetentionResult struct {
	// Statements is one entry per statement, in the order they ran.
	Statements []StatementResult

	// Deleted is the sum across statements that succeeded.
	Deleted int64

	// Failed is how many statements could not run. Non-zero does NOT fail the
	// run: the other tables were still swept, and the next run retries the one
	// that was not.
	Failed int
}

// PurgeIdentityRetention runs identity's retention statements once.
//
// One activity, no loop — unlike the reservation sweep, which loops while its
// batches keep filling. These statements are unbounded DELETEs with no LIMIT and
// no work list: each one either removes everything it should or fails, so there
// is nothing for a second pass to pick up.
//
// The clock is read ONCE, through workflow.Now, and passed to the activity.
// time.Now here would be non-deterministic and would fail replay; reading it in
// the activity would make a retried attempt use a different horizon from the
// original.
func PurgeIdentityRetention(
	ctx workflow.Context, _ PurgeRetentionInput,
) (PurgeRetentionResult, error) {
	ctx = workflow.WithActivityOptions(ctx, workflow.ActivityOptions{
		// Five unbounded DELETEs. Generous because a first run against a
		// deployment that has never had retention may be deleting a very large
		// backlog, and short enough that a hung database is retried rather than
		// waited on until the next daily run.
		StartToCloseTimeout: 30 * time.Minute,
		RetryPolicy: &sdktemporal.RetryPolicy{
			InitialInterval:    30 * time.Second,
			BackoffCoefficient: 2,
			MaximumInterval:    5 * time.Minute,
			// Bounded by ScheduleToClose rather than by attempts, and the bound is
			// well short of the daily interval: there is no value in a run still
			// retrying when the next one is due, because the next one does exactly
			// the same work.
			MaximumAttempts: 0,
			// An input the activity refuses is refused identically forever.
			NonRetryableErrorTypes: []string{errTypePermanent},
		},
		ScheduleToCloseTimeout: 2 * time.Hour,
	})

	now := workflow.Now(ctx).UTC()
	log := workflow.GetLogger(ctx)

	var res PurgeRetentionResult
	err := workflow.ExecuteActivity(ctx, purgeRetentionActivity,
		PurgeRetentionActivityInput{Now: now}).Get(ctx, &res)
	if err != nil {
		// Returned rather than swallowed: the pass could not be attempted at all,
		// and "retention is broken" must not look like "there was nothing to
		// delete". A schedule with PauseOnFailure off simply runs again tomorrow.
		return res, fmt.Errorf("purging identity retention: %w", err)
	}

	// Logged HERE as well as in the result, and per statement. The result is what
	// survives in the UI; the log line is what an alert can be built on. Neither
	// alone is enough — a job nobody can see the output of is a job nobody
	// notices has stopped.
	for _, s := range res.Statements {
		if s.Error != "" {
			log.Error("an identity retention statement failed; its table keeps growing "+
				"until a later run clears it",
				"statement", s.Statement, "error", s.Error)
			continue
		}
		log.Info("identity retention statement complete",
			"statement", s.Statement, "deleted", s.Deleted)
	}

	// Every statement failing is a different fact from one statement failing: it
	// means the database was unreachable or the app role lost its grants, not that
	// one DELETE is broken. That must surface as a FAILED run — the whole point of
	// tolerating per-statement failures is that the other statements still ran,
	// and here none did.
	if res.Failed > 0 && res.Failed == len(res.Statements) {
		return res, fmt.Errorf("every identity retention statement failed (%d of %d); "+
			"nothing was deleted", res.Failed, len(res.Statements))
	}
	return res, nil
}

// PurgeRetentionActivityInput is the activity argument.
//
// Now is passed IN rather than read in the activity, so that a retried attempt
// and the original agree about the horizon — and so the workflow, not the
// activity, owns the only clock reading in the run.
type PurgeRetentionActivityInput struct{ Now time.Time }

// IdentityRetainer is the activity's dependency: the identity use case that owns
// the statements and the horizons they measure against.
//
// Declared as an interface so this package neither depends on the identity module
// nor can be tempted into deciding retention policy for it. How long a session
// row is kept is a question about what the security-settings screen has to
// answer, and this package has no business having an opinion about that.
type IdentityRetainer interface {
	PurgeOnce(ctx context.Context, now time.Time) (PurgeRetentionResult, error)
}

// RetentionActivities holds the I/O half of the retention job.
type RetentionActivities struct{ retainer IdentityRetainer }

// NewRetentionActivities builds the activity set.
func NewRetentionActivities(r IdentityRetainer) (*RetentionActivities, error) {
	if r == nil {
		return nil, errors.New("temporal: the retention activity needs a retainer; without " +
			"one every run would report success while deleting nothing, and identity's " +
			"tables with no TTL would grow for the lifetime of the deployment")
	}
	return &RetentionActivities{retainer: r}, nil
}

// Purge performs one pass.
//
// It returns an error only when the pass could not be ATTEMPTED — a missing
// instant, a use case that could not read anything at all. Individual statements
// that fail are counted and reported inside the result, because these five tables
// are unrelated and one broken statement must not stop the other four from being
// swept.
func (a *RetentionActivities) Purge(
	ctx context.Context, in PurgeRetentionActivityInput,
) (PurgeRetentionResult, error) {
	if in.Now.IsZero() {
		return PurgeRetentionResult{}, sdktemporal.NewNonRetryableApplicationError(
			"retention needs the instant to measure its horizons against", errTypePermanent,
			errors.New("no time supplied"))
	}
	return a.retainer.PurgeOnce(ctx, in.Now.UTC())
}

// RegisterIdentityRetention adds the retention job to a worker, returning the
// workflow names it now answers to.
//
// It returns the names rather than nothing so a composition-root test can assert
// the binary registered them WITHOUT starting a worker or reaching Temporal.
// Three adapters in this repository were once fully built, fully tested and
// constructed by no binary; for retention the equivalent gap produces no symptom
// whatsoever until a table nothing bounds is the largest object in the database.
func (w *Worker) RegisterIdentityRetention(a *RetentionActivities) ([]string, error) {
	if w == nil || w.w == nil {
		return nil, errors.New("temporal: cannot register identity retention on a nil worker")
	}
	if a == nil {
		return nil, errors.New("temporal: refusing to register identity retention with no " +
			"activity set; the schedule would start runs that fail on every task")
	}
	registerRetention(w.w, a)
	return []string{PurgeIdentityRetentionWorkflow}, nil
}

// registerRetention is the ONE place these names are bound to the code, so the
// worker and the test cannot register different things under the same names. It
// takes the same narrow registry the sweep does, which is what lets the SDK's
// test environment go through production's registration path.
func registerRetention(r registry, a *RetentionActivities) {
	r.RegisterWorkflowWithOptions(PurgeIdentityRetention,
		workflow.RegisterOptions{Name: PurgeIdentityRetentionWorkflow})
	r.RegisterActivityWithOptions(a.Purge,
		activity.RegisterOptions{Name: purgeRetentionActivity})
}
