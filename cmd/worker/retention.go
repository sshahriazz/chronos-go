package main

import (
	"context"
	"errors"
	"log/slog"
	"time"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
)

// retentionAdapter presents the identity use case as the durable-work port.
//
// Two result types rather than one shared type, for the same reason sweepAdapter
// exists: the alternative is internal/adapter/temporal importing an identity use
// case, and an adapter that knows a module is an adapter that will eventually
// decide something for it — here, how long a session row is kept. The conversion
// is mechanical and total.
type retentionAdapter struct{ retention *app.Retention }

var _ temporaladapter.IdentityRetainer = retentionAdapter{}

func (r retentionAdapter) PurgeOnce(
	ctx context.Context, now time.Time,
) (temporaladapter.PurgeRetentionResult, error) {
	res, err := r.retention.PurgeOnce(ctx, now)

	out := temporaladapter.PurgeRetentionResult{
		Statements: make([]temporaladapter.StatementResult, 0, len(res.Outcomes)),
		Deleted:    res.Deleted,
		Failed:     res.Failed,
	}
	for _, o := range res.Outcomes {
		s := temporaladapter.StatementResult{Statement: o.Statement, Deleted: o.Deleted}
		if o.Err != nil {
			// Flattened to a string at the boundary: this crosses into workflow
			// history, where it is read by a person in the Temporal UI long after
			// the run. An error value would serialise to an object nobody can act
			// on.
			s.Error = o.Err.Error()
		}
		out.Statements = append(out.Statements, s)
	}
	return out, err
}

// newIdentityRetention builds the retention job, or reports why it could not be.
//
// The read model is the whole dependency: every one of the five statements is a
// DELETE against it. There is no event store here and there should not be —
// retention removes rows the log cannot restore (a token digest, a spent step)
// and rows a replay would recreate anyway (a released reservation). Nothing it
// does is an event, because nothing decided anything: a deadline passed.
func newIdentityRetention(d *dependencies, log *slog.Logger) (*app.Retention, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: identity's retention statements are DELETEs " +
			"against it, so none of them can run")
	}

	store, err := identitypg.NewRetention(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}
	return app.NewRetention(store, log)
}

// scheduleRetention makes identity's retention job recur.
//
// Separate from scheduleSweep rather than folded into it, because the two failures
// are different and the log lines have to say different things. A missing sweep
// eventually reaches a user who cannot register with their own address; a missing
// retention job reaches nobody, ever, which is precisely why it needs its own
// line saying so.
func (d *dependencies) scheduleRetention(log *slog.Logger) {
	ctx, cancel := context.WithTimeout(context.Background(), scheduleTimeout)
	defer cancel()

	created, err := temporaladapter.EnsureRetentionSchedule(ctx, d.temporal,
		temporaladapter.PurgeRetentionInput{}, temporaladapter.DefaultRetentionInterval)
	switch {
	case err != nil:
		log.Error("identity retention is NOT scheduled; spent TOTP steps, expired token "+
			"digests and dead session secrets are retained indefinitely and nothing else "+
			"will report it",
			"schedule", temporaladapter.PurgeRetentionScheduleID, "error", err)
	case created:
		log.Info("identity retention scheduled",
			"schedule", temporaladapter.PurgeRetentionScheduleID,
			"every", temporaladapter.DefaultRetentionInterval)
	default:
		log.Info("identity retention already scheduled",
			"schedule", temporaladapter.PurgeRetentionScheduleID)
	}
}
