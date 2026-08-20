package temporal

import (
	"context"
	"errors"
	"fmt"
	"time"

	enumspb "go.temporal.io/api/enums/v1"
	"go.temporal.io/sdk/client"
	sdktemporal "go.temporal.io/sdk/temporal"
)

// ResealCredentialKeysScheduleID identifies the recurring re-sealing job.
//
// Stable and permanent: a schedule is server-side state, so a changed id creates
// a SECOND schedule rather than moving the first, and both then run. Two
// re-sealing schedules would not corrupt anything — the compare-and-set makes a
// duplicate pass a no-op — but the old one would keep its old interval and
// nothing reports that two exist.
const ResealCredentialKeysScheduleID = "chronos.identity.credential-key-reseal"

// DefaultResealInterval is how often credential secrets are carried onto the
// current sealing key.
//
// HOURLY, and the choice sits deliberately between the reservation sweep's
// fifteen minutes and retention's twenty-four hours, because this job is neither
// of those things.
//
// It is not a security control in the sweep's sense: nothing is unsafe while it
// is late. It is not housekeeping in retention's sense either — nothing here is
// deleted and nothing grows. It exists to make ONE operator decision answerable:
// "is anything still sealed under the key I am about to destroy?" Before this job
// that question had no path to "no", so the only safe answer was to keep every
// old key forever, including a leaked one.
//
// The interval is therefore chosen against the OPERATOR's loop, not against a
// user's and not against a table's growth. A rotation is a deliberate act
// followed by a wait; hourly means the wait is measured in hours and a rotation
// started in the morning is usually completable the same working day. Daily would
// stretch a routine rotation across the better part of a week, and the cost of
// that is not patience — it is that a key nobody can retire in a reasonable time
// is a key somebody eventually destroys without waiting.
//
// Faster buys nothing. Nobody is blocked on a per-minute basis, and the job's
// idle cost is not free: with no rotation in flight, each run is still one work
// list and one COUNT per kind, and the count has no index behind it. Once an hour
// that is irrelevant; once a minute it is a table scan a minute, forever, for a
// question whose answer changes a few times a year.
//
// The schedule is the BACKSTOP, not the trigger. An operator who has just rotated
// does not have to wait for it — the workflow can be started immediately by hand
// on the same task queue, and that is the expected way a rotation actually
// begins. What the schedule guarantees is that the rotation still finishes if
// nobody remembers to, and that the done check keeps being taken afterwards.
const DefaultResealInterval = time.Hour

// EnsureResealSchedule creates the recurring re-sealing job if it is not already
// there.
//
// A schedule rather than a ticker, a cron table or a time.AfterFunc, for the
// reason ADR-017 gives: none of those outlives the process that created them, and
// this one has to run whether or not any particular worker is up.
//
// Existing schedules are LEFT ALONE, exactly as EnsureSweepSchedule and
// EnsureRetentionSchedule leave theirs. The reason bites hardest here. An
// operator mid-rotation may have paused this job, or narrowed its batch, to keep
// load off a database during a migration; silently reverting that on the next
// deployment restart would restart a bulk rewrite of the credential table with
// nobody expecting it. It is also why nothing about the CURRENT KEY VERSION or
// the set of kinds is baked into the schedule's arguments — anything stored there
// is frozen at creation, and a frozen key version would pin the job to a key that
// stopped being current a rotation ago.
func EnsureResealSchedule(
	ctx context.Context, c *Client, in ResealCredentialKeysInput, every time.Duration,
) (created bool, err error) {
	if c == nil || c.c == nil {
		return false, errors.New("temporal: no client, so credential re-sealing cannot be " +
			"scheduled; a key rotation can then never be completed and every old sealing key " +
			"must be kept alive indefinitely")
	}
	if every <= 0 {
		every = DefaultResealInterval
	}

	_, err = c.c.ScheduleClient().Create(ctx, resealScheduleOptions(c.queue, in, every))
	switch {
	case err == nil:
		return true, nil
	case errors.Is(err, sdktemporal.ErrScheduleAlreadyRunning):
		// The normal case on every restart after the first.
		return false, nil
	default:
		return false, fmt.Errorf("temporal: creating the %s schedule: %w",
			ResealCredentialKeysScheduleID, err)
	}
}

// resealScheduleOptions is what the schedule is created with.
//
// Split out from the call so it can be asserted without a server. The thing worth
// asserting is the ACTION: a schedule naming a workflow no worker registers, or a
// task queue no worker polls, creates a run that is queued where nothing is
// listening — and every observable signal stays green while the count of rows on
// the old key never moves.
func resealScheduleOptions(
	queue string, in ResealCredentialKeysInput, every time.Duration,
) client.ScheduleOptions {
	return client.ScheduleOptions{
		ID:   ResealCredentialKeysScheduleID,
		Spec: client.ScheduleSpec{Intervals: []client.ScheduleIntervalSpec{{Every: every}}},
		Action: &client.ScheduleWorkflowAction{
			ID:        ResealCredentialKeysScheduleID,
			Workflow:  ResealCredentialKeysWorkflow,
			Args:      []any{in.withDefaults()},
			TaskQueue: queue,
		},
		// SKIP, not BUFFER. Two re-sealing runs at once are harmless — the
		// compare-and-set means the loser writes nothing — but they would open
		// and re-seal the same ciphertext twice for no benefit, and a buffered
		// queue turns one slow pass into a pile-up of identical work against the
		// one table in identity that is not rebuildable.
		Overlap: enumspb.SCHEDULE_OVERLAP_POLICY_SKIP,
		// One hour rather than the server's one-year default. The work list is
		// the CURRENT set of rows below the current key version, not a
		// per-interval delta, so replaying a month of missed runs would achieve
		// exactly what the next single run achieves.
		CatchupWindow: time.Hour,
		// A failing run must keep being retried. Pausing would leave a rotation
		// half-finished with no signal saying so — and a half-finished rotation
		// is the state in which destroying the old key does the most damage.
		PauseOnFailure: false,
	}
}

// ResealCredentialKeysProbe watches the re-sealing schedule.
//
// Written here rather than at the wiring site so the consequence is worded once,
// next to the schedule it describes, by whoever knows what the job is for.
//
// This probe reports the least visible of the three schedules. An unscheduled
// reservation sweep eventually reaches a user; an unscheduled retention job
// eventually reaches a disk. An unscheduled re-sealing job reaches an OPERATOR,
// through a number that does not move, and the two conclusions available from
// that number are "keep the old key forever" and "destroy it anyway".
func ResealCredentialKeysProbe(c *Client) ScheduleProbe {
	return ScheduleProbe{
		Client:    c,
		ID:        ResealCredentialKeysScheduleID,
		ProbeName: "credential_key_reseal",
		Consequence: "Credential secrets are never carried onto the current sealing key, so a " +
			"key rotation can never complete: the count of rows at the old version never " +
			"falls, the old pepper and TOTP sealing keys must be kept alive indefinitely, " +
			"and any account that has not signed in since the rotation is stranded. Nothing " +
			"else reports this.",
	}
}
