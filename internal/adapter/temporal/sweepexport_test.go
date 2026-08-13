package temporal

import (
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// RegisterSweepForTest registers the sweep under the same names the real worker
// does, through the same function.
//
// It exists so a test cannot pass against a registration the production worker
// does not perform: both sides go through registerSweep, so a name that drifts
// breaks here rather than stranding a schedule against a workflow no worker
// answers to.
func RegisterSweepForTest(env *testsuite.TestWorkflowEnvironment, a *ReservationActivities) {
	registerSweep(env, a)
}

// SweepActivityNameForTest exposes the activity name, which is unexported for
// the same reason the workflow name is exported: only the schedule and the
// worker need the workflow name, while the activity name never leaves this
// package.
const SweepActivityNameForTest = releaseLapsedActivity

// SweepScheduleOptionsForTest exposes what the schedule would be created with,
// so the action can be asserted without a server.
func SweepScheduleOptionsForTest(
	queue string, in SweepReservationsInput, every time.Duration,
) client.ScheduleOptions {
	return sweepScheduleOptions(queue, in, every)
}
