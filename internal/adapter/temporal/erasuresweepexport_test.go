package temporal

import (
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// RegisterErasureSweepForTest exposes the registration to the package's tests.
func RegisterErasureSweepForTest(
	env *testsuite.TestWorkflowEnvironment, a *ErasureSweepActivities,
) {
	registerErasureSweep(env, a)
}

// ErasureSweepScheduleOptionsForTest exposes what the schedule would be created
// with, so the action can be asserted without a server.
func ErasureSweepScheduleOptionsForTest(
	queue string, in SweepErasuresInput, every time.Duration,
) client.ScheduleOptions {
	return erasureSweepScheduleOptions(queue, in, every)
}
