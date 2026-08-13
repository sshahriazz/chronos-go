package temporal

import (
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// RegisterRetentionForTest registers the retention job under the same names the
// real worker does, through the same function.
//
// It exists so a test cannot pass against a registration the production worker
// does not perform: both sides go through registerRetention, so a name that
// drifts breaks here rather than stranding a schedule against a workflow no
// worker answers to.
func RegisterRetentionForTest(env *testsuite.TestWorkflowEnvironment, a *RetentionActivities) {
	registerRetention(env, a)
}

// RetentionActivityNameForTest exposes the activity name, which is unexported for
// the same reason the workflow name is exported: only the schedule and the worker
// need the workflow name, while the activity name never leaves this package.
const RetentionActivityNameForTest = purgeRetentionActivity

// RetentionScheduleOptionsForTest exposes what the schedule would be created
// with, so the action can be asserted without a server.
func RetentionScheduleOptionsForTest(
	queue string, in PurgeRetentionInput, every time.Duration,
) client.ScheduleOptions {
	return retentionScheduleOptions(queue, in, every)
}
