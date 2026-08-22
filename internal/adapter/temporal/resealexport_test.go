package temporal

import (
	"time"

	"go.temporal.io/sdk/client"
	"go.temporal.io/sdk/testsuite"
)

// RegisterResealForTest registers the re-sealing job under the same names the
// real worker does, through the same function.
//
// It exists so a test cannot pass against a registration the production worker
// does not perform: both sides go through registerReseal, so a name that drifts
// breaks here rather than stranding a schedule against a workflow no worker
// answers to.
func RegisterResealForTest(env *testsuite.TestWorkflowEnvironment, a *ResealActivities) {
	registerReseal(env, a)
}

// The activity names, exposed for assertions. They are unexported for the reason
// the sweep's is: only the schedule and the worker need the WORKFLOW name, while
// an activity name never leaves this package.
const (
	ResealBatchActivityNameForTest = resealBatchActivity
	ResealKindsActivityNameForTest = resealKindsActivity
)

// ResealScheduleOptionsForTest exposes what the schedule would be created with,
// so the action can be asserted without a server.
func ResealScheduleOptionsForTest(
	queue string, in ResealCredentialKeysInput, every time.Duration,
) client.ScheduleOptions {
	return resealScheduleOptions(queue, in, every)
}

// RegisterInvitationLifecycleForTest registers the invitation lifecycle under
// the same names the real worker does, through the same function.
//
// It exists so a test cannot pass against a registration the production worker
// does not perform: both sides go through registerInvitationLifecycle, so a name
// that drifts breaks here rather than stranding every outstanding invitation
// against a workflow no worker answers to.
func RegisterInvitationLifecycleForTest(
	env *testsuite.TestWorkflowEnvironment, a *InvitationLifecycleActivities,
) {
	registerInvitationLifecycle(env, a)
}

// The activity names, exposed for assertions.
const (
	InvitationStateActivityNameForTest  = invitationStateActivity
	RemindInvitationActivityNameForTest = remindInvitationActivity
	ExpireInvitationActivityNameForTest = expireInvitationActivity
)

// InvitationSweepScheduleOptionsForTest exposes what the sweep's schedule would
// be created with, so the action can be asserted without a server.
func InvitationSweepScheduleOptionsForTest(
	queue string, in SweepInvitationsInput, every time.Duration,
) client.ScheduleOptions {
	return invitationSweepScheduleOptions(queue, in, every)
}
