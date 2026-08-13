package temporal

import (
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	commonpb "go.temporal.io/api/common/v1"
	"go.temporal.io/sdk/activity"
	"go.temporal.io/sdk/testsuite"
	"go.temporal.io/sdk/workflow"
)

// RegisterForTest registers the same names the real worker does.
//
// It exists so a test cannot pass against a registration the production worker
// does not perform: both go through the same constants, and a name that drifts
// breaks here before it strands an execution.
func RegisterForTest(env *testsuite.TestWorkflowEnvironment, a *NotificationActivities) {
	env.RegisterWorkflowWithOptions(SendNotification,
		workflow.RegisterOptions{Name: SendNotificationWorkflow})
	env.RegisterActivityWithOptions(a.Deliver,
		activity.RegisterOptions{Name: deliverActivity})
}

// PropagateForTest seeds a chain the way a real start does — as HEADERS, read
// by the production propagator — rather than by planting a value in the
// activity's context. Planting it would test nothing: the whole question is
// whether the chain survives the workflow boundary.
func PropagateForTest(suite *testsuite.WorkflowTestSuite, t eventsourcing.Trace) {
	suite.SetContextPropagators(propagators())

	header := &commonpb.Header{Fields: map[string]*commonpb.Payload{}}
	if err := write(t, testHeaderWriter{header}); err != nil {
		panic(err)
	}
	suite.SetHeader(header)
}

type testHeaderWriter struct{ h *commonpb.Header }

func (w testHeaderWriter) Set(key string, value *commonpb.Payload) {
	w.h.Fields[key] = value
}
