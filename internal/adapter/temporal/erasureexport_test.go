package temporal

import "go.temporal.io/sdk/testsuite"

// RegisterErasureForTest exposes the registration to the package's tests.
func RegisterErasureForTest(
	env *testsuite.TestWorkflowEnvironment, state *ErasureState, execute *ExecuteErasure,
) {
	registerErasure(env, state, execute)
}

// The activity names, exposed for assertions.
const (
	ErasureStateActivityNameForTest   = erasureStateActivity
	ExecuteErasureActivityNameForTest = executeErasureActivity
)
