package temporal

import "go.temporal.io/sdk/testsuite"

// RegisterDataExportForTest binds the export workflow and its activities to a
// test environment, through the SAME function the worker uses.
//
// Through that function and not a copy of it: a test that registered by hand
// would pass while the real registration bound a different name, and the symptom
// in production is a run that never starts with nothing to say why.
func RegisterDataExportForTest(env *testsuite.TestWorkflowEnvironment, a *ExportActivities) {
	registerDataExport(env, a)
}

// The activity names, exposed for assertions.
const (
	BeginExportActivityNameForTest         = beginExportActivity
	ListExportObjectsActivityNameForTest   = listExportObjectsActivity
	WriteExportManifestActivityNameForTest = writeExportManifestActivity
	FailExportActivityNameForTest          = failExportActivity
)

// MaxExportPagesForTest is the workflow's own page budget.
const MaxExportPagesForTest = maxExportPages
