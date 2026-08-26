package operator_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/operator"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// TestEveryOperatorEventIsRegistered is the operator plane's half of the
// completeness rule cmd/worker's TestTheCodecDecodesEveryEventInTheRepository
// applies to the tenant plane.
//
// # Why this test has to exist, in the words of the thing it replaces
//
// That test walks `internal/` for every `EventType()` in the repository and
// fails if the worker's codec cannot decode one. It SKIPS `internal/operator`,
// because the operator plane is a separate deployable with its own codec and
// cmd/worker has no business holding the operator schema.
//
// A skip in a completeness guard is normally how a gap gets in. This is what
// stops that: the same rule, over the same events, against the codec that
// actually reads them. If this file is deleted, the operator events are covered
// by nothing at all — and the symptom would be the one the tenant-side test
// names precisely, a projection that silently skips what it cannot decode.
//
// # Why it scans the source rather than a list
//
// For the reason cmd/worker's own comment gives: "a guard whose scope is set by
// the thing it guards cannot fail". Verifying RegisterEvents against a
// hand-maintained list of what RegisterEvents registers would pass forever.
func TestEveryOperatorEventIsRegistered(t *testing.T) {
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	operator.RegisterEvents(codec)
	registered := codec.Types()

	var missing []string
	for _, event := range operatorEventUniverse(t) {
		if !slices.Contains(registered, event) {
			missing = append(missing, event)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("operator.RegisterEvents does not register %d event type(s) this plane "+
			"defines: %v\n\n"+
			"cmd/operator builds its codec from RegisterEvents, and a projection cannot "+
			"apply what it cannot decode — so the audit log or the customer directory "+
			"would silently stop tracking these while every log line said the projection "+
			"was running.", len(missing), missing)
	}
}

// TestEveryRegisteredOperatorEventHasASchemaVersion is the second half, and it
// guards a failure that is worse than the first.
//
// ADR-029: Repository.decode calls UpcasterRegistry.Apply on every read, and
// Apply refuses a type with no registered version. An event registered in the
// codec but missing from the schema registry WRITES perfectly and makes its
// stream unreadable forever — so the damage is done before anything notices.
func TestEveryRegisteredOperatorEventHasASchemaVersion(t *testing.T) {
	upcasters := eventsourcing.NewUpcasterRegistry()
	codec := eventcodec.NewJSON(upcasters)
	operator.RegisterEvents(codec)
	operator.RegisterSchemas(upcasters)

	for _, event := range codec.Types() {
		if _, ok := upcasters.CurrentVersion(event); !ok {
			t.Errorf("%s is decodable but has no schema version; every append of it "+
				"produces a stream this build can never read back (ADR-029)", event)
		}
	}
}

// TestEventTypesMatchesWhatIsRegistered keeps the exported inventory honest.
//
// EventTypes() is what a composition-root test would assert a binary
// registers. If it drifts from RegisterEvents, that assertion becomes a
// comparison of two stale lists with each other.
func TestEventTypesMatchesWhatIsRegistered(t *testing.T) {
	codec := eventcodec.NewJSON(eventsourcing.NewUpcasterRegistry())
	operator.RegisterEvents(codec)

	declared := operator.EventTypes()
	registered := codec.Types()

	slices.Sort(declared)
	slices.Sort(registered)

	if !slices.Equal(declared, registered) {
		t.Errorf("EventTypes() and RegisterEvents disagree:\n  declared:   %v\n  registered: %v",
			declared, registered)
	}
}

// TestOperatorEventsNotifyNobody records a DECISION rather than an absence.
//
// The tenant plane requires every event to have a notification decision — it
// notifies somebody, or it is declared silent with a reason. The operator
// plane's events are exempt from that catalogue because cmd/worker does not
// read them, and an exemption with no reasoning behind it is how "nobody
// decided" comes to look like "somebody decided no".
//
// So the reasoning is here, and it is per-event:
//
//   - The four Viewed*/SignedIn/SignedOut events are AUDIT records. Their
//     audience is the audit log and, through operator.md §5, the tenant's own
//     operator-access history — which is a read model, not a message.
//   - Provisioned, RoleChanged, Disabled and CredentialEnrolled are changes to
//     OUR staff's access. operator.md §3 says every role addition is an audited
//     event; it does not ask for mail, and mail to an employee about their own
//     onboarding is a thing an HR system does.
//
// Slice 2 changes this for exactly one case: break-glass elevation "raises an
// alert to a second person AT THE TIME OF USE" (operator.md §5). When
// OperatorElevated arrives it must NOT be added to this list.
func TestOperatorEventsNotifyNobody(t *testing.T) {
	// OperatorElevated is the one event on this plane that DOES notify, and it
	// is listed here rather than omitted so the exception is visible.
	//
	// operator.md §5 requires an alert "at the time of use", and it is raised by
	// internal/operator/adapter/alert — a Prometheus counter plus a WARN line,
	// not mail, because this plane deliberately holds no operator addresses. It
	// is therefore not a notification in NOTIFICATIONS.md's sense and has no
	// entry in that catalogue; it is an operational page.
	notifies := map[string]string{
		"operator.OperatorElevated.v1": "raises a break-glass alert (operator.md §5) through " +
			"internal/operator/adapter/alert, as a metric and a WARN line rather than mail",
	}

	silent := map[string]string{
		"operator.OperatorProvisioned.v1":        "an access grant to our own staff; audited, not announced",
		"operator.OperatorRoleChanged.v1":        "an audited privilege change; the alert on escalation reads the log",
		"operator.OperatorDisabled.v1":           "offboarding; the person already knows, and the audit trail is the record",
		"operator.OperatorCredentialEnrolled.v1": "the operator performed it themselves, seconds earlier",
		"operator.OperatorSignedIn.v1":           "an audit record; per-sign-in mail would be ignored within a week",
		"operator.OperatorSignedOut.v1":          "an audit record",
		"operator.OperatorElevationExpired.v1":   "the closing half of a window whose opening already alerted",
		"operator.OperatorAccessManaged.v1":      "an audited access change to our own staff; the alert on escalation reads the log",
		"operator.OperatorChangedTenant.v1":      "the TENANT event it accompanies is what notifies them (organization.suspended); this carries the operator's justification, which is not for the tenant",
		"operator.OperatorViewedCustomer.v1":     "the tenant sees this in their operator-access history (operator.md §5)",
		"operator.OperatorViewedPersonalData.v1": "same, with the justification attached",
	}

	for _, event := range operatorEventUniverse(t) {
		if _, ok := notifies[event]; ok {
			continue
		}
		if _, ok := silent[event]; !ok {
			t.Errorf("%s has no notification decision.\n\n"+
				"Every operator event either notifies somebody or is declared silent WITH A "+
				"REASON. Add it to this map with the reason, or — if it does notify — build "+
				"the path and say so here. operator.md §5's break-glass alert is the first "+
				"event that will need the second answer.", event)
		}
	}
}

// operatorEventUniverse reads every `EventType()` under internal/operator out
// of the source.
func operatorEventUniverse(t *testing.T) []string {
	t.Helper()

	root := operatorRoot(t)
	fset := token.NewFileSet()

	var types []string
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == "testdata" {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		file, err := parser.ParseFile(fset, path, nil, parser.SkipObjectResolution)
		if err != nil {
			return err
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok || fn.Recv == nil || fn.Name.Name != "EventType" {
				continue
			}
			name, ok := returnedStringLiteral(fn)
			if !ok {
				t.Fatalf("%s: EventType is not a single string literal, so the guard "+
					"cannot read its name — and a name it cannot read is a name it cannot "+
					"check", fset.Position(fn.Pos()))
			}
			types = append(types, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s for event types: %v", root, err)
	}
	if len(types) == 0 {
		t.Fatal("found no operator event types at all, which means this guard is " +
			"inspecting the wrong directory and would pass whatever the plane declared")
	}
	return types
}

func returnedStringLiteral(fn *ast.FuncDecl) (string, bool) {
	if fn.Body == nil || len(fn.Body.List) != 1 {
		return "", false
	}
	ret, ok := fn.Body.List[0].(*ast.ReturnStmt)
	if !ok || len(ret.Results) != 1 {
		return "", false
	}
	lit, ok := ret.Results[0].(*ast.BasicLit)
	if !ok || lit.Kind != token.STRING {
		return "", false
	}
	v, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return v, true
}

func operatorRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("locating the package directory: %v", err)
	}
	return dir
}
