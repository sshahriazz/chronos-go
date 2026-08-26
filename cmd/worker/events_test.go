package main

import (
	"context"
	"errors"
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
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/adapter/mailrender"
	identityevents "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/mail"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"github.com/chronos/chronos-go/internal/platform/workflow"
)

// THE test. Every event the REPOSITORY defines must have a notification
// decision recorded against it — either it notifies someone, or it is declared
// silent with a reason.
//
// It verifies against eventUniverse, not against codec.Types(), and the
// difference is the whole reason this file was rewritten. Verifying against the
// codec made the guard's scope equal to whatever registerEvents happened to
// list: it read as "every event has a notification decision" and meant "every
// event I remembered to register has one". Under that wording identity's
// twenty-nine event types — including every Sec-class alert in NOTIFICATIONS §5
// — were absent from both lists at once, and the test passed.
//
// A guard whose scope is set by the thing it guards cannot fail. This one takes
// its scope from the source tree instead, so an event added anywhere under
// internal/ fails the build until somebody decides what it tells people.
func TestEveryEventHasANotificationDecision(t *testing.T) {
	cat := notifications()

	if err := cat.Verify(eventUniverse(t)); err != nil {
		t.Fatalf(`%v

Fix by adding ONE of these to cmd/worker/events.go:

    cat.On[modulepkg.TheEvent](notify.Spec{
        Template: "module.the_event",
        Class:    notify.Security,        // or Transactional / Activity / Product / Operator
        Audience: notify.AudienceSubject, // who receives it
    }, func(e *modulepkg.TheEvent) map[string]any { ... })

    cat.Silent[modulepkg.TheEvent]("why nobody needs to hear about this")`, err)
	}
}

// The catalogue may only decide about events this binary can actually DECODE.
//
// A decision on an event the codec has never heard of is not coverage. The
// reactor's subscription filter is built from the catalogue, so the event is
// delivered, `codec.Unmarshal` fails, and React returns ErrPoison — the
// notification parks instead of being sent. Declaring it silent is worse still:
// it looks settled while the reactor could not have acted on it either way.
//
// This is the check that makes registerEvents non-optional. Removing
// identity.RegisterEvents fails HERE, loudly, naming every event that would
// have gone undelivered.
func TestTheCodecDecodesEveryEventInTheRepository(t *testing.T) {
	registered := newCodec().Types()

	var missing []string
	for _, event := range eventUniverse(t) {
		if !slices.Contains(registered, event) {
			missing = append(missing, event)
		}
	}
	if len(missing) > 0 {
		t.Fatalf("the codec cannot decode %d event type(s) this repository defines: %v\n\n"+
			"The notification reactor skips what it cannot decode — no error, no metric, "+
			"no log line, just a security alert nobody receives. Register them in "+
			"registerEvents (cmd/worker/events.go), through the owning module's "+
			"RegisterEvents where it has one.", len(missing), missing)
	}
}

// A renamed or retired event leaves its notification behind, pointing at
// something that can no longer arrive. The entry then looks like coverage while
// covering nothing.
func TestNoOrphanedCatalogueEntries(t *testing.T) {
	cat := notifications()

	if orphans := cat.Orphans(eventUniverse(t)); len(orphans) > 0 {
		t.Fatalf("the catalogue decides about %v, which this repository does not define. "+
			"Either the event was renamed and the entry was not, or it was retired "+
			"and the entry outlived it", orphans)
	}
}

// ---------------------------------------------------------------------------
// The event universe
// ---------------------------------------------------------------------------

// eventUniverse is every stored event type this repository defines, read from
// the SOURCE.
//
// # Why the source and not a registry
//
// Three enumerations were possible and two of them are circular:
//
//   - codec.Types() is what registerEvents put there. Using it to check
//     registerEvents is the defect this file exists to fix.
//   - A hand-maintained list is a third place to forget the same event, and it
//     is the one place where forgetting produces no symptom at all.
//   - Go has no package-level reflection, so there is no runtime way to ask
//     "which types implement eventsourcing.Event".
//
// So the list is derived by parsing every non-test file under internal/ for
// `EventType() string` method declarations. That set cannot be shortened by
// forgetting anything — an event type exists precisely when somebody writes
// that method, and writing it is what puts it in scope here.
//
// It is also why the module registration in registerEvents is a real
// dependency rather than a gesture: cmd/worker must import identity to satisfy
// the check this produces, and the import is the point.
//
// The scan is deliberately strict. An `EventType` method whose body is not a
// single string literal FAILS rather than being skipped, because a skipped
// event is exactly the invisible gap this whole mechanism exists to prevent.
func eventUniverse(t *testing.T) []string {
	t.Helper()

	root := filepath.Join(repoRoot(t), "internal")
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
			// The OPERATOR plane is a separate deployable with its own codec
			// (ADR-024), and this universe is the TENANT plane's.
			//
			// This skip is the kind of exclusion that usually hides a gap, so
			// it is worth being precise about why it does not. cmd/worker
			// cannot decide about operator events: it neither registers them
			// nor subscribes to their streams, and making it do so would link
			// the operator schema into a binary that has no business holding
			// it. And the events themselves notify nobody by design — they are
			// audit records, and NOTIFICATIONS.md governs what we send to
			// TENANTS.
			//
			// What replaces this coverage is not nothing:
			// TestEveryOperatorEventIsRegistered in internal/operator applies
			// the same completeness rule to the same events, against the codec
			// that actually reads them. Deleting that test does not make this
			// one start covering them — it makes them uncovered, which is why
			// the test names this comment and this comment names the test.
			if d.Name() == "operator" && filepath.Dir(path) == root {
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
				t.Fatalf("%s: EventType is not a single string literal.\n"+
					"The notification completeness guard reads event type names out of "+
					"the source, and a name it cannot read is a name it cannot check. "+
					"Return the literal directly, or this event silently leaves the "+
					"universe every other guard is measured against.",
					fset.Position(fn.Pos()))
			}
			types = append(types, name)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("scanning %s for event types: %v", root, err)
	}

	slices.Sort(types)
	types = slices.Compact(types)

	// A guard on the guard. If this scan ever returns nothing — a moved
	// directory, a changed layout, a build tag — every test above would pass
	// vacuously, which is the precise failure mode that made the previous
	// version of this file worthless. Two known-present names are asserted so
	// an empty or truncated scan is a failure rather than a green run.
	for _, want := range []string{"identity.TotpDisabled.v1", "notification.Created.v1"} {
		if !slices.Contains(types, want) {
			t.Fatalf("the event scan found %d type(s) and none of them is %q; "+
				"it is not reading the repository, so every completeness check "+
				"above it is passing over an empty set", len(types), want)
		}
	}
	return types
}

// returnedStringLiteral reduces `func (*T) EventType() string { return "x" }` to
// `x`. Anything else reports false and is treated as a hard failure by the
// caller.
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
	value, err := strconv.Unquote(lit.Value)
	if err != nil {
		return "", false
	}
	return value, true
}

// repoRoot walks up from the test's working directory to the module root.
// Tests run in their package directory, so this is what turns "internal/" into
// an absolute path that does not depend on where `go test` was invoked.
func repoRoot(t *testing.T) string {
	t.Helper()

	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("no go.mod above the test's working directory; the event scan " +
				"cannot locate the repository")
		}
		dir = parent
	}
}

// ---------------------------------------------------------------------------
// The catalogue's own consistency
// ---------------------------------------------------------------------------

// Every template the catalogue names must exist. A missing one fails at
// DELIVERY time — the moment somebody needs the message — and by then the event
// is long past.
func TestEveryCatalogueTemplateExists(t *testing.T) {
	cat := notifications()
	templates := cat.Templates()
	if len(templates) == 0 {
		t.Fatal("the catalogue names no templates at all. With identity registered " +
			"that cannot be right, and an empty set would make this test pass " +
			"without checking anything")
	}

	renderer := mailrender.New(mailrender.Embedded{}, mailrender.Config{
		From:    mail.Address{Email: "no-reply@chronos.local"},
		BaseURL: "http://localhost:3000",
	})
	if err := renderer.Load(context.Background()); err != nil {
		t.Fatalf("loading templates: %v", err)
	}

	available := map[string]struct{}{}
	for _, name := range renderer.Templates() {
		available[name] = struct{}{}
	}
	for _, want := range templates {
		if _, ok := available[want]; !ok {
			t.Errorf("the catalogue names template %q, which does not exist in "+
				"internal/adapter/mailrender/templates", want)
		}
	}
}

// Security and Transactional mail cannot be switched off, and that is a
// security property rather than a product one: if switching off email could
// stop a security alert, an attacker who gains access to an account would
// simply switch it off and silence the message that reveals them
// (NOTIFICATIONS §3).
//
// So the class of an account-safety alert is asserted, not merely declared.
// Downgrading one of these to Activity is a one-word edit that compiles, passes
// every other test in this file, and makes the alert suppressible.
func TestAccountSafetyAlertsCannotBeSwitchedOff(t *testing.T) {
	cat := notifications()

	// NOTIFICATIONS §5, the rows marked Sec ★, restricted to the events
	// identity actually emits today.
	mustBeUnsuppressible := []string{
		"identity.PasswordChanged.v1",
		"identity.CredentialCompromiseDetected.v1",
		"identity.TotpEnabled.v1",
		"identity.TotpDisabled.v1",
		"identity.RecoveryCodesGenerated.v1",
		"identity.RecoveryCodeConsumed.v1",
		"identity.RecoveryCodesExhausted.v1",
		"identity.AuthenticatorDisabled.v1",
		"identity.DeviceRegistered.v1",
		"identity.UserDeactivated.v1",
		"identity.UserReactivated.v1",
		"identity.UserSuspended.v1",
	}

	for _, event := range mustBeUnsuppressible {
		spec, ok := cat.For(event)
		if !ok {
			reason, silent := cat.IsSilent(event)
			t.Errorf("%s notifies nobody (%q), but NOTIFICATIONS §5 marks it Sec ★ — "+
				"the alert that tells a person their account was taken over",
				event, silenceNote(reason, silent))
			continue
		}
		if spec.Class != notify.Security {
			t.Errorf("%s is class %s; NOTIFICATIONS §3 requires Security, which ignores "+
				"preferences and carries no unsubscribe. As %s an attacker who reached "+
				"the account could switch this off and silence the alert that reveals them",
				event, spec.Class, spec.Class)
		}
		if spec.Audience != notify.AudienceSubject {
			t.Errorf("%s notifies the %s audience; a security alert about an account "+
				"goes to the person whose account it is", event, spec.Audience)
		}
	}

	// The list above answers "did somebody delete this alert?". It cannot answer
	// "did somebody downgrade an alert that is not on the list?", because a
	// hand-maintained list only covers what was on it the day it was written.
	//
	// That gap was real and was found by mutation: reclassifying
	// UserDeletionRequested from Security to Transactional left the entire
	// repository green, because that event is marked Sec ★ in NOTIFICATIONS §4
	// and was never added here. Transactional respects the recipient's
	// preferences, so the downgrade would have handed an attacker who reached a
	// session the ability to schedule an erasure AND suppress the only message
	// that reports it.
	//
	// So the sweep below inverts the question. Every identity entry in the
	// catalogue must be Security to the subject unless it is named as an
	// exception — which makes the DEFAULT for a new identity alert the
	// unsuppressible one, and makes a downgrade an edit somebody has to justify
	// in this table rather than a one-word change in cmd/worker/events.go.
	transactionalByDesign := map[string]string{
		// NOTIFICATIONS §5 marks the welcome Txn ★, not Sec ★: it is the message
		// the person's own verification asked for, it reports no change to the
		// account's security posture, and there is nothing in it an attacker
		// would want silenced.
		"identity.EmailVerified.v1": "the welcome message; NOTIFICATIONS §5 marks it Txn ★",
	}

	for _, event := range cat.Events() {
		if !strings.HasPrefix(event, "identity.") {
			continue
		}
		spec, ok := cat.For(event)
		if !ok {
			continue
		}
		if _, exempt := transactionalByDesign[event]; exempt {
			if spec.Class == notify.Security {
				t.Errorf("%s is named in transactionalByDesign but is class Security; "+
					"remove it from that table rather than leaving a stale exemption "+
					"that would hide a future downgrade", event)
			}
			continue
		}
		if spec.Class != notify.Security {
			t.Errorf("%s notifies as class %s. Every identity notification is a security "+
				"alert unless transactionalByDesign says why not, because %s respects the "+
				"recipient's preferences — so this one can be switched off by whoever "+
				"reached the account", event, spec.Class, spec.Class)
		}
		if spec.Audience != notify.AudienceSubject {
			t.Errorf("%s notifies the %s audience; an identity alert concerns one "+
				"account and goes to the person whose account it is", event, spec.Audience)
		}
	}
}

func silenceNote(reason string, silent bool) string {
	if !silent {
		return "no decision at all"
	}
	return reason
}

// The guard above is only worth having if it actually fires. This proves the
// mechanism on a fixture, so a trivially-empty catalogue cannot make the real
// test pass vacuously.
func TestVerificationActuallyFires(t *testing.T) {
	codec := eventcodec.NewJSON(nil)
	eventcodec.Register[undecidedEvent](codec)

	err := notifications().Verify(codec.Types())
	if err == nil {
		t.Fatal("an event with no decision passed verification; the guard does not work")
	}
	if !strings.Contains(err.Error(), "test.Undecided.v1") {
		t.Errorf("the failure must name the offending type, got: %v", err)
	}
}

type undecidedEvent struct{}

func (*undecidedEvent) EventType() string { return "test.Undecided.v1" }

// Operator alerts have nowhere to go unless an address is configured. The
// reactor parks them rather than dropping them, but an empty configuration
// makes that certain — better to know here.
func TestOperatorRecipients(t *testing.T) {
	if got := operatorRecipients(""); len(got) != 0 {
		t.Errorf("an unset operator address must yield no recipients, got %v", got)
	}
	got := operatorRecipients("ops@chronos.local")
	if len(got) != 1 || got[0].Address != "ops@chronos.local" {
		t.Fatalf("got %v", got)
	}
	// Operator mail must never be addressed to a tenant subject.
	if got[0].SubjectID != "" {
		t.Error("an operator recipient must carry no tenant subject id")
	}
}

// "An administrator did this, not you" is the most important sentence a
// security mail can carry, and it is decided by comparing two pseudonyms. The
// unknown-actor case is the one worth pinning: identity sets ActorID to the
// subject for self-service, so an EMPTY actor means metadata was incomplete —
// and reporting that as "somebody else" would tell people an administrator
// touched their account whenever it was.
func TestActedOnBehalf(t *testing.T) {
	tests := []struct {
		name             string
		actor, subject   string
		wantOnBehalfFlag bool
	}{
		{name: "self-service", actor: "sub_a", subject: "sub_a", wantOnBehalfFlag: false},
		{name: "an operator acted", actor: "sub_ops", subject: "sub_a", wantOnBehalfFlag: true},
		{name: "no actor recorded", actor: "", subject: "sub_a", wantOnBehalfFlag: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := actedOnBehalf(tt.actor, tt.subject); got != tt.wantOnBehalfFlag {
				t.Errorf("actedOnBehalf(%q, %q) = %v, want %v",
					tt.actor, tt.subject, got, tt.wantOnBehalfFlag)
			}
		})
	}
}

// The subscription filter must never be empty-meaning-everything: a
// notification reactor with nothing registered would otherwise wake on every
// event in the system.
func TestEmptyCatalogueDoesNotSubscribeToEverything(t *testing.T) {
	r := notify.NewEventReactor("notifications", notify.NewCatalogue(), newCodec(),
		notify.SubjectAudiences{}, nil)

	f := r.Filter()
	if len(f.EventTypePrefixes) == 0 && len(f.StreamPrefixes) == 0 {
		t.Fatal("an empty catalogue produced a filter with no prefixes, which means " +
			"'no filter' — the reactor would be handed every event in the system")
	}
}

// The real filter must name the identity events, or the reactor never sees
// them. The catalogue can be complete and the subscription still miss.
func TestTheSubscriptionFilterCoversTheSecurityAlerts(t *testing.T) {
	f := notify.NewEventReactor(notificationReactorName, notifications(), newCodec(),
		notify.SubjectAudiences{}, nil).Filter()

	for _, want := range []string{
		"identity.TotpDisabled.v1",
		"identity.PasswordChanged.v1",
		"identity.RecoveryCodeConsumed.v1",
	} {
		if !slices.Contains(f.EventTypePrefixes, want) {
			t.Errorf("the reactor's subscription does not match %s, so the event is "+
				"never delivered to it however complete the catalogue is", want)
		}
	}
}

// Delivery is keyed on the event, so a redelivery asks to start the run that
// already exists — and Temporal refuses it, which the reactor treats as success
// because the work was already done.
//
// The keying belongs to the reactor rather than to any entry, so this asserts it
// through a real catalogue entry: if a future entry could opt out of it, one
// redelivered event would become two "your second factor was disabled" emails,
// which reads to the person as two separate incidents.
func TestARedeliveredEventAsksToStartTheSameWorkflow(t *testing.T) {
	spy := &recordingStarter{}
	r := notify.NewEventReactor(notificationReactorName, notifications(), newCodec(),
		notify.SubjectAudiences{}, nil, notify.WithWorkflows(spy))

	env := decidedEnvelope(t)
	for i := range 2 {
		if err := r.React(context.Background(), env); err != nil {
			t.Fatalf("delivery %d: %v", i+1, err)
		}
	}

	if len(spy.ids) != 2 {
		t.Fatalf("two deliveries produced %d workflow starts, want 2", len(spy.ids))
	}
	if spy.ids[0] != spy.ids[1] {
		t.Fatalf("the redelivery asked for workflow %q where the first asked for %q; "+
			"two different ids means Temporal starts two runs and the person is "+
			"told twice", spy.ids[1], spy.ids[0])
	}
	if want := env.ID.String() + ":0"; spy.ids[0] != want {
		t.Errorf("workflow id %q is not derived from the event id (%q); a random id "+
			"cannot deduplicate anything", spy.ids[0], want)
	}
	if spy.names[0] != notify.SendNotificationWorkflow {
		t.Errorf("started %q, want %q", spy.names[0], notify.SendNotificationWorkflow)
	}
	// Workflow input is durable, replicated history. A resolved address there is
	// personal data crypto-shredding cannot reach (ADR-002).
	if spy.inputs[0].SubjectID == "" {
		t.Error("the workflow carries no subject pseudonym, so the activity has nobody to resolve")
	}
}

type recordingStarter struct {
	ids    []string
	names  []string
	inputs []notify.SendNotificationInput
}

func (s *recordingStarter) Start(_ context.Context, w workflow.Start) (workflow.Run, error) {
	s.ids = append(s.ids, w.ID)
	s.names = append(s.names, w.Name)
	in, _ := w.Input.(notify.SendNotificationInput)
	s.inputs = append(s.inputs, in)
	return workflow.Run{ID: w.ID, RunID: "run_1"}, nil
}

// decidedEnvelope is one real, catalogued identity event, encoded by the real
// codec — so this test fails if TotpDisabled ever stops being decodable or
// stops notifying.
func decidedEnvelope(t *testing.T) eventsourcing.Envelope {
	t.Helper()

	event := &identityevents.TotpDisabled{
		SubjectID: "sub_probe", CredentialID: "cred_probe", DisabledAt: time.Now().UTC(),
	}
	payload, err := newCodec().Marshal(event)
	if err != nil {
		t.Fatalf("the worker's codec cannot encode %s: %v", event.EventType(), err)
	}
	return eventsourcing.Envelope{
		ID:      eventsourcing.DeriveEventID("cmd-probe", 0),
		Type:    event.EventType(),
		Payload: payload,
		Meta: eventsourcing.Metadata{
			OccurredAt: time.Now().UTC(),
			SubjectIDs: []string{"sub_probe"},
			ActorID:    "sub_probe",
		},
	}
}

// An audience a catalogue entry uses but nothing can answer parks every
// notification that needs it. Better caught here than by a user asking why they
// were never told.
func TestEveryAudienceInUseHasAResolver(t *testing.T) {
	cat := notifications()
	// A STAND-IN for the organization-member resolver, because the real one
	// reads a table and this test must not need one. What it proves is the
	// catalogue/registry contract: every audience some entry names is
	// registered. That the BINARY wires the real one is a different property,
	// asserted at the composition root by TestTheOrgMemberAudienceIsWired.
	reg := audiences("ops@chronos.local", standInAudience{})

	for _, event := range cat.Events() {
		spec, _ := cat.For(event)
		_, err := reg.Resolve(context.Background(), spec.Audience, eventsourcing.Envelope{
			Meta: eventsourcing.Metadata{OrgID: "org_probe", SubjectIDs: []string{"sub_probe"}, ActorID: "sub_probe"},
		})
		if errors.Is(err, notify.ErrAudienceUnsupported) {
			t.Errorf("%s notifies the %s audience, but nothing can resolve it — "+
				"every one of those notifications will park. Either wire a resolver "+
				"in audiences(), or change the audience", event, spec.Audience)
		}
	}
}

// standInAudience answers any audience with one recipient.
type standInAudience struct{}

func (standInAudience) Resolve(
	_ context.Context, _ notify.Audience, env eventsourcing.Envelope,
) ([]notify.Recipient, error) {
	return []notify.Recipient{{SubjectID: "sub_probe", OrgID: env.Meta.OrgID}}, nil
}

// AN UNWIRED MEMBER AUDIENCE PARKS, AND DOES NOT QUIETLY SUCCEED.
//
// The nil path is the one worth asserting, because the alternative implementation
// — a stub resolving to nobody — would report success having told nobody, which
// is indistinguishable from an organization that genuinely has no members. That
// is the exact silence OrganizationSuspended sat in while it was Silent.
func TestAnUnwiredMemberAudienceParks(t *testing.T) {
	reg := audiences("ops@chronos.local", nil)

	_, err := reg.Resolve(context.Background(), notify.AudienceOrgMembers,
		eventsourcing.Envelope{Meta: eventsourcing.Metadata{OrgID: "org_probe"}})
	if !errors.Is(err, notify.ErrAudienceUnsupported) {
		t.Fatalf("an unwired member audience returned %v; a suspension would report "+
			"success having told nobody", err)
	}
}
