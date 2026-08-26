package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
)

// These test compliance.md §4 step 2 — "check LegalHold → held ⇒ defer +
// explain" — which could not be written until something could place a hold.
//
// The worklist named it BLOCKED rather than unbuilt for exactly that reason: a
// check against holds nothing could create is a check that can only ever pass,
// which is the vacuous-test shape this repository has twice shipped. Now that
// the operator plane places them, the check is real and so are these.

// --------------------------------------------------------------------------
// Recorders
// --------------------------------------------------------------------------

type recordingVault struct{ erased []string }

func (v *recordingVault) Erase(_ context.Context, subjectID string) error {
	v.erased = append(v.erased, subjectID)
	return nil
}

type recordingAccounts struct{ erased []string }

func (a *recordingAccounts) Erase(_ context.Context, subjectID string) error {
	a.erased = append(a.erased, subjectID)
	return nil
}

type recordingObjects struct{ erased []string }

func (o *recordingObjects) ErasePrefixes(_ context.Context, subjectID string) (int, error) {
	o.erased = append(o.erased, subjectID)
	return 0, nil
}

type recordingConfirm struct {
	sent []string

	// retained is what the LAST confirmation was asked to state. Kept so a test
	// can assert the person was told what survives — the field that used to be a
	// package-level []string nothing checked.
	retained []domain.RetentionPolicy
}

func (c *recordingConfirm) SendErasureComplete(
	_ context.Context, subjectID string, retained []domain.RetentionPolicy,
) error {
	c.sent = append(c.sent, subjectID)
	c.retained = retained
	return nil
}

// fixedExemptions is a resolver whose answer a test chooses.
//
// `nil` is a legitimate answer here and is the case that matters: it is what a
// broken resolver produces, and the erasure must refuse rather than confirm.
type fixedExemptions struct{ policies []domain.RetentionPolicy }

func (f fixedExemptions) For(context.Context, string) []domain.RetentionPolicy {
	return f.policies
}

// realExemptions is the schedule the running system uses. Tests that are not
// about retention take this, so they exercise the real set rather than a
// convenient stub.
func realExemptions() fixedExemptions {
	return fixedExemptions{policies: domain.RetentionExemptions()}
}

// holds answers the gate. `err` takes precedence, so a test can assert what
// happens when the hold store cannot be reached.
type holds struct {
	held   bool
	matter string
	err    error
}

func (h holds) Held(context.Context, string) (string, bool, error) {
	return h.matter, h.held, h.err
}

// deferrals records what the Article 12(4) path did.
type deferrals struct {
	deferred []string
	resumed  []string
	err      error
}

func (d *deferrals) Defer(_ context.Context, subjectID string, _ time.Time) (bool, error) {
	if d.err != nil {
		return false, d.err
	}
	d.deferred = append(d.deferred, subjectID)
	// The aggregate is what makes the second call free; this mimics it, so a
	// test can assert the CALLER stops mailing rather than that the store
	// happens to deduplicate.
	return len(d.deferred) <= 1, nil
}

func (d *deferrals) Resume(_ context.Context, subjectID string, _ time.Time) error {
	if d.err != nil {
		return d.err
	}
	d.resumed = append(d.resumed, subjectID)
	return nil
}

type fixture struct {
	vault     *recordingVault
	accounts  *recordingAccounts
	objects   *recordingObjects
	confirm   *recordingConfirm
	deferrals *deferrals
	erasure   *app.Erasure
}

func newFixture(t *testing.T, h app.LegalHolds) *fixture {
	t.Helper()
	f := &fixture{
		vault:     &recordingVault{},
		accounts:  &recordingAccounts{},
		objects:   &recordingObjects{},
		confirm:   &recordingConfirm{},
		deferrals: &deferrals{},
	}
	e, err := app.NewErasure(app.ErasureDeps{
		Vault: f.vault, Accounts: f.accounts, Objects: f.objects,
		Confirm: f.confirm, Holds: h, Deferrals: f.deferrals,
		Exemptions: realExemptions(),
		Now:        func() time.Time { return time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("building the eraser: %v", err)
	}
	f.erasure = e
	return f
}

// --------------------------------------------------------------------------
// The gate
// --------------------------------------------------------------------------

// TestAHeldSubjectIsNotErased is the assertion the whole feature exists for.
//
// The key destruction is irreversible. If the gate is wrong in this direction
// there is no recovery — not for the court order, not for the data, not for
// whoever has to explain it.
func TestAHeldSubjectIsNotErased(t *testing.T) {
	f := newFixture(t, holds{held: true, matter: "litigation 2026-4711"})

	err := f.erasure.Execute(t.Context(), "subj_1")
	if err == nil {
		t.Fatal("a held subject was erased")
	}
	if !errors.Is(err, app.ErrHeld) {
		t.Fatalf("want ErrHeld so the workflow can DEFER rather than retry or fail; got %v", err)
	}
	// The matter is named, because §4 says "defer + explain" and an explanation
	// with no reference in it explains nothing.
	if !strings.Contains(err.Error(), "litigation 2026-4711") {
		t.Errorf("the deferral does not name the matter: %v", err)
	}

	if len(f.vault.erased) != 0 {
		t.Error("the SUBJECT KEY was destroyed for a held subject; nothing recovers from this")
	}
	if len(f.accounts.erased) != 0 {
		t.Error("the account was erased for a held subject")
	}
	if len(f.objects.erased) != 0 {
		t.Error("the objects were erased for a held subject")
	}
}

// TestAHeldSubjectIsNotToldTheirDataWasErased is why the gate is ahead of the
// confirmation, not just ahead of the destroy.
//
// compliance.md §4 numbers the hold check second and puts the confirmation
// last; this implementation moves the confirmation to the FRONT, because it is
// rendered from an address the vault destruction makes unreadable.
//
// That move is what creates this hazard. A hold check placed between the
// confirmation and the destroy would mail "your data has been erased" to
// somebody whose erasure is deferred — a false statement about a legal
// obligation, and the one message here that cannot be retracted.
func TestAHeldSubjectIsNotToldTheirDataWasErased(t *testing.T) {
	f := newFixture(t, holds{held: true, matter: "m-1"})

	if err := f.erasure.Execute(t.Context(), "subj_1"); err == nil {
		t.Fatal("a held subject was erased")
	}
	if len(f.confirm.sent) != 0 {
		t.Fatal("a held subject was told their data had been erased. It has not been, the " +
			"statement is false, and it cannot be retracted")
	}
}

// TestAHoldStoreThatCannotAnswerStopsTheErasure.
//
// A failure to ANSWER is not "not held". Proceeding on the assumption that no
// hold exists is precisely the assumption the check was added to stop anybody
// making, and an unreachable event store is not a licence to destroy a key.
func TestAHoldStoreThatCannotAnswerStopsTheErasure(t *testing.T) {
	f := newFixture(t, holds{err: errors.New("the event store is unreachable")})

	err := f.erasure.Execute(t.Context(), "subj_1")
	if err == nil {
		t.Fatal("an erasure proceeded while the hold check was unanswerable")
	}
	if errors.Is(err, app.ErrHeld) {
		t.Error("an unanswerable check was reported as a HOLD; the workflow would then " +
			"wait for a lift that is never coming, rather than retrying")
	}
	if len(f.vault.erased) != 0 {
		t.Error("the subject key was destroyed while the hold check was unanswerable")
	}
	if len(f.confirm.sent) != 0 {
		t.Error("a confirmation was sent while the hold check was unanswerable")
	}
}

// TestAnUnheldSubjectIsErased is the counterpart, and it is what stops the gate
// being satisfied by refusing everybody.
//
// A test suite that only asserted refusals would pass on an implementation that
// never erased anyone — which is the failure this repository names as "ask what
// the test would do if the feature were deleted", pointed the other way.
func TestAnUnheldSubjectIsErased(t *testing.T) {
	f := newFixture(t, holds{})

	if err := f.erasure.Execute(t.Context(), "subj_1"); err != nil {
		t.Fatalf("an unheld subject was not erased: %v", err)
	}

	for _, step := range []struct {
		name string
		got  []string
	}{
		{"confirmation", f.confirm.sent},
		{"vault", f.vault.erased},
		{"objects", f.objects.erased},
		{"account", f.accounts.erased},
	} {
		if len(step.got) != 1 || step.got[0] != "subj_1" {
			t.Errorf("the %s step did not run for an unheld subject: %v", step.name, step.got)
		}
	}
}

// TestTheEraserRefusesToBuildWithoutAHoldChecker is the composition-root
// assertion.
//
// The gate is the kind of dependency that gets left nil in a second wiring — a
// test harness, a migration tool, a one-off script — and the failure is silent:
// every other step succeeds, so the erasure looks correct while destroying a
// key a court order says must be preserved.
func TestTheEraserRefusesToBuildWithoutAHoldChecker(t *testing.T) {
	_, err := app.NewErasure(app.ErasureDeps{
		Vault: &recordingVault{}, Accounts: &recordingAccounts{},
		Objects: &recordingObjects{}, Confirm: &recordingConfirm{},
		Holds: nil, Deferrals: &deferrals{}, Exemptions: realExemptions(),
		Now: time.Now,
	})
	if err == nil {
		t.Fatal("an eraser was built with no legal-hold checker, so it would destroy keys " +
			"that court orders say must be preserved — silently, because every other " +
			"step succeeds")
	}
	if !strings.Contains(err.Error(), "legal-hold") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// --------------------------------------------------------------------------
// Article 12(4)
// --------------------------------------------------------------------------

// TestADeferredErasureAnswersTheRequester is the obligation this slice created.
//
// "If the controller does not take action on the request of the data subject,
// the controller shall inform the data subject without delay and at the latest
// within one month of the reasons for not taking action."
//
// Legal holds made "not taking action" reachable for the first time. Before
// them the erasure either ran or failed, and a failure was a retry — so there
// was no state in which we were deliberately not acting, and nothing to answer
// for. This is that answer being triggered.
func TestADeferredErasureAnswersTheRequester(t *testing.T) {
	f := newFixture(t, holds{held: true, matter: "litigation 2026-4711"})

	if err := f.erasure.Execute(t.Context(), "subj_1"); !errors.Is(err, app.ErrHeld) {
		t.Fatalf("want ErrHeld, got %v", err)
	}

	if len(f.deferrals.deferred) != 1 {
		t.Fatalf("the deferral was recorded %d times, want 1.\n\n"+
			"Recording it is what triggers the Article 12(4) answer — without it the "+
			"person is told nothing for the length of a legal matter.",
			len(f.deferrals.deferred))
	}
	// And it did NOT resume, which would have closed a window that is open.
	if len(f.deferrals.resumed) != 0 {
		t.Errorf("a held erasure resumed its deferral: %v", f.deferrals.resumed)
	}
}

// TestTheRequesterIsAnsweredONCE is the whole reason the deferral is an
// aggregate rather than a variable.
//
// The workflow re-runs this step hourly for as long as the hold stands. A
// person told weekly that their erasure is still deferred is being harassed by
// a compliance obligation — so the SECOND call must record nothing, and the
// caller must be able to tell that it recorded nothing.
func TestTheRequesterIsAnsweredONCE(t *testing.T) {
	f := newFixture(t, holds{held: true, matter: "m-1"})

	for i := range 5 {
		if err := f.erasure.Execute(t.Context(), "subj_1"); !errors.Is(err, app.ErrHeld) {
			t.Fatalf("attempt %d: want ErrHeld, got %v", i, err)
		}
	}

	// Every attempt asks — that is cheap and it is what makes the answer
	// survive a workflow restarting from scratch. What must not happen is five
	// mails, and the recorder reporting `recorded` only once is what stops them.
	if got := f.deferrals.deferred; len(got) != 5 {
		t.Fatalf("Defer was called %d times over 5 attempts; the erasure must ask every "+
			"time, because remembering in workflow state would forget across a restart",
			len(got))
	}
}

// TestADeferralThatCannotBeRecordedFailsRatherThanDefers.
//
// The failure ordering matters. If recording the deferral fails and we return
// ErrHeld anyway, the workflow settles into its hourly wait and the person is
// never told — for the length of a matter, silently. Returning a plain error
// instead makes the workflow RETRY, which is what an unmet obligation deserves.
func TestADeferralThatCannotBeRecordedFailsRatherThanDefers(t *testing.T) {
	f := newFixture(t, holds{held: true, matter: "m-1"})
	f.deferrals.err = errors.New("the event store is unreachable")

	err := f.erasure.Execute(t.Context(), "subj_1")
	if err == nil {
		t.Fatal("an erasure deferred with no record of the deferral")
	}
	if errors.Is(err, app.ErrHeld) {
		t.Fatal("the erasure reported ErrHeld while failing to record the deferral. " +
			"The workflow treats that as a WAIT, so it would settle into an hourly " +
			"poll and the person would never be told — for the length of a matter, " +
			"silently.")
	}
	if len(f.vault.erased) != 0 {
		t.Error("the subject key was destroyed")
	}
}

// TestAnUnheldErasureClosesAnyOpenDeferral.
//
// The window needs a close. It is also the COMMON path — every erasure of an
// unheld subject reaches it — so the recorder must be free when there is
// nothing to close, which is why Resume is idempotent rather than conditional
// on a read the caller performs.
func TestAnUnheldErasureClosesAnyOpenDeferral(t *testing.T) {
	f := newFixture(t, holds{})

	if err := f.erasure.Execute(t.Context(), "subj_1"); err != nil {
		t.Fatalf("erasing: %v", err)
	}
	if len(f.deferrals.resumed) != 1 {
		t.Errorf("Resume was called %d times, want 1", len(f.deferrals.resumed))
	}
	if len(f.deferrals.deferred) != 0 {
		t.Errorf("an unheld erasure recorded a deferral: %v", f.deferrals.deferred)
	}
}

// TestAFailureToCloseTheDeferralDoesNotStopTheErasure is the opposite ordering
// decision from the one above, and the asymmetry is the point.
//
// Failing to RECORD a deferral must stop the erasure, because the person goes
// unanswered. Failing to CLOSE one must not, because the obstacle is gone, they
// have already been told it would complete automatically, and refusing to
// proceed over a bookkeeping append would hold their data longer for nobody's
// benefit.
func TestAFailureToCloseTheDeferralDoesNotStopTheErasure(t *testing.T) {
	f := newFixture(t, holds{})
	f.deferrals.err = errors.New("the event store is unreachable")

	if err := f.erasure.Execute(t.Context(), "subj_1"); err != nil {
		t.Fatalf("an erasure was blocked by a failure to CLOSE a deferral: %v", err)
	}
	if len(f.vault.erased) != 1 {
		t.Error("the erasure did not run")
	}
}

// TestTheEraserRefusesToBuildWithoutADeferralRecorder.
//
// Same shape as the hold checker's, and the same silent failure: every other
// step succeeds, so an erasure waits forever with nobody told — which looks
// from the outside exactly like a slow legal matter.
func TestTheEraserRefusesToBuildWithoutADeferralRecorder(t *testing.T) {
	_, err := app.NewErasure(app.ErasureDeps{
		Vault: &recordingVault{}, Accounts: &recordingAccounts{},
		Objects: &recordingObjects{}, Confirm: &recordingConfirm{},
		Holds: holds{}, Deferrals: nil, Exemptions: realExemptions(),
		Now: time.Now,
	})
	if err == nil {
		t.Fatal("an eraser was built with no deferral recorder, so a held request would " +
			"wait silently for as long as a matter runs and Article 12(4) would go unmet")
	}
	if !strings.Contains(err.Error(), "deferral") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}

// --------------------------------------------------------------------------
// Retention exemptions (compliance.md §4 step 3, §7)
// --------------------------------------------------------------------------

// TestTheConfirmationStatesWhatSurvivesTheErasure.
//
// compliance.md §7: erasure "does not delete [an invoice], and the DSAR response
// says so explicitly rather than implying total deletion". The confirmation is
// that response, and until the exemptions were resolved per subject it carried a
// package-level []string that nothing compared against the published schedule.
//
// The assertion is on the LEGAL BASIS as much as on the class. "We keep some
// things" is not what §7 asks for; "we keep invoices, for 7–10 years, under
// Article 17(3)(b)" is.
func TestTheConfirmationStatesWhatSurvivesTheErasure(t *testing.T) {
	f := newFixture(t, holds{})

	if err := f.erasure.Execute(t.Context(), "subj_1"); err != nil {
		t.Fatalf("erasing: %v", err)
	}
	if len(f.confirm.retained) == 0 {
		t.Fatal("the person was told their account was erased and told nothing about what " +
			"survives, which implies total deletion while tax records are retained")
	}

	var invoices domain.RetentionPolicy
	for _, p := range f.confirm.retained {
		if p.Class == domain.ClassInvoices {
			invoices = p
		}
	}
	if invoices.Class == "" {
		t.Fatalf("the confirmation names %v and not invoices", f.confirm.retained)
	}
	if !strings.Contains(invoices.LegalBasis, "17(3)(b)") {
		t.Errorf("the invoice exemption cites %q; §7 requires the ground to be stated, "+
			"and the ground for keeping data past an erasure request is an article",
			invoices.LegalBasis)
	}
	if invoices.Period == "" {
		t.Error("the invoice exemption states no period, so 'we keep it' has no end")
	}
}

// TestTheConfirmationNeverStatesWhatIsErased.
//
// The same misleading-statement failure pointing the other way. Two of the six
// classes in the schedule go with the subject; telling somebody we keep their
// sign-in history for 90 days after they asked to be forgotten would be false.
func TestTheConfirmationNeverStatesWhatIsErased(t *testing.T) {
	f := newFixture(t, holds{})

	if err := f.erasure.Execute(t.Context(), "subj_1"); err != nil {
		t.Fatalf("erasing: %v", err)
	}
	for _, p := range f.confirm.retained {
		if p.Disposition == domain.DispositionErased {
			t.Errorf("the confirmation states %q as surviving, and it is erased with the "+
				"subject", p.Class)
		}
	}
}

// TestAnEmptyExemptionSetSTOPSTheErasure.
//
// Two exemptions are unconditional — the event log and the operator audit trail
// apply to everybody who ever used this system — so an empty set is not a
// subject with unusually little data. It is a resolver that is not doing its
// job, and the confirmation it would produce says everything about the person is
// gone.
//
// It stops BEFORE the destroy, which is the property worth asserting: the key
// survives, so the erasure can run again once the resolver is fixed. A version
// that destroyed first and refused to confirm would have sent nobody a message
// about an irreversible act.
func TestAnEmptyExemptionSetStopsTheErasure(t *testing.T) {
	f := &fixture{
		vault:     &recordingVault{},
		accounts:  &recordingAccounts{},
		objects:   &recordingObjects{},
		confirm:   &recordingConfirm{},
		deferrals: &deferrals{},
	}
	e, err := app.NewErasure(app.ErasureDeps{
		Vault: f.vault, Accounts: f.accounts, Objects: f.objects,
		Confirm: f.confirm, Holds: holds{}, Deferrals: f.deferrals,
		Exemptions: fixedExemptions{},
		Now:        func() time.Time { return time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC) },
	})
	if err != nil {
		t.Fatalf("building the eraser: %v", err)
	}

	if err := e.Execute(t.Context(), "subj_1"); err == nil {
		t.Fatal("an erasure ran with no exemptions resolved, so the person was told " +
			"everything about them is gone while the event log and the operator audit " +
			"trail survive")
	}
	if len(f.vault.erased) != 0 {
		t.Error("the SUBJECT KEY was destroyed anyway; nothing recovers from this, and " +
			"the reason to refuse was a broken resolver rather than anything about the " +
			"subject")
	}
	if len(f.confirm.sent) != 0 {
		t.Error("a confirmation was sent implying total deletion")
	}
}

// TestTheEraserRefusesToBuildWithoutAnExemptionResolver.
//
// The same silent shape as the hold checker's and the deferral recorder's: every
// other step would succeed, and the only symptom is a confirmation that implies
// total deletion while invoices are retained under Article 17(3)(b).
func TestTheEraserRefusesToBuildWithoutAnExemptionResolver(t *testing.T) {
	_, err := app.NewErasure(app.ErasureDeps{
		Vault: &recordingVault{}, Accounts: &recordingAccounts{},
		Objects: &recordingObjects{}, Confirm: &recordingConfirm{},
		Holds: holds{}, Deferrals: &deferrals{}, Exemptions: nil,
		Now: time.Now,
	})
	if err == nil {
		t.Fatal("an eraser was built with no exemption resolver, so every confirmation " +
			"would imply total deletion")
	}
	if !strings.Contains(err.Error(), "retention-exemption") {
		t.Errorf("refused for the wrong reason: %v", err)
	}
}
