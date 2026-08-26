package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
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

type recordingConfirm struct{ sent []string }

func (c *recordingConfirm) SendErasureComplete(
	_ context.Context, subjectID string, _ []string,
) error {
	c.sent = append(c.sent, subjectID)
	return nil
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

type fixture struct {
	vault    *recordingVault
	accounts *recordingAccounts
	objects  *recordingObjects
	confirm  *recordingConfirm
	erasure  *app.Erasure
}

func newFixture(t *testing.T, h app.LegalHolds) *fixture {
	t.Helper()
	f := &fixture{
		vault:    &recordingVault{},
		accounts: &recordingAccounts{},
		objects:  &recordingObjects{},
		confirm:  &recordingConfirm{},
	}
	e, err := app.NewErasure(app.ErasureDeps{
		Vault: f.vault, Accounts: f.accounts, Objects: f.objects,
		Confirm: f.confirm, Holds: h,
		Now: func() time.Time { return time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC) },
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
		Holds: nil,
		Now:   time.Now,
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
