package domain_test

import (
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var exportAt = time.Date(2026, 8, 23, 9, 0, 0, 0, time.UTC)

func requested(t *testing.T) *domain.Export {
	t.Helper()
	e := eventsourcing.NewAggregate(domain.NewExport)
	if err := e.Request("exp_1", "subj_1", exportAt); err != nil {
		t.Fatalf("request: %v", err)
	}
	e.ClearUncommitted()
	return e
}

// A REQUEST IS PENDING, NOT READY.
//
// The zero value must never read as a finished export: a caller polling an id
// that was never requested, or one still building, must not be handed a state
// that says "fetch it".
func TestAFreshExportIsPendingAndAnUnknownOneIsNothing(t *testing.T) {
	if got := eventsourcing.NewAggregate(domain.NewExport).State(); got != domain.ExportStateNone {
		t.Fatalf("an export nobody requested reports state %q", got)
	}
	if got := requested(t).State(); got != domain.ExportStatePending {
		t.Fatalf("a requested export reports state %q, want pending", got)
	}
}

// REQUESTING TWICE RECORDS ONCE.
//
// The id is derived from the caller's idempotency key, so a retried request
// lands on the same stream. A second event would start a second workflow, and
// two workflows building one person's export is two bundles and two "your export
// is ready" mails for one request.
func TestRequestingTwiceRecordsOnce(t *testing.T) {
	e := requested(t)
	if err := e.Request("exp_1", "subj_1", exportAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := e.Uncommitted(); len(got) != 0 {
		t.Fatalf("a retried request recorded %d events; two workflows now build one "+
			"person's export", len(got))
	}
}

// A COMPLETED EXPORT IS NEVER FAILED AFTERWARDS.
//
// A redelivered failure from an earlier attempt, or a late timeout on a run that
// had already succeeded, would otherwise overwrite a fetchable bundle with an
// error — and the subject would be told their export failed while the manifest
// sat there waiting for them.
func TestAReadyExportCannotBeFailed(t *testing.T) {
	e := requested(t)
	if err := e.Complete("obj_manifest", 3, exportAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.ClearUncommitted()

	if err := e.Fail(contract.ExportFailedUnreadable, exportAt.Add(2*time.Minute)); err == nil {
		t.Fatal("a late failure overwrote a finished export; the subject is told it " +
			"failed while the bundle is sitting there")
	}
	if e.State() != domain.ExportStateReady || e.ManifestKey() != "obj_manifest" {
		t.Fatalf("the refused failure still moved the export to %q/%q",
			e.State(), e.ManifestKey())
	}
}

// A FAILURE IS RECOVERABLE BY A LATER SUCCESS.
//
// The mirror of the rule above, and the pair is what makes either meaningful: a
// workflow that failed and was retried into success must leave a fetchable
// export, not a permanent error.
func TestAFailedExportCanStillBeCompleted(t *testing.T) {
	e := requested(t)
	if err := e.Fail(contract.ExportFailedUnreadable, exportAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	if err := e.Complete("obj_manifest", 0, exportAt.Add(2*time.Minute)); err != nil {
		t.Fatalf("a retried workflow could not complete a previously failed export: %v", err)
	}
	if e.State() != domain.ExportStateReady {
		t.Fatalf("state is %q after a successful retry", e.State())
	}
	if e.Reason() != "" {
		t.Errorf("the completed export still carries failure reason %q, so it reads as "+
			"having both succeeded and failed", e.Reason())
	}
}

// AN OUTCOME FOR A REQUEST NOBODY MADE IS REFUSED.
//
// Article 15's evidence is "this person asked, and this is what they got". An
// outcome with no request is a bundle nobody can be shown to have asked for.
func TestAnOutcomeWithoutARequestIsRefused(t *testing.T) {
	for name, apply := range map[string]func(*domain.Export) error{
		"complete": func(e *domain.Export) error { return e.Complete("obj_x", 1, exportAt) },
		"fail": func(e *domain.Export) error {
			return e.Fail(contract.ExportFailedUnreadable, exportAt)
		},
	} {
		t.Run(name, func(t *testing.T) {
			if err := apply(eventsourcing.NewAggregate(domain.NewExport)); err == nil {
				t.Fatalf("%s succeeded on an export nobody requested", name)
			}
		})
	}
}

// COMPLETING TWICE WITH THE SAME MANIFEST RECORDS ONCE.
//
// An activity is at-least-once, so this is the ordinary retry.
func TestCompletingTwiceRecordsOnce(t *testing.T) {
	e := requested(t)
	if err := e.Complete("obj_manifest", 2, exportAt.Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	e.ClearUncommitted()
	if err := e.Complete("obj_manifest", 2, exportAt.Add(2*time.Minute)); err != nil {
		t.Fatal(err)
	}
	if got := e.Uncommitted(); len(got) != 0 {
		t.Fatalf("a retried completion recorded %d events", len(got))
	}
}

// A COMPLETION MUST NAME ITS MANIFEST.
//
// An export reported ready with no manifest key is one the poll endpoint cannot
// mint a URL for: the subject is told to fetch something that has no address.
func TestACompletionWithoutAManifestIsRefused(t *testing.T) {
	if err := requested(t).Complete("", 0, exportAt); err == nil {
		t.Fatal("an export was reported ready with no manifest to fetch")
	}
}

// A FAILURE MUST STATE A REASON.
func TestAFailureWithoutAReasonIsRefused(t *testing.T) {
	if err := requested(t).Fail("", exportAt); err == nil {
		t.Fatal("an export failed with no reason; nothing downstream can tell a retryable " +
			"outage from a subject who holds too many objects")
	}
}
