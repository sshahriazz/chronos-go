package app_test

import (
	"context"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/codec"
)

// The BUNDLE — what a data subject actually receives.
//
// # These tests used to drive a use case that shipped in no binary
//
// They lived in export_test.go and exercised `app.Exports`, the synchronous
// export: build the bundle, upload it, return a URL, all in one call. It was
// complete, it was tested by exactly these assertions, and it was constructed
// by nothing. The path that ships is `ExportRuns`, driven by a Temporal
// workflow, and it built its bundle in its own code.
//
// So every property below was asserted about an implementation nobody ran, and
// the one people receive their personal data from was covered by none of them.
// That is the "built, tested, wired into nothing" shape CLAUDE.md names, with
// its worst consequence: the tests read as coverage.
//
// They now drive the async producer through the same harness the rest of
// exportrun_test.go uses, so they assert the bytes the store is actually handed.

// writeBundle runs one export to completion and returns what was stored.
func writeBundle(t *testing.T, profileFields map[string]string) app.Bundle {
	t.Helper()

	hh := newRunHarnessWithProfile(t, profileFields)
	ctx := context.Background()

	id, err := hh.runs.Request(ctx, app.RequestExportCommand{
		SubjectID: "subj_1", IdempotencyKey: "k-bundle",
	})
	if err != nil {
		t.Fatalf("Request: %v", err)
	}
	if _, err := hh.runs.WriteManifest(ctx, id, nil); err != nil {
		t.Fatalf("WriteManifest: %v", err)
	}
	if len(hh.store.put) != 1 {
		t.Fatalf("the store was handed %d objects, want 1", len(hh.store.put))
	}

	bundle, err := codec.Tolerant[app.Bundle](hh.store.put[0])
	if err != nil {
		t.Fatalf("the stored bundle does not decode: %v", err)
	}
	return bundle
}

// THE BUNDLE CARRIES EVERY FIELD THE VAULT HOLDS.
//
// A person cannot know what they were not given, so a field silently dropped
// between the vault and the file is an Article 15 answer that is wrong in the
// one direction nobody can detect from the outside.
func TestTheBundleCarriesEveryField(t *testing.T) {
	bundle := writeBundle(t, map[string]string{
		"email": "a@example.test", "name": "Sam", "locale": "en", "timezone": "UTC",
	})

	if len(bundle.PersonalData) != 4 {
		t.Fatalf("the bundle carries %d fields, want 4; a person cannot know what they "+
			"were not given", len(bundle.PersonalData))
	}
	if bundle.PersonalData["email"] != "a@example.test" {
		t.Errorf("the email is %q", bundle.PersonalData["email"])
	}
	if bundle.SubjectID != "subj_1" {
		t.Errorf("the bundle names %q", bundle.SubjectID)
	}
	if bundle.FormatVersion != app.ExportFormatVersion {
		t.Errorf("format version %d", bundle.FormatVersion)
	}
	if !bundle.GeneratedAt.Equal(runAt) {
		t.Errorf("generated at %v, want %v", bundle.GeneratedAt, runAt)
	}
}

// AND IT SAYS WHAT IS RETAINED.
//
// Article 15(1) asks about the PROCESSING, not only the values. A file listing
// a name and an address while saying nothing about invoices retained under a
// statutory obligation is accurate and misleading — the same reason the erasure
// confirmation carries the list.
func TestTheBundleStatesWhatIsRetained(t *testing.T) {
	bundle := writeBundle(t, nil)

	if len(bundle.Retained) == 0 {
		t.Fatal("the bundle states nothing about what is retained; it lists values and " +
			"implies they are everything")
	}
	var invoices app.RetainedRecord
	for _, r := range bundle.Retained {
		if strings.Contains(strings.ToLower(r.DataClass), "invoice") {
			invoices = r
		}
	}
	if invoices.DataClass == "" {
		t.Fatalf("the retained list does not mention invoices: %v. They survive under "+
			"Article 17(3)(b) and a bundle that implies otherwise is a misleading "+
			"statement about processing", bundle.Retained)
	}

	// THE LEGAL BASIS IS ITS OWN FIELD, and this is what the format-version bump
	// bought. It used to be a clause inside an English sentence, so a reader
	// could display the statement and could not do anything else with it — not
	// tell which class it was about, not extract the basis, not translate it.
	if invoices.LegalBasis == "" {
		t.Error("the invoice exemption states no legal basis. compliance.md §7 requires " +
			"the DSAR response to say what is retained AND why, and 'why' under the GDPR " +
			"is an article rather than a business reason")
	}
	if !strings.Contains(invoices.LegalBasis, "17(3)(b)") {
		t.Errorf("the invoice exemption cites %q; tax-law retention rests on Article "+
			"17(3)(b) and citing anything else states the wrong ground for keeping "+
			"somebody's data", invoices.LegalBasis)
	}
	if invoices.Period == "" {
		t.Error("the invoice exemption states no retention period. Article 15(1)(d) asks " +
			"for the envisaged storage period, which is the one thing 'we keep some of it' " +
			"does not answer")
	}
}

// THE BUNDLE STATES ONLY WHAT SURVIVES, NOT THE WHOLE SCHEDULE.
//
// The retention schedule has classes that are erased with the subject. Listing
// those under a heading that says what is RETAINED would tell somebody their
// session logs are kept when they are destroyed — the same misleading-statement
// failure as the omission, pointing the other way.
func TestTheBundleDoesNotListWhatIsErased(t *testing.T) {
	bundle := writeBundle(t, nil)

	for _, r := range bundle.Retained {
		lower := strings.ToLower(r.DataClass)
		if strings.Contains(lower, "session") || strings.Contains(lower, "notification") {
			t.Errorf("the retained list names %q, which is ERASED with the account. A "+
				"person told their session logs survive has been given a false "+
				"statement about their own data", r.DataClass)
		}
	}
}
