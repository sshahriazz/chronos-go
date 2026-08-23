package main

import (
	"errors"
	"testing"

	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	complianceapp "github.com/chronos/chronos-go/internal/modules/compliance/app"
)

// THE PERMANENCE MAPPING SURVIVES THE ADAPTER.
//
// # What breaks without it, and why nothing else sees it
//
// compliance marks a failure permanent with its own error type; the workflow
// engine recognises its own marker; and neither package may import the other, so
// this adapter is the only place the two meet. If the mapping is lost, a subject
// under Article 18 restriction has their export RETRIED for the workflow's whole
// hour before they are told something the first attempt already knew.
//
// The module's tests assert the error is produced. The workflow's tests assert
// the marker is honoured. Only this asserts they are connected — and the
// end-to-end test cannot, because it runs against a copy of this adapter for
// want of being able to import a main package.
func TestThePermanenceMappingSurvivesTheAdapter(t *testing.T) {
	permanent := &complianceapp.PermanentExportError{Reason: "processing_restricted"}
	mapped := permanence(permanent)

	if !errors.Is(mapped, temporaladapter.ErrPermanentExport) {
		t.Fatalf("a permanent failure mapped to %v, which the workflow will RETRY for an "+
			"hour. A restricted subject waits the full schedule to be told something the "+
			"first attempt already knew", mapped)
	}
	// The REASON survives, because the workflow reads it back out of the message
	// — an activity error crosses a process boundary and arrives having lost the
	// Go type.
	if !contains(mapped.Error(), "processing_restricted") {
		t.Errorf("the mapped error is %q and does not carry its reason; the workflow "+
			"records `source_unreadable` for a restriction, and the person is told to "+
			"try again for something trying again cannot fix", mapped)
	}

	// A TRANSIENT failure is NOT marked. Marking one would permanently fail a
	// request the person is entitled to, because an object store is briefly down.
	transient := errors.New("s3 is unreachable")
	if errors.Is(permanence(transient), temporaladapter.ErrPermanentExport) {
		t.Fatal("a transient failure was marked permanent; an object store that is down " +
			"for a minute permanently fails an Article 15 request")
	}
}
