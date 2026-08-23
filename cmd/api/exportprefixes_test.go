package main

import (
	"testing"

	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
)

// THE EXPORT WALKS EXACTLY WHAT THE ERASURE DELETES.
//
// # The worst combination available here
//
// cmd/api walks these prefixes to EXPORT and cmd/worker walks its own copy to
// ERASE. If the export's list is shorter, a person receives a bundle that looks
// complete, and the erasure then destroys the files the bundle omitted — so they
// are handed a plausible answer to Article 15 and lose the part it left out,
// with no way to know either happened.
//
// The two lists live in two composition roots because compliance may not import
// another module's internals (CONVENTIONS §2) and `profile.AvatarPrefix` is
// exactly that kind of detail. Nothing but this holds them equal.
//
// It compares the RESULTS rather than the source, so a list that grew in one
// binary and not the other fails here rather than in a subject access request.
func TestTheExportAndTheErasureWalkTheSamePrefixes(t *testing.T) {
	const subject = "subj_01ARZ3NDEKTSV4RRFFQ69G5FAV"

	got := subjectObjectPrefixes(subject)
	if len(got) == 0 {
		t.Fatal("the export walks no object prefixes at all; every file a person uploaded " +
			"is silently missing from their Article 15 bundle")
	}

	// Every prefix a module contributes must be present. Named explicitly rather
	// than derived, so ADDING a module that stores objects fails this test until
	// somebody decides whether it belongs in an export.
	want := map[string]string{
		"profile avatars": profiledomain.AvatarPrefix(subject),
	}
	for what, prefix := range want {
		var found bool
		for _, p := range got {
			if p == prefix {
				found = true
			}
		}
		if !found {
			t.Errorf("%s (%q) is not in the export's prefix list %v. Those objects are "+
				"omitted from the bundle and deleted by the erasure that follows",
				what, prefix, got)
		}
	}

	if len(got) != len(want) {
		t.Errorf("the export walks %d prefixes and this test knows about %d. A prefix "+
			"added to one composition root and not the other is an export that covers "+
			"less than the erasure deletes", len(got), len(want))
	}
}
