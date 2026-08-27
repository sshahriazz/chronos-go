package subjectdata_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/subjectdata"
)

func prefix(namespace string) subjectdata.PrefixFor {
	return func(subjectID string) string { return namespace + "/" + subjectID + "/" }
}

func profileFragment() subjectdata.Fragment {
	return subjectdata.Fragment{
		Module:         "profile",
		ObjectPrefixes: []subjectdata.PrefixFor{prefix("avatars")},
	}
}

func identityFragment() subjectdata.Fragment {
	return subjectdata.Fragment{
		Module:       "identity",
		VaultFields:  []string{"email", "display_name"},
		Reservations: []string{"email_index", "username"},
	}
}

// THE TRAVERSAL IS THE SAME OBJECT FOR EVERY CALLER.
//
// This is compliance.md §16's "export and erasure traverse the same subject
// graph". It used to be asserted by a test comparing two hand-written lists
// against a third hand-written list, in two `main` packages that cannot import
// each other. Here it is not asserted at all: both callers hold the same Graph
// and call the same method, so there is nothing left to disagree.
func TestEveryFragmentsPrefixesAreWalked(t *testing.T) {
	g, err := subjectdata.Assemble([]subjectdata.Fragment{
		profileFragment(),
		{Module: "attachments", ObjectPrefixes: []subjectdata.PrefixFor{prefix("files")}},
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	got := g.Prefixes("subj_1")
	if len(got) != 2 {
		t.Fatalf("walked %d prefixes, want 2: a module missing from the traversal erases "+
			"incompletely and the symptom is nothing at all", len(got))
	}
	for _, want := range []string{"avatars/subj_1/", "files/subj_1/"} {
		found := false
		for _, p := range got {
			if p == want {
				found = true
			}
		}
		if !found {
			t.Errorf("the traversal does not cover %q: %v", want, got)
		}
	}
}

// The order does not depend on the argument order, so two Graphs assembled from
// the same fragments compare equal and a traversal is reproducible.
func TestAssemblyIsOrderIndependent(t *testing.T) {
	a, err := subjectdata.Assemble([]subjectdata.Fragment{profileFragment(), identityFragment()})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	b, err := subjectdata.Assemble([]subjectdata.Fragment{identityFragment(), profileFragment()})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	if strings.Join(a.Prefixes("s"), "|") != strings.Join(b.Prefixes("s"), "|") {
		t.Errorf("prefixes differ by argument order: %v vs %v", a.Prefixes("s"), b.Prefixes("s"))
	}
	if strings.Join(a.VaultFields(), "|") != strings.Join(b.VaultFields(), "|") {
		t.Errorf("vault fields differ by argument order")
	}
	if strings.Join(a.Modules(), "|") != strings.Join(b.Modules(), "|") {
		t.Errorf("modules differ by argument order: %v vs %v", a.Modules(), b.Modules())
	}
}

// AN EMPTY GRAPH IS REFUSED.
//
// It traverses nothing, deletes nothing and reports success, which is the one
// outcome an erasure must never have. Refused at assembly so the failure lands
// at startup rather than on somebody's erasure.
func TestAnEmptyGraphIsRefused(t *testing.T) {
	if _, err := subjectdata.Assemble(nil); err == nil {
		t.Fatal("an empty subject graph was accepted; an erasure over it deletes nothing " +
			"and reports success")
	}
}

// A FRAGMENT THAT HOLDS NOTHING IS REFUSED.
//
// A module with no personal data declares no fragment. An empty one reads, to
// anybody auditing the list, as a module that was considered and covered.
func TestAFragmentHoldingNothingIsRefused(t *testing.T) {
	_, err := subjectdata.Assemble([]subjectdata.Fragment{{Module: "billing"}})
	if err == nil {
		t.Fatal("a fragment declaring no data at all was accepted")
	}
	if !strings.Contains(err.Error(), "billing") {
		t.Errorf("the refusal does not name the module, so it is not actionable: %v", err)
	}
}

// A VAULT FIELD MAY HAVE SEVERAL WRITERS, AND THE GRAPH NAMES THEM ALL.
//
// This test asserted the opposite until an inventory of the running system
// showed why the opposite is wrong. `email` is written by identity at
// registration AND by workspace when an invitation goes to somebody with no
// account — workspace mints a pseudonym for them and stores their address under
// it.
//
// An exclusivity rule would refuse that, and refusing it would encode an
// invariant this system does not have: erasure destroys the subject's KEY, so
// every field of that subject dies at once whoever wrote it. What the
// declaration is for is answering "who puts personal data in the vault", which
// a controller must be able to answer and nothing else here records.
func TestAVaultFieldMayHaveSeveralWriters(t *testing.T) {
	g, err := subjectdata.Assemble([]subjectdata.Fragment{
		identityFragment(),
		{Module: "workspace", VaultFields: []string{"email"}},
	})
	if err != nil {
		t.Fatalf("two modules writing one field was refused: %v", err)
	}

	writers := g.WritersOf("email")
	if len(writers) != 2 {
		t.Fatalf("the graph names %d writers of email, want 2: %v", len(writers), writers)
	}
	if writers[0] != "identity" || writers[1] != "workspace" {
		t.Errorf("writers of email are %v, want [identity workspace] sorted", writers)
	}
	if len(g.WritersOf("phone")) != 0 {
		t.Error("a field nothing declares reports a writer")
	}
}

// The SAME module declaring one field twice is still refused: it is a copied
// line rather than a second writer, and the duplicate would inflate the count a
// controller reads.
func TestOneModuleCannotDeclareAFieldTwice(t *testing.T) {
	_, err := subjectdata.Assemble([]subjectdata.Fragment{
		{Module: "identity", VaultFields: []string{"email", "email"}},
	})
	if err == nil {
		t.Fatal("a module declared one vault field twice and it was accepted")
	}
}

// A RESERVATION has exactly one holder, and that rule stays.
//
// Unlike a vault field, a reservation is RELEASED by a specific module on
// erasure — identity releases the address and tombstones the handle. Two
// claimants would mean two modules each believing the other releases it.
func TestTwoModulesCannotClaimOneReservation(t *testing.T) {
	_, err := subjectdata.Assemble([]subjectdata.Fragment{
		identityFragment(),
		{Module: "workspace", Reservations: []string{"email_index"}},
	})
	if err == nil {
		t.Fatal("two modules claimed one reservation; each would believe the other " +
			"releases it on erasure")
	}
	for _, want := range []string{"identity", "workspace", "email_index"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the refusal does not name %q: %v", want, err)
		}
	}
}

// The same module declared twice is refused: the second silently replaces the
// first in every error message, and the two may not agree.
func TestOneModuleDeclaresOneFragment(t *testing.T) {
	_, err := subjectdata.Assemble([]subjectdata.Fragment{profileFragment(), profileFragment()})
	if err == nil {
		t.Fatal("a module declared two fragments and both were accepted")
	}
}

// A nil prefix function is refused at assembly rather than panicking on the
// first erasure — which would be the first time anybody exercised the path,
// during somebody's statutory request.
func TestANilPrefixIsRefused(t *testing.T) {
	_, err := subjectdata.Assemble([]subjectdata.Fragment{
		{Module: "profile", ObjectPrefixes: []subjectdata.PrefixFor{nil}},
	})
	if err == nil {
		t.Fatal("a nil prefix function was accepted; it panics on the first traversal")
	}
}

// Prefixes DIFFER PER SUBJECT.
//
// A constant prefix would make one erasure delete another person's objects, and
// would make every export bundle contain everybody.
func TestPrefixesAreScopedToTheSubject(t *testing.T) {
	g, err := subjectdata.Assemble([]subjectdata.Fragment{profileFragment()})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if strings.Join(g.Prefixes("subj_1"), "") == strings.Join(g.Prefixes("subj_2"), "") {
		t.Fatal("two subjects share a prefix; one erasure would delete the other's " +
			"objects and one export would carry them")
	}
}
