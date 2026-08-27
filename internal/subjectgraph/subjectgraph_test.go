package subjectgraph_test

import (
	"strings"
	"testing"

	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/pii"
	"github.com/chronos/chronos-go/internal/subjectgraph"
)

// unwrittenByDesign are vault fields no module writes, ON PURPOSE.
//
// A field here is still enumerated by a subject access request — `pii.AllFields`
// is what answers one — so it is exportable and revealable while nothing ever
// puts a value in it. That is harmless and it is not obviously harmless, which
// is why it is written down with a reason rather than left to be rediscovered.
//
// Moving a field OUT of this map is the correct action when a writer appears.
// Adding one is a decision somebody has to type, next to the reason.
var unwrittenByDesign = map[pii.Field]string{
	pii.FieldPhone: "SMS second factors are not built, so no flow writes a phone " +
		"number. identity.md keeps the field because the vault's field set is a " +
		"closed vocabulary (pii.Field.Valid) and adding one later is a migration of " +
		"meaning rather than of schema; compliance's rectification deliberately " +
		"excludes it for the same reason — there is nothing inaccurate to correct.",
}

// EVERY VAULT FIELD IS EITHER CLAIMED BY A MODULE OR NAMED AS UNWRITTEN.
//
// # This is the gate the subject graph exists for
//
// Before it, the answer to "what would fail if a new module started holding
// personal data" was: nothing. A module could write a vault field, store objects
// under its own prefix, or put personal data in its own table, and no test, no
// lint rule and no startup check would notice. The failure mode is silent by
// construction — an erasure that misses something reports success, and the only
// person positioned to discover it is the data subject.
//
// This closes the vault half of that, which is the half a machine can check: the
// field set is a closed vocabulary (`pii.AllFields`), so every member of it can
// be required to have a declared writer. A module that starts writing one
// without declaring it fails here.
//
// It cannot close the other half — a module holding personal data in its own
// table, outside the vault, is invisible to any check that does not know the
// module exists. What it does is make the declaration a habit and the omission
// loud in the one place it can be.
func TestEveryVaultFieldIsClaimedOrNamedAsUnwritten(t *testing.T) {
	g, err := subjectgraph.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	for _, field := range pii.AllFields {
		writers := g.WritersOf(string(field))
		reason, excused := unwrittenByDesign[field]

		switch {
		case len(writers) > 0 && excused:
			t.Errorf("the vault field %q is written by %v and is ALSO listed as unwritten "+
				"by design (%q). One of the two is out of date, and the list is the one "+
				"that cannot be checked against reality — remove the entry.",
				field, writers, reason)
		case len(writers) == 0 && !excused:
			t.Errorf("no module declares it writes the vault field %q.\n\n"+
				"A subject access request enumerates pii.AllFields, so this field is "+
				"exported and revealable. Either a module writes it and never said so — "+
				"in which case add it to that module's SubjectDataFragment — or nothing "+
				"writes it, in which case add it to unwrittenByDesign with the reason. "+
				"Both are one line; the silence is what is not allowed.", field)
		}
	}

	// And the other direction: a declaration naming a field the vault does not
	// have is a typo that would otherwise sit there looking like coverage.
	for _, declared := range g.VaultFields() {
		if !pii.Field(declared).Valid() {
			t.Errorf("a module declares it writes %q, which is not a vault field. The "+
				"declaration covers nothing and reads as though it does.", declared)
		}
	}
}

// THE GRAPH ASSEMBLES AT ALL, AND COVERS THE ONE PREFIX THE VAULT CANNOT REACH.
//
// Assembly refuses an empty graph, a module declared twice, a fragment holding
// nothing and a nil prefix — so this failing means one of those, and the message
// says which. The avatar assertion is the specific one: it is the only object
// namespace in the system, and objects are the only personal data a key
// destruction leaves behind.
func TestTheGraphCoversAvatars(t *testing.T) {
	g, err := subjectgraph.Assemble()
	if err != nil {
		t.Fatalf("the subject graph does not assemble, so no process that erases or "+
			"exports can start: %v", err)
	}

	want := profiledomain.AvatarPrefix("subj_1")
	found := false
	for _, prefix := range g.Prefixes("subj_1") {
		if prefix == want {
			found = true
		}
	}
	if !found {
		t.Fatalf("the traversal does not cover profile's avatars (%v). An erasure over it "+
			"deletes the vault key and leaves the photographs, still servable by a "+
			"signed URL.", g.Prefixes("subj_1"))
	}
}

// The prefixes are per subject, so one erasure cannot delete another person's
// objects and one export cannot carry them.
func TestTheTraversalIsScopedToOneSubject(t *testing.T) {
	g, err := subjectgraph.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if strings.Join(g.Prefixes("subj_1"), "|") == strings.Join(g.Prefixes("subj_2"), "|") {
		t.Fatal("two subjects share every prefix; one erasure would delete the other's " +
			"objects")
	}
}

// EVERY DECLARING MODULE IS IN THE LIST.
//
// The authorization model has the same shape and no such gate: a module can add
// an `accessfragment.go` and forget the line in `authzmodel.Fragments()`, and
// the type is simply absent from the deployed model. Here the equivalent
// omission means a module's personal data is never traversed, so it is asserted.
//
// Checked by NAME against what the fragments declare, rather than by walking the
// filesystem: a directory walk would pass for a module whose file exists and
// whose fragment is not in the list, which is precisely the omission.
func TestEveryDeclaredModuleIsNamed(t *testing.T) {
	g, err := subjectgraph.Assemble()
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}

	want := []string{"identity", "profile", "workspace"}
	got := g.Modules()
	if len(got) != len(want) {
		t.Fatalf("the graph names %v; this test knows about %v.\n\n"+
			"A module added to the graph and not to this list is fine and this line is "+
			"the reminder to say so. A module REMOVED from the graph is the dangerous "+
			"direction: its personal data stops being traversed and every erasure keeps "+
			"reporting success.", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("module %d is %q, want %q (the graph sorts them)", i, got[i], want[i])
		}
	}
}
