// Package subjectgraph is the composition root for compliance.md §4 step 4.
//
// # Why this is not part of the compliance module
//
// `compliance` traverses the graph and must not know which modules exist — the
// same argument ADR-006 makes for resource types, and the same shape
// `internal/authzmodel` takes for the authorization model. A compliance module
// holding a list of other modules' storage would need editing every time
// somebody shipped a feature, and the edit nobody remembers is the one that
// makes an erasure incomplete.
//
// # Why it is a package and not a function in a binary
//
// It was two functions in two binaries. `cmd/api/deps.go` and
// `cmd/worker/erasure.go` each defined their own `subjectObjectPrefixes`, both
// returning the profile avatar prefix, because a main package is importable by
// nothing. The export walked one and the erasure walked the other.
//
// compliance.md §16 asks for "a property test asserting the two sets are
// identical", and what existed instead was two tests, one per binary, each
// comparing its own list against a THIRD hand-written literal inside the test.
// A consistency check between two copies is only as good as the copy nobody
// updates — which is exactly how the projection registry drifted twice before
// it was collapsed the same way.
//
// So there is one graph. Both callers hold it and both call Prefixes, and the
// property the test was trying to assert is true by construction instead.
package subjectgraph

import (
	"fmt"

	identitydomain "github.com/chronos/chronos-go/internal/modules/identity/domain"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	workspacedomain "github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/subjectdata"
)

// Fragments is every module's declaration, in one place.
//
// A module that holds personal data about a subject appears here. A module that
// holds none does not, and declaring an empty fragment for it is refused —
// "considered and holds nothing" and "forgotten" must not look the same in this
// list.
func Fragments() []subjectdata.Fragment {
	return []subjectdata.Fragment{
		// Vault addresses — the primary, the pending one an email change has
		// claimed but not proven, and the previous one a revert would restore.
		// Plus the two identifier reservations the key destruction cannot reach:
		// the email blind index (EVENT-SOURCING §5's deliberate exception, keyed
		// under a key that is never destroyed) and the username, which is
		// tombstoned rather than released because the handle is published by
		// design (ADR-051).
		identitydomain.SubjectDataFragment(),

		// Avatars in the object store — the only personal data in this system the
		// vault's key destruction does not reach — plus the display name, locale
		// and timezone it writes.
		profiledomain.SubjectDataFragment(),

		// The one that is easy to miss: issuing an invitation to somebody with no
		// account stores THEIR address, under a pseudonym workspace mints for a
		// person who has never used this system. It was found by inventory rather
		// than by anybody remembering it, which is the argument for this list
		// existing at all.
		workspacedomain.SubjectDataFragment(),
	}
}

// Assemble builds the graph, refusing a list that would traverse incompletely.
//
// Called by every composition root that erases or exports. A failure here stops
// the process from starting, which is the correct place for it: the alternative
// is a running deployment whose erasures silently miss a module.
func Assemble() (subjectdata.Graph, error) {
	g, err := subjectdata.Assemble(Fragments())
	if err != nil {
		return subjectdata.Graph{}, fmt.Errorf("subjectgraph: %w", err)
	}
	return g, nil
}
