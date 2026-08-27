// Package subjectdata is the kernel half of compliance.md §4 step 4: "traverse
// the subject graph → which streams, rows, objects".
//
// # Why a fragment, and why the kernel declares the type
//
// The module that HOLDS personal data is the only one that can say where it
// holds it, and compliance must not know which modules exist — the same
// argument ADR-006 makes for resource types, which is why
// `internal/platform/authz/model` exists in exactly this shape. A compliance
// module with a list of other modules' storage would need editing every time
// somebody added a feature, and the edit nobody remembers is the one that makes
// an erasure incomplete.
//
// So each module declares a Fragment, a composition root names them
// (`internal/subjectgraph`), and compliance traverses the assembled Graph
// without knowing whose data it is walking.
//
// # What it does NOT cover, and why that is not a hole
//
// Event streams. Personal data never enters an event (ADR-002) — events carry
// `SubjectID` pseudonyms — so there is no stream to traverse and destroying the
// subject's key makes every vault reference in the log unreadable at once. The
// graph covers what the key destruction does not reach: objects in the bucket,
// and identifier reservations that are deliberately readable so a released
// address can be re-registered.
package subjectdata

import (
	"fmt"
	"slices"
	"sort"
)

// PrefixFor names an object-store namespace belonging to one subject.
//
// A FUNCTION rather than a literal prefix, because the prefix depends on the
// subject and because a projection can only name the current object. An avatar
// that was replaced leaves the old one behind, and an upload that was granted
// and never confirmed leaves one no row ever mentioned; both are personal data,
// both sit under the subject's prefix, and enumerating the prefix finds all
// three kinds where enumerating rows finds one.
type PrefixFor func(subjectID string) string

// Fragment is one module's declaration of the personal data it holds.
//
// A module that holds none declares no fragment. An empty fragment would say
// "this module was considered and holds nothing", which is a useful thing to be
// able to say and a dangerous default — so Assemble refuses one, and a module
// with nothing to declare simply stays out of the list.
type Fragment struct {
	// Module names the declaring module, for the error messages. It is what
	// makes "two modules claim this" actionable.
	Module string

	// ObjectPrefixes are the bucket namespaces this module stores a subject's
	// objects under. Erasure deletes everything beneath them; export lists it.
	ObjectPrefixes []PrefixFor

	// VaultFields are the PII vault fields this module WRITES.
	//
	// Erasure does not walk these — one key destruction makes every field
	// unreadable at once, which is the whole point of ADR-002 — so this is not a
	// work list. It is the COMPLETENESS gate: a test asserts that every field the
	// vault defines is claimed by exactly one fragment, so a module that starts
	// storing personal data and does not declare it fails the build rather than
	// being discovered by a data subject.
	VaultFields []string

	// Reservations are the identifier reservations this module holds for a
	// subject — an email index entry, a username tombstone.
	//
	// Named rather than traversed, for the same reason as VaultFields: releasing
	// them is identity's own erasure step (compliance.md §4 step 7), and what
	// this buys is that the graph can be asked "what does this system hold about
	// a person" and answer completely, including the parts another module owns
	// the destruction of.
	Reservations []string
}

// Graph is every module's declaration, assembled.
type Graph struct {
	fragments []Fragment
	writersOf map[string][]string
}

// Assemble merges the fragments, refusing the mistakes that would make a
// traversal quietly incomplete.
//
// Deterministic: the same fragments in any order produce the same Graph, so a
// traversal is reproducible and a test comparing two of them compares content
// rather than argument order.
func Assemble(fragments []Fragment) (Graph, error) {
	if len(fragments) == 0 {
		// An empty graph traverses nothing and reports success, which is exactly
		// what an erasure must never do. Refused here rather than at the first
		// traversal, so the failure lands at startup with the composition root in
		// the stack.
		return Graph{}, fmt.Errorf("subjectdata: the subject graph is empty; an erasure " +
			"that traverses nothing deletes nothing and reports success")
	}

	seenModule := map[string]bool{}
	writersOf := map[string][]string{}
	ownerOfReservation := map[string]string{}

	for _, f := range fragments {
		if f.Module == "" {
			return Graph{}, fmt.Errorf("subjectdata: a fragment declares no module; the " +
				"name is what makes a conflict between two of them actionable")
		}
		if seenModule[f.Module] {
			return Graph{}, fmt.Errorf("subjectdata: %q declares two fragments; one module "+
				"has one declaration, or the second silently replaces the first in every "+
				"error message", f.Module)
		}
		seenModule[f.Module] = true

		if len(f.ObjectPrefixes) == 0 && len(f.VaultFields) == 0 && len(f.Reservations) == 0 {
			return Graph{}, fmt.Errorf("subjectdata: %q declares a fragment holding nothing; "+
				"a module with no personal data declares no fragment, and an empty one "+
				"reads as a module that was covered", f.Module)
		}
		for i, prefix := range f.ObjectPrefixes {
			if prefix == nil {
				return Graph{}, fmt.Errorf("subjectdata: %q declares a nil object prefix at "+
					"%d; it would panic on the first erasure rather than at startup",
					f.Module, i)
			}
		}

		// A field may have SEVERAL writing modules, and that is not a mistake.
		//
		// `email` is written by identity at registration and by workspace when an
		// invitation is issued to somebody who has no account yet — workspace mints
		// a fresh pseudonym for them and stores their address under it. An
		// exclusivity rule here would refuse that, and refusing it would encode an
		// invariant this system does not have: erasure destroys a subject's KEY, so
		// every field of that subject dies at once regardless of who wrote which.
		//
		// What the declaration buys is the answer to "who puts personal data in the
		// vault", which is a question a controller has to be able to answer and
		// which nothing else in this codebase records.
		for _, field := range f.VaultFields {
			if field == "" {
				return Graph{}, fmt.Errorf("subjectdata: %q declares an empty vault field",
					f.Module)
			}
			if slices.Contains(writersOf[field], f.Module) {
				return Graph{}, fmt.Errorf("subjectdata: %q declares the vault field %q "+
					"twice", f.Module, field)
			}
			writersOf[field] = append(writersOf[field], f.Module)
		}
		for _, reservation := range f.Reservations {
			if reservation == "" {
				return Graph{}, fmt.Errorf("subjectdata: %q declares an empty reservation",
					f.Module)
			}
			if owner, taken := ownerOfReservation[reservation]; taken {
				return Graph{}, fmt.Errorf("subjectdata: %s and %s both claim the reservation "+
					"%q; a reservation has one holder, because exactly one module releases "+
					"it on erasure", owner, f.Module, reservation)
			}
			ownerOfReservation[reservation] = f.Module
		}
	}

	sorted := make([]Fragment, len(fragments))
	copy(sorted, fragments)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Module < sorted[j].Module })
	for field := range writersOf {
		sort.Strings(writersOf[field])
	}
	return Graph{fragments: sorted, writersOf: writersOf}, nil
}

// Prefixes is every object-store namespace this subject's data lives under.
//
// THE traversal, and the only one that walks rather than declares. Both erasure
// and export call it, which is what makes compliance.md §16's "export and
// erasure traverse the same subject graph" true by construction rather than by
// two lists that a test compares.
func (g Graph) Prefixes(subjectID string) []string {
	out := make([]string, 0, len(g.fragments))
	for _, f := range g.fragments {
		for _, prefix := range f.ObjectPrefixes {
			out = append(out, prefix(subjectID))
		}
	}
	return out
}

// VaultFields is every field any module declares it writes, sorted.
//
// The completeness gate reads this and compares it against the vault's own
// definitions. It is not a work list — see Fragment.VaultFields.
func (g Graph) VaultFields() []string {
	out := []string{}
	for _, f := range g.fragments {
		out = append(out, f.VaultFields...)
	}
	sort.Strings(out)
	return out
}

// Reservations is every identifier reservation any module declares, sorted.
func (g Graph) Reservations() []string {
	out := []string{}
	for _, f := range g.fragments {
		out = append(out, f.Reservations...)
	}
	sort.Strings(out)
	return out
}

// Modules names the declaring modules, sorted. For the startup log line: a
// traversal covering fewer modules than somebody expects is otherwise invisible.
func (g Graph) Modules() []string {
	out := make([]string, 0, len(g.fragments))
	for _, f := range g.fragments {
		out = append(out, f.Module)
	}
	return out
}

// WritersOf names every module that declares it writes a vault field, sorted.
//
// Empty for a field nothing claims — which is what the completeness gate looks
// for. A field the vault defines, that a subject access request will therefore
// answer for, and that no module admits to writing is one of two things: a
// field nothing writes (dead vocabulary a DSAR still enumerates), or a writer
// that never declared itself. The gate cannot tell them apart and does not try;
// it makes somebody say which.
func (g Graph) WritersOf(field string) []string {
	out := make([]string, len(g.writersOf[field]))
	copy(out, g.writersOf[field])
	return out
}
