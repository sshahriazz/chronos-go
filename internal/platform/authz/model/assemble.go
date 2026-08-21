package model

import (
	"fmt"
	"regexp"
	"slices"
	"sort"
	"strings"
)

// Model is the assembled result: every type, merged and ordered.
type Model struct {
	Types []Type
}

// nameRule is OpenFGA's own restriction on type and relation names.
//
// Checked here rather than discovered at deploy time, because a model rejected
// by the server is a deploy that fails after the fragments were already merged —
// and the error names the model, not the fragment that broke it.
var nameRule = regexp.MustCompile(`^[a-zA-Z0-9_][a-zA-Z0-9_-]*$`)

// Assemble merges fragments into one model, or explains what cannot be merged.
//
// # What it refuses, and why each refusal is worth a build failure
//
// The expensive failure this prevents is the one access.md §10 calls
// non-negotiable: a tuple naming a type absent from the pinned model is
// REJECTED by OpenFGA, the access projector starts failing, and it falls behind.
// That surfaces to a user as newly created resources being unreachable —
// "sometimes things do not appear" — which is about as far from its cause as a
// symptom can get.
//
// Every reference in a fragment is therefore resolved here, at build time,
// against the merged set. A relation pointing at a type no fragment defines is a
// compile-time-adjacent error with the module name attached, rather than a
// runtime rejection with a stack trace.
//
// Order is normalised — types by name, relations by name, references within a
// relation — so the same fragments always produce byte-identical output. That is
// what makes the assembled model diffable in review and lets a gate compare a
// checked-in artefact against the fragments that produced it.
func Assemble(fragments []Fragment) (Model, error) {
	owner := map[string]string{} // type name -> module that defined it
	merged := map[string]Type{}

	for _, f := range fragments {
		if f.Module == "" {
			return Model{}, fmt.Errorf("access: a fragment declares no module; the module name " +
				"is what makes a collision between two fragments diagnosable")
		}
		for _, t := range f.Types {
			if !nameRule.MatchString(t.Name) {
				return Model{}, fmt.Errorf("access: %s declares type %q, which is not a legal "+
					"OpenFGA type name", f.Module, t.Name)
			}
			if prev, taken := owner[t.Name]; taken {
				// Not merged. Two modules defining one type means neither owns
				// it, and silently unioning their relations would give a type
				// whose shape no single fragment describes.
				return Model{}, fmt.Errorf("access: %s and %s both define type %q; a type has "+
					"exactly one owning module (ADR-006)", prev, f.Module, t.Name)
			}
			owner[t.Name] = f.Module

			seen := map[string]bool{}
			for _, r := range t.Relations {
				if !nameRule.MatchString(r.Name) {
					return Model{}, fmt.Errorf("access: %s declares relation %q on type %q, "+
						"which is not a legal OpenFGA relation name", f.Module, r.Name, t.Name)
				}
				if seen[r.Name] {
					return Model{}, fmt.Errorf("access: %s declares relation %q on type %q "+
						"twice", f.Module, r.Name, t.Name)
				}
				seen[r.Name] = true

				if len(r.Direct) == 0 && len(r.Implies) == 0 && len(r.Inherits) == 0 {
					// A relation with no source can never be held by anyone, so
					// every check against it denies. That is a typo rather than
					// a decision — a deliberate always-deny needs no relation.
					return Model{}, fmt.Errorf("access: %s declares relation %q on type %q "+
						"with no way to hold it: no direct assignment, no implication and no "+
						"inheritance, so every check against it denies",
						f.Module, r.Name, t.Name)
				}
			}
			merged[t.Name] = t
		}
	}

	if len(merged) == 0 {
		return Model{}, fmt.Errorf("access: the assembled model has no types; every check " +
			"would be evaluated against nothing")
	}

	if err := resolve(merged, owner); err != nil {
		return Model{}, err
	}
	return Model{Types: normalise(merged)}, nil
}

// resolve checks that every reference names something the merged model defines.
func resolve(merged map[string]Type, owner map[string]string) error {
	relationsOf := func(typeName string) map[string]bool {
		out := map[string]bool{}
		for _, r := range merged[typeName].Relations {
			out[r.Name] = true
		}
		return out
	}

	for _, typeName := range sortedKeys(merged) {
		t := merged[typeName]
		here := relationsOf(typeName)
		mod := owner[typeName]

		for _, r := range t.Relations {
			for _, ref := range r.Direct {
				if _, ok := merged[ref.Type]; !ok {
					return fmt.Errorf("access: %s.%s may be assigned to type %q, which no "+
						"fragment defines. A tuple naming a type absent from the model is "+
						"REJECTED by OpenFGA, and the access projector then falls behind "+
						"(access.md §10)", typeName, r.Name, ref.Type)
				}
				if ref.Relation != "" && !relationsOf(ref.Type)[ref.Relation] {
					return fmt.Errorf("access: %s.%s may be assigned to %q, and type %q has "+
						"no relation %q", typeName, r.Name, ref.Type+"#"+ref.Relation,
						ref.Type, ref.Relation)
				}
				if ref.Relation != "" && ref.Wildcard {
					return fmt.Errorf("access: %s.%s names %q as both a userset and a "+
						"wildcard; they are different grants and it can only be one",
						typeName, r.Name, ref.Type)
				}
			}

			for _, implied := range r.Implies {
				if !here[implied] {
					return fmt.Errorf("access: %s.%s is implied by %q, which type %q does not "+
						"declare (%s)", typeName, r.Name, implied, typeName, mod)
				}
				if implied == r.Name {
					return fmt.Errorf("access: %s.%s implies itself", typeName, r.Name)
				}
			}

			for _, inh := range r.Inherits {
				if !here[inh.Through] {
					return fmt.Errorf("access: %s.%s inherits through %q, which type %q does "+
						"not declare (%s)", typeName, r.Name, inh.Through, typeName, mod)
				}
				// Every type the `through` relation can point at must carry the
				// relation being inherited, or the inheritance silently resolves
				// to nothing for that parent kind.
				for _, parent := range through(merged[typeName], inh.Through) {
					if !relationsOf(parent)[inh.Relation] {
						return fmt.Errorf("access: %s.%s inherits %q from %q, but %q — which "+
							"%q can point at — has no relation %q, so the inheritance "+
							"resolves to nothing",
							typeName, r.Name, inh.Relation, inh.Through, parent,
							inh.Through, inh.Relation)
					}
				}
			}
		}
	}
	return nil
}

// through returns the types a relation can point at.
func through(t Type, relation string) []string {
	for _, r := range t.Relations {
		if r.Name != relation {
			continue
		}
		var out []string
		for _, ref := range r.Direct {
			if !ref.Wildcard && ref.Relation == "" {
				out = append(out, ref.Type)
			}
		}
		return out
	}
	return nil
}

// normalise sorts everything, so identical fragments produce identical output.
func normalise(merged map[string]Type) []Type {
	out := make([]Type, 0, len(merged))
	for _, name := range sortedKeys(merged) {
		t := merged[name]
		relations := slices.Clone(t.Relations)
		sort.Slice(relations, func(i, j int) bool { return relations[i].Name < relations[j].Name })
		for i := range relations {
			refs := slices.Clone(relations[i].Direct)
			sort.Slice(refs, func(a, b int) bool { return refKey(refs[a]) < refKey(refs[b]) })
			relations[i].Direct = refs
			relations[i].Implies = sortedCopy(relations[i].Implies)
			inh := slices.Clone(relations[i].Inherits)
			sort.Slice(inh, func(a, b int) bool {
				return inh[a].Through+"/"+inh[a].Relation < inh[b].Through+"/"+inh[b].Relation
			})
			relations[i].Inherits = inh
		}
		out = append(out, Type{Name: name, Relations: relations})
	}
	return out
}

// refKey renders a TypeRef the way OpenFGA writes it, which is also a stable
// sort key: `user`, `team#member`, `user:*`.
func refKey(r TypeRef) string {
	switch {
	case r.Wildcard:
		return r.Type + ":*"
	case r.Relation != "":
		return r.Type + "#" + r.Relation
	default:
		return r.Type
	}
}

// String renders the assembled model in OpenFGA's DSL.
//
// Nothing parses this — the deployed model is built from the structs. It exists
// so a human reviewing a model change reads the language OpenFGA's own
// documentation is written in, rather than a diff of Go literals.
func (m Model) String() string {
	var b strings.Builder
	b.WriteString("model\n  schema 1.1\n")
	for _, t := range m.Types {
		fmt.Fprintf(&b, "\ntype %s\n", t.Name)
		if len(t.Relations) == 0 {
			continue
		}
		b.WriteString("  relations\n")
		for _, r := range t.Relations {
			fmt.Fprintf(&b, "    define %s: %s\n", r.Name, clause(r))
		}
	}
	return b.String()
}

func clause(r Relation) string {
	var parts []string
	if len(r.Direct) > 0 {
		refs := make([]string, 0, len(r.Direct))
		for _, ref := range r.Direct {
			refs = append(refs, refKey(ref))
		}
		parts = append(parts, "["+strings.Join(refs, ", ")+"]")
	}
	parts = append(parts, r.Implies...)
	for _, inh := range r.Inherits {
		parts = append(parts, inh.Relation+" from "+inh.Through)
	}
	return strings.Join(parts, " or ")
}

func sortedKeys[V any](m map[string]V) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sortedCopy(in []string) []string {
	if in == nil {
		return nil
	}
	out := slices.Clone(in)
	sort.Strings(out)
	return out
}
