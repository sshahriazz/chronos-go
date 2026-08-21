// Package model is the authorization model, assembled from module fragments.
//
// # Why the model is assembled rather than written
//
// ADR-006 and access.md §10 both say the same thing: the authorization model is
// built from fragments each module contributes, and is never hand-edited as one
// file. That is not a style preference. `access` must not know what a workspace
// IS — the moment it does, adding a resource type means editing the access
// module, and the dependency runs the wrong way.
//
// So `organization` declares that an organization has an owner; `workspace`
// declares that a workspace hangs off one; and this package knows only how to
// put fragments together and refuse the combinations that cannot work.
//
// # Why these types rather than OpenFGA's
//
// The generated `fgav1` types describe the same thing, and a module could build
// them directly. It must not: `internal/modules/*/domain/**` may not import
// `gen/` at all, because a generated wire type is a DTO and never a domain type
// (ADR-007). A fragment is a statement about the domain — "a workspace inherits
// its organization's admins" — and belongs in that vocabulary.
//
// The translation to OpenFGA's wire form lives in the adapter, which is the only
// place that should know OpenFGA exists.
package model

// Fragment is one module's contribution to the authorization model.
//
// Module names the owner, and it exists for the error messages: when two
// fragments collide, "organization and workspace both define type `team`" is
// actionable and "duplicate type `team`" is not.
type Fragment struct {
	Module string
	Types  []Type
}

// Type is a node kind in the graph — `user`, `organization`, `workspace`.
type Type struct {
	Name      string
	Relations []Relation
}

// Relation is one edge kind on a type.
//
// The three fields are the three ways OpenFGA can grant a relation, and a
// relation may combine them — `admin: [user] or owner or admin from parent` is
// all three at once, which is exactly what organization.md §5.1 describes.
//
// Splitting them into named fields rather than exposing OpenFGA's `Userset`
// union is deliberate. The union admits shapes that are legal to construct and
// meaningless in this system, and a reviewer reading a fragment should be
// reading a sentence about the domain rather than a tree.
type Relation struct {
	Name string

	// Direct is who may be ASSIGNED this relation by a tuple.
	//
	// An empty Direct with a non-empty Implies or Inherits is a computed
	// relation: nobody is ever granted it, it is derived. `viewer` on a resource
	// whose only source is `editor` is the usual case.
	Direct []TypeRef

	// Implies names relations on the SAME object that confer this one.
	//
	// `viewer: ... or editor` — role implication encoded once in the model, so
	// no caller ever checks two relations and no caller can forget the second.
	Implies []string

	// Inherits reaches a relation on ANOTHER object, through a relation on this
	// one. This is the whole of the inheritance property: one tuple linking a
	// workspace to its organization makes every org admin an admin of that
	// workspace, present and future, with no fan-out.
	Inherits []Inheritance
}

// TypeRef names who can hold a relation directly.
//
// Three shapes, and the distinction matters at the graph level:
//
//	{Type: "user"}                      a user
//	{Type: "team", Relation: "member"}  every member of a team — ONE tuple,
//	                                    regardless of how large the team is
//	{Type: "user", Wildcard: true}      every user, i.e. a public grant
type TypeRef struct {
	Type     string
	Relation string
	Wildcard bool
}

// Inheritance is a relation reached through another object.
//
// Through is a relation on THIS type whose value is the other object —
// `workspace.parent` — and Relation is what to check on it. Read
// `{Through: "parent", Relation: "admin"}` as "admin from parent".
type Inheritance struct {
	Through  string
	Relation string
}
