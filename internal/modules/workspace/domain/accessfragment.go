package domain

import "github.com/chronos/chronos-go/internal/platform/authz/model"

// AccessFragment is workspace's contribution to the authorization model.
//
// It is workspace.md §3 and organization.md §5.1 expressed as types, declared
// here because ADR-006 requires the owning module to declare its own resource
// type — otherwise adding one means editing the access module and the dependency
// runs backwards.
//
// # `parent` is the whole topology
//
// One tuple links a workspace to its organization, and every org admin becomes
// an admin of that workspace — present and future, with no fan-out. It is why
// `admin` inherits rather than being written per person per workspace, which
// would be O(admins x workspaces) tuples and is the design this one was chosen
// over.
//
// The edge is deliberately BREAKABLE (ADR-027): deleting the parent tuple makes
// a workspace private to its own members. The guards on that live in the domain,
// because `access` must stay ignorant of what a workspace is.
func AccessFragment() model.Fragment {
	return model.Fragment{
		Module: "workspace",
		Types: []model.Type{{
			Name: "workspace",
			Relations: []model.Relation{
				// The organization this workspace hangs off. One tuple.
				{Name: "parent", Direct: []model.TypeRef{{Type: "organization"}}},

				// Direct admins, plus everyone who administers the organization.
				{
					Name:     "admin",
					Direct:   []model.TypeRef{{Type: "user"}},
					Inherits: []model.Inheritance{{Through: "parent", Relation: "admin"}},
				},

				// A member can see the workspace; an admin is one implicitly, so
				// no membership tuple is needed for them.
				{
					Name:    "member",
					Direct:  []model.TypeRef{{Type: "user"}},
					Implies: []string{"admin"},
				},
			},
		}},
	}
}
