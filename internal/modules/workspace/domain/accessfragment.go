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
				//
				// A TEAM's members can hold it too, and that entry is the whole
				// economics of teams: `{Type: "team", Relation: "member"}` makes
				// `team:eng#member` a valid subject, so granting to a team of any
				// size costs ONE tuple. access.md §4 measured it and §6 confirmed
				// it holds at the latency level as well — a check through a
				// thousand-member team costs 2.1 ms against a direct grant's
				// 2.0 ms.
				//
				// It is declared here, on workspace, rather than waiting for the
				// first feature that shares something. A team that cannot be
				// granted anything is not a grantable subject, and the type would
				// then have to be added to the model later — which is a model
				// deploy, not a code change.
				{
					Name: "member",
					Direct: []model.TypeRef{
						{Type: "user"},
						{Type: "team", Relation: "member"},
					},
					Implies: []string{"admin"},
				},
			},
		}, {
			// A team is a GRANTABLE SUBJECT and nothing else. It has one
			// relation, and deliberately: everything a team is for happens on the
			// other side of a grant, where `team:x#member` appears as the subject.
			//
			// # Flat, never nested
			//
			// `member` admits users and NOT `{Type: "team", Relation: "member"}`.
			// The engine would model that happily, and the reason to refuse it is
			// not technical: nesting makes effective membership non-obvious to the
			// people managing it — "who is actually in this team" stops being
			// answerable by looking — and that is the problem teams exist to solve
			// (workspace.md §6).
			//
			// # No `parent` edge to the workspace
			//
			// A team is not a container and nothing is stored in it, so there is
			// nothing for a workspace admin to inherit THROUGH it. Who may manage
			// a team is decided by its maintainer roster in the aggregate, which
			// is where workspace.md §6 puts it: maintainers manage membership
			// without being workspace admins, and an inherited `admin` relation
			// here would quietly make every workspace admin a maintainer.
			Name: "team",
			Relations: []model.Relation{
				{Name: "member", Direct: []model.TypeRef{{Type: "user"}}},
			},
		}},
	}
}
