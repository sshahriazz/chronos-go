package domain

import "github.com/chronos/chronos-go/internal/platform/authz/model"

// AccessFragment is organization's contribution to the authorization model.
//
// It is organization.md §5.1 expressed as types, and it is declared HERE rather
// than in the access module because ADR-006 requires the owning module to
// declare its own resource type — otherwise adding one means editing access, and
// the dependency runs backwards.
//
// # The billing split is the part worth reading twice
//
// `billing_manager` resolves to the OWNER ALONE, while `billing_viewer` includes
// every admin. That asymmetry is deliberate and is ADR-027: an org admin may see
// spend, invoices and the plan in every lifecycle state, and may change what the
// company is committed to in none of them. Billing is the one authority an admin
// does not inherit.
//
// Both relations are COMPUTED — neither has a Direct list — so no tuple ever
// grants them. They are derived from owner and admin, which means there is no
// way to grant somebody billing access without granting the underlying role, and
// no way for the two to drift apart.
func AccessFragment() model.Fragment {
	return model.Fragment{
		Module: "organization",
		Types: []model.Type{{
			Name: "organization",
			Relations: []model.Relation{
				// Exactly one holder, always (ADR-027). The cardinality is not
				// expressible in OpenFGA — the model would happily hold two
				// owner tuples — so it is the aggregate's invariant, and this
				// relation is only the graph's view of it.
				{Name: "owner", Direct: []model.TypeRef{{Type: "user"}}},

				// The owner administers by BEING the owner, which is why owner
				// implies admin rather than the projector writing both tuples.
				// Two tuples for one fact is two things to keep in step.
				{
					Name:    "admin",
					Direct:  []model.TypeRef{{Type: "user"}},
					Implies: []string{"owner"},
				},

				{Name: "billing_viewer", Implies: []string{"admin"}},
				{Name: "billing_manager", Implies: []string{"owner"}},
			},
		}},
	}
}
