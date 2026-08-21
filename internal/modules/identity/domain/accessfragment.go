package domain

import "github.com/chronos/chronos-go/internal/platform/authz/model"

// AccessFragment is identity's contribution to the authorization model.
//
// # Why identity owns `user` and nothing else owns it
//
// ADR-006 requires the module that owns a resource to declare its type, so that
// `access` never learns what any of them are. `user` is the subject of every
// grant in the system and identity is what a user IS, so it is declared here.
//
// It has NO relations, and that is a statement rather than an omission. Every
// authorization declaration in this service is `self` on `user` (22 of 22), and
// a self check is answered locally from the authenticated principal — enforce
// returns at `p.SelfScoped()` before OpenFGA is consulted at all. So no tuple
// naming a user as an object is ever written, and a relation here would be one
// nothing could hold.
//
// A `user` type with no relations is still required. It is the type every other
// fragment names in its `Direct` references — `owner: [user]` — and a reference
// to a type the model does not define is rejected at assembly.
func AccessFragment() model.Fragment {
	return model.Fragment{
		Module: "identity",
		Types:  []model.Type{{Name: "user"}},
	}
}
