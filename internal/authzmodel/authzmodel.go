// Package authzmodel is the composition root for the authorization model.
//
// # Why this is not part of the access module
//
// `access` assembles fragments and must not know which modules exist — that is
// ADR-006, and it is what keeps "add a resource type" from meaning "edit the
// access module". Something has to name the fragments, though, and that
// something is a composition root: the same role cmd/api plays for services.
//
// Keeping it here rather than inside the tool that deploys the model means the
// list has ONE definition. A tool with its own list and a server with another is
// how a type ends up in the deployed model and not in the checked-in artefact,
// or the reverse.
package authzmodel

import (
	"fmt"

	identitydomain "github.com/chronos/chronos-go/internal/modules/identity/domain"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/authz/model"
)

// Fragments is every module's contribution, in one place.
//
// A module that owns a resource type appears here. A module that owns none —
// notification and profile both act on the caller's own subject — does not, and
// adding an empty fragment for them would suggest they have something to say.
func Fragments() []model.Fragment {
	return []model.Fragment{
		identitydomain.AccessFragment(),
		orgdomain.AccessFragment(),
	}
}

// Assemble builds the model this build deploys.
func Assemble() (model.Model, error) {
	m, err := model.Assemble(Fragments())
	if err != nil {
		return model.Model{}, fmt.Errorf("assembling the authorization model: %w", err)
	}
	return m, nil
}
