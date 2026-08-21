package model_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/authz/model"
)

// identityFragment is the minimum any model needs: somebody to be the subject.
func identityFragment() model.Fragment {
	return model.Fragment{Module: "identity", Types: []model.Type{{Name: "user"}}}
}

// orgFragment is organization.md §5.1, in fragment form.
func orgFragment() model.Fragment {
	return model.Fragment{
		Module: "organization",
		Types: []model.Type{{
			Name: "organization",
			Relations: []model.Relation{
				{Name: "owner", Direct: []model.TypeRef{{Type: "user"}}},
				{Name: "admin", Direct: []model.TypeRef{{Type: "user"}}, Implies: []string{"owner"}},
				{Name: "billing_manager", Implies: []string{"owner"}},
				{Name: "billing_viewer", Implies: []string{"admin"}},
			},
		}},
	}
}

// workspaceFragment hangs a workspace off an organization, which is the
// inheritance the whole topology turns on.
func workspaceFragment() model.Fragment {
	return model.Fragment{
		Module: "workspace",
		Types: []model.Type{{
			Name: "workspace",
			Relations: []model.Relation{
				{Name: "parent", Direct: []model.TypeRef{{Type: "organization"}}},
				{
					Name:     "admin",
					Direct:   []model.TypeRef{{Type: "user"}},
					Inherits: []model.Inheritance{{Through: "parent", Relation: "admin"}},
				},
			},
		}},
	}
}

func TestAssembleMergesFragments(t *testing.T) {
	t.Parallel()

	m, err := model.Assemble([]model.Fragment{
		workspaceFragment(), orgFragment(), identityFragment(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if len(m.Types) != 3 {
		t.Fatalf("merged %d types, want 3", len(m.Types))
	}
	// Sorted regardless of the order fragments arrived in.
	for i, want := range []string{"organization", "user", "workspace"} {
		if m.Types[i].Name != want {
			t.Errorf("type %d is %q, want %q", i, m.Types[i].Name, want)
		}
	}
}

// The assembled model does not depend on the order fragments are passed in.
//
// A model whose bytes change with argument order cannot be diffed in review and
// cannot be compared against a checked-in artefact, which is what the gate does.
// It would also produce a NEW model id on every deploy — and since checks pin a
// model id, that is a deploy with no change in it.
func TestAssemblyIsOrderIndependent(t *testing.T) {
	t.Parallel()

	a, err := model.Assemble([]model.Fragment{
		identityFragment(), orgFragment(), workspaceFragment(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	b, err := model.Assemble([]model.Fragment{
		workspaceFragment(), identityFragment(), orgFragment(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	if a.String() != b.String() {
		t.Errorf("the same fragments in a different order assembled differently:\n--- a\n%s\n--- b\n%s",
			a.String(), b.String())
	}
}

// A reference to a type no fragment defines is refused at BUILD time.
//
// This is the failure access.md §10 calls non-negotiable, caught early. A tuple
// naming a type absent from the pinned model is rejected by OpenFGA; the access
// projector then fails on that event and stops, and what a user sees is that
// newly created resources are unreachable. The cause and the symptom could not
// be further apart, so the check belongs where the mistake is made.
func TestAReferenceToAnUndefinedTypeIsRefused(t *testing.T) {
	t.Parallel()

	// workspace.parent points at `organization`, and organization is absent.
	_, err := model.Assemble([]model.Fragment{identityFragment(), workspaceFragment()})
	if err == nil {
		t.Fatal("a fragment referencing an undefined type assembled cleanly; the model would " +
			"deploy and every tuple naming that type would then be rejected at runtime")
	}
	for _, want := range []string{"organization", "no fragment defines"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not mention %q: %v", want, err)
		}
	}
}

// Inheritance that resolves to nothing is refused.
//
// `admin from parent` is silent when the parent type has no `admin`: OpenFGA
// evaluates it, finds nothing, and denies. Nothing errors, no tuple is rejected,
// and the only symptom is that an org admin is mysteriously not an admin of a
// workspace — the exact property the topology exists to provide.
func TestInheritanceThatResolvesToNothingIsRefused(t *testing.T) {
	t.Parallel()

	hollowOrg := model.Fragment{
		Module: "organization",
		Types: []model.Type{{
			Name:      "organization",
			Relations: []model.Relation{{Name: "owner", Direct: []model.TypeRef{{Type: "user"}}}},
		}},
	}
	_, err := model.Assemble([]model.Fragment{
		identityFragment(), hollowOrg, workspaceFragment(),
	})
	if err == nil {
		t.Fatal("workspace.admin inherits `admin` from an organization that has no `admin` " +
			"relation, and this assembled cleanly. Every org admin would silently fail to be " +
			"an admin of any workspace")
	}
	if !strings.Contains(err.Error(), "resolves to nothing") {
		t.Errorf("the error does not explain the silence: %v", err)
	}
}

func TestTwoModulesCannotOwnOneType(t *testing.T) {
	t.Parallel()

	_, err := model.Assemble([]model.Fragment{
		identityFragment(),
		{Module: "organization", Types: []model.Type{{Name: "team",
			Relations: []model.Relation{{Name: "member", Direct: []model.TypeRef{{Type: "user"}}}}}}},
		{Module: "workspace", Types: []model.Type{{Name: "team",
			Relations: []model.Relation{{Name: "maintainer", Direct: []model.TypeRef{{Type: "user"}}}}}}},
	})
	if err == nil {
		t.Fatal("two modules defined `team` and the fragments merged; the resulting type has " +
			"a shape neither fragment describes")
	}
	for _, want := range []string{"organization", "workspace", "team"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("the error does not name %q, so it is not actionable: %v", want, err)
		}
	}
}

// A relation nobody can ever hold is a typo, and it denies silently.
func TestARelationWithNoSourceIsRefused(t *testing.T) {
	t.Parallel()

	_, err := model.Assemble([]model.Fragment{
		identityFragment(),
		{Module: "organization", Types: []model.Type{{
			Name:      "organization",
			Relations: []model.Relation{{Name: "admin"}},
		}}},
	})
	if err == nil {
		t.Fatal("a relation with no direct assignment, no implication and no inheritance " +
			"assembled; every check against it denies and nothing says why")
	}
	if !strings.Contains(err.Error(), "every check against it denies") {
		t.Errorf("the error does not state the consequence: %v", err)
	}
}

func TestASelfImplicationIsRefused(t *testing.T) {
	t.Parallel()

	_, err := model.Assemble([]model.Fragment{
		identityFragment(),
		{Module: "organization", Types: []model.Type{{
			Name: "organization",
			Relations: []model.Relation{
				{Name: "admin", Direct: []model.TypeRef{{Type: "user"}}, Implies: []string{"admin"}},
			},
		}}},
	})
	if err == nil {
		t.Fatal("a relation implying itself assembled")
	}
}

// The DSL rendering is what a reviewer reads, so it has to be right.
func TestTheModelRendersAsOpenFGADSL(t *testing.T) {
	t.Parallel()

	m, err := model.Assemble([]model.Fragment{
		identityFragment(), orgFragment(), workspaceFragment(),
	})
	if err != nil {
		t.Fatalf("Assemble: %v", err)
	}
	got := m.String()
	for _, want := range []string{
		"model\n  schema 1.1",
		"type user",
		"define owner: [user]",
		"define admin: [user] or owner",
		"define billing_manager: owner",
		"define parent: [organization]",
		"define admin: [user] or admin from parent",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("the rendered model does not contain %q:\n%s", want, got)
		}
	}
}
