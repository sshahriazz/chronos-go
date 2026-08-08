package errs_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/errs"
)

// The guarantee behind CONVENTIONS §7.1: docs cannot drift from behaviour.
// Declaring a new Reason without documenting it fails the build.
func TestCatalogue_CoversEveryDeclaredReason(t *testing.T) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "errs.go", nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse errs.go: %v", err)
	}

	declared := map[string]bool{}
	ast.Inspect(f, func(n ast.Node) bool {
		vs, ok := n.(*ast.ValueSpec)
		if !ok {
			return true
		}
		id, ok := vs.Type.(*ast.Ident)
		if !ok || id.Name != "Reason" {
			return true
		}
		for _, name := range vs.Names {
			declared[name.Name] = true
		}
		return true
	})
	if len(declared) == 0 {
		t.Fatal("found no Reason constants — the AST walk is broken, not the catalogue")
	}

	documented := map[errs.Reason]bool{}
	for _, d := range errs.Catalogue() {
		documented[d.Reason] = true
	}

	byValue := map[string]errs.Reason{
		"Unauthenticated": errs.Unauthenticated, "StepUpRequired": errs.StepUpRequired,
		"AccessDenied": errs.AccessDenied, "PlanUpgradeRequired": errs.PlanUpgradeRequired,
		"QuotaExceeded": errs.QuotaExceeded, "OrgSuspended": errs.OrgSuspended,
		"NotFound": errs.NotFound, "Conflict": errs.Conflict,
		"ValidationFailed": errs.ValidationFailed, "RateLimited": errs.RateLimited,
		"Internal": errs.Internal,
	}
	for name := range declared {
		r, known := byValue[name]
		if !known {
			t.Errorf("Reason %s is declared but not wired into this test's map — add it, then document it", name)
			continue
		}
		if !documented[r] {
			t.Errorf("Reason %s (%q) is declared but missing from Catalogue(); it would ship undocumented", name, r)
		}
	}
}

func TestCatalogue_EntriesAreComplete(t *testing.T) {
	for _, d := range errs.Catalogue() {
		if d.Meaning == "" || d.ClientShould == "" || d.ConnectCode == "" || d.HTTPStatus == 0 {
			t.Errorf("%s: every field is part of the published contract, got %+v", d.Reason, d)
		}
	}
}

// The distinction the whole taxonomy exists for.
func TestCatalogue_AccessAndPlanGiveOppositeAdvice(t *testing.T) {
	var access, plan errs.Doc
	for _, d := range errs.Catalogue() {
		switch d.Reason {
		case errs.AccessDenied:
			access = d
		case errs.PlanUpgradeRequired:
			plan = d
		}
	}
	if access.ClientShould == plan.ClientShould {
		t.Fatal("ACCESS_DENIED and PLAN_UPGRADE_REQUIRED must give different client guidance")
	}
}
