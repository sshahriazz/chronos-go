package db_test

import (
	"context"
	"errors"
	"testing"

	"github.com/chronos/chronos-go/internal/platform/db"
)

func TestRequireTenant_FailsWithoutScope(t *testing.T) {
	if _, err := db.RequireTenant(context.Background()); !errors.Is(err, db.ErrNoTenant) {
		t.Fatalf("an unscoped context must be refused, got %v", err)
	}
}

func TestRequireTenant_FailsWithoutOrg(t *testing.T) {
	ctx := db.WithTenant(context.Background(), db.Tenant{WorkspaceID: "ws_1"})
	_, err := db.RequireTenant(ctx)
	if !errors.Is(err, db.ErrIncompleteTenant) {
		t.Fatalf("org_id is mandatory, got %v", err)
	}
}

func TestRequireTenant_AllowsOrgWithoutWorkspace(t *testing.T) {
	// Org-level work is legitimate: listing an org's workspaces, for instance.
	ctx := db.WithTenant(context.Background(), db.Tenant{OrgID: "org_1"})
	got, err := db.RequireTenant(ctx)
	if err != nil {
		t.Fatalf("org-only scope must be valid: %v", err)
	}
	if got.OrgID != "org_1" {
		t.Fatalf("got %+v", got)
	}
}

func TestTenantRoundTrip(t *testing.T) {
	want := db.Tenant{OrgID: "org_1", WorkspaceID: "ws_1", UserID: "usr_1", Residency: "eu"}
	got, ok := db.TenantFrom(db.WithTenant(context.Background(), want))
	if !ok || got != want {
		t.Fatalf("got %+v ok=%v want %+v", got, ok, want)
	}
}

func TestTenantFrom_AbsentIsNotAZeroValue(t *testing.T) {
	// The bool matters: a zero Tenant and no Tenant must be distinguishable, or
	// a missing scope silently becomes an empty one.
	if _, ok := db.TenantFrom(context.Background()); ok {
		t.Fatal("absent scope must report ok=false")
	}
}
