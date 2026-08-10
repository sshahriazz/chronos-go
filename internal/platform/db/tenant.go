// Package db is the tenant-scoped access path to the read model (ADR-011).
//
// One rule governs everything here:
//
//	Every query runs inside a transaction that begins by setting the tenant
//	context with SET LOCAL — reads included.
//
// SET LOCAL is scoped to the transaction and cannot outlive it. Plain SET would
// persist on the pooled connection and be inherited by whoever borrows it next,
// which is a cross-tenant data breach rather than a style preference.
package db

import (
	"context"
	"errors"
	"fmt"
)

// Tenant is the scope every query is evaluated in. It is set once by the
// org-context interceptor and read by the query engine; nothing else may
// construct one mid-request.
type Tenant struct {
	OrgID       string
	WorkspaceID string
	UserID      string
	Residency   string
}

var (
	// ErrNoTenant is returned when a tenant-scoped query is attempted without a
	// scope. It is deliberately an error and not a default: a query that
	// silently runs unscoped is the failure this package exists to prevent.
	ErrNoTenant = errors.New("db: no tenant in context")

	ErrIncompleteTenant = errors.New("db: tenant is missing a required field")
)

// Validate reports whether the scope is usable. WorkspaceID may be empty for
// org-level work; OrgID never may.
func (t Tenant) Validate() error {
	if t.OrgID == "" {
		return fmt.Errorf("%w: org_id", ErrIncompleteTenant)
	}
	return nil
}

func (t Tenant) IsZero() bool { return t == Tenant{} }

type tenantKey struct{}

// WithTenant returns a context carrying the scope. Called by the org-context
// interceptor (ADR-021), not by handlers.
func WithTenant(ctx context.Context, t Tenant) context.Context {
	return context.WithValue(ctx, tenantKey{}, t)
}

// TenantFrom extracts the scope, reporting whether one was present.
func TenantFrom(ctx context.Context) (Tenant, bool) {
	t, ok := ctx.Value(tenantKey{}).(Tenant)
	return t, ok
}

// RequireTenant extracts the scope or fails. This is what the query engine
// calls, so an unscoped query cannot reach the database.
func RequireTenant(ctx context.Context) (Tenant, error) {
	t, ok := TenantFrom(ctx)
	if !ok {
		return Tenant{}, ErrNoTenant
	}
	if err := t.Validate(); err != nil {
		return Tenant{}, err
	}
	return t, nil
}
