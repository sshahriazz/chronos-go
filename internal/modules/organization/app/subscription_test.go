package app_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
)

type stubReader struct {
	status domain.Status
	err    error
}

func (s stubReader) StatusOf(context.Context, string) (domain.Status, error) {
	return s.status, s.err
}

func scoped(t *testing.T) context.Context {
	t.Helper()
	return db.WithTenant(t.Context(), db.Tenant{
		OrgID:  "org_01ARZ3NDEKTSV4RRFFQ69G5FAV",
		UserID: "sub_alice",
	})
}

// An unreadable status REFUSES, and does not wave the request through.
//
// # Why this is the most important test in the file
//
// The failure it prevents is the one a billing system can least afford: a
// projection outage that silently lifts payment enforcement for every tenant at
// once. Nothing errors, nothing alarms, and suspended organizations quietly work
// again — a fail-open here is indistinguishable from a working system until the
// invoice run.
func TestAnUnreadableStatusFailsClosed(t *testing.T) {
	t.Parallel()

	gate, err := app.NewSubscriptionGate(stubReader{err: errors.New("read model unavailable")})
	if err != nil {
		t.Fatalf("NewSubscriptionGate: %v", err)
	}

	got := gate.Permit(scoped(t), domain.ClassWrite)
	if got == nil {
		t.Fatal("gate 3 permitted a write while it could not read the organization's status. " +
			"A projection outage now lifts payment enforcement for every tenant at once, " +
			"silently")
	}
	if reason := errs.ReasonOf(got); reason != errs.OrgSuspended {
		t.Errorf("the refusal carries reason %q, want %q", reason, errs.OrgSuspended)
	}
}

// Running without a tenant scope is OUR bug, and says so.
//
// It means the pipeline ran out of order — gate 3 executed without gate 1 having
// resolved an organization. Reported as ACCESS_DENIED it would send an operator
// to look at permissions for a wiring fault.
func TestNoTenantScopeIsInternal(t *testing.T) {
	t.Parallel()

	gate, err := app.NewSubscriptionGate(stubReader{status: domain.StatusActive})
	if err != nil {
		t.Fatalf("NewSubscriptionGate: %v", err)
	}

	got := gate.Permit(t.Context(), domain.ClassRead)
	if got == nil {
		t.Fatal("the gate ran with no tenant scope and permitted the request")
	}
	if reason := errs.ReasonOf(got); reason != errs.Internal {
		t.Errorf("a pipeline ordering fault is reported as %q, want %q — an operator would "+
			"go looking at the caller's permissions", reason, errs.Internal)
	}
}

// The gate applies the table, and the refusal is the table's own message.
func TestTheGateAppliesTheMatrix(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status  domain.Status
		class   domain.OperationClass
		allowed bool
	}{
		{domain.StatusActive, domain.ClassGrow, true},
		{domain.StatusPastDue, domain.ClassWrite, true},
		{domain.StatusPastDue, domain.ClassGrow, false},
		{domain.StatusSuspended, domain.ClassWrite, false},
		{domain.StatusSuspended, domain.ClassBillingManage, true},
		{domain.StatusSuspended, domain.ClassExport, true},
		{domain.StatusClosed, domain.ClassExport, true},
	} {
		t.Run(tc.status.String()+"/"+string(tc.class), func(t *testing.T) {
			gate, err := app.NewSubscriptionGate(stubReader{status: tc.status})
			if err != nil {
				t.Fatalf("NewSubscriptionGate: %v", err)
			}
			got := gate.Permit(scoped(t), tc.class)
			if tc.allowed && got != nil {
				t.Errorf("%s during %s was refused: %v", tc.class, tc.status, got)
			}
			if !tc.allowed {
				if got == nil {
					t.Fatalf("%s during %s was permitted", tc.class, tc.status)
				}
				if strings.TrimSpace(got.Error()) == "" {
					t.Error("the refusal carries no message for the customer")
				}
			}
		})
	}
}

// A gate built with no reader is refused at construction.
func TestAGateWithNoReaderIsRefused(t *testing.T) {
	t.Parallel()

	if _, err := app.NewSubscriptionGate(nil); err == nil {
		t.Fatal("a subscription gate with no status reader was constructed; it could only " +
			"fail open or fail closed, and neither is enforcement")
	}
}
