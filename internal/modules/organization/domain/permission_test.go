package domain_test

import (
	"strings"
	"testing"

	"github.com/chronos/chronos-go/internal/modules/organization/domain"
)

// EVERY cell of the operation-class × status matrix.
//
// organization.md §13 asks for this by name: "the operation-class × status
// matrix as an exhaustive table test — this is the payment enforcement contract
// and deserves every cell asserted."
//
// The expectation below is transcribed from organization.md §5.2 and written
// INDEPENDENTLY of the table in permission.go. Deriving it from the map under
// test would make the two agree by construction and assert nothing at all —
// which is the trap a table-driven test of a table invites.
//
// Provisioning takes the shape §5.2 gives Pending: the org exists, is not yet
// usable, and can already pay.
func TestTheOperationClassMatrix(t *testing.T) {
	t.Parallel()

	// nil means "denies everything", which is what an unknown status must do.
	want := map[domain.Status]map[domain.OperationClass]bool{
		domain.StatusUnknown: nil,
		domain.StatusProvisioning: {
			domain.ClassRead: true, domain.ClassWrite: false, domain.ClassGrow: false,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: false,
		},
		domain.StatusTrialing: {
			domain.ClassRead: true, domain.ClassWrite: true, domain.ClassGrow: true,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: true,
		},
		domain.StatusActive: {
			domain.ClassRead: true, domain.ClassWrite: true, domain.ClassGrow: true,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: true,
		},
		domain.StatusPastDue: {
			domain.ClassRead: true, domain.ClassWrite: true, domain.ClassGrow: false,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: true,
		},
		domain.StatusSuspended: {
			domain.ClassRead: true, domain.ClassWrite: false, domain.ClassGrow: false,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: true,
		},
		domain.StatusClosed: {
			domain.ClassRead: true, domain.ClassWrite: false, domain.ClassGrow: false,
			domain.ClassBillingView: true, domain.ClassBillingManage: true,
			domain.ClassExport: true,
		},
	}

	cells := 0
	for _, status := range domain.Statuses() {
		for _, class := range domain.OperationClasses() {
			if class == domain.ClassUnknown {
				continue // asserted separately below
			}
			cells++
			t.Run(status.String()+"/"+string(class), func(t *testing.T) {
				got := status.Permits(class)
				if got != want[status][class] {
					t.Errorf("%s during %s: got permitted=%t, want %t (organization.md §5.2)",
						class, status, got, want[status][class])
				}
			})
		}
	}
	// 7 statuses — the six real ones plus StatusUnknown, whose row is nil and
	// must therefore deny every class — times 6 classes.
	if want, got := len(domain.Statuses())*(len(domain.OperationClasses())-1), cells; got != want {
		t.Errorf("asserted %d cells, want %d. A status or class was added without a row "+
			"here, and the new combination is untested", got, want)
	}
}

// Neither billing class is EVER blocked, in any status.
//
// Stated as its own test because it is a commercial rule rather than a
// mechanical one, and the cost of breaking it is invisible in code review:
// locking a past-due customer out of the page where they would pay you is
// self-inflicted revenue loss, and the tenant most likely to hit it is the one
// you most want to keep.
func TestBillingIsNeverBlocked(t *testing.T) {
	t.Parallel()

	for _, status := range domain.Statuses() {
		if status == domain.StatusUnknown {
			continue // an unloaded organization denies everything, by design
		}
		for _, class := range []domain.OperationClass{
			domain.ClassBillingView, domain.ClassBillingManage,
		} {
			if !status.Permits(class) {
				t.Errorf("%s is blocked while %s. The customer cannot reach the page where "+
					"they would fix the very problem that blocked them", class, status)
			}
		}
	}
}

// Export is never blocked once there is anything to export.
//
// Withholding a suspended tenant's own data is a GDPR portability violation, not
// leverage.
func TestExportIsNeverBlockedOnceThereIsDataToExport(t *testing.T) {
	t.Parallel()

	for _, status := range []domain.Status{
		domain.StatusTrialing, domain.StatusActive, domain.StatusPastDue,
		domain.StatusSuspended, domain.StatusClosed,
	} {
		if !status.Permits(domain.ClassExport) {
			t.Errorf("export is blocked while %s; withholding a tenant's own data is a "+
				"portability violation, not leverage", status)
		}
	}
}

// Growth is blocked before writing, never after.
//
// The ordering is the whole point: stop them adding seats before you stop them
// working. A status that blocks writes while still allowing growth has the
// escalation backwards and lets a non-paying tenant keep consuming quota.
func TestGrowthIsBlockedBeforeWriting(t *testing.T) {
	t.Parallel()

	for _, status := range domain.Statuses() {
		if status.Permits(domain.ClassGrow) && !status.Permits(domain.ClassWrite) {
			t.Errorf("%s permits grow but refuses write; the escalation is backwards and a "+
				"tenant who cannot work can still consume quota", status)
		}
	}
}

// An unknown status and an unknown class both deny.
func TestTheZeroValuesDeny(t *testing.T) {
	t.Parallel()

	for _, class := range domain.OperationClasses() {
		if domain.StatusUnknown.Permits(class) {
			t.Errorf("an organization whose status was never loaded permits %s; a failed "+
				"read would grant the tenant everything (ADR-010)", class)
		}
	}
	for _, status := range domain.Statuses() {
		if status.Permits(domain.ClassUnknown) {
			t.Errorf("%s permits an RPC that declared no operation class; an undeclared "+
				"class would be treated as a read", status)
		}
	}
}

// The refusal says what happened and what to do about it.
func TestTheRefusalIsActionable(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		status domain.Status
		want   string
	}{
		{domain.StatusPastDue, "payment method"},
		{domain.StatusSuspended, "adding a payment method"},
		{domain.StatusClosed, "closed"},
		{domain.StatusProvisioning, "still being set up"},
	} {
		err := tc.status.SubscriptionError(domain.ClassGrow)
		if err == nil {
			t.Fatalf("%s produced no error", tc.status)
		}
		if !strings.Contains(err.Error(), tc.want) {
			t.Errorf("the refusal for %s does not mention %q, so the customer has to open a "+
				"support ticket to learn what a machine already knows: %v",
				tc.status, tc.want, err)
		}
	}
}
