//go:build integration

package postgres_test

import (
	"context"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	orgpg "github.com/chronos/chronos-go/internal/modules/organization/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/organization/app"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	// chronos_app, never the owner: the owner bypasses RLS entirely, and a test
	// that runs as one proves nothing about what the application can see.
	// org_status_view carries `tenant_isolation`, so the role is the whole point
	// of this file.
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func pool(t *testing.T) *pgxpool.Pool {
	t.Helper()
	p, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(p.Close)
	return p
}

func freshOrgID() string {
	return ids.New[ids.Org](time.Now(), ids.Entropy()).String()
}

// seedStatus writes a row the way the PROJECTOR does — through the same
// generated statement, under a tenant scope.
func seedStatus(t *testing.T, tx db.TX, orgID string, status domain.Status) {
	t.Helper()
	ctx := db.WithTenant(t.Context(), db.Tenant{OrgID: orgID, UserID: "sub_alice"})
	err := tx.InTenantTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, organizationdb.UpsertOrgStatus,
			orgID, string(status), nil, "sub_stripe_1", time.Now().UTC())
		return err
	})
	if err != nil {
		t.Fatalf("seeding %s: %v", status, err)
	}
}

// The status a projector writes is the status gate 3 reads.
func TestTheStatusReaderReadsWhatTheProjectionWrote(t *testing.T) {
	tx := pgadapter.New(pool(t))
	reader, err := orgpg.NewStatusReader(tx)
	if err != nil {
		t.Fatalf("NewStatusReader: %v", err)
	}

	for _, status := range []domain.Status{
		domain.StatusProvisioning, domain.StatusTrialing, domain.StatusActive,
		domain.StatusPastDue, domain.StatusSuspended, domain.StatusClosed,
	} {
		t.Run(status.String(), func(t *testing.T) {
			orgID := freshOrgID()
			seedStatus(t, tx, orgID, status)

			ctx := db.WithTenant(t.Context(), db.Tenant{OrgID: orgID, UserID: "sub_alice"})
			got, err := reader.StatusOf(ctx, orgID)
			if err != nil {
				t.Fatalf("StatusOf: %v", err)
			}
			if got != status {
				t.Errorf("read back %q, want %q", got, status)
			}
		})
	}
}

// ROW SECURITY: one organization cannot read another's subscription status.
//
// # Why this is worth a test of its own
//
// The status is the answer to "may this tenant act", and it is the last answer
// that should be reachable across a tenant boundary. The query filters on
// org_id, so it would appear correct with the policy removed — WHERE and the
// policy say the same thing, which is precisely why the policy is what holds
// when somebody forgets the predicate.
//
// So this reads with the SCOPE of one organization and the ID of another. That
// is the shape a forged or leaked org id takes, and RLS is the only thing
// standing in its way.
func TestAnotherOrganizationsStatusIsInvisible(t *testing.T) {
	tx := pgadapter.New(pool(t))
	reader, err := orgpg.NewStatusReader(tx)
	if err != nil {
		t.Fatalf("NewStatusReader: %v", err)
	}

	victim := freshOrgID()
	attacker := freshOrgID()
	seedStatus(t, tx, victim, domain.StatusActive)
	seedStatus(t, tx, attacker, domain.StatusSuspended)

	// Scoped as the attacker, asking about the victim.
	ctx := db.WithTenant(t.Context(), db.Tenant{OrgID: attacker, UserID: "sub_mallory"})
	got, err := reader.StatusOf(ctx, victim)
	if err == nil {
		t.Fatalf("a suspended organization read an ACTIVE one's status (%q) by naming its "+
			"id. Row security is not holding, and the answer to \"may this tenant act\" is "+
			"reachable across a tenant boundary", got)
	}
	if got != domain.StatusUnknown {
		t.Errorf("the failed read returned %q rather than the fail-closed zero value", got)
	}
}

// End to end: a seeded status drives gate 3's real decision.
//
// The unit tests assert the matrix against a stub. This asserts the same rules
// through the adapter, the transaction, the policy and the generated SQL — so a
// status that round-trips wrongly (a typo in a constant, a column of the wrong
// type) shows up as the wrong ENFORCEMENT rather than as a wrong string.
func TestGateThreeEnforcesAgainstTheRealProjection(t *testing.T) {
	tx := pgadapter.New(pool(t))
	reader, err := orgpg.NewStatusReader(tx)
	if err != nil {
		t.Fatalf("NewStatusReader: %v", err)
	}
	gate, err := app.NewSubscriptionGate(reader)
	if err != nil {
		t.Fatalf("NewSubscriptionGate: %v", err)
	}

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
		{domain.StatusProvisioning, domain.ClassWrite, false},
	} {
		t.Run(tc.status.String()+"/"+string(tc.class), func(t *testing.T) {
			orgID := freshOrgID()
			seedStatus(t, tx, orgID, tc.status)
			ctx := db.WithTenant(t.Context(), db.Tenant{OrgID: orgID, UserID: "sub_alice"})

			err := gate.Permit(ctx, tc.class)
			if tc.allowed && err != nil {
				t.Errorf("%s during %s was refused: %v", tc.class, tc.status, err)
			}
			if !tc.allowed && err == nil {
				t.Errorf("%s during %s was permitted", tc.class, tc.status)
			}
		})
	}
}

// An organization the projection has never seen is REFUSED, not waved through.
//
// This is the fail-closed path with a real database behind it: no row, so no
// status, so no permission. A gate that treated a missing row as StatusUnknown
// and StatusUnknown as "no restriction" would let every unprojected
// organization do anything.
func TestAnUnprojectedOrganizationIsRefused(t *testing.T) {
	tx := pgadapter.New(pool(t))
	reader, err := orgpg.NewStatusReader(tx)
	if err != nil {
		t.Fatalf("NewStatusReader: %v", err)
	}
	gate, err := app.NewSubscriptionGate(reader)
	if err != nil {
		t.Fatalf("NewSubscriptionGate: %v", err)
	}

	orgID := freshOrgID() // never seeded
	ctx := db.WithTenant(t.Context(), db.Tenant{OrgID: orgID, UserID: "sub_alice"})

	got := gate.Permit(ctx, domain.ClassRead)
	if got == nil {
		t.Fatal("an organization with no row in org_status_view was permitted to read; a " +
			"projection that has not caught up would grant every new tenant everything")
	}
	if reason := errs.ReasonOf(got); reason != errs.OrgSuspended {
		t.Errorf("the refusal carries reason %q, want %q", reason, errs.OrgSuspended)
	}
}
