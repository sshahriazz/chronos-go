//go:build integration

package postgres_test

import (
	"context"
	"errors"
	"os"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/entitlement/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/entitlement/app"
	"github.com/chronos/chronos-go/internal/modules/entitlement/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

func appDSN() string {
	if v := os.Getenv("APP_DATABASE_URL"); v != "" {
		return v
	}
	// chronos_app, never the owner: quota_reservation carries RLS, and the owner
	// bypasses it entirely.
	return "postgres://chronos_app:chronos_app_dev_password@localhost:5432/chronos?sslmode=disable"
}

func reservations(t *testing.T) *postgres.Reservations {
	t.Helper()
	pool, err := pgxpool.New(context.Background(), appDSN())
	if err != nil {
		t.Fatalf("pool: %v", err)
	}
	t.Cleanup(pool.Close)

	adapter := pgadapter.New(pool)
	store, err := postgres.NewReservations(adapter, adapter)
	if err != nil {
		t.Fatalf("NewReservations: %v", err)
	}
	return store
}

func freshOrg() string {
	return ids.New[ids.Org](time.Now(), ids.Entropy()).String()
}

func scoped(t *testing.T, orgID string) context.Context {
	t.Helper()
	return db.WithTenant(t.Context(), db.Tenant{OrgID: orgID, UserID: "sub_alice"})
}

func reservation(orgID string, key domain.LimitKey) app.Reservation {
	return app.Reservation{
		ID:       ids.New[ids.Event](time.Now(), ids.Entropy()).String(),
		OrgID:    orgID,
		Limit:    key,
		ExpireAt: time.Now().UTC().Add(time.Minute),
	}
}

// TWO CONCURRENT RESERVATIONS FOR THE LAST UNIT: exactly one wins.
//
// # Why this is the only test that justifies the whole table
//
// entitlement.md §4 opens with the failure: "two admins inviting the last seat
// simultaneously both read `49 < 50` and both proceed". Every cheaper design —
// count then insert, a Valkey counter, a check in the handler — passes a
// sequential test and loses this one.
//
// It has to run against a real PostgreSQL, because what makes it work is
// `SELECT ... FOR UPDATE` serialising the two transactions. A fake store cannot
// exhibit that, and would report success while the property did not hold.
func TestTwoConcurrentReservationsForTheLastUnit(t *testing.T) {
	store := reservations(t)
	orgID := freshOrg()
	ctx := scoped(t, orgID)

	const limit = 1 // the last unit is the only unit

	var wg sync.WaitGroup
	results := make([]error, 2)
	start := make(chan struct{})

	for i := range results {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start // release both at once
			results[i] = store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), limit)
		}(i)
	}
	close(start)
	wg.Wait()

	won := 0
	for _, err := range results {
		if err == nil {
			won++
			continue
		}
		if !errors.Is(err, app.ErrQuotaExhausted) {
			t.Errorf("the loser failed with %v, want a quota-exhausted error a customer can "+
				"act on", err)
		}
	}
	if won != 1 {
		t.Fatalf("%d of 2 concurrent reservations succeeded for a limit of 1, want exactly 1. "+
			"With 2 the customer got more than they paid for and the counter is now wrong; "+
			"with 0 a request that should have been served was refused.\nresults: %v",
			won, results)
	}
}

// A held reservation counts against the limit exactly as a committed one does.
//
// That is the point of holding it. If only committed rows counted, the window
// between reserve and commit would be wide open — which is the window the
// protocol exists to close.
func TestAHeldReservationCountsAgainstTheLimit(t *testing.T) {
	store := reservations(t)
	orgID := freshOrg()
	ctx := scoped(t, orgID)

	if err := store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), 1); err != nil {
		t.Fatalf("the first reservation was refused: %v", err)
	}
	// NOT committed. A second must still be refused.
	err := store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), 1)
	if !errors.Is(err, app.ErrQuotaExhausted) {
		t.Fatalf("a second reservation succeeded while the first was merely HELD (%v). The "+
			"window between reserve and commit is open, which is the window the whole "+
			"protocol exists to close", err)
	}
}

// Releasing returns the unit; committing does not.
func TestReleaseReturnsTheUnitAndCommitDoesNot(t *testing.T) {
	store := reservations(t)

	t.Run("released", func(t *testing.T) {
		orgID := freshOrg()
		ctx := scoped(t, orgID)
		first := reservation(orgID, domain.WorkspacesCount)

		if err := store.Reserve(ctx, first, 1); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		if err := store.Release(ctx, first.ID); err != nil {
			t.Fatalf("Release: %v", err)
		}
		if err := store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), 1); err != nil {
			t.Errorf("the unit was not returned to the pool after release: %v", err)
		}
	})

	t.Run("committed", func(t *testing.T) {
		orgID := freshOrg()
		ctx := scoped(t, orgID)
		first := reservation(orgID, domain.WorkspacesCount)

		if err := store.Reserve(ctx, first, 1); err != nil {
			t.Fatalf("Reserve: %v", err)
		}
		committed, err := store.Commit(ctx, first.ID)
		if err != nil || !committed {
			t.Fatalf("Commit: committed=%t err=%v", committed, err)
		}
		// The gate defers release after EVERY request, so this runs on the happy
		// path too. It must not undo the commit.
		if err := store.Release(ctx, first.ID); err != nil {
			t.Fatalf("Release after commit: %v", err)
		}
		if err := store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), 1); err == nil {
			t.Error("releasing a COMMITTED reservation returned its unit to the pool. The " +
				"gate defers release unconditionally, so every successful request would " +
				"give back the quota it just consumed")
		}
	})
}

// An expired reservation stops counting, and cannot be committed afterwards.
//
// The unit it held went back to the pool and may already be taken; resurrecting
// it would hand out the same unit twice.
func TestAnExpiredReservationStopsCounting(t *testing.T) {
	store := reservations(t)
	orgID := freshOrg()
	ctx := scoped(t, orgID)

	stale := reservation(orgID, domain.WorkspacesCount)
	stale.ExpireAt = time.Now().UTC().Add(-time.Minute) // already lapsed

	if err := store.Reserve(ctx, stale, 1); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	if err := store.Reserve(ctx, reservation(orgID, domain.WorkspacesCount), 1); err != nil {
		t.Errorf("an EXPIRED reservation is still counting against the limit: %v", err)
	}
	committed, err := store.Commit(ctx, stale.ID)
	if err != nil {
		t.Fatalf("Commit: %v", err)
	}
	if committed {
		t.Error("an expired reservation was committed; the unit it held had already been " +
			"returned to the pool and handed to somebody else")
	}
}

// Separate limits are separate pools (ADR-027).
//
// Exhausting guest seats must never block hiring.
func TestLimitsDoNotShareAPool(t *testing.T) {
	store := reservations(t)
	orgID := freshOrg()
	ctx := scoped(t, orgID)

	if err := store.Reserve(ctx, reservation(orgID, domain.SeatsGuest), 1); err != nil {
		t.Fatalf("reserving a guest seat: %v", err)
	}
	if err := store.Reserve(ctx, reservation(orgID, domain.SeatsMember), 1); err != nil {
		t.Errorf("a member seat was refused because a GUEST seat was taken; the pools are "+
			"independent (ADR-027) and exhausting guests must never block hiring: %v", err)
	}
}

// One organization's usage is invisible to another.
func TestQuotaIsTenantIsolated(t *testing.T) {
	store := reservations(t)
	victim, attacker := freshOrg(), freshOrg()

	if err := store.Reserve(scoped(t, victim),
		reservation(victim, domain.WorkspacesCount), 1); err != nil {
		t.Fatalf("seeding the victim: %v", err)
	}
	// The attacker's own pool is untouched by the victim's usage.
	if err := store.Reserve(scoped(t, attacker),
		reservation(attacker, domain.WorkspacesCount), 1); err != nil {
		t.Errorf("one organization's quota was consumed by another's usage: %v", err)
	}
}
