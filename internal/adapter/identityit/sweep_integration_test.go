//go:build integration

package identityit_test

import (
	"context"
	"log/slog"
	"testing"
	"time"

	identityv1 "github.com/chronos/chronos-go/gen/proto/chronos/identity/v1"
	identitypg "github.com/chronos/chronos-go/internal/modules/identity/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// TestALapsedReservationIsReleasedAndTheAddressIsRegisterableAgain proves the
// bound on the residual harm IDENTITY-REVIEW C8 accepts.
//
// C8 records the surviving attack as "an attacker can claim an address they do
// not own and deny it to its real owner UNTIL THE RESERVATION LAPSES (48h)".
// Every word of that is load-bearing, and the last clause is an unproven claim
// about a mechanism — the lapse sweep — rather than an observation. If the lapse
// does not actually return the address to circulation, the finding is not a
// bounded denial of service at all: it is a permanent one, which is a materially
// different severity and a different fix.
//
// So this test does not assert that a release event was written. It asserts the
// property the finding depends on: after the lapse, SOMEBODY ELSE CAN REGISTER
// THE ADDRESS AND END UP WITH AN ACCOUNT. Everything before the last assertion
// is setup for that one.
//
// # Why the work list is filtered to this test's own address
//
// ListLapsed is deliberately global — a lapsed reservation belongs to no tenant,
// because the registration that created it never completed. Running an unfiltered
// sweep here would release every other test's unverified claim as a side effect,
// which is a test that breaks its neighbours to prove a point about itself.
//
// The filter wraps the REAL adapter rather than replacing it, so the generated
// SQL, the system transaction and the row-to-LapsedReservation mapping are all
// exercised; only the rows belonging to other tests are dropped after the query
// has returned them. The assertion below that our own index came back from that
// query is what stops the filter from hiding a work list that found nothing.
func TestALapsedReservationIsReleasedAndTheAddressIsRegisterableAgain(t *testing.T) {
	ctx := context.Background()
	address := h.freshEmail("sweep-lapse")
	index := h.emailIndex(t, address)

	// 1. The squat. This is step 1 of the pre-hijack sequence, performed by
	//    somebody who does not own the mailbox and will never prove it.
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: address,
	})); err != nil {
		t.Fatalf("Register: %v\n%s", err, h.serverLogs())
	}
	squatter := h.awaitAccount(t, index)
	t.Logf("the address is claimed by subject=%s state=%s", squatter.subjectID, squatter.state)

	// 2. The lapse has not happened yet, so the address is genuinely denied. This
	//    is asserted rather than assumed: without it, a sweep that released
	//    nothing and an address that was never held look identical at the end.
	if held := h.reservationRow(t, index); held.releasedAt != nil {
		t.Fatalf("the claim is already released at %v before any sweep ran", held.releasedAt)
	}

	// 3. The sweep, run at an instant past the lease. The clock is supplied by the
	//    caller because in production the caller is a Temporal workflow and
	//    workflow.Now is the only clock that survives a replay — which is exactly
	//    what makes "48 hours from now" testable without waiting 48 hours.
	reader, err := identitypg.NewReservations(h.pg)
	if err != nil {
		t.Fatalf("the lapsed-reservation reader: %v", err)
	}
	list := &onlyIndex{inner: reader, want: contract.EmailIndex(index)}
	sweep, err := app.NewReservationSweep(list, h.reservationRepo, slog.New(slog.DiscardHandler))
	if err != nil {
		t.Fatalf("the reservation sweep: %v", err)
	}

	after := time.Now().UTC().Add(app.DefaultReservationLease + time.Hour)
	res, err := sweep.SweepOnce(ctx, after, 1000)
	if err != nil {
		t.Fatalf("SweepOnce: %v", err)
	}
	t.Logf("sweep: scanned=%d released=%d stale=%d failed=%d more=%v",
		res.Scanned, res.Released, res.Stale, res.Failed, res.More)

	if !list.sawWanted {
		t.Fatal("the lapsed-reservation query did not return this address at all. The sweep " +
			"cannot release what it never finds, so the 48h bound in IDENTITY-REVIEW C8 is " +
			"not enforced by anything and the denial is permanent.")
	}
	if res.Released != 1 {
		t.Fatalf("the sweep released %d claims, want 1 (scanned=%d stale=%d failed=%d)",
			res.Released, res.Scanned, res.Stale, res.Failed)
	}

	// 4. The STREAM is the authority, so the release is checked there and not only
	//    in the row the projector wrote.
	agg, err := h.reservationRepo.Load(ctx, index)
	if err != nil {
		t.Fatalf("loading the reservation stream: %v", err)
	}
	if agg.Held() {
		t.Fatalf("the reservation stream still reports the address held by %s after a "+
			"release was appended", agg.SubjectID())
	}

	// 5. And the projection catches up, which is what the NEXT sweep reads.
	deadline := time.Now().Add(30 * time.Second)
	for {
		row := h.reservationRow(t, index)
		if row.releasedAt != nil {
			t.Logf("the projected claim is released at %v", row.releasedAt)
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("email_reservation_view still shows the claim held 30s after the "+
				"release was appended; the next sweep will keep finding it\n%s", h.serverLogs())
		}
		time.Sleep(200 * time.Millisecond)
	}

	// 6. THE ASSERTION THIS TEST EXISTS FOR. The real owner registers, and must
	//    end up with an account of their own — a second one, because the
	//    squatter's Pending account is not deleted by a release and is not
	//    supposed to be.
	if _, err := h.client.Register(ctx, write(&identityv1.RegisterRequest{
		Email: address,
	})); err != nil {
		t.Fatalf("re-registering a released address: %v\n%s", err, h.serverLogs())
	}

	deadline = time.Now().Add(30 * time.Second)
	for {
		var accounts int
		h.systemQuery(t, func(ctx context.Context, q db.Querier) error {
			return q.QueryRow(ctx,
				`SELECT count(*) FROM user_view WHERE email_index = $1`, index).Scan(&accounts)
		})
		if accounts == 2 {
			t.Log("the address is registerable again: a second account now holds it, so the " +
				"denial in IDENTITY-REVIEW C8 is bounded by the lease as recorded")
			return
		}
		if time.Now().After(deadline) {
			// Read the reservation stream again, so the failure says WHICH half
			// broke: a claim the second registration never took, or a claim it
			// took whose account never reached the read model.
			agg, loadErr := h.reservationRepo.Load(ctx, index)
			held, holder := false, ""
			if loadErr == nil {
				held, holder = agg.Held(), agg.SubjectID()
			}
			t.Fatalf("%d account(s) hold the address 30s after re-registration, want 2. "+
				"reservation stream: held=%v holder=%q. If the stream shows the new holder "+
				"but no second row appeared, the identity projector is stuck — user_view."+
				"email_index is UNIQUE and the squatter's abandoned row still occupies it, "+
				"which turns the bounded 48h denial into a permanent one AND stops every "+
				"identity projection.\n%s",
				accounts, held, holder, h.serverLogs())
		}
		time.Sleep(200 * time.Millisecond)
	}
}

// onlyIndex narrows the real work list to one address.
//
// It records whether the underlying query returned that address, because a
// filter that silently emptied the list would make the sweep report "nothing to
// do" and the test would then be asserting that a no-op is harmless.
type onlyIndex struct {
	inner     app.LapsedReservations
	want      contract.EmailIndex
	sawWanted bool
}

// scanLimit is what the INNER query is asked for, regardless of the sweep's own
// limit, and it is the difference between this test passing and it degrading
// with the age of the database.
//
// ListLapsedReservations is `ORDER BY expires_at LIMIT n`. This test's own
// reservation is the newest lapsed row in the table, so it sorts LAST — behind
// every unreleased squat every previous run of this suite left behind. Against a
// dev database with more than `n` of those it falls off the page, the filter
// returns nothing, and the failure reads as "the sweep cannot find lapsed
// reservations, so the 48h bound is not enforced by anything" — a true sentence
// about a mechanism that is working.
//
// Paging cannot fix it: the filter drops the other rows before the sweep can
// release them, so the same first page comes back forever. Asking for a page
// large enough to contain the whole table is what makes the filter's job — find
// ONE known row — independent of how many rows are beside it. The sweep's own
// limit still governs what it releases, which is what the test measures.
const scanLimit = 1_000_000

func (o *onlyIndex) ListLapsed(
	ctx context.Context, deadline time.Time, limit int,
) ([]app.LapsedReservation, error) {
	if limit < scanLimit {
		limit = scanLimit
	}
	rows, err := o.inner.ListLapsed(ctx, deadline, limit)
	if err != nil {
		return nil, err
	}
	var out []app.LapsedReservation
	for _, r := range rows {
		if r.Index == o.want {
			o.sawWanted = true
			out = append(out, r)
		}
	}
	return out, nil
}

type reservationRow struct {
	subjectID  string
	verified   bool
	expiresAt  time.Time
	releasedAt *time.Time
}

func (hh *harness) reservationRow(t *testing.T, index string) reservationRow {
	t.Helper()
	var row reservationRow
	hh.systemQuery(t, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, `
			SELECT subject_id, verified, expires_at, released_at
			FROM email_reservation_view WHERE email_index = $1`, index).
			Scan(&row.subjectID, &row.verified, &row.expiresAt, &row.releasedAt)
	})
	return row
}
