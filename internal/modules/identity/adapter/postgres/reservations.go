package postgres

import (
	"context"
	"fmt"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Reservations reads the lapse sweep's work list.
//
// It lives in the module's adapter package rather than in the worker's
// composition root, where it was first written. The composition root is where
// dependencies are ASSEMBLED; a type that knows a generated query and a column
// order is an adapter, and leaving it in main means the next binary that needs
// the same read either imports from a command package or writes it a second time.
//
// One generated query, in a SYSTEM transaction. Identity's tables carry no RLS —
// a user exists before any organization, so a tenant policy on them could never
// be satisfied — and the sweep is cross-tenant by nature besides: a lapsed
// reservation belongs to nobody's organization, because the registration that
// created it never completed.
type Reservations struct{ tx db.SystemTX }

var _ app.LapsedReservations = (*Reservations)(nil)

// NewReservations builds the reader.
func NewReservations(tx db.SystemTX) (*Reservations, error) {
	if tx == nil {
		return nil, fmt.Errorf("identity: the reservation reader needs a system transaction; " +
			"without one the lapse sweep has no work list and unverified claims are held forever")
	}
	return &Reservations{tx: tx}, nil
}

// MaxLapsedBatch bounds one call.
//
// The sweep asks for a batch and loops while batches keep filling, so a ceiling
// here costs an extra round trip and never a missed reservation. It exists so the
// limit reaching the database is provably inside the int32 the query takes —
// a caller passing a wildly large limit gets a bounded read rather than a
// conversion that wraps to a negative LIMIT.
const MaxLapsedBatch = 10_000

// ListLapsed returns unverified, unreleased claims whose lease has run out.
func (r *Reservations) ListLapsed(
	ctx context.Context, deadline time.Time, limit int,
) ([]app.LapsedReservation, error) {
	if limit < 1 {
		return nil, fmt.Errorf("identity: a lapsed-reservation batch of %d would sweep nothing; "+
			"the caller must ask for at least one", limit)
	}
	// Clamped rather than converted, and the clamp is what the narrowing rests on:
	// batch stays int32 throughout and only takes a converted value inside a branch
	// that has already proved the value is under MaxLapsedBatch. There is no
	// //nolint here because there is nothing to suppress — a reader can follow the
	// bound rather than take a suppression on trust.
	batch := int32(MaxLapsedBatch)
	if limit < MaxLapsedBatch {
		batch = int32(limit)
	}

	var out []app.LapsedReservation
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Query(ctx, identitydb.ListLapsedReservations, deadline.UTC(), batch)
		if err != nil {
			return fmt.Errorf("listing lapsed reservations: %w", err)
		}
		defer rows.Close()

		for rows.Next() {
			var (
				index     string
				subjectID string
				expiresAt time.Time
			)
			if err := rows.Scan(&index, &subjectID, &expiresAt); err != nil {
				return fmt.Errorf("scanning a lapsed reservation: %w", err)
			}
			out = append(out, app.LapsedReservation{
				Index:     contract.EmailIndex(index),
				SubjectID: subjectID,
				ExpiresAt: expiresAt.UTC(),
			})
		}
		return rows.Err()
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}
