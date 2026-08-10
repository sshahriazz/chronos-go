package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	platformdb "github.com/chronos/chronos-go/gen/sqlc/platform"
	"github.com/chronos/chronos-go/internal/platform/cqrs"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/jackc/pgx/v5"
)

// Idempotency stores the request-pipeline's idempotency records (CONVENTIONS §6).
//
// Every statement runs in a SYSTEM transaction, not a tenant one, and that is
// not an oversight. The gate runs BEFORE the request has been authorized, so
// there is no tenant scope to set yet and an RLS policy on this table could
// never be satisfied. Isolation comes from the principal being part of the
// primary key instead — which is why cqrs.Scope refuses to be built without one.
type Idempotency struct{ tx db.SystemTX }

var _ cqrs.Store = (*Idempotency)(nil)

func NewIdempotency(tx db.SystemTX) *Idempotency { return &Idempotency{tx: tx} }

// Claim takes the claim for a scope, or reports what is already there.
//
// Atomicity lives in the SQL, not here: the INSERT … ON CONFLICT is one
// statement, so exactly one of N concurrent duplicates can be told to execute. A
// SELECT-then-INSERT in Go would reintroduce the double-click this whole gate
// exists to stop.
func (i *Idempotency) Claim(
	ctx context.Context, s cqrs.Scope, fp [32]byte, ttl time.Duration,
) (cqrs.Record, error) {
	if err := s.Validate(); err != nil {
		return cqrs.Record{}, err
	}
	if ttl <= 0 {
		return cqrs.Record{}, fmt.Errorf("%w: an idempotency record needs a positive TTL; "+
			"without one it would be replayable forever", cqrs.ErrInvalid)
	}

	var rec cqrs.Record
	err := i.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, platformdb.ClaimIdempotencyKey,
			s.Principal, s.Operation, string(s.Key), fp[:], ttl.Seconds())
		if err != nil {
			return fmt.Errorf("claiming: %w", err)
		}
		if rows > 0 {
			// We inserted, or took over an expired row. Either way the claim is
			// ours and the caller must execute.
			rec = cqrs.Record{State: cqrs.StateNew, Fingerprint: fp}
			return nil
		}

		// Somebody else holds it. Read what they left. Same transaction, so the
		// row cannot vanish between the two statements — a release landing in
		// between would otherwise turn "held" into "no row" and produce a
		// spurious error on a path clients hit constantly.
		var storedFP, response []byte
		scanErr := q.QueryRow(ctx, platformdb.GetIdempotencyKey,
			s.Principal, s.Operation, string(s.Key)).Scan(&storedFP, &response)
		if errors.Is(scanErr, pgx.ErrNoRows) {
			// The row expired between the two statements. Reporting "running"
			// would refuse a request nothing is actually executing; the caller
			// retries the claim and wins it.
			rec = cqrs.Record{State: cqrs.StateRunning, Fingerprint: fp}
			return nil
		}
		if scanErr != nil {
			return fmt.Errorf("reading the existing record: %w", scanErr)
		}
		if len(storedFP) != len(rec.Fingerprint) {
			// A CHECK constraint enforces this, so reaching it means the row was
			// written by something other than this code.
			return fmt.Errorf("stored fingerprint is %d bytes, want %d",
				len(storedFP), len(rec.Fingerprint))
		}
		copy(rec.Fingerprint[:], storedFP)
		if response == nil {
			rec.State = cqrs.StateRunning
			return nil
		}
		rec.State = cqrs.StateDone
		rec.Response = response
		return nil
	})
	if err != nil {
		return cqrs.Record{}, fmt.Errorf("postgres: idempotency %s: %w", s, err)
	}
	return rec, nil
}

// Complete records the response against a claim this caller holds.
//
// Zero rows affected is an ERROR, not a silent success. It means the claim was
// taken over or expired while the handler ran, so the response is NOT stored —
// and a caller told "recorded" would believe a retry will replay it.
func (i *Idempotency) Complete(ctx context.Context, s cqrs.Scope, response []byte) error {
	if err := s.Validate(); err != nil {
		return err
	}
	if response == nil {
		// NULL is what marks a row as an in-flight claim. Storing one here would
		// leave the record looking permanently in flight, so every retry of a
		// mutation that already succeeded would be refused as a duplicate.
		return fmt.Errorf("%w: refusing to store a nil idempotency response; NULL is what "+
			"marks a claim as still running", cqrs.ErrInvalid)
	}
	return i.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, platformdb.CompleteIdempotencyKey,
			s.Principal, s.Operation, string(s.Key), response)
		if err != nil {
			return fmt.Errorf("postgres: recording the response for %s: %w", s, err)
		}
		if rows == 0 {
			return fmt.Errorf("postgres: no claim to complete for %s: it expired or was taken "+
				"over while the handler ran, so this response was not stored", s)
		}
		return nil
	})
}

// Release drops a claim whose execution failed.
//
// It can only ever delete an UNCOMPLETED claim — the `response IS NULL` in the
// SQL is what makes that true. Deleting a completed record would let the
// mutation run a second time under the same key, which is the gate failing open.
func (i *Idempotency) Release(ctx context.Context, s cqrs.Scope) error {
	if err := s.Validate(); err != nil {
		return err
	}
	return i.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		if _, err := q.Exec(ctx, platformdb.ReleaseIdempotencyKey,
			s.Principal, s.Operation, string(s.Key)); err != nil {
			return fmt.Errorf("postgres: releasing the claim for %s: %w", s, err)
		}
		return nil
	})
}

// Sweep deletes expired records.
//
// Not optional housekeeping: a stored response can contain personal data, so the
// TTL is a retention bound rather than a cache hint (ADR-002). It returns the
// count so the caller can report it — a sweep that silently deletes nothing for
// a week looks identical to a sweep that is working.
func (i *Idempotency) Sweep(ctx context.Context) (int64, error) {
	var deleted int64
	err := i.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, err := q.Exec(ctx, platformdb.DeleteExpiredIdempotencyKeys)
		if err != nil {
			return fmt.Errorf("postgres: sweeping expired idempotency records: %w", err)
		}
		deleted = n
		return nil
	})
	return deleted, err
}
