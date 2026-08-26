package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"

	platformdb "github.com/chronos/chronos-go/gen/sqlc/platform"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// KEKCanary stores the single wrapped proof that the key-encryption key has not
// changed (ADR-028).
//
// A SYSTEM transaction: the canary belongs to the installation rather than to
// any tenant, and it is read before any request has a tenant context at all.
type KEKCanary struct{ tx db.SystemTX }

// NewKEKCanary builds the store.
func NewKEKCanary(tx db.SystemTX) (*KEKCanary, error) {
	if tx == nil {
		return nil, fmt.Errorf("postgres: the KEK canary needs a system transaction source")
	}
	return &KEKCanary{tx: tx}, nil
}

var _ pii.CanaryStore = (*KEKCanary)(nil)

// Get returns the stored canary.
func (c *KEKCanary) Get(ctx context.Context) (string, []byte, error) {
	var (
		name    string
		wrapped []byte
	)
	err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, platformdb.GetKEKCanary).Scan(&name, &wrapped)
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return "", nil, pii.ErrNoCanary
	case err != nil:
		return "", nil, fmt.Errorf("postgres: reading the KEK canary: %w", err)
	}
	return name, wrapped, nil
}

// Put writes the canary the first time only.
func (c *KEKCanary) Put(ctx context.Context, kekName string, wrapped []byte) error {
	if err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, platformdb.InsertKEKCanary, kekName, wrapped)
		return err
	}); err != nil {
		return fmt.Errorf("postgres: writing the KEK canary: %w", err)
	}
	return nil
}

// Touch records that the canary verified.
func (c *KEKCanary) Touch(ctx context.Context, at time.Time) error {
	if err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, platformdb.TouchKEKCanary, at.UTC())
		return err
	}); err != nil {
		return fmt.Errorf("postgres: recording the KEK verification: %w", err)
	}
	return nil
}
