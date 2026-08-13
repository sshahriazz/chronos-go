package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Retention implements identity's retention port: the five statements that
// delete rows nothing can act on any more.
//
// It EMBEDS Guards rather than restating two of them. Guards already owns
// SweepTOTPReplay and SweepTokens, next to the single-use statements they clean
// up after, and that is where they belong: whoever changes what a spent step or
// an expired digest means should find the retention for it in the same file. A
// second copy here would be a second place to change, and the failure mode of
// getting that wrong is silent — the copy nothing calls keeps compiling.
//
// Every statement runs in a SYSTEM transaction, one statement per transaction.
// Identity's tables carry no RLS (see the package comment in guards.go) and
// retention is cross-tenant by nature. Separate transactions rather than one
// wrapping all five, because these tables are unrelated: a single transaction
// would make one failing DELETE roll back four successful ones, and would hold
// locks across five unbounded deletes on a live system.
type Retention struct {
	*Guards
	tx db.SystemTX
}

var _ app.RetentionStore = (*Retention)(nil)

// NewRetention builds the adapter.
func NewRetention(tx db.SystemTX) (*Retention, error) {
	if tx == nil {
		return nil, errors.New("identity/postgres: retention needs a system transaction; " +
			"without one nothing is ever deleted and the tables with no TTL grow for the " +
			"lifetime of the deployment")
	}
	guards, err := NewGuards(tx)
	if err != nil {
		return nil, err
	}
	return &Retention{Guards: guards, tx: tx}, nil
}

// SweepSessionTokens drops the SECRET half of sessions that can no longer be
// used — expired absolutely, or revoked.
//
// Only the token. The projected half is deliberately left to
// SweepExpiredSessionViews on a much longer horizon: it is the evidence that a
// session existed, and "when did this device last sign in" is a question the
// security-settings screen has to answer. Deleting the digest is what makes the
// secret unrecoverable, which is the part that matters here.
//
// It finds its rows by joining session_view, and there is no foreign key between
// the two. That is what makes the ORDER of the retention pass matter: see the
// step list in app.Retention.PurgeOnce.
func (r *Retention) SweepSessionTokens(ctx context.Context) (int64, error) {
	var n int64
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.SweepSessionTokens)
		if err != nil {
			return fmt.Errorf("identity/postgres: sweeping session tokens: %w", err)
		}
		n = rows
		return nil
	})
	return n, err
}

// SweepExpiredSessionViews drops session rows whose absolute deadline passed
// before cutoff.
//
// A zero cutoff is refused rather than passed through. The statement compares
// against it directly, so year 1 would match nothing and the call would report a
// perfectly healthy zero — a retention statement that has stopped working looks
// exactly like one with nothing to do, and this is the one input that can cause
// that silently.
func (r *Retention) SweepExpiredSessionViews(ctx context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, errors.New("identity/postgres: sweeping session views needs a cutoff; a zero " +
			"one deletes nothing and reports success")
	}

	var n int64
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.SweepExpiredSessionViews, cutoff.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: sweeping expired session views: %w", err)
		}
		n = rows
		return nil
	})
	return n, err
}

// DeleteReleasedReservations drops reservation rows released before cutoff.
//
// Safe on a projection because it deletes only what a replay would recreate
// (reservation.sql). The zero cutoff is refused for the same reason as above.
func (r *Retention) DeleteReleasedReservations(ctx context.Context, cutoff time.Time) (int64, error) {
	if cutoff.IsZero() {
		return 0, errors.New("identity/postgres: deleting released reservations needs a " +
			"cutoff; a zero one deletes nothing and reports success")
	}

	var n int64
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		rows, err := q.Exec(ctx, identitydb.DeleteReleasedReservations, cutoff.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: deleting released reservations: %w", err)
		}
		n = rows
		return nil
	})
	return n, err
}
