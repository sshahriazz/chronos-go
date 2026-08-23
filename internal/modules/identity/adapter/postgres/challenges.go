package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Challenges holds WebAuthn ceremonies in flight.
//
// A SYSTEM transaction, because a discoverable login has no authenticated caller
// yet — that is the point of usernameless sign-in — so there is no tenant
// context to scope by. Isolation comes from the challenge id being unguessable
// and from the purpose being checked in the same statement that consumes it.
type Challenges struct{ tx db.SystemTX }

func NewChallenges(tx db.SystemTX) (*Challenges, error) {
	if tx == nil {
		return nil, fmt.Errorf("identity/postgres: a system transaction source is required")
	}
	return &Challenges{tx: tx}, nil
}

var _ app.ChallengeStore = (*Challenges)(nil)

// Issue records a ceremony.
func (c *Challenges) Issue(ctx context.Context, ch app.Challenge) error {
	switch {
	case ch.ID == "":
		return fmt.Errorf("identity/postgres: a challenge id is required")
	case len(ch.State) == 0:
		return fmt.Errorf("identity/postgres: a challenge with no state verifies nothing")
	case ch.ExpiresAt.IsZero():
		// A ceremony with no deadline stays redeemable forever, which is the one
		// property a single-use challenge must not have.
		return fmt.Errorf("identity/postgres: a challenge needs a deadline")
	}
	return c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		_, err := q.Exec(ctx, identitydb.InsertWebauthnChallenge,
			ch.ID, nullable(ch.SubjectID), string(ch.Purpose),
			ch.State, ch.ExpiresAt.UTC())
		if err != nil {
			return fmt.Errorf("identity/postgres: issuing a challenge: %w", err)
		}
		return nil
	})
}

// Consume redeems a ceremony exactly once.
//
// One statement, and that is the whole single-use rule: a read-then-delete
// races two simultaneous finishes and both win — one ceremony producing two
// credentials, or two sessions from one signature.
//
// Unknown, already spent, expired and wrong-purpose are ONE outcome. Telling
// them apart would confirm that a ceremony id was real, which is the only thing
// a holder of a stale one learns for free.
func (c *Challenges) Consume(
	ctx context.Context, id string, purpose app.CeremonyPurpose, now time.Time,
) (app.Challenge, error) {
	if id == "" {
		return app.Challenge{}, app.ErrNoSuchChallenge
	}

	out := app.Challenge{ID: id, Purpose: purpose}
	err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var subject pgtype.Text
		err := q.QueryRow(ctx, identitydb.ConsumeWebauthnChallenge,
			id, string(purpose), now.UTC()).Scan(&subject, &out.State)
		if err != nil {
			return err
		}
		out.SubjectID = subject.String
		return nil
	})
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return app.Challenge{}, app.ErrNoSuchChallenge
	case err != nil:
		return app.Challenge{}, fmt.Errorf("identity/postgres: consuming a challenge: %w", err)
	}
	return out, nil
}

// Sweep drops ceremonies nobody completed.
//
// Abandoned challenges are the ORDINARY case — a closed tab, a browser prompt
// that timed out — so a non-zero count here is housekeeping and not a signal.
func (c *Challenges) Sweep(ctx context.Context, now time.Time) (int, error) {
	var removed int64
	err := c.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		n, err := q.Exec(ctx, identitydb.SweepWebauthnChallenges, now.UTC())
		removed = n
		return err
	})
	if err != nil {
		return 0, fmt.Errorf("identity/postgres: sweeping challenges: %w", err)
	}
	return int(removed), nil
}
