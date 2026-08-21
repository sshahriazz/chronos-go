// Package postgres reads the profile module's projection.
//
// Read-only, absolutely. Nothing here writes: `profile_view` is a projection,
// filled by its projector from the log (ADR-019), and a second writer would
// make rebuild order undefined and put state in PostgreSQL that no replay
// reproduces.
package postgres

import (
	"context"
	"errors"
	"fmt"

	profiledb "github.com/chronos/chronos-go/gen/sqlc/profile"
	"github.com/chronos/chronos-go/internal/modules/profile/app"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	pgxv5 "github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ReadModel answers "what has this person configured".
//
// # The transaction, and why it is a SYSTEM transaction
//
// `profile_view` carries no `org_id` and has no row-level security, for the
// reason the migration gives: a profile is global to a person exactly as their
// account is, so there is no tenant to scope it by. That is the same shape as
// identity's tables, and it is read the same way — through db.SystemTX.
//
// The isolation is not weaker for it, it is differently sourced: every statement
// here is filtered by the caller's own `subject_id`, which the authentication
// gate supplies from the session and which no request field can name. A caller
// cannot ask for somebody else's row because there is nowhere in the API to put
// the question.
type ReadModel struct{ tx db.SystemTX }

// NewReadModel builds the adapter.
func NewReadModel(tx db.SystemTX) (*ReadModel, error) {
	if tx == nil {
		return nil, errors.New("profile/postgres: a system transaction is required")
	}
	return &ReadModel{tx: tx}, nil
}

var _ app.Reader = (*ReadModel)(nil)

// View returns one subject's projected profile.
//
// A subject with no row is NOT an error. Every account has a profile in the
// sense that matters — it simply holds nothing until somebody sets something —
// and returning a not-found here would make every client branch on a
// distinction that is not one.
func (r *ReadModel) View(ctx context.Context, subjectID string) (app.View, error) {
	if subjectID == "" {
		// Refused rather than run. `WHERE subject_id = ''` matches nothing, and
		// an empty result reads as "this person has configured nothing" — which
		// is exactly the wrong answer to a bug.
		return app.View{}, errors.New("profile/postgres: a profile read needs a subject")
	}

	var out app.View
	err := r.tx.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		var (
			updatedAt   pgtype.Timestamptz
			key         string
			contentType string
			size        int64
		)
		err := q.QueryRow(ctx, profiledb.GetProfileView, subjectID).Scan(
			&out.SubjectID,
			&out.DisplayNameSet, &out.LocaleSet, &out.TimezoneSet,
			&key, &contentType, &size,
			&updatedAt,
		)
		if errors.Is(err, pgxv5.ErrNoRows) {
			return nil
		}
		if err != nil {
			return err
		}
		out.Exists = true
		out.Avatar = domain.Avatar{ObjectKey: key, ContentType: contentType, SizeBytes: size}
		if updatedAt.Valid {
			out.UpdatedAt = updatedAt.Time.UTC()
		}
		return nil
	})
	if err != nil {
		return app.View{}, fmt.Errorf("profile: reading a profile: %w", err)
	}
	return out, nil
}
