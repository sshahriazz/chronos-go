package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	compliancedb "github.com/chronos/chronos-go/gen/sqlc/compliance"
	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Exports answers "where has my data-subject request got to".
//
// A SYSTEM transaction, for Restrictions' reason and one more. The caller is a
// request handler, so gate 1 has run — but a data-subject request is a fact
// about a PERSON rather than about any tenant, and a person in three
// organizations exercises Article 15 once. Scoping the read by the organization
// they happened to be looking at would hide their own export from them half the
// time.
//
// Isolation is by PSEUDONYM instead, and it is enforced in the statement: every
// query here takes the subject from the authenticated caller and matches on it,
// so an export id belonging to somebody else answers exactly as an unknown one.
type Exports struct{ system db.SystemTX }

// maxExportListLimit bounds one page of a subject's own export history.
const maxExportListLimit = 50

// clampListLimit narrows a requested page into the column's own type.
//
// Both ends, so the conversion cannot wrap: a negative LIMIT is refused by
// Postgres and would surface as an internal error on somebody's own privacy
// screen, which is the least useful place for one.
func clampListLimit(limit int) int32 {
	switch {
	case limit < 1:
		return 20
	case limit > maxExportListLimit:
		return maxExportListLimit
	default:
		return int32(limit)
	}
}

func NewExports(system db.SystemTX) (*Exports, error) {
	if system == nil {
		return nil, fmt.Errorf("compliance: a system transaction source is required")
	}
	return &Exports{system: system}, nil
}

var _ app.ExportReader = (*Exports)(nil)

// Export returns one request, scoped to the subject who made it.
func (e *Exports) Export(
	ctx context.Context, exportID, subjectID string,
) (app.ExportRecord, error) {
	if exportID == "" || subjectID == "" {
		return app.ExportRecord{}, fmt.Errorf(
			"compliance: reading an export needs both an id and a subject")
	}

	var (
		row    app.ExportRecord
		key    pgtype.Text
		reason pgtype.Text
		req    pgtype.Timestamptz
		settle pgtype.Timestamptz
		count  int32
	)
	err := e.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, compliancedb.GetDataExport, exportID, subjectID).Scan(
			&row.ExportID, &row.SubjectID, &row.Status, &key, &count, &reason, &req, &settle)
	})
	if err != nil {
		if noRows(err) {
			// The SAME answer for "no such export" and "somebody else's export".
			// Distinguishing them confirms that an id names a real request, which
			// is the only thing a holder of a leaked id learns for free.
			return app.ExportRecord{}, app.ErrNoSuchExport
		}
		return app.ExportRecord{}, fmt.Errorf("compliance: reading export %s: %w", exportID, err)
	}

	row.ManifestKey = key.String
	row.FailureReason = reason.String
	row.ObjectCount = int(count)
	row.RequestedAt = utc(req)
	row.SettledAt = utc(settle)
	return row, nil
}

// Exports returns the subject's own requests, newest first.
func (e *Exports) Exports(
	ctx context.Context, subjectID string, limit int,
) ([]app.ExportRecord, error) {
	if subjectID == "" {
		return nil, fmt.Errorf("compliance: listing exports needs a subject")
	}
	// CLAMPED at both ends before it becomes an int32. The lower bound is a
	// default; the upper stops an oversized int from wrapping negative on the way
	// into the query, which would ask Postgres for a negative LIMIT.
	rows := clampListLimit(limit)

	var out []app.ExportRecord
	err := e.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		cursor, err := q.Query(ctx, compliancedb.ListDataExports, subjectID, rows)
		if err != nil {
			return err
		}
		defer cursor.Close()
		for cursor.Next() {
			var (
				row    app.ExportRecord
				reason pgtype.Text
				req    pgtype.Timestamptz
				settle pgtype.Timestamptz
				count  int32
			)
			if err := cursor.Scan(&row.ExportID, &row.Status, &count,
				&reason, &req, &settle); err != nil {
				return err
			}
			row.SubjectID = subjectID
			row.FailureReason = reason.String
			row.ObjectCount = int(count)
			row.RequestedAt = utc(req)
			row.SettledAt = utc(settle)
			out = append(out, row)
		}
		return cursor.Err()
	})
	if err != nil {
		return nil, fmt.Errorf("compliance: listing exports for %s: %w", subjectID, err)
	}
	return out, nil
}

// utc normalises a nullable timestamp. Storage is always UTC (ADR-008); this is
// what stops a driver's local zone reaching a response.
func utc(t pgtype.Timestamptz) time.Time {
	if !t.Valid {
		return time.Time{}
	}
	return t.Time.UTC()
}

// noRows recognises pgx's empty-result error.
//
// The driver's own sentinel, matched with errors.Is rather than by comparing
// message text: a string match would break silently on a driver upgrade and
// would turn "no such export" into an internal error on the one endpoint a
// person uses when they are already waiting for something.
func noRows(err error) bool { return errors.Is(err, pgx.ErrNoRows) }
