// Package postgres is compliance's read-model adapter.
package postgres

import (
	"context"
	"fmt"

	compliancedb "github.com/chronos/chronos-go/gen/sqlc/compliance"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Restrictions answers "has this subject halted processing" (Article 18).
//
// # A SYSTEM transaction, and why that is not a shortcut
//
// The caller is the notification dispatcher, running inside a reactor: no
// request, no gate 1, no `app.org_id`. A tenant transaction would match nothing,
// which would look exactly like "nobody is restricted" and resume processing for
// every person who asked it to stop.
//
// The table carries no row security for the same reason `user_view` does not: a
// restriction is a fact about a PERSON rather than about their membership of any
// organization, and isolation is by pseudonym — the dispatcher passes a subject
// taken from an event's own metadata, never one a caller named.
type Restrictions struct{ system db.SystemTX }

func NewRestrictions(system db.SystemTX) (*Restrictions, error) {
	if system == nil {
		return nil, fmt.Errorf("compliance: a system transaction source is required")
	}
	return &Restrictions{system: system}, nil
}

// Restricted reports whether processing is halted for a subject.
func (r *Restrictions) Restricted(ctx context.Context, subjectID string) (bool, error) {
	if subjectID == "" {
		// An empty subject would match a row whose column happens to be empty.
		// Refused rather than answered false: answering false is permission to
		// send, and this is the one lookup where a wrong "no" resumes processing
		// for somebody who asked it to stop.
		return false, fmt.Errorf("compliance: checking a restriction needs a subject")
	}
	var restricted bool
	err := r.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, compliancedb.IsProcessingRestricted, subjectID).Scan(&restricted)
	})
	if err != nil {
		return false, fmt.Errorf("compliance: reading the restriction for %s: %w", subjectID, err)
	}
	return restricted, nil
}
