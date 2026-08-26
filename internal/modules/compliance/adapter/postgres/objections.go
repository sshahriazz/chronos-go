package postgres

import (
	"context"
	"fmt"

	compliancedb "github.com/chronos/chronos-go/gen/sqlc/compliance"
	"github.com/chronos/chronos-go/internal/platform/db"
)

// Objections answers "has this subject objected to this purpose" (Article 21).
//
// # A SYSTEM transaction, for Restrictions' reason
//
// The caller is the notification dispatcher, running inside a reactor: no
// request, no gate 1, no `app.org_id`. A tenant transaction would match nothing,
// which would look exactly like "nobody has objected" and resume processing for
// every person who stopped it.
//
// The table carries no row security for the same reason `processing_restriction_view`
// does not: an objection is a fact about a PERSON rather than about their
// membership of any organization, and isolation is by pseudonym — the dispatcher
// passes a subject taken from an event's own metadata, never one a caller named.
type Objections struct{ system db.SystemTX }

func NewObjections(system db.SystemTX) (*Objections, error) {
	if system == nil {
		return nil, fmt.Errorf("compliance: a system transaction source is required")
	}
	return &Objections{system: system}, nil
}

// Objected reports whether one purpose is stopped for a subject.
//
// An empty subject or an empty purpose is REFUSED rather than answered false.
// Answering false is permission to send, and an empty argument would match a row
// whose column happens to be empty — which is the one way this lookup could
// quietly hand back the wrong answer for everybody at once.
func (o *Objections) Objected(ctx context.Context, subjectID, purpose string) (bool, error) {
	switch {
	case subjectID == "":
		return false, fmt.Errorf("compliance: checking an objection needs a subject")
	case purpose == "":
		return false, fmt.Errorf("compliance: checking an objection needs a purpose")
	}

	var objected bool
	err := o.system.InSystemTx(ctx, func(ctx context.Context, q db.Querier) error {
		return q.QueryRow(ctx, compliancedb.HasObjectedToPurpose, subjectID, purpose).
			Scan(&objected)
	})
	if err != nil {
		return false, fmt.Errorf("compliance: reading the objection of %s to %s: %w",
			subjectID, purpose, err)
	}
	return objected, nil
}
