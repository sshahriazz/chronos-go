// Package projection builds compliance's read model.
package projection

import (
	"context"

	compliancedb "github.com/chronos/chronos-go/gen/sqlc/compliance"
	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// RestrictionsName is permanent: it keys the checkpoint row and the
// single-writer lease, so renaming it silently restarts from zero.
const RestrictionsName = "processing_restriction_view"

// Restrictions builds `processing_restriction_view`.
//
// A row's PRESENCE is the restriction, so this projection does exactly two
// things: insert on restricted, delete on lifted.
type Restrictions struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Restrictions)(nil)

// NewRestrictions wires the handlers.
func NewRestrictions(codec eventsourcing.Codec) *Restrictions {
	d := projection.NewDispatch(codec)

	d.On[contract.ProcessingRestricted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ProcessingRestricted,
	) error {
		w.Exec(compliancedb.UpsertRestriction, e.SubjectID, e.RestrictedAt, e.ActorID)
		return nil
	})

	d.On[contract.ProcessingRestrictionLifted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ProcessingRestrictionLifted,
	) error {
		w.Exec(compliancedb.DeleteRestriction, e.SubjectID)
		return nil
	})

	return &Restrictions{dispatch: d}
}

func (r *Restrictions) Name() string { return RestrictionsName }

// Filter covers restriction streams only.
func (r *Restrictions) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.RestrictionCategory) + "-"},
	}
}

func (r *Restrictions) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return r.dispatch.Apply(ctx, w, env)
}

// Reset empties the table for a rebuild.
//
// The failure direction is worth noting: a rebuild that has not yet replayed a
// restriction leaves somebody UNRESTRICTED — processing resumes for a person who
// asked it to stop. That is the wrong direction, and it is why the dispatcher
// treats an unreadable restriction lookup as a refusal to send rather than as
// permission.
func (r *Restrictions) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, compliancedb.TruncateRestrictions)
	return err
}
