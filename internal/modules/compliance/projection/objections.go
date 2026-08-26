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

// ObjectionsName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts from zero.
const ObjectionsName = "processing_objection_view"

// Objections builds `processing_objection_view`.
//
// A row's PRESENCE is the objection, so this does exactly two things: insert on
// objected, delete on withdrawn. It is deliberately the same shape as
// Restrictions — the two rights are different, and the mechanism for making a
// per-subject legal state readable on the notification path is not.
type Objections struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Objections)(nil)

// NewObjections wires the handlers.
func NewObjections(codec eventsourcing.Codec) *Objections {
	d := projection.NewDispatch(codec)

	d.On[contract.ProcessingObjected](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ProcessingObjected,
	) error {
		w.Exec(compliancedb.UpsertObjection, e.SubjectID, e.Purpose, e.ObjectedAt, e.ActorID)
		return nil
	})

	d.On[contract.ProcessingObjectionWithdrawn](func(
		_ context.Context, w db.Writer, _ projection.Envelope,
		e *contract.ProcessingObjectionWithdrawn,
	) error {
		// Scoped to the ONE purpose. A delete by subject would release every
		// objection the person holds when they withdrew one — the failure the
		// composite key makes hard to write and this line makes impossible.
		w.Exec(compliancedb.DeleteObjection, e.SubjectID, e.Purpose)
		return nil
	})

	return &Objections{dispatch: d}
}

func (o *Objections) Name() string { return ObjectionsName }

// Filter covers objection streams only.
func (o *Objections) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.ObjectionCategory) + "-"},
	}
}

func (o *Objections) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return o.dispatch.Apply(ctx, w, env)
}

// Reset empties the table for a rebuild.
//
// The failure direction is the one Restrictions documents: a rebuild that has
// not yet replayed an objection resumes a purpose somebody stopped. That is why
// the dispatcher treats an unreadable objection lookup as a refusal to send
// rather than as permission.
func (o *Objections) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, compliancedb.TruncateObjections)
	return err
}
