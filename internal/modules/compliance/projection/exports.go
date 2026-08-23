package projection

import (
	"context"
	"math"

	compliancedb "github.com/chronos/chronos-go/gen/sqlc/compliance"
	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// ExportsName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts from zero.
const ExportsName = "data_export_view"

// Exports builds `data_export_view` — what a subject polls.
//
// # It is not authority for anything
//
// Every DECISION about an export is taken against the aggregate: whether a
// request may be recorded, whether a completion is legal, whether a late failure
// may overwrite a finished bundle. This table answers "where has my request got
// to", which tolerates lag — a poll that is a second behind tells somebody their
// export is still building, and the next poll corrects it.
type Exports struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Exports)(nil)

// NewExports wires the handlers.
func NewExports(codec eventsourcing.Codec) *Exports {
	d := projection.NewDispatch(codec)

	d.On[contract.DataExportRequested](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.DataExportRequested,
	) error {
		w.Exec(compliancedb.UpsertDataExportRequest, e.ExportID, e.SubjectID, e.RequestedAt)
		return nil
	})

	// The COMPLETION clears the failure reason, because an export that failed
	// once and was retried into success must not read as having done both. It is
	// deliberately NOT guarded on the current status: a rebuild replays
	// requested → failed → completed for exactly that case, and a guard on
	// `pending` would leave the row failed forever while the bundle sat there.
	d.On[contract.DataExportCompleted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.DataExportCompleted,
	) error {
		w.Exec(compliancedb.CompleteDataExport,
			e.ExportID, e.ManifestKey, objectCount(e.ObjectCount), e.CompletedAt)
		return nil
	})

	// The FAILURE is guarded on `status <> 'ready'` in the statement itself, and
	// that guard is the table's half of the rule the aggregate holds: a late
	// failure from an earlier attempt must never overwrite a fetchable bundle.
	d.On[contract.DataExportFailed](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.DataExportFailed,
	) error {
		w.Exec(compliancedb.FailDataExport, e.ExportID, e.Reason, e.FailedAt)
		return nil
	})

	return &Exports{dispatch: d}
}

func (e *Exports) Name() string { return ExportsName }

// Filter covers export streams only.
//
// By STREAM prefix rather than event type, because every event this projection
// handles lives on one category and nothing else writes there — so the narrower
// filter is available and a group that woke for all of compliance would spend
// its life deciding it has nothing to do.
func (e *Exports) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.ExportCategory) + "-"},
	}
}

func (e *Exports) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return e.dispatch.Apply(ctx, w, env)
}

func (e *Exports) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, compliancedb.TruncateDataExports)
	return err
}

// objectCount narrows the count for the column, refusing to wrap.
//
// The aggregate refuses a negative count and the listing is bounded well below
// this, so neither branch is reachable today. They are written because the
// alternative is a silent wrap into a negative object_count, which the table's
// CHECK constraint would then reject — stopping the whole projection on a value
// that should have been clamped three layers earlier.
func objectCount(n int) int32 {
	switch {
	case n < 0:
		return 0
	case n > math.MaxInt32:
		return math.MaxInt32
	default:
		return int32(n)
	}
}
