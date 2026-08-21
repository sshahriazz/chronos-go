package projection

import (
	"context"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// PreferenceName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const PreferenceName = "notification_preferences"

// Preferences builds the settings screen's read model, and the table the
// dispatcher consults before delivering anything suppressible.
//
// A projection of its own rather than a third handler on the feed, because one
// projector owns one table: two writers to one projection makes rebuild order
// undefined, and the advisory lease enforces that at runtime (CONVENTIONS §8).
//
// # What this table can and cannot do
//
// It holds `(org_id, subject_id, channel, enabled)` and nothing else. There is
// no class column and no template column, so no row here can name Security —
// which is the structural half of why a preference cannot silence a security
// alert. The other half is in the dispatcher, which checks class BEFORE it reads
// this table at all, so even a row that somehow named one would never be
// consulted for it (notification.md §6).
type Preferences struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Preferences)(nil)

func NewPreferences(codec eventsourcing.Codec) *Preferences {
	d := projection.NewDispatch(codec)

	d.On[contract.ChannelPreferenceSet](func(
		ctx context.Context, w db.Writer, env projection.Envelope, e *contract.ChannelPreferenceSet,
	) error {
		// Upsert, not insert: a projector is replayed on restart and on rebuild,
		// so the same event WILL arrive twice and an insert would fail the second
		// time and stall the projection permanently.
		//
		// LAST WRITER WINS, and the ordering is the STREAM's rather than the
		// clock's. All of one person's preference changes for one organization
		// live on one stream, so by the time two concurrent saves reach here they
		// are already totally ordered — which is what stops a torn result where
		// one channel took the first save and another took the second.
		//
		// The org comes from the EVENT rather than from the envelope. Both carry
		// it and they agree, but the payload is what a rebuild can rely on
		// without the envelope having been written correctly by every producer
		// that ever existed — and it is the column the RLS policy checks.
		w.Exec(notificationdb.UpsertChannelPreference,
			e.SubjectID, e.OrgID, e.Channel, e.Enabled, e.ChangedAt)
		return nil
	})

	return &Preferences{dispatch: d}
}

func (p *Preferences) Name() string { return PreferenceName }

// Filter narrows to this module's own streams. One category, so a rebuild reads
// the category stream instead of scanning the whole log.
func (p *Preferences) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{StreamPrefixes: []string{"notification-"}}
}

func (p *Preferences) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return p.dispatch.Apply(ctx, w, env)
}

func (p *Preferences) Reset(ctx context.Context, q db.Querier) error {
	// TRUNCATE, because a rebuild runs in an unscoped system transaction where
	// RLS hides every row and DELETE would remove none (ADR-019).
	_, err := q.Exec(ctx, notificationdb.TruncateChannelPreferences)
	return err
}
