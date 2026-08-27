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

	// An erased account loses its toggles too, and this is the weakest of the
	// three claims in this module — so it is made explicitly rather than by
	// following the other two.
	//
	// A row here holds a channel name, a boolean and a pseudonym whose key has
	// been destroyed. Nothing in it can be read back to a person, so unlike the
	// feed's free text and the push endpoint's device identifier this is not an
	// Article 17 obligation.
	//
	// It goes anyway, because the row can never become useful again — a pseudonym
	// is not reissued, so no future account can own these toggles, and ABSENCE
	// MEANS ENABLED, so a stranded row is not a defensible default for anybody
	// either. What it buys is a property that can be tested in one query: an
	// erased subject has no rows in notification, rather than none in two of its
	// three tables and a sentence somebody has to maintain about the third.
	onUserErased(d, notificationdb.DeleteChannelPreferencesOfSubject)

	return &Preferences{dispatch: d}
}

func (p *Preferences) Name() string { return PreferenceName }

// Filter is this module's shared subscription: its own events, plus the erasure
// that empties this table.
func (p *Preferences) Filter() eventsourcing.SubscriptionFilter { return subscription() }

// Handles reports whether this projection has a handler for an event type, so a
// test can assert the filter above delivers everything registered below it.
func (p *Preferences) Handles(eventType string) bool { return p.dispatch.Handles(eventType) }

func (p *Preferences) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return p.dispatch.Apply(ctx, w, env)
}

func (p *Preferences) Reset(ctx context.Context, q db.Querier) error {
	// TRUNCATE, because a rebuild runs in an unscoped system transaction where
	// RLS hides every row and DELETE would remove none (ADR-019).
	_, err := q.Exec(ctx, notificationdb.TruncateChannelPreferences)
	return err
}
