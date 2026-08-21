// Package projection builds profile's read model.
//
// One projection, one table, one event type. It is rebuildable from position
// zero by construction: every column it writes comes from the event, and the
// only column it could not reconstruct — a display name — is deliberately not
// here (see migration 00017).
package projection

import (
	"context"

	profiledb "github.com/chronos/chronos-go/gen/sqlc/profile"
	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// Name is permanent: it keys the checkpoint row and the single-writer lease, so
// renaming it silently restarts the projection from zero.
const Name = "profile_view"

// Profile builds `profile_view`.
type Profile struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Profile)(nil)

// NewProfile wires the one handler.
func NewProfile(codec eventsourcing.Codec) *Profile {
	d := projection.NewDispatch(codec)

	d.On[contract.ProfileUpdated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.ProfileUpdated,
	) error {
		// EVERY optional column is passed as a POINTER, and that is where the
		// sparse update lives: a nil pointer becomes SQL NULL, and the
		// statement's COALESCE keeps whatever is already stored. Anything else —
		// including the empty string and zero — is a value the event carried, so
		// it wins.
		//
		// The alternative, dereferencing into a plain value with a default, is
		// the bug this shape exists to prevent: every update that left a field
		// out would clear it, and the person who changed only their timezone
		// would find their avatar gone.
		key, contentType, size := avatarColumns(e.Avatar)

		// Upsert, not insert: a projector is replayed on restart and on rebuild,
		// so this event WILL arrive twice and an insert would fail the second
		// time and stall the projection permanently.
		w.Exec(profiledb.UpsertProfile,
			e.SubjectID,
			setFlag(e.DisplayName), setFlag(e.Locale), setFlag(e.Timezone),
			key, contentType, size,
			e.UpdatedAt)
		return nil
	})

	return &Profile{dispatch: d}
}

// setFlag turns a field's marker into the boolean the table stores, or nil for
// a field this event did not mention.
func setFlag(c *contract.Change) *bool {
	if c == nil {
		return nil
	}
	set := *c == contract.Set
	return &set
}

// avatarColumns turns the avatar's marker into the three columns, or three nils
// for an event that did not mention it.
//
// All three move together, which is what the table's CHECK constraint requires:
// a key with no content type is a download URL for an object nothing can
// describe.
func avatarColumns(a *contract.AvatarChange) (*string, *string, *int64) {
	if a == nil {
		return nil, nil, nil
	}
	if a.Change == contract.Cleared {
		empty, zero := "", int64(0)
		return &empty, &empty, &zero
	}
	key, contentType, size := a.ObjectKey, a.ContentType, a.SizeBytes
	return &key, &contentType, &size
}

func (p *Profile) Name() string { return Name }

// Filter narrows $all to this module's own streams.
//
// One category, so a REBUILD reads the `$ce-profile` category stream instead of
// scanning the whole log — which is the difference between a rebuild that is
// proportional to this module's history and one proportional to the system's
// (ADR-042).
func (p *Profile) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.Category) + "-"},
	}
}

func (p *Profile) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return p.dispatch.Apply(ctx, w, env)
}

// Reset empties the table for a rebuild.
func (p *Profile) Reset(ctx context.Context, q db.Querier) error {
	// TRUNCATE for the reason every other projection here uses it: a rebuild
	// runs in an UNSCOPED system transaction, and DELETE under row security
	// would remove none (ADR-019). This table has no row security, so DELETE
	// would in fact work — using TRUNCATE anyway is what stops this one being
	// the exception somebody has to remember.
	_, err := q.Exec(ctx, profiledb.TruncateProfiles)
	return err
}
