// Package projection builds identity's read models.
//
// Every projection here is rebuildable from position zero — with ONE documented
// exception that is not a projection at all: the `credential` table. Password
// verifiers and TOTP secrets never enter events (identity.md §4), so nothing
// here writes them and a rebuild does not reconstruct them. That table is
// written by command handlers directly and is the one piece of identity state
// that is not derived.
//
// Everything below is derived, and a rebuild recomputes it exactly.
package projection

import (
	"context"
	"fmt"

	identitydb "github.com/chronos/chronos-go/gen/sqlc/identity"
	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// UserName is the projection's permanent identity: it keys the checkpoint row
// and the single-writer lease, so renaming it silently restarts from zero.
const UserName = "identity_user"

// User builds user_view — the account projection.
type User struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*User)(nil)

// NewUser wires the account handlers.
func NewUser(codec eventsourcing.Codec) *User {
	d := projection.NewDispatch(codec)

	d.On[contract.UserRegistered](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserRegistered,
	) error {
		// Upsert, not insert. A projector is replayed on restart and on rebuild,
		// so this event WILL arrive twice; an insert would fail the second time
		// and stall the projection permanently.
		w.Exec(identitydb.UpsertUser,
			e.SubjectID, e.UserID, string(e.EmailIndex),
			domain.StatePending.String(), e.RegisteredAt)
		return nil
	})

	d.On[contract.EmailVerified](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailVerified,
	) error {
		// The index is written again because verification can be for a NEW
		// address during an email change, and the projection must follow the
		// address that was actually proven.
		w.Exec(identitydb.MarkEmailVerified, e.SubjectID, string(e.Index))
		return nil
	})

	// The four state transitions share one shape. Written as a loop over a table
	// rather than four near-identical closures, so a state added to the domain
	// without a projector handler is a visibly missing table entry rather than a
	// silently absent case.
	for _, t := range []struct {
		apply func(*projection.Dispatch)
	}{
		{func(d *projection.Dispatch) {
			d.On[contract.UserActivated](func(
				_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserActivated,
			) error {
				w.Exec(identitydb.SetUserState, e.SubjectID, domain.StateActive.String())
				return nil
			})
		}},
		{func(d *projection.Dispatch) {
			d.On[contract.UserDeactivated](func(
				_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserDeactivated,
			) error {
				w.Exec(identitydb.SetUserState, e.SubjectID, domain.StateDeactivated.String())
				return nil
			})
		}},
		{func(d *projection.Dispatch) {
			d.On[contract.UserReactivated](func(
				_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserReactivated,
			) error {
				w.Exec(identitydb.SetUserState, e.SubjectID, domain.StateActive.String())
				return nil
			})
		}},
		{func(d *projection.Dispatch) {
			d.On[contract.UserSuspended](func(
				_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserSuspended,
			) error {
				w.Exec(identitydb.SetUserState, e.SubjectID, domain.StateSuspended.String())
				return nil
			})
		}},
	} {
		t.apply(d)
	}

	return &User{dispatch: d}
}

func (u *User) Name() string { return UserName }

// Filter narrows the subscription to identity's streams.
//
// Without it this projection is offered every event in the system and skips
// almost all of them — which works, and re-scans the entire log on every
// restart (ADR-042).
func (u *User) Filter() eventsourcing.SubscriptionFilter {
	// ONE dimension only — a KurrentDB filter matches streams or types, never
	// both, and a mixed filter is refused at startup rather than silently
	// reduced to whichever half the adapter honours.
	//
	// By event-type prefix rather than stream prefix, because identity writes to
	// three different stream categories (user-, session-, reservation_email-)
	// and every event in all of them shares the "identity." type prefix. A
	// stream-prefix filter would need all three listed and would silently miss a
	// category added later.
	return eventsourcing.SubscriptionFilter{EventTypePrefixes: []string{"identity."}}
}

func (u *User) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return u.dispatch.Apply(ctx, w, env)
}

func (u *User) Handles(eventType string) bool { return u.dispatch.Handles(eventType) }

// Reset empties the projection so it can be rebuilt from zero.
//
// It touches ONLY projection tables. `credential`, `recovery_code` and
// `identity_token` are authoritative — written by command handlers, holding
// verifiers and secrets that never enter events — so a rebuild cannot restore
// them and this must not delete them.
//
// That separation is enforced by the schema rather than by care taken here:
// migration 00009 drops the foreign keys those tables had to user_view,
// precisely so this delete cannot cascade into them. Writing this method is what
// found the problem — there was no version of it that was both correct and safe
// while the constraints existed.
//
// session_view is deleted explicitly rather than by cascade. Relying on the
// cascade would make the correctness of a rebuild depend on a foreign key
// somebody could reasonably drop while tidying.
func (u *User) Reset(ctx context.Context, q db.Querier) error {
	// One generated statement, authored in db/query/identity/session.sql and
	// checked against the real schema by sqlc (CONVENTIONS §8, ADR-011).
	//
	// The first version of this method built the DELETEs as string literals in
	// Go. That is the exact carve-out this project has been bitten by before —
	// SQL in Go source is banned, and `make sql-check` refuses it — and the ban
	// earns its keep here: writing the statement in a .sql file is what put it
	// somewhere sqlc validates the table list against the schema.
	if _, err := q.Exec(ctx, identitydb.TruncateIdentityProjections); err != nil {
		return fmt.Errorf("identity user projection: resetting: %w", err)
	}
	return nil
}
