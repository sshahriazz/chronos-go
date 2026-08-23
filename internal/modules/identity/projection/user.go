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

	// THE ADDRESS MOVING (identity.md §12), on both legs.
	//
	// Without these two the account is findable by the address it LEFT and by no
	// other: `AccountByEmailIndex` reads this table, so a completed change would
	// leave the person unable to sign in with their new address while whoever
	// caused the change keeps signing in with the old one. That is the change
	// achieving the exact opposite of what it is for.
	//
	// They write the same statement EmailVerified writes, because they assert the
	// same two facts — this account's address is now X, and X is proven. The
	// events are distinct rather than reusing EmailVerified so that the log says
	// what happened; the projection collapses them because the ROW does not care
	// how the address came to be proven.
	//
	// There is no handler clearing the old index, and there must not be: the row
	// holds ONE address and these overwrite it. `EmailReleased` below is a
	// different transition — an account holding no address at all — and firing it
	// for the old address of a change would blank the account's identifier
	// immediately after moving it.
	d.On[contract.EmailChanged](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailChanged,
	) error {
		w.Exec(identitydb.MarkEmailVerified, e.SubjectID, string(e.ToIndex))
		return nil
	})

	d.On[contract.EmailChangeReverted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailChangeReverted,
	) error {
		w.Exec(identitydb.MarkEmailVerified, e.SubjectID, string(e.ToIndex))
		return nil
	})

	// EmailReleased is the ONLY event that says an account has stopped holding
	// its address, and it lives on the reservation stream rather than the
	// account's own. Handling it here is therefore not a convenience: without it
	// user_view cannot represent the state the domain legitimately produces —
	// one account that held an address and another that holds it now — and the
	// next registration for a lapsed address stops this projector on a duplicate
	// key. That happened, and it took the rebuild with it: the table was no
	// longer reconstructable from position zero.
	//
	// Ordering is what makes this correct, and it is guaranteed rather than
	// assumed. The release is committed before the taking-over UserRegistered:
	// when Reserve takes over a lapsed claim it emits both in ONE multi-stream
	// append with the reservation stream first (app.Registration.appendBoth), and
	// when the sweep releases first it is a separate, earlier append. Live
	// consumption reads $all, so it sees them in commit order. A REBUILD sees the
	// same order because this projection's filter names an event-type PREFIX,
	// which resolves to neither exactly one type nor exactly one category — so
	// Runner.rebuildFromLinkStreams falls through to $all and never takes the
	// sharded link-stream path that gives up cross-aggregate ordering (ADR-044).
	// That is a property of the handler set, not a setting: this projection
	// handles six event types across two stream categories and cannot collapse
	// to one of either.
	//
	// There is deliberately no EmailReserved handler to clear the column again.
	// Every route back to an address mints a FRESH SubjectID — registration
	// always creates a new account, and identifier reuse after erasure is
	// explicitly a new subject (identity.md §7.5) — so no live path re-claims an
	// index for a subject that released it. A handler for a transition nothing
	// can perform is a handler nothing can test.
	d.On[contract.EmailReleased](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.EmailReleased,
	) error {
		// The reason is not projected, for the same reason the reservation
		// projection does not project it: a lapse, an address changed away from
		// and an erasure differ in what they mean and not in what this row must
		// say afterwards, which is "no longer held" in all three cases.
		w.Exec(identitydb.ReleaseUserEmailIndex,
			e.SubjectID, string(e.Index), e.ReleasedAt)
		return nil
	})

	// The public handle (ADR-051). Two handlers, on two streams, and the pair is
	// the only place in this system where a projection is asked to hold personal
	// data and to DELETE it.
	//
	// UsernameAssigned arrives on the ACCOUNT's stream and says which handle this
	// account answers to. UsernameTombstoned arrives on the HANDLE's own stream
	// and says the handle is burned — it carries no subject, deliberately, so
	// nothing links a tombstone back to the person it protects, and the statement
	// it drives is keyed by the handle instead.
	//
	// Ordering across the two is guaranteed the same way the EmailReleased
	// handler's is, and by the same property of this handler set: the filter names
	// an event-type PREFIX spanning three stream categories, which resolves to
	// neither exactly one type nor exactly one category, so a rebuild falls
	// through to $all and never takes the sharded link-stream path that gives up
	// cross-aggregate ordering (ADR-044). A rebuild therefore replays
	// assign-then-tombstone in commit order and lands on cleared, which is what an
	// erasure must survive: a rebuild that restored an erased handle would undo
	// the erasure every time the read model was rebuilt.
	d.On[contract.UsernameAssigned](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UsernameAssigned,
	) error {
		w.Exec(identitydb.AssignUsername, e.SubjectID, e.Username)
		return nil
	})

	d.On[contract.UsernameTombstoned](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UsernameTombstoned,
	) error {
		// Matching no row is the normal case on a replay, and it is not an error:
		// the first application cleared it, and there is nothing left to clear.
		w.Exec(identitydb.ClearUsername, e.Username)
		return nil
	})

	// UserDeletionRequested is NOT a state transition and is deliberately not in
	// the table below. The account keeps its lifecycle position — it keeps its
	// credentials and its sessions too — until `compliance` acts on the request,
	// and that module does not exist. Writing a state here would make this row
	// disagree with what every gate in the system still permits.
	//
	// Projected anyway, and now rather than when the consumer arrives, because
	// this row is the only place the request is visible to a person or an
	// operator until then, and because an event nothing projects is an event
	// whose REPLAY is never exercised — the first rebuild after the consumer
	// lands is the worst moment to find out it stops the projector.
	d.On[contract.UserDeletionRequested](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserDeletionRequested,
	) error {
		// Idempotent in the statement (`deletion_requested_at IS NULL`), not here:
		// a replay must leave the FIRST deadline standing, because that is the date
		// already mailed to the person (NOTIFICATIONS.md §4).
		w.Exec(identitydb.RecordDeletionRequest,
			e.SubjectID, e.RequestedAt, e.ScheduledFor)
		return nil
	})

	// A CANCELLATION CLEARS BOTH COLUMNS.
	//
	// It was missing when UserDeletionCancelled was added, and the consequence is
	// worse than a stale date: `deletion_requested_at` is what
	// RecordDeletionRequest's `IS NULL` guard tests, so a row left set makes a
	// LATER request a silent no-op here while the aggregate records one happily.
	// The log and the read model would then disagree about whether somebody is
	// scheduled for erasure, and the read model is what a screen shows and what
	// the overdue sweep reads.
	d.On[contract.UserDeletionCancelled](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserDeletionCancelled,
	) error {
		w.Exec(identitydb.ClearDeletionRequest, e.SubjectID)
		return nil
	})

	// ERASURE is a state like any other here, and it is terminal.
	//
	// The deletion columns are deliberately NOT cleared: "this account was
	// erased, and it was scheduled for that date" is the fact, and clearing them
	// would leave a row that looks like an account that simply stopped.
	d.On[contract.UserErased](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.UserErased,
	) error {
		w.Exec(identitydb.SetUserState, e.SubjectID, domain.StateErased.String())
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
