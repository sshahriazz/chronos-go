package projection

import (
	"context"
	"fmt"

	notificationdb "github.com/chronos/chronos-go/gen/sqlc/notification"
	identitycontract "github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// userErasedType is the one event from outside this module that its projections
// consume.
//
// Taken from the contract type rather than written out, so it cannot drift from
// what the codec registers and identity appends — the same reason compliance's
// erasure reactor derives its filter that way. Identity's `contract` package is
// the only part of identity this module may import (CONVENTIONS §2), which is
// also why the filter below selects on event types rather than on identity's
// stream category: `UserCategory` lives in identity's `app` package and is not
// reachable from here, so a stream-prefix filter would have to spell "user-" as
// a literal that nothing checks.
var userErasedType = (&identitycontract.UserErased{}).EventType()

// subscription is the filter every projection in this module uses.
//
// # One filter, shared, on purpose
//
// All three projections consume the same two things: this module's own events,
// and the erasure that removes a subject from all three of its tables. Three
// copies of that would be three places to widen, and the one that got missed
// would be a projection whose erasure handler is registered and never called —
// the failure this codebase keeps hitting, and the one a filter with no test
// hides best.
//
// # Event types, not stream prefixes, and what that costs
//
// The filter must select on ONE dimension: a KurrentDB filter matches streams or
// types and never both, and a mixed one is refused at startup
// (eventsourcing.SubscriptionFilter.Validate). This module's events all carry
// the "notification." type prefix, and the erasure is named exactly, so the two
// fit on the type dimension together.
//
// It used to be `StreamPrefixes: {"notification-"}`, which was ONE whole
// category and therefore let a REBUILD read `$ce-notification` instead of
// scanning `$all` — measured 14.8x on a projection wanting 5% of the log
// (ADR-042). That is now lost, and it is worth being plain about why it is not
// recoverable rather than leaving it to be rediscovered: the runner uses a link
// stream only when the filter resolves to exactly ONE category or ONE whole
// event type (projection.Runner.rebuildFromLinkStreams), because replaying two
// in sequence applies all of the first before any of the second and loses global
// commit order. Two stream prefixes — "notification-" and "user-" — would fall
// back to `$all` for exactly the same reason, so no arrangement of this filter
// keeps the optimisation once an outside event is needed.
//
// What the type dimension buys over the stream one is the live path: the
// subscription is offered ONE identity event instead of every event on every
// account stream, which is most of the log on this system. A rebuild is rare and
// logs the fallback it takes; the live path runs forever.
func subscription() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		EventTypePrefixes: []string{"notification.", userErasedType},
	}
}

// onUserErased registers the handler that removes an erased subject's rows.
//
// # Why this is in the projection and not in an erasure use case
//
// Identity's session projection already answers this and the reasoning transfers
// unchanged (identity/projection/session.go, and `RevokeSessionsOfSubject` in
// db/query/identity/session.sql).
//
// Each of these tables has exactly one writer, which is the projection that owns
// it (CONVENTIONS §8), so a use case deleting from them would be a second path
// to the same rows — and two writers to one projection makes rebuild order
// undefined.
//
// And it must survive a REBUILD. Replaying `identity.UserErased.v1` re-runs
// this, so a projection rebuilt from position zero ends with the same empty set.
// A one-off DELETE issued once by a use case would replay into rows the same
// rebuild had just reinserted, and a rebuild that resurrected an erased person's
// push endpoint has no symptom anywhere: the browser simply starts receiving
// notifications for an account that no longer exists.
//
// # Why the scope statement comes first
//
// `UserErased` names no organization — an account is a fact about a person — so
// the projector's batch carries no `app.org_id`, and all three of these tables
// have row security keyed on it. Measured against the running server before
// migration 00052: the DELETE reported `DELETE 0` and the row was still there
// afterwards. The statement below names the subject the batch may reach, and the
// policy that migration adds admits exactly those rows and nothing else. It is
// transaction-local, so it ends with the batch.
//
// Passing the statements in rather than taking a table name keeps the SQL in
// .sql where sqlc checks it against the real schema (CONVENTIONS §8).
func onUserErased(d *projection.Dispatch, statements ...string) {
	d.On[identitycontract.UserErased](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *identitycontract.UserErased,
	) error {
		if e.SubjectID == "" {
			// STOPS the projection, and that is the right direction. The empty
			// string is not a subject: the scope statement would grant nothing,
			// the DELETEs would remove nothing, and the checkpoint would advance
			// past an erasure this module silently failed to perform. A retry
			// re-reads the same bytes, so this does not resolve itself — it is
			// meant to be seen.
			return fmt.Errorf("notification: %s names no subject, so no rows can be erased",
				userErasedType)
		}
		w.Exec(notificationdb.ScopeErasedSubject, e.SubjectID)
		for _, stmt := range statements {
			w.Exec(stmt, e.SubjectID)
		}
		return nil
	})
}
