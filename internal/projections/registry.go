// Package projections is the registry of every read model in the system.
//
// # Why this is a package rather than a function in cmd/projector
//
// It lived in cmd/projector, which is a main package and therefore importable
// by nothing. Every other process that needs to run projections — the
// protocol integration harness, a rebuild tool, anything that comes later —
// had to restate the list, and a restated list is a list that drifts.
//
// It drifted twice, and both times silently. Compliance's two projections were
// missing from the harness, so two read models were permanently empty and
// anything reading them "passed" by never being exercised. Then identity's API
// key projection was missing the same way, and every service account created
// through the running server was invisible to the command that mints keys for
// it — which surfaces as `not_found: no such service account` against a
// service account that demonstrably exists.
//
// A test was written to compare the two lists by name. It could not work: it
// compared against a THIRD hand-written list, so it caught only the drift
// somebody had already noticed. The failure is not that the copies disagree —
// it is that there are copies.
//
// So there is one list, here, and everything that runs projections calls it.
package projections

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	billingprojection "github.com/chronos/chronos-go/internal/modules/billing/projection"
	complianceprojection "github.com/chronos/chronos-go/internal/modules/compliance/projection"
	identityprojection "github.com/chronos/chronos-go/internal/modules/identity/projection"
	notificationprojection "github.com/chronos/chronos-go/internal/modules/notification/projection"
	organizationprojection "github.com/chronos/chronos-go/internal/modules/organization/projection"
	profileprojection "github.com/chronos/chronos-go/internal/modules/profile/projection"
	workspaceprojection "github.com/chronos/chronos-go/internal/modules/workspace/projection"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// All is every read model in the system.
//
// A projection that is not in this list does not run — which is the intended
// way to retire one, and the reason the list is worth reading before a deploy.
func All(codec *eventcodec.JSON) []projection.Projection {
	return []projection.Projection{
		// One projection per table. Two writers to one table makes rebuild
		// order undefined (CONVENTIONS §8).
		notificationprojection.NewFeed(codec),
		notificationprojection.NewPushSubscriptions(codec),
		notificationprojection.NewPreferences(codec),

		profileprojection.NewProfile(codec),

		organizationprojection.NewStatus(codec),

		// Billing's invoice mirror. Its own projection because it is its own
		// table, and its own STREAM CATEGORY because an invoice is Stripe's
		// object rather than part of the organization's lifecycle.
		billingprojection.NewInvoices(codec),

		// Article 18 restrictions. Its absence is silent in the dangerous
		// direction: an empty table reads as "nobody is restricted", so
		// processing resumes for exactly the people who asked it to stop.
		complianceprojection.NewRestrictions(codec),

		// Article 21 objections. Its absence fails in the same direction as the
		// restriction above and is easier to miss, because it costs less when it
		// happens: an empty table reads as "nobody has objected", so activity and
		// product mail resumes for the people who stopped it. Nothing errors, no
		// metric moves, and the only signal is a complaint from somebody who
		// already told us once.
		complianceprojection.NewObjections(codec),

		// Data-subject export requests. Its absence is silent in a different
		// direction from the one above: the workflow still builds the bundle and
		// still records the outcome in the log, but the subject's poll finds no
		// row — so a completed export reads as a request that was never made, and
		// the person is told to ask again for something they already have.
		complianceprojection.NewExports(codec),

		// Both membership projections belong to WORKSPACE, including the one
		// that builds `org_member_index`: belonging to an organization comes
		// from organization events AND from workspace joins, one table has one
		// writer, and `workspace -> organization` is the only direction the
		// dependency may run (ADR-020).
		workspaceprojection.NewOrgMembers(codec),
		workspaceprojection.NewMembers(codec),
		workspaceprojection.NewInvitations(codec),
		workspaceprojection.NewTeams(codec),

		identityprojection.NewUser(codec),
		identityprojection.NewSession(codec),
		identityprojection.NewReservation(codec),

		// Service accounts and API keys (identity.md §10). ORG-SCOPED, unlike
		// every other identity projection: its two tables carry row-level
		// security, so every statement it queues runs under the tenant scope taken
		// from the event's own metadata (projection.ScopeOf). An API key event
		// appended without an OrgID would stop this projection on the policy's
		// WITH CHECK rather than be projected into no tenant, which is the correct
		// direction for that mistake to fail in.
		//
		// Its absence is what made a service account created through the running
		// server invisible to the command that mints keys for it.
		identityprojection.NewAPIKey(codec),
	}
}
