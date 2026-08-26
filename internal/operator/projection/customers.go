package projection

import (
	"context"

	operatordb "github.com/chronos/chronos-go/gen/sqlc/operator"
	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	wscontract "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	wsdomain "github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// CustomersName is permanent: it keys the checkpoint row and the lease.
const CustomersName = "operator_customer_list"

// Customers builds `operator_customer_list` — the customer directory
// (operator.md §9).
//
// # It reads TENANT events and writes an OPERATOR table
//
// That direction is the only one allowed, and the depguard rule enforces it:
// `internal/modules/**` may not import `internal/operator`, while this package
// imports two module contracts. The operator plane is downstream of the tenant
// plane and never the reverse — a tenant module that knew about operators would
// be a tenant module whose behaviour could depend on who was watching.
//
// # What it does not project, and why the omission is the design
//
// There is no handler here for a workspace's NAME, a member's identity, an
// invitation, a team, or anything a tenant put inside their workspace. Not
// because those events are uninteresting, but because the table has no column
// to put them in — operator.md §4: "there is no query that COULD return
// customer content, the columns do not exist in the projection".
//
// Adding a handler here would therefore require adding a column first, which is
// exactly the reviewable step the design wants. And
// TestOperatorProjectionsHoldNoPersonalData asserts the column list against the
// live schema, so the migration that added one would fail the suite before the
// handler could be written.
type Customers struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Customers)(nil)

// NewCustomers wires the handlers.
func NewCustomers(codec eventsourcing.Codec) *Customers {
	d := projection.NewDispatch(codec)

	// ── Lifecycle ──────────────────────────────────────────────────────────

	d.On[orgcontract.OrganizationCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationCreated,
	) error {
		w.Exec(operatordb.UpsertCustomer, e.OrgID, e.Slug, e.Name, "active", e.CreatedAt)
		return nil
	})

	d.On[orgcontract.OrganizationActivated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationActivated,
	) error {
		// Clears the suspension columns as well as setting the state. An org
		// that was suspended and came back must not keep showing a reason:
		// a stale "payment failed" beside an active customer is what makes a
		// support engineer open with an apology for a problem that is fixed.
		w.Exec(operatordb.SetCustomerLifecycle, e.OrgID, "active", nil, nil)
		return nil
	})

	d.On[orgcontract.OrganizationPastDue](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationPastDue,
	) error {
		w.Exec(operatordb.SetCustomerLifecycle, e.OrgID, "past_due", nil, nil)
		return nil
	})

	d.On[orgcontract.OrganizationSuspended](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationSuspended,
	) error {
		reason := string(e.Reason)
		w.Exec(operatordb.SetCustomerLifecycle, e.OrgID, "suspended", e.SuspendedAt, &reason)
		return nil
	})

	d.On[orgcontract.OrganizationClosed](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationClosed,
	) error {
		w.Exec(operatordb.SetCustomerLifecycle, e.OrgID, "closed", nil, nil)
		return nil
	})

	// ── Billing ────────────────────────────────────────────────────────────

	d.On[orgcontract.OrganizationTrialStarted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationTrialStarted,
	) error {
		trialing := "trialing"
		w.Exec(operatordb.SetCustomerPlan, e.OrgID, nil, nil, &trialing, e.TrialEndsAt)
		return nil
	})

	// ── Activity ───────────────────────────────────────────────────────────

	d.On[wscontract.WorkspaceCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *wscontract.WorkspaceCreated,
	) error {
		w.Exec(operatordb.BumpCustomerWorkspaceCount, e.OrgID, int32(1))
		w.Exec(operatordb.TouchCustomerActivity, e.OrgID, e.CreatedAt)
		return nil
	})

	// ARCHIVED, not deleted: a workspace an org archived is one they may
	// restore, and a directory that counted it would tell a support engineer
	// the customer has more than they can currently use.
	d.On[wscontract.WorkspaceArchived](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *wscontract.WorkspaceArchived,
	) error {
		w.Exec(operatordb.BumpCustomerWorkspaceCount, e.OrgID, int32(-1))
		return nil
	})

	d.On[wscontract.WorkspaceRestored](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *wscontract.WorkspaceRestored,
	) error {
		w.Exec(operatordb.BumpCustomerWorkspaceCount, e.OrgID, int32(1))
		return nil
	})

	// The member count is a SEAT count, not a sum of memberships — five
	// workspaces and one person is one (workspace.md §2). That distinction is
	// only expressible because the events carry it: MemberJoined.SeatConsumed
	// is true exactly when the person was not already in the organization.
	//
	// Counting joins instead would have made the directory disagree with the
	// invoice, which is the number a support engineer is usually being asked
	// about.
	d.On[wscontract.MemberJoined](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *wscontract.MemberJoined,
	) error {
		if e.SeatConsumed {
			w.Exec(operatordb.BumpCustomerMemberCount, e.OrgID, int32(1))
		}
		w.Exec(operatordb.TouchCustomerActivity, e.OrgID, e.JoinedAt)
		return nil
	})

	d.On[wscontract.MemberRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *wscontract.MemberRemoved,
	) error {
		if e.SeatReleased {
			w.Exec(operatordb.BumpCustomerMemberCount, e.OrgID, int32(-1))
		}
		return nil
	})

	return &Customers{dispatch: d}
}

func (c *Customers) Name() string { return CustomersName }

// Filter covers three categories, and the third is easy to miss.
//
// Membership events live on `membership-`, NOT on `workspace-`: a membership is
// its own aggregate so that adding a person does not contend with every other
// change to the workspace. A filter of organization and workspace alone would
// therefore compile, run, and produce a directory whose member count is
// permanently zero — which reads as "this customer has nobody" rather than as a
// bug.
//
// Stream prefixes rather than a list of event types, because the filter must
// select on ONE dimension — KurrentDB matches streams or types, never both. It
// does mean this projection wakes for events it ignores; that is the cheaper
// mistake, because an event-type list would silently stop covering a lifecycle
// event somebody added later, and a directory that quietly stops tracking
// suspensions looks exactly like one where nobody is suspended.
func (c *Customers) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{
			string(orgdomain.Category) + "-",
			string(wsdomain.Category) + "-",
			string(wsdomain.MembershipCategory) + "-",
		},
	}
}

func (c *Customers) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return c.dispatch.Apply(ctx, w, env)
}

func (c *Customers) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, operatordb.TruncateCustomers)
	return err
}
