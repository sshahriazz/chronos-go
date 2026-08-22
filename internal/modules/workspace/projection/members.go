// Package projection builds workspace's read models.
package projection

import (
	"context"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// OrgMembersName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
//
// It kept the name it had in the organization module, because the checkpoint is
// keyed on it and a rename is a rebuild.
const OrgMembersName = "org_member_index"

// OrgMembers builds `org_member_index`, which gate 1 verifies against.
//
// # Why it lives in the workspace module
//
// Belonging to an organization has two sources: an organization event grants it
// directly, and a workspace join grants it as a consequence. One table has
// exactly one writer (CONVENTIONS §8) — two would make rebuild order undefined —
// so a single projection has to consume both sets of events.
//
// `workspace -> organization` is the only permitted direction (ADR-020), so the
// module that may import the other's contract is this one. The projection
// therefore lives here and organization keeps the reads, which is what gate 1
// does with the table.
type OrgMembers struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*OrgMembers)(nil)

// NewOrgMembers wires the handlers.
//
// # The owner is a member, from the creation event
//
// Not a later grant: an organization whose creator was not yet a member would
// have a window in which its own owner could not resolve it as their tenant
// scope — and gate 1 runs before everything, so that window is one in which they
// can do nothing at all.
func NewOrgMembers(codec eventsourcing.Codec) *OrgMembers {
	d := projection.NewDispatch(codec)

	d.On[orgcontract.OrganizationCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrganizationCreated,
	) error {
		w.Exec(workspacedb.UpsertOrgMember, e.OrgID, e.OwnerID, "owner", e.CreatedAt)
		return nil
	})

	d.On[orgcontract.OrgAdminAdded](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrgAdminAdded,
	) error {
		w.Exec(workspacedb.UpsertOrgMember, e.OrgID, e.AdminID, "admin", e.AddedAt)
		return nil
	})

	// Removing an ADMIN removes the membership their admin grant created. It
	// does NOT remove one a workspace join created: those rows carry a workspace
	// role, and this statement rewrites the row rather than deleting it only
	// because there is no such row to keep today. When an org admin can also be
	// an ordinary member this becomes a demotion.
	d.On[orgcontract.OrgAdminRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *orgcontract.OrgAdminRemoved,
	) error {
		w.Exec(workspacedb.RemoveOrgMember, e.OrgID, e.AdminID)
		return nil
	})

	// A workspace join makes somebody an organization member, which is what lets
	// them resolve the tenant at gate 1 at all. Without this handler a person
	// added to a workspace could authenticate and then do NOTHING: gate 1 would
	// refuse to resolve an organization they demonstrably belong to, and the
	// refusal is NOT_FOUND, so the symptom is a workspace that does not appear
	// to exist.
	//
	// IfAbsent, never an upsert. The workspace role is not the organization
	// role: writing `guest` over `owner` would demote somebody out of their own
	// organization with no event that says so.
	d.On[contract.MemberJoined](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.MemberJoined,
	) error {
		w.Exec(workspacedb.InsertOrgMemberIfAbsent, e.OrgID, e.SubjectID, string(e.Role), e.JoinedAt)
		return nil
	})

	// Only when the seat came back, which is the event's own record of "this was
	// their last membership in the organization". Deleting on every removal
	// would evict somebody who is still in four other workspaces, and gate 1
	// would then refuse them their own tenant.
	//
	// The statement additionally refuses to delete `owner` and `admin` rows, so
	// an owner leaving their last workspace keeps the organization they own.
	d.On[contract.MemberRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.MemberRemoved,
	) error {
		if !e.SeatReleased {
			return nil
		}
		w.Exec(workspacedb.RemoveOrgMemberIfWorkspaceOnly, e.OrgID, e.SubjectID)
		return nil
	})

	return &OrgMembers{dispatch: d}
}

func (m *OrgMembers) Name() string { return OrgMembersName }

// Filter spans BOTH sources of membership.
//
// Three prefixes, not two: memberships live in their own category (one stream
// per person per workspace, so a join never contends with another join for the
// same revision), and a filter that named only `workspace-` would silently
// ignore every membership event this projection exists to consume.
func (m *OrgMembers) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{
			string(orgdomain.Category) + "-",
			string(domain.Category) + "-",
			string(domain.MembershipCategory) + "-",
		},
	}
}

func (m *OrgMembers) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return m.dispatch.Apply(ctx, w, env)
}

func (m *OrgMembers) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, workspacedb.TruncateOrgMembers)
	return err
}
