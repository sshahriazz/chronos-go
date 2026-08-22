package projection

import (
	"context"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// MembersName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const MembersName = "org_member_index"

// Members builds `org_member_index`, which gate 1 verifies against.
type Members struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Members)(nil)

// NewMembers wires the handlers.
//
// # The owner is a member, from the creation event
//
// Not a later grant: an organization whose creator was not yet a member would
// have a window in which its own owner could not resolve it as their tenant
// scope — and gate 1 runs before everything, so that window is one in which they
// can do nothing at all.
func NewMembers(codec eventsourcing.Codec) *Members {
	d := projection.NewDispatch(codec)

	d.On[contract.OrganizationCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationCreated,
	) error {
		w.Exec(organizationdb.UpsertOrgMember, e.OrgID, e.OwnerID, "owner", e.CreatedAt)
		return nil
	})

	d.On[contract.OrgAdminAdded](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrgAdminAdded,
	) error {
		w.Exec(organizationdb.UpsertOrgMember, e.OrgID, e.AdminID, "admin", e.AddedAt)
		return nil
	})

	// Removing an ADMIN removes their membership, because admin is the only way
	// to belong to an organization today. When ordinary members exist this
	// becomes a demotion rather than a removal — the row stays and the role
	// changes — and this handler is where that distinction lands.
	d.On[contract.OrgAdminRemoved](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrgAdminRemoved,
	) error {
		w.Exec(organizationdb.RemoveOrgMember, e.OrgID, e.AdminID)
		return nil
	})

	return &Members{dispatch: d}
}

func (m *Members) Name() string { return MembersName }

func (m *Members) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.Category) + "-"},
	}
}

func (m *Members) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return m.dispatch.Apply(ctx, w, env)
}

func (m *Members) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, organizationdb.TruncateOrgMembers)
	return err
}
