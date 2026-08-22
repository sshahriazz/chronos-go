// Package projection writes the authorization graph from the event log.
//
// Tuples are a PROJECTION; the event log is truth (ADR-013, access.md §11). This
// is the only thing in the system that writes them — access.md §15 puts
// TupleWriter behind a projector-only boundary, because a use case that wrote a
// tuple directly would have bypassed the log and created drift nothing can
// reconcile.
package projection

import (
	"context"
	"fmt"

	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	workspacecontract "github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/platform/authz"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Name is permanent: it keys the checkpoint row, so renaming it silently
// restarts the projection from zero — which for this one means rebuilding the
// entire authorization graph.
const Name = "access_tuples"

// Writer is the tuple side of the graph.
type Writer interface {
	Write(ctx context.Context, tuples []authz.Tuple) error
	Delete(ctx context.Context, tuples []authz.Tuple) error
}

// Tuples writes the authorization graph.
//
// It is NOT a db projection: it has no table, and its output is OpenFGA. That is
// why it implements the reactor shape rather than projection.Projection — the
// platform's projector writes rows and its checkpoint in one transaction, which
// is exactly the guarantee an external service cannot give.
type Tuples struct {
	writer Writer
	codec  eventsourcing.Codec
}

func NewTuples(writer Writer, codec eventsourcing.Codec) (*Tuples, error) {
	if writer == nil {
		return nil, fmt.Errorf("access: a tuple writer is required")
	}
	if codec == nil {
		return nil, fmt.Errorf("access: a codec is required")
	}
	return &Tuples{writer: writer, codec: codec}, nil
}

func (t *Tuples) Name() string { return Name }

// Filter narrows $all to the modules that own resource types.
//
// Identity is absent on purpose: every identity RPC is self-scoped, so no
// identity event grants anything in the graph.
func (t *Tuples) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{
			string(orgdomain.Category) + "-",
			"workspace-",

			// Memberships live in their OWN category: one stream per person per
			// workspace, so a join never contends with another join for the same
			// revision (workspace.md §1). A filter naming only `workspace-`
			// would silently skip every join, role change and removal — and
			// silently is the operative word, because grants that never land
			// deny, and denying is what a healthy graph looks like from outside.
			"membership-",
		},
	}
}

// React writes or deletes the tuples one event implies.
//
// # Why writes are idempotent and deletes tolerant
//
// Delivery is at-least-once and a rebuild replays everything, so every event
// here WILL be applied more than once. The writer uses `on_duplicate: ignore`
// for exactly that reason; a delete of a tuple that is already gone is likewise
// not an error.
func (t *Tuples) React(ctx context.Context, env eventsourcing.Envelope) error {
	decoded, err := t.codec.Unmarshal(env.Type, env.Payload)
	if err != nil {
		return fmt.Errorf("%w: decoding %s: %w", eventsourcing.ErrPoison, env.Type, err)
	}

	switch e := decoded.(type) {
	case *orgcontract.OrganizationCreated:
		// The FIRST tuple for an organization. organization.md §4 has it written
		// by a billing-driven reactor because ownership came from payment; with
		// a cardless trial the creator owns it from the first event, so it is
		// written from that event instead.
		return t.writer.Write(ctx, []authz.Tuple{owner(e.OrgID, e.OwnerID)})

	case *orgcontract.OrgAdminAdded:
		return t.writer.Write(ctx, []authz.Tuple{orgAdmin(e.OrgID, e.AdminID)})

	case *orgcontract.OrgAdminRemoved:
		return t.writer.Delete(ctx, []authz.Tuple{orgAdmin(e.OrgID, e.AdminID)})

	case *workspacecontract.WorkspaceCreated:
		// TWO tuples, and the parent edge is the important one: it is what makes
		// every org admin an admin of this workspace, present and future, with
		// no fan-out (organization.md §5.1). Without it the workspace is
		// reachable only by its direct admins, and the organization is locked
		// out of its own data.
		return t.writer.Write(ctx, []authz.Tuple{
			workspaceParent(e.WorkspaceID, e.OrgID),
			workspaceAdmin(e.WorkspaceID, e.CreatedBy),
		})

	case *workspacecontract.WorkspaceAdminAdded:
		return t.writer.Write(ctx, []authz.Tuple{workspaceAdmin(e.WorkspaceID, e.AdminID)})

	case *workspacecontract.WorkspaceAdminRemoved:
		return t.writer.Delete(ctx, []authz.Tuple{workspaceAdmin(e.WorkspaceID, e.AdminID)})

	case *workspacecontract.MemberJoined:
		// One tuple, and only for a role that holds one. An admin's `admin` edge
		// comes from WorkspaceAdminAdded on the workspace's own stream, not from
		// here: the two appends are separate, and the use case orders them so
		// that a failure leaves somebody a member without the admin grant rather
		// than the reverse. Writing `admin` here as well would undo that
		// ordering by granting from the append that is meant to be the safe one.
		return t.writer.Write(ctx, workspaceMember(e.WorkspaceID, e.SubjectID, e.Role))

	case *workspacecontract.MemberRoleChanged:
		// Delete first, then write. Both orders converge, but this one never has
		// the person holding the union of the two roles — and a promotion is far
		// more common than a demotion, so the union is the permissive direction.
		if err := t.writer.Delete(ctx, workspaceMember(e.WorkspaceID, e.SubjectID, e.From)); err != nil {
			return err
		}
		return t.writer.Write(ctx, workspaceMember(e.WorkspaceID, e.SubjectID, e.To))

	case *workspacecontract.MemberRemoved:
		// This is what CONFIRMS the tombstone the removal handler laid. The
		// writer deletes the tuple and then clears it, in that order, so a
		// deletion that fails leaves the tombstone denying (ADR-045).
		return t.writer.Delete(ctx, workspaceMember(e.WorkspaceID, e.SubjectID, e.Role))
	}

	// Every other event on these streams reaches here and grants nothing. Not an
	// error: a rename does not change who may touch a thing.
	return nil
}

func owner(orgID, subjectID string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID}},
		Relation: "owner",
		Resource: authz.ResourceRef{Type: "organization", ID: orgID},
	}
}

func orgAdmin(orgID, subjectID string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID}},
		Relation: "admin",
		Resource: authz.ResourceRef{Type: "organization", ID: orgID},
	}
}

// workspaceParent is the object-to-object edge the whole topology rests on.
func workspaceParent(workspaceID, orgID string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Object: authz.ResourceRef{Type: "organization", ID: orgID}},
		Relation: "parent",
		Resource: authz.ResourceRef{Type: "workspace", ID: workspaceID},
	}
}

func workspaceAdmin(workspaceID, subjectID string) authz.Tuple {
	return authz.Tuple{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID}},
		Relation: "admin",
		Resource: authz.ResourceRef{Type: "workspace", ID: workspaceID},
	}
}

// workspaceMember is the membership edge, or nothing at all.
//
// A GUEST gets no tuple. Guests are structurally the absence of the membership
// edge (access.md §7.6) rather than a role with deny rules, so there is nothing
// to write — and a nil slice is what both Write and Delete take to mean "no
// work", which is why every membership handler can call this unconditionally.
func workspaceMember(workspaceID, subjectID string, role workspacecontract.MemberRole) []authz.Tuple {
	if role == workspacecontract.RoleGuest {
		return nil
	}
	return []authz.Tuple{{
		Subject:  authz.Subject{Principal: authz.Principal{Kind: authz.KindUser, ID: subjectID}},
		Relation: "member",
		Resource: authz.ResourceRef{Type: "workspace", ID: workspaceID},
	}}
}
