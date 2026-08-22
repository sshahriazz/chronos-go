package projection

import (
	"context"

	workspacedb "github.com/chronos/chronos-go/gen/sqlc/workspace"
	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// InvitationsName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts the projection from zero.
const InvitationsName = "invitation_view"

// Invitations builds `invitation_view`.
//
// # It is not authority for anything
//
// Every decision on the invitation paths — accept, decline, revoke, resend —
// reads the AGGREGATE. A projection is behind the log by construction, so a
// decision taken from one can be taken twice with two different answers, and
// each of those decisions spends a seat or a credential. This table answers
// three questions that tolerate lag: who is outstanding in a workspace, what is
// about to expire, and what a departing inviter left behind.
type Invitations struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Invitations)(nil)

// NewInvitations wires the handlers.
//
// # Every settlement shares one statement
//
// Five terminal states, one UPDATE, differing only in the status written. The
// alternative — a handler per state with its own query — is five places to
// forget `settled_at`, and the one that forgot it would look right on every
// screen while making "how long did this sit" unanswerable.
func NewInvitations(codec eventsourcing.Codec) *Invitations {
	d := projection.NewDispatch(codec)

	d.On[contract.InvitationIssued](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationIssued,
	) error {
		w.Exec(workspacedb.UpsertInvitation,
			e.InvitationID, e.WorkspaceID, e.OrgID, e.SubjectID, e.EmailIndex,
			e.InvitedBy, string(e.Role), e.ExpiresAt, e.IssuedAt)
		return nil
	})

	// A resend moved the deadline, and the deadline is the SWEEP'S key. Without
	// this the invitation is swept at its original expiry and its seat returned
	// while a live link is still in somebody's inbox.
	d.On[contract.InvitationTokenRotated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationTokenRotated,
	) error {
		w.Exec(workspacedb.ExtendInvitation, e.InvitationID, e.ExpiresAt)
		return nil
	})

	d.On[contract.InvitationAccepted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationAccepted,
	) error {
		w.Exec(workspacedb.SettleInvitation, e.InvitationID,
			string(domain.InvitationAccepted), e.AcceptedAt)
		return nil
	})

	d.On[contract.InvitationRevoked](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationRevoked,
	) error {
		w.Exec(workspacedb.SettleInvitation, e.InvitationID,
			string(domain.InvitationRevoked), e.RevokedAt)
		return nil
	})

	d.On[contract.InvitationDeclined](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationDeclined,
	) error {
		w.Exec(workspacedb.SettleInvitation, e.InvitationID,
			string(domain.InvitationDeclined), e.DeclinedAt)
		return nil
	})

	d.On[contract.InvitationExpired](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationExpired,
	) error {
		w.Exec(workspacedb.SettleInvitation, e.InvitationID,
			string(domain.InvitationExpired), e.ExpiredAt)
		return nil
	})

	d.On[contract.InvitationUndeliverable](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.InvitationUndeliverable,
	) error {
		w.Exec(workspacedb.SettleInvitation, e.InvitationID,
			string(domain.InvitationUndeliverable), e.BouncedAt)
		return nil
	})

	return &Invitations{dispatch: d}
}

func (i *Invitations) Name() string { return InvitationsName }

// Filter covers invitation streams only.
func (i *Invitations) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.InvitationCategory) + "-"},
	}
}

func (i *Invitations) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return i.dispatch.Apply(ctx, w, env)
}

func (i *Invitations) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, workspacedb.TruncateInvitations)
	return err
}
