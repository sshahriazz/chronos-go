// Package projection builds the operator plane's read models.
//
// # These run inside cmd/operator, not cmd/projector
//
// cmd/projector connects as chronos_app, and chronos_app is REVOKED from every
// operator table (migration 00037). That revoke is what keeps the tenant plane
// out of the operator plane's data, and it would be worthless if the tenant
// plane's projector held the grant needed to write these tables.
//
// So the operator binary runs its own catch-up subscriptions as
// chronos_operator. One more responsibility on a process that has to be running
// anyway, in exchange for an isolation boundary a misconfigured DSN cannot
// cross.
package projection

import (
	"context"

	operatordb "github.com/chronos/chronos-go/gen/sqlc/operator"
	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// AccountsName is permanent: it keys the checkpoint row and the single-writer
// lease, so renaming it silently restarts from zero.
const AccountsName = "operator_account"

// Accounts builds `operator_account` — who may sign in, and as what.
//
// # This projection is on the authentication path, which is unusual here
//
// Most read models in this system tolerate lag: a poll that is a second behind
// corrects itself on the next one. This one decides whether an operator can
// sign in and whether their live session still works, so its lag is the width
// of the window in which an OFFBOARDED employee still reads every customer.
//
// That is a deliberate trade rather than an oversight. The alternative — read
// the operator's stream on every request — would put an event-store round trip
// in front of every call and still be a snapshot, just a more expensive one.
// What makes the lag acceptable is that it is bounded by the projector's own
// lateness, which is alerted on, and that the disable path in cmd/operator ALSO
// ends the operator's sessions directly. Neither alone is sufficient; together
// the window is the shorter of the two.
type Accounts struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Accounts)(nil)

// NewAccounts wires the handlers.
func NewAccounts(codec eventsourcing.Codec) *Accounts {
	d := projection.NewDispatch(codec)

	d.On[contract.OperatorProvisioned](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OperatorProvisioned,
	) error {
		w.Exec(operatordb.UpsertOperatorAccount,
			e.OperatorID, e.SubjectID, e.Issuer, e.ProviderSubject,
			string(e.Role), nil, e.ProvisionedAt)
		return nil
	})

	// A role change is an UPDATE rather than the upsert above, because it does
	// not carry issuer or provider_subject and an upsert would insert a row
	// with empty identity columns if it ever ran first. It cannot: a catch-up
	// subscription preserves order within a stream, so the provisioning is
	// always applied before any change to it.
	d.On[contract.OperatorRoleChanged](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OperatorRoleChanged,
	) error {
		w.Exec(operatordb.SetOperatorRole, e.OperatorID, string(e.NewRole))
		return nil
	})

	// The disable sets one column and leaves the role alone. A disabled
	// operator's role still matters: the audit trail says what they could do
	// while they had access.
	d.On[contract.OperatorDisabled](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OperatorDisabled,
	) error {
		w.Exec(operatordb.DisableOperatorAccount, e.OperatorID, e.DisabledAt)
		return nil
	})

	return &Accounts{dispatch: d}
}

func (a *Accounts) Name() string { return AccountsName }

// Filter covers operator streams only.
func (a *Accounts) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.OperatorCategory) + "-"},
	}
}

func (a *Accounts) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return a.dispatch.Apply(ctx, w, env)
}

func (a *Accounts) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, operatordb.TruncateOperatorAccounts)
	return err
}
