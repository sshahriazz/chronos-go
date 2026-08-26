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

// AuditLogName is permanent: it keys the checkpoint row and the lease.
const AuditLogName = "operator_audit_log"

// AuditLog builds `operator_audit_log` — every operator action, reads included.
//
// # It is a projection, and that is the point rather than a convenience
//
// The obvious alternative is to write the row directly from the handler and be
// done. It would be simpler and it would destroy the property the table exists
// for: a row written by a handler is a row a handler can decline to write, and
// an audit trail whose completeness depends on every call site remembering is
// not evidence.
//
// Built from the event log instead, the table is derived — so it can be
// truncated and rebuilt, and rebuilding it reproduces the same rows, because
// the authority is the append-only log rather than this table. An operator who
// could reach the database and delete a row would find it back after the next
// rebuild, and the rows they could not reach are the ones in KurrentDB.
type AuditLog struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*AuditLog)(nil)

// NewAuditLog wires the handlers.
func NewAuditLog(codec eventsourcing.Codec) *AuditLog {
	d := projection.NewDispatch(codec)

	d.On[contract.OperatorSignedIn](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorSignedIn,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, "signed_in", "sign_in",
			nil, nil, nil, nil, nullIP(e.FromIP), e.SignedInAt)
		return nil
	})

	d.On[contract.OperatorSignedOut](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorSignedOut,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, "signed_out", "sign_out",
			nil, nil, nil, nil, nil, e.SignedOutAt)
		return nil
	})

	d.On[contract.OperatorViewedCustomer](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorViewedCustomer,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, "viewed_customer", e.Method,
			nullText(e.OrgID), nil, nil, nil, nullIP(e.FromIP), e.ViewedAt)
		return nil
	})

	d.On[contract.OperatorViewedPersonalData](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorViewedPersonalData,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, "viewed_personal_data", e.Method,
			nullText(e.OrgID), nullText(e.TargetSubjectID), e.Fields, nullText(e.Reason),
			nullIP(e.FromIP), e.ViewedAt)
		return nil
	})

	return &AuditLog{dispatch: d}
}

func (a *AuditLog) Name() string { return AuditLogName }

// Filter covers the audit streams only.
func (a *AuditLog) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.AuditCategory) + "-"},
	}
}

func (a *AuditLog) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return a.dispatch.Apply(ctx, w, env)
}

func (a *AuditLog) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, operatordb.TruncateAuditLog)
	return err
}

// entryID recovers the entry's id from the STREAM NAME rather than from the
// event body.
//
// The events carry no entry id, deliberately: an event that named the stream it
// lives on would be a second copy of a fact the store already holds, and the two
// could disagree. The stream is `operatoraudit-<entry id>`, so the id is
// already there — and taking it from the envelope means the projection cannot
// write a row under an id no stream has.
func entryID(env projection.Envelope) string {
	return env.Stream.Key()
}

func nullText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// nullIP hands the `inet` column a NULL for anything it cannot parse.
//
// The address is evidence, not an authorization input. A malformed
// X-Forwarded-For must not stop the audit row being written — the alternative
// would let a header somebody else controls suppress the record of their own
// access.
func nullIP(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}
