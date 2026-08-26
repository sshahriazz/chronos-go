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
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionSignedIn), "sign_in",
			nil, nil, nil, nil, nullText(e.FromIP), e.SignedInAt)
		return nil
	})

	d.On[contract.OperatorSignedOut](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorSignedOut,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionSignedOut), "sign_out",
			nil, nil, nil, nil, nil, e.SignedOutAt)
		return nil
	})

	// The break-glass pair. `reason` carries the justification on the grant and
	// deliberately not on the expiry: the justification belongs to the act of
	// breaking the glass, and repeating it would put the same free text in the
	// log twice.
	d.On[contract.OperatorElevated](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorElevated,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionElevated), e.Capability,
			nil, nil, nil, nullText(e.Reason), nil, e.ElevatedAt)
		return nil
	})

	// `used` rides in the FIELDS column, which is a string array and otherwise
	// unused on this action. A dedicated column would be a fifth nullable that
	// one action out of six populates; the array already means "what this entry
	// is about", and "used" or "unused" is exactly that here.
	d.On[contract.OperatorElevationExpired](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorElevationExpired,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionElevationExpired), e.Capability,
			nil, nil, []string{usedLabel(e.Used)}, nil, nil, e.ExpiredAt)
		return nil
	})

	// The CHANGE rides in the fields array, for the reason usedLabel does: the
	// array already means "what this entry is about", and a dedicated column
	// would be a nullable that one action out of seven populates.
	d.On[contract.OperatorAccessManaged](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorAccessManaged,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionManagedOperators), e.Change,
			nil, nullText(e.TargetOperatorID), nil, nil, nullText(e.FromIP), e.ManagedAt)
		return nil
	})

	d.On[contract.OperatorChangedTenant](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorChangedTenant,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionChangedTenant), e.Change,
			nullText(e.OrgID), nullText(e.TargetSubjectID), nil,
			nullText(e.Reason), nullText(e.FromIP), e.ChangedAt)
		return nil
	})

	d.On[contract.OperatorViewedCustomer](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorViewedCustomer,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionViewedCustomer), e.Method,
			nullText(e.OrgID), nil, nil, nil, nullText(e.FromIP), e.ViewedAt)
		return nil
	})

	d.On[contract.OperatorViewedPersonalData](func(
		_ context.Context, w db.Writer, env projection.Envelope, e *contract.OperatorViewedPersonalData,
	) error {
		w.Exec(operatordb.InsertAuditEntry,
			entryID(env), e.OperatorID, e.SubjectID, string(domain.ActionViewedPersonalData), e.Method,
			nullText(e.OrgID), nullText(e.TargetSubjectID), e.Fields, nullText(e.Reason),
			nullText(e.FromIP), e.ViewedAt)
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

// nullText renders an empty string as SQL NULL.
//
// One helper for every optional column, including the `inet` one — an earlier
// version had a second, byte-identical `nullIP` beside it, which is two things
// to keep correct and one place for them to drift.
//
// # What the `inet` column relies on it for
//
// A malformed origin becomes NULL rather than failing the insert. The address
// is EVIDENCE, not an authorization input, so losing it must not stop the audit
// row being written — the alternative would let a header somebody else controls
// suppress the record of their own access.
//
// The guard treats the same input in the opposite way, and deliberately: there
// the address IS the input to an access decision, and a decision that cannot be
// made must fail closed. Same value, two questions, two answers.
func nullText(s string) *string {
	if s == "" {
		return nil
	}
	return &s
}

// usedLabel renders whether a break-glass was exercised, for the audit row.
//
// An elevation nobody used is a false alarm, and telling it apart from one that
// was needed is the difference between an alert people act on and one they
// mute.
func usedLabel(used bool) string {
	if used {
		return "used"
	}
	return "unused"
}
