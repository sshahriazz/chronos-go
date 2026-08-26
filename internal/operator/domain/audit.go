package domain

import (
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// AuditCategory is the audit stream category, and it is PERMANENT.
const AuditCategory eventsourcing.Category = "operatoraudit"

// AuditStreamKey is the entry's own id — ONE STREAM PER ENTRY.
//
// # Why not one stream per operator, which is the obvious choice
//
// Because an audit entry is written on every read, and a stream per operator
// would make every page an operator opens an append to the same stream. That
// has three consequences and all three are bad: the stream grows without bound
// for the operator's whole employment, `Load` before append replays all of it,
// and two concurrent reads by one operator collide on the optimistic version
// precondition — so a support engineer opening two tabs gets a CONFLICT on a
// READ.
//
// One stream per entry costs nothing to write, never needs loading, and cannot
// contend. What it gives up is the ability to fold "everything operator X did"
// from a single stream, which is the projection's job anyway — that is what
// `operator_audit_log` is for, and it indexes by operator, by tenant and by
// time, none of which a stream ordering would have given.
func AuditStreamKey(entryID string) string { return entryID }

// AuditEntry is one recorded operator action.
//
// A single-event aggregate. It exists as an aggregate rather than as a bare
// append so that the audit path goes through the SAME repository, metadata,
// tracing and idempotency machinery as every other write in the system. An
// audit record written by a special-cased code path is an audit record with its
// own bugs.
type AuditEntry struct {
	eventsourcing.Base

	recorded bool
}

var _ eventsourcing.Root = (*AuditEntry)(nil)

// NewAuditEntry returns an empty aggregate for the repository to rebuild into.
func NewAuditEntry() *AuditEntry { return &AuditEntry{} }

// Recorded reports whether this entry already exists.
func (a *AuditEntry) Recorded() bool { return a.recorded }

// Apply rebuilds state from the log.
func (a *AuditEntry) Apply(event eventsourcing.Event) {
	switch event.(type) {
	case *contract.OperatorSignedIn,
		*contract.OperatorSignedOut,
		*contract.OperatorElevated,
		*contract.OperatorElevationExpired,
		*contract.OperatorAccessManaged,
		*contract.OperatorChangedTenant,
		*contract.OperatorViewedCustomer,
		*contract.OperatorViewedPersonalData:
		a.recorded = true
	}
}

// RecordSignIn records a completed sign-in — both factors.
func (a *AuditEntry) RecordSignIn(ev contract.OperatorSignedIn) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: a sign-in record needs an operator")
	case ev.SessionID == "":
		return fmt.Errorf("operator: a sign-in record needs a session")
	}
	ev.SignedInAt = ev.SignedInAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordSignOut records a deliberately ended session.
func (a *AuditEntry) RecordSignOut(ev contract.OperatorSignedOut) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: a sign-out record needs an operator")
	case ev.SessionID == "":
		return fmt.Errorf("operator: a sign-out record needs a session")
	}
	ev.SignedOutAt = ev.SignedOutAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordElevation records a break-glass, and REFUSES one with no justification.
//
// The same three-layer enforcement RecordPersonalDataView has, and for the same
// reason: this is the other act on this plane whose lawfulness rests on the
// account of why it was taken. A break-glass with no recorded reason is a
// record that somebody broke the glass and nothing else.
func (a *AuditEntry) RecordElevation(ev contract.OperatorElevated) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: an elevation record needs an operator")
	case ev.SessionID == "":
		return fmt.Errorf("operator: an elevation is scoped to a session and needs one")
	case ev.Capability == "":
		return fmt.Errorf("operator: an elevation record needs the capability granted")
	case ev.Reason == "":
		return fmt.Errorf("operator: a break-glass requires a recorded justification")
	case !ev.ExpiresAt.After(ev.ElevatedAt):
		// An elevation that expires at or before it began is either a clock
		// problem or a zero deadline, and the second reads as "never expires"
		// to anything comparing against it.
		return fmt.Errorf("operator: an elevation must expire after it begins")
	}
	ev.ElevatedAt = ev.ElevatedAt.UTC()
	ev.ExpiresAt = ev.ExpiresAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordElevationExpiry closes the window in the log.
//
// It carries no justification, and that is right: the justification belongs to
// the act of breaking the glass, and repeating it here would put the same free
// text in the log twice.
func (a *AuditEntry) RecordElevationExpiry(ev contract.OperatorElevationExpired) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: an expiry record needs an operator")
	case ev.SessionID == "":
		return fmt.Errorf("operator: an expiry record needs a session")
	case ev.Capability == "":
		return fmt.Errorf("operator: an expiry record needs the capability that lapsed")
	}
	ev.ExpiredAt = ev.ExpiredAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordOperatorManaged records a change to who may use this plane.
func (a *AuditEntry) RecordOperatorManaged(ev contract.OperatorAccessManaged) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: an access-management record needs an actor")
	case ev.Change == "":
		return fmt.Errorf("operator: an access-management record needs to say what changed")
	}
	ev.ManagedAt = ev.ManagedAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordTenantWrite records an operator change to a tenant, and REFUSES one
// with no justification.
//
// The third act on this plane whose lawfulness rests on the account of why it
// was taken — beside a personal-data read and a break-glass — and enforced the
// same three ways: protovalidate at the edge, here, and a CHECK constraint.
func (a *AuditEntry) RecordTenantWrite(ev contract.OperatorChangedTenant) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: a tenant-change record needs an operator")
	case ev.OrgID == "":
		return fmt.Errorf("operator: a tenant-change record names exactly one organization")
	case ev.Change == "":
		return fmt.Errorf("operator: a tenant-change record needs to say what changed")
	case ev.Reason == "":
		return fmt.Errorf("operator: changing a tenant requires a recorded justification")
	}
	ev.ChangedAt = ev.ChangedAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordView records a read of one tenant's operator-plane record.
//
// OrgID is deliberately NOT required: a list view is an aggregate over many
// tenants, and naming one of them would be false. What is required is the
// method, because the audit's unit is the action.
func (a *AuditEntry) RecordView(ev contract.OperatorViewedCustomer) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: a view record needs an operator")
	case ev.Method == "":
		return fmt.Errorf("operator: a view record needs the method that was called")
	}
	ev.ViewedAt = ev.ViewedAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// RecordPersonalDataView records a vault resolution, and REFUSES one with no
// justification.
//
// The refusal is here, in the domain, rather than only in the request
// validator. Both are wanted — protovalidate gives the caller a useful error —
// but the rule that a justified-access-only path cannot record an unjustified
// access is an invariant of the record itself, and an invariant enforced only
// at the edge is an invariant that a second caller can skip.
func (a *AuditEntry) RecordPersonalDataView(ev contract.OperatorViewedPersonalData) error {
	switch {
	case a.recorded:
		return fmt.Errorf("operator: audit entry already recorded")
	case ev.OperatorID == "":
		return fmt.Errorf("operator: a personal-data record needs an operator")
	case ev.TargetSubjectID == "":
		return fmt.Errorf("operator: a personal-data record needs a target subject")
	case ev.Reason == "":
		return fmt.Errorf("operator: personal-data access requires a recorded justification")
	case len(ev.Fields) == 0:
		return fmt.Errorf("operator: a personal-data record needs the fields that were resolved")
	case ev.Method == "":
		return fmt.Errorf("operator: a personal-data record needs the method that was called")
	}
	ev.ViewedAt = ev.ViewedAt.UTC()
	eventsourcing.Record(a, &ev)
	return nil
}

// AuditAt normalises the instant an entry is stamped with.
//
// A helper rather than an inline `.UTC()` because every recorder needs it and a
// missed one produces an audit trail whose ordering depends on the process's
// timezone — which is exactly the kind of defect that surfaces only when
// somebody tries to use the trail as evidence.
func AuditAt(t time.Time) time.Time { return t.UTC() }
