package app

import (
	"context"
	"crypto/rand"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/operator/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Auditor appends the operator plane's audit events.
//
// # It is a use case, not a middleware helper
//
// The temptation is to make auditing an interceptor concern: wrap every
// handler, write a row on the way out, done. That design fails on the one
// method where it matters most. RevealPersonalData must record the access
// BEFORE the vault is read, and it must fail the call if the record cannot be
// written — an interceptor that writes on the way out cannot do either, because
// by then the data has already been fetched and, on the error path, already
// returned.
//
// So the interceptor enforces that a policy DECLARES an audit action, and the
// handlers call this at the point in their own flow where the record is
// correct. The two together give "no endpoint without an audit entry" plus
// "recorded before the disclosure", which neither gives alone.
type Auditor struct {
	events EventAppender
	clock  Clock
}

// NewAuditor builds the recorder.
func NewAuditor(events EventAppender, clock Clock) *Auditor {
	return &Auditor{events: events, clock: clock}
}

// Actor is who is acting, resolved from the session by the interceptor.
type Actor struct {
	OperatorID string
	SubjectID  string
	Role       contract.Role
	SessionID  string
	FromIP     string
}

// RecordSignIn records a completed sign-in — both factors.
func (a *Auditor) RecordSignIn(ctx context.Context, actor Actor, credentialID string) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordSignIn(contract.OperatorSignedIn{
		OperatorID:   actor.OperatorID,
		SubjectID:    actor.SubjectID,
		SessionID:    actor.SessionID,
		CredentialID: credentialID,
		FromIP:       actor.FromIP,
		SignedInAt:   a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordSignOut records a deliberately ended session.
func (a *Auditor) RecordSignOut(ctx context.Context, actor Actor) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordSignOut(contract.OperatorSignedOut{
		OperatorID:  actor.OperatorID,
		SubjectID:   actor.SubjectID,
		SessionID:   actor.SessionID,
		SignedOutAt: a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordElevation records a break-glass.
func (a *Auditor) RecordElevation(
	ctx context.Context, actor Actor, capability, reason string, expiresAt time.Time,
) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordElevation(contract.OperatorElevated{
		OperatorID: actor.OperatorID,
		SubjectID:  actor.SubjectID,
		SessionID:  actor.SessionID,
		Capability: capability,
		Reason:     reason,
		ElevatedAt: a.clock.Now(),
		ExpiresAt:  expiresAt,
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordElevationExpiry closes a break-glass window in the log.
func (a *Auditor) RecordElevationExpiry(ctx context.Context, e ExpiredElevation) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordElevationExpiry(contract.OperatorElevationExpired{
		OperatorID: e.OperatorID,
		SubjectID:  e.SubjectID,
		SessionID:  e.SessionID,
		Capability: e.Capability,
		Used:       e.Used,
		ExpiredAt:  e.ExpiredAt,
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordOperatorManaged records a change to who may use this plane.
func (a *Auditor) RecordOperatorManaged(
	ctx context.Context, actor Actor, targetOperatorID, change string,
) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordOperatorManaged(contract.OperatorAccessManaged{
		OperatorID:       actor.OperatorID,
		SubjectID:        actor.SubjectID,
		TargetOperatorID: targetOperatorID,
		Change:           change,
		FromIP:           actor.FromIP,
		ManagedAt:        a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordTenantWrite records an operator change to a tenant.
func (a *Auditor) RecordTenantWrite(
	ctx context.Context, actor Actor, orgID, change, reason string,
) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordTenantWrite(contract.OperatorChangedTenant{
		OperatorID: actor.OperatorID,
		SubjectID:  actor.SubjectID,
		OrgID:      orgID,
		Change:     change,
		Reason:     reason,
		FromIP:     actor.FromIP,
		ChangedAt:  a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordSubjectWrite records an operator change scoped to a SUBJECT rather than
// to an organization — a legal hold, today.
//
// It reuses OperatorChangedTenant with the target in `TargetSubjectID` and no
// org, rather than adding a ninth action. The act is the same shape from the
// audit log's point of view: an operator changed something about a customer,
// with a justification, and the question a review asks is the same one.
func (a *Auditor) RecordSubjectWrite(
	ctx context.Context, actor Actor, subjectID, change, reason string,
) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordSubjectWrite(contract.OperatorChangedTenant{
		OperatorID:      actor.OperatorID,
		SubjectID:       actor.SubjectID,
		TargetSubjectID: subjectID,
		Change:          change,
		Reason:          reason,
		FromIP:          actor.FromIP,
		ChangedAt:       a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordView records a read of the directory or of one customer.
//
// orgID is empty on a list, and that is not an omission: a page is an aggregate
// over many tenants, so naming one of them would be false.
func (a *Auditor) RecordView(ctx context.Context, actor Actor, method, orgID string) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordView(contract.OperatorViewedCustomer{
		OperatorID: actor.OperatorID,
		SubjectID:  actor.SubjectID,
		OrgID:      orgID,
		Method:     method,
		FromIP:     actor.FromIP,
		ViewedAt:   a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

// RecordPersonalDataView records a vault resolution, and refuses one with no
// justification.
func (a *Auditor) RecordPersonalDataView(
	ctx context.Context, actor Actor, method, targetSubjectID, orgID string,
	fields []string, reason string,
) (string, error) {
	entryID, err := newAuditID(a.clock.Now())
	if err != nil {
		return "", err
	}
	entry := eventsourcing.NewAggregate(domain.NewAuditEntry)
	if err := entry.RecordPersonalDataView(contract.OperatorViewedPersonalData{
		OperatorID:      actor.OperatorID,
		SubjectID:       actor.SubjectID,
		TargetSubjectID: targetSubjectID,
		OrgID:           orgID,
		Fields:          fields,
		Reason:          reason,
		Method:          method,
		FromIP:          actor.FromIP,
		ViewedAt:        a.clock.Now(),
	}); err != nil {
		return "", err
	}
	return entryID, a.append(ctx, entryID, entry)
}

func (a *Auditor) append(ctx context.Context, entryID string, entry *domain.AuditEntry) error {
	pending := entry.Uncommitted()
	if len(pending) != 1 {
		// Every recorder above produces exactly one event. A different count
		// means the aggregate changed shape and the append below would silently
		// drop the rest.
		return fmt.Errorf("operator: an audit entry produced %d events, want 1", len(pending))
	}
	if err := a.events.AppendAudit(ctx, entryID, pending[0]); err != nil {
		return fmt.Errorf("recording an audit entry: %w", err)
	}
	return nil
}

// newAuditID mints an entry id.
//
// Random rather than derived, and it is worth saying why given how much of this
// codebase derives ids from an idempotency key. An audit entry is not
// idempotent: an operator who opens the same customer twice performed TWO
// processing activities, and collapsing them would produce an audit trail that
// under-reports access — the one direction an audit trail must never be wrong
// in.
func newAuditID(now time.Time) (string, error) {
	id := ids.New[ids.AuditEntry](now, rand.Reader)
	if id.String() == "" {
		return "", fmt.Errorf("operator: minting an audit entry id")
	}
	return id.String(), nil
}
