package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
)

// Errors the tenant-write use cases return.
var (
	// ErrNoSuchOrganization means the org id names nothing in the event log.
	//
	// Distinct from ErrNoSuchCustomer, which means the DIRECTORY has no row.
	// The two differ during a projection rebuild, and the difference matters:
	// an org absent from the directory may still be suspendable, and an org
	// absent from the log is not.
	ErrNoSuchOrganization = errors.New("operator: no such organization")

	// ErrIllegalTransition means the organization is in a state this command
	// cannot move it out of.
	//
	// It carries the domain's own message, unlike most refusals here, for the
	// reason ErrElevationRefused does: the caller is an authenticated operator
	// acting deliberately, and "this org is closed" is what tells them to stop
	// rather than retry.
	ErrIllegalTransition = errors.New("operator: this organization cannot make that change")
)

// TenantOrganizations writes to the ORGANIZATION aggregate.
//
// # This is the cross-plane write, and it is the pattern the rest copy
//
// operator.md §7: "Operator writes go through the same domain commands as
// everything else — they emit the same events and honour the same invariants.
// There is no privileged back-channel that skips domain rules, because that
// back-channel is exactly what corrupts state that then cannot be replayed."
//
// So this port does not write rows and does not append an operator-flavoured
// event. It loads the tenant's own aggregate, calls the tenant's own command,
// and appends the tenant's own event to the tenant's own stream. The tenant's
// projections update, the tenant's notification fires, and the tenant's state
// machine refuses what it would refuse from any other caller.
//
// What is operator-specific is the AUDIT entry beside it, and the fact that
// this plane is allowed to make the call at all.
//
// # The direction is the only one allowed
//
// `internal/operator` importing `internal/modules/organization` is permitted;
// the reverse is denied by depguard. The operator plane is downstream of the
// tenant plane and never the reverse — a tenant module that knew about
// operators would be one whose behaviour could depend on who was watching.
type TenantOrganizations interface {
	// Suspend switches a tenant off, through the organization aggregate.
	//
	// It returns the organization's status BEFORE the call, so the use case can
	// report whether anything changed without a second read.
	Suspend(ctx context.Context, orgID string, reason orgcontract.SuspensionReason,
		at time.Time) (changed bool, err error)

	// Reinstate returns a suspended tenant to active.
	Reinstate(ctx context.Context, orgID string, at time.Time) (changed bool, err error)
}

// TenantLegalHolds writes compliance's LegalHold aggregate (compliance.md §7).
//
// # Why the operator plane is the only thing that can place one
//
// A hold has an owner and a recorded justification, and both are operator
// concerns — there is no tenant-facing action that produces either. The
// worklist named this as BLOCKED rather than unbuilt for exactly that reason: a
// LegalHold aggregate with no way to create a hold is a check that can only ever
// pass, which is the vacuous-test shape this repository has a name for.
//
// The direction is the same as every other cross-plane write: the operator
// plane calls compliance's own aggregate and appends compliance's own event.
type TenantLegalHolds interface {
	// Place holds a subject's data under a matter reference.
	Place(ctx context.Context, subjectID, placedBy, matter string, at time.Time) error

	// Lift releases them, and reports whether anything changed.
	Lift(ctx context.Context, subjectID, liftedBy string, at time.Time) (changed bool, err error)
}

// ErrHoldRefused means the hold could not be placed, and carries the domain's
// own message.
//
// The commonest cause is a subject already held under another matter, which the
// compliance aggregate refuses rather than absorbing — one stream per subject
// means one hold at a time, and a silently absorbed second hold would be
// released by lifting the first with nothing recording that two matters
// overlapped.
var ErrHoldRefused = errors.New("operator: this legal hold was refused")

// Tenants is the operator's write surface onto tenant state.
type Tenants struct {
	orgs    TenantOrganizations
	holds   TenantLegalHolds
	auditor *Auditor
	clock   Clock
	log     *slog.Logger
}

// NewTenants builds the use case.
func NewTenants(
	orgs TenantOrganizations, holds TenantLegalHolds,
	auditor *Auditor, clock Clock, log *slog.Logger,
) (*Tenants, error) {
	switch {
	case orgs == nil:
		return nil, errors.New("operator: tenant writes need an organization repository")
	case holds == nil:
		return nil, errors.New("operator: tenant writes need a legal-hold repository; the " +
			"operator plane is the only thing that can place one, so without it " +
			"compliance's hold check can only ever pass")
	case auditor == nil:
		return nil, errors.New("operator: tenant writes need an auditor")
	case clock == nil:
		return nil, errors.New("operator: tenant writes need a clock")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Tenants{orgs: orgs, holds: holds, auditor: auditor, clock: clock, log: log}, nil
}

// PlaceLegalHold suspends erasure and retention purges for one subject
// (compliance.md §7).
//
// # The justification splits, as it does for a suspension
//
// The compliance event carries a MATTER REFERENCE — "litigation 2026-4711" —
// and nothing more. The narrative goes to the operator audit log alone.
//
// The reason is ADR-002 rather than discretion: a hold's justification is prose
// about a legal matter, and legal matters name people — the opposing party, a
// complainant, a third party who is not the subject of this stream at all.
// Putting it on the tenant's permanent, replicated log would be putting other
// people's personal data there under a subject id that is not theirs.
//
// # It notifies nobody, deliberately
//
// Telling somebody a hold has been placed on their data is tipping off. What
// they are owed under Article 12(4) is an answer to their OWN erasure request
// saying it is deferred — a response to a request, not a broadcast about our
// decision. See cmd/worker/events.go, where that distinction is recorded
// against the event itself.
func (t *Tenants) PlaceLegalHold(
	ctx context.Context, actor Actor, subjectID, matter, reason string,
) (TenantWriteResult, error) {
	entryID, err := t.auditor.RecordSubjectWrite(ctx, actor, subjectID,
		"legal hold placed under "+matter, reason)
	if err != nil {
		return TenantWriteResult{}, fmt.Errorf("recording the hold: %w", err)
	}

	if err := t.holds.Place(ctx, subjectID, actor.OperatorID, matter, t.clock.Now()); err != nil {
		return TenantWriteResult{}, fmt.Errorf("%w: %w", ErrHoldRefused, err)
	}

	t.log.WarnContext(ctx, "an operator placed a LEGAL HOLD",
		"subject_id", subjectID, "matter", matter,
		"operator_id", actor.OperatorID, "audit_entry_id", entryID)

	return TenantWriteResult{Changed: true, AuditEntryID: entryID}, nil
}

// LiftLegalHold releases a subject, and resumes any deferred erasure.
//
// The resumption is compliance's, not this call's: an erasure deferred by a
// hold is retried by the workflow once the hold lifts (§7). Coupling the two
// here would make a transient vault error look like a hold that did not lift.
func (t *Tenants) LiftLegalHold(
	ctx context.Context, actor Actor, subjectID, reason string,
) (TenantWriteResult, error) {
	entryID, err := t.auditor.RecordSubjectWrite(ctx, actor, subjectID,
		"legal hold lifted", reason)
	if err != nil {
		return TenantWriteResult{}, fmt.Errorf("recording the lift: %w", err)
	}

	changed, err := t.holds.Lift(ctx, subjectID, actor.OperatorID, t.clock.Now())
	if err != nil {
		return TenantWriteResult{}, fmt.Errorf("%w: %w", ErrHoldRefused, err)
	}

	if changed {
		t.log.WarnContext(ctx, "an operator LIFTED a legal hold",
			"subject_id", subjectID, "operator_id", actor.OperatorID,
			"audit_entry_id", entryID)
	}

	return TenantWriteResult{Changed: changed, AuditEntryID: entryID}, nil
}

// TenantWriteResult reports the state after a suspension or a reinstatement.
type TenantWriteResult struct {
	Changed      bool
	AuditEntryID string
}

// Suspend switches a tenant off (operator.md §7).
//
// # The reason is mandatory and goes to TWO places, saying different things
//
// The tenant's event carries `operator_action`, a closed enum value, and the
// mail that follows says the account was suspended by us. The operator's
// justification — free text, verbatim — goes to the audit log alone.
//
// That split is deliberate. A suspension decided by us is usually about abuse,
// a legal instruction or a fraud investigation, and broadcasting the specifics
// to every member of the organization tells people who are not the subject of
// the decision something they should not be told. "Why did we suspend them" is
// answered in a store with access controls; "you have been suspended" is
// answered to the tenant.
//
// # Audit first, as everywhere on this plane
//
// A suspension that could not be recorded does not happen. This is the most
// consequential thing an operator can do to a customer — it is the only action
// that stops a paying tenant working — so the ordering that makes the record
// unconditional matters more here than anywhere.
func (t *Tenants) Suspend(
	ctx context.Context, actor Actor, orgID, reason string,
) (TenantWriteResult, error) {
	entryID, err := t.auditor.RecordTenantWrite(ctx, actor, orgID, "suspended", reason)
	if err != nil {
		return TenantWriteResult{}, fmt.Errorf("recording the suspension: %w", err)
	}

	now := t.clock.Now()
	changed, err := t.orgs.Suspend(ctx, orgID, orgcontract.OperatorAction, now)
	if err != nil {
		return TenantWriteResult{}, err
	}

	if changed {
		// WARN, and the reason is in it. This is the operator action most
		// likely to be asked about afterwards, and the log line is what somebody
		// reads before they find the audit query.
		t.log.WarnContext(ctx, "an operator SUSPENDED a customer",
			"org_id", orgID, "operator_id", actor.OperatorID,
			"reason", reason, "audit_entry_id", entryID)
	}

	return TenantWriteResult{Changed: changed, AuditEntryID: entryID}, nil
}

// Reinstate returns a suspended tenant to active.
//
// It calls the organization's ordinary `Activate`, not a reinstate-specific
// command, because there is no such thing: a suspension lifted and a trial
// converting both land in Active, and the state machine already says so. An
// operator-only path would be a second way to reach one state, which is how the
// two drift.
//
// The justification is mandatory here too. Turning a customer back on is less
// dangerous than turning them off and it is equally worth being able to explain
// — an account reinstated with no recorded reason is one nobody can defend
// having reinstated.
func (t *Tenants) Reinstate(
	ctx context.Context, actor Actor, orgID, reason string,
) (TenantWriteResult, error) {
	entryID, err := t.auditor.RecordTenantWrite(ctx, actor, orgID, "reinstated", reason)
	if err != nil {
		return TenantWriteResult{}, fmt.Errorf("recording the reinstatement: %w", err)
	}

	now := t.clock.Now()
	changed, err := t.orgs.Reinstate(ctx, orgID, now)
	if err != nil {
		return TenantWriteResult{}, err
	}

	if changed {
		t.log.WarnContext(ctx, "an operator REINSTATED a customer",
			"org_id", orgID, "operator_id", actor.OperatorID,
			"reason", reason, "audit_entry_id", entryID)
	}

	return TenantWriteResult{Changed: changed, AuditEntryID: entryID}, nil
}
