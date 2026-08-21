// Package projection builds organization's read model.
//
// One projection, one table. Every column comes from an event, so it is
// rebuildable from position zero by construction (ADR-019).
package projection

import (
	"context"
	"time"

	organizationdb "github.com/chronos/chronos-go/gen/sqlc/organization"
	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/db"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/projection"
)

// Name is permanent: it keys the checkpoint row and the single-writer lease, so
// renaming it silently restarts the projection from zero.
const Name = "org_status_view"

// Status builds `org_status_view`, the table gate 3 reads on every request.
type Status struct{ dispatch *projection.Dispatch }

var _ projection.Projection = (*Status)(nil)

// NewStatus wires one handler per lifecycle event.
//
// # Why every handler is a separate statement rather than one upsert
//
// Only Created and TrialStarted know the Stripe columns. The rest change the
// status alone, and folding them into the upsert would mean each restating a
// subscription id it is not changing — which is exactly how a projector blanks
// a column it never meant to touch. The SQL is split the same way for the same
// reason.
func NewStatus(codec eventsourcing.Codec) *Status {
	d := projection.NewDispatch(codec)

	// Created is the only INSERT. Everything after it is an update, which is
	// also the ordering guarantee the stream gives: nothing precedes Created.
	d.On[contract.OrganizationCreated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationCreated,
	) error {
		// Upsert, not insert: a projector is replayed on restart and on rebuild,
		// so this event WILL arrive twice and an insert would fail the second
		// time and stall the projection permanently.
		w.Exec(organizationdb.UpsertOrgStatus,
			e.OrgID, string(domain.StatusProvisioning), nil, "", e.CreatedAt)
		return nil
	})

	// TrialStarted carries the Stripe ids and the deadline, so it is the second
	// and last statement that writes them.
	d.On[contract.OrganizationTrialStarted](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationTrialStarted,
	) error {
		w.Exec(organizationdb.UpsertOrgStatus,
			e.OrgID, string(domain.StatusTrialing), e.TrialEndsAt,
			e.StripeSubscriptionID, e.StartedAt)
		return nil
	})

	// Activation ends the trial, so the deadline is cleared as well as the
	// status changed — otherwise the due-trials index keeps naming an
	// organization that converted, and reconciliation chases a trial that
	// already ended successfully.
	d.On[contract.OrganizationActivated](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationActivated,
	) error {
		setStatus(w, e.OrgID, domain.StatusActive, e.ActivatedAt)
		w.Exec(organizationdb.ClearOrgTrialEnd, e.OrgID, e.ActivatedAt)
		return nil
	})

	d.On[contract.OrganizationPastDue](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationPastDue,
	) error {
		setStatus(w, e.OrgID, domain.StatusPastDue, e.At)
		return nil
	})

	// A suspension also clears the deadline. A lapsed trial has already ended —
	// leaving the timestamp would keep it in the due-trials index forever, and
	// every reconciliation pass would try to end it again.
	d.On[contract.OrganizationSuspended](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationSuspended,
	) error {
		setStatus(w, e.OrgID, domain.StatusSuspended, e.SuspendedAt)
		w.Exec(organizationdb.ClearOrgTrialEnd, e.OrgID, e.SuspendedAt)
		return nil
	})

	d.On[contract.OrganizationClosed](func(
		_ context.Context, w db.Writer, _ projection.Envelope, e *contract.OrganizationClosed,
	) error {
		setStatus(w, e.OrgID, domain.StatusClosed, e.ClosedAt)
		w.Exec(organizationdb.ClearOrgTrialEnd, e.OrgID, e.ClosedAt)
		return nil
	})

	// OrgAdminAdded and OrgAdminRemoved are deliberately NOT handled here. This
	// table answers one question — what may this tenant do — and who
	// administers it is a different one, answered by OpenFGA and by
	// org_admin_view. A projection that grew an admin column would be read on
	// every request for a fact almost no request needs.

	return &Status{dispatch: d}
}

func setStatus(w db.Writer, orgID string, status domain.Status, at time.Time) {
	w.Exec(organizationdb.SetOrgStatus, orgID, string(status), at)
}

func (s *Status) Name() string { return Name }

// Filter narrows $all to this module's own streams, so a rebuild reads the
// `$ce-organization` category stream instead of scanning the whole log
// (ADR-042).
func (s *Status) Filter() eventsourcing.SubscriptionFilter {
	return eventsourcing.SubscriptionFilter{
		StreamPrefixes: []string{string(domain.Category) + "-"},
	}
}

func (s *Status) Apply(ctx context.Context, w db.Writer, env projection.Envelope) error {
	return s.dispatch.Apply(ctx, w, env)
}

// Reset empties the table for a rebuild.
//
// TRUNCATE, because the rebuild runs in an UNSCOPED system transaction and this
// table HAS row security — so DELETE would match no rows and silently leave the
// old projection in place (ADR-019).
func (s *Status) Reset(ctx context.Context, q db.Querier) error {
	_, err := q.Exec(ctx, organizationdb.TruncateOrgStatus)
	return err
}
