package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// DueInvitation is one entry of the sweep's work list.
//
// It carries pseudonyms and ids and nothing else. The whole row is safe in a log
// line, a metric label and — the reason it matters — in workflow history, which
// is durable and replicated and to which ADR-002 applies exactly as it does to
// the event log.
type DueInvitation struct {
	InvitationID string
	OrgID        string
	WorkspaceID  string

	// ExpiresAt is the projected deadline. ADVISORY ONLY: the expiry is decided
	// against the deadline the STREAM reports, because a resend moves the window
	// and this row can be behind that.
	ExpiresAt time.Time
}

// DueInvitations is the sweep's work list.
//
// It exists because "which invitations have run out?" is the one question about
// invitations that cannot be answered from the log without reading every
// invitation stream in the system. Everything else is decided against the
// stream, where the answer is not eventually consistent.
//
// The port is READ-ONLY, and that is a deliberate restriction rather than an
// accident of what the sweep needs. invitation_view is written by the projector
// from the InvitationExpired event this sweep produces; a sweep that could also
// write it would be able to mark an invitation expired with no event saying so,
// and the projection would stop being reconstructable by replaying the log
// (ADR-019).
type DueInvitations interface {
	// ListDue returns pending invitations whose deadline is at or before
	// deadline, oldest first, at most limit of them.
	ListDue(ctx context.Context, deadline time.Time, limit int) ([]DueInvitation, error)
}

// InvitationSweepResult is what one bounded pass did.
type InvitationSweepResult struct {
	// Scanned is how many rows the work list returned.
	Scanned int

	// Expired is how many invitations this pass actually closed.
	Expired int

	// Stale is how many rows named an invitation that no longer needed expiring
	// — already settled, or resent since and now live again. Not an error and
	// not rare: the view lags the log by design, and a resend moves the deadline
	// the row was selected on. Each costs a single aggregate load, which is
	// precisely the price paid to make a stale row incapable of expiring a live
	// invitation.
	Stale int

	// Failed is how many rows could not be processed. Counted rather than
	// returned, because one invitation whose stream is unreadable must not stop
	// the rest of the batch from releasing their seats.
	Failed int

	// More reports that the batch limit was reached, so there is very likely work
	// left. The caller must act on it — loop, or run again sooner. A sweep that
	// silently stopped at its limit reads as "everything is swept" while an
	// unbounded number of seats stay held by invitations nobody will ever accept.
	More bool
}

// InvitationSweep expires invitations whose window has closed.
//
// # Why a sweep exists at all when a workflow also does this
//
// The per-invitation workflow is what makes expiry TIMELY. This is what makes it
// CERTAIN. A workflow that was never started — because the worker was down when
// the event arrived, because Temporal was unreachable, because the reactor
// parked — leaves a seat held forever by an invitation nobody can accept, and
// there is nothing in the system that would ever notice.
//
// It is the same relationship organization.md §5 describes for trials: the
// webhook does the work, and the reconciliation catches the webhook that never
// came. Neither replaces the other, and the sweep is the one that must not be
// skipped, because it is the one that bounds the damage.
//
// # It never decides from the row
//
// The work list selects candidates; the aggregate decides. A resend that moved
// the deadline after the row was read makes the row wrong, and the domain's
// Expire refuses to run before the deadline the STREAM reports — so the worst a
// stale row can do is waste one load. That refusal is counted as Stale rather
// than Failed, because it is the mechanism working.
type InvitationSweep struct {
	list      DueInvitations
	expire    Expirer
	batchSize int
	log       *slog.Logger
}

// Expirer closes one invitation and returns its seat.
//
// Narrow on purpose: a sweep holding the whole invitation use case could also
// issue, accept and revoke. The only thing this flow legitimately does is expire
// something whose deadline has passed.
type Expirer interface {
	Expire(ctx context.Context, invitationID string) (bool, error)
}

// DefaultSweepBatch bounds one pass.
//
// Bounded because an unbounded sweep on a large tenant holds one transaction
// open for as long as it takes to expire everything, and because a pass that
// cannot finish is better reported as More than as a timeout.
const DefaultSweepBatch = 200

// NewInvitationSweep builds the use case.
//
// Both ports are required. A sweep with either half missing would run, report
// success and expire nothing — which is the failure this whole mechanism exists
// to prevent, arriving through the wiring instead of through the design.
func NewInvitationSweep(
	list DueInvitations, expire Expirer, log *slog.Logger,
) (*InvitationSweep, error) {
	switch {
	case list == nil:
		return nil, errors.New("workspace: the invitation sweep needs a work list; without " +
			"one no lapsed invitation is ever found and every seat it holds is held forever")
	case expire == nil:
		return nil, errors.New("workspace: the invitation sweep needs an expirer; without " +
			"one it would scan, report what it found, and close nothing")
	}
	if log == nil {
		log = slog.Default()
	}
	return &InvitationSweep{
		list: list, expire: expire, batchSize: DefaultSweepBatch, log: log,
	}, nil
}

// Run performs one bounded pass.
//
// A failure on one invitation is COUNTED, never returned. One unreadable stream
// must not stop the rest of the batch: every row in it is a seat an organization
// is paying for, and the whole point of the pass is to give those back.
func (s *InvitationSweep) Run(ctx context.Context, now time.Time) (InvitationSweepResult, error) {
	due, err := s.list.ListDue(ctx, now.UTC(), s.batchSize)
	if err != nil {
		// The list itself failing IS returned: nothing was scanned, so reporting
		// a successful pass would say "no invitations are overdue" when the truth
		// is "nobody looked".
		return InvitationSweepResult{}, fmt.Errorf("workspace: listing due invitations: %w", err)
	}

	result := InvitationSweepResult{Scanned: len(due), More: len(due) >= s.batchSize}
	for _, inv := range due {
		// The row selected it; the AGGREGATE decides. Expire returns false when
		// the invitation no longer needs closing — settled since, or resent so
		// its deadline moved past this row's — and that is the mechanism
		// working, not a failure.
		expired, err := s.expire.Expire(ctx, inv.InvitationID)
		switch {
		case err != nil:
			result.Failed++
			s.log.ErrorContext(ctx, "an overdue invitation could not be expired; its seat "+
				"stays held until the next pass",
				"invitation", inv.InvitationID, "org", inv.OrgID, "error", err)
		case expired:
			result.Expired++
		default:
			result.Stale++
		}
	}
	return result, nil
}
