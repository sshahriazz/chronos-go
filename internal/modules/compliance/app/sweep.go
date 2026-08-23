package app

import (
	"context"
	"fmt"
	"log/slog"
	"time"
)

// OverdueRequest is one deletion request whose deadline has passed.
type OverdueRequest struct {
	SubjectID    string
	ScheduledFor time.Time
}

// OverdueRequests is the sweep's work list.
//
// Declared by its consumer (CONVENTIONS §2); satisfied by identity's read model,
// because `user_view` is where the request's deadline is projected.
type OverdueRequests interface {
	ListOverdue(ctx context.Context, before time.Time, limit int) ([]OverdueRequest, error)
}

// ErasureStarter puts a clock on a request. The same port the reactor uses.
type ErasureStarter interface {
	StartErasure(ctx context.Context, subjectID string) error
}

// SweepResult reports what one pass did.
type SweepResult struct {
	Scanned int

	// Started is how many workflows this pass began. It is normally ZERO on a
	// healthy system — every request already has a running clock — and that is
	// the number worth alerting on when it is not.
	Started int

	Failed int

	// More is true when the batch came back full, so the caller runs again.
	More bool
}

// Sweep restarts erasure clocks for requests that have none.
//
// # Why this exists when the workflow is durable
//
// Temporal does not lose workflows, and that is not what this guards. It guards
// a request whose workflow was NEVER STARTED: the reactor unregistered for a
// deployment, the subscription group renamed, or Temporal disabled when the
// request came in. Each leaves somebody who asked to be forgotten, was told a
// date, and is in no workflow at all — and nothing else in the system would ever
// notice.
//
// Every other timer here has a sweep behind it for that reason (billing.md §5
// case 15). This is the one where the missed deadline is statutory.
//
// # It starts clocks; it does not erase
//
// A sweep that erased directly would be a second path to an irreversible action,
// with its own copy of the grace-period and cancellation rules. Starting the
// SAME workflow means the sweep can only ever cause what the ordinary path
// causes — and the workflow re-reads, so a request cancelled since is still not
// erased.
type Sweep struct {
	requests OverdueRequests
	starter  ErasureStarter
	log      *slog.Logger
}

// SweepDeps is what Sweep needs.
type SweepDeps struct {
	Requests OverdueRequests
	Starter  ErasureStarter
	Log      *slog.Logger
}

func NewSweep(d SweepDeps) (*Sweep, error) {
	switch {
	case d.Requests == nil:
		return nil, fmt.Errorf("compliance: an overdue-request source is required; without " +
			"one the sweep scans nothing and reports a clean pass forever")
	case d.Starter == nil:
		return nil, fmt.Errorf("compliance: an erasure starter is required")
	case d.Log == nil:
		return nil, fmt.Errorf("compliance: a logger is required")
	}
	return &Sweep{requests: d.Requests, starter: d.Starter, log: d.Log}, nil
}

// SweepOnce runs one bounded pass.
//
// Starting a clock that already exists is NOT an error — the starter collapses
// it on the workflow id — so a healthy system sweeps every overdue request every
// pass and starts nothing. `Started` being non-zero is the signal: it means a
// request existed with no clock, which is the failure this exists to catch.
func (s *Sweep) SweepOnce(
	ctx context.Context, now time.Time, limit int,
) (SweepResult, error) {
	if limit <= 0 {
		return SweepResult{}, fmt.Errorf("compliance: a positive batch size is required, got %d", limit)
	}

	overdue, err := s.requests.ListOverdue(ctx, now.UTC(), limit)
	if err != nil {
		return SweepResult{}, fmt.Errorf("compliance: listing overdue erasures: %w", err)
	}

	result := SweepResult{Scanned: len(overdue), More: len(overdue) == limit}
	for _, req := range overdue {
		if err := s.starter.StartErasure(ctx, req.SubjectID); err != nil {
			// COUNTED, not returned. One subject whose workflow cannot start must
			// not stop the pass: the others are equally overdue, and the next run
			// retries this one.
			result.Failed++
			s.log.ErrorContext(ctx, "an overdue erasure could not be restarted",
				"module", "compliance", "subject_id", req.SubjectID,
				"scheduled_for", req.ScheduledFor.Format(time.RFC3339), "error", err)
			continue
		}
		result.Started++
	}

	if result.Started > 0 {
		// WARN, not Info. A healthy system starts nothing here — every request
		// already has a clock from the reactor — so a non-zero count means
		// requests existed that nothing was going to act on.
		s.log.WarnContext(ctx, "the erasure sweep restarted clocks that should already "+
			"have been running; some deletion requests were not picked up by the reactor",
			"module", "compliance", "started", result.Started, "scanned", result.Scanned)
	}
	return result, nil
}
