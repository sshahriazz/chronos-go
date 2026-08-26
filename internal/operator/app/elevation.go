package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/operator/domain"
)

// ErrElevationRefused means the request was not permitted, and the wrapped
// error says why in words the operator can act on.
//
// The ONLY endpoint on this plane that explains itself, and the asymmetry is
// deliberate. Everywhere else an opaque refusal stops an attacker learning
// which check failed; here the caller is an authenticated operator asking for a
// privilege, and "your role cannot reach that one" is how they learn to ask a
// human instead of retrying.
var ErrElevationRefused = errors.New("operator: this elevation was refused")

// ErrElevationInProgress means a live break-glass already stands on this
// session.
//
// Refused rather than replaced. Replacing would let an operator chain windows
// into an unbounded grant while every individual event looked correctly
// time-boxed — which is precisely what the fifteen-minute limit exists to
// prevent, defeated by a loop.
var ErrElevationInProgress = errors.New(
	"operator: this session already holds a live elevation; it cannot be replaced or " +
		"extended, and a second one begins when the first has lapsed")

// ElevationAlerter raises the alert operator.md §5 requires AT THE TIME OF USE.
//
// # What "alert a second person" means on a plane that holds no addresses
//
// §5 asks for an alert "to a second person at the time of use — not in a report
// someone reads next quarter". The obvious reading is mail, and mail needs
// operator addresses, which this plane deliberately does not hold: an operator
// is a pseudonym here precisely so the audit trail survives their erasure
// (§5's own retention rule).
//
// So the alert is a METRIC and a log line at WARN, routed by the alerting stack
// that already carries every other operational page. That satisfies "at the
// time of use" — Prometheus scrapes on the order of seconds and the rule pages
// a human — and it keeps the operator plane out of the business of storing
// staff contact details.
//
// It is an interface rather than a direct metric call so the composition root
// decides, and so a test can assert the alert FIRED rather than that a counter
// exists. "The adapter was built and constructed by no binary" is this
// repository's named failure, and an alert nobody wired is the same shape.
type ElevationAlerter interface {
	// Alert is called once per granted elevation, BEFORE the grant is returned
	// to the caller. It must not block for long and must not fail the request:
	// an alerting outage may not be a reason a break-glass is unavailable
	// during an incident.
	Alert(ctx context.Context, actor Actor, capability, reason string, expiresAt time.Time)
}

// Elevation is the break-glass use case.
type Elevation struct {
	sessions Sessions
	auditor  *Auditor
	alerter  ElevationAlerter
	clock    Clock
	log      *slog.Logger
}

// NewElevation builds the use case.
func NewElevation(
	sessions Sessions, auditor *Auditor, alerter ElevationAlerter,
	clock Clock, log *slog.Logger,
) (*Elevation, error) {
	switch {
	case sessions == nil:
		return nil, errors.New("operator: elevation needs a session store")
	case auditor == nil:
		return nil, errors.New("operator: elevation needs an auditor")
	case alerter == nil:
		// REQUIRED, not optional. operator.md §5 lists the alert alongside the
		// justification and the time box as one of three controls, and a
		// break-glass that raises none is the feature without the control that
		// makes it safe.
		return nil, errors.New("operator: elevation needs an alerter; §5 requires an alert " +
			"at the time of use, and a break-glass that raises none is the dangerous " +
			"half of the feature")
	case clock == nil:
		return nil, errors.New("operator: elevation needs a clock")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Elevation{sessions: sessions, auditor: auditor, alerter: alerter,
		clock: clock, log: log}, nil
}

// GrantResult is the window that was opened.
type GrantResult struct {
	Capability   string
	ExpiresAt    time.Time
	AuditEntryID string
}

// Request grants a break-glass on the caller's own session.
//
// # The order is audit → grant → alert, and each step earns its place
//
//	validate  — the domain decides whether this role may reach this capability
//	audit     — appended BEFORE the grant, so a privilege that could not be
//	            recorded is not taken; the same rule RevealPersonalData follows
//	grant     — the database's conditional UPDATE is what refuses a second
//	            window, atomically, rather than a read-then-write that two
//	            concurrent requests could both pass
//	alert     — after the grant, because alerting on a grant that then failed
//	            would train people that the alert means nothing
//
// A failure to grant AFTER the audit leaves an OperatorElevated in the log for
// a window that never opened. That is the acceptable direction: the trail
// over-reports an intent, which an incident review can reconcile against the
// absence of any use — and the alternative under-reports a privilege that was
// actually held.
func (e *Elevation) Request(
	ctx context.Context, actor Actor, digest []byte, capability, reason string,
) (GrantResult, error) {
	cap := domain.Capability(capability)

	if err := domain.ValidateElevation(actor.Role, cap, reason); err != nil {
		e.log.InfoContext(ctx, "a break-glass was refused",
			"operator_id", actor.OperatorID, "role", actor.Role,
			"capability", capability, "error", err)
		// Both wrapped: the sentinel is what the API layer maps to a code, and
		// the domain's message is what tells the operator which rule refused
		// them. Formatting the second with %s would flatten it, and a caller
		// wanting to distinguish "unknown capability" from "out of reach" would
		// be back to matching on substrings.
		return GrantResult{}, fmt.Errorf("%w: %w", ErrElevationRefused, err)
	}

	now := e.clock.Now()
	expires := now.Add(domain.ElevationWindow)

	entryID, err := e.auditor.RecordElevation(ctx, actor, capability, reason, expires)
	if err != nil {
		return GrantResult{}, fmt.Errorf("recording the break-glass: %w", err)
	}

	granted, err := e.sessions.Elevate(ctx, digest, domain.Elevation{
		Capability: cap, Reason: reason, ExpiresAt: expires,
	}, now)
	if err != nil {
		return GrantResult{}, fmt.Errorf("granting the elevation: %w", err)
	}
	if !granted {
		// The conditional UPDATE matched nothing, which means a live elevation
		// already stands — or the session ended between the guard resolving it
		// and this statement. Both are refusals, and the message names the
		// likelier one.
		e.log.WarnContext(ctx, "a second break-glass was refused inside an open window",
			"operator_id", actor.OperatorID, "capability", capability,
			"audit_entry_id", entryID)
		return GrantResult{}, ErrElevationInProgress
	}

	e.alerter.Alert(ctx, actor, capability, reason, expires)

	return GrantResult{Capability: capability, ExpiresAt: expires, AuditEntryID: entryID}, nil
}

// SweepExpired closes lapsed windows in the log.
//
// # A sweep, not a timer per elevation
//
// ADR-045's reasoning, in its second application. A timer is a promise, and a
// promise lost to a restart leaves the log claiming a window is still open. The
// sweep is idempotent — `MarkElevationExpiryRecorded` is conditional — and
// finds what any timer would have missed.
//
// It gates nothing. Whether a grant is live is decided by comparing the
// deadline in SQL, so a sweep that is late costs an audit record its
// punctuality and can never extend a privilege. That is the opposite of the
// revocation-tombstone case, where a timer firing EARLY restores access; here
// the only thing a late sweep delays is the record that the glass closed.
func (e *Elevation) SweepExpired(ctx context.Context, limit int32) (int, error) {
	now := e.clock.Now()

	expired, err := e.sessions.ExpiredElevations(ctx, now, limit)
	if err != nil {
		return 0, fmt.Errorf("listing expired elevations: %w", err)
	}

	recorded := 0
	for _, x := range expired {
		if _, err := e.auditor.RecordElevationExpiry(ctx, x); err != nil {
			// One failure must not stop the rest: the next pass retries this
			// entry, and abandoning the batch would let one bad row hold every
			// other expiry out of the log indefinitely.
			e.log.ErrorContext(ctx, "an elevation expiry could not be recorded",
				"operator_id", x.OperatorID, "session_id", x.SessionID,
				"capability", x.Capability, "error", err)
			continue
		}
		if err := e.sessions.MarkElevationExpiryRecorded(ctx, x.SessionID, now); err != nil {
			// The event IS in the log and this only marks it as recorded, so a
			// failure here means the next pass appends a duplicate. Reported
			// rather than hidden: two expiry events for one window is a
			// confusing audit trail, and it is better to know why.
			e.log.ErrorContext(ctx, "an elevation expiry was logged but not marked",
				"session_id", x.SessionID, "error", err)
		}
		recorded++

		if !x.Used {
			// An elevation nobody exercised. Worth a line of its own: a stream
			// of unused break-glasses is either a role scoped too tightly or a
			// habit forming, and both are worth noticing before somebody
			// notices the alerts instead.
			e.log.InfoContext(ctx, "a break-glass window closed unused",
				"operator_id", x.OperatorID, "capability", x.Capability)
		}
	}
	return recorded, nil
}
