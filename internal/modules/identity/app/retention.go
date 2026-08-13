package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"
)

// Retention horizons.
//
// Only two of identity's five retention statements take a cutoff. The other
// three measure against now() in SQL, and deliberately so: a spent TOTP step, an
// expired token digest and the token half of a dead session all protect nothing
// past their own expiry, so there is no horizon to choose — the row is waste the
// instant it stops being usable.
//
// These two are different. Both delete rows that a human being may still need to
// ask a question about, so the horizon is the answer to "for how long could
// somebody reasonably ask?" rather than a storage calculation.
const (
	// SessionViewRetention is how long a session row is kept after its ABSOLUTE
	// deadline has passed.
	//
	// The row is what the security-settings screen reads to answer "which devices
	// have signed into this account, and when" (session.sql, SweepSessionTokens).
	// Ninety days is chosen against that question: it is the window in which
	// somebody who has just discovered a compromise looks back over their own
	// sign-ins, and it matches the horizon login history is reviewed over. Shorter
	// and the account-takeover victim finds an empty list; longer and the
	// projection accumulates rows nobody will ever read again.
	//
	// Note the ordering constraint this creates — see the comment on the step
	// list in PurgeOnce. The secret half must be swept BEFORE this deletes the
	// rows that the secret half is found through.
	SessionViewRetention = 90 * 24 * time.Hour

	// ReleasedReservationRetention is how long a released email reservation row
	// is kept after its release.
	//
	// Thirty days, and short on purpose. The row is a projection — deleting it
	// removes only what a replay would recreate (reservation.sql) — and it holds
	// nothing anybody acts on once the address is free again. What it is good for
	// is answering a support question with a memory attached to it: "I abandoned
	// a signup last month and now I cannot register." A month covers that; past
	// it the row is one more entry in a table that gains one for every
	// registration anyone ever abandoned.
	ReleasedReservationRetention = 30 * 24 * time.Hour
)

// Statement names, as they appear in the result and in the log.
//
// Stable strings rather than the Go identifiers, because they are what an
// operator greps for when asking "did the TOTP replay table actually shrink last
// night", and a Go rename must not silently change what that grep matches.
const (
	StatementTOTPReplay           = "totp_replay"
	StatementTokens               = "identity_token"
	StatementSessionTokens        = "session_token"
	StatementSessionViews         = "session_view"
	StatementReleasedReservations = "email_reservation_view"
)

// RetentionStore is the port: identity's five retention statements, each
// reporting how many rows it removed.
//
// Declared here rather than reached for through a generated Querier so the use
// case can be driven without a database, and so the SET of statements is
// something a reader can see in one place. A statement that exists in
// db/query/identity and is absent from this interface is a statement nothing
// runs — which is exactly the state all five were in before this job existed.
//
// Every implementation must run in a SYSTEM transaction. Identity's tables carry
// no RLS (see the package comment on identity/adapter/postgres), and retention is
// cross-tenant by nature besides.
type RetentionStore interface {
	// SweepTOTPReplay drops spent TOTP steps whose codes can no longer be
	// presented. No cutoff: the SQL measures against now(), because a step past
	// its expiry is unreplayable and the row protects nothing.
	SweepTOTPReplay(ctx context.Context) (int64, error)

	// SweepTokens drops expired verification and reset digests. No cutoff, for
	// the same reason.
	SweepTokens(ctx context.Context) (int64, error)

	// SweepSessionTokens drops the SECRET half of sessions that can no longer be
	// used — expired or revoked. It finds them by joining session_view, which is
	// what makes the order of these calls matter.
	SweepSessionTokens(ctx context.Context) (int64, error)

	// SweepExpiredSessionViews drops the projected half of sessions whose
	// absolute deadline passed before cutoff.
	SweepExpiredSessionViews(ctx context.Context, cutoff time.Time) (int64, error)

	// DeleteReleasedReservations drops reservation rows released before cutoff.
	DeleteReleasedReservations(ctx context.Context, cutoff time.Time) (int64, error)
}

// RetentionOutcome is what one statement did, or why it did nothing.
type RetentionOutcome struct {
	// Statement is one of the Statement* names above.
	Statement string

	// Deleted is the affected-row count. Zero is the normal steady state for
	// most of these and is NOT a signal on its own; the signal is a count that
	// stops moving on a table that is known to be growing.
	Deleted int64

	// Err is why this statement did nothing. Non-nil here does not stop the
	// others: one broken statement must not hold every other table's retention
	// hostage.
	Err error
}

// RetentionResult is what one pass did, per statement.
//
// Per-statement rather than a single total, because the totals answer nothing.
// "We deleted 4,000 rows" is compatible with the TOTP replay table never being
// touched at all, and that table is the reason this job exists — it has no TTL,
// no natural bound, and it grows for the lifetime of the deployment (ADR-049).
type RetentionResult struct {
	// Outcomes is one entry per statement, in the order they ran.
	Outcomes []RetentionOutcome

	// Deleted is the sum across statements that succeeded.
	Deleted int64

	// Failed is how many statements could not run.
	Failed int
}

// Retention runs identity's retention statements.
//
// It is housekeeping, not a security control — which is the opposite of
// ReservationSweep in this same package, and the difference is why this one runs
// daily and that one runs every fifteen minutes. Nothing here changes what
// anybody is allowed to do; the statements delete rows that can no longer affect
// a decision. The cost of not running it is unbounded growth in tables that have
// no TTL, plus secret material — token digests, spent steps — retained long past
// the point where it protects anything.
type Retention struct {
	store RetentionStore
	log   *slog.Logger
}

// NewRetention builds the use case.
//
// The store is required and has no safe stand-in: a retention job with no store
// runs to completion, reports success, and deletes nothing — which is
// indistinguishable, from every signal outside this process, from a retention job
// with nothing left to delete.
func NewRetention(store RetentionStore, log *slog.Logger) (*Retention, error) {
	if store == nil {
		return nil, errors.New("identity: the retention job needs a store; without one every " +
			"run reports success while spent TOTP steps, expired token digests and dead " +
			"session secrets are retained for the lifetime of the deployment")
	}
	if log == nil {
		log = slog.Default()
	}
	return &Retention{store: store, log: log}, nil
}

// PurgeOnce runs every statement once.
//
// It returns an error only when the pass could not be ATTEMPTED. A statement that
// fails is recorded in its own outcome and the rest still run: these five tables
// have nothing to do with each other, and letting an unreadable one stop the
// others turns one broken statement into four tables that grow forever.
//
// now is supplied by the caller rather than read from the clock, because the
// caller is a Temporal workflow and workflow.Now is the only clock whose value
// survives a replay unchanged. Deriving both cutoffs from that single instant
// also means a retried attempt and the original agree about the horizon.
func (r *Retention) PurgeOnce(ctx context.Context, now time.Time) (RetentionResult, error) {
	if now.IsZero() {
		return RetentionResult{}, errors.New("identity: retention needs the instant to " +
			"measure its horizons against; a zero time would make every cutoff year 1 and " +
			"delete nothing, silently")
	}
	now = now.UTC()

	// THE ORDER IS LOAD-BEARING, in exactly one place: session_token must be
	// swept BEFORE session_view.
	//
	// SweepSessionTokens finds dead secrets by joining session_view
	// (session.sql). There is no foreign key between the two — 00010 removed the
	// possibility deliberately, because session_view is truncated on every
	// rebuild and a cascade would take the secrets with it. So a session_view row
	// deleted first does not cascade; it simply removes the only route by which
	// its token digest can ever be found again, and that digest is then retained
	// permanently. Reversing these two lines leaves orphaned secret material in
	// the database with nothing reporting it.
	steps := []struct {
		name string
		run  func(context.Context) (int64, error)
	}{
		{StatementTOTPReplay, r.store.SweepTOTPReplay},
		{StatementTokens, r.store.SweepTokens},
		{StatementSessionTokens, r.store.SweepSessionTokens},
		{StatementSessionViews, func(ctx context.Context) (int64, error) {
			return r.store.SweepExpiredSessionViews(ctx, now.Add(-SessionViewRetention))
		}},
		{StatementReleasedReservations, func(ctx context.Context) (int64, error) {
			return r.store.DeleteReleasedReservations(ctx, now.Add(-ReleasedReservationRetention))
		}},
	}

	res := RetentionResult{Outcomes: make([]RetentionOutcome, 0, len(steps))}
	for _, step := range steps {
		deleted, err := step.run(ctx)
		if err != nil {
			res.Failed++
			res.Outcomes = append(res.Outcomes, RetentionOutcome{
				Statement: step.name,
				Err:       fmt.Errorf("identity: retention statement %s: %w", step.name, err),
			})
			// Logged at Error and named, because the alternative is a job that
			// keeps reporting a healthy run while one table grows unbounded.
			r.log.Error("an identity retention statement failed; its table keeps growing "+
				"until the next successful run",
				"statement", step.name, "error", err)
			continue
		}
		res.Deleted += deleted
		res.Outcomes = append(res.Outcomes, RetentionOutcome{Statement: step.name, Deleted: deleted})
	}

	// One line per run carrying every count, because a retention job whose output
	// nobody can see is one nobody notices has stopped. The counts are per
	// statement for the reason RetentionResult is: a total hides the one table
	// that is not being swept.
	attrs := make([]any, 0, 2*len(res.Outcomes)+4)
	for _, o := range res.Outcomes {
		attrs = append(attrs, o.Statement, o.Deleted)
	}
	attrs = append(attrs, "deleted", res.Deleted, "failed", res.Failed)
	r.log.Info("identity retention pass complete", attrs...)

	return res, nil
}
