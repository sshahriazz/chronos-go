package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// LapsedReservation is one entry of the sweep's work list.
//
// It carries the blind INDEX, never the address. The index is a keyed HMAC
// (ADR-044), so it is safe to put in a log line, a metric label and — the reason
// it matters here — in workflow history, which is durable and replicated and to
// which ADR-002 applies exactly as it does to the event log.
type LapsedReservation struct {
	// Index is both the projected key and the reservation stream's key, which is
	// what lets the sweep go from a row straight to an aggregate with no second
	// lookup and no ability to derive an address.
	Index contract.EmailIndex

	// SubjectID is the pseudonym that claimed the address. The release is issued
	// on its behalf and the domain refuses a mismatch, so carrying it is what
	// makes a stale row unable to free somebody else's claim.
	SubjectID string

	// ExpiresAt is the projected deadline. Advisory only: the release is decided
	// against the deadline the STREAM reports, because this one can be stale.
	ExpiresAt time.Time
}

// LapsedReservations is the sweep's work list.
//
// It exists because "which unverified reservations have lapsed?" is the one
// question about reservations that cannot be answered from the log without
// reading every reservation stream in the system. Everything else is decided
// against the stream, where the answer is not eventually consistent.
//
// The port is READ-ONLY, and that is a deliberate restriction rather than an
// accident of what the sweep happens to need. email_reservation_view is written
// by the projector, from the EmailReleased event this sweep produces; a sweep
// that could also write it would be able to mark a reservation released without
// an event saying so, and the projection would then no longer be reconstructable
// by replaying the log (ADR-019).
type LapsedReservations interface {
	// ListLapsed returns unverified, unreleased claims whose deadline is at or
	// before deadline, oldest first, at most limit of them.
	ListLapsed(ctx context.Context, deadline time.Time, limit int) ([]LapsedReservation, error)
}

// ReservationRepository is the write side: one aggregate per address, on the
// stream named from its blind index.
//
// Satisfied by eventsourcing.Repository[*domain.EmailReservation]; declared here
// so the use case can be driven without a store.
type ReservationRepository interface {
	// Load rebuilds the reservation for one index. A stream that does not exist
	// yields an empty aggregate rather than an error, which for this sweep means
	// "nothing to release".
	Load(ctx context.Context, key string) (*domain.EmailReservation, error)

	// Save appends what the aggregate recorded, under the expected-revision
	// precondition it was loaded at. idempotencyKey derives the event ids, so a
	// retry that produces the same key collapses into the original append.
	Save(
		ctx context.Context,
		key string,
		agg *domain.EmailReservation,
		idempotencyKey string,
		meta eventsourcing.Metadata,
	) (eventsourcing.AppendResult, error)
}

// SweepResult is what one bounded pass did.
type SweepResult struct {
	// Scanned is how many rows the work list returned.
	Scanned int

	// Released is how many claims this pass actually freed.
	Released int

	// Stale is how many rows named a claim that no longer needed releasing —
	// already released, confirmed since, re-reserved, or now held by a different
	// subject. Not an error and not rare: the view lags the log by design. Each
	// one costs a single aggregate load, which is precisely the price the design
	// pays to make a stale row incapable of causing a wrong release.
	Stale int

	// Failed is how many rows could not be processed. Counted rather than
	// returned, because one address whose stream is unreadable must not stop the
	// other addresses in the batch from being freed.
	Failed int

	// More reports that the batch limit was reached, so there is very likely
	// work left. The caller must act on it — loop, or run again sooner. A sweep
	// that silently stopped at its limit reads as "everything is swept" while an
	// unbounded number of addresses stay held by people who never proved they
	// own them.
	More bool
}

// ReservationSweep frees email reservations whose unverified lease has run out.
//
// This is a SECURITY CONTROL, not housekeeping. Uniqueness is enforced by a
// stream per address, and a registration claims that stream before anything has
// proven the registrant can receive mail there (IDENTITY-SLICE-1, "the
// registration ordering"). Without a sweep, anyone can register with an address
// they do not control and hold it forever, and the real owner can never register
// — with no account to appeal to, because none was ever proven.
//
// It never writes email_reservation_view. The release is appended to the stream
// and the projector updates the row from the resulting event. That direction is
// what makes a stale work list harmless: the aggregate is re-read and the
// decision retaken against the log, so the worst a wrong row can do is waste one
// load.
type ReservationSweep struct {
	list LapsedReservations
	repo ReservationRepository
	log  *slog.Logger
}

// NewReservationSweep builds the use case.
//
// Both ports are required. A sweep with either half missing would run, report
// success and free nothing — which is the failure mode this whole mechanism
// exists to prevent, arriving through the wiring instead of through the design.
func NewReservationSweep(
	list LapsedReservations, repo ReservationRepository, log *slog.Logger,
) (*ReservationSweep, error) {
	switch {
	case list == nil:
		return nil, errors.New("identity: the reservation sweep needs a work list; without " +
			"one no lapsed claim is ever found and abandoned registrations hold their " +
			"addresses permanently")
	case repo == nil:
		return nil, errors.New("identity: the reservation sweep needs a reservation " +
			"repository; the release is an event on the address's stream, not a row update")
	}
	if log == nil {
		log = slog.Default()
	}
	return &ReservationSweep{list: list, repo: repo, log: log}, nil
}

// SweepOnce releases at most limit lapsed claims.
//
// It returns an error only when the work list itself could not be read: at that
// point nothing is known and the caller must retry. A single reservation that
// fails is counted in Failed and the batch continues — one unreadable stream
// must not leave every other lapsed address held.
//
// now is supplied by the caller rather than read from the clock, because the
// caller is a Temporal workflow and workflow.Now is the only clock whose value
// survives a replay unchanged.
func (s *ReservationSweep) SweepOnce(ctx context.Context, now time.Time, limit int) (SweepResult, error) {
	if limit <= 0 {
		return SweepResult{}, fmt.Errorf("identity: a sweep limit of %d would release nothing", limit)
	}
	now = now.UTC()

	rows, err := s.list.ListLapsed(ctx, now, limit)
	if err != nil {
		return SweepResult{}, fmt.Errorf("identity: listing lapsed reservations: %w", err)
	}

	res := SweepResult{Scanned: len(rows), More: len(rows) >= limit}
	for _, row := range rows {
		released, err := s.release(ctx, row, now)
		switch {
		case err != nil:
			res.Failed++
			// The index is a keyed HMAC and the subject is a pseudonym, so this
			// line carries no personal data (ADR-002).
			s.log.Error("a lapsed email reservation could not be released; the address "+
				"stays held until the next sweep",
				"email_index", string(row.Index), "subject_id", row.SubjectID, "error", err)
		case released:
			res.Released++
		default:
			res.Stale++
		}
	}
	if res.More {
		s.log.Info("the lapsed-reservation sweep filled its batch; work remains",
			"limit", limit, "released", res.Released, "failed", res.Failed)
	}
	return res, nil
}

// release frees one claim, reporting whether it actually recorded anything.
//
// Every branch that declines to release is a case where the projected row
// disagrees with the stream, and the stream wins. The verified check is the one
// that matters most: freeing an address whose owner has PROVEN control of it is
// the worst outcome this table can cause, and it is refused here even though the
// query already excludes verified rows — the row could have been confirmed in
// the interval between the query and this load, and it should take two mistakes
// rather than one to give somebody else's address away.
func (s *ReservationSweep) release(
	ctx context.Context, row LapsedReservation, now time.Time,
) (bool, error) {
	key := string(row.Index)
	if key == "" {
		return false, errors.New("identity: a lapsed reservation with no index names no stream")
	}

	agg, err := s.repo.Load(ctx, key)
	if err != nil {
		return false, fmt.Errorf("loading reservation %s: %w", key, err)
	}

	switch {
	case !agg.Held():
		// Already free. A redelivered activity lands here, and so does a row the
		// projector has not caught up with yet.
		return false, nil
	case agg.Verified():
		return false, nil
	case agg.SubjectID() != row.SubjectID:
		// The claim moved on: this address was re-reserved by somebody else
		// after the row was written. Releasing would take it from its current
		// holder. The domain refuses this too; it is checked here so the outcome
		// is a counted stale row rather than a counted failure.
		return false, nil
	case now.Before(agg.ExpiresAt()):
		// The lease the STREAM reports has not run out, whatever the row said.
		return false, nil
	}

	// Read BEFORE the release: applying EmailReleased clears the deadline, and
	// the idempotency key has to name the lease that is being ended.
	deadline := agg.ExpiresAt()

	if err := agg.Release(row.SubjectID, domain.ReleaseExpired, now); err != nil {
		return false, fmt.Errorf("releasing reservation %s: %w", key, err)
	}

	_, err = s.repo.Save(ctx, key, agg, sweepIdempotencyKey(key, deadline), eventsourcing.Metadata{
		OccurredAt: now,
		// The subject whose claim this was. No ActorID: nobody did this, a
		// deadline passed — and naming a person as the actor would make the
		// release look like an action they took.
		SubjectIDs: []string{row.SubjectID},
	})
	if err != nil {
		return false, fmt.Errorf("appending the release of %s: %w", key, err)
	}
	return true, nil
}

// sweepIdempotencyKey derives event ids that are stable for one lapsed claim.
//
// Keyed on the index and the deadline the STREAM reports, not on the current
// time: two sweeps that overlap, or one activity that is retried after its
// append already landed, then derive byte-identical event ids and the store
// collapses the duplicate instead of writing a second release. The deadline is
// part of it so that a LATER lease on the same address — reserved again, lapsed
// again — is a different claim with a different id, rather than an append the
// store silently discards as a duplicate of the first.
func sweepIdempotencyKey(index string, expiresAt time.Time) string {
	return "identity.reservation.sweep:" + index + ":" +
		expiresAt.UTC().Format(time.RFC3339Nano)
}
