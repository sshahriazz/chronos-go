package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// Erasure performs the IDENTITY half of an account erasure.
//
// # What this is not
//
// It is not the decision to erase, and it is not the key destruction. The
// decision and its grace period belong to compliance's orchestration; the key
// destruction belongs to the vault. This is the part that only identity can do,
// because only identity knows what an account holds: sessions, an address
// reservation, a username.
//
// # Order matters, and it is the reverse of what looks natural
//
// Sessions first, identifiers second, the account's own event LAST.
//
// Appending UserErased first would look tidier — the fact recorded, then the
// cleanup — and it would be wrong twice over. The aggregate refuses every
// command afterwards, so the identifier work would have to run against an
// account already marked erased; and a failure in the middle would leave a log
// asserting the account is gone while its sessions still authenticate.
//
// Ending last means every intermediate failure is retryable and nothing claims
// completion until it is complete.
type Erasure struct {
	directory UserDirectory
	users     *eventsourcing.Repository[*domain.User]
	emails    *eventsourcing.Repository[*domain.EmailReservation]
	usernames *eventsourcing.Repository[*domain.UsernameReservation]
	now       func() time.Time
}

// ErasureDeps is what Erasure needs.
type ErasureDeps struct {
	// Directory resolves the pseudonym an erasure names to the account id its
	// stream is named after. Every event in this system carries a SubjectID
	// (ADR-002) and user streams are keyed on UserID, so nothing maps one to the
	// other without this lookup or a scan of every user stream.
	Directory UserDirectory

	Users     *eventsourcing.Repository[*domain.User]
	Emails    *eventsourcing.Repository[*domain.EmailReservation]
	Usernames *eventsourcing.Repository[*domain.UsernameReservation]
	Now       func() time.Time
}

func NewErasure(d ErasureDeps) (*Erasure, error) {
	switch {
	case d.Directory == nil:
		return nil, fmt.Errorf("identity: a user directory is required; an erasure names a " +
			"pseudonym and user streams are named after account ids, so without it there " +
			"is no stream to erase")
	case d.Users == nil:
		return nil, fmt.Errorf("identity: a user repository is required")
	case d.Emails == nil:
		return nil, fmt.Errorf("identity: an email reservation repository is required; " +
			"without it an erased account's address stays claimed forever and nobody — " +
			"including the person who owned it — can ever register it again")
	case d.Usernames == nil:
		return nil, fmt.Errorf("identity: a username reservation repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("identity: a clock is required")
	}
	return &Erasure{
		directory: d.Directory,
		users:     d.Users, emails: d.Emails, usernames: d.Usernames,
		now: d.Now,
	}, nil
}

// ErasureResult reports what the identity half did.
type ErasureResult struct {
	SessionsRevoked int
	AddressReleased bool
	UsernameBurned  bool

	// AlreadyErased is true when the account was erased by an earlier attempt.
	// Not a failure: the orchestration retries, and the whole operation is built
	// to converge rather than to run exactly once.
	AlreadyErased bool
}

// Erase performs the identity half and records the account as erased.
//
// Every step is idempotent, because the caller is a Temporal workflow whose
// activities are retried. A second run revokes no sessions, releases nothing,
// and records nothing — and returns success, so the workflow advances instead of
// parking on work that is done.
func (e *Erasure) Erase(ctx context.Context, subjectID string) (ErasureResult, error) {
	if subjectID == "" {
		return ErasureResult{}, errs.ValidationFailedf("a subject is required")
	}

	userID, err := e.directory.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			// The projection holds no account for this pseudonym. Poison rather
			// than a retry: an erasure was ordered for a subject nothing knows,
			// and no amount of waiting produces one.
			return ErasureResult{}, fmt.Errorf("%w: erasure names subject %s, which the "+
				"account directory does not know", eventsourcing.ErrPoison, subjectID)
		}
		return ErasureResult{}, errs.Internalf("resolving the account").Wrap(err)
	}

	user, err := e.users.Load(ctx, userID.String())
	if err != nil {
		return ErasureResult{}, errs.Internalf("loading the account").Wrap(err)
	}
	if user.State() == domain.StateNone {
		// Poison rather than a failure: the orchestration named a subject with no
		// stream, and no retry produces one.
		return ErasureResult{}, fmt.Errorf("%w: erasure names subject %s, which has no "+
			"account events", eventsourcing.ErrPoison, subjectID)
	}
	if user.State() == domain.StateErased {
		return ErasureResult{AlreadyErased: true}, nil
	}

	// Checked BEFORE any destructive step. The aggregate refuses the final
	// append without an outstanding request, so without this an erasure for the
	// wrong subject would revoke their sessions and burn their username before
	// discovering it was never authorised.
	if _, outstanding := user.DeletionRequested(); !outstanding {
		return ErasureResult{}, fmt.Errorf("%w: subject %s has no outstanding erasure "+
			"request; erasure follows a request and a grace period, and there is no undo",
			eventsourcing.ErrPoison, subjectID)
	}

	result := ErasureResult{}

	// SESSIONS are NOT revoked here, and their absence is deliberate rather than
	// an omission. `session_view` has exactly one writer — the session
	// projection — and it deletes this subject's sessions when it applies the
	// UserErased appended below. Doing it here as well would be a second path to
	// rows this use case does not own, and it would not survive a rebuild.
	//
	// 1. THE ADDRESS. Released so it can be registered again — by anybody,
	//    including the person who just left. A reservation that outlived the
	//    account it belonged to would deny the address forever on behalf of
	//    somebody who asked to be forgotten.
	if index := user.EmailIndex(); index != "" {
		released, err := e.releaseAddress(ctx, string(index), subjectID)
		if err != nil {
			return result, err
		}
		result.AddressReleased = released
	}

	// 2. THE USERNAME. TOMBSTONED, not released, and the asymmetry with the
	//    address above is deliberate. An address is private and reissuing it
	//    harms nobody; a handle was PUBLISHED, so every old mention and link
	//    would silently re-point at a stranger. Reissuing it would turn a
	//    privacy action into an impersonation vector aimed at the person who
	//    took it.
	if username := user.Username(); username != "" {
		burned, err := e.burnUsername(ctx, username)
		if err != nil {
			return result, err
		}
		result.UsernameBurned = burned
	}

	// 3. THE ACCOUNT. Last, so nothing claims completion until it is complete —
	//    and it is what the session projection reacts to.
	now := e.now().UTC()
	if err := user.Erase(now); err != nil {
		return result, errs.Internalf("recording the erasure").Wrap(err)
	}
	if _, err := e.users.Save(ctx, userID.String(), user, "erasure:"+subjectID,
		eventsourcing.Metadata{OccurredAt: now, SubjectIDs: []string{subjectID}},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// Another attempt won. Both were erasing the same account.
			return result, nil
		}
		return result, errs.Internalf("recording the erasure").Wrap(err)
	}
	return result, nil
}

// releaseAddress frees the email reservation, reporting whether it did anything.
func (e *Erasure) releaseAddress(ctx context.Context, index, subjectID string) (bool, error) {
	reservation, err := e.emails.Load(ctx, index)
	if err != nil {
		return false, errs.Internalf("loading the address reservation").Wrap(err)
	}
	if err := reservation.Release(subjectID, domain.ReleaseErased, e.now().UTC()); err != nil {
		// CONFLICT specifically: the address is held by a DIFFERENT account,
		// which happens when it was released earlier and registered again by
		// somebody else. Tolerated, because what erasure needs is that this
		// account no longer holds it — and it does not.
		//
		// Branched on the reason rather than on "any error", so a validation
		// failure here still surfaces. Swallowing every error would hide a bad
		// release reason as silently as a benign conflict.
		if errs.ReasonOf(err) == errs.Conflict {
			return false, nil
		}
		return false, errs.Internalf("releasing the address").Wrap(err)
	}
	if _, err := e.emails.Save(ctx, index, reservation, "erasure:"+subjectID+":address",
		eventsourcing.Metadata{OccurredAt: e.now().UTC()},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return false, nil
		}
		return false, errs.Internalf("releasing the address").Wrap(err)
	}
	return true, nil
}

// burnUsername tombstones the handle, reporting whether it did anything.
func (e *Erasure) burnUsername(ctx context.Context, username string) (bool, error) {
	reservation, err := e.usernames.Load(ctx, username)
	if err != nil {
		return false, errs.Internalf("loading the username reservation").Wrap(err)
	}
	if reservation.Tombstoned() {
		return false, nil
	}
	if err := reservation.Tombstone(e.now().UTC()); err != nil {
		// NOT_FOUND specifically: nothing was ever claimed under this handle, so
		// the account's copy is stale. Survivable — there is no handle to burn —
		// and narrowed to that reason so any other failure still surfaces.
		if errs.ReasonOf(err) == errs.NotFound {
			return false, nil
		}
		return false, errs.Internalf("burning the username").Wrap(err)
	}
	if _, err := e.usernames.Save(ctx, username, reservation, "erasure:"+username,
		eventsourcing.Metadata{OccurredAt: e.now().UTC()},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return false, nil
		}
		return false, errs.Internalf("burning the username").Wrap(err)
	}
	return true, nil
}

// ErasureSnapshot is the current state of one erasure request.
//
// Mirrors what the workflow needs and nothing else. It is deliberately NOT the
// User aggregate: a workflow activity that received the whole account would put
// every field of it into workflow history, which is durable and replicated, and
// ADR-002 applies there exactly as it does to the event log.
type ErasureSnapshot struct {
	Exists       bool
	Requested    bool
	Erased       bool
	ScheduledFor time.Time
}

// State reports where an erasure request stands.
//
// Read from the AGGREGATE rather than a projection, and the reason is the same
// one that makes the workflow re-read at all: a cancellation must stop an
// erasure, and a projection that lagged by even a second would let a workflow
// wake, read a stale "still requested", and destroy an account whose owner
// changed their mind. There is no undo for that.
func (e *Erasure) State(ctx context.Context, subjectID string) (ErasureSnapshot, error) {
	if subjectID == "" {
		return ErasureSnapshot{}, errs.ValidationFailedf("a subject is required")
	}
	userID, err := e.directory.UserBySubject(ctx, subjectID)
	if err != nil {
		if errors.Is(err, ErrNoSuchSubject) {
			// Not an error for the workflow: "no account" is a state it handles,
			// and it ends the run rather than retrying forever.
			return ErasureSnapshot{}, nil
		}
		return ErasureSnapshot{}, errs.Internalf("resolving the account").Wrap(err)
	}
	user, err := e.users.Load(ctx, userID.String())
	if err != nil {
		return ErasureSnapshot{}, errs.Internalf("loading the account").Wrap(err)
	}
	if user.State() == domain.StateNone {
		return ErasureSnapshot{}, nil
	}
	when, requested := user.DeletionRequested()
	return ErasureSnapshot{
		Exists:       true,
		Requested:    requested,
		Erased:       user.State() == domain.StateErased,
		ScheduledFor: when,
	}, nil
}
