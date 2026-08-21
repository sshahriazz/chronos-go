package app

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// UsernameCategory names the public handle's uniqueness stream:
// reservation_username-<handle>.
//
// KurrentDB derives a category from everything before the FIRST dash, so the
// category may not contain one — and neither may the key, which is why
// domain.NormalizeUsername excludes the hyphen from the character set rather
// than treating it as a style choice.
//
// The key is the HANDLE ITSELF, in the clear, and that is the one place this
// differs from ReservationCategory (ADR-051). ADR-048 hides an address because an
// address is secret and a stream name can never be shredded; a handle is
// published by design, so hiding it would buy nothing and cost the ability to
// read the log while debugging. There is consequently no keyed derivation here,
// no k_res equivalent, and nothing to lose or rotate.
const UsernameCategory eventsourcing.Category = "reservation_username"

// Usernames answers "is this handle free?" and nothing else.
//
// A use case of its own rather than a method on Registration, and the split is
// the one every other port in this module is drawn on: this one is reached by an
// unauthenticated stranger typing into a signup form, and it must hold nothing
// that could create an account, spend a token or claim a handle. It holds a
// LOADER and a ceiling. There is no appender here at all.
type Usernames struct {
	reservations AggregateLoader[*domain.UsernameReservation]
	byCaller     AttemptLimiter
	log          *slog.Logger
}

// UsernamesDeps is everything the check needs.
type UsernamesDeps struct {
	// Reservations loads the handle's aggregate. It reads the STREAM, not a
	// projection, and that is the whole reason the answer is worth giving: a
	// projection is behind the log by construction, so it would report a handle
	// free that was claimed a moment ago — and the claim it would then lose is
	// the one that matters, because it happens under contention.
	Reservations AggregateLoader[*domain.UsernameReservation]

	// CallerLimiter bounds how many handles one caller may test.
	//
	// REQUIRED. This endpoint is an enumeration oracle BY DESIGN — publicity is
	// the entire point of a handle — but "an attacker may learn whether @alice
	// exists" is not the same permission as "an attacker may read a stream from
	// KurrentDB as fast as they can open sockets". The ceiling bounds the second
	// without pretending to bound the first.
	CallerLimiter AttemptLimiter

	// Log is optional and defaults to slog.Default(). A handle is public, so it
	// is the one user-supplied value in this module that MAY be logged — and it
	// still is not, because a log line that carried it would be the only record
	// tying a probe to a caller's address.
	Log *slog.Logger
}

// NewUsernames validates the wiring and returns the use case.
func NewUsernames(deps UsernamesDeps) (*Usernames, error) {
	switch {
	case deps.Reservations == nil:
		return nil, fmt.Errorf("identity/app: a username check needs a reservation loader")
	case deps.CallerLimiter == nil:
		return nil, fmt.Errorf("identity/app: a username check needs a caller ceiling; " +
			"without one an unauthenticated caller can read one stream from the event " +
			"store per request, as fast as they can open sockets")
	}
	log := deps.Log
	if log == nil {
		log = slog.Default()
	}
	return &Usernames{
		reservations: deps.Reservations, byCaller: deps.CallerLimiter, log: log,
	}, nil
}

// CheckUsernameCommand asks whether a handle can be claimed.
type CheckUsernameCommand struct {
	// Username is the raw handle as typed. It is normalized here, and the
	// normalized form is the only one that names a stream.
	Username string

	// CallerScope identifies whoever is asking, for the ceiling. REQUIRED for the
	// reason ResendVerificationCommand's is: an empty value puts every caller in
	// one bucket, and the first few requests anywhere exhaust the budget for
	// everybody.
	CallerScope string
}

// CheckUsernameResult is one boolean and the canonical form.
//
// # There is deliberately no reason field
//
// Taken, reserved and tombstoned are ONE answer. That is not the usual
// oracle-avoidance in this module — a handle is public and this endpoint exists
// to answer questions about it — and the reason is narrower and only applies to
// one of the three: "this handle was tombstoned" means "the account that held it
// was erased", which is a fact about a PERSON. The tombstone exists to protect
// that person, so an API that announced it would undo the protection at the
// point of use.
//
// The other two are merged with it rather than distinguished from each other,
// because a two-valued answer with one value split off is exactly the shape a
// client would render as "erased", and because there is nothing to do
// differently: the action for all three is to pick another handle.
type CheckUsernameResult struct {
	// Available is true only when the handle is free AND well-formed AND not
	// reserved.
	Available bool

	// Username is the NORMALIZED form, echoed so a client can show what will
	// actually be claimed. Empty when the input could not be normalized.
	Username string
}

// Check reports whether a handle can be claimed.
//
// # It is an enumeration oracle, and that is intentional
//
// A caller can learn that @alice is taken. They can learn it here, and they can
// learn it from any page that renders a mention, from a profile URL, and from
// the person themselves — because a handle is PUBLISHED, and publication is its
// purpose (ADR-051). Nothing about this endpoint is a leak, and nobody should
// "harden" it into an indistinguishable response later: the resulting API would
// answer no question, the signup form would be unable to tell a person their
// handle was taken until they had already spent their verification link, and the
// information would remain freely available everywhere else.
//
// The one thing it must NOT distinguish is a tombstone; see CheckUsernameResult.
//
// # The answer is advisory, and the claim is authoritative
//
// This reads the reservation stream at an instant. Between the answer and a
// claim, somebody else may take the handle — so VerifyEmail re-decides against
// the stream and the atomic append's precondition settles it (ADR-044). Any
// check-then-claim is racy by construction; the point of this call is that a
// person finds out at the FORM rather than after clicking a link they cannot get
// back.
//
// # Malformed input answers "unavailable", not an error
//
// A handle that fails normalization — too short, a hyphen, a reserved name — is
// reported as unavailable with the validation error attached, because the
// question "may I have this?" has an honest answer for it and that answer is no.
func (u *Usernames) Check(ctx context.Context, cmd CheckUsernameCommand) (CheckUsernameResult, error) {
	if cmd.CallerScope == "" {
		return CheckUsernameResult{}, errs.ValidationFailedf("a caller scope is required")
	}

	// Spent FIRST, before normalization and before any stream is read. A ceiling
	// that only counted well-formed handles would let an attacker probe the
	// normalizer for free, and — worse — would make a malformed request cheaper
	// than a well-formed one, which is a timing signal about the handle rather
	// than about the request.
	if err := u.spend(ctx, cmd.CallerScope); err != nil {
		return CheckUsernameResult{}, err
	}

	normalized, err := domain.NormalizeUsername(cmd.Username)
	if err != nil {
		// The validation error is returned as-is. It says WHY the handle is
		// unusable — too short, a bad character, reserved — and every one of those
		// is a property of the caller's own bytes plus a public rule, so none of
		// them says anything about any account.
		return CheckUsernameResult{}, err
	}

	reservation, err := u.reservations.Load(ctx, normalized)
	if err != nil {
		return CheckUsernameResult{}, fmt.Errorf("loading the username reservation: %w", err)
	}
	return CheckUsernameResult{Available: reservation.Available(), Username: normalized}, nil
}

// spend charges the caller's ceiling.
//
// It FAILS OPEN, like every other ceiling in this module, and says so when it
// does. The alternative — refusing when Valkey is unreachable — would make a
// cache outage into a signup outage, and this call grants nothing: the worst a
// caller does with an unmetered budget is read streams that hold no secret.
func (u *Usernames) spend(ctx context.Context, scope string) error {
	decision, err := u.byCaller.Allow(ctx, scope)
	if err != nil {
		u.log.WarnContext(ctx, "the username-check ceiling could not be evaluated; "+
			"the request was allowed unmetered",
			"module", "identity", "reason", "ceiling_unavailable", "error", err)
		return nil
	}
	if !decision.Allowed() {
		return errs.RateLimitedf("too many username checks; try again later").
			WithMeta(map[string]string{
				"rule":        decision.Rule,
				"retry_after": decision.RetryAfter.String(),
			})
	}
	return nil
}
