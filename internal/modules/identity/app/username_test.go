package app

import (
	"context"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ratelimit"
)

// ---------------------------------------------------------------------------
// Fakes
// ---------------------------------------------------------------------------

// handleLimiter reports a fixed decision and remembers every scope it was
// asked about.
//
// The SCOPES are kept rather than a call count, because the assertion that
// matters is that the budget was spent against the CALLER and before anything
// else happened — a counter would pass on a limiter consulted after the stream
// had already been read.
type handleLimiter struct {
	refuse bool
	err    error
	scopes []string
}

func (l *handleLimiter) Allow(ctx context.Context, scope string) (ratelimit.Decision, error) {
	l.scopes = append(l.scopes, scope)
	if l.err != nil {
		// The real limiter fails OPEN: the decision that comes back with the error
		// is allowed-and-degraded.
		return ratelimit.Decision{Degraded: true}, l.err
	}
	if l.refuse {
		return ratelimit.Decision{Rule: "hourly", RetryAfter: time.Minute}, nil
	}
	// ratelimit.Decision's allow flag is unexported, so an allowing decision can
	// only be produced by the real limiter. Driving it through one is better than
	// a fake that could not express the type's own zero-value-denies discipline.
	limiter, err := ratelimit.New(allowingCounter{}, "test-username",
		ratelimit.Rule{Name: "hourly", Limit: 1000, Window: time.Hour})
	if err != nil {
		return ratelimit.Decision{}, err
	}
	return limiter.Allow(ctx, scope)
}

func allowingHandleLimiter() *handleLimiter { return &handleLimiter{} }

// handleLoader serves one reservation and counts how often it was asked.
type handleLoader struct {
	reservation *domain.UsernameReservation
	err         error
	calls       int
}

func (l *handleLoader) Load(
	context.Context, string,
) (*domain.UsernameReservation, error) {
	l.calls++
	return l.reservation, l.err
}

func freeHandle() *domain.UsernameReservation {
	return eventsourcing.NewAggregate(domain.NewUsernameReservation)
}

func heldHandle(username, subject string) *domain.UsernameReservation {
	r := eventsourcing.NewAggregate(domain.NewUsernameReservation)
	r.Apply(&contract.UsernameReserved{
		Username: username, SubjectID: subject, ReservedAt: testNow,
	})
	return r
}

func tombstonedHandle(username string) *domain.UsernameReservation {
	r := heldHandle(username, "subj_gone")
	r.Apply(&contract.UsernameTombstoned{Username: username, TombstonedAt: testNow})
	return r
}

func newUsernameChecks(t *testing.T, loader *handleLoader, limiter *handleLimiter) *Usernames {
	t.Helper()
	u, err := NewUsernames(UsernamesDeps{Reservations: loader, CallerLimiter: limiter})
	if err != nil {
		t.Fatalf("wiring the username check: %v", err)
	}
	return u
}

// ---------------------------------------------------------------------------
// Check
// ---------------------------------------------------------------------------

// TestCheckUsername is the availability answer itself.
//
// The three unavailable cases are asserted to produce the SAME shape — one
// boolean, no reason — because the merge is a control rather than tidiness for
// one of them. "This handle was tombstoned" means "the account that held it was
// erased", which is a fact about a person, and the tombstone exists to protect
// exactly that person.
func TestCheckUsername(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name          string
		reservation   *domain.UsernameReservation
		username      string
		wantAvailable bool
		wantNormal    string
		wantReason    errs.Reason // the zero Reason means "must succeed"
		wantLoads     int
		why           string
	}{
		{
			name:        "a free handle is available",
			reservation: freeHandle(), username: "ada_lovelace",
			wantAvailable: true, wantNormal: "ada_lovelace", wantLoads: 1,
		},
		{
			name:        "the canonical form comes back, not what was typed",
			reservation: freeHandle(), username: "  Ada_Lovelace  ",
			wantAvailable: true, wantNormal: "ada_lovelace", wantLoads: 1,
			why: "a client must be able to show what would ACTUALLY be claimed; echoing " +
				"the input would let somebody believe they hold @Ada_Lovelace",
		},
		{
			name:        "a held handle is unavailable",
			reservation: heldHandle("ada_lovelace", "subj_someone"), username: "ada_lovelace",
			wantAvailable: false, wantNormal: "ada_lovelace", wantLoads: 1,
		},
		{
			name:        "a tombstoned handle is unavailable, and says nothing more",
			reservation: tombstonedHandle("ada_lovelace"), username: "ada_lovelace",
			wantAvailable: false, wantNormal: "ada_lovelace", wantLoads: 1,
			why: "identical to the held case in every observable way. A distinguishable " +
				"answer would announce that the account behind this handle was erased.",
		},
		{
			name:        "a reserved name is unavailable and never reaches the store",
			reservation: freeHandle(), username: "admin",
			wantReason: errs.ValidationFailed, wantLoads: 0,
			why: "refused by the normalizer, so no stream is read at all — the screening " +
				"list is a property of the system, not of any account",
		},
		{
			name:        "a malformed handle is refused before any stream is read",
			reservation: freeHandle(), username: "ada-lovelace",
			wantReason: errs.ValidationFailed, wantLoads: 0,
		},
		{
			name:        "a handle under the floor is refused",
			reservation: freeHandle(), username: "ab",
			wantReason: errs.ValidationFailed, wantLoads: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			loader := &handleLoader{reservation: tt.reservation}
			limiter := allowingHandleLimiter()

			got, err := newUsernameChecks(t, loader, limiter).Check(
				context.Background(),
				CheckUsernameCommand{Username: tt.username, CallerScope: "203.0.113.7"})

			if loader.calls != tt.wantLoads {
				t.Errorf("the reservation was loaded %d times, want %d. %s",
					loader.calls, tt.wantLoads, tt.why)
			}
			// The ceiling is spent on EVERY path, including the ones that refuse
			// before reading anything. A budget that only counted well-formed
			// handles would let a caller probe the normalizer for free, and would
			// make a malformed request measurably cheaper than a well-formed one.
			if len(limiter.scopes) != 1 || limiter.scopes[0] != "203.0.113.7" {
				t.Errorf("the caller ceiling was charged %v, want exactly [203.0.113.7]",
					limiter.scopes)
			}

			if tt.wantReason != "" {
				if r := errs.ReasonOf(err); r != tt.wantReason {
					t.Fatalf("reason %s, want %s (%v). %s", r, tt.wantReason, err, tt.why)
				}
				return
			}
			if err != nil {
				t.Fatalf("Check: %v. %s", err, tt.why)
			}
			if got.Available != tt.wantAvailable {
				t.Errorf("available=%v, want %v. %s", got.Available, tt.wantAvailable, tt.why)
			}
			if got.Username != tt.wantNormal {
				t.Errorf("username %q, want %q. %s", got.Username, tt.wantNormal, tt.why)
			}
		})
	}
}

// TestCheckUsernameResultCarriesNoReason is the type-level half of the merge
// above.
//
// A value-level assertion passes for as long as nobody populates a reason field;
// a struct with no field for one cannot acquire the disclosure by a later commit
// that "improves the error message".
func TestCheckUsernameResultCarriesNoReason(t *testing.T) {
	t.Parallel()

	fields := []string{"Available", "Username"}
	var got []string
	for _, f := range reflect.VisibleFields(reflect.TypeFor[CheckUsernameResult]()) {
		got = append(got, f.Name)
	}
	if len(got) != len(fields) {
		t.Fatalf("CheckUsernameResult has fields %v, want %v — taken, reserved and "+
			"tombstoned are ONE answer, and the third is a fact about a person",
			got, fields)
	}
	for i := range got {
		if got[i] != fields[i] {
			t.Fatalf("CheckUsernameResult has fields %v, want %v", got, fields)
		}
	}
}

// TestCheckUsernameRefusesAnEmptyCallerScope keeps the ceiling from collapsing
// into one bucket.
//
// An empty scope is not a caller nobody can identify; it is EVERY caller, so the
// first few requests anywhere would exhaust the budget for the whole deployment.
// Refused rather than defaulted, because the alternative is a wiring mistake that
// looks like a working rate limit.
func TestCheckUsernameRefusesAnEmptyCallerScope(t *testing.T) {
	t.Parallel()

	loader := &handleLoader{reservation: freeHandle()}
	limiter := allowingHandleLimiter()
	_, err := newUsernameChecks(t, loader, limiter).Check(
		context.Background(), CheckUsernameCommand{Username: "ada_lovelace"})

	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Fatalf("reason %s, want %s (%v)", errs.ReasonOf(err), errs.ValidationFailed, err)
	}
	if loader.calls != 0 {
		t.Error("an unscoped request read a stream")
	}
	if len(limiter.scopes) != 0 {
		t.Error("an unscoped request was charged against a bucket")
	}
}

// TestCheckUsernameCeiling covers the two branches a limiter has.
func TestCheckUsernameCeiling(t *testing.T) {
	t.Parallel()

	t.Run("an exhausted budget refuses and reads nothing", func(t *testing.T) {
		t.Parallel()
		loader := &handleLoader{reservation: freeHandle()}
		limiter := &handleLimiter{refuse: true}

		_, err := newUsernameChecks(t, loader, limiter).Check(
			context.Background(),
			CheckUsernameCommand{Username: "ada_lovelace", CallerScope: "203.0.113.7"})

		if errs.ReasonOf(err) != errs.RateLimited {
			t.Fatalf("reason %s, want %s (%v)", errs.ReasonOf(err), errs.RateLimited, err)
		}
		if loader.calls != 0 {
			t.Error("a refused request still read a stream; the ceiling exists to stop " +
				"an unauthenticated caller making this process read one per socket")
		}
	})

	t.Run("an unreachable limiter FAILS OPEN", func(t *testing.T) {
		t.Parallel()
		loader := &handleLoader{reservation: freeHandle()}
		limiter := &handleLimiter{err: errors.New("valkey is unreachable")}

		got, err := newUsernameChecks(t, loader, limiter).Check(
			context.Background(),
			CheckUsernameCommand{Username: "ada_lovelace", CallerScope: "203.0.113.7"})

		// Open, and deliberately. This call grants nothing — it appends nothing,
		// mints nothing and sends no mail — so refusing on a cache outage would
		// turn a Valkey blip into a signup outage and buy nothing back.
		if err != nil {
			t.Fatalf("a degraded ceiling refused the request: %v", err)
		}
		if !got.Available {
			t.Error("the answer changed because the ceiling was unavailable")
		}
	})
}

// TestNewUsernamesRefusesIncompleteWiring.
//
// The limiter in particular: a nil there has no functional symptom at all — every
// check still answers correctly — so the omission would ship green and the
// endpoint would be an unmetered public read against the event store.
func TestNewUsernamesRefusesIncompleteWiring(t *testing.T) {
	t.Parallel()

	complete := func() UsernamesDeps {
		return UsernamesDeps{
			Reservations:  &handleLoader{reservation: freeHandle()},
			CallerLimiter: allowingHandleLimiter(),
		}
	}
	if _, err := NewUsernames(complete()); err != nil {
		t.Fatalf("complete wiring was refused: %v", err)
	}
	for name, remove := range map[string]func(*UsernamesDeps){
		"reservation loader": func(d *UsernamesDeps) { d.Reservations = nil },
		"caller ceiling":     func(d *UsernamesDeps) { d.CallerLimiter = nil },
	} {
		t.Run("with no "+name, func(t *testing.T) {
			t.Parallel()
			deps := complete()
			remove(&deps)
			if _, err := NewUsernames(deps); err == nil {
				t.Errorf("wiring with no %s was accepted", name)
			}
		})
	}
}

// The limiter port must be satisfied by the production type. A
// consumer-declared interface no producer implements is a mock the tests pass
// against and the composition root cannot wire.
var _ AttemptLimiter = (*ratelimit.Limiter)(nil)
