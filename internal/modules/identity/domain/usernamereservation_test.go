package domain_test

import (
	"reflect"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/identity/contract"
	"github.com/chronos/chronos-go/internal/modules/identity/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// handleAt is the instant every case below decides at. A fixed value rather than
// time.Now, because nothing about a handle's availability depends on the clock —
// and a test that passed a moving instant would suggest it did.
var handleAt = time.Date(2026, 8, 20, 12, 0, 0, 0, time.UTC)

const (
	theHandle   = "ada_lovelace"
	holder      = "subj_01H8XG5N2QK7VB3C9WPYZR4TFN"
	otherHolder = "subj_01H8XG5N2QK7VB3C9WPYZR4TFP"
)

// replayHandle rebuilds a reservation from a stream, so a case can arrange a
// held or tombstoned handle through Apply rather than by reaching into fields.
func replayHandle(events ...eventsourcing.Event) *domain.UsernameReservation {
	r := eventsourcing.NewAggregate(domain.NewUsernameReservation)
	for _, e := range events {
		r.Apply(e)
	}
	return r
}

func eventTypes(r *domain.UsernameReservation) []string {
	out := make([]string, 0, len(r.Uncommitted()))
	for _, e := range r.Uncommitted() {
		out = append(out, e.EventType())
	}
	return out
}

// TestUsernameReservationReserve covers who may claim a handle and what is
// recorded when they do.
func TestUsernameReservationReserve(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		arrange    func() *domain.UsernameReservation
		username   string
		subject    string
		wantReason errs.Reason // the zero Reason means "must succeed"
		wantEvents []string
		why        string
	}{
		{
			name:     "a free handle is claimed",
			arrange:  func() *domain.UsernameReservation { return replayHandle() },
			username: theHandle, subject: holder,
			wantEvents: []string{"identity.UsernameReserved.v1"},
		},
		{
			name: "re-claiming our own handle records nothing",
			arrange: func() *domain.UsernameReservation {
				return replayHandle(&contract.UsernameReserved{
					Username: theHandle, SubjectID: holder, ReservedAt: handleAt,
				})
			},
			username: theHandle, subject: holder,
			wantEvents: nil,
			why: "a retried verification must not fail and must not record a second " +
				"claim; the append would then carry an entry whose only content is a " +
				"precondition, turning a replay into a concurrency failure",
		},
		{
			name: "a handle somebody else holds is refused",
			arrange: func() *domain.UsernameReservation {
				return replayHandle(&contract.UsernameReserved{
					Username: theHandle, SubjectID: otherHolder, ReservedAt: handleAt,
				})
			},
			username: theHandle, subject: holder,
			wantReason: errs.Conflict,
		},
		{
			name: "a tombstoned handle is refused forever",
			arrange: func() *domain.UsernameReservation {
				return replayHandle(
					&contract.UsernameReserved{
						Username: theHandle, SubjectID: otherHolder, ReservedAt: handleAt,
					},
					&contract.UsernameTombstoned{Username: theHandle, TombstonedAt: handleAt},
				)
			},
			username: theHandle, subject: holder,
			wantReason: errs.Conflict,
			why: "THE rule ADR-051 exists for. If @alice could be reissued after an " +
				"erasure, every old mention and link would silently re-point at a " +
				"stranger — an erasure request would create an impersonation vector " +
				"aimed at the person it protects.",
		},
		{
			name:     "an empty handle is refused",
			arrange:  func() *domain.UsernameReservation { return replayHandle() },
			username: "", subject: holder,
			wantReason: errs.ValidationFailed,
		},
		{
			name:     "an empty subject is refused",
			arrange:  func() *domain.UsernameReservation { return replayHandle() },
			username: theHandle, subject: "",
			wantReason: errs.ValidationFailed,
		},
		{
			name: "a claim for a different handle on this stream is an internal fault",
			arrange: func() *domain.UsernameReservation {
				return replayHandle(&contract.UsernameReserved{
					Username: theHandle, SubjectID: otherHolder, ReservedAt: handleAt,
				})
			},
			username: "grace_hopper", subject: holder,
			wantReason: errs.Internal,
			why: "unreachable through the repository, because the stream is named from " +
				"the handle — but reachable through a hand-built aggregate, and " +
				"overwriting silently would move a claim between two handles",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			r := tt.arrange()
			err := r.Reserve(tt.username, tt.subject, handleAt)

			if tt.wantReason != "" {
				if got := errs.ReasonOf(err); got != tt.wantReason {
					t.Fatalf("reason %s, want %s (%v). %s", got, tt.wantReason, err, tt.why)
				}
				if n := len(r.Uncommitted()); n != 0 {
					t.Errorf("%d events recorded by a refused claim", n)
				}
				return
			}
			if err != nil {
				t.Fatalf("Reserve: %v. %s", err, tt.why)
			}
			got := eventTypes(r)
			if len(got) != len(tt.wantEvents) {
				t.Fatalf("recorded %v, want %v. %s", got, tt.wantEvents, tt.why)
			}
			for i := range got {
				if got[i] != tt.wantEvents[i] {
					t.Fatalf("recorded %v, want %v", got, tt.wantEvents)
				}
			}
		})
	}
}

// TestAClaimNamesItsHolderAndATombstoneNamesNobody is the shape ADR-051's
// lawfulness argument rests on, asserted rather than described.
//
// The tombstone is data retained AFTER an erasure request, and that is only
// defensible because it retains no personal data: it is the handle string plus
// "never reissue", with no subject, no actor and nothing that links it back to
// whoever held it. A SubjectID field appearing on UsernameTombstoned would make
// the erasure retain a permanent record of the person who asked for it.
func TestAClaimNamesItsHolderAndATombstoneNamesNobody(t *testing.T) {
	t.Parallel()

	r := replayHandle()
	if err := r.Reserve(theHandle, holder, handleAt); err != nil {
		t.Fatalf("Reserve: %v", err)
	}
	claim, ok := r.Uncommitted()[0].(*contract.UsernameReserved)
	if !ok {
		t.Fatalf("recorded %T, want UsernameReserved", r.Uncommitted()[0])
	}
	if claim.SubjectID != holder {
		t.Errorf("the claim names %q, want %q", claim.SubjectID, holder)
	}

	held := replayHandle(&contract.UsernameReserved{
		Username: theHandle, SubjectID: holder, ReservedAt: handleAt,
	})
	if err := held.Tombstone(handleAt); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	stone, ok := held.Uncommitted()[0].(*contract.UsernameTombstoned)
	if !ok {
		t.Fatalf("recorded %T, want UsernameTombstoned", held.Uncommitted()[0])
	}
	if stone.Username != theHandle {
		t.Errorf("the tombstone names handle %q, want %q", stone.Username, theHandle)
	}

	// The strongest form of the assertion: the TYPE has no field that could carry
	// a subject. A value-level check would pass for as long as nobody happened to
	// populate one.
	if _, hasSubject := any(stone).(interface{ Subject() string }); hasSubject {
		t.Error("UsernameTombstoned exposes a subject")
	}
	fields := structFieldNames(t, stone)
	for _, f := range fields {
		if f == "SubjectID" || f == "ActorID" || f == "UserID" {
			t.Errorf("UsernameTombstoned has field %q. A tombstone outlives an erasure, "+
				"so a field naming the erased account would be a permanent record "+
				"linking a person to their own erasure request (ADR-051)", f)
		}
	}

	// And the aggregate FORGETS the holder when it applies the tombstone, so an
	// aggregate rebuilt from a tombstoned stream holds nothing that names anybody.
	rebuilt := replayHandle(
		&contract.UsernameReserved{Username: theHandle, SubjectID: holder, ReservedAt: handleAt},
		&contract.UsernameTombstoned{Username: theHandle, TombstonedAt: handleAt},
	)
	if got := rebuilt.SubjectID(); got != "" {
		t.Errorf("a tombstoned reservation still names subject %q", got)
	}
	if rebuilt.Held() {
		t.Error("a tombstoned reservation still reports itself held")
	}
	if !rebuilt.Tombstoned() {
		t.Error("a tombstoned reservation does not report itself tombstoned")
	}
	if rebuilt.Available() {
		t.Error("a tombstoned handle reports itself available; it may never be reissued")
	}
}

// TestTombstone covers the transition's own rules.
func TestTombstone(t *testing.T) {
	t.Parallel()

	t.Run("a second tombstone records nothing", func(t *testing.T) {
		t.Parallel()
		r := replayHandle(
			&contract.UsernameReserved{Username: theHandle, SubjectID: holder, ReservedAt: handleAt},
			&contract.UsernameTombstoned{Username: theHandle, TombstonedAt: handleAt},
		)
		if err := r.Tombstone(handleAt); err != nil {
			t.Fatalf("Tombstone: %v", err)
		}
		if n := len(r.Uncommitted()); n != 0 {
			t.Errorf("%d events for a repeated tombstone", n)
		}
	})

	t.Run("a handle nobody claimed cannot be tombstoned", func(t *testing.T) {
		t.Parallel()
		r := replayHandle()
		if got := errs.ReasonOf(r.Tombstone(handleAt)); got != errs.NotFound {
			t.Fatalf("reason %s, want %s", got, errs.NotFound)
		}
		if n := len(r.Uncommitted()); n != 0 {
			t.Errorf("%d events; a tombstone on an unclaimed handle would burn a name "+
				"on the strength of a typo, permanently and with no way back", n)
		}
	})

	t.Run("there is no way back", func(t *testing.T) {
		t.Parallel()
		// Asserted against the TYPE. The rule is "a tombstone is permanent", and
		// the only thing that could break it is a method that clears one — so the
		// absence of such a method is where the rule lives.
		var r any = domain.NewUsernameReservation()
		for _, name := range []string{"Untombstone", "Clear", "Release", "Revive", "Restore"} {
			if hasMethod(r, name) {
				t.Errorf("UsernameReservation has a %s method. Reissuing a handle is the "+
					"failure this type exists to prevent (ADR-051)", name)
			}
		}
	})
}

// TestAHandleIsNeverReissuedEndToEnd walks the whole life of one handle through
// the aggregate: claimed, erased, and refused to everybody afterwards.
//
// It is a sequence rather than a table because the property is about ORDER — the
// refusal must survive the claim being gone, which no single state can show.
func TestAHandleIsNeverReissuedEndToEnd(t *testing.T) {
	t.Parallel()

	r := replayHandle()
	if err := r.Reserve(theHandle, holder, handleAt); err != nil {
		t.Fatalf("the first claim was refused: %v", err)
	}
	// Committed, as the append would.
	replayed := replayHandle(r.Uncommitted()...)

	if err := replayed.Tombstone(handleAt.Add(time.Hour)); err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	erased := replayHandle(
		&contract.UsernameReserved{Username: theHandle, SubjectID: holder, ReservedAt: handleAt},
		&contract.UsernameTombstoned{Username: theHandle, TombstonedAt: handleAt.Add(time.Hour)},
	)

	// Nobody may take it: not a stranger, and not the original holder either.
	// Both matter. The stranger is the impersonation case; the original holder is
	// the one whose erasure this was, and re-registering under the same handle
	// would defeat the deletion they asked for.
	for _, subject := range []string{otherHolder, holder} {
		if got := errs.ReasonOf(erased.Reserve(theHandle, subject, handleAt.Add(2*time.Hour))); got != errs.Conflict {
			t.Errorf("subject %s reclaimed a tombstoned handle (reason %s)", subject, got)
		}
	}
	if n := len(erased.Uncommitted()); n != 0 {
		t.Errorf("%d events recorded against a tombstoned handle", n)
	}
}

// structFieldNames lists a struct pointer's exported field names.
//
// Reflection rather than a hand-written list, so a field ADDED to
// UsernameTombstoned is caught by the test above instead of slipping past a
// literal that was written before it existed.
func structFieldNames(t *testing.T, v any) []string {
	t.Helper()
	typ := reflect.TypeOf(v)
	for typ.Kind() == reflect.Pointer {
		typ = typ.Elem()
	}
	if typ.Kind() != reflect.Struct {
		t.Fatalf("%T is not a struct", v)
	}
	out := make([]string, 0, typ.NumField())
	for _, f := range reflect.VisibleFields(typ) {
		out = append(out, f.Name)
	}
	return out
}

// hasMethod reports whether a value has an exported method by that name.
func hasMethod(v any, name string) bool {
	_, ok := reflect.TypeOf(v).MethodByName(name)
	return ok
}
