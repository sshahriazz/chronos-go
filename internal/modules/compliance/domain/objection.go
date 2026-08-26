package domain

import (
	"fmt"
	"maps"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// ObjectionCategory is the stream category, and it is PERMANENT: it is half of
// every stream name, so changing it orphans every objection ever made.
const ObjectionCategory eventsourcing.Category = "objection"

// ObjectionStreamKey is the subject's pseudonym.
//
// One stream per SUBJECT rather than one per purpose, which is the choice worth
// justifying because the aggregate holds a set.
//
// The question asked of it is "what has this person objected to", which a stream
// per purpose would turn into a fan-out across every purpose that exists — and
// the set of purposes grows. One stream also serialises two concurrent
// objections into one ordering, so a person toggling two purposes from two tabs
// cannot produce a state that is half of each.
//
// The cost is that objecting to one purpose contends with objecting to another.
// That is a person clicking two controls on one screen within the same instant,
// where the loser is told to retry — an acceptable price for a right exercised
// perhaps twice in an account's lifetime.
func ObjectionStreamKey(subjectID string) string { return subjectID }

// Purpose is one processing purpose that rests on LEGITIMATE INTERESTS and can
// therefore be objected to under Article 21.
//
// # The set is short because the article is narrow, not because the list is
// # unfinished
//
// Article 21 reaches processing grounded in Article 6(1)(e) or 6(1)(f). It does
// not reach processing grounded in contract or in a legal obligation, which is
// most of what this system does: a password-changed alert, a verification link
// and an invoice are none of them objectionable.
//
// So this set contains only purposes the system can actually STOP, each of which
// a notification-catalogue entry rests on. A purpose nobody can enforce is a
// promise, and a right implemented as a promise is worse than one that is
// honestly absent — the person believes the processing stopped.
type Purpose string

const (
	// PurposeActivityNotifications is messages about what other people did: a
	// mention, an assignment, an expiring key. Legitimate interest — they keep
	// an account useful and nobody agreed to them individually.
	PurposeActivityNotifications Purpose = "activity_notifications"

	// PurposeProductUpdates is product and marketing mail.
	//
	// Article 21(2), which admits no balancing test: direct marketing stops on
	// request, always. It is opt-in here as well (NOTIFICATIONS §3), so an
	// objection overlaps with simply not consenting — and it is offered anyway,
	// because consent that is withheld may be solicited again and an objection
	// may not be, until its author withdraws it.
	PurposeProductUpdates Purpose = "product_updates"
)

// objectionablePurposes is the whole set, in a stable order.
var objectionablePurposes = []Purpose{
	PurposeActivityNotifications, PurposeProductUpdates,
}

// Purposes returns every purpose that may be objected to.
func Purposes() []Purpose { return slices.Clone(objectionablePurposes) }

// Valid reports whether a purpose is one this system can stop.
func (p Purpose) Valid() bool { return slices.Contains(objectionablePurposes, p) }

// Objection is one subject's Article 21 state: which purposes they have stopped.
//
// # Why this is its own aggregate rather than a field on Restriction
//
// They are different rights with different lifetimes, and folding them together
// would make each change to one a decision about the other.
//
// A restriction is total and temporary — everything but storage halts while a
// dispute about the data runs, and it ends when the dispute is settled. An
// objection is per-purpose and open-ended: the account works normally, receipts
// and verification links keep arriving, and one purpose stops until the person
// withdraws it. A subject can hold both at once, and lifting the restriction
// must not release the objection.
//
// The test that keeps them apart is observable rather than doctrinal: a
// restricted subject receives no transactional mail, an objecting subject does.
// If that stops being true, one of the two has absorbed the other.
type Objection struct {
	eventsourcing.Base

	subjectID string

	// objected maps each stopped purpose to when it was stopped.
	//
	// The INSTANT is kept per purpose rather than one for the aggregate, because
	// it is reported to the person — "you objected to this on the 3rd" — and two
	// objections made months apart have two dates.
	objected map[Purpose]time.Time
}

var _ eventsourcing.Root = (*Objection)(nil)

// NewObjection returns an empty aggregate for the repository to rebuild into.
func NewObjection() *Objection { return &Objection{} }

// Exists reports whether anything has ever been recorded for this subject.
func (o *Objection) Exists() bool { return o.subjectID != "" }

// Objected reports whether one purpose is currently stopped, and since when.
func (o *Objection) Objected(p Purpose) (time.Time, bool) {
	at, ok := o.objected[p]
	return at, ok
}

// Purposes returns every purpose currently objected to, oldest objection first.
//
// Sorted by INSTANT rather than by name so a list screen reads as a history. Ties
// break on the purpose string, because a map iteration order that leaked into a
// response would make an otherwise stable list shuffle between polls.
func (o *Objection) Purposes() []Purpose {
	out := slices.Collect(maps.Keys(o.objected))
	slices.SortFunc(out, func(a, b Purpose) int {
		if c := o.objected[a].Compare(o.objected[b]); c != 0 {
			return c
		}
		return slices.Index(objectionablePurposes, a) - slices.Index(objectionablePurposes, b)
	})
	return out
}

// Apply rebuilds state from the log.
//
// An UNKNOWN purpose is applied, not skipped. A purpose removed from the Go
// constants after somebody objected to it is still an objection they made, and a
// replay that dropped it would resume processing they stopped — silently, and
// only for the people who objected earliest. Validation belongs at the write.
func (o *Objection) Apply(event eventsourcing.Event) {
	switch ev := event.(type) {
	case *contract.ProcessingObjected:
		o.subjectID = ev.SubjectID
		if o.objected == nil {
			o.objected = map[Purpose]time.Time{}
		}
		o.objected[Purpose(ev.Purpose)] = ev.ObjectedAt

	case *contract.ProcessingObjectionWithdrawn:
		o.subjectID = ev.SubjectID
		delete(o.objected, Purpose(ev.Purpose))
	}
}

// Object stops one purpose.
//
// Idempotent, and it keeps the FIRST instant: the date has been reported to the
// person, and a repeated call must not move it. The same rule Restriction and
// Deferral follow, for the same reason.
func (o *Objection) Object(subjectID, actorID string, p Purpose, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: an objection needs a subject")
	case actorID == "":
		return fmt.Errorf("compliance: an objection needs an actor")
	case !p.Valid():
		// REFUSED rather than recorded. An objection to a purpose nothing
		// enforces is a promise: the person is told the processing stopped, and
		// no code anywhere consults the record. That failure is invisible from
		// both sides — no error, no metric, and mail that keeps arriving for
		// reasons the recipient now believes were ruled out.
		return fmt.Errorf("compliance: %q is not a processing purpose this system can "+
			"stop; Article 21 reaches processing grounded in legitimate interests, and "+
			"recording an objection nothing enforces would be a promise rather than a "+
			"right", p)
	}
	if _, already := o.objected[p]; already {
		return nil
	}

	eventsourcing.Record(o, &contract.ProcessingObjected{
		SubjectID: subjectID, Purpose: string(p), ActorID: actorID, ObjectedAt: at.UTC(),
	})
	return nil
}

// Withdraw releases one objection.
//
// # It accepts a purpose Object would refuse, and the asymmetry is deliberate
//
// A purpose retired from the Go constants is still one somebody objected to, and
// their record still stops processing (see Apply). Refusing to withdraw it
// because the constant is gone would leave a person unable to release an
// instruction they gave — the one direction of this right that is theirs alone.
//
// Idempotent otherwise: withdrawing what was never objected to is asking for a
// state that already holds.
func (o *Objection) Withdraw(subjectID, actorID string, p Purpose, at time.Time) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: withdrawing an objection needs a subject")
	case actorID == "":
		return fmt.Errorf("compliance: withdrawing an objection needs an actor")
	case p == "":
		return fmt.Errorf("compliance: withdrawing an objection needs a purpose")
	}
	if _, stands := o.objected[p]; !stands {
		return nil
	}

	eventsourcing.Record(o, &contract.ProcessingObjectionWithdrawn{
		SubjectID: subjectID, Purpose: string(p), ActorID: actorID, WithdrawnAt: at.UTC(),
	})
	return nil
}
