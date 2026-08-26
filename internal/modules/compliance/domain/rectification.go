package domain

import (
	"errors"
	"fmt"
	"slices"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RectificationCategory is the stream category, and it is PERMANENT: it is half
// of every stream name, so changing it orphans every correction ever recorded.
const RectificationCategory eventsourcing.Category = "rectification"

// RectificationStreamKey is the subject's pseudonym.
//
// One stream per subject rather than one per request, matching Restriction and
// LegalHold. A correction history is a per-person record — "how many times has
// this person told us we were wrong, and when" is the question a supervisory
// authority asks — and a stream per request would make it a fold across many.
func RectificationStreamKey(subjectID string) string { return subjectID }

// CorrectableField is one field a data subject may correct about themselves.
//
// # A closed set, and the closure is the security property
//
// The wire message already names three fields, so this list adds nothing a
// client can reach. What it adds is a place for the REFUSALS to be written down
// and tested: the fields this system holds and deliberately does not rectify
// here are enumerable beside the ones it does, so "why can I not correct my
// email address through this endpoint" has an answer in code rather than in a
// review comment.
type CorrectableField string

const (
	// CorrectDisplayName is the name other people read.
	CorrectDisplayName CorrectableField = "display_name"

	// CorrectLocale is the language wording is rendered in.
	CorrectLocale CorrectableField = "locale"

	// CorrectTimezone is the zone timestamps are rendered in.
	CorrectTimezone CorrectableField = "timezone"
)

// correctableFields is the whole set, in the order the wire message declares.
var correctableFields = []CorrectableField{
	CorrectDisplayName, CorrectLocale, CorrectTimezone,
}

// CorrectableFields returns every field this right acts on.
func CorrectableFields() []CorrectableField { return slices.Clone(correctableFields) }

// Valid reports whether a field is one rectification acts on.
func (f CorrectableField) Valid() bool { return slices.Contains(correctableFields, f) }

// ErrEmailNotRectifiable refuses a correction of the email address.
//
// # This is the decision this aggregate exists to hold, and it is a REFUSAL
//
// Article 16 covers every inaccurate field, and an email address is the field
// somebody is most likely to have wrong. It is still not correctable here.
//
// identity.md §12 owns the change: a token mailed to the new address proves the
// person can read it, a revert token mailed to the old one gives them a way back
// if the change was not theirs, and a window bounds how long that way back
// lasts. All three exist because a login identifier is also the account-recovery
// route, so moving it is an authentication event and not a data edit.
//
// A rectification path for `email` would move that identifier on one
// authenticated call with none of the proof — a statutory right turned into a
// bypass of an authentication control. Article 16 does not require that the
// correction be unverified; it requires that it be possible, and `ChangeEmail`
// makes it possible.
//
// The refusal lives here rather than only in the schema's silence because a
// field absent from a message is a decision nobody can see. This one names
// itself, carries its reason, and can be asserted against.
var ErrEmailNotRectifiable = errors.New(
	"compliance: an email address is changed through identity's verified email-change " +
		"flow, not through rectification: it is the login identifier and the " +
		"account-recovery route, so moving it requires proof that the new mailbox can " +
		"be read (identity.md §12)")

// MaxCorrectedFields bounds one request.
//
// It is the size of the closed set, so the bound can never refuse a legitimate
// request — a caller naming every field they may correct is at the limit, and a
// caller naming more has named one twice.
const MaxCorrectedFields = 3

// Rectification is one subject's Article 16 history.
//
// # Why it has state at all, when nothing reads it yet
//
// A pure "append an event" use case needs no aggregate, and this one very nearly
// is. What it keeps is the last correction's instant and the count, and both
// exist because Article 12(3) puts a one-month clock on responding to a request
// — so "when did they last exercise this, and how often" is a question with an
// obligation behind it, asked of the log rather than reconstructed from
// timestamps elsewhere.
//
// It also gives the repository something to load, which is what makes two
// concurrent corrections serialise into an ordering instead of two appends that
// each believe they were first.
type Rectification struct {
	eventsourcing.Base

	subjectID   string
	corrections int
	lastAt      time.Time
}

var _ eventsourcing.Root = (*Rectification)(nil)

// NewRectification returns an empty aggregate for the repository to rebuild
// into.
func NewRectification() *Rectification { return &Rectification{} }

// Corrections is how many times this subject has exercised Article 16, and
// LastCorrectedAt is when they last did.
func (r *Rectification) Corrections() int           { return r.corrections }
func (r *Rectification) LastCorrectedAt() time.Time { return r.lastAt }

// Exists reports whether anything has ever been recorded for this subject.
func (r *Rectification) Exists() bool { return r.subjectID != "" }

// Apply rebuilds state from the log.
func (r *Rectification) Apply(event eventsourcing.Event) {
	if ev, ok := event.(*contract.PersonalDataCorrected); ok {
		r.subjectID = ev.SubjectID
		r.corrections++
		r.lastAt = ev.CorrectedAt
	}
}

// Correct records that the subject asserted these fields were inaccurate.
//
// # It is NOT idempotent, and that is the opposite of Restriction on purpose
//
// A restriction is a STATE: asking for it twice asks for something that already
// holds, so the second call records nothing. A correction is an EVENT in a
// person's history — they told us again that something is wrong — and there is
// no state for the second one to already be in.
//
// The concrete case is a person correcting a field to the same value twice,
// because the first attempt appeared not to work. Recording nothing the second
// time would lose a request that was made, and Article 12(3)'s clock runs from
// requests rather than from changes.
//
// Deduplication of a RETRY is a different problem and is solved where it belongs:
// the repository refuses a replayed idempotency key, so a client resending one
// HTTP request appends once.
func (r *Rectification) Correct(
	subjectID, actorID string, fields []CorrectableField, at time.Time,
) error {
	switch {
	case subjectID == "":
		return fmt.Errorf("compliance: a correction needs a subject")
	case actorID == "":
		return fmt.Errorf("compliance: a correction needs an actor")
	case len(fields) == 0:
		return fmt.Errorf("compliance: a correction that names no field corrects nothing; " +
			"an event asserting that a right was exercised over no data is evidence of " +
			"nothing")
	case len(fields) > MaxCorrectedFields:
		return fmt.Errorf("compliance: a correction names at most %d fields and this one "+
			"names %d, so one is repeated", MaxCorrectedFields, len(fields))
	}

	seen := make(map[CorrectableField]struct{}, len(fields))
	names := make([]string, 0, len(fields))
	for _, f := range fields {
		if !f.Valid() {
			return fmt.Errorf("compliance: %q is not a field this right corrects", f)
		}
		if _, dup := seen[f]; dup {
			// REFUSED rather than deduplicated. A request naming one field twice
			// was built by something that lost track of what it was sending, and
			// silently collapsing it would record a correction the caller cannot
			// reconcile with what it sent.
			return fmt.Errorf("compliance: %q is named twice in one correction", f)
		}
		seen[f] = struct{}{}
		names = append(names, string(f))
	}

	eventsourcing.Record(r, &contract.PersonalDataCorrected{
		SubjectID:   subjectID,
		Fields:      names,
		ActorID:     actorID,
		CorrectedAt: at.UTC(),
	})
	return nil
}
