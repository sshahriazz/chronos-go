package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// PersonalDataCorrections applies the correction to whoever owns the field.
//
// # compliance does NOT write the vault, and this port is why
//
// The obvious implementation of Article 16 is `vault.PutAll` from inside this
// use case. It is wrong, and it is wrong in a way that only shows up in a
// support conversation.
//
// The display name, the locale and the timezone belong to `profile`. Its own
// aggregate serialises concurrent saves, its own event records that the value
// changed, and its projection is rebuilt from that event. A second writer would
// put a value in the vault that no `profile.ProfileUpdated.v1` accounts for — so
// the vault would say one thing and profile's history another, and the history
// is what an impersonation report is settled from. profile's own use case
// documents the same ordering hazard from the other side.
//
// It is also the import contract (CONVENTIONS §2): `modules/compliance/**` may
// import another module's `contract` package and nothing else. Reaching
// `profile/app` from here is not available, and that constraint is pointing at
// the right design rather than obstructing it. The composition root satisfies
// this port with profile's use case, exactly as it satisfies AccountErasure with
// identity's.
type PersonalDataCorrections interface {
	// Correct applies one sparse correction. A nil pointer means the field was
	// not part of the request.
	//
	// It returns whatever the owning module returns, INCLUDING its validation
	// errors: the correction has to satisfy the same rules as the settings
	// screen, or a person exercising a statutory right could store a display
	// name the product refuses.
	Correct(ctx context.Context, c PersonalDataCorrection) error
}

// PersonalDataCorrection is one sparse correction, in the shape the owning
// module accepts.
//
// Pointers rather than strings, mirroring `profile.UpdateCommand` and the wire
// message: nil is "not part of this request", and an empty string is a value the
// owning module refuses for its own reasons. Collapsing the two would make a
// correction of one field silently touch the others.
type PersonalDataCorrection struct {
	SubjectID string

	DisplayName *string
	Locale      *string
	Timezone    *string

	// IdempotencyKey is the CALLER'S key, forwarded unchanged.
	//
	// Unchanged so that a client retrying one HTTP request produces one write in
	// the owning module as well as one event here. Deriving a second key would
	// make the retry idempotent in compliance and duplicated in profile, which is
	// the worst of both: the log would record one correction and the vault would
	// have been written twice.
	IdempotencyKey string
}

// RectifyCommand is a data subject correcting their own data (Article 16).
type RectifyCommand struct {
	// SubjectID is the CALLER'S pseudonym, from the session. There is
	// deliberately no field naming another subject: a request that could name a
	// subject is a request to exercise somebody else's rights.
	SubjectID string

	// ActorID is who asked. The subject, today and by construction.
	ActorID string

	DisplayName *string
	Locale      *string
	Timezone    *string

	IdempotencyKey string
}

// fields returns what this command names, in the schema's declared order.
//
// The ORDER is fixed rather than incidental: it reaches the event, the response
// and eventually a report, and a set whose rendering depends on map iteration
// would make two identical corrections look different.
func (c RectifyCommand) fields() []domain.CorrectableField {
	out := make([]domain.CorrectableField, 0, domain.MaxCorrectedFields)
	if c.DisplayName != nil {
		out = append(out, domain.CorrectDisplayName)
	}
	if c.Locale != nil {
		out = append(out, domain.CorrectLocale)
	}
	if c.Timezone != nil {
		out = append(out, domain.CorrectTimezone)
	}
	return out
}

// RectifyResult is what was corrected, and when.
type RectifyResult struct {
	// Fields names what the subject asked to have corrected, in the schema's
	// order. Never the values — see contract.PersonalDataCorrected.
	Fields []string

	// CorrectedAt is when it was recorded, UTC.
	CorrectedAt time.Time
}

// Rectifications is the Article 16 use case.
type Rectifications struct {
	repo    *eventsourcing.Repository[*domain.Rectification]
	applier PersonalDataCorrections
	now     func() time.Time
}

// RectificationsDeps is what Rectifications needs.
type RectificationsDeps struct {
	Repo    *eventsourcing.Repository[*domain.Rectification]
	Applier PersonalDataCorrections
	Now     func() time.Time
}

func NewRectifications(d RectificationsDeps) (*Rectifications, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("compliance: a rectification repository is required; the " +
			"record that a right was exercised is what has the statutory clock on it, and " +
			"it lives in the log")
	case d.Applier == nil:
		return nil, fmt.Errorf("compliance: a correction applier is required; without one " +
			"this endpoint records that somebody's data was corrected and corrects " +
			"nothing — which is the worst available outcome, because the log would then " +
			"be evidence that we answered a request we did not act on")
	case d.Now == nil:
		return nil, fmt.Errorf("compliance: a clock is required")
	}
	return &Rectifications{repo: d.Repo, applier: d.Applier, now: d.Now}, nil
}

// Rectify corrects inaccurate personal data about the caller.
//
// # The order: correct first, record second
//
// The value is written by the owning module BEFORE this appends its own event,
// and the reverse would be wrong for the reason profile's own use case gives for
// writing the vault before its event. If the append fails after the correction
// landed, the data is right and the log has not yet recorded that a right was
// exercised — the client's retry carries the same idempotency key, the owning
// module's write is an idempotent upsert, and the append then lands. If the
// event were appended first and the correction failed, the log would assert that
// we acted on a statutory request we did not act on, which is evidence of
// compliance that is false.
//
// The asymmetry in the failure costs is what settles it: a missing record of a
// correction that happened is recoverable by retrying, and a record of a
// correction that never happened is not detectable at all.
func (r *Rectifications) Rectify(
	ctx context.Context, cmd RectifyCommand,
) (RectifyResult, error) {
	switch {
	case cmd.SubjectID == "":
		return RectifyResult{}, errs.ValidationFailedf("a subject is required")
	case cmd.ActorID == "":
		return RectifyResult{}, errs.Internalf(
			"no authenticated subject reached the rectification handler")
	case cmd.IdempotencyKey == "":
		return RectifyResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	fields := cmd.fields()
	if len(fields) == 0 {
		return RectifyResult{}, errs.ValidationFailedf(
			"a rectification that names no field corrects nothing; name at least one of " +
				"display_name, locale or timezone")
	}

	key := domain.RectificationStreamKey(cmd.SubjectID)
	agg, err := r.repo.Load(ctx, key)
	if err != nil {
		return RectifyResult{}, errs.Internalf("loading the rectification history").Wrap(err)
	}

	now := r.now().UTC()
	if err := agg.Correct(cmd.SubjectID, cmd.ActorID, fields, now); err != nil {
		if errors.Is(err, domain.ErrEmailNotRectifiable) {
			// Unreachable from the wire — the schema has no email field — and
			// mapped anyway, because the day somebody adds one this is the answer
			// they should get rather than a generic refusal.
			return RectifyResult{}, errs.ValidationFailedf("%s", err).Wrap(err)
		}
		return RectifyResult{}, errs.ValidationFailedf("%s", err).Wrap(err)
	}

	// THE CORRECTION ITSELF, through whoever owns the field. Before the append;
	// see the doc comment.
	//
	// Its error is returned unwrapped in reason: the owning module refuses a
	// display name of the wrong shape with a message written for a person, and
	// replacing that with one of ours would tell somebody exercising a right
	// less than the settings screen tells somebody editing a preference.
	if err := r.applier.Correct(ctx, PersonalDataCorrection{
		SubjectID:      cmd.SubjectID,
		DisplayName:    cmd.DisplayName,
		Locale:         cmd.Locale,
		Timezone:       cmd.Timezone,
		IdempotencyKey: cmd.IdempotencyKey,
	}); err != nil {
		return RectifyResult{}, err
	}

	if _, err := r.repo.Save(ctx, key, agg, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OccurredAt: now,
			// The subject is named so a later Article 19 report — "who was this
			// disclosed to, and were they told" — has an audience to resolve.
			// Nothing notifies on this event today: the correction's own
			// `profile.ProfileUpdated.v1` already sends a Security-class alert,
			// and two mails for one action is one too many.
			SubjectIDs: []string{cmd.SubjectID},
			ActorID:    cmd.ActorID,
		}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return RectifyResult{}, errs.Conflictf(
				"your data changed while this correction was being recorded; try again")
		}
		return RectifyResult{}, errs.Internalf("recording the correction").Wrap(err)
	}

	names := make([]string, 0, len(fields))
	for _, f := range fields {
		names = append(names, string(f))
	}
	return RectifyResult{Fields: names, CorrectedAt: now}, nil
}
