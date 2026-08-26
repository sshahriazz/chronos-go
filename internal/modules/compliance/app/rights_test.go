package app_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/chronos/chronos-go/internal/modules/compliance/app"
	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/modules/compliance/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

var rightsAt = time.Date(2026, 8, 26, 9, 0, 0, 0, time.UTC)

// --------------------------------------------------------------------------
// Article 16 — rectification
// --------------------------------------------------------------------------

// recordingApplier stands in for whichever module owns the field.
//
// In production this is profile's own write use case, reached through a port
// because compliance may not import another module's app package. Here it
// records what it was handed and can be made to fail.
type recordingApplier struct {
	applied []app.PersonalDataCorrection
	err     error
}

func (r *recordingApplier) Correct(
	_ context.Context, c app.PersonalDataCorrection,
) error {
	r.applied = append(r.applied, c)
	return r.err
}

func newRectifications(t *testing.T, applier app.PersonalDataCorrections) (
	*app.Rectifications, *memoryStore,
) {
	t.Helper()
	events := newMemoryStore()
	r, err := app.NewRectifications(app.RectificationsDeps{
		Repo: eventsourcing.NewRepository[*domain.Rectification](
			events, events.codec, nil,
			domain.RectificationCategory, domain.NewRectification),
		Applier: applier,
		Now:     func() time.Time { return rightsAt },
	})
	if err != nil {
		t.Fatalf("building the use case: %v", err)
	}
	return r, events
}

func ptr[T any](v T) *T { return &v }

// THE CORRECTION IS APPLIED BY THE MODULE THAT OWNS THE FIELD.
//
// compliance owns the retention policy and none of the data (compliance.md §15).
// A use case that wrote the vault itself would leave a value that no
// `profile.ProfileUpdated.v1` accounts for — the vault saying one thing and
// profile's own history another, which is what a support conversation about
// impersonation is settled from.
//
// The idempotency key travels UNCHANGED, which is the second half of the same
// property: a derived key would make a client's retry idempotent here and
// duplicated there, so the log would record one correction and the vault would
// have been written twice.
func TestTheCorrectionIsAppliedByTheOwningModule(t *testing.T) {
	applier := &recordingApplier{}
	rect, _ := newRectifications(t, applier)

	if _, err := rect.Rectify(context.Background(), app.RectifyCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		DisplayName: ptr("Sam"), IdempotencyKey: "key-1",
	}); err != nil {
		t.Fatalf("rectifying: %v", err)
	}

	if len(applier.applied) != 1 {
		t.Fatalf("the owning module was called %d times, want 1. A correction that "+
			"records the right and changes nothing is evidence that we answered a "+
			"request we did not act on", len(applier.applied))
	}
	got := applier.applied[0]
	if got.DisplayName == nil || *got.DisplayName != "Sam" {
		t.Errorf("the value reached the owning module as %v", got.DisplayName)
	}
	if got.IdempotencyKey != "key-1" {
		t.Errorf("the idempotency key was rewritten to %q; a retry would then be "+
			"deduplicated here and duplicated there", got.IdempotencyKey)
	}
}

// THE EVENT NAMES FIELDS AND CARRIES NO VALUES.
//
// ADR-002, asserted against the stored bytes rather than against the struct: the
// event is what is permanent, and the payload is what a later reader sees.
func TestTheCorrectionEventCarriesNoValues(t *testing.T) {
	const value = "Sam The Corrected Person"
	rect, events := newRectifications(t, &recordingApplier{})

	if _, err := rect.Rectify(context.Background(), app.RectifyCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		DisplayName: ptr(value), IdempotencyKey: "key-1",
	}); err != nil {
		t.Fatalf("rectifying: %v", err)
	}

	stored := events.streams["rectification-subj_1"]
	if len(stored) != 1 {
		t.Fatalf("the stream holds %d events, want 1", len(stored))
	}
	if strings.Contains(string(stored[0].Payload), value) {
		t.Fatalf("the stored event carries the corrected value: %s. An event is "+
			"permanent and replayable, so a name in one outlives every erasure request "+
			"the log will ever see (ADR-002)", stored[0].Payload)
	}
	if !strings.Contains(string(stored[0].Payload), "display_name") {
		t.Errorf("the stored event does not name the field it corrected: %s. Without "+
			"that, the record cannot answer what the request was about",
			stored[0].Payload)
	}
	if stored[0].Type != (&contract.PersonalDataCorrected{}).EventType() {
		t.Errorf("recorded as %q", stored[0].Type)
	}
}

// NOTHING IS RECORDED WHEN THE CORRECTION ITSELF FAILS.
//
// The ordering the use case documents: correct first, record second. A record of
// a correction that never happened is evidence of compliance that is false, and
// unlike the reverse it is not detectable — nothing later disagrees with it.
func TestAFailedCorrectionRecordsNothing(t *testing.T) {
	applier := &recordingApplier{err: errs.Internalf("storing profile details")}
	rect, events := newRectifications(t, applier)

	if _, err := rect.Rectify(context.Background(), app.RectifyCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		DisplayName: ptr("Sam"), IdempotencyKey: "key-1",
	}); err == nil {
		t.Fatal("a failed correction reported success")
	}
	if n := len(events.streams["rectification-subj_1"]); n != 0 {
		t.Fatalf("the log records %d corrections that did not happen; that is evidence "+
			"we answered a statutory request we did not act on", n)
	}
}

// A CORRECTION THAT NAMES NO FIELD IS REFUSED, AND TOUCHES NOTHING.
func TestARectificationNamingNoFieldIsRefused(t *testing.T) {
	applier := &recordingApplier{}
	rect, events := newRectifications(t, applier)

	_, err := rect.Rectify(context.Background(), app.RectifyCommand{
		SubjectID: "subj_1", ActorID: "subj_1", IdempotencyKey: "key-1",
	})
	if err == nil {
		t.Fatal("a rectification over no fields was accepted")
	}
	if len(applier.applied) != 0 {
		t.Error("it reached the owning module anyway")
	}
	if n := len(events.streams["rectification-subj_1"]); n != 0 {
		t.Errorf("it recorded %d events", n)
	}
}

// AN INCOMPLETE WIRING IS REFUSED.
//
// The applier is the half worth naming: without it this endpoint records that
// somebody's data was corrected and corrects nothing, which is the worst
// available outcome because the log becomes evidence for a request we did not
// act on.
func TestRectificationsRefusesAnIncompleteWiring(t *testing.T) {
	events := newMemoryStore()
	repo := eventsourcing.NewRepository[*domain.Rectification](
		events, events.codec, nil,
		domain.RectificationCategory, domain.NewRectification)

	if _, err := app.NewRectifications(app.RectificationsDeps{
		Repo: repo, Now: func() time.Time { return rightsAt },
	}); err == nil {
		t.Error("a use case with no correction applier was accepted; it would record " +
			"corrections it never made")
	}
	if _, err := app.NewRectifications(app.RectificationsDeps{
		Applier: &recordingApplier{}, Now: func() time.Time { return rightsAt },
	}); err == nil {
		t.Error("a use case with no repository was accepted; the record with the " +
			"statutory clock on it lives in the log")
	}
}

// --------------------------------------------------------------------------
// Article 21 — objection
// --------------------------------------------------------------------------

func newObjections(t *testing.T) (*app.Objections, *memoryStore) {
	t.Helper()
	events := newMemoryStore()
	o, err := app.NewObjections(app.ObjectionsDeps{
		Repo: eventsourcing.NewRepository[*domain.Objection](
			events, events.codec, nil,
			domain.ObjectionCategory, domain.NewObjection),
		Now: func() time.Time { return rightsAt },
	})
	if err != nil {
		t.Fatalf("building the use case: %v", err)
	}
	return o, events
}

// OBJECTING RECORDS ONCE AND REPORTS THE ORIGINAL INSTANT.
func TestObjectingIsIdempotentAndKeepsTheFirstInstant(t *testing.T) {
	obj, events := newObjections(t)
	cmd := app.ObjectionCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		Purpose: domain.PurposeActivityNotifications, IdempotencyKey: "key-1",
	}

	first, err := obj.Object(context.Background(), cmd)
	if err != nil {
		t.Fatalf("objecting: %v", err)
	}
	if !first.Changed || !first.Since.Equal(rightsAt) {
		t.Fatalf("the first objection reported changed=%v since=%v",
			first.Changed, first.Since)
	}

	cmd.IdempotencyKey = "key-2"
	second, err := obj.Object(context.Background(), cmd)
	if err != nil {
		t.Fatalf("objecting twice: %v", err)
	}
	if second.Changed {
		t.Error("a repeated objection reported a change")
	}
	if !second.Since.Equal(rightsAt) {
		t.Errorf("the instant moved to %v; it has been reported to the person",
			second.Since)
	}
	if n := len(events.streams["objection-subj_1"]); n != 1 {
		t.Errorf("the stream holds %d events for one objection", n)
	}
}

// THE LIST IS READ FROM THE AGGREGATE, SO A FRESH OBJECTION IS VISIBLE AT ONCE.
//
// The subject is asking about their own instruction. A projection read would
// tell somebody who has just objected that their objection has not taken effect
// while a projector catches up — on the one screen where that is alarming rather
// than merely stale. The dispatcher reads the projection instead, where the lag
// is in the safe direction.
func TestAFreshObjectionIsListedImmediately(t *testing.T) {
	obj, _ := newObjections(t)

	if _, err := obj.Object(context.Background(), app.ObjectionCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		Purpose: domain.PurposeProductUpdates, IdempotencyKey: "key-1",
	}); err != nil {
		t.Fatal(err)
	}

	standing, err := obj.List(context.Background(), "subj_1")
	if err != nil {
		t.Fatalf("listing: %v", err)
	}
	if len(standing) != 1 || standing[0].Purpose != domain.PurposeProductUpdates {
		t.Fatalf("listed %v immediately after objecting; the person is told their "+
			"instruction has not taken effect when it has", standing)
	}
	if !standing[0].Since.Equal(rightsAt) {
		t.Errorf("listed since %v", standing[0].Since)
	}
}

// AN OBJECTION TO A PURPOSE NOTHING ENFORCES IS REFUSED, NOT STORED.
//
// The person would be told the processing stopped, and no code anywhere would
// consult the record — invisible from both sides.
func TestObjectingToAnUnenforceablePurposeIsRefused(t *testing.T) {
	obj, events := newObjections(t)

	_, err := obj.Object(context.Background(), app.ObjectionCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		Purpose: domain.Purpose("telemetry"), IdempotencyKey: "key-1",
	})
	if err == nil {
		t.Fatal("an objection to a purpose this system cannot stop was accepted")
	}
	if errs.ReasonOf(err) != errs.ValidationFailed {
		t.Errorf("refused with %v; a purpose the caller chose from a closed enum is a "+
			"request problem, not ours", err)
	}
	if n := len(events.streams["objection-subj_1"]); n != 0 {
		t.Errorf("it recorded %d events", n)
	}
}

// EVERY MUTATION NEEDS AN IDEMPOTENCY KEY.
func TestObjectingWithoutAnIdempotencyKeyIsRefused(t *testing.T) {
	obj, _ := newObjections(t)
	_, err := obj.Object(context.Background(), app.ObjectionCommand{
		SubjectID: "subj_1", ActorID: "subj_1",
		Purpose: domain.PurposeActivityNotifications,
	})
	if err == nil {
		t.Fatal("a mutation with no idempotency key was accepted")
	}
}

// AN OBJECTION USE CASE WITH NO REPOSITORY IS REFUSED.
func TestObjectionsRefusesAnIncompleteWiring(t *testing.T) {
	if _, err := app.NewObjections(app.ObjectionsDeps{
		Now: func() time.Time { return rightsAt },
	}); err == nil {
		t.Error("a use case with no repository was accepted")
	}
	events := newMemoryStore()
	if _, err := app.NewObjections(app.ObjectionsDeps{
		Repo: eventsourcing.NewRepository[*domain.Objection](
			events, events.codec, nil,
			domain.ObjectionCategory, domain.NewObjection),
	}); err == nil {
		t.Error("a use case with no clock was accepted")
	}
}
