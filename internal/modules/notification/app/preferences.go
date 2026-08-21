package app

import (
	"context"
	"errors"
	"fmt"

	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// SetPreferencesCommand changes a person's own channel toggles.
//
// It has no field for a class and no field for a template, and that absence is
// the point. A preference names a CHANNEL. If it could name a class it could
// name Security, and the message telling somebody their second factor was
// removed is the one message an account takeover must not be able to switch off
// (NOTIFICATIONS §3). The dispatcher enforces the same rule a second time, from
// the other end: it checks class before it consults any preference, so even a
// forged preference row cannot reach a security alert.
type SetPreferencesCommand struct {
	OrgID     string
	SubjectID string

	// Settings are the toggles to apply, at most one per channel. Channels left
	// out are left alone.
	Settings []ChannelPreference

	IdempotencyKey string
}

// Preferences is the settings screen's write half.
type Preferences struct {
	repo  PreferenceRepository
	prefs PreferenceReader
	clock clock.Clock
}

// PreferencesDeps is what the use case needs.
type PreferencesDeps struct {
	// Repo is the aggregate store. Required: the aggregate is what serialises
	// two concurrent saves into one ordering instead of a torn mixture.
	Repo PreferenceRepository

	// Reader is the projection, used only to render the result. Required,
	// because a settings screen that saves and then shows nothing is a screen
	// people press twice.
	Reader PreferenceReader

	Clock clock.Clock
}

// NewPreferences builds the use case, refusing a partial one.
func NewPreferences(deps PreferencesDeps) (*Preferences, error) {
	switch {
	case deps.Repo == nil:
		return nil, fmt.Errorf("notification/app: setting preferences needs a repository")
	case deps.Reader == nil:
		return nil, fmt.Errorf("notification/app: setting preferences needs a preference reader")
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	return &Preferences{repo: deps.Repo, prefs: deps.Reader, clock: deps.Clock}, nil
}

// Set applies a batch of channel toggles.
//
// # It appends an event and never writes the table
//
// `notification_preference` is a PROJECTION. The event is the fact; the row
// follows. A handler that wrote the row directly would put state in PostgreSQL
// that no replay reproduces and that the next rebuild deletes — and would take
// with it the only record of when somebody changed their mind, which is what a
// support conversation about missing mail actually needs.
//
// # Concurrency
//
// All of one person's preference changes in one organization live on ONE stream,
// and the aggregate is saved under the revision it was loaded at. Two settings
// screens saving at the same instant therefore collide: one wins, the other gets
// CONFLICT and retries against the winner's state. The alternative — last write
// wins per row — produces a state that is half of each save, which is the
// specific failure "a preference write must not tear" names.
//
// CONFLICT is returned to the caller rather than retried here. A retry would
// re-apply toggles against a state the person did not see, and quietly undoing
// somebody else's change is worse than asking for the button to be pressed
// again. `Aborted`/`CONFLICT` is the documented "retry this" reason
// (CONVENTIONS §5).
//
// # The returned view
//
// Read back from the PROJECTION rather than from the aggregate — see view.
func (p *Preferences) Set(
	ctx context.Context, cmd SetPreferencesCommand,
) (PreferenceView, error) {
	if err := requireScope(cmd.OrgID, cmd.SubjectID, "setting notification preferences"); err != nil {
		return PreferenceView{}, err
	}
	switch {
	case len(cmd.Settings) == 0:
		return PreferenceView{}, errs.ValidationFailedf(
			"a preference change with no channels changes nothing")
	case cmd.IdempotencyKey == "":
		return PreferenceView{}, errs.ValidationFailedf("an idempotency key is required")
	}

	key := domain.PreferenceStreamKey(cmd.OrgID, cmd.SubjectID)
	agg, err := p.repo.Load(ctx, key)
	if err != nil {
		return PreferenceView{}, errs.Internalf("reading notification preferences").Wrap(err)
	}

	now := p.clock.Now().UTC()
	if err := agg.Set(cmd.SubjectID, cmd.OrgID, cmd.Settings, now); err != nil {
		if errors.Is(err, domain.ErrNotGovernable) {
			// Naming the channel is safe: it is a value from a closed enum the
			// caller sent, not a fact about anybody's account.
			return PreferenceView{}, errs.ValidationFailedf("%v", err).Wrap(err)
		}
		return PreferenceView{}, errs.ValidationFailedf("%v", err).Wrap(err)
	}

	trace := eventsourcing.TraceFrom(ctx)
	_, err = p.repo.Save(ctx, key, agg, cmd.IdempotencyKey, eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    now,
		OrgID:         cmd.OrgID,
		SubjectIDs:    []string{cmd.SubjectID},
		ActorID:       cmd.SubjectID,
		CorrelationID: trace.CorrelationID,
		CausationID:   trace.CausationID,
	})
	switch {
	case errors.Is(err, eventsourcing.ErrWrongExpectedRevision):
		return PreferenceView{}, errs.Conflictf(
			"these preferences changed while you were editing them; reload and try again").Wrap(err)
	case err != nil:
		return PreferenceView{}, errs.Internalf("saving notification preferences").Wrap(err)
	}

	return p.view(ctx, cmd)
}

// view renders the settings screen after a save.
//
// Read back from the PROJECTION, not from the aggregate. The aggregate would
// report what this call decided; the screen is meant to show what the system
// will actually do, and on the rare occasion those differ it is because the
// projector has stalled — which a screen showing the aggregate's answer would
// hide behind something that looks correct.
//
// A read failure here FAILS the call even though the append already succeeded,
// and that is safe rather than merely defensible: the idempotency gate releases
// its claim when a handler errors, so the client's retry with the same key
// re-executes — and the second execution loads an aggregate already in the
// requested state, records nothing, appends nothing, and returns the view. The
// alternative, reporting success with the aggregate's state, would report a
// stalled projector as a healthy save.
func (p *Preferences) view(
	ctx context.Context, cmd SetPreferencesCommand,
) (PreferenceView, error) {
	stored, err := p.prefs.ChannelPreferences(ctx, cmd.OrgID, cmd.SubjectID)
	if err != nil {
		return PreferenceView{}, errs.Internalf(
			"your preferences were saved, but reading them back failed; try again").Wrap(err)
	}

	explicit := make(map[string]bool, len(stored))
	for _, s := range stored {
		if domain.IsGovernable(s.Channel) {
			explicit[string(s.Channel)] = s.Enabled
		}
	}
	channels := make([]ChannelPreference, 0, len(domain.Governable()))
	for _, ch := range domain.Governable() {
		enabled, ok := explicit[string(ch)]
		if !ok {
			enabled = true
		}
		channels = append(channels, ChannelPreference{Channel: ch, Enabled: enabled})
	}
	return PreferenceView{
		Channels:        channels,
		Governed:        domain.GovernedClasses(),
		AlwaysDelivered: domain.AlwaysDeliveredClasses(),
	}, nil
}
