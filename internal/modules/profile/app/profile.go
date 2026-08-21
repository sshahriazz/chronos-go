package app

import (
	"context"
	"errors"

	"github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/blob"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/pii"
)

// UpdateCommand is one sparse change to the caller's own profile.
//
// Every optional field is a POINTER, mirroring the wire message and the event:
// nil means "not part of this update". A struct of plain strings would make
// "leave my timezone alone" and "empty my timezone" the same command, and the
// handler would have to guess which the caller meant — which is how a settings
// screen that renders one field silently wipes the other three.
type UpdateCommand struct {
	// SubjectID is the CALLER'S pseudonym, from the session. It is never a
	// request field; see the api package.
	SubjectID string

	DisplayName *string
	Locale      *string
	Timezone    *string

	// AvatarObjectKey is a key CreateAvatarUpload minted for this caller, or the
	// empty string to remove the current avatar. It is the one field whose empty
	// value is meaningful rather than refused.
	AvatarObjectKey *string

	IdempotencyKey string
}

// isEmpty reports a command that names no field.
func (c UpdateCommand) isEmpty() bool {
	return c.DisplayName == nil && c.Locale == nil &&
		c.Timezone == nil && c.AvatarObjectKey == nil
}

// Updates is the write half of a person's own profile.
type Updates struct {
	repo    Repository
	vault   SubjectVault
	avatars AvatarStore
	queries *Queries
	clock   clock.Clock
}

// UpdatesDeps is what the use case needs.
type UpdatesDeps struct {
	// Repo is the aggregate store. Required: the aggregate is what serialises
	// two concurrent saves into one ordering instead of a torn mixture.
	Repo Repository

	// Vault is where the display name, the locale and the timezone go. Required:
	// without it there is nowhere those values may legally be written, and a use
	// case that carried on would be one that put them in the event instead.
	Vault SubjectVault

	// Avatars verifies what was uploaded. Required: a confirm call that skipped
	// verification would record whatever key the client named.
	Avatars AvatarStore

	// Queries renders the result. Required, because a settings screen that saves
	// and then shows nothing is a screen people press twice.
	Queries *Queries

	Clock clock.Clock
}

// NewUpdates builds the use case, refusing a partial one.
func NewUpdates(deps UpdatesDeps) (*Updates, error) {
	switch {
	case deps.Repo == nil:
		return nil, errors.New("profile/app: updating a profile needs a repository")
	case deps.Vault == nil:
		return nil, errors.New("profile/app: updating a profile needs the PII vault")
	case deps.Avatars == nil:
		return nil, errors.New("profile/app: updating a profile needs an object store")
	case deps.Queries == nil:
		return nil, errors.New("profile/app: updating a profile needs the read side to " +
			"render the result")
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	return &Updates{
		repo: deps.Repo, vault: deps.Vault, avatars: deps.Avatars,
		queries: deps.Queries, clock: deps.Clock,
	}, nil
}

// Update applies a sparse change and returns the profile as it now stands.
//
// # It appends an event and never writes the table
//
// `profile_view` is a PROJECTION. The event is the fact; the row follows. A
// handler that wrote the row directly would put state in PostgreSQL that no
// replay reproduces and that the next rebuild deletes — and it would take with
// it the only record of when somebody changed their name, which is what a
// support conversation about an impersonation report actually needs.
//
// # Concurrency
//
// All of one person's profile changes live on ONE stream, and the aggregate is
// saved under the revision it was loaded at. Two browser tabs saving at the same
// instant therefore collide: one wins, the other gets CONFLICT and retries
// against the winner's state. The alternative — last write wins per column —
// produces a profile that is half of each save.
//
// CONFLICT is returned rather than retried here. A retry would re-apply values
// against a state the person did not see, and quietly undoing somebody else's
// change is worse than asking for the button to be pressed again.
// `Aborted`/`CONFLICT` is the documented "retry this" reason (CONVENTIONS §5).
//
// # The order of the two writes, which is not arbitrary
//
// The vault is written BEFORE the event is appended, and the reverse would be
// wrong. If the append fails after the vault write, the value is stored and the
// log has not yet recorded that it changed; the client's retry carries the same
// idempotency key, the vault write is an idempotent upsert, and the append then
// lands — the two converge. If the event were appended first and the vault write
// failed, the log would assert a change that did not happen, and every email
// from then on would render the OLD name while the history said otherwise. A
// system of record that disagrees with its own log is the worse failure, so the
// order puts the vault first.
func (u *Updates) Update(ctx context.Context, cmd UpdateCommand) (Profile, error) {
	if err := requireSubject(cmd.SubjectID, "updating a profile"); err != nil {
		return Profile{}, err
	}
	switch {
	case cmd.IdempotencyKey == "":
		return Profile{}, errs.ValidationFailedf("an idempotency key is required")
	case cmd.isEmpty():
		return Profile{}, errs.ValidationFailedf(
			"an update that names no field changes nothing")
	}

	values, update, err := u.plan(ctx, cmd)
	if err != nil {
		return Profile{}, err
	}

	key := domain.StreamKey(cmd.SubjectID)
	agg, err := u.repo.Load(ctx, key)
	if err != nil {
		return Profile{}, errs.Internalf("reading a profile").Wrap(err)
	}

	now := u.clock.Now().UTC()
	if err := agg.Update(cmd.SubjectID, update, now); err != nil {
		switch {
		case errors.Is(err, domain.ErrNothingToUpdate):
			return Profile{}, errs.ValidationFailedf("%v", err).Wrap(err)
		case errors.Is(err, domain.ErrWrongSubject):
			// Only reachable if the stream key derivation and the caller
			// disagree, which is a wiring bug rather than a request problem.
			return Profile{}, errs.Internalf("profile stream mismatch").Wrap(err)
		default:
			return Profile{}, errs.ValidationFailedf("%v", err).Wrap(err)
		}
	}

	if len(agg.Uncommitted()) == 0 {
		// Nothing changed — a re-confirmed avatar key, or a removal of an avatar
		// that was already gone. No event, no vault write, and the current state
		// is returned so the caller still sees what the system holds.
		return u.queries.Get(ctx, cmd.SubjectID)
	}

	if len(values) > 0 {
		if err := u.vault.PutAll(ctx, pii.SubjectID(cmd.SubjectID), values); err != nil {
			// The message names no field VALUE. This error reaches a log line,
			// and a log line is exactly where a display name must not be
			// (CONVENTIONS §11).
			return Profile{}, errs.Internalf("storing profile details").Wrap(err)
		}
	}

	trace := eventsourcing.TraceFrom(ctx)
	_, err = u.repo.Save(ctx, key, agg, cmd.IdempotencyKey, eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    now,
		// No OrgID. A profile is global to a person, exactly as their account is
		// — one display name across every organization they belong to — so there
		// is no tenant to scope this event to and inventing one would make the
		// same fact appear once per membership.
		SubjectIDs:    []string{cmd.SubjectID},
		ActorID:       cmd.SubjectID,
		CorrelationID: trace.CorrelationID,
		CausationID:   trace.CausationID,
	})
	switch {
	case errors.Is(err, eventsourcing.ErrWrongExpectedRevision):
		return Profile{}, errs.Conflictf(
			"your profile changed while you were editing it; reload and try again").Wrap(err)
	case err != nil:
		return Profile{}, errs.Internalf("saving a profile").Wrap(err)
	}

	// Read back from the PROJECTION and the vault, not from the aggregate. The
	// aggregate would report what this call decided; the screen is meant to show
	// what the system will actually serve, and on the rare occasion those differ
	// it is because the projector has stalled — which a screen showing the
	// aggregate's answer would hide behind something that looks correct.
	return u.queries.Get(ctx, cmd.SubjectID)
}

// plan turns a command into the vault values to store and the domain update to
// record, refusing anything either of them will not accept.
//
// Everything that can be refused is refused HERE, before the aggregate is
// loaded and before a single byte is written. That ordering is what makes a bad
// request cost nothing and, more importantly, what keeps a rejected update from
// having already changed the vault.
func (u *Updates) plan(
	ctx context.Context, cmd UpdateCommand,
) (map[pii.Field]string, domain.Update, error) {
	values := map[pii.Field]string{}
	var update domain.Update

	if cmd.DisplayName != nil {
		name, err := parseVaultField(*cmd.DisplayName, pii.FieldName, "display name", domain.ParseDisplayName)
		if err != nil {
			return nil, domain.Update{}, err
		}
		values[pii.FieldName] = name
		update.DisplayName = ptr(true)
	}
	if cmd.Locale != nil {
		locale, err := parseVaultField(*cmd.Locale, pii.FieldLocale, "locale", domain.ParseLocale)
		if err != nil {
			return nil, domain.Update{}, err
		}
		values[pii.FieldLocale] = locale
		update.Locale = ptr(true)
	}
	if cmd.Timezone != nil {
		zone, err := parseVaultField(*cmd.Timezone, pii.FieldTimezone, "timezone", domain.ParseTimezone)
		if err != nil {
			return nil, domain.Update{}, err
		}
		values[pii.FieldTimezone] = zone
		update.Timezone = ptr(true)
	}

	if cmd.AvatarObjectKey != nil {
		avatar, err := u.resolveAvatar(ctx, cmd.SubjectID, *cmd.AvatarObjectKey)
		if err != nil {
			return nil, domain.Update{}, err
		}
		update.Avatar = &avatar
	}
	return values, update, nil
}

// resolveAvatar turns the key a client sent into the reference to record.
//
// # The order of the two checks is the security property
//
// domain.ParseAvatarKey runs FIRST, and it refuses any key outside the caller's
// own derived prefix. Only then is the object store contacted. Reversing them
// would turn this endpoint into an existence oracle for the whole bucket: a
// caller could name any key and learn from the error whether an object was
// there.
//
// # What the store says beats what the client said
//
// The content type and the size come from Verify — the store's own answer about
// what it holds — and are validated by the domain. Nothing an uploader claimed
// survives to the event.
func (u *Updates) resolveAvatar(
	ctx context.Context, subjectID, key string,
) (domain.Avatar, error) {
	if key == "" {
		// The remove case. A zero Avatar is what the aggregate reads as "clear
		// it", and it is the one field of this profile that HAS an empty state.
		return domain.Avatar{}, nil
	}

	parsed, err := domain.ParseAvatarKey(subjectID, key)
	if err != nil {
		return domain.Avatar{}, errs.ValidationFailedf(
			"that is not an avatar upload issued to this account").Wrap(err)
	}

	object, err := u.avatars.Verify(ctx, blob.Key(parsed))
	switch {
	case errors.Is(err, blob.ErrNotFound):
		return domain.Avatar{}, errs.ValidationFailedf(
			"no image has been uploaded to that grant yet").Wrap(err)
	case err != nil:
		return domain.Avatar{}, errs.Internalf("verifying an uploaded avatar").Wrap(err)
	}

	avatar, err := domain.NewAvatar(parsed, object.ContentType, object.Size)
	if err != nil {
		return domain.Avatar{}, errs.ValidationFailedf("%v", err).Wrap(err)
	}
	return avatar, nil
}

// parseVaultField applies one field's parser, turning the "you sent an empty
// value" case into an error that says why it is not simply ignored.
//
// # Why a vault-held field cannot be cleared
//
// internal/platform/pii can destroy a subject's KEY and cannot delete one field
// — erasure is crypto-shredding, and shredding is all-or-nothing by design
// (ADR-002). There is therefore no operation this system could perform to empty
// a display name, and pretending otherwise by storing an empty string is not
// available either: pii.Validate refuses one, precisely so a vault row cannot
// mean "present but blank".
//
// The refusal is explicit rather than silent. A caller that sent an empty value
// meant something by it, and an update that quietly did nothing would be a save
// that appeared to work.
func parseVaultField(
	raw string, field pii.Field, what string, parse func(string) (string, error),
) (string, error) {
	if raw == "" {
		return "", errs.ValidationFailedf(
			"a %s cannot be removed, only replaced: it lives in the PII vault, which "+
				"destroys a subject's key rather than deleting one field", what)
	}
	value, err := parse(raw)
	if err != nil {
		return "", errs.ValidationFailedf("%v", err).Wrap(err)
	}
	if err := pii.Validate(field, value); err != nil {
		// The vault's own bound, checked before the value travels: it is the one
		// store that cannot be rebuilt, so an over-long row there is permanent.
		return "", errs.ValidationFailedf("that %s cannot be stored", what).Wrap(err)
	}
	return value, nil
}

func ptr[T any](v T) *T { return &v }
