package main

import (
	"errors"
	"fmt"
	"log/slog"

	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	profilepg "github.com/chronos/chronos-go/internal/modules/profile/adapter/postgres"
	profileapi "github.com/chronos/chronos-go/internal/modules/profile/api"
	profileapp "github.com/chronos/chronos-go/internal/modules/profile/app"
	profiledomain "github.com/chronos/chronos-go/internal/modules/profile/domain"
	"github.com/chronos/chronos-go/internal/platform/config"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// buildProfile assembles the profile service, or explains why it could not be.
//
// Profile is its OWN module rather than part of identity, and the split is the
// same one ADR-020 made between organization and workspace: identity answers
// "who is this" — credentials, sessions, lifecycle — and a display name and an
// avatar are presentation. Every attribute added to identity widens the
// aggregate that guards authentication, which is the wrong thing to grow.
//
// Failure is loud and NOT fatal (ADR-010). The consequence is stated at the call
// site, because "profile is unavailable" and "the server would not start" are
// very different outages and only one of them is warranted here.
func (d *dependencies) buildProfile(
	cfg *config.Config, log *slog.Logger,
) (*profileapi.Service, error) {
	if d.pool == nil {
		return nil, errors.New("no postgres pool: profile_view is a projection and there " +
			"is no read side without it")
	}
	if d.store == nil {
		return nil, errors.New("no event store: an update is an append, and a handler that " +
			"wrote the projection directly would be writing the answer instead of the fact")
	}
	if d.piiVault == nil {
		return nil, errors.New("no PII vault: the display name, locale and timezone live " +
			"there and nowhere else, so a profile without it can be neither read nor written")
	}
	if d.blobs == nil {
		return nil, errors.New("no object store: an avatar is a reference to an object, and " +
			"without one there is nothing to reference and no upload target to sign")
	}

	reads, err := profilepg.NewReadModel(pgadapter.New(d.pool))
	if err != nil {
		return nil, fmt.Errorf("profile read model: %w", err)
	}

	// The SAME codec and upcaster registry the rest of this binary uses.
	//
	// Building a second registry here is not hypothetical: it happened while this
	// module was being written, and the symptom was that the FIRST update to a
	// subject succeeded and every later one failed to load its own aggregate — a
	// registry that never heard of the type demands a 0→1 upcaster that should not
	// exist. Nothing looked wrong until a profile was edited twice.
	repo := eventsourcing.NewRepository[*profiledomain.Profile](
		d.store, d.codec, d.upcasters, profiledomain.Category, profiledomain.NewProfile)

	queries, err := profileapp.NewQueries(profileapp.QueriesDeps{
		Reader:  reads,
		Vault:   d.piiVault,
		Avatars: d.blobs,
	})
	if err != nil {
		return nil, fmt.Errorf("profile queries: %w", err)
	}

	updates, err := profileapp.NewUpdates(profileapp.UpdatesDeps{
		Repo:    repo,
		Vault:   d.piiVault,
		Avatars: d.blobs,
		Queries: queries,
		Clock:   d.clock,
	})
	if err != nil {
		return nil, fmt.Errorf("profile updates: %w", err)
	}

	avatars, err := profileapp.NewAvatars(profileapp.AvatarsDeps{Store: d.blobs})
	if err != nil {
		return nil, fmt.Errorf("profile avatars: %w", err)
	}

	log.Info("profile service constructed",
		// Named at startup because it is the one thing an operator most needs to
		// know about this module: no avatar byte passes through this process. The
		// client uploads to the object store directly against a signed target.
		"avatar_uploads", "direct to object store",
		"bucket", cfg.Storage.Bucket)

	return profileapi.New(profileapi.Deps{
		Queries: queries,
		Updates: updates,
		Avatars: avatars,
	})
}
