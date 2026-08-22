package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// CreateTeamCommand opens a team inside a workspace.
type CreateTeamCommand struct {
	OrgID       string
	WorkspaceID string
	Name        string
	CreatedBy   string

	IdempotencyKey string
}

// CreateTeamResult names what was created.
type CreateTeamResult struct {
	TeamID string
	Name   string
}

// RenameTeamCommand changes a team's display name.
type RenameTeamCommand struct {
	OrgID       string
	WorkspaceID string
	TeamID      string
	Name        string

	IdempotencyKey string
}

// DeleteTeamCommand ends a team.
type DeleteTeamCommand struct {
	OrgID       string
	WorkspaceID string
	TeamID      string

	IdempotencyKey string
}

// Teams is the team lifecycle.
type Teams struct {
	repo *eventsourcing.Repository[*domain.Team]
	now  func() time.Time
}

// TeamsDeps is what Teams needs.
type TeamsDeps struct {
	Repo *eventsourcing.Repository[*domain.Team]
	Now  func() time.Time
}

func NewTeams(d TeamsDeps) (*Teams, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: a team repository is required")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Teams{repo: d.Repo, now: d.Now}, nil
}

// Create opens a team.
//
// It consumes no quota and takes no seat. A team is a grouping of people who are
// already in the workspace and already hold whatever seat their membership took;
// creating one grants nobody anything until something is shared with it.
func (t *Teams) Create(ctx context.Context, cmd CreateTeamCommand) (CreateTeamResult, error) {
	switch {
	case cmd.OrgID == "":
		return CreateTeamResult{}, errs.Internalf("no organization reached the team handler; " +
			"gate 1 resolved none")
	case cmd.WorkspaceID == "":
		return CreateTeamResult{}, errs.ValidationFailedf("a workspace is required")
	case cmd.CreatedBy == "":
		return CreateTeamResult{}, errs.Internalf("no authenticated subject reached the " +
			"team handler")
	case cmd.IdempotencyKey == "":
		return CreateTeamResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := t.now().UTC()
	// A FRESH ULID, and nothing recycles one. access.md §7.5 makes that
	// load-bearing rather than tidy: grants target `team:x#member`, so a reused
	// id would silently inherit a deleted team's access.
	teamID := ids.New[ids.Team](now, ids.Entropy()).String()

	team, err := t.repo.Load(ctx, domain.TeamStreamKey(teamID))
	if err != nil {
		return CreateTeamResult{}, errs.Internalf("loading the team stream").Wrap(err)
	}
	if err := team.Create(teamID, cmd.WorkspaceID, cmd.OrgID, cmd.Name, cmd.CreatedBy, now); err != nil {
		return CreateTeamResult{}, errs.ValidationFailedf("%s", err)
	}

	if _, err := t.repo.Save(ctx, domain.TeamStreamKey(teamID), team, cmd.IdempotencyKey,
		eventsourcing.Metadata{
			OrgID: cmd.OrgID, WorkspaceID: cmd.WorkspaceID, OccurredAt: now,
		},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return CreateTeamResult{}, errs.Conflictf("this team was already created")
		}
		return CreateTeamResult{}, errs.Internalf("creating the team").Wrap(err)
	}

	return CreateTeamResult{TeamID: teamID, Name: team.Name()}, nil
}

// Rename changes a team's display name.
//
// It grants and revokes nothing: the access engine knows a team by its id, so a
// rename is invisible to every tuple naming it.
func (t *Teams) Rename(ctx context.Context, cmd RenameTeamCommand) error {
	return t.command(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID, cmd.IdempotencyKey,
		func(team *domain.Team, at time.Time) error { return team.Rename(cmd.Name, at) })
}

// Delete ends a team.
//
// Terminal, and the id is never reused — see the aggregate. What this does NOT
// do is remove the grants naming the team, because none can exist yet: a grant
// to a team is a share, sharing needs resources, and feature verticals inside a
// workspace are out of scope (ADR-006). The cascade lands with the first feature
// that can grant to a team; until then the id never being reused is what holds
// the invariant.
func (t *Teams) Delete(ctx context.Context, cmd DeleteTeamCommand) error {
	return t.command(ctx, cmd.OrgID, cmd.WorkspaceID, cmd.TeamID, cmd.IdempotencyKey,
		func(team *domain.Team, at time.Time) error { return team.Delete(at) })
}

// command loads a team the caller named, applies one change and appends it.
func (t *Teams) command(
	ctx context.Context, orgID, workspaceID, teamID, key string,
	apply func(*domain.Team, time.Time) error,
) error {
	switch {
	case orgID == "":
		return errs.Internalf("no organization reached the team handler; gate 1 resolved none")
	case teamID == "":
		return errs.ValidationFailedf("a team is required")
	case key == "":
		return errs.ValidationFailedf("an Idempotency-Key is required on every mutating request")
	}

	team, err := t.repo.Load(ctx, domain.TeamStreamKey(teamID))
	if err != nil {
		return errs.Internalf("loading the team").Wrap(err)
	}
	if err := t.belongsHere(team, orgID, workspaceID); err != nil {
		return err
	}

	now := t.now().UTC()
	if err := apply(team, now); err != nil {
		// CONFLICT rather than VALIDATION_FAILED: the request is well formed and
		// the caller is permitted, and it is the current state — deleted, or the
		// last maintainer — that says no.
		return errs.Conflictf("%s", err)
	}
	// A command that changed nothing — a rename to the name it already has —
	// records no event, and Repository.Save returns early on an empty set. That
	// is where the no-op is handled; a guard here would be a second copy of the
	// same check, and a mutation of it survives every test because the platform
	// makes it unreachable.
	if _, err := t.repo.Save(ctx, domain.TeamStreamKey(teamID), team, key,
		eventsourcing.Metadata{OrgID: orgID, WorkspaceID: workspaceID, OccurredAt: now},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this team changed concurrently")
		}
		return errs.Internalf("recording the change").Wrap(err)
	}
	return nil
}

// belongsHere refuses a team that is not the caller's to touch.
//
// The authz gate checked `admin` on the WORKSPACE the request named. Nothing
// checked that the TEAM belongs to that workspace — an id is just a string — so
// without this an admin of one workspace could rename or DELETE another's team,
// and deletion is terminal.
//
// NOT_FOUND, never a message that distinguishes "no such team" from "not yours":
// both would confirm an id exists (ADR-036).
func (t *Teams) belongsHere(team *domain.Team, orgID, workspaceID string) error {
	if !team.Exists() || team.OrgID() != orgID {
		return errs.NotFoundf("not found")
	}
	if workspaceID != "" && team.WorkspaceID() != workspaceID {
		return errs.NotFoundf("not found")
	}
	return nil
}
