// Package app is workspace's use cases and the ports they depend on.
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

// QuotaCommitter turns the reservation gate 4 granted into usage.
//
// A port declared by the consumer, so this layer never learns that entitlement
// has a database. It is NARROW on purpose: a use case holding the whole reserver
// could reserve as well as commit, and reserving is the gate's job — doing it
// here would take a second unit for every workspace created.
type QuotaCommitter interface {
	Commit(ctx context.Context, reservationID string) error
}

// CreateCommand is a request to open a workspace.
type CreateCommand struct {
	OrgID     string
	Name      string
	CreatedBy string

	// ReservationID is what gate 4 granted this request. Empty means the gate
	// did not run, which is a wiring fault rather than a permitted state.
	ReservationID string

	IdempotencyKey string
}

// CreateResult is what the caller gets back.
type CreateResult struct {
	WorkspaceID string
	Name        string
	Status      domain.Status
}

// Creation opens workspaces.
type Creation struct {
	repo  *eventsourcing.Repository[*domain.Workspace]
	quota QuotaCommitter
	now   func() time.Time
}

// CreationDeps is what Creation needs.
type CreationDeps struct {
	Repo  *eventsourcing.Repository[*domain.Workspace]
	Quota QuotaCommitter
	Now   func() time.Time
}

func NewCreation(d CreationDeps) (*Creation, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: a repository is required")
	case d.Quota == nil:
		return nil, fmt.Errorf("workspace: a quota committer is required; without one every " +
			"workspace created would release its reservation and the cap would never bind")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Creation{repo: d.Repo, quota: d.Quota, now: d.Now}, nil
}

// Create opens a workspace and commits the quota it consumed.
//
// # The order, and why the append comes first
//
// Append, then commit. The reverse — commit then append — would consume a unit
// for a workspace that then failed to be created, and the unit would stay
// consumed: a committed reservation does not expire.
//
// This way round the failure mode is the harmless one. If the process dies
// between the append and the commit, the workspace exists and its reservation
// lapses at its TTL, so the organization gets the unit back while holding the
// workspace. That is one workspace over the cap until somebody notices, which is
// recoverable; a permanently consumed unit for a workspace that never existed is
// not.
//
// # Why the reservation is required rather than optional
//
// An empty ReservationID means gate 4 did not run — the RPC forgot to declare
// its entitlement, or the gate is unwired. Creating the workspace anyway would
// mean the cap silently does not apply, which is the failure that ordering this
// slice was supposed to prevent.
func (c *Creation) Create(ctx context.Context, cmd CreateCommand) (CreateResult, error) {
	name, err := domain.NewName(cmd.Name)
	if err != nil {
		return CreateResult{}, errs.ValidationFailedf("%s", err)
	}
	switch {
	case cmd.OrgID == "":
		return CreateResult{}, errs.Internalf("no organization reached the create handler; " +
			"gate 1 did not resolve one")
	case cmd.CreatedBy == "":
		return CreateResult{}, errs.Internalf("no authenticated subject reached the create " +
			"handler")
	case cmd.ReservationID == "":
		return CreateResult{}, errs.Internalf("no quota reservation reached the create " +
			"handler, so gate 4 did not run and the workspace cap would not apply")
	case cmd.IdempotencyKey == "":
		return CreateResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := c.now().UTC()
	workspaceID := ids.New[ids.Workspace](now, ids.Entropy()).String()

	ws, err := c.repo.Load(ctx, domain.StreamKey(workspaceID))
	if err != nil {
		return CreateResult{}, errs.Internalf("loading the workspace stream").Wrap(err)
	}
	if err := ws.Create(workspaceID, cmd.OrgID, name, cmd.CreatedBy, now); err != nil {
		return CreateResult{}, errs.ValidationFailedf("%s", err)
	}

	if _, err := c.repo.Save(ctx, domain.StreamKey(workspaceID), ws, cmd.IdempotencyKey,
		eventsourcing.Metadata{OrgID: cmd.OrgID, WorkspaceID: workspaceID, OccurredAt: now},
	); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return CreateResult{}, errs.Conflictf("this workspace was already created")
		}
		return CreateResult{}, errs.Internalf("creating the workspace").Wrap(err)
	}

	if err := c.quota.Commit(ctx, cmd.ReservationID); err != nil {
		// The workspace EXISTS. Failing the request now would tell the caller it
		// does not, and they would try again and get a second one. So this is
		// reported as a success with a loud error path: the reservation lapses
		// at its TTL and the organization is briefly one workspace over its cap,
		// which the next reservation attempt corrects.
		return CreateResult{
			WorkspaceID: workspaceID, Name: name, Status: domain.StatusActive,
		}, errs.Internalf("the workspace was created but its quota was not committed").Wrap(err)
	}

	return CreateResult{
		WorkspaceID: workspaceID, Name: name, Status: domain.StatusActive,
	}, nil
}
