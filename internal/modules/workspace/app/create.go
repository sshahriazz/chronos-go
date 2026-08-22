// Package app is workspace's use cases and the ports they depend on.
package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/workspace/contract"
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
	repo     *eventsourcing.Repository[*domain.Workspace]
	appender eventsourcing.MultiAppender
	schemas  eventsourcing.SchemaVersions
	quota    QuotaCommitter
	seats    *Seats
	now      func() time.Time
}

// CreationDeps is what Creation needs.
type CreationDeps struct {
	Repo     *eventsourcing.Repository[*domain.Workspace]
	Appender eventsourcing.MultiAppender
	Schemas  eventsourcing.SchemaVersions
	Quota    QuotaCommitter
	Seats    *Seats
	Now      func() time.Time
}

func NewCreation(d CreationDeps) (*Creation, error) {
	switch {
	case d.Repo == nil:
		return nil, fmt.Errorf("workspace: a repository is required")
	case d.Appender == nil:
		return nil, fmt.Errorf("workspace: an appender is required; the workspace and its " +
			"creator's membership are one atomic append, and two appends would leave a " +
			"workspace whose own creator is not a member of it")
	case d.Schemas == nil:
		return nil, fmt.Errorf("workspace: a schema registry is required; an event stored " +
			"without its version cannot be upcast later (ADR-029)")
	case d.Quota == nil:
		return nil, fmt.Errorf("workspace: a quota committer is required; without one every " +
			"workspace created would release its reservation and the cap would never bind")
	case d.Seats == nil:
		return nil, fmt.Errorf("workspace: seat accounting is required; the creator becomes " +
			"a member, and a membership that took no seat is one the plan does not limit")
	case d.Now == nil:
		return nil, fmt.Errorf("workspace: a clock is required")
	}
	return &Creation{
		repo: d.Repo, appender: d.Appender, schemas: d.Schemas,
		quota: d.Quota, seats: d.Seats, now: d.Now,
	}, nil
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

	// The creator's seat, before the append, for the reason Members.Add gives:
	// a recorded membership that no seat backs is a limit that silently does not
	// apply. Conditional, like every other join — the org owner opening their
	// second workspace already holds a seat.
	_, seatConsumed, err := c.seats.ReserveForJoin(ctx, cmd.OrgID, cmd.CreatedBy, contract.RoleAdmin)
	if err != nil {
		return CreateResult{}, errs.QuotaExceededf("%s", err)
	}

	if err := c.append(ctx, cmd, workspaceID, ws, seatConsumed, now); err != nil {
		if seatConsumed {
			_, _ = c.seats.ReleaseOnRemoval(ctx, cmd.OrgID, cmd.CreatedBy, contract.RoleAdmin, 0)
		}
		return CreateResult{}, err
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

// append writes the workspace and its creator's membership in ONE atomic
// append.
//
// # Why they cannot be two appends
//
// The creator IS a member, and for a long time this code left that fact implicit
// in `WorkspaceCreated` alone. Nothing carried it into the membership category,
// so the creator had no Membership aggregate — and every operation that reads
// one silently did the wrong thing: removing them was a no-op that reported
// success, changing their role was NOT_FOUND, and their membership had consumed
// no seat, so the very first member of every workspace was free.
//
// Recording it as a second append would have fixed the reads and introduced a
// worse failure: a workspace that exists with no membership behind it, which
// nothing retries and nothing detects.
//
// # The preconditions
//
// NoStream on both. A fresh ULID cannot collide, so the workspace's is a guard
// against an id generator that repeats; the membership's is the real one, and it
// makes "the creator joins exactly once" true at the moment of the write rather
// than checked before it.
func (c *Creation) append(
	ctx context.Context, cmd CreateCommand, workspaceID string,
	ws *domain.Workspace, seatConsumed bool, now time.Time,
) error {
	wsStream, err := eventsourcing.NewStreamID(domain.Category, domain.StreamKey(workspaceID))
	if err != nil {
		return errs.Internalf("workspace stream").Wrap(err)
	}
	memberStream, err := eventsourcing.NewStreamID(domain.MembershipCategory,
		domain.MembershipStreamKey(workspaceID, cmd.CreatedBy))
	if err != nil {
		return errs.Internalf("membership stream").Wrap(err)
	}

	meta := eventsourcing.Metadata{OrgID: cmd.OrgID, WorkspaceID: workspaceID, OccurredAt: now}

	// Event ids are DERIVED from the idempotency key, so a retry of the same
	// command produces byte-identical ids and the store refuses the redelivery
	// rather than appending it twice.
	pending := ws.Uncommitted()
	wsEvents := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		wsEvents = append(wsEvents, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, c.schemas, e.EventType()),
		})
	}

	joined := &contract.MemberJoined{
		WorkspaceID: workspaceID, OrgID: cmd.OrgID, SubjectID: cmd.CreatedBy,
		Role: contract.RoleAdmin, SeatConsumed: seatConsumed, JoinedAt: now,
	}

	if _, err := c.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{
		{Stream: wsStream, Expected: eventsourcing.NoStream(), Events: wsEvents},
		{
			Stream:   memberStream,
			Expected: eventsourcing.NoStream(),
			Events: []eventsourcing.PendingEvent{{
				ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey+":member", 0),
				Event: joined,
				Meta:  eventsourcing.StampSchemaVersion(meta, c.schemas, joined.EventType()),
			}},
		},
	}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			return errs.Conflictf("this workspace was already created")
		}
		return errs.Internalf("creating the workspace").Wrap(err)
	}
	return nil
}
