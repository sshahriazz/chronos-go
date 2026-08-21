package app

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// CreateCommand is a request to open a new organization.
type CreateCommand struct {
	Name  string
	Slug  string
	Owner string // the caller's SubjectID pseudonym

	IdempotencyKey string
}

// CreateResult is what the caller gets back.
type CreateResult struct {
	OrgID  string
	Slug   string
	Status domain.Status
}

// Creation opens organizations.
type Creation struct {
	appender eventsourcing.MultiAppender
	schemas  eventsourcing.SchemaVersions
	now      func() time.Time
}

// CreationDeps is what Creation needs.
type CreationDeps struct {
	Appender eventsourcing.MultiAppender
	Schemas  eventsourcing.SchemaVersions
	Now      func() time.Time
}

func NewCreation(d CreationDeps) (*Creation, error) {
	switch {
	case d.Appender == nil:
		return nil, fmt.Errorf("organization: an appender is required")
	case d.Schemas == nil:
		return nil, fmt.Errorf("organization: a schema registry is required; an event stored " +
			"without its version cannot be upcast later (ADR-029)")
	case d.Now == nil:
		return nil, fmt.Errorf("organization: a clock is required")
	}
	return &Creation{appender: d.Appender, schemas: d.Schemas, now: d.Now}, nil
}

// Create opens an organization owned by its creator.
//
// # Three streams, one append, all or nothing
//
// The organization, a reservation naming the OWNER, and a reservation naming the
// SLUG are appended together with `NoStream` on each. That single atomic append
// is what makes both uniqueness rules true at the moment of the write:
//
//	organization-<id>   NoStream   the organization cannot already exist
//	orgowner-<subject>  NoStream   this person owns no organization yet
//	orgslug-<slug>      NoStream   this slug is unclaimed
//
// Two people racing for one slug contend on the slug stream. One person racing
// themselves — a double-clicked button, two tabs — contends on the owner stream.
// KurrentDB rejects the loser, and because the append is atomic, the loser
// writes NOTHING: no orphan organization, no half-held reservation.
//
// The alternative, checking a projection first, cannot work and fails in the way
// hardest to notice: a projection is behind the log by construction, so under
// concurrency both callers read "free" and both append (ADR-052).
//
// # Why the refusals are deliberately vague about which stream lost
//
// A conflict returns CONFLICT naming the slug, or CONFLICT naming the
// organization the caller already owns. It does NOT report which precondition
// failed in the general case, because the two are distinguishable to the caller
// anyway: they know whether they already have an organization.
func (c *Creation) Create(ctx context.Context, cmd CreateCommand) (CreateResult, error) {
	name, err := domain.NewName(cmd.Name)
	if err != nil {
		return CreateResult{}, errs.ValidationFailedf("%s", err)
	}
	slug, err := domain.NewSlug(cmd.Slug)
	if err != nil {
		return CreateResult{}, errs.ValidationFailedf("%s", err)
	}
	if cmd.Owner == "" {
		return CreateResult{}, errs.Internalf("no authenticated subject reached the create " +
			"handler; an organization with no owner is one nobody can administer or pay for")
	}
	if cmd.IdempotencyKey == "" {
		return CreateResult{}, errs.ValidationFailedf(
			"an Idempotency-Key is required on every mutating request")
	}

	now := c.now().UTC()
	orgID := ids.New[ids.Org](now, ids.Entropy()).String()

	org := domain.NewOrganization()
	if err := org.Create(orgID, name, slug, cmd.Owner, now); err != nil {
		return CreateResult{}, errs.ValidationFailedf("%s", err)
	}

	orgStream, err := eventsourcing.NewStreamID(domain.Category, domain.StreamKey(orgID))
	if err != nil {
		return CreateResult{}, errs.Internalf("organization stream").Wrap(err)
	}
	ownerStream, err := eventsourcing.NewStreamID(
		domain.OwnerCategory, domain.OwnerStreamKey(cmd.Owner))
	if err != nil {
		return CreateResult{}, errs.Internalf("owner reservation stream").Wrap(err)
	}
	slugStream, err := eventsourcing.NewStreamID(domain.SlugCategory, domain.SlugStreamKey(slug))
	if err != nil {
		return CreateResult{}, errs.Internalf("slug reservation stream").Wrap(err)
	}

	meta := eventsourcing.Metadata{OrgID: orgID, OccurredAt: now}

	// Event ids are DERIVED from the idempotency key, so a retry of the same
	// command produces byte-identical ids. A redelivery is then refused by the
	// store as a duplicate rather than appended twice.
	pending := org.Uncommitted()
	orgEvents := make([]eventsourcing.PendingEvent, 0, len(pending))
	for i, e := range pending {
		orgEvents = append(orgEvents, eventsourcing.PendingEvent{
			ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey, i),
			Event: e,
			Meta:  eventsourcing.StampSchemaVersion(meta, c.schemas, e.EventType()),
		})
	}

	ownerHeld := &contract.OwnerReservationHeld{
		SubjectID: cmd.Owner, OrgID: orgID, HeldAt: now,
	}
	slugHeld := &contract.SlugReservationHeld{Slug: slug, OrgID: orgID, HeldAt: now}

	_, err = c.appender.AppendToMany(ctx, []eventsourcing.StreamAppend{
		{
			Stream: orgStream,
			// NoStream: a fresh ULID cannot collide, so this precondition is a
			// belt-and-braces guard against an id generator that ever repeats.
			Expected: eventsourcing.NoStream(),
			Events:   orgEvents,
		},
		{
			Stream: ownerStream,
			// NoStream is the ONE-ORGANIZATION-PER-SUBJECT invariant. Nothing
			// else enforces it.
			Expected: eventsourcing.NoStream(),
			Events: []eventsourcing.PendingEvent{{
				ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey+":owner", 0),
				Event: ownerHeld,
				Meta:  eventsourcing.StampSchemaVersion(meta, c.schemas, ownerHeld.EventType()),
			}},
		},
		{
			Stream: slugStream,
			// NoStream is slug uniqueness.
			Expected: eventsourcing.NoStream(),
			Events: []eventsourcing.PendingEvent{{
				ID:    eventsourcing.DeriveEventID(cmd.IdempotencyKey+":slug", 0),
				Event: slugHeld,
				Meta:  eventsourcing.StampSchemaVersion(meta, c.schemas, slugHeld.EventType()),
			}},
		},
	})
	if err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// One of the three preconditions failed and NOTHING was written.
			// Which one is not reported: the caller knows whether they already
			// own an organization, and naming the slug is the actionable half.
			return CreateResult{}, errs.Conflictf(
				"either %q is already taken or you already own an organization; a person may "+
					"own one organization at a time", slug)
		}
		return CreateResult{}, errs.Internalf("creating the organization").Wrap(err)
	}
	org.ClearUncommitted()

	return CreateResult{OrgID: orgID, Slug: slug, Status: domain.StatusProvisioning}, nil
}
