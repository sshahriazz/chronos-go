package kurrentdb

import (
	"context"
	"crypto/rand"
	"errors"
	"fmt"
	"time"

	orgcontract "github.com/chronos/chronos-go/internal/modules/organization/contract"
	orgdomain "github.com/chronos/chronos-go/internal/modules/organization/domain"
	"github.com/chronos/chronos-go/internal/operator/app"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
)

// Organizations writes to the TENANT's organization aggregate on the operator's
// behalf.
//
// # There is no operator-flavoured event here, and that is the point
//
// operator.md §7: "Operator writes go through the same domain commands as
// everything else — they emit the same events and honour the same invariants.
// There is no privileged back-channel that skips domain rules, because that
// back-channel is exactly what corrupts state that then cannot be replayed."
//
// So this loads the organization's own stream, calls the organization's own
// command, and appends the organization's own event. Every downstream
// consequence follows for free and identically: the tenant's projections
// update, `organization.suspended` mails every member, gate 3 starts refusing
// writes, and the state machine refuses an illegal transition exactly as it
// would for any other caller.
//
// What the operator plane adds is the AUDIT entry beside it and the
// authorization to make the call — neither of which changes what the tenant
// experiences.
//
// # It loads the STREAM, not a projection
//
// Unlike operator account management, which rebuilds its aggregate from a row.
// The difference is what the rules depend on: an operator's role is a value,
// and an organization's status is a STATE MACHINE whose legal moves depend on
// exactly where it is. A stale projection would let a closed organization be
// suspended, and the append would then succeed because nothing downstream
// re-checks.
//
// Loading the stream also gives real optimistic concurrency, which is what
// operator.md §5's D15 asks for: two operators acting on one organization at
// once, and the second is refused rather than silently overwriting.
type Organizations struct {
	repo    *eventsourcing.Repository[*orgdomain.Organization]
	clock   func() time.Time
	entropy func() string
}

// NewOrganizations builds the writer.
func NewOrganizations(
	store eventsourcing.EventStore,
	codec eventsourcing.Codec,
	upcasters *eventsourcing.UpcasterRegistry,
	clock func() time.Time,
) (*Organizations, error) {
	if store == nil || codec == nil {
		return nil, fmt.Errorf("operator kurrentdb: the organization writer needs a store and a codec")
	}
	if clock == nil {
		clock = time.Now
	}
	return &Organizations{
		repo: eventsourcing.NewRepository(store, codec, upcasters,
			orgdomain.Category, orgdomain.NewOrganization),
		clock: clock,
		entropy: func() string {
			return ids.New[ids.Event](time.Now(), rand.Reader).String()
		},
	}, nil
}

var _ app.TenantOrganizations = (*Organizations)(nil)

// Suspend switches a tenant off through the organization aggregate.
func (o *Organizations) Suspend(
	ctx context.Context, orgID string, reason orgcontract.SuspensionReason, at time.Time,
) (bool, error) {
	return o.command(ctx, orgID, func(agg *orgdomain.Organization) error {
		return agg.Suspend(reason, at)
	})
}

// Reinstate returns a suspended tenant to active.
//
// It calls `Activate`, the organization's ordinary command, rather than a
// reinstate-specific one — there is no such thing, because a suspension lifted
// and a trial converting both land in Active and the state machine already says
// so. An operator-only path would be a second way to reach one state, which is
// how two paths drift.
func (o *Organizations) Reinstate(ctx context.Context, orgID string, at time.Time) (bool, error) {
	return o.command(ctx, orgID, func(agg *orgdomain.Organization) error {
		return agg.Activate(at)
	})
}

// command loads, applies and appends.
func (o *Organizations) command(
	ctx context.Context, orgID string, apply func(*orgdomain.Organization) error,
) (bool, error) {
	agg, err := o.repo.Load(ctx, orgdomain.StreamKey(orgID))
	if err != nil {
		return false, fmt.Errorf("loading organization %s: %w", orgID, err)
	}
	if !agg.Exists() {
		// A missing stream is not an error to the repository — it returns a new
		// aggregate, which is what lets create and modify share a path. Here it
		// means the org id names nothing, and suspending nothing must not
		// silently succeed.
		return false, app.ErrNoSuchOrganization
	}

	if err := apply(agg); err != nil {
		// The state machine's own refusal, carried through with its message.
		// The domain says "cannot transition from closed to suspended", which
		// is what tells an operator to stop rather than retry — and it is safe
		// to disclose because the caller has already been authenticated and
		// authorized to act on this tenant.
		return false, fmt.Errorf("%w: %w", app.ErrIllegalTransition, err)
	}
	if len(agg.Uncommitted()) == 0 {
		// The command was legal and recorded nothing, which the aggregates use
		// for "already in that state". A success that changed nothing.
		return false, nil
	}

	// A fresh idempotency key per command.
	//
	// There is no client Idempotency-Key to derive from — the operator console
	// is not the tenant API — and a constant would make two legitimate
	// consecutive commands collide on the same derived event id. What actually
	// protects against a lost update is the optimistic version precondition the
	// repository applies from the revision it loaded at.
	if _, err := o.repo.Save(ctx, orgdomain.StreamKey(orgID), agg, o.entropy(),
		eventsourcing.Metadata{OrgID: orgID}); err != nil {
		if errors.Is(err, eventsourcing.ErrWrongExpectedRevision) {
			// D15's case, reached: two operators acted on one organization at
			// once. The second is refused rather than overwriting, and the
			// message says so rather than reporting a generic failure.
			return false, fmt.Errorf(
				"operator: this organization changed while the command was being applied; "+
					"read it again and retry: %w", err)
		}
		return false, fmt.Errorf("appending to organization %s: %w", orgID, err)
	}
	return true, nil
}
