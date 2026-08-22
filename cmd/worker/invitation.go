package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"log/slog"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	temporaladapter "github.com/chronos/chronos-go/internal/adapter/temporal"
	entitlementpg "github.com/chronos/chronos-go/internal/modules/entitlement/adapter/postgres"
	entitlementapp "github.com/chronos/chronos-go/internal/modules/entitlement/app"
	entitlementdomain "github.com/chronos/chronos-go/internal/modules/entitlement/domain"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspacepg "github.com/chronos/chronos-go/internal/modules/workspace/adapter/postgres"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	workspacedomain "github.com/chronos/chronos-go/internal/modules/workspace/domain"
	workspacereactor "github.com/chronos/chronos-go/internal/modules/workspace/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/secret"
)

// newInvitationIssuer builds the thing that mints invitation links, or reports
// why it could not be.
//
// Constructed in the composition root and held, like the verification issuer
// beside it, so its absence is a logged and testable fact rather than a reactor
// quietly missing from a list. A worker without it consumes no InvitationIssued
// at all: every invitation then spends a seat, sits Pending for seven days, and
// mails nobody.
func newInvitationIssuer(d *dependencies) (*workspaceapp.InvitationIssuer, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: link digests live in invitation_token, so " +
			"nothing can record the digest an emailed link is checked against")
	}
	tokens, err := workspacepg.NewInvitationTokens(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}

	// Workspace's OWN lifetime table. platform/secret holds no policy, and an
	// invitation's window is a decision about invitations (workspace.md §5's
	// seven days) rather than about hashing.
	minter, err := secret.New(map[secret.Purpose]time.Duration{
		workspaceapp.PurposeInvitation: workspaceapp.InvitationTTL,
	})
	if err != nil {
		return nil, fmt.Errorf("invitation minter: %w", err)
	}

	return workspaceapp.NewInvitationIssuer(workspaceapp.InvitationIssuerDeps{
		Clock:  clock.System{},
		Tokens: tokens,
		Minter: minter,
	})
}

// invitationIssuerAdapter presents workspace's use case as the reactor's port.
//
// Two structurally identical types rather than one shared one, for the reason
// issuerAdapter gives: the alternative is workspace/reactor importing
// workspace/app, and a reactor that can reach into a use case is a reactor that
// will eventually make a decision for it. The conversion is mechanical and
// total.
type invitationIssuerAdapter struct {
	issuer *workspaceapp.InvitationIssuer
}

var _ workspacereactor.Issuer = invitationIssuerAdapter{}

func (a invitationIssuerAdapter) IssueLink(
	ctx context.Context, invitationID, orgID string,
) (workspacereactor.Link, error) {
	link, err := a.issuer.Issue(ctx, invitationID, orgID)
	if err != nil {
		return workspacereactor.Link{}, err
	}
	return workspacereactor.Link{
		Plaintext: link.Plaintext,
		// The TTL is the CONSTANT and not `ExpiresAt - now`, because the wording
		// says "expires in seven days" and a subtraction across a slow mint would
		// say "6 days" for a link that genuinely lasts seven.
		TTL:         workspaceapp.InvitationTTL,
		Fingerprint: link.Fingerprint,
	}, nil
}

// newInvitationMail builds the invitation-mail reactor.
//
// Its OWN codec, carrying workspace's schemas as well as its types — the same
// reason newVerificationMail builds identity's: a stored event read back through
// a version chain needs the registry that was built alongside RegisterSchemas
// (ADR-029).
//
// A separate reactor rather than a catalogue entry, for the reason the
// verification mail is one: the catalogue maps an event onto wording and an
// audience and its Data function sees only the decoded event, while this
// notification's payload is a CREDENTIAL that does not exist yet and cannot be
// derived from anything the event carries. And its own subscription group, so an
// invitation that keeps failing parks on its own queue instead of sharing
// retries with every other notification in the system.
func newInvitationMail(d *dependencies) (*workspacereactor.InvitationMail, error) {
	if d.invitations == nil {
		return nil, errors.New("no invitation issuer was constructed")
	}

	var opts []workspacereactor.Option
	if d.temporal != nil {
		// Durable delivery, for the reason ADR-017 gives: an SMTP outage becomes
		// an hour of workflow retries that survive this process restarting,
		// rather than a parked backlog of people whose seats are spent and who
		// were never told. Conditional because the client is nil with
		// TEMPORAL_ENABLED false, and that deployment must still deliver.
		opts = append(opts, workspacereactor.WithWorkflows(d.temporal))
	}

	r, err := workspacereactor.NewInvitationMail(
		invitationIssuerAdapter{issuer: d.invitations}, workspaceCodec(), d.Notify(), opts...)
	if err != nil {
		return nil, fmt.Errorf("invitation mail: %w", err)
	}
	return r, nil
}

// workspaceCodec is what the invitation reactor decodes with.
//
// A function rather than an inline construction, so a composition-root test can
// encode an event with the SAME codec the reactor is handed. Two constructions
// would let the test pass against a codec the binary does not use — and the
// failure that hides is total: every invitation event parks, after its seat has
// already been spent.
//
// It carries workspace's SCHEMAS as well as its types, for the reason
// newIdentityCodec does: a stored event read back through a version chain needs
// the registry that was built alongside RegisterSchemas (ADR-029).
func workspaceCodec() *eventcodec.JSON {
	codec := eventcodec.NewJSON(workspaceUpcasters())
	workspace.RegisterEvents(codec)
	return codec
}

// workspaceUpcasters is the version registry the repository reads through.
//
// Separate from the codec because eventsourcing.Repository takes both, and
// handing it a BARE registry would make a stored event at an older version fail
// to resolve — visibly, but only for invitations that already exist (ADR-029).
func workspaceUpcasters() *eventsourcing.UpcasterRegistry {
	upcasters := eventsourcing.NewUpcasterRegistry()
	workspace.RegisterSchemas(upcasters)
	return upcasters
}

// newInvitationSweep builds the reconciliation, or reports why it could not be.
//
// It needs a repository as well as a work list, because the decision is taken
// against the AGGREGATE and never against the row: a resend moves the deadline
// after the row was read, and expiring on the row's word would kill a live link
// and take back a seat that is still needed.
func newInvitationSweep(d *dependencies, log *slog.Logger) (*workspaceapp.InvitationSweep, error) {
	if d.pool == nil {
		return nil, errors.New("no read model: the work list is invitation_view, so nothing " +
			"can find an invitation that has run out")
	}
	if d.store == nil {
		return nil, errors.New("no event store: expiring appends to the invitation's stream")
	}

	due, err := workspacepg.NewDueReads(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}
	// The SETTLEMENT half only. Expiring touches the stream, the token store and
	// the seat pool; issuing needs a blind indexer, an account directory and the
	// vault, none of which this binary has and none of which a sweep has any
	// business being able to reach.
	repo := eventsourcing.NewRepository[*workspacedomain.Invitation](
		d.store, workspaceCodec(), workspaceUpcasters(),
		workspacedomain.InvitationCategory, workspacedomain.NewInvitation)

	tokens, err := workspacepg.NewInvitationTokens(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}
	counter, err := workspacepg.NewMembership(pgadapter.New(d.pool))
	if err != nil {
		return nil, err
	}
	reserver, err := newEntitlementReserver(d)
	if err != nil {
		return nil, err
	}
	seats, err := workspaceapp.NewSeats(workspaceapp.SeatsDeps{
		Reserver: reserver, Members: counter,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace seats: %w", err)
	}

	settlements, err := workspaceapp.NewSettlements(workspaceapp.SettlementsDeps{
		Repo: repo, Tokens: tokens, Seats: seats, Now: clock.System{}.Now,
	})
	if err != nil {
		return nil, fmt.Errorf("workspace settlements: %w", err)
	}
	return workspaceapp.NewInvitationSweep(due, settlements, log)
}

// invitationSweepAdapter presents workspace's use case as the activity's port.
//
// Two structurally identical result types rather than one shared one, for the
// reason sweepAdapter gives: the alternative is adapter/temporal importing
// workspace/app, and an adapter that can reach into a use case is an adapter
// that will eventually make a decision for it.
type invitationSweepAdapter struct{ sweep *workspaceapp.InvitationSweep }

var _ temporaladapter.InvitationSweeper = invitationSweepAdapter{}

func (a invitationSweepAdapter) SweepOnce(
	ctx context.Context, now time.Time, limit int,
) (temporaladapter.InvitationSweepPass, error) {
	result, err := a.sweep.Run(ctx, now)
	if err != nil {
		return temporaladapter.InvitationSweepPass{}, err
	}
	_ = limit // the batch is the use case's own bound; see app.DefaultSweepBatch
	return temporaladapter.InvitationSweepPass{
		Scanned: result.Scanned,
		Expired: result.Expired,
		Stale:   result.Stale,
		Failed:  result.Failed,
		More:    result.More,
	}, nil
}

// newEntitlementReserver builds the seat pool this binary settles against.
//
// The same construction cmd/api makes, and deliberately so: a sweep that
// released seats through a DIFFERENT reserver would be releasing against a
// different view of the same pool, and the two would drift in the direction
// nobody audits. It is built here rather than shared because the two binaries do
// not share a process — what has to match is the store and the plan, and both
// are named the same way in both places.
func newEntitlementReserver(d *dependencies) (workspaceapp.Reserver, error) {
	catalogue, err := entitlementdomain.NewCatalogue(entitlementdomain.Trial())
	if err != nil {
		return nil, fmt.Errorf("entitlement catalogue: %w", err)
	}
	plans, err := entitlementapp.NewOrgPlans(catalogue, "trial")
	if err != nil {
		return nil, fmt.Errorf("entitlement plans: %w", err)
	}

	adapter := pgadapter.New(d.pool)
	store, err := entitlementpg.NewReservations(adapter, adapter)
	if err != nil {
		return nil, fmt.Errorf("reservation store: %w", err)
	}

	reserver, err := entitlementapp.NewReserver(entitlementapp.ReserverDeps{
		Store: store,
		Plans: plans,
		Now:   clock.System{}.Now,
		NewID: func() string {
			return ids.New[ids.Event](clock.System{}.Now(), ids.Entropy()).String()
		},
	})
	if err != nil {
		return nil, fmt.Errorf("reserver: %w", err)
	}
	return &workerSeatReserver{inner: reserver}, nil
}

// workerSeatReserver translates entitlement's already-held signal into
// workspace's, exactly as cmd/api's seatReserver does.
//
// Duplicated rather than shared because the two binaries do not share a package,
// and because neither module may import the other's app layer (CONVENTIONS §2).
// A settlement never reserves, so only the release path is exercised here — but
// the translation is total, so a future caller cannot find half of it.
type workerSeatReserver struct{ inner *entitlementapp.Reserver }

var _ workspaceapp.Reserver = (*workerSeatReserver)(nil)

func (r *workerSeatReserver) ReserveFor(
	ctx context.Context, orgID, limitKey, subjectRef string,
) (string, error) {
	id, err := r.inner.ReserveFor(ctx, orgID, limitKey, subjectRef)
	var held entitlementapp.SeatAlreadyHeld
	if errors.As(err, &held) {
		return id, workspaceapp.SeatAlreadyHeld{ReservationID: held.ReservationID}
	}
	return id, err
}

func (r *workerSeatReserver) Commit(ctx context.Context, reservationID string) error {
	return r.inner.Commit(ctx, reservationID)
}

func (r *workerSeatReserver) Release(ctx context.Context, reservationID string) error {
	return r.inner.Release(ctx, reservationID)
}

func (r *workerSeatReserver) ReleaseFor(ctx context.Context, orgID, limitKey, subjectRef string) error {
	return r.inner.ReleaseFor(ctx, orgID, limitKey, subjectRef)
}
