package main

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	pgadapter "github.com/chronos/chronos-go/internal/adapter/postgres"
	"github.com/chronos/chronos-go/internal/modules/workspace"
	workspacepg "github.com/chronos/chronos-go/internal/modules/workspace/adapter/postgres"
	workspaceapp "github.com/chronos/chronos-go/internal/modules/workspace/app"
	workspacereactor "github.com/chronos/chronos-go/internal/modules/workspace/reactor"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
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
	upcasters := eventsourcing.NewUpcasterRegistry()
	workspace.RegisterSchemas(upcasters)
	codec := eventcodec.NewJSON(upcasters)
	workspace.RegisterEvents(codec)
	return codec
}
