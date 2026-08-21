package app

import (
	"context"
	"fmt"
	"time"

	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/modules/notification/domain"
	"github.com/chronos/chronos-go/internal/platform/clock"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterPushCommand enrols one browser profile on one device.
type RegisterPushCommand struct {
	// OrgID is the organization this device should receive push for.
	//
	// Per organization, not global. One browser produces ONE endpoint across
	// every organization a person belongs to, so the same endpoint arriving for
	// a second organization is a second subscription rather than a move
	// (ADR-043).
	OrgID string

	// SubjectID is the CALLER'S pseudonym, from the session.
	SubjectID string

	// Endpoint, P256dh and Auth are what the browser's own PushSubscription
	// reports. They are transport credentials — not personal data, but they
	// identify a device — and no response ever returns them.
	Endpoint string
	P256dh   string
	Auth     string

	// UserAgent lets a person recognise a device in a support conversation.
	UserAgent string

	IdempotencyKey string
}

// RemovePushCommand retires one browser endpoint.
type RemovePushCommand struct {
	OrgID     string
	SubjectID string

	// Endpoint, rather than a subscription id, because the endpoint is what a
	// browser holds: a service worker unsubscribing knows its own endpoint and
	// has no reason to have kept an id we minted.
	Endpoint string

	IdempotencyKey string
}

// PushRegistry is the browser-endpoint half of the module's client surface.
type PushRegistry struct {
	appender Appender
	clock    clock.Clock
}

// PushRegistryDeps is what the use case needs.
type PushRegistryDeps struct {
	Appends Appender
	Clock   clock.Clock
}

// NewPushRegistry builds the use case, refusing a partial one.
func NewPushRegistry(deps PushRegistryDeps) (*PushRegistry, error) {
	if deps.Appends == nil {
		return nil, fmt.Errorf("notification/app: the push registry needs an event store")
	}
	if deps.Clock == nil {
		deps.Clock = clock.System{}
	}
	return &PushRegistry{appender: deps.Appends, clock: deps.Clock}, nil
}

// Register enrols a browser.
//
// # It reads nothing
//
// The subscription's identity is DERIVED from the organization and the endpoint
// (domain.PushSubscriptionID), so there is no lookup to do and no projection to
// wait for. That matters more than it looks: the alternative — read the table,
// find an existing row, reuse its id — fails for as long as the projection lags
// the registration that just happened, which is exactly the window a browser
// re-subscribing after a permission prompt lands in.
//
// # Re-registering is the normal case
//
// A permission prompt answered again produces the same endpoint. The append
// therefore uses AnyRevision and the projector upserts on `(org_id, endpoint)`,
// so the row is refreshed with the new keys and revived if it had expired —
// which is correct, because the person granted permission again and their
// earlier `410 Gone` is history.
//
// # The endpoint is validated, not merely shaped
//
// domain.ParsePushEndpoint refuses anything the server should not POST to. The
// schema already refuses non-https, and this refuses the rest — an address
// literal, a loopback name, a private suffix, a non-https port, credentials in
// the URL. Without it an endpoint field is a request-forgery primitive aimed at
// whatever this server can reach.
func (p *PushRegistry) Register(
	ctx context.Context, cmd RegisterPushCommand,
) (RegisterPushResult, error) {
	if err := requireScope(cmd.OrgID, cmd.SubjectID, "registering a push subscription"); err != nil {
		return RegisterPushResult{}, err
	}
	if cmd.IdempotencyKey == "" {
		return RegisterPushResult{}, errs.ValidationFailedf("an idempotency key is required")
	}
	switch {
	case cmd.P256dh == "":
		return RegisterPushResult{}, errs.ValidationFailedf(
			"a push subscription needs its P-256 key")
	case cmd.Auth == "":
		return RegisterPushResult{}, errs.ValidationFailedf(
			"a push subscription needs its authentication secret")
	}

	endpoint, err := domain.ParsePushEndpoint(cmd.Endpoint)
	if err != nil {
		// The message names the shape, never the value: an endpoint is a
		// per-device credential and must not reach a log line or an error body.
		return RegisterPushResult{}, errs.ValidationFailedf(
			"this push endpoint cannot be used").Wrap(err)
	}

	id := domain.PushSubscriptionID(cmd.OrgID, endpoint)
	stream, err := eventsourcing.NewStreamID(domain.Category, id.String())
	if err != nil {
		return RegisterPushResult{}, errs.Internalf("push subscription stream id").Wrap(err)
	}

	now := p.clock.Now().UTC()
	_, err = p.appender.Append(ctx, stream,
		// AnyRevision: a subscription accumulates a history — subscribed,
		// expired, subscribed again — and re-subscribing is not a decision that
		// depends on what came before.
		eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID: eventsourcing.DeriveEventID(cmd.IdempotencyKey, 0),
			Event: &contract.PushSubscribed{
				SubscriptionID: id.String(),
				SubjectID:      cmd.SubjectID,
				Endpoint:       endpoint.String(),
				P256dh:         cmd.P256dh,
				Auth:           cmd.Auth,
				UserAgent:      cmd.UserAgent,
				SubscribedAt:   now,
			},
			Meta: p.meta(ctx, cmd.OrgID, cmd.SubjectID, cmd.IdempotencyKey, now),
		}})
	if err != nil {
		return RegisterPushResult{}, errs.Internalf("registering a push subscription").Wrap(err)
	}

	// Created is reported as true from here because this call did append a
	// subscribed event. Whether a ROW already existed is a question about the
	// projection, and answering it would mean reading a table that may not have
	// caught up — an answer that would be wrong precisely when it mattered.
	return RegisterPushResult{SubscriptionID: id, Created: true}, nil
}

// Remove retires a browser endpoint.
//
// The row is marked expired rather than deleted, because "why did I stop getting
// push?" is a real support question and a deleted row cannot answer it — the
// projector already implements that, and this simply appends the fact.
//
// Removing an endpoint that was never registered is NOT an error. The caller
// wanted it gone and it is gone; reporting NOT_FOUND would tell a caller whether
// an endpoint was registered in this organization, which is a question about
// somebody's devices, and it would make a service worker's cleanup path fail
// noisily for doing the right thing twice.
func (p *PushRegistry) Remove(ctx context.Context, cmd RemovePushCommand) (RemovePushResult, error) {
	if err := requireScope(cmd.OrgID, cmd.SubjectID, "removing a push subscription"); err != nil {
		return RemovePushResult{}, err
	}
	if cmd.IdempotencyKey == "" {
		return RemovePushResult{}, errs.ValidationFailedf("an idempotency key is required")
	}

	endpoint, err := domain.ParsePushEndpoint(cmd.Endpoint)
	if err != nil {
		return RemovePushResult{}, errs.ValidationFailedf(
			"this push endpoint cannot be used").Wrap(err)
	}

	id := domain.PushSubscriptionID(cmd.OrgID, endpoint)
	stream, err := eventsourcing.NewStreamID(domain.Category, id.String())
	if err != nil {
		return RemovePushResult{}, errs.Internalf("push subscription stream id").Wrap(err)
	}

	now := p.clock.Now().UTC()
	_, err = p.appender.Append(ctx, stream, eventsourcing.AnyRevision(),
		[]eventsourcing.PendingEvent{{
			ID: eventsourcing.DeriveEventID(cmd.IdempotencyKey, 0),
			Event: &contract.PushSubscriptionExpired{
				SubscriptionID: id.String(),
				SubjectID:      cmd.SubjectID,
				// A fixed reason, distinct from the "410 Gone" the sender writes
				// when a push service rejects an endpoint. The two are different
				// facts — the person unsubscribed, or the browser dropped it —
				// and support needs to tell them apart.
				Reason:    ReasonUnsubscribed,
				ExpiredAt: now,
			},
			Meta: p.meta(ctx, cmd.OrgID, cmd.SubjectID, cmd.IdempotencyKey, now),
		}})
	if err != nil {
		return RemovePushResult{}, errs.Internalf("removing a push subscription").Wrap(err)
	}
	return RemovePushResult{SubscriptionID: id}, nil
}

// ReasonUnsubscribed is why a subscription this call retired went away.
//
// A constant rather than a literal, because it is written into the log forever
// and read back by whoever answers "why did I stop getting push?".
const ReasonUnsubscribed = "unsubscribed"

func (p *PushRegistry) meta(
	ctx context.Context, orgID, subjectID, idempotencyKey string, now time.Time,
) eventsourcing.Metadata {
	trace := eventsourcing.TraceFrom(ctx)
	return eventsourcing.Metadata{
		SchemaVersion: 1,
		OccurredAt:    now,
		OrgID:         orgID,
		SubjectIDs:    []string{subjectID},
		ActorID:       subjectID,
		CorrelationID: rootCorrelation(trace.CorrelationID, idempotencyKey),
		CausationID:   rootCausation(trace.CausationID, idempotencyKey),
	}
}
