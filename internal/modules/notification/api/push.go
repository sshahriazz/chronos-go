package api

import (
	"context"

	"connectrpc.com/connect"
	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
)

// RegisterPushSubscription enrols one browser profile on one device.
//
// The response carries the subscription id and NOTHING ELSE. Not the endpoint,
// not the keys, not the user agent: those are transport credentials for a
// device, and an endpoint that came back out of this API would be readable by
// anything that could replay a response — including the idempotency store, which
// keeps a serialized copy for 24 hours.
func (s *Service) RegisterPushSubscription(
	ctx context.Context, req *connect.Request[notificationv1.RegisterPushSubscriptionRequest],
) (*connect.Response[notificationv1.RegisterPushSubscriptionResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.push.Register(ctx, app.RegisterPushCommand{
		OrgID:     req.Msg.GetOrgId(),
		SubjectID: subjectID,
		Endpoint:  req.Msg.GetEndpoint(),
		P256dh:    req.Msg.GetP256Dh(),
		Auth:      req.Msg.GetAuth(),
		UserAgent: req.Msg.GetUserAgent(),

		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.RegisterPushSubscriptionResponse{
		SubscriptionId: result.SubscriptionID.String(),
	}), nil
}

// RemovePushSubscription retires a browser endpoint.
//
// Removing one that was never registered is not an error — see app.PushRegistry
// for why reporting NOT_FOUND here would answer a question about somebody's
// devices.
func (s *Service) RemovePushSubscription(
	ctx context.Context, req *connect.Request[notificationv1.RemovePushSubscriptionRequest],
) (*connect.Response[notificationv1.RemovePushSubscriptionResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	result, err := s.push.Remove(ctx, app.RemovePushCommand{
		OrgID:          req.Msg.GetOrgId(),
		SubjectID:      subjectID,
		Endpoint:       req.Msg.GetEndpoint(),
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.RemovePushSubscriptionResponse{
		SubscriptionId: result.SubscriptionID.String(),
	}), nil
}
