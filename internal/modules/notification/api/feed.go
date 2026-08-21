package api

import (
	"context"

	"connectrpc.com/connect"
	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	"github.com/chronos/chronos-go/internal/platform/errs"
	"github.com/chronos/chronos-go/internal/platform/ids"
	"github.com/chronos/chronos-go/internal/platform/page"
)

// The three RPCs in this file are the inbox. Each names its recipient with the
// CALLER'S pseudonym and with nothing from the request: none of the three
// request messages carries a subject id, and that is the schema's decision
// rather than this layer's convenience.

// ListNotifications returns one page of the caller's own feed, newest first.
//
// The page token and page size go straight through to `app.Queries`, which owns
// the whole pagination contract: it clamps an oversized size, refuses a negative
// one, and treats an unusable token as an ERROR rather than as "start again".
// This layer must not soften any of those — a client handed page one for a token
// it believes points into the middle of a list walks that list forever, and
// nothing in the loop looks like a failure.
//
// The token is bound to the query it came from, and that binding includes both
// the SUBJECT and the ORGANIZATION. So a token minted for one person is a decode
// failure against another, and one minted in one organization is a decode
// failure in the next — independently of the scoping above.
func (s *Service) ListNotifications(
	ctx context.Context, req *connect.Request[notificationv1.ListNotificationsRequest],
) (*connect.Response[notificationv1.ListNotificationsResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	result, err := s.queries.ListNotifications(ctx,
		req.Msg.GetOrgId(), subjectID,
		page.Token(req.Msg.GetPageToken()), int(req.Msg.GetPageSize()))
	if err != nil {
		return nil, fail(err)
	}

	items := make([]*notificationv1.Notification, 0, len(result.Items))
	for _, item := range result.Items {
		items = append(items, protoNotification(item))
	}
	return connect.NewResponse(&notificationv1.ListNotificationsResponse{
		Notifications: items,
		NextPageToken: string(result.Next),
	}), nil
}

// GetUnreadCount returns the caller's own badge number.
func (s *Service) GetUnreadCount(
	ctx context.Context, req *connect.Request[notificationv1.GetUnreadCountRequest],
) (*connect.Response[notificationv1.GetUnreadCountResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	n, err := s.queries.UnreadCount(ctx, req.Msg.GetOrgId(), subjectID)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.GetUnreadCountResponse{Unread: n}), nil
}

// MarkNotificationsRead dismisses items the caller has seen.
//
// The ids are parsed HERE rather than passed as strings, so a value that is not
// a notification id is an InvalidArgument at the boundary instead of a not-found
// three layers down. protovalidate has already checked the pattern; this turns
// the checked string into the typed value the use case takes, and the two agree
// because both derive the prefix from `platform/ids` rather than from a literal.
//
// Whether each id is the CALLER'S is decided by the use case, against the
// caller's own feed. This layer does not and must not attempt it: an id is a
// stream name, not a capability, and the check needs a read this layer has no
// port for.
func (s *Service) MarkNotificationsRead(
	ctx context.Context, req *connect.Request[notificationv1.MarkNotificationsReadRequest],
) (*connect.Response[notificationv1.MarkNotificationsReadResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	raw := req.Msg.GetNotificationIds()
	parsed := make([]ids.NotificationID, 0, len(raw))
	for _, s := range raw {
		id, err := ids.Parse[ids.Notification](s)
		if err != nil {
			// The value is echoed because the caller sent it and it is not a
			// fact about anybody's account — it is either a typo or a guess, and
			// naming it is what makes the first case fixable. Whether the id
			// EXISTS is a different question, answered identically for every id
			// the caller does not own.
			return nil, fail(errs.ValidationFailedf(
				"%q is not a notification id", s).Wrap(err))
		}
		parsed = append(parsed, id)
	}

	result, err := s.inbox.MarkRead(ctx, app.MarkReadCommand{
		OrgID:           req.Msg.GetOrgId(),
		SubjectID:       subjectID,
		NotificationIDs: parsed,
		IdempotencyKey:  key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.MarkNotificationsReadResponse{
		//nolint:gosec // MarkRead bounds the batch at MaxMarkReadBatch.
		Marked: int32(result.Marked),
	}), nil
}
