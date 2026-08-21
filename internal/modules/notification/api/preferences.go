package api

import (
	"context"

	"connectrpc.com/connect"
	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
)

// GetNotificationPreferences returns the caller's own channel toggles, and what
// those toggles reach.
//
// The two class lists are not decoration and are not a hand-written constant.
// They come from `domain.GovernedClasses` and `domain.AlwaysDeliveredClasses`,
// which are computed from `notify.Class.IgnoresPreferences` — the SAME predicate
// the dispatcher applies before it consults any preference. That is what makes
// "you may turn off product mail but not the message telling you your second
// factor was removed" a property the API reports rather than a promise a
// document makes: if the predicate ever changed, this response would change with
// it, and the tests that assert Security is always delivered would fail
// immediately instead of the change landing silently.
func (s *Service) GetNotificationPreferences(
	ctx context.Context, req *connect.Request[notificationv1.GetNotificationPreferencesRequest],
) (*connect.Response[notificationv1.GetNotificationPreferencesResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	view, err := s.queries.GetPreferences(ctx, req.Msg.GetOrgId(), subjectID)
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.GetNotificationPreferencesResponse{
		Channels:               protoPreferences(view.Channels),
		GovernedClasses:        protoClasses(view.Governed),
		AlwaysDeliveredClasses: protoClasses(view.AlwaysDelivered),
	}), nil
}

// SetNotificationPreferences changes the caller's own channel toggles.
//
// The request carries `(channel, enabled)` pairs and nothing else. There is no
// class field and no template field to map here, because there is none on the
// wire — which is why this handler has no branch that could ever decide whether
// a class is suppressible. It cannot make that mistake; it was never given the
// input that would let it.
func (s *Service) SetNotificationPreferences(
	ctx context.Context, req *connect.Request[notificationv1.SetNotificationPreferencesRequest],
) (*connect.Response[notificationv1.SetNotificationPreferencesResponse], error) {
	subjectID, err := callerSubject(ctx)
	if err != nil {
		return nil, fail(err)
	}
	key, err := idempotencyKey(req.Header())
	if err != nil {
		return nil, fail(err)
	}

	wire := req.Msg.GetChannels()
	settings := make([]app.ChannelPreference, 0, len(wire))
	for _, c := range wire {
		// An unrecognised enum becomes the empty channel, which the domain
		// refuses by name. Mapping it to a real channel would apply a toggle the
		// caller did not choose — see domainChannel.
		settings = append(settings, app.ChannelPreference{
			Channel: domainChannel(c.GetChannel()),
			Enabled: c.GetEnabled(),
		})
	}

	view, err := s.prefs.Set(ctx, app.SetPreferencesCommand{
		OrgID:          req.Msg.GetOrgId(),
		SubjectID:      subjectID,
		Settings:       settings,
		IdempotencyKey: key,
	})
	if err != nil {
		return nil, fail(err)
	}
	return connect.NewResponse(&notificationv1.SetNotificationPreferencesResponse{
		Channels:               protoPreferences(view.Channels),
		GovernedClasses:        protoClasses(view.Governed),
		AlwaysDeliveredClasses: protoClasses(view.AlwaysDelivered),
	}), nil
}
