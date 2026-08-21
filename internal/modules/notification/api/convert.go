package api

import (
	"sort"
	"strconv"
	"time"

	notificationv1 "github.com/chronos/chronos-go/gen/proto/chronos/notification/v1"
	"github.com/chronos/chronos-go/internal/modules/notification/app"
	jsoncodec "github.com/chronos/chronos-go/internal/platform/codec"
	"github.com/chronos/chronos-go/internal/platform/notify"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// protoTime renders a UTC instant, or nil for "never".
//
// nil rather than a zero Timestamp, because a zero Timestamp is 1970 on the
// wire and a client rendering it shows a date rather than an absence. Every
// optional time in this API is unset by being absent.
func protoTime(t time.Time) *timestamppb.Timestamp {
	if t.IsZero() {
		return nil
	}
	return timestamppb.New(t.UTC())
}

// protoChannel maps a channel onto the wire enum.
//
// An unrecognised channel becomes UNSPECIFIED rather than being dropped, so a
// client sees that something exists it cannot name — which is a better failure
// than a settings screen silently missing a switch.
func protoChannel(ch notify.Channel) notificationv1.Channel {
	switch ch {
	case notify.ChannelEmail:
		return notificationv1.Channel_CHANNEL_EMAIL
	case notify.ChannelInApp:
		return notificationv1.Channel_CHANNEL_IN_APP
	case notify.ChannelWebPush:
		return notificationv1.Channel_CHANNEL_WEB_PUSH
	default:
		return notificationv1.Channel_CHANNEL_UNSPECIFIED
	}
}

// domainChannel maps the wire enum onto a channel.
//
// UNSPECIFIED and anything unrecognised map to the empty channel, which
// `domain.IsGovernable` refuses. That is the SAFE direction: a value this build
// cannot name never becomes a real channel by accident, and the caller is told
// rather than having a toggle applied to something they did not choose.
// protovalidate refuses UNSPECIFIED before a handler runs; this is what holds if
// that rule is ever relaxed.
func domainChannel(ch notificationv1.Channel) notify.Channel {
	switch ch {
	case notificationv1.Channel_CHANNEL_EMAIL:
		return notify.ChannelEmail
	case notificationv1.Channel_CHANNEL_IN_APP:
		return notify.ChannelInApp
	case notificationv1.Channel_CHANNEL_WEB_PUSH:
		return notify.ChannelWebPush
	default:
		return ""
	}
}

// protoClass maps a notification class onto the wire enum.
func protoClass(c notify.Class) notificationv1.NotificationClass {
	switch c {
	case notify.Security:
		return notificationv1.NotificationClass_NOTIFICATION_CLASS_SECURITY
	case notify.Transactional:
		return notificationv1.NotificationClass_NOTIFICATION_CLASS_TRANSACTIONAL
	case notify.Activity:
		return notificationv1.NotificationClass_NOTIFICATION_CLASS_ACTIVITY
	case notify.Product:
		return notificationv1.NotificationClass_NOTIFICATION_CLASS_PRODUCT
	default:
		// Operator lands here too, and correctly: an operator alert has no tenant
		// recipient, so it can never appear in anybody's feed. There is
		// deliberately no wire value for it — publishing one would invite a client
		// to ask for operator notifications.
		return notificationv1.NotificationClass_NOTIFICATION_CLASS_UNSPECIFIED
	}
}

func protoClasses(cs []notify.Class) []notificationv1.NotificationClass {
	out := make([]notificationv1.NotificationClass, 0, len(cs))
	for _, c := range cs {
		out = append(out, protoClass(c))
	}
	return out
}

// protoPreferences renders the channel toggles.
func protoPreferences(prefs []app.ChannelPreference) []*notificationv1.ChannelPreference {
	out := make([]*notificationv1.ChannelPreference, 0, len(prefs))
	for _, p := range prefs {
		out = append(out, &notificationv1.ChannelPreference{
			Channel: protoChannel(p.Channel),
			Enabled: p.Enabled,
		})
	}
	return out
}

// protoData renders template input as sorted key/value text.
//
// SORTED, and that is not cosmetic: a Go map iterates in a random order, so an
// unsorted result would give two identical requests two different responses —
// which turns a diff between a live response and an idempotency-store replay
// into noise, and makes any client-side snapshot test flap.
//
// The rendering is deterministic and total. A float that is a whole number is
// written without a decimal point, because JSON has no integers and a count of 8
// arriving as "8.000000" on a screen is a defect a client cannot fix. Anything
// this function does not recognise is JSON-encoded, so a nested value survives
// as its own JSON rather than as Go'"'"'s %v — which no client could parse.
//
// It is not a place personal data could leak from: the column is written by the
// feed projector from an event payload, and an event carries no personal data
// (ADR-002). This function copies whatever is there and adds nothing.
func protoData(data map[string]any) []*notificationv1.TemplateValue {
	if len(data) == 0 {
		return nil
	}
	keys := make([]string, 0, len(data))
	for k := range data {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	out := make([]*notificationv1.TemplateValue, 0, len(keys))
	for _, k := range keys {
		out = append(out, &notificationv1.TemplateValue{Key: k, Value: renderValue(data[k])})
	}
	return out
}

func renderValue(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		return strconv.FormatBool(t)
	case float64:
		// 'f' with precision -1 is the shortest representation that round-trips,
		// and a whole number therefore renders as "8" rather than "8.000000".
		return strconv.FormatFloat(t, 'f', -1, 64)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	default:
		encoded, err := jsoncodec.Marshal(v)
		if err != nil {
			// Unencodable template input is a bug in whatever raised the
			// notification, and it can never become encodable. An empty value
			// costs one placeholder; refusing would cost the whole inbox, and the
			// security alerts in it are exactly what must stay reachable.
			return ""
		}
		return string(encoded)
	}
}

// protoNotification renders one feed item.
func protoNotification(f app.FeedItem) *notificationv1.Notification {
	return &notificationv1.Notification{
		NotificationId: f.NotificationID.String(),
		Template:       f.Template,
		Class:          protoClass(f.Class),
		Data:           protoData(f.Data),
		WorkspaceId:    f.WorkspaceID,
		OccurredAt:     protoTime(f.OccurredAt),
		ReadAt:         protoTime(f.ReadAt),
	}
}
