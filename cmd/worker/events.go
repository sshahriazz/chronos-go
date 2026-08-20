package main

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/notify"
)

// This file is the whole answer to "what notifies whom, and where does it come
// from?".
//
// Two declarations, side by side on purpose:
//
//   - registerEvents says which events this binary can DECODE.
//   - notifications says, for each of them, whether it notifies and to whom.
//
// events_test.go asserts the two agree. An event added to the first without a
// decision in the second fails the build — which is the point. Nothing about
// notification delivery is implicit: not the audience, not the class, not the
// wording, and not the decision to stay silent.
func registerEvents(codec *eventcodec.JSON) {
	// Module event types register here as the verticals land, e.g.
	//   eventcodec.Register[identity.PasswordChanged](codec)
	eventcodec.Register[contract.NotificationCreated](codec)
	eventcodec.Register[contract.NotificationRead](codec)
	eventcodec.Register[contract.PushSubscribed](codec)
	eventcodec.Register[contract.PushSubscriptionExpired](codec)
	eventcodec.Register[contract.PushSent](codec)
}

// notifications declares what each event sends, and to whom.
//
// Every entry names four things and cannot omit any of them: the event (from
// the type parameter), the wording, the class that decides whether it is
// delivered at all, and the audience that decides who receives it.
//
//	cat.On[identity.PasswordChanged](notify.Spec{
//	    Template: "identity.password_changed",
//	    Class:    notify.Security,          // always sent, no unsubscribe
//	    Audience: notify.AudienceSubject,   // the person whose password it was
//	}, func(e *identity.PasswordChanged) map[string]any {
//	    return map[string]any{"Device": e.Device, "Location": e.City}
//	})
//
// An event that should tell nobody is declared too, with a reason:
//
//	cat.Silent[identity.TelemetryRecorded]("internal counter")
func notifications() *notify.Catalogue {
	cat := notify.NewCatalogue()

	// The notification module's OWN events notify nobody. They are operational
	// records of delivery — that a feed item was created, that a push was sent
	// — and notifying about them would be a loop: a notification about a
	// notification, which itself notifies (notification.md §10).
	cat.Silent[contract.NotificationCreated]("operational record of in-app delivery; notifying about it would recurse")
	cat.Silent[contract.NotificationRead]("the recipient read it; telling them so is circular")
	cat.Silent[contract.PushSubscribed]("the person just granted permission in the browser; they know")
	cat.Silent[contract.PushSubscriptionExpired]("a dead endpoint is an operational fact, surfaced in-app if it matters")
	cat.Silent[contract.PushSent]("operational record of push delivery")

	return cat
}

// audiences maps each role to the thing that can answer it.
//
// An audience with no resolver stays UNANSWERABLE and parks the notification,
// rather than being approximated. That is deliberate: notifying the wrong
// person is worse than notifying nobody, and a parked event is visible where a
// wrong recipient is not.
//
// AudienceOrgOwner and AudienceOrgAdmins are absent until the organization
// module lands with a read model that can answer them. Any catalogue entry using
// them parks until then — loudly, and by design.
func audiences(operator string) *notify.Registry {
	subject := notify.SubjectAudiences{Operator: operatorRecipients(operator)}
	return notify.NewRegistry().
		Register(notify.AudienceSubject, subject).
		Register(notify.AudienceActor, subject).
		Register(notify.AudienceOperator, subject)
}

// operatorRecipients is who receives Operator-class alerts — a stopped
// projection, a parked backlog. Never a tenant, and never carrying tenant
// personal data (NOTIFICATIONS §4).
func operatorRecipients(address string) []notify.Recipient {
	if address == "" {
		return nil
	}
	return []notify.Recipient{{Address: address, Locale: "en", Timezone: "UTC"}}
}

// notificationReactorName is the persistent subscription group and is
// PERMANENT. Renaming it creates a fresh group starting at the end of the log,
// silently abandoning anything the old one had not yet delivered (ADR-019).
const notificationReactorName = "notifications"
