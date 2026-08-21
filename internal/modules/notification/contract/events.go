// Package contract is the notification module's published surface — the only
// package another module may import (CONVENTIONS §1).
//
// These are OPERATIONAL events, not business ones (notification.md §10): they
// record that something was created, delivered, read or expired. No other module
// should subscribe to them for business logic — doing so couples a business rule
// to whether an email went out.
//
// Plain structs, no wire tags: serialization is the codec's job (ADR-001).
package contract

import "time"

// NotificationCreated is a feed item coming into existence.
//
// The in-app "delivery" IS this event. The feed table is a projection built from
// it, so nothing writes that table directly and the feed can be rebuilt from the
// log like any other read model (ADR-019).
//
// It carries NO personal data — no name, no address, no message body. Only the
// subject pseudonym, the template, and the data the template needs, which the
// catalogue guarantees is free of anything identifying (ADR-002).
type NotificationCreated struct {
	NotificationID string
	SubjectID      string
	Template       string
	Class          string
	OrgID          string
	WorkspaceID    string
	Data           map[string]any
	OccurredAt     time.Time
}

func (*NotificationCreated) EventType() string { return "notification.Created.v1" }

// NotificationRead records that the recipient saw it in-app.
//
// This is what alert arbitration reads: an Activity email is suppressed when the
// item was read within the window (ADR-026).
type NotificationRead struct {
	NotificationID string
	SubjectID      string
	ReadAt         time.Time
}

func (*NotificationRead) EventType() string { return "notification.Read.v1" }

// PushSubscribed registers one browser profile on one device.
//
// A subscription is per browser profile per device, not per user: one person
// commonly has several (notification.md §4). Keys are opaque transport
// credentials, not personal data, but they identify a device and are treated as
// sensitive.
type PushSubscribed struct {
	SubscriptionID string
	SubjectID      string
	Endpoint       string
	P256dh         string
	Auth           string
	UserAgent      string
	SubscribedAt   time.Time
}

func (*PushSubscribed) EventType() string { return "notification.PushSubscribed.v1" }

// PushSubscriptionExpired retires an endpoint the push service rejected.
//
// A 404 or 410 means the browser dropped the subscription. Stale endpoints
// accumulate fast and silently degrade delivery, so they are pruned on the first
// rejection rather than retried (notification.md §4).
type PushSubscriptionExpired struct {
	SubscriptionID string
	SubjectID      string
	Reason         string
	ExpiredAt      time.Time
}

func (*PushSubscriptionExpired) EventType() string { return "notification.PushSubscriptionExpired.v1" }

// PushSent records a successful push. Operational evidence for support
// questions: "was I notified?" is answerable without guessing.
type PushSent struct {
	NotificationID string
	SubscriptionID string
	SentAt         time.Time
}

func (*PushSent) EventType() string { return "notification.PushSent.v1" }

// ChannelPreferenceSet records that one person turned one channel on or off for
// one organization.
//
// One event per CHANNEL, never one per settings screen. A screen that saved a
// whole snapshot would make "did they turn email off, or did email simply not
// appear in that save?" unanswerable from the log, and the answer matters: the
// absence of a preference means ENABLED, so the two readings differ.
//
// It deliberately carries no class and no template. A preference names a
// channel, and that is what stops a preference from ever naming
// Security — the class whose message is the only thing standing between a
// silent account takeover and a detected one (NOTIFICATIONS §3). The dispatcher
// checks class before it consults any preference, so this event cannot reach a
// security alert even if one were forged.
//
// OrgID is on the payload as well as in the envelope because preferences are per
// person PER ORGANIZATION: one stream carries a person's changes across every
// organization they belong to, and a projector rebuilding from position zero
// must be able to scope each row from the event alone.
type ChannelPreferenceSet struct {
	SubjectID string
	OrgID     string
	Channel   string
	Enabled   bool
	ChangedAt time.Time
}

func (*ChannelPreferenceSet) EventType() string { return "notification.ChannelPreferenceSet.v1" }
