// Package notification is the module's composition surface: the two declarations
// every binary that touches notification events must make, in one place.
//
// They live here rather than in each cmd/ because there are three binaries —
// api, projector, worker — and a type registered in two of them is a projector
// that stops on an event the API can happily write. That drift is not
// hypothetical in this repository: it is the failure that left three
// notification adapters wired into nothing, and it is why this file exists
// alongside identity's rather than after the same lesson is learned twice.
package notification

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/notification/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every notification event this build can DECODE.
//
// Registering an event the module can no longer produce is harmless and
// necessary — the log still contains it. Failing to register one the log
// contains is a hard stop at read time, which is the correct direction for that
// mistake to fail in.
func RegisterEvents(codec *eventcodec.JSON) {
	// The in-app feed.
	eventcodec.Register[contract.NotificationCreated](codec)
	eventcodec.Register[contract.NotificationRead](codec)

	// Browser endpoints.
	eventcodec.Register[contract.PushSubscribed](codec)
	eventcodec.Register[contract.PushSubscriptionExpired](codec)
	eventcodec.Register[contract.PushSent](codec)

	// A person's own channel toggles.
	eventcodec.Register[contract.ChannelPreferenceSet](codec)
}

// RegisterSchemas declares the current schema version of every notification
// event (ADR-029).
//
// Everything is v1 and there are no upcasters. The function exists now rather
// than when the first upcaster is needed, because the registry refuses to decode
// an unregistered type — so the alternative is discovering the omission from a
// projector that has already stopped.
//
// When a shape changes: bump the version here in the SAME commit as the field
// change, and add the Upcast call beside it. A version without an upcaster is a
// load failure, by design.
func RegisterSchemas(r *eventsourcing.UpcasterRegistry) {
	for _, t := range eventTypes() {
		r.Register(t, 1)
	}
}

// eventTypes lists every notification event type as a string.
//
// Derived from the same zero values the codec registers, so the two lists cannot
// disagree about a name — a typed literal here is checked by the compiler, a
// string literal would not be.
func eventTypes() []string {
	events := []eventsourcing.Event{
		&contract.NotificationCreated{}, &contract.NotificationRead{},
		&contract.PushSubscribed{}, &contract.PushSubscriptionExpired{},
		&contract.PushSent{},
		&contract.ChannelPreferenceSet{},
	}
	out := make([]string, 0, len(events))
	for _, e := range events {
		out = append(out, e.EventType())
	}
	return out
}

// EventTypes is the same list, exported so a composition-root test can assert
// that what a binary registers and what this module publishes are the same set.
func EventTypes() []string { return eventTypes() }
