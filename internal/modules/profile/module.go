// Package profile is the module's composition surface: the two declarations
// every binary that touches profile events must make, in one place.
//
// They live here rather than in each cmd/ because there are three binaries —
// api, projector, worker — and a type registered in two of them is a projector
// that stops on an event the API can happily write. That drift is not
// hypothetical in this repository: it is the failure that left three
// notification adapters wired into nothing, and it is why this file exists
// alongside identity's and notification's rather than after the same lesson is
// learned a third time.
package profile

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/profile/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every profile event this build can DECODE.
//
// Registering an event the module can no longer produce is harmless and
// necessary — the log still contains it. Failing to register one the log
// contains is a hard stop at read time, which is the correct direction for that
// mistake to fail in.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.ProfileUpdated](codec)
}

// RegisterSchemas declares the current schema version of every profile event
// (ADR-029).
//
// Everything is v1 and there are no upcasters. The function exists now rather
// than when the first upcaster is needed, because the registry refuses to decode
// an unregistered type — so the alternative is discovering the omission from a
// projector that has already stopped.
//
// # This module is built so that this function almost never changes
//
// A profile grows by attributes, and each new attribute is a POINTER FIELD on
// the existing payload rather than a new event. Adding one leaves every stored
// event decodable: a payload written before the field existed simply has no key
// for it, and the pointer is nil, which already means "this update did not
// mention it". So the common change costs no version bump and no upcaster.
//
// A version bump is still required if a field is ever RENAMED, RETYPED or
// REMOVED — and when that happens, bump it here in the SAME commit as the
// change and add the Upcast call beside it. A version without an upcaster is a
// load failure, by design.
func RegisterSchemas(r *eventsourcing.UpcasterRegistry) {
	for _, t := range eventTypes() {
		r.Register(t, 1)
	}
}

// eventTypes lists every profile event type as a string.
//
// Derived from the same zero values the codec registers, so the two lists cannot
// disagree about a name — a typed literal here is checked by the compiler, a
// string literal would not be.
func eventTypes() []string {
	events := []eventsourcing.Event{
		&contract.ProfileUpdated{},
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
