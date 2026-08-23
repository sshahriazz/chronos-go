// Package organization is the module's composition surface: the declarations
// every binary that touches organization events must make, in one place.
//
// They live here rather than in each cmd/ because there are three binaries —
// api, projector, worker — and a type registered in two of them is a projector
// that stops on an event the API can happily write. That is not hypothetical
// here: it shipped once, when cmd/api registered identity's events and nothing
// else while serving notification and profile too.
package organization

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/organization/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every organization event this build can DECODE.
//
// Registering an event the module can no longer produce is harmless and
// necessary — the log still contains it. Failing to register one the log
// contains is a hard stop at read time, which is the correct direction for that
// mistake to fail in.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.OrganizationCreated](codec)
	eventcodec.Register[contract.OrganizationTrialStarted](codec)
	eventcodec.Register[contract.OrganizationTrialEndingSoon](codec)
	eventcodec.Register[contract.OrganizationActivated](codec)
	eventcodec.Register[contract.OrganizationPastDue](codec)
	eventcodec.Register[contract.OrganizationSuspended](codec)
	eventcodec.Register[contract.OrganizationClosed](codec)
	eventcodec.Register[contract.OrgAdminAdded](codec)
	eventcodec.Register[contract.OrgAdminRemoved](codec)
	eventcodec.Register[contract.OwnerReservationHeld](codec)
	eventcodec.Register[contract.OwnerReservationReleased](codec)
	eventcodec.Register[contract.SlugReservationHeld](codec)
	eventcodec.Register[contract.SlugReservationReleased](codec)
}

// RegisterSchemas declares the current schema version of every organization
// event (ADR-029).
//
// Everything is v1 and there are no upcasters. The function exists now rather
// than when the first upcaster is needed, because the registry refuses to decode
// an unregistered type — so the alternative is discovering the omission from a
// projector that has already stopped.
func RegisterSchemas(r *eventsourcing.UpcasterRegistry) {
	for _, t := range eventTypes() {
		r.Register(t, 1)
	}
}

// EventTypes is what this module declares, so a composition-root test can assert
// what a binary registers.
func EventTypes() []string { return eventTypes() }

func eventTypes() []string {
	return []string{
		(&contract.OrganizationCreated{}).EventType(),
		(&contract.OrganizationTrialStarted{}).EventType(),
		(&contract.OrganizationActivated{}).EventType(),
		(&contract.OrganizationPastDue{}).EventType(),
		(&contract.OrganizationSuspended{}).EventType(),
		(&contract.OrganizationClosed{}).EventType(),
		(&contract.OrgAdminAdded{}).EventType(),
		(&contract.OrgAdminRemoved{}).EventType(),
		(&contract.OwnerReservationHeld{}).EventType(),
		(&contract.OwnerReservationReleased{}).EventType(),
		(&contract.SlugReservationHeld{}).EventType(),
		(&contract.SlugReservationReleased{}).EventType(),
	}
}
