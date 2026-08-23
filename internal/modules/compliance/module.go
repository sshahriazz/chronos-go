// Package compliance is the module's composition surface.
package compliance

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/compliance/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every compliance event this build can DECODE.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.ProcessingRestricted](codec)
	eventcodec.Register[contract.ProcessingRestrictionLifted](codec)
}

// RegisterSchemas declares the current schema version of every compliance event
// (ADR-029).
//
// Not bookkeeping: Repository.decode calls UpcasterRegistry.Apply on every read,
// and Apply refuses a type with no registered version. An event registered above
// but missing here writes perfectly and makes its stream unreadable forever.
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
		(&contract.ProcessingRestricted{}).EventType(),
		(&contract.ProcessingRestrictionLifted{}).EventType(),
	}
}
