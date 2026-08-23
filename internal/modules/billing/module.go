// Package billing is the module's composition surface: the declarations every
// binary that touches billing events must make, in one place.
//
// They live here rather than in each cmd/ because there are three binaries —
// api, projector, worker — and a type registered in two of them is a projector
// that stops on an event the API can happily write.
package billing

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/modules/billing/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every billing event this build can DECODE.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.InvoiceRecorded](codec)
}

// RegisterSchemas declares the current schema version of every billing event
// (ADR-029).
//
// Not optional bookkeeping: Repository.decode calls UpcasterRegistry.Apply on
// every read, and Apply refuses a type with no registered version. An event
// registered above but missing here writes perfectly and makes its stream
// unreadable forever.
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
		(&contract.InvoiceRecorded{}).EventType(),
	}
}
