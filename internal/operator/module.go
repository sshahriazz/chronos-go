// Package operator is the operator plane's composition surface (ADR-024).
//
// It sits at `internal/operator`, NOT `internal/modules/operator`, and the
// location is load-bearing: the depguard rule `api-excludes-operator` denies
// this import path to `cmd/api`, `internal/server` and every module. Moving it
// under `internal/modules` would silently opt out of the one rule that makes
// the separation real.
package operator

import (
	"github.com/chronos/chronos-go/internal/adapter/eventcodec"
	"github.com/chronos/chronos-go/internal/operator/contract"
	"github.com/chronos/chronos-go/internal/platform/eventsourcing"
)

// RegisterEvents declares every operator event this build can DECODE.
func RegisterEvents(codec *eventcodec.JSON) {
	eventcodec.Register[contract.OperatorProvisioned](codec)
	eventcodec.Register[contract.OperatorRoleChanged](codec)
	eventcodec.Register[contract.OperatorDisabled](codec)
	eventcodec.Register[contract.OperatorCredentialEnrolled](codec)
	eventcodec.Register[contract.OperatorSignedIn](codec)
	eventcodec.Register[contract.OperatorSignedOut](codec)
	eventcodec.Register[contract.OperatorViewedCustomer](codec)
	eventcodec.Register[contract.OperatorViewedPersonalData](codec)
}

// RegisterSchemas declares the current schema version of every operator event
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

// EventTypes is what this plane declares, so a composition-root test can assert
// what the binary registers.
func EventTypes() []string { return eventTypes() }

func eventTypes() []string {
	return []string{
		(&contract.OperatorProvisioned{}).EventType(),
		(&contract.OperatorRoleChanged{}).EventType(),
		(&contract.OperatorDisabled{}).EventType(),
		(&contract.OperatorCredentialEnrolled{}).EventType(),
		(&contract.OperatorSignedIn{}).EventType(),
		(&contract.OperatorSignedOut{}).EventType(),
		(&contract.OperatorViewedCustomer{}).EventType(),
		(&contract.OperatorViewedPersonalData{}).EventType(),
	}
}
